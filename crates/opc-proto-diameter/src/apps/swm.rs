//! 3GPP SWm Diameter dictionary subset and typed helpers.
//!
//! This module covers the ePDG-restricted SWm DER/DEA exchange that carries
//! EAP payloads between the ePDG and an AAA/DRA peer, the request-bound
//! Session-Termination STR/STA and Abort-Session ASR/ASA lifecycle exchanges,
//! including the deterministic successful-ASA transition to an administrative
//! STR when Diameter session state is maintained, and the RAR/RAA then AAR/AAA
//! authorization-information update sequence, the non-overload DER access
//! context (QoS capabilities, visited PLMN, AAA failover, and priority), a
//! typed request-correlated RFC 6733 routing boundary for Proxy-Info,
//! Route-Record, generic E-bit redirects, and exact request-bound DRA
//! `DIAMETER_UNABLE_TO_DELIVER` / `DIAMETER_TOO_BUSY` responses, a
//! typed request-conditioned RFC 7683 baseline loss-overload offer/report,
//! ordered RFC 8583 Diameter Load context, typed successful-session timer
//! context, request-bound canonical RFC 5447 serving/emergency gateway
//! context, typed redaction-safe top-level DEA subscriber facts, typed sealed
//! SWm DEA WLAN access/civic-location context with a location-bound last-known
//! timestamp, typed correlation-gated SWm subscriber/equipment trace
//! activation for the Release-18 PDN-GW profile, and a
//! bounded, request-conditioned complete SWm APN authorization surface with
//! sealed extension retention, its default Context-Identifier,
//! Service-Selection, and the TS 29.273 emergency attach sequence. The
//! top-level default pointer is accepted under the DEA
//! extension-AVP wildcard; it is not part of the baseline SWm DEA command ABNF.
//! This module does not select redirect targets, enforce redirect cache
//! lifetime, attempt peer connections, implement transport state or realm
//! routing, choose local emergency-access policy, set duplicate-request cache
//! lifetime, or implement IKEv2 policy.
//! A live Diameter client must still atomically consume a pending request keyed
//! by peer connection and Hop-by-Hop Identifier before passing parsed response
//! envelopes to correlation or emergency evidence; the codec enforces the
//! remaining identifiers and request facts but cannot prove transport
//! liveness or reject a response replay without that consumer-owned state.
//!
//! @spec 3GPP TS29273
//! @spec 3GPP TS29272 7.3
//! @spec 3GPP TS32422 5
//! @spec 3GPP TS32158 4.4.3
//! @spec IETF RFC4072
//! @spec IETF RFC5778
//! @spec IETF RFC7683
//! @spec IETF RFC8583
//! @conformance scaffold — see CONFORMANCE.md

use bytes::BytesMut;
use hmac::{Hmac, Mac};
use opc_protocol::{
    DecodeContext, DecodeError, DecodeErrorCode, DuplicateIePolicy, EncodeContext, EncodeError,
    EncodeErrorCode, SpecRef, UnknownIePolicy,
};
use opc_types::{Imei, Imei15};
use sha2::{Digest, Sha256};
use std::{collections::HashSet, error::Error, fmt, net::IpAddr};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use super::{builder_helpers, VENDOR_ID_3GPP};
use crate::avp::dictionary::Redacted;
use crate::base;
use crate::dictionary::{
    ApplicationDefinition, AvpCardinality, AvpDataType, AvpDefinition, AvpFlagRules, AvpKey,
    CommandAvpRule, CommandDefinition, CommandKind, Dictionary, FlagRequirement,
};
use crate::parser_error::DiameterParserError;
use crate::{
    ApplicationId, AvpCode, AvpHeader, CommandCode, Message, OwnedMessage, RawAvp, VendorId,
};

mod apn;
mod authorization;
mod dea_authorization;
mod lifecycle;
mod location;
mod mobility;
mod trace;

pub use super::subscription_id::{
    AVP_SUBSCRIPTION_ID, AVP_SUBSCRIPTION_ID_DATA, AVP_SUBSCRIPTION_ID_TYPE,
};
pub use apn::*;
pub use authorization::*;
pub use dea_authorization::*;
pub use lifecycle::*;
pub use location::*;
pub use mobility::*;
pub use trace::*;

/// 3GPP SWm application identifier.
pub const APPLICATION_ID: ApplicationId = ApplicationId::new(16_777_264);

/// Diameter-EAP command code (RFC 4072).
pub const COMMAND_DIAMETER_EAP: CommandCode = CommandCode::new(268);

const MAX_SWM_DIAMETER_EAP_EXTENSIONS: usize = 128;
const MAX_SWM_DIAMETER_EAP_ROUTING_AVPS: usize = 128;
const MAX_SWM_REDIRECT_HOSTS: usize = 128;

/// EAP-Payload AVP code (RFC 4072).
pub const AVP_EAP_PAYLOAD: AvpCode = AvpCode::new(462);
/// EAP-Reissued-Payload AVP code (RFC 4072).
pub const AVP_EAP_REISSUED_PAYLOAD: AvpCode = AvpCode::new(463);
/// EAP-Master-Session-Key AVP code (RFC 4072).
pub const AVP_EAP_MASTER_SESSION_KEY: AvpCode = AvpCode::new(464);
/// Auth-Request-Type AVP code.
pub const AVP_AUTH_REQUEST_TYPE: AvpCode = AvpCode::new(274);
/// MIP6-Feature-Vector AVP code (RFC 5447 section 4.2.5).
pub const AVP_MIP6_FEATURE_VECTOR: AvpCode = AvpCode::new(124);
/// QoS-Capability grouped AVP code (RFC 5777 section 6).
pub const AVP_QOS_CAPABILITY: AvpCode = AvpCode::new(578);
/// QoS-Profile-Template grouped AVP code (RFC 5777 section 5.3).
pub const AVP_QOS_PROFILE_TEMPLATE: AvpCode = AvpCode::new(574);
/// QoS-Profile-Id AVP code (RFC 5777 section 5.2).
pub const AVP_QOS_PROFILE_ID: AvpCode = AvpCode::new(573);
/// Supported-Features grouped AVP code (3GPP TS 29.229 section 6.3.29).
pub const AVP_SUPPORTED_FEATURES: AvpCode = AvpCode::new(628);
/// Feature-List-ID AVP code (3GPP TS 29.229 section 6.3.30).
pub const AVP_FEATURE_LIST_ID: AvpCode = AvpCode::new(629);
/// Feature-List AVP code (3GPP TS 29.229 section 6.3.31).
pub const AVP_FEATURE_LIST: AvpCode = AvpCode::new(630);
/// RAT-Type AVP code (3GPP TS 29.212 section 5.3.31).
pub const AVP_RAT_TYPE: AvpCode = AvpCode::new(1032);
/// AAR-Flags AVP code (3GPP TS 29.273 section 7.2.3.5).
pub const AVP_AAR_FLAGS: AvpCode = AvpCode::new(1539);
/// UE-Local-IP-Address AVP code (3GPP TS 29.212 section 5.3.96).
pub const AVP_UE_LOCAL_IP_ADDRESS: AvpCode = AvpCode::new(2805);
/// High-Priority-Access-Info AVP code (3GPP TS 29.273 section 5.2.3.36).
pub const AVP_HIGH_PRIORITY_ACCESS_INFO: AvpCode = AvpCode::new(1542);
/// Visited-Network-Identifier AVP code (3GPP TS 29.273 section 9.2.3.1.2).
pub const AVP_VISITED_NETWORK_IDENTIFIER: AvpCode = AvpCode::new(600);
/// AAA-Failure-Indication AVP code (3GPP TS 29.273 section 8.2.3.21).
pub const AVP_AAA_FAILURE_INDICATION: AvpCode = AvpCode::new(1518);
/// State AVP code (RFC 4005 section 9.3.4).
pub const AVP_STATE: AvpCode = AvpCode::new(24);
/// Reply-Message AVP code (RFC 4005 section 4.9).
pub const AVP_REPLY_MESSAGE: AvpCode = AvpCode::new(18);
/// Service-Selection AVP code (RFC 5778 §6.2).
pub const AVP_SERVICE_SELECTION: AvpCode = AvpCode::new(493);
/// Mobile-Node-Identifier AVP code (RFC 5779 §5.6).
pub const AVP_MOBILE_NODE_IDENTIFIER: AvpCode = AvpCode::new(506);
/// Emergency-Services AVP code (3GPP TS 29.273 §7.2.3.4).
pub const AVP_EMERGENCY_SERVICES: AvpCode = AvpCode::new(1538);
/// Terminal-Information grouped AVP code (3GPP TS 29.272 §7.3.3).
pub const AVP_TERMINAL_INFORMATION: AvpCode = AvpCode::new(1401);
/// IMEI AVP code (3GPP TS 29.272 §7.3.4).
pub const AVP_IMEI: AvpCode = AvpCode::new(1402);
/// Software-Version AVP code (3GPP TS 29.272 §7.3.5).
pub const AVP_SOFTWARE_VERSION: AvpCode = AvpCode::new(1403);
/// APN-OI-Replacement AVP code (3GPP TS 29.272 section 7.3.32).
pub const AVP_APN_OI_REPLACEMENT: AvpCode = AvpCode::new(1427);
/// 3GPP-Charging-Characteristics AVP code (3GPP TS 29.061 section 16.4.7).
pub const AVP_3GPP_CHARGING_CHARACTERISTICS: AvpCode = AvpCode::new(13);
/// UE-Usage-Type AVP code (3GPP TS 29.272 section 7.3.202).
pub const AVP_UE_USAGE_TYPE: AvpCode = AvpCode::new(1680);
/// Core-Network-Restrictions AVP code (3GPP TS 29.272 section 7.3.230).
pub const AVP_CORE_NETWORK_RESTRICTIONS: AvpCode = AvpCode::new(1704);
/// MPS-Priority AVP code (3GPP TS 29.272 section 7.3.131).
pub const AVP_MPS_PRIORITY: AvpCode = AvpCode::new(1616);

/// Emergency-Indication bit in the Emergency-Services AVP.
pub const EMERGENCY_SERVICES_EMERGENCY_INDICATION: u32 = 1 << 0;

/// 3GPP experimental result requesting emergency IMEI recovery.
pub const DIAMETER_ERROR_USER_UNKNOWN: u32 = 5001;
const DIAMETER_MULTI_ROUND_AUTH: u32 = 1001;
/// Width of the TS 33.402 Annex A.4 unauthenticated-emergency MSK.
pub const UNAUTHENTICATED_EMERGENCY_MSK_LEN: usize = 32;
/// Base result used by an RFC 6733 redirect agent.
pub const DIAMETER_REDIRECT_INDICATION: u32 = 3006;
/// Largest identity body that fits an RFC 3748 EAP-Response/Identity packet.
///
/// The five-octet fixed packet prefix (Code, Identifier, Length, and Type) is
/// included in EAP's two-octet packet length.
pub const EAP_RESPONSE_IDENTITY_MAX_IDENTITY_LEN: usize = u16::MAX as usize - 5;

/// APN-Configuration grouped AVP code (3GPP TS 29.272 §7.3.35).
pub const AVP_APN_CONFIGURATION: AvpCode = AvpCode::new(1430);
/// Context-Identifier AVP code (3GPP TS 29.272 §7.3.27).
pub const AVP_CONTEXT_IDENTIFIER: AvpCode = AvpCode::new(1423);
/// PDN-Type AVP code (3GPP TS 29.272 §7.3.62).
pub const AVP_PDN_TYPE: AvpCode = AvpCode::new(1456);
/// EPS-Subscribed-QoS-Profile grouped AVP code (3GPP TS 29.272 §7.3.37).
pub const AVP_EPS_SUBSCRIBED_QOS_PROFILE: AvpCode = AvpCode::new(1431);
/// QoS-Class-Identifier AVP code (3GPP TS 29.212 §5.3.17).
pub const AVP_QOS_CLASS_IDENTIFIER: AvpCode = AvpCode::new(1028);
/// Allocation-Retention-Priority grouped AVP code (3GPP TS 29.212 §5.3.32).
pub const AVP_ALLOCATION_RETENTION_PRIORITY: AvpCode = AvpCode::new(1034);
/// Priority-Level AVP code (3GPP TS 29.212 §5.3.45).
pub const AVP_PRIORITY_LEVEL: AvpCode = AvpCode::new(1046);
/// Pre-emption-Capability AVP code (3GPP TS 29.212 §5.3.46).
pub const AVP_PRE_EMPTION_CAPABILITY: AvpCode = AvpCode::new(1047);
/// Pre-emption-Vulnerability AVP code (3GPP TS 29.212 §5.3.47).
pub const AVP_PRE_EMPTION_VULNERABILITY: AvpCode = AvpCode::new(1048);
/// AMBR grouped AVP code (3GPP TS 29.272 §7.3.41).
pub const AVP_AMBR: AvpCode = AvpCode::new(1435);
/// Max-Requested-Bandwidth-UL AVP code (3GPP TS 29.214 §5.3.15).
pub const AVP_MAX_REQUESTED_BANDWIDTH_UL: AvpCode = AvpCode::new(516);
/// Max-Requested-Bandwidth-DL AVP code (3GPP TS 29.214 §5.3.14).
pub const AVP_MAX_REQUESTED_BANDWIDTH_DL: AvpCode = AvpCode::new(515);
/// Extended-Max-Requested-BW-DL AVP code (3GPP TS 29.214 §5.3.52).
pub const AVP_EXTENDED_MAX_REQUESTED_BANDWIDTH_DL: AvpCode = AvpCode::new(554);
/// Extended-Max-Requested-BW-UL AVP code (3GPP TS 29.214 §5.3.53).
pub const AVP_EXTENDED_MAX_REQUESTED_BANDWIDTH_UL: AvpCode = AvpCode::new(555);

/// Auth-Request-Type value for AUTHORIZE_AUTHENTICATE.
pub const AUTH_REQUEST_TYPE_AUTHORIZE_AUTHENTICATE: u32 = 3;
/// Auth-Request-Type value for AUTHORIZE_ONLY.
pub const AUTH_REQUEST_TYPE_AUTHORIZE_ONLY: u32 = 2;

/// SWm feature-list identifier assigned by 3GPP TS 29.273.
pub const SWM_FEATURE_LIST_ID: u32 = 1;
/// SWm feature-list value for TS 29.273 Release 18.
pub const SWM_FEATURE_LIST: u32 = 0;

const MAX_SWM_SUPPORTED_FEATURES: usize = 128;
const MAX_SWM_QOS_PROFILE_TEMPLATES: usize = 128;
const MAX_SWM_QOS_GROUP_CHILDREN: usize = 128;
const MAX_SWM_LOAD_REPORTS: usize = 128;

const fn is_overload_grouped_child(code: AvpCode) -> bool {
    matches!(
        code,
        AVP_OC_FEATURE_VECTOR
            | AVP_OC_SEQUENCE_NUMBER
            | AVP_OC_VALIDITY_DURATION
            | AVP_OC_REPORT_TYPE
            | AVP_OC_REDUCTION_PERCENTAGE
            | AVP_LOAD_TYPE
            | AVP_LOAD_VALUE
            | AVP_SOURCE_ID
    )
}

fn is_forbidden_der_overload_avp(code: AvpCode) -> bool {
    code == AVP_OC_OLR || code == AVP_LOAD || is_overload_grouped_child(code)
}

/// 3GPP SWm application definition.
pub const APPLICATION: ApplicationDefinition = ApplicationDefinition::new(
    APPLICATION_ID,
    "3GPP SWm",
    Some(VENDOR_ID_3GPP),
    SpecRef::new("3gpp", "TS29273", "SWm Diameter application"),
);

static SWM_REQUEST_AVP_RULES: [CommandAvpRule; 40] = [
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_SESSION_ID),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(AvpKey::ietf(AVP_STATE), AvpCardinality::ZeroOrMore),
    CommandAvpRule::new(
        AvpKey::vendor(AVP_EMERGENCY_SERVICES, VENDOR_ID_3GPP),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::vendor(AVP_TERMINAL_INFORMATION, VENDOR_ID_3GPP),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::vendor(AVP_RAT_TYPE, VENDOR_ID_3GPP),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(AVP_SERVICE_SELECTION),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(AVP_MIP6_FEATURE_VECTOR),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(AvpKey::ietf(AVP_QOS_CAPABILITY), AvpCardinality::ZeroOrOne),
    CommandAvpRule::new(
        AvpKey::vendor(AVP_VISITED_NETWORK_IDENTIFIER, VENDOR_ID_3GPP),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::vendor(AVP_AAA_FAILURE_INDICATION, VENDOR_ID_3GPP),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::vendor(AVP_SUPPORTED_FEATURES, VENDOR_ID_3GPP),
        AvpCardinality::ZeroOrMore,
    ),
    CommandAvpRule::new(
        AvpKey::vendor(AVP_UE_LOCAL_IP_ADDRESS, VENDOR_ID_3GPP),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::vendor(AVP_HIGH_PRIORITY_ACCESS_INFO, VENDOR_ID_3GPP),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(AVP_OC_SUPPORTED_FEATURES),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(AVP_OC_FEATURE_VECTOR),
        AvpCardinality::Forbidden,
    ),
    CommandAvpRule::new(AvpKey::ietf(AVP_OC_OLR), AvpCardinality::Forbidden),
    CommandAvpRule::new(
        AvpKey::ietf(AVP_OC_SEQUENCE_NUMBER),
        AvpCardinality::Forbidden,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(AVP_OC_VALIDITY_DURATION),
        AvpCardinality::Forbidden,
    ),
    CommandAvpRule::new(AvpKey::ietf(AVP_OC_REPORT_TYPE), AvpCardinality::Forbidden),
    CommandAvpRule::new(
        AvpKey::ietf(AVP_OC_REDUCTION_PERCENTAGE),
        AvpCardinality::Forbidden,
    ),
    CommandAvpRule::new(AvpKey::ietf(AVP_LOAD), AvpCardinality::Forbidden),
    CommandAvpRule::new(AvpKey::ietf(AVP_LOAD_TYPE), AvpCardinality::Forbidden),
    CommandAvpRule::new(AvpKey::ietf(AVP_LOAD_VALUE), AvpCardinality::Forbidden),
    CommandAvpRule::new(AvpKey::ietf(AVP_SOURCE_ID), AvpCardinality::Forbidden),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_RESULT_CODE),
        AvpCardinality::Forbidden,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_EXPERIMENTAL_RESULT),
        AvpCardinality::Forbidden,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_REDIRECT_HOST),
        AvpCardinality::Forbidden,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_REDIRECT_HOST_USAGE),
        AvpCardinality::Forbidden,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_REDIRECT_MAX_CACHE_TIME),
        AvpCardinality::Forbidden,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_FAILED_AVP),
        AvpCardinality::Forbidden,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_MULTI_ROUND_TIME_OUT),
        AvpCardinality::Forbidden,
    ),
    CommandAvpRule::new(
        AvpKey::vendor(AVP_APN_OI_REPLACEMENT, VENDOR_ID_3GPP),
        AvpCardinality::Forbidden,
    ),
    CommandAvpRule::new(AvpKey::ietf(AVP_SUBSCRIPTION_ID), AvpCardinality::Forbidden),
    CommandAvpRule::new(
        AvpKey::vendor(AVP_3GPP_CHARGING_CHARACTERISTICS, VENDOR_ID_3GPP),
        AvpCardinality::Forbidden,
    ),
    CommandAvpRule::new(
        AvpKey::vendor(AVP_UE_USAGE_TYPE, VENDOR_ID_3GPP),
        AvpCardinality::Forbidden,
    ),
    CommandAvpRule::new(
        AvpKey::vendor(AVP_CORE_NETWORK_RESTRICTIONS, VENDOR_ID_3GPP),
        AvpCardinality::Forbidden,
    ),
    CommandAvpRule::new(
        AvpKey::vendor(AVP_MPS_PRIORITY, VENDOR_ID_3GPP),
        AvpCardinality::Forbidden,
    ),
    CommandAvpRule::new(
        AvpKey::vendor(AVP_TRACE_INFO, VENDOR_ID_3GPP),
        AvpCardinality::Forbidden,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_PROXY_INFO),
        AvpCardinality::ZeroOrMore,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_ROUTE_RECORD),
        AvpCardinality::ZeroOrMore,
    ),
];

static SWM_ANSWER_AVP_RULES: [CommandAvpRule; 44] = [
    CommandAvpRule::new(AvpKey::ietf(AVP_STATE), AvpCardinality::ZeroOrMore),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_RESULT_CODE),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_EXPERIMENTAL_RESULT),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(AVP_MOBILE_NODE_IDENTIFIER),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::vendor(AVP_APN_CONFIGURATION, VENDOR_ID_3GPP),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::vendor(AVP_CONTEXT_IDENTIFIER, VENDOR_ID_3GPP),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(AVP_MIP6_FEATURE_VECTOR),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(AvpKey::ietf(AVP_MIP6_AGENT_INFO), AvpCardinality::ZeroOrOne),
    CommandAvpRule::new(
        AvpKey::vendor(AVP_EMERGENCY_INFO, VENDOR_ID_3GPP),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_SESSION_TIMEOUT),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_MULTI_ROUND_TIME_OUT),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_AUTHORIZATION_LIFETIME),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_RE_AUTH_REQUEST_TYPE),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_AUTH_GRACE_PERIOD),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_AUTH_SESSION_STATE),
        AvpCardinality::Forbidden,
    ),
    CommandAvpRule::new(
        AvpKey::vendor(AVP_SUPPORTED_FEATURES, VENDOR_ID_3GPP),
        AvpCardinality::ZeroOrMore,
    ),
    CommandAvpRule::new(
        AvpKey::vendor(AVP_ACCESS_NETWORK_INFO, VENDOR_ID_3GPP),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::vendor(AVP_USER_LOCATION_INFO_TIME, VENDOR_ID_3GPP),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(AVP_OC_SUPPORTED_FEATURES),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(AvpKey::ietf(AVP_OC_OLR), AvpCardinality::ZeroOrOne),
    CommandAvpRule::new(AvpKey::ietf(AVP_LOAD), AvpCardinality::ZeroOrMore),
    CommandAvpRule::new(
        AvpKey::ietf(AVP_OC_FEATURE_VECTOR),
        AvpCardinality::Forbidden,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(AVP_OC_SEQUENCE_NUMBER),
        AvpCardinality::Forbidden,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(AVP_OC_VALIDITY_DURATION),
        AvpCardinality::Forbidden,
    ),
    CommandAvpRule::new(AvpKey::ietf(AVP_OC_REPORT_TYPE), AvpCardinality::Forbidden),
    CommandAvpRule::new(
        AvpKey::ietf(AVP_OC_REDUCTION_PERCENTAGE),
        AvpCardinality::Forbidden,
    ),
    CommandAvpRule::new(AvpKey::ietf(AVP_LOAD_TYPE), AvpCardinality::Forbidden),
    CommandAvpRule::new(AvpKey::ietf(AVP_LOAD_VALUE), AvpCardinality::Forbidden),
    CommandAvpRule::new(AvpKey::ietf(AVP_SOURCE_ID), AvpCardinality::Forbidden),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_PROXY_INFO),
        AvpCardinality::ZeroOrMore,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_DESTINATION_HOST),
        AvpCardinality::Forbidden,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_DESTINATION_REALM),
        AvpCardinality::Forbidden,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_ROUTE_RECORD),
        AvpCardinality::Forbidden,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_REDIRECT_HOST),
        AvpCardinality::ZeroOrMore,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_REDIRECT_HOST_USAGE),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_REDIRECT_MAX_CACHE_TIME),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_FAILED_AVP),
        AvpCardinality::ZeroOrMore,
    ),
    CommandAvpRule::new(
        AvpKey::vendor(AVP_APN_OI_REPLACEMENT, VENDOR_ID_3GPP),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(AvpKey::ietf(AVP_SUBSCRIPTION_ID), AvpCardinality::ZeroOrOne),
    CommandAvpRule::new(
        AvpKey::vendor(AVP_3GPP_CHARGING_CHARACTERISTICS, VENDOR_ID_3GPP),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::vendor(AVP_UE_USAGE_TYPE, VENDOR_ID_3GPP),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::vendor(AVP_CORE_NETWORK_RESTRICTIONS, VENDOR_ID_3GPP),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::vendor(AVP_MPS_PRIORITY, VENDOR_ID_3GPP),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::vendor(AVP_TRACE_INFO, VENDOR_ID_3GPP),
        AvpCardinality::ZeroOrOne,
    ),
];

static SWM_PROJECTED_PROFILE_ANSWER_AVP_RULES: [CommandAvpRule; 44] = [
    CommandAvpRule::new(AvpKey::ietf(AVP_STATE), AvpCardinality::ZeroOrMore),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_RESULT_CODE),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_EXPERIMENTAL_RESULT),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(AVP_MOBILE_NODE_IDENTIFIER),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::vendor(AVP_APN_CONFIGURATION, VENDOR_ID_3GPP),
        AvpCardinality::ZeroOrMore,
    ),
    CommandAvpRule::new(
        AvpKey::vendor(AVP_CONTEXT_IDENTIFIER, VENDOR_ID_3GPP),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(AVP_MIP6_FEATURE_VECTOR),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(AvpKey::ietf(AVP_MIP6_AGENT_INFO), AvpCardinality::ZeroOrOne),
    CommandAvpRule::new(
        AvpKey::vendor(AVP_EMERGENCY_INFO, VENDOR_ID_3GPP),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_SESSION_TIMEOUT),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_MULTI_ROUND_TIME_OUT),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_AUTHORIZATION_LIFETIME),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_RE_AUTH_REQUEST_TYPE),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_AUTH_GRACE_PERIOD),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_AUTH_SESSION_STATE),
        AvpCardinality::Forbidden,
    ),
    CommandAvpRule::new(
        AvpKey::vendor(AVP_SUPPORTED_FEATURES, VENDOR_ID_3GPP),
        AvpCardinality::ZeroOrMore,
    ),
    CommandAvpRule::new(
        AvpKey::vendor(AVP_ACCESS_NETWORK_INFO, VENDOR_ID_3GPP),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::vendor(AVP_USER_LOCATION_INFO_TIME, VENDOR_ID_3GPP),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(AVP_OC_SUPPORTED_FEATURES),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(AvpKey::ietf(AVP_OC_OLR), AvpCardinality::ZeroOrOne),
    CommandAvpRule::new(AvpKey::ietf(AVP_LOAD), AvpCardinality::ZeroOrMore),
    CommandAvpRule::new(
        AvpKey::ietf(AVP_OC_FEATURE_VECTOR),
        AvpCardinality::Forbidden,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(AVP_OC_SEQUENCE_NUMBER),
        AvpCardinality::Forbidden,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(AVP_OC_VALIDITY_DURATION),
        AvpCardinality::Forbidden,
    ),
    CommandAvpRule::new(AvpKey::ietf(AVP_OC_REPORT_TYPE), AvpCardinality::Forbidden),
    CommandAvpRule::new(
        AvpKey::ietf(AVP_OC_REDUCTION_PERCENTAGE),
        AvpCardinality::Forbidden,
    ),
    CommandAvpRule::new(AvpKey::ietf(AVP_LOAD_TYPE), AvpCardinality::Forbidden),
    CommandAvpRule::new(AvpKey::ietf(AVP_LOAD_VALUE), AvpCardinality::Forbidden),
    CommandAvpRule::new(AvpKey::ietf(AVP_SOURCE_ID), AvpCardinality::Forbidden),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_PROXY_INFO),
        AvpCardinality::ZeroOrMore,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_DESTINATION_HOST),
        AvpCardinality::Forbidden,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_DESTINATION_REALM),
        AvpCardinality::Forbidden,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_ROUTE_RECORD),
        AvpCardinality::Forbidden,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_REDIRECT_HOST),
        AvpCardinality::ZeroOrMore,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_REDIRECT_HOST_USAGE),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_REDIRECT_MAX_CACHE_TIME),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_FAILED_AVP),
        AvpCardinality::ZeroOrMore,
    ),
    CommandAvpRule::new(
        AvpKey::vendor(AVP_APN_OI_REPLACEMENT, VENDOR_ID_3GPP),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(AvpKey::ietf(AVP_SUBSCRIPTION_ID), AvpCardinality::ZeroOrOne),
    CommandAvpRule::new(
        AvpKey::vendor(AVP_3GPP_CHARGING_CHARACTERISTICS, VENDOR_ID_3GPP),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::vendor(AVP_UE_USAGE_TYPE, VENDOR_ID_3GPP),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::vendor(AVP_CORE_NETWORK_RESTRICTIONS, VENDOR_ID_3GPP),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::vendor(AVP_MPS_PRIORITY, VENDOR_ID_3GPP),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::vendor(AVP_TRACE_INFO, VENDOR_ID_3GPP),
        AvpCardinality::ZeroOrOne,
    ),
];

static TERMINAL_INFORMATION_AVP_RULES: [CommandAvpRule; 2] = [
    CommandAvpRule::new(
        AvpKey::vendor(AVP_IMEI, VENDOR_ID_3GPP),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::vendor(AVP_SOFTWARE_VERSION, VENDOR_ID_3GPP),
        AvpCardinality::ZeroOrOne,
    ),
];

static APN_CONFIGURATION_AVP_RULES: [CommandAvpRule; 14] = [
    CommandAvpRule::new(
        AvpKey::vendor(AVP_CONTEXT_IDENTIFIER, VENDOR_ID_3GPP),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::vendor(AVP_SERVED_PARTY_IP_ADDRESS, VENDOR_ID_3GPP),
        AvpCardinality::ZeroOrMore,
    ),
    CommandAvpRule::new(
        AvpKey::vendor(AVP_PDN_TYPE, VENDOR_ID_3GPP),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(AVP_SERVICE_SELECTION),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::vendor(AVP_EPS_SUBSCRIBED_QOS_PROFILE, VENDOR_ID_3GPP),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::vendor(AVP_VPLMN_DYNAMIC_ADDRESS_ALLOWED, VENDOR_ID_3GPP),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(AvpKey::ietf(AVP_MIP6_AGENT_INFO), AvpCardinality::ZeroOrOne),
    CommandAvpRule::new(
        AvpKey::vendor(AVP_VISITED_NETWORK_IDENTIFIER, VENDOR_ID_3GPP),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::vendor(AVP_PDN_GW_ALLOCATION_TYPE, VENDOR_ID_3GPP),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::vendor(AVP_3GPP_CHARGING_CHARACTERISTICS, VENDOR_ID_3GPP),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::vendor(AVP_AMBR, VENDOR_ID_3GPP),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::vendor(AVP_APN_OI_REPLACEMENT, VENDOR_ID_3GPP),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::vendor(AVP_INTERWORKING_5GS_INDICATOR, VENDOR_ID_3GPP),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::vendor(apn::AVP_SPECIFIC_APN_INFO, VENDOR_ID_3GPP),
        AvpCardinality::ZeroOrMore,
    ),
];

static SPECIFIC_APN_INFO_AVP_RULES: [CommandAvpRule; 3] = [
    CommandAvpRule::new(
        AvpKey::ietf(AVP_SERVICE_SELECTION),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(AvpKey::ietf(AVP_MIP6_AGENT_INFO), AvpCardinality::ZeroOrOne),
    CommandAvpRule::new(
        AvpKey::vendor(AVP_VISITED_NETWORK_IDENTIFIER, VENDOR_ID_3GPP),
        AvpCardinality::ZeroOrOne,
    ),
];

static EPS_SUBSCRIBED_QOS_PROFILE_AVP_RULES: [CommandAvpRule; 2] = [
    CommandAvpRule::new(
        AvpKey::vendor(AVP_QOS_CLASS_IDENTIFIER, VENDOR_ID_3GPP),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::vendor(AVP_ALLOCATION_RETENTION_PRIORITY, VENDOR_ID_3GPP),
        AvpCardinality::ZeroOrOne,
    ),
];

static ALLOCATION_RETENTION_PRIORITY_AVP_RULES: [CommandAvpRule; 3] = [
    CommandAvpRule::new(
        AvpKey::vendor(AVP_PRIORITY_LEVEL, VENDOR_ID_3GPP),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::vendor(AVP_PRE_EMPTION_CAPABILITY, VENDOR_ID_3GPP),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::vendor(AVP_PRE_EMPTION_VULNERABILITY, VENDOR_ID_3GPP),
        AvpCardinality::ZeroOrOne,
    ),
];

static AMBR_AVP_RULES: [CommandAvpRule; 4] = [
    CommandAvpRule::new(
        AvpKey::vendor(AVP_MAX_REQUESTED_BANDWIDTH_UL, VENDOR_ID_3GPP),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::vendor(AVP_MAX_REQUESTED_BANDWIDTH_DL, VENDOR_ID_3GPP),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::vendor(AVP_EXTENDED_MAX_REQUESTED_BANDWIDTH_UL, VENDOR_ID_3GPP),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::vendor(AVP_EXTENDED_MAX_REQUESTED_BANDWIDTH_DL, VENDOR_ID_3GPP),
        AvpCardinality::ZeroOrOne,
    ),
];

static SUPPORTED_FEATURES_AVP_RULES: [CommandAvpRule; 3] = [
    CommandAvpRule::new(AvpKey::ietf(base::AVP_VENDOR_ID), AvpCardinality::ZeroOrOne),
    CommandAvpRule::new(
        AvpKey::vendor(AVP_FEATURE_LIST_ID, VENDOR_ID_3GPP),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::vendor(AVP_FEATURE_LIST, VENDOR_ID_3GPP),
        AvpCardinality::ZeroOrOne,
    ),
];

static SUBSCRIPTION_ID_AVP_RULES: [CommandAvpRule; 2] = [
    CommandAvpRule::new(
        AvpKey::ietf(AVP_SUBSCRIPTION_ID_TYPE),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(AVP_SUBSCRIPTION_ID_DATA),
        AvpCardinality::ZeroOrOne,
    ),
];

static QOS_CAPABILITY_AVP_RULES: [CommandAvpRule; 1] = [CommandAvpRule::new(
    AvpKey::ietf(AVP_QOS_PROFILE_TEMPLATE),
    AvpCardinality::ZeroOrMore,
)];

static QOS_PROFILE_TEMPLATE_AVP_RULES: [CommandAvpRule; 2] = [
    CommandAvpRule::new(AvpKey::ietf(base::AVP_VENDOR_ID), AvpCardinality::ZeroOrOne),
    CommandAvpRule::new(AvpKey::ietf(AVP_QOS_PROFILE_ID), AvpCardinality::ZeroOrOne),
];

static OC_SUPPORTED_FEATURES_AVP_RULES: [CommandAvpRule; 1] = [CommandAvpRule::new(
    AvpKey::ietf(AVP_OC_FEATURE_VECTOR),
    AvpCardinality::ZeroOrOne,
)];

static OC_OLR_AVP_RULES: [CommandAvpRule; 4] = [
    CommandAvpRule::new(
        AvpKey::ietf(AVP_OC_SEQUENCE_NUMBER),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(AVP_OC_VALIDITY_DURATION),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(AvpKey::ietf(AVP_OC_REPORT_TYPE), AvpCardinality::ZeroOrOne),
    CommandAvpRule::new(
        AvpKey::ietf(AVP_OC_REDUCTION_PERCENTAGE),
        AvpCardinality::ZeroOrOne,
    ),
];

static LOAD_AVP_RULES: [CommandAvpRule; 3] = [
    CommandAvpRule::new(AvpKey::ietf(AVP_LOAD_TYPE), AvpCardinality::ZeroOrOne),
    CommandAvpRule::new(AvpKey::ietf(AVP_LOAD_VALUE), AvpCardinality::ZeroOrOne),
    CommandAvpRule::new(AvpKey::ietf(AVP_SOURCE_ID), AvpCardinality::ZeroOrOne),
];

static MIP6_AGENT_INFO_AVP_RULES: [CommandAvpRule; 3] = [
    CommandAvpRule::new(
        AvpKey::ietf(AVP_MIP_HOME_AGENT_ADDRESS),
        AvpCardinality::ZeroOrMore,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(AVP_MIP_HOME_AGENT_HOST),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(AVP_MIP6_HOME_LINK_PREFIX),
        AvpCardinality::ZeroOrOne,
    ),
];

static MIP_HOME_AGENT_HOST_AVP_RULES: [CommandAvpRule; 2] = [
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_DESTINATION_REALM),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(base::AVP_DESTINATION_HOST),
        AvpCardinality::ZeroOrOne,
    ),
];

static EMERGENCY_INFO_AVP_RULES: [CommandAvpRule; 1] = [CommandAvpRule::new(
    AvpKey::ietf(AVP_MIP6_AGENT_INFO),
    AvpCardinality::ZeroOrOne,
)];

static TRACE_INFO_AVP_RULES: [CommandAvpRule; 1] = [CommandAvpRule::new(
    AvpKey::vendor(AVP_TRACE_DATA, VENDOR_ID_3GPP),
    // The dictionary cardinality model records singleton/repeatability. The
    // command-specific parser below separately enforces mandatory presence.
    AvpCardinality::ZeroOrOne,
)];

static TRACE_DATA_AVP_RULES: [CommandAvpRule; 7] = [
    CommandAvpRule::new(
        AvpKey::vendor(AVP_TRACE_REFERENCE, VENDOR_ID_3GPP),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::vendor(AVP_TRACE_DEPTH, VENDOR_ID_3GPP),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::vendor(AVP_TRACE_NE_TYPE_LIST, VENDOR_ID_3GPP),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::vendor(AVP_TRACE_INTERFACE_LIST, VENDOR_ID_3GPP),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::vendor(AVP_TRACE_EVENT_LIST, VENDOR_ID_3GPP),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::vendor(AVP_TRACE_COLLECTION_ENTITY, VENDOR_ID_3GPP),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::vendor(AVP_TRACE_REPORTING_CONSUMER_URI, VENDOR_ID_3GPP),
        AvpCardinality::ZeroOrOne,
    ),
];

/// SWm Diameter-EAP-Request command definition.
pub const COMMAND_DIAMETER_EAP_REQUEST: CommandDefinition = CommandDefinition::new(
    COMMAND_DIAMETER_EAP,
    "Diameter-EAP-Request",
    CommandKind::Request,
    APPLICATION_ID,
    true,
    SpecRef::new("3gpp", "TS29273", "DER"),
)
.with_avp_rules(&SWM_REQUEST_AVP_RULES);

/// SWm Diameter-EAP-Answer command definition.
pub const COMMAND_DIAMETER_EAP_ANSWER: CommandDefinition = CommandDefinition::new(
    COMMAND_DIAMETER_EAP,
    "Diameter-EAP-Answer",
    CommandKind::Answer,
    APPLICATION_ID,
    true,
    SpecRef::new("3gpp", "TS29273", "DEA"),
)
.with_avp_rules(&SWM_ANSWER_AVP_RULES);

/// SWm DEA command profile for an explicitly negotiated APN-Configuration-Profile projection.
///
/// This is intentionally separate from [`COMMAND_DIAMETER_EAP_ANSWER`]: the
/// baseline TS 29.273 DEA grammar permits at most one APN-Configuration, while
/// this opt-in extension projects the repeatable TS 29.272 subscription profile.
pub const COMMAND_DIAMETER_EAP_ANSWER_PROJECTED_PROFILE: CommandDefinition =
    CommandDefinition::new(
        COMMAND_DIAMETER_EAP,
        "Diameter-EAP-Answer (projected APN profile)",
        CommandKind::Answer,
        APPLICATION_ID,
        true,
        SpecRef::new("3gpp", "TS29273", "DEA extension AVP projection"),
    )
    .with_avp_rules(&SWM_PROJECTED_PROFILE_ANSWER_AVP_RULES);

const SWM_AVPS: [AvpDefinition; 86] = [
    AvpDefinition::new(
        AvpKey::ietf(AVP_EAP_PAYLOAD),
        "EAP-Payload",
        AvpDataType::OctetString,
        AvpFlagRules::base_mandatory(),
        SpecRef::new("ietf", "RFC4072", "4.1"),
    ),
    AvpDefinition::new(
        AvpKey::ietf(AVP_EAP_REISSUED_PAYLOAD),
        "EAP-Reissued-Payload",
        AvpDataType::OctetString,
        AvpFlagRules::base_optional(),
        SpecRef::new("ietf", "RFC4072", "4.2"),
    ),
    AvpDefinition::new(
        AvpKey::ietf(AVP_EAP_MASTER_SESSION_KEY),
        "EAP-Master-Session-Key",
        AvpDataType::OctetString,
        AvpFlagRules::base_optional(),
        SpecRef::new("ietf", "RFC4072", "4.3"),
    ),
    AvpDefinition::new(
        AvpKey::ietf(AVP_AUTH_REQUEST_TYPE),
        "Auth-Request-Type",
        AvpDataType::Enumerated,
        AvpFlagRules::base_mandatory(),
        SpecRef::new("ietf", "RFC6733", "8.7"),
    ),
    AvpDefinition::new(
        AvpKey::ietf(AVP_MIP6_FEATURE_VECTOR),
        "MIP6-Feature-Vector",
        AvpDataType::Unsigned64,
        AvpFlagRules::base_optional(),
        SpecRef::new("ietf", "RFC5447", "4.2.5"),
    ),
    AvpDefinition::new(
        AvpKey::ietf(AVP_MIP6_AGENT_INFO),
        "MIP6-Agent-Info",
        AvpDataType::Grouped,
        // Canonical SWm emission follows the defining M setting. TS 29.273's
        // SWm re-use table 7.2.3.1/2 and note 2 require receivers that
        // understand the AVP to ignore an M mismatch.
        // TS 29.272 reuses the understood AVP without a contrary nested flag
        // rule, so the same receive behavior applies inside Emergency-Info.
        AvpFlagRules::base_optional(),
        SpecRef::new("ietf", "RFC5447", "4.2.1"),
    )
    .with_grouped_avp_rules(&MIP6_AGENT_INFO_AVP_RULES),
    AvpDefinition::new(
        AvpKey::ietf(AVP_MIP_HOME_AGENT_ADDRESS),
        "MIP-Home-Agent-Address",
        AvpDataType::Address,
        AvpFlagRules::base_mandatory(),
        SpecRef::new("ietf", "RFC5447", "4.2.2"),
    ),
    AvpDefinition::new(
        AvpKey::ietf(AVP_MIP_HOME_AGENT_HOST),
        "MIP-Home-Agent-Host",
        AvpDataType::Grouped,
        AvpFlagRules::base_mandatory(),
        SpecRef::new("ietf", "RFC4004", "7.11"),
    )
    .with_grouped_avp_rules(&MIP_HOME_AGENT_HOST_AVP_RULES),
    AvpDefinition::new(
        AvpKey::ietf(AVP_MIP6_HOME_LINK_PREFIX),
        "MIP6-Home-Link-Prefix",
        AvpDataType::OctetString,
        AvpFlagRules::base_mandatory(),
        SpecRef::new("ietf", "RFC5447", "4.2.4"),
    ),
    AvpDefinition::new(
        AvpKey::vendor(AVP_EMERGENCY_INFO, VENDOR_ID_3GPP),
        "Emergency-Info",
        AvpDataType::Grouped,
        AvpFlagRules::new(
            FlagRequirement::MustBeSet,
            FlagRequirement::MayBeSet,
            FlagRequirement::MustBeUnset,
        ),
        SpecRef::new("3gpp", "TS29272", "7.3.210"),
    )
    .with_grouped_avp_rules(&EMERGENCY_INFO_AVP_RULES),
    AvpDefinition::new(
        AvpKey::vendor(AVP_TRACE_INFO, VENDOR_ID_3GPP),
        "Trace-Info",
        AvpDataType::Grouped,
        AvpFlagRules::new(
            FlagRequirement::MustBeSet,
            FlagRequirement::MustBeUnset,
            FlagRequirement::MustBeUnset,
        ),
        SpecRef::new("3gpp", "TS29273", "8.2.3.13"),
    )
    .with_grouped_avp_rules(&TRACE_INFO_AVP_RULES),
    AvpDefinition::new(
        AvpKey::vendor(AVP_TRACE_DATA, VENDOR_ID_3GPP),
        "Trace-Data",
        AvpDataType::Grouped,
        AvpFlagRules::new(
            FlagRequirement::MustBeSet,
            FlagRequirement::MustBeSet,
            FlagRequirement::MustBeUnset,
        ),
        SpecRef::new("3gpp", "TS29272", "7.3.63"),
    )
    .with_grouped_avp_rules(&TRACE_DATA_AVP_RULES),
    AvpDefinition::new(
        AvpKey::vendor(AVP_TRACE_REFERENCE, VENDOR_ID_3GPP),
        "Trace-Reference",
        AvpDataType::OctetString,
        AvpFlagRules::new(
            FlagRequirement::MustBeSet,
            FlagRequirement::MustBeSet,
            FlagRequirement::MustBeUnset,
        ),
        SpecRef::new("3gpp", "TS29272", "7.3.64"),
    ),
    AvpDefinition::new(
        AvpKey::vendor(AVP_TRACE_DEPTH, VENDOR_ID_3GPP),
        "Trace-Depth",
        AvpDataType::Enumerated,
        AvpFlagRules::new(
            FlagRequirement::MustBeSet,
            FlagRequirement::MustBeSet,
            FlagRequirement::MustBeUnset,
        ),
        SpecRef::new("3gpp", "TS29272", "7.3.67"),
    ),
    AvpDefinition::new(
        AvpKey::vendor(AVP_TRACE_NE_TYPE_LIST, VENDOR_ID_3GPP),
        "Trace-NE-Type-List",
        AvpDataType::OctetString,
        AvpFlagRules::new(
            FlagRequirement::MustBeSet,
            FlagRequirement::MustBeSet,
            FlagRequirement::MustBeUnset,
        ),
        SpecRef::new("3gpp", "TS29272", "7.3.68"),
    ),
    AvpDefinition::new(
        AvpKey::vendor(AVP_TRACE_INTERFACE_LIST, VENDOR_ID_3GPP),
        "Trace-Interface-List",
        AvpDataType::OctetString,
        AvpFlagRules::new(
            FlagRequirement::MustBeSet,
            FlagRequirement::MustBeSet,
            FlagRequirement::MustBeUnset,
        ),
        SpecRef::new("3gpp", "TS29272", "7.3.69"),
    ),
    AvpDefinition::new(
        AvpKey::vendor(AVP_TRACE_EVENT_LIST, VENDOR_ID_3GPP),
        "Trace-Event-List",
        AvpDataType::OctetString,
        AvpFlagRules::new(
            FlagRequirement::MustBeSet,
            FlagRequirement::MustBeSet,
            FlagRequirement::MustBeUnset,
        ),
        SpecRef::new("3gpp", "TS29272", "7.3.70"),
    ),
    AvpDefinition::new(
        AvpKey::vendor(AVP_TRACE_COLLECTION_ENTITY, VENDOR_ID_3GPP),
        "Trace-Collection-Entity",
        AvpDataType::Address,
        AvpFlagRules::new(
            FlagRequirement::MustBeSet,
            FlagRequirement::MustBeSet,
            FlagRequirement::MustBeUnset,
        ),
        SpecRef::new("3gpp", "TS29272", "7.3.98"),
    ),
    AvpDefinition::new(
        AvpKey::vendor(AVP_TRACE_REPORTING_CONSUMER_URI, VENDOR_ID_3GPP),
        "Trace-Reporting-Consumer-Uri",
        AvpDataType::DiameterUri,
        AvpFlagRules::new(
            FlagRequirement::MustBeSet,
            FlagRequirement::MustBeUnset,
            FlagRequirement::MustBeUnset,
        ),
        SpecRef::new("3gpp", "TS29272", "7.3.252"),
    ),
    AvpDefinition::new(
        AvpKey::vendor(AVP_APN_OI_REPLACEMENT, VENDOR_ID_3GPP),
        "APN-OI-Replacement",
        AvpDataType::Utf8String,
        AvpFlagRules::new(
            FlagRequirement::MustBeSet,
            FlagRequirement::MayBeSet,
            FlagRequirement::MustBeUnset,
        ),
        SpecRef::new("3gpp", "TS29272", "7.3.32"),
    ),
    AvpDefinition::new(
        AvpKey::ietf(AVP_SUBSCRIPTION_ID),
        "Subscription-Id",
        AvpDataType::Grouped,
        AvpFlagRules::new(
            FlagRequirement::MustBeUnset,
            FlagRequirement::MayBeSet,
            FlagRequirement::MayBeSet,
        ),
        SpecRef::new("ietf", "RFC4006", "8.46"),
    )
    .with_grouped_avp_rules(&SUBSCRIPTION_ID_AVP_RULES),
    AvpDefinition::new(
        AvpKey::ietf(AVP_SUBSCRIPTION_ID_TYPE),
        "Subscription-Id-Type",
        AvpDataType::Enumerated,
        AvpFlagRules::new(
            FlagRequirement::MustBeUnset,
            FlagRequirement::MustBeSet,
            FlagRequirement::MayBeSet,
        ),
        SpecRef::new("ietf", "RFC4006", "8.47"),
    ),
    AvpDefinition::new(
        AvpKey::ietf(AVP_SUBSCRIPTION_ID_DATA),
        "Subscription-Id-Data",
        AvpDataType::Utf8String,
        AvpFlagRules::new(
            FlagRequirement::MustBeUnset,
            FlagRequirement::MustBeSet,
            FlagRequirement::MayBeSet,
        ),
        SpecRef::new("ietf", "RFC4006", "8.48"),
    ),
    AvpDefinition::new(
        AvpKey::vendor(AVP_3GPP_CHARGING_CHARACTERISTICS, VENDOR_ID_3GPP),
        "3GPP-Charging-Characteristics",
        AvpDataType::Utf8String,
        AvpFlagRules::new(
            FlagRequirement::MustBeSet,
            FlagRequirement::MayBeSet,
            FlagRequirement::MayBeSet,
        ),
        SpecRef::new("3gpp", "TS29061", "16.4.7"),
    ),
    AvpDefinition::new(
        AvpKey::vendor(AVP_UE_USAGE_TYPE, VENDOR_ID_3GPP),
        "UE-Usage-Type",
        AvpDataType::Unsigned32,
        AvpFlagRules::new(
            FlagRequirement::MustBeSet,
            FlagRequirement::MayBeSet,
            FlagRequirement::MustBeUnset,
        ),
        SpecRef::new("3gpp", "TS29272", "7.3.202"),
    ),
    AvpDefinition::new(
        AvpKey::vendor(AVP_CORE_NETWORK_RESTRICTIONS, VENDOR_ID_3GPP),
        "Core-Network-Restrictions",
        AvpDataType::Unsigned32,
        AvpFlagRules::new(
            FlagRequirement::MustBeSet,
            FlagRequirement::MayBeSet,
            FlagRequirement::MustBeUnset,
        ),
        SpecRef::new("3gpp", "TS29272", "7.3.230"),
    ),
    AvpDefinition::new(
        AvpKey::vendor(AVP_MPS_PRIORITY, VENDOR_ID_3GPP),
        "MPS-Priority",
        AvpDataType::Unsigned32,
        AvpFlagRules::new(
            FlagRequirement::MustBeSet,
            FlagRequirement::MayBeSet,
            FlagRequirement::MustBeUnset,
        ),
        SpecRef::new("3gpp", "TS29272", "7.3.131"),
    ),
    AvpDefinition::new(
        AvpKey::ietf(AVP_QOS_CAPABILITY),
        "QoS-Capability",
        AvpDataType::Grouped,
        // TS 29.273 requires canonical senders to set M, but table
        // 7.2.3.1/1 note 2 requires receivers to ignore a known M mismatch.
        AvpFlagRules::base_optional(),
        SpecRef::new("ietf", "RFC5777", "6"),
    )
    .with_grouped_avp_rules(&QOS_CAPABILITY_AVP_RULES),
    AvpDefinition::new(
        AvpKey::ietf(AVP_QOS_PROFILE_TEMPLATE),
        "QoS-Profile-Template",
        AvpDataType::Grouped,
        AvpFlagRules::base_mandatory(),
        SpecRef::new("ietf", "RFC5777", "5.3"),
    )
    .with_grouped_avp_rules(&QOS_PROFILE_TEMPLATE_AVP_RULES),
    AvpDefinition::new(
        AvpKey::ietf(AVP_QOS_PROFILE_ID),
        "QoS-Profile-Id",
        AvpDataType::Unsigned32,
        AvpFlagRules::base_mandatory(),
        SpecRef::new("ietf", "RFC5777", "5.2"),
    ),
    AvpDefinition::new(
        AvpKey::vendor(AVP_SUPPORTED_FEATURES, VENDOR_ID_3GPP),
        "Supported-Features",
        AvpDataType::Grouped,
        AvpFlagRules::new(
            FlagRequirement::MustBeSet,
            FlagRequirement::MayBeSet,
            FlagRequirement::MustBeUnset,
        ),
        SpecRef::new("3gpp", "TS29229", "6.3.29"),
    )
    .with_grouped_avp_rules(&SUPPORTED_FEATURES_AVP_RULES),
    AvpDefinition::new(
        AvpKey::vendor(AVP_FEATURE_LIST_ID, VENDOR_ID_3GPP),
        "Feature-List-ID",
        AvpDataType::Unsigned32,
        AvpFlagRules::vendor_specific(),
        SpecRef::new("3gpp", "TS29229", "6.3.30"),
    ),
    AvpDefinition::new(
        AvpKey::vendor(AVP_FEATURE_LIST, VENDOR_ID_3GPP),
        "Feature-List",
        AvpDataType::Unsigned32,
        AvpFlagRules::vendor_specific(),
        SpecRef::new("3gpp", "TS29229", "6.3.31"),
    ),
    AvpDefinition::new(
        AvpKey::vendor(AVP_AAR_FLAGS, VENDOR_ID_3GPP),
        "AAR-Flags",
        AvpDataType::Unsigned32,
        AvpFlagRules::new(
            FlagRequirement::MustBeSet,
            FlagRequirement::MustBeUnset,
            FlagRequirement::MustBeUnset,
        ),
        SpecRef::new("3gpp", "TS29273", "7.2.3.5"),
    ),
    AvpDefinition::new(
        AvpKey::vendor(AVP_UE_LOCAL_IP_ADDRESS, VENDOR_ID_3GPP),
        "UE-Local-IP-Address",
        AvpDataType::Address,
        AvpFlagRules::new(
            FlagRequirement::MustBeSet,
            FlagRequirement::MayBeSet,
            FlagRequirement::MustBeUnset,
        ),
        SpecRef::new("3gpp", "TS29212", "5.3.96"),
    ),
    AvpDefinition::new(
        AvpKey::vendor(AVP_RAT_TYPE, VENDOR_ID_3GPP),
        "RAT-Type",
        AvpDataType::Enumerated,
        AvpFlagRules::new(
            FlagRequirement::MustBeSet,
            FlagRequirement::MustBeSet,
            FlagRequirement::MustBeUnset,
        ),
        SpecRef::new("3gpp", "TS29212", "5.3.31"),
    ),
    AvpDefinition::new(
        AvpKey::vendor(AVP_HIGH_PRIORITY_ACCESS_INFO, VENDOR_ID_3GPP),
        "High-Priority-Access-Info",
        AvpDataType::Unsigned32,
        AvpFlagRules::new(
            FlagRequirement::MustBeSet,
            FlagRequirement::MayBeSet,
            FlagRequirement::MustBeUnset,
        ),
        SpecRef::new("3gpp", "TS29273", "5.2.3.36"),
    ),
    AvpDefinition::new(
        AvpKey::vendor(AVP_VISITED_NETWORK_IDENTIFIER, VENDOR_ID_3GPP),
        "Visited-Network-Identifier",
        AvpDataType::OctetString,
        AvpFlagRules::new(
            FlagRequirement::MustBeSet,
            FlagRequirement::MayBeSet,
            FlagRequirement::MustBeUnset,
        ),
        SpecRef::new("3gpp", "TS29273", "9.2.3.1.2"),
    ),
    AvpDefinition::new(
        AvpKey::vendor(AVP_AAA_FAILURE_INDICATION, VENDOR_ID_3GPP),
        "AAA-Failure-Indication",
        AvpDataType::Unsigned32,
        AvpFlagRules::new(
            FlagRequirement::MustBeSet,
            FlagRequirement::MayBeSet,
            FlagRequirement::MustBeUnset,
        ),
        SpecRef::new("3gpp", "TS29273", "8.2.3.21"),
    ),
    AvpDefinition::new(
        AvpKey::vendor(AVP_ACCESS_NETWORK_INFO, VENDOR_ID_3GPP),
        "Access-Network-Info",
        AvpDataType::Grouped,
        // TS 29.273 requires V set and P clear, while table 7.2.3.1/1 note 2
        // allows an understood receiver to ignore an M-bit mismatch.
        AvpFlagRules::new(
            FlagRequirement::MustBeSet,
            FlagRequirement::MayBeSet,
            FlagRequirement::MustBeUnset,
        ),
        SpecRef::new("3gpp", "TS29273", "5.2.3.24"),
    )
    .with_grouped_avp_rules(&ACCESS_NETWORK_INFO_AVP_RULES),
    AvpDefinition::new(
        AvpKey::vendor(AVP_SSID, VENDOR_ID_3GPP),
        "SSID",
        AvpDataType::Utf8String,
        AvpFlagRules::new(
            FlagRequirement::MustBeSet,
            FlagRequirement::MayBeSet,
            FlagRequirement::MustBeUnset,
        ),
        SpecRef::new("3gpp", "TS29273", "5.2.3.22"),
    ),
    AvpDefinition::new(
        AvpKey::vendor(AVP_BSSID, VENDOR_ID_3GPP),
        "BSSID",
        AvpDataType::Utf8String,
        AvpFlagRules::new(
            FlagRequirement::MustBeSet,
            FlagRequirement::MayBeSet,
            FlagRequirement::MayBeSet,
        ),
        SpecRef::new("3gpp", "TS32299", "7.2.30A"),
    ),
    AvpDefinition::new(
        AvpKey::ietf(AVP_LOCATION_INFORMATION),
        "Location-Information",
        AvpDataType::OctetString,
        AvpFlagRules::new(
            FlagRequirement::MustBeUnset,
            FlagRequirement::MayBeSet,
            FlagRequirement::MayBeSet,
        ),
        SpecRef::new("ietf", "RFC5580", "4.2"),
    ),
    AvpDefinition::new(
        AvpKey::ietf(AVP_LOCATION_DATA),
        "Location-Data",
        AvpDataType::OctetString,
        AvpFlagRules::new(
            FlagRequirement::MustBeUnset,
            FlagRequirement::MayBeSet,
            FlagRequirement::MayBeSet,
        ),
        SpecRef::new("ietf", "RFC5580", "4.3"),
    ),
    AvpDefinition::new(
        AvpKey::ietf(AVP_OPERATOR_NAME),
        "Operator-Name",
        AvpDataType::OctetString,
        AvpFlagRules::new(
            FlagRequirement::MustBeUnset,
            FlagRequirement::MayBeSet,
            FlagRequirement::MayBeSet,
        ),
        SpecRef::new("ietf", "RFC5580", "4.1"),
    ),
    AvpDefinition::new(
        AvpKey::vendor(AVP_LOGICAL_ACCESS_ID, VENDOR_ID_ETSI),
        "Logical-Access-ID",
        AvpDataType::OctetString,
        AvpFlagRules::new(
            FlagRequirement::MustBeSet,
            FlagRequirement::MayBeSet,
            FlagRequirement::MayBeSet,
        ),
        SpecRef::new("etsi", "ES283034", "7.3.3"),
    ),
    AvpDefinition::new(
        AvpKey::vendor(AVP_USER_LOCATION_INFO_TIME, VENDOR_ID_3GPP),
        "User-Location-Info-Time",
        AvpDataType::Time,
        AvpFlagRules::new(
            FlagRequirement::MustBeSet,
            FlagRequirement::MayBeSet,
            FlagRequirement::MayBeSet,
        ),
        SpecRef::new("3gpp", "TS29212", "5.3.101"),
    ),
    AvpDefinition::new(
        AvpKey::ietf(AVP_STATE),
        "State",
        AvpDataType::OctetString,
        AvpFlagRules::new(
            FlagRequirement::MustBeUnset,
            FlagRequirement::MustBeSet,
            FlagRequirement::MayBeSet,
        ),
        SpecRef::new("ietf", "RFC4005", "9.3.4"),
    ),
    AvpDefinition::new(
        AvpKey::ietf(AVP_REPLY_MESSAGE),
        "Reply-Message",
        AvpDataType::Utf8String,
        AvpFlagRules::base_mandatory(),
        SpecRef::new("ietf", "RFC4005", "4.9"),
    ),
    AvpDefinition::new(
        AvpKey::ietf(AVP_DRMP),
        "DRMP",
        AvpDataType::Enumerated,
        // TS 29.273 7.2.3.1 note 2 requires receivers to ignore a known
        // DRMP M-bit mismatch. Typed builders still always emit M clear.
        AvpFlagRules::base_optional(),
        SpecRef::new("ietf", "RFC7944", "9.1"),
    ),
    AvpDefinition::new(
        AvpKey::ietf(AVP_OC_SUPPORTED_FEATURES),
        "OC-Supported-Features",
        AvpDataType::Grouped,
        AvpFlagRules::base_optional(),
        SpecRef::new("ietf", "RFC7683", "7.1"),
    )
    .with_grouped_avp_rules(&OC_SUPPORTED_FEATURES_AVP_RULES),
    AvpDefinition::new(
        AvpKey::ietf(AVP_OC_FEATURE_VECTOR),
        "OC-Feature-Vector",
        AvpDataType::Unsigned64,
        AvpFlagRules::base_optional(),
        SpecRef::new("ietf", "RFC7683", "7.2"),
    ),
    AvpDefinition::new(
        AvpKey::ietf(AVP_OC_OLR),
        "OC-OLR",
        AvpDataType::Grouped,
        AvpFlagRules::base_optional(),
        SpecRef::new("ietf", "RFC7683", "7.3"),
    )
    .with_grouped_avp_rules(&OC_OLR_AVP_RULES),
    AvpDefinition::new(
        AvpKey::ietf(AVP_OC_SEQUENCE_NUMBER),
        "OC-Sequence-Number",
        AvpDataType::Unsigned64,
        AvpFlagRules::base_optional(),
        SpecRef::new("ietf", "RFC7683", "7.4"),
    ),
    AvpDefinition::new(
        AvpKey::ietf(AVP_OC_VALIDITY_DURATION),
        "OC-Validity-Duration",
        AvpDataType::Unsigned32,
        AvpFlagRules::base_optional(),
        SpecRef::new("ietf", "RFC7683", "7.5"),
    ),
    AvpDefinition::new(
        AvpKey::ietf(AVP_OC_REPORT_TYPE),
        "OC-Report-Type",
        AvpDataType::Enumerated,
        AvpFlagRules::base_optional(),
        SpecRef::new("ietf", "RFC7683", "7.6"),
    ),
    AvpDefinition::new(
        AvpKey::ietf(AVP_OC_REDUCTION_PERCENTAGE),
        "OC-Reduction-Percentage",
        AvpDataType::Unsigned32,
        AvpFlagRules::base_optional(),
        SpecRef::new("ietf", "RFC7683", "7.7"),
    ),
    AvpDefinition::new(
        AvpKey::ietf(AVP_SOURCE_ID),
        "SourceID",
        AvpDataType::DiameterIdentity,
        AvpFlagRules::base_optional(),
        SpecRef::new("ietf", "RFC8581", "7.3"),
    ),
    AvpDefinition::new(
        AvpKey::ietf(AVP_LOAD),
        "Load",
        AvpDataType::Grouped,
        // TS 29.273 7.2.3.1 note 2 requires receivers to ignore a known
        // Load M-bit mismatch. Lifecycle encoding canonicalizes it to clear.
        AvpFlagRules::base_optional(),
        SpecRef::new("3gpp", "TS29273", "7.2.3.1/2"),
    )
    .with_grouped_avp_rules(&LOAD_AVP_RULES),
    AvpDefinition::new(
        AvpKey::ietf(AVP_LOAD_TYPE),
        "Load-Type",
        AvpDataType::Enumerated,
        AvpFlagRules::base_optional(),
        SpecRef::new("ietf", "RFC8583", "7.2"),
    ),
    AvpDefinition::new(
        AvpKey::ietf(AVP_LOAD_VALUE),
        "Load-Value",
        AvpDataType::Unsigned64,
        AvpFlagRules::base_optional(),
        SpecRef::new("ietf", "RFC8583", "7.3"),
    ),
    AvpDefinition::new(
        AvpKey::ietf(AVP_SERVICE_SELECTION),
        "Service-Selection",
        AvpDataType::Utf8String,
        AvpFlagRules::base_optional(),
        SpecRef::new("ietf", "RFC5778", "6.2"),
    ),
    AvpDefinition::new(
        AvpKey::ietf(AVP_MOBILE_NODE_IDENTIFIER),
        "Mobile-Node-Identifier",
        AvpDataType::Utf8String,
        AvpFlagRules::base_mandatory(),
        SpecRef::new("ietf", "RFC5779", "5.6"),
    ),
    AvpDefinition::new(
        AvpKey::vendor(AVP_EMERGENCY_SERVICES, VENDOR_ID_3GPP),
        "Emergency-Services",
        AvpDataType::Unsigned32,
        AvpFlagRules::new(
            FlagRequirement::MustBeSet,
            FlagRequirement::MustBeUnset,
            FlagRequirement::MustBeUnset,
        ),
        SpecRef::new("3gpp", "TS29273", "7.2.3.4"),
    ),
    AvpDefinition::new(
        AvpKey::vendor(AVP_TERMINAL_INFORMATION, VENDOR_ID_3GPP),
        "Terminal-Information",
        AvpDataType::Grouped,
        AvpFlagRules::new(
            FlagRequirement::MustBeSet,
            FlagRequirement::MustBeSet,
            FlagRequirement::MustBeUnset,
        ),
        SpecRef::new("3gpp", "TS29272", "7.3.3"),
    )
    .with_grouped_avp_rules(&TERMINAL_INFORMATION_AVP_RULES),
    AvpDefinition::new(
        AvpKey::vendor(AVP_IMEI, VENDOR_ID_3GPP),
        "IMEI",
        AvpDataType::Utf8String,
        AvpFlagRules::new(
            FlagRequirement::MustBeSet,
            FlagRequirement::MustBeSet,
            FlagRequirement::MustBeUnset,
        ),
        SpecRef::new("3gpp", "TS29272", "7.3.4"),
    ),
    AvpDefinition::new(
        AvpKey::vendor(AVP_SOFTWARE_VERSION, VENDOR_ID_3GPP),
        "Software-Version",
        AvpDataType::Utf8String,
        AvpFlagRules::new(
            FlagRequirement::MustBeSet,
            FlagRequirement::MustBeSet,
            FlagRequirement::MustBeUnset,
        ),
        SpecRef::new("3gpp", "TS29272", "7.3.5"),
    ),
    AvpDefinition::new(
        AvpKey::vendor(AVP_APN_CONFIGURATION, VENDOR_ID_3GPP),
        "APN-Configuration",
        AvpDataType::Grouped,
        AvpFlagRules::vendor_specific(),
        SpecRef::new("3gpp", "TS29272", "7.3.35"),
    )
    .with_grouped_avp_rules(&APN_CONFIGURATION_AVP_RULES),
    AvpDefinition::new(
        AvpKey::vendor(apn::AVP_SPECIFIC_APN_INFO, VENDOR_ID_3GPP),
        "Specific-APN-Info",
        AvpDataType::Grouped,
        AvpFlagRules::vendor_specific(),
        SpecRef::new("3gpp", "TS29272", "7.3.82"),
    )
    .with_grouped_avp_rules(&SPECIFIC_APN_INFO_AVP_RULES),
    AvpDefinition::new(
        AvpKey::vendor(AVP_CONTEXT_IDENTIFIER, VENDOR_ID_3GPP),
        "Context-Identifier",
        AvpDataType::Unsigned32,
        AvpFlagRules::vendor_specific(),
        SpecRef::new("3gpp", "TS29272", "7.3.27"),
    ),
    AvpDefinition::new(
        AvpKey::vendor(AVP_PDN_TYPE, VENDOR_ID_3GPP),
        "PDN-Type",
        AvpDataType::Enumerated,
        AvpFlagRules::vendor_specific(),
        SpecRef::new("3gpp", "TS29272", "7.3.62"),
    ),
    AvpDefinition::new(
        AvpKey::vendor(AVP_SERVED_PARTY_IP_ADDRESS, VENDOR_ID_3GPP),
        "Served-Party-IP-Address",
        AvpDataType::Address,
        AvpFlagRules::new(
            FlagRequirement::MustBeSet,
            FlagRequirement::MayBeSet,
            FlagRequirement::MustBeUnset,
        ),
        SpecRef::new("3gpp", "TS32299", "7.2.187"),
    ),
    AvpDefinition::new(
        AvpKey::vendor(AVP_VPLMN_DYNAMIC_ADDRESS_ALLOWED, VENDOR_ID_3GPP),
        "VPLMN-Dynamic-Address-Allowed",
        AvpDataType::Enumerated,
        AvpFlagRules::new(
            FlagRequirement::MustBeSet,
            FlagRequirement::MayBeSet,
            FlagRequirement::MustBeUnset,
        ),
        SpecRef::new("3gpp", "TS29272", "7.3.38"),
    ),
    AvpDefinition::new(
        AvpKey::vendor(AVP_PDN_GW_ALLOCATION_TYPE, VENDOR_ID_3GPP),
        "PDN-GW-Allocation-Type",
        AvpDataType::Enumerated,
        AvpFlagRules::new(
            FlagRequirement::MustBeSet,
            FlagRequirement::MayBeSet,
            FlagRequirement::MustBeUnset,
        ),
        SpecRef::new("3gpp", "TS29272", "7.3.44"),
    ),
    AvpDefinition::new(
        AvpKey::vendor(AVP_INTERWORKING_5GS_INDICATOR, VENDOR_ID_3GPP),
        "Interworking-5GS-Indicator",
        AvpDataType::Enumerated,
        AvpFlagRules::new(
            FlagRequirement::MustBeSet,
            FlagRequirement::MayBeSet,
            FlagRequirement::MustBeUnset,
        ),
        SpecRef::new("3gpp", "TS29272", "7.3.231"),
    ),
    AvpDefinition::new(
        AvpKey::vendor(AVP_EPS_SUBSCRIBED_QOS_PROFILE, VENDOR_ID_3GPP),
        "EPS-Subscribed-QoS-Profile",
        AvpDataType::Grouped,
        AvpFlagRules::vendor_specific(),
        SpecRef::new("3gpp", "TS29272", "7.3.37"),
    )
    .with_grouped_avp_rules(&EPS_SUBSCRIBED_QOS_PROFILE_AVP_RULES),
    AvpDefinition::new(
        AvpKey::vendor(AVP_QOS_CLASS_IDENTIFIER, VENDOR_ID_3GPP),
        "QoS-Class-Identifier",
        AvpDataType::Enumerated,
        AvpFlagRules::vendor_specific(),
        SpecRef::new("3gpp", "TS29212", "5.3.17"),
    ),
    AvpDefinition::new(
        AvpKey::vendor(AVP_ALLOCATION_RETENTION_PRIORITY, VENDOR_ID_3GPP),
        "Allocation-Retention-Priority",
        AvpDataType::Grouped,
        AvpFlagRules::vendor_specific(),
        SpecRef::new("3gpp", "TS29212", "5.3.32"),
    )
    .with_grouped_avp_rules(&ALLOCATION_RETENTION_PRIORITY_AVP_RULES),
    AvpDefinition::new(
        AvpKey::vendor(AVP_PRIORITY_LEVEL, VENDOR_ID_3GPP),
        "Priority-Level",
        AvpDataType::Unsigned32,
        AvpFlagRules::vendor_specific(),
        SpecRef::new("3gpp", "TS29212", "5.3.45"),
    ),
    AvpDefinition::new(
        AvpKey::vendor(AVP_PRE_EMPTION_CAPABILITY, VENDOR_ID_3GPP),
        "Pre-emption-Capability",
        AvpDataType::Enumerated,
        AvpFlagRules::vendor_specific(),
        SpecRef::new("3gpp", "TS29212", "5.3.46"),
    ),
    AvpDefinition::new(
        AvpKey::vendor(AVP_PRE_EMPTION_VULNERABILITY, VENDOR_ID_3GPP),
        "Pre-emption-Vulnerability",
        AvpDataType::Enumerated,
        AvpFlagRules::vendor_specific(),
        SpecRef::new("3gpp", "TS29212", "5.3.47"),
    ),
    AvpDefinition::new(
        AvpKey::vendor(AVP_AMBR, VENDOR_ID_3GPP),
        "AMBR",
        AvpDataType::Grouped,
        AvpFlagRules::vendor_specific(),
        SpecRef::new("3gpp", "TS29272", "7.3.41"),
    )
    .with_grouped_avp_rules(&AMBR_AVP_RULES),
    AvpDefinition::new(
        AvpKey::vendor(AVP_MAX_REQUESTED_BANDWIDTH_UL, VENDOR_ID_3GPP),
        "Max-Requested-Bandwidth-UL",
        AvpDataType::Unsigned32,
        AvpFlagRules::vendor_specific(),
        SpecRef::new("3gpp", "TS29214", "5.3.15"),
    ),
    AvpDefinition::new(
        AvpKey::vendor(AVP_MAX_REQUESTED_BANDWIDTH_DL, VENDOR_ID_3GPP),
        "Max-Requested-Bandwidth-DL",
        AvpDataType::Unsigned32,
        AvpFlagRules::vendor_specific(),
        SpecRef::new("3gpp", "TS29214", "5.3.14"),
    ),
    AvpDefinition::new(
        AvpKey::vendor(AVP_EXTENDED_MAX_REQUESTED_BANDWIDTH_UL, VENDOR_ID_3GPP),
        "Extended-Max-Requested-BW-UL",
        AvpDataType::Unsigned32,
        AvpFlagRules::vendor_specific(),
        SpecRef::new("3gpp", "TS29214", "5.3.53"),
    ),
    AvpDefinition::new(
        AvpKey::vendor(AVP_EXTENDED_MAX_REQUESTED_BANDWIDTH_DL, VENDOR_ID_3GPP),
        "Extended-Max-Requested-BW-DL",
        AvpDataType::Unsigned32,
        AvpFlagRules::vendor_specific(),
        SpecRef::new("3gpp", "TS29214", "5.3.52"),
    ),
];

const SWM_COMMANDS: [CommandDefinition; 10] = [
    COMMAND_DIAMETER_EAP_REQUEST,
    COMMAND_DIAMETER_EAP_ANSWER,
    COMMAND_ABORT_SESSION_REQUEST,
    COMMAND_ABORT_SESSION_ANSWER,
    COMMAND_SESSION_TERMINATION_REQUEST,
    COMMAND_SESSION_TERMINATION_ANSWER,
    COMMAND_RE_AUTH_REQUEST,
    COMMAND_RE_AUTH_ANSWER,
    COMMAND_AA_REQUEST,
    COMMAND_AA_ANSWER,
];

const SWM_PROJECTED_PROFILE_COMMANDS: [CommandDefinition; 10] = [
    COMMAND_DIAMETER_EAP_REQUEST,
    COMMAND_DIAMETER_EAP_ANSWER_PROJECTED_PROFILE,
    COMMAND_ABORT_SESSION_REQUEST,
    COMMAND_ABORT_SESSION_ANSWER,
    COMMAND_SESSION_TERMINATION_REQUEST,
    COMMAND_SESSION_TERMINATION_ANSWER,
    COMMAND_RE_AUTH_REQUEST,
    COMMAND_RE_AUTH_ANSWER,
    COMMAND_AA_REQUEST,
    COMMAND_AA_ANSWER,
];

/// Static SWm dictionary covering DER/DEA and typed STR/STA, ASR/ASA,
/// RAR/RAA, and AAR/AAA lifecycle slices.
pub static DICTIONARY: Dictionary = Dictionary::new(
    "diameter-3gpp-swm-subset",
    &[APPLICATION],
    &SWM_COMMANDS,
    &SWM_AVPS,
);

/// Static SWm dictionary for peers explicitly configured for the projected APN profile.
///
/// Supply this dictionary instead of [`DICTIONARY`]. Supplying both makes the
/// DEA grammar ambiguous and dictionary-aware decode fails closed.
pub static PROJECTED_PROFILE_DICTIONARY: Dictionary = Dictionary::new(
    "diameter-3gpp-swm-projected-apn-profile",
    &[APPLICATION],
    &SWM_PROJECTED_PROFILE_COMMANDS,
    &SWM_AVPS,
);

/// Return the static SWm dictionary subset.
pub const fn dictionary() -> &'static Dictionary {
    &DICTIONARY
}

/// Return the opt-in projected APN profile dictionary.
pub const fn projected_profile_dictionary() -> &'static Dictionary {
    &PROJECTED_PROFILE_DICTIONARY
}

/// Auth-Request-Type values used by SWm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthRequestType {
    /// AUTHORIZE_ONLY.
    AuthorizeOnly,
    /// AUTHORIZE_AUTHENTICATE.
    AuthorizeAuthenticate,
    /// Unknown or application-specific value.
    Other(u32),
}

impl AuthRequestType {
    /// Return the wire value.
    pub const fn value(self) -> u32 {
        match self {
            Self::AuthorizeOnly => AUTH_REQUEST_TYPE_AUTHORIZE_ONLY,
            Self::AuthorizeAuthenticate => AUTH_REQUEST_TYPE_AUTHORIZE_AUTHENTICATE,
            Self::Other(v) => v,
        }
    }

    /// Parse from a wire value.
    pub const fn from_value(value: u32) -> Self {
        match value {
            AUTH_REQUEST_TYPE_AUTHORIZE_ONLY => Self::AuthorizeOnly,
            AUTH_REQUEST_TYPE_AUTHORIZE_AUTHENTICATE => Self::AuthorizeAuthenticate,
            other => Self::Other(other),
        }
    }

    /// Return true for AUTHORIZE_AUTHENTICATE.
    pub const fn is_authorize_authenticate(self) -> bool {
        matches!(self, Self::AuthorizeAuthenticate)
    }

    /// Return true for AUTHORIZE_ONLY.
    pub const fn is_authorize_only(self) -> bool {
        matches!(self, Self::AuthorizeOnly)
    }
}

/// Access-network RAT-Type values carried by a SWm DER.
///
/// The ePDG uses [`Self::Wlan`] when it knows that the serving access is WLAN
/// and [`Self::Virtual`] when the access type is not known. Unrecognized values
/// are retained so a proxy can remain forward-compatible without silently
/// rewriting peer input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SwmRatType {
    /// WLAN access.
    Wlan,
    /// Unknown access represented by the TS 29.273 `VIRTUAL` value.
    Virtual,
    /// Unknown or subsequently assigned value.
    ///
    /// Values zero and one alias [`Self::Wlan`] and [`Self::Virtual`]
    /// respectively. They are noncanonical and rejected by outbound builders.
    Other(u32),
}

impl SwmRatType {
    /// Return the TS 29.212 wire value.
    pub const fn value(self) -> u32 {
        match self {
            Self::Wlan => 0,
            Self::Virtual => 1,
            Self::Other(value) => value,
        }
    }

    /// Parse a TS 29.212 wire value without discarding future assignments.
    pub const fn from_value(value: u32) -> Self {
        match value {
            0 => Self::Wlan,
            1 => Self::Virtual,
            other => Self::Other(other),
        }
    }

    const fn is_canonical(self) -> bool {
        !matches!(self, Self::Other(0 | 1))
    }
}

/// Coarse Diameter result-code family mapping for SWm answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SwmResultCategory {
    /// 1xxx.
    Informational,
    /// 2xxx.
    Success,
    /// 3xxx.
    ProtocolError,
    /// 4xxx.
    TransientFailure,
    /// 5xxx.
    PermanentFailure,
    /// Unknown family.
    Unknown,
}

/// Agent-generated SWm delivery failure that may be originated with RFC
/// 6733's generic E-bit answer grammar.
///
/// This intentionally models only the two routing failures a DRA can produce
/// without application processing. Other protocol failures continue through
/// the request-bound [`crate::error_answer`] machinery so required diagnostic
/// evidence cannot be omitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SwmDiameterEapAgentDeliveryFailure {
    /// No eligible destination could receive the request.
    UnableToDeliver,
    /// The explicitly selected `Destination-Host` cannot currently serve the
    /// request.
    TooBusy,
}

impl SwmDiameterEapAgentDeliveryFailure {
    const fn from_result_code(result_code: u32) -> Option<Self> {
        match result_code {
            base::RESULT_CODE_DIAMETER_UNABLE_TO_DELIVER => Some(Self::UnableToDeliver),
            base::RESULT_CODE_DIAMETER_TOO_BUSY => Some(Self::TooBusy),
            _ => None,
        }
    }

    /// Return the exact RFC 6733 base `Result-Code` value.
    #[must_use]
    pub const fn result_code(self) -> u32 {
        match self {
            Self::UnableToDeliver => base::RESULT_CODE_DIAMETER_UNABLE_TO_DELIVER,
            Self::TooBusy => base::RESULT_CODE_DIAMETER_TOO_BUSY,
        }
    }

    const fn is_valid_for(self, request: &SwmDiameterEapRequest) -> bool {
        match self {
            Self::UnableToDeliver => true,
            Self::TooBusy => request.destination_host.is_some(),
        }
    }
}

impl SwmResultCategory {
    /// Classify a result code by its thousand-digit family.
    pub const fn from_result_code(result_code: u32) -> Self {
        match result_code / 1000 {
            1 => Self::Informational,
            2 => Self::Success,
            3 => Self::ProtocolError,
            4 => Self::TransientFailure,
            5 => Self::PermanentFailure,
            _ => Self::Unknown,
        }
    }
}

/// Exactly one Diameter result carried by a SWm DEA.
///
/// RFC 6733 requires `Result-Code` and `Experimental-Result` to be mutually
/// exclusive. Keeping the wire family in the type prevents a 3GPP
/// experimental failure from being mistaken for a base result with the same
/// numeric value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SwmDiameterResult {
    /// Base `Result-Code` AVP.
    Base(u32),
    /// Grouped `Experimental-Result` AVP.
    Experimental {
        /// Vendor-Id child.
        vendor_id: VendorId,
        /// Experimental-Result-Code child.
        code: u32,
    },
}

impl SwmDiameterResult {
    /// Return the numeric result code without discarding its wire family.
    pub const fn code(self) -> u32 {
        match self {
            Self::Base(code) | Self::Experimental { code, .. } => code,
        }
    }

    /// Return the coarse thousand-digit result category.
    pub const fn category(self) -> SwmResultCategory {
        SwmResultCategory::from_result_code(self.code())
    }

    /// Return whether this is exact base `DIAMETER_SUCCESS`.
    pub const fn is_diameter_success(self) -> bool {
        matches!(self, Self::Base(base::RESULT_CODE_DIAMETER_SUCCESS))
    }

    /// Return whether this is exact base `DIAMETER_AUTHORIZATION_REJECTED`.
    ///
    /// RFC 6733 assigns authorization rejection value 5003. Value 4001 is
    /// `DIAMETER_AUTHENTICATION_REJECTED` and intentionally returns false.
    ///
    /// This method classifies one received SWm result. Selecting a downstream
    /// access-protocol response remains product policy.
    ///
    /// @spec IETF RFC6733 7.1.5; 3GPP TS29.273 7.1.2.1.2
    #[must_use]
    pub const fn is_diameter_authorization_rejected(self) -> bool {
        matches!(
            self,
            Self::Base(base::RESULT_CODE_DIAMETER_AUTHORIZATION_REJECTED)
        )
    }

    /// Return whether this is the 3GPP emergency identity-recovery response.
    pub const fn requests_emergency_identity_recovery(self) -> bool {
        matches!(
            self,
            Self::Experimental {
                vendor_id: VENDOR_ID_3GPP,
                code: DIAMETER_ERROR_USER_UNKNOWN,
            }
        )
    }
}

/// RFC 6733 Redirect-Host-Usage cache scope.
///
/// The SDK rejects unassigned values because applying an unknown cache scope
/// would silently broaden or narrow routing policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SwmRedirectHostUsage {
    /// Do not cache the redirect target.
    DontCache,
    /// Cache for this Session-Id only.
    AllSession,
    /// Cache for all requests in the realm.
    AllRealm,
    /// Cache for this realm and application.
    RealmAndApplication,
    /// Cache for this application.
    AllApplication,
    /// Cache for this Destination-Host.
    AllHost,
    /// Cache for this user.
    AllUser,
}

impl SwmRedirectHostUsage {
    /// Parse the assigned RFC 6733 value.
    #[must_use]
    pub const fn from_value(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::DontCache),
            1 => Some(Self::AllSession),
            2 => Some(Self::AllRealm),
            3 => Some(Self::RealmAndApplication),
            4 => Some(Self::AllApplication),
            5 => Some(Self::AllHost),
            6 => Some(Self::AllUser),
            _ => None,
        }
    }

    /// Return the assigned RFC 6733 value.
    #[must_use]
    pub const fn value(self) -> u32 {
        match self {
            Self::DontCache => 0,
            Self::AllSession => 1,
            Self::AllRealm => 2,
            Self::RealmAndApplication => 3,
            Self::AllApplication => 4,
            Self::AllHost => 5,
            Self::AllUser => 6,
        }
    }

    /// Return whether this directive creates a cached route.
    #[must_use]
    pub const fn is_cacheable(self) -> bool {
        !matches!(self, Self::DontCache)
    }

    /// Return RFC 6733 section 6.13's cache-route precedence rank.
    ///
    /// This order intentionally differs from the numeric wire values. A
    /// smaller rank has higher precedence; `DONT_CACHE` creates no route.
    #[must_use]
    pub const fn routing_precedence_rank(self) -> Option<u8> {
        match self {
            Self::DontCache => None,
            Self::AllSession => Some(1),
            Self::AllUser => Some(2),
            Self::RealmAndApplication => Some(3),
            Self::AllRealm => Some(4),
            Self::AllApplication => Some(5),
            Self::AllHost => Some(6),
        }
    }
}

/// Redaction-safe validation failure for an RFC 6733 redirect plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SwmDiameterRedirectError {
    /// Redirect-Indication omitted every Redirect-Host.
    MissingHost,
    /// Redirect-Host count exceeds the typed boundary.
    TooManyHosts,
    /// Combined redirect AVP count exceeds the shared routing boundary.
    TooManyAvps,
    /// A Redirect-Host is not a valid DiameterURI.
    InvalidHost,
    /// A cacheable usage omitted Redirect-Max-Cache-Time.
    MissingMaxCacheTime,
}

impl SwmDiameterRedirectError {
    /// Stable value-free diagnostic code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MissingHost => "swm_diameter_redirect_missing_host",
            Self::TooManyHosts => "swm_diameter_redirect_too_many_hosts",
            Self::TooManyAvps => "swm_diameter_redirect_too_many_avps",
            Self::InvalidHost => "swm_diameter_redirect_invalid_host",
            Self::MissingMaxCacheTime => "swm_diameter_redirect_missing_max_cache_time",
        }
    }
}

impl fmt::Display for SwmDiameterRedirectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Error for SwmDiameterRedirectError {}

/// Wire-ordered RFC 6733 redirect targets plus their exact cache directive.
///
/// Redirect host values are redacted in diagnostics. `usage` and
/// `max_cache_time` preserve wire presence: an absent usage is distinct from
/// an explicitly encoded `DONT_CACHE`, and the SDK never invents a cache
/// lifetime. Wire order is preserved for replay and diagnostics; RFC 6733 does
/// not define it as target preference, and target selection remains consumer
/// policy.
#[derive(Clone, PartialEq, Eq)]
pub struct SwmDiameterRedirect {
    hosts: Vec<Redacted<String>>,
    usage: Option<SwmRedirectHostUsage>,
    max_cache_time: Option<u32>,
}

impl SwmDiameterRedirect {
    /// Construct a validated redirect plan.
    pub fn new(
        hosts: Vec<Redacted<String>>,
        usage: Option<SwmRedirectHostUsage>,
        max_cache_time: Option<u32>,
    ) -> Result<Self, SwmDiameterRedirectError> {
        validate_redirect_values(&hosts, usage, max_cache_time)?;
        Ok(Self {
            hosts,
            usage,
            max_cache_time,
        })
    }

    /// Borrow ordered redirect targets.
    #[must_use]
    pub fn hosts(&self) -> &[Redacted<String>] {
        &self.hosts
    }

    /// Return the exact optional cache scope.
    #[must_use]
    pub const fn usage(&self) -> Option<SwmRedirectHostUsage> {
        self.usage
    }

    /// Return the RFC 6733 effective cache scope.
    ///
    /// Absence defaults to `DONT_CACHE`, while [`Self::usage`] retains the
    /// exact wire-presence distinction.
    #[must_use]
    pub const fn effective_usage(&self) -> SwmRedirectHostUsage {
        match self.usage {
            Some(usage) => usage,
            None => SwmRedirectHostUsage::DontCache,
        }
    }

    /// Return the exact optional cache lifetime in seconds.
    #[must_use]
    pub const fn max_cache_time(&self) -> Option<u32> {
        self.max_cache_time
    }
}

impl fmt::Debug for SwmDiameterRedirect {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwmDiameterRedirect")
            .field("host_count", &self.hosts.len())
            .field("usage", &self.usage)
            .field("max_cache_time_present", &self.max_cache_time.is_some())
            .finish()
    }
}

/// Maximum service lifetime carried by a successful SWm DEA.
///
/// `Session-Timeout` is an RFC 6733 `Unsigned32` measured in seconds. A zero
/// value explicitly means an unlimited session, while absence of the
/// surrounding [`Option`] means the AAA server supplied no timeout. The value
/// is omitted from diagnostic output because it reflects subscriber policy.
///
/// @spec IETF RFC6733 8.13
/// @spec 3GPP TS29273 7.1.2.1.2
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SwmSessionTimeout(u32);

impl SwmSessionTimeout {
    /// Construct a timeout from its exact wire value in seconds.
    #[must_use]
    pub const fn from_seconds(seconds: u32) -> Self {
        Self(seconds)
    }

    /// Construct the explicit RFC 6733 unlimited-session value.
    #[must_use]
    pub const fn unlimited() -> Self {
        Self(0)
    }

    /// Return the exact `Unsigned32` wire value in seconds.
    #[must_use]
    pub const fn seconds(self) -> u32 {
        self.0
    }

    /// Return whether this is the explicit unlimited-session value.
    #[must_use]
    pub const fn is_unlimited(self) -> bool {
        self.0 == 0
    }
}

impl fmt::Debug for SwmSessionTimeout {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SwmSessionTimeout(<redacted>)")
    }
}

/// Maximum response time for one EAP Request in a multi-round SWm exchange.
///
/// `Multi-Round-Time-Out` is an RFC 6733 `Unsigned32` measured in seconds.
/// Every value in the wire domain, including zero, is preserved exactly;
/// absence is represented by the surrounding [`Option`]. This type does not
/// impose a local cap, choose a default, start a clock, or extend the value to
/// any later EAP Request.
///
/// Use [`SwmCorrelatedDiameterEapResponse::current_eap_request_timeout`] before
/// treating a received value as actionable. The raw field remains available
/// so grammar-valid answers retain exact wire provenance even when their
/// result or EAP packet does not make the timer applicable.
///
/// @spec IETF RFC6733 8.19
/// @spec IETF RFC4072 2.5, 3.2, 5
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SwmMultiRoundTimeout(u32);

impl SwmMultiRoundTimeout {
    /// Construct a timeout from its exact `Unsigned32` wire value in seconds.
    #[must_use]
    pub const fn from_seconds(seconds: u32) -> Self {
        Self(seconds)
    }

    /// Return the exact wire value in seconds.
    #[must_use]
    pub const fn seconds(self) -> u32 {
        self.0
    }
}

impl fmt::Debug for SwmMultiRoundTimeout {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SwmMultiRoundTimeout(<redacted>)")
    }
}

/// Typed Emergency-Services bitmask for a SWm DER.
///
/// TS 29.273 defines this AVP as an `Unsigned32`, not a grouped AVP. Only bit
/// zero is assigned. Undefined received bits are discarded as the specification
/// requires, and encoding always clears them.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SwmEmergencyServices {
    emergency_indication: bool,
}

impl SwmEmergencyServices {
    /// Construct a bitmask with an explicit Emergency-Indication value.
    pub const fn new(emergency_indication: bool) -> Self {
        Self {
            emergency_indication,
        }
    }

    /// Construct the emergency-PDN request indication.
    pub const fn emergency_indication() -> Self {
        Self::new(true)
    }

    /// Decode the wire bitmask while discarding every undefined bit.
    pub const fn from_value(value: u32) -> Self {
        Self::new(value & EMERGENCY_SERVICES_EMERGENCY_INDICATION != 0)
    }

    /// Return the canonical wire bitmask with every undefined bit cleared.
    pub const fn value(self) -> u32 {
        if self.emergency_indication {
            EMERGENCY_SERVICES_EMERGENCY_INDICATION
        } else {
            0
        }
    }

    /// Return whether the Emergency-Indication bit is set.
    pub const fn is_emergency_indicated(self) -> bool {
        self.emergency_indication
    }
}

/// Terminal-Information sent by an ePDG in a SWm DER.
#[derive(Clone, PartialEq, Eq)]
pub struct SwmTerminalInformation {
    /// Validated IMEI. Formatting remains redacted through [`Imei`].
    pub imei: Imei,
    /// Optional two-digit IMEI software version.
    pub software_version: Option<Redacted<String>>,
}

impl fmt::Debug for SwmTerminalInformation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwmTerminalInformation")
            .field("imei", &self.imei)
            .field("software_version", &self.software_version)
            .finish()
    }
}

/// TS 33.402 Annex A.4 IMEI-derived MSK.
///
/// Debug output never exposes key bytes. The wrapper zeroizes its storage and
/// must be passed to the existing IKEv2 method-2 shared-key AUTH helper; it is
/// not subscriber-authentication evidence.
pub struct SwmUnauthenticatedEmergencyMsk(Zeroizing<[u8; UNAUTHENTICATED_EMERGENCY_MSK_LEN]>);

impl SwmUnauthenticatedEmergencyMsk {
    /// Borrow the MSK for an authorized cryptographic operation.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl fmt::Debug for SwmUnauthenticatedEmergencyMsk {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SwmUnauthenticatedEmergencyMsk(<redacted>)")
    }
}

/// Derive the unauthenticated-emergency MSK defined by TS 33.402 Annex A.4.
///
/// The TS 33.220 KDF is `HMAC-SHA-256(Key, S)`, where the IMEI is the key and
/// `S = 0x22 || "unauth-emer" || 0x000b`.
pub fn derive_unauthenticated_emergency_msk(imei: &Imei15) -> SwmUnauthenticatedEmergencyMsk {
    const DERIVATION_INPUT: &[u8] = b"\x22unauth-emer\x00\x0b";
    let mut mac = match Hmac::<Sha256>::new_from_slice(imei.as_str().as_bytes()) {
        Ok(mac) => mac,
        Err(_) => unreachable!("HMAC-SHA-256 accepts an IMEI-length key"),
    };
    mac.update(DERIVATION_INPUT);
    let mut output = mac.finalize().into_bytes();
    let mut key = [0_u8; UNAUTHENTICATED_EMERGENCY_MSK_LEN];
    key.copy_from_slice(&output);
    output.as_mut_slice().zeroize();
    SwmUnauthenticatedEmergencyMsk(Zeroizing::new(key))
}

/// Diameter transaction identifiers retained beside parsed typed SWm facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SwmDiameterTransaction {
    hop_by_hop_identifier: u32,
    end_to_end_identifier: u32,
}

impl SwmDiameterTransaction {
    /// Construct the identifiers assigned to one outbound Diameter request.
    pub const fn new(hop_by_hop_identifier: u32, end_to_end_identifier: u32) -> Self {
        Self {
            hop_by_hop_identifier,
            end_to_end_identifier,
        }
    }

    fn from_message(message: &Message<'_>) -> Self {
        Self::new(
            message.header.hop_by_hop_identifier,
            message.header.end_to_end_identifier,
        )
    }

    /// Return the hop-local request/answer correlation identifier.
    pub const fn hop_by_hop_identifier(self) -> u32 {
        self.hop_by_hop_identifier
    }

    /// Return the end-to-end duplicate-detection identifier.
    pub const fn end_to_end_identifier(self) -> u32 {
        self.end_to_end_identifier
    }
}

/// Trusted mobility mode configured locally for one SWm request boundary.
///
/// This is application-side provenance and has no Diameter wire
/// representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SwmLocallyConfiguredMobilityMode {
    /// The ePDG uses a network-based mobility protocol selected locally.
    NetworkBased,
    /// The ePDG assigns the UE address locally without network-based mobility.
    LocalIpAddressAssignment,
}

/// A parsed SWm DER together with its immutable Diameter transaction IDs.
#[derive(Clone, PartialEq, Eq)]
pub struct SwmDiameterEapRequestEnvelope {
    transaction: SwmDiameterTransaction,
    proxiable: bool,
    potentially_retransmitted: bool,
    expected_answer_peer: Option<SwmExpectedAnswerPeer>,
    locally_configured_mobility_mode: Option<SwmLocallyConfiguredMobilityMode>,
    request: SwmDiameterEapRequest,
    proxy_infos: Vec<SwmAdditionalAvp>,
}

impl SwmDiameterEapRequestEnvelope {
    /// Bind outbound DER facts to the identifiers used by their builder.
    ///
    /// The caller must pass these same identifiers to
    /// [`build_swm_diameter_eap_request`]. Parsed inbound messages should use
    /// [`parse_swm_diameter_eap_request_envelope`] instead.
    pub fn for_outbound(
        request: SwmDiameterEapRequest,
        transaction: SwmDiameterTransaction,
    ) -> Self {
        Self {
            transaction,
            proxiable: true,
            potentially_retransmitted: false,
            expected_answer_peer: None,
            locally_configured_mobility_mode: None,
            request,
            proxy_infos: Vec::new(),
        }
    }

    /// Bind an outbound DER to its authenticated answer connection.
    #[must_use]
    pub fn for_outbound_on(
        request: SwmDiameterEapRequest,
        transaction: SwmDiameterTransaction,
        expected_answer_peer: SwmExpectedAnswerPeer,
    ) -> Self {
        Self {
            transaction,
            proxiable: true,
            potentially_retransmitted: false,
            expected_answer_peer: Some(expected_answer_peer),
            locally_configured_mobility_mode: None,
            request,
            proxy_infos: Vec::new(),
        }
    }

    /// Attach trusted answer-peer evidence before transport dispatch.
    #[must_use]
    pub fn with_expected_answer_peer(mut self, peer: SwmExpectedAnswerPeer) -> Self {
        self.expected_answer_peer = Some(peer);
        self
    }

    /// Borrow the authenticated answer-path binding.
    #[must_use]
    pub const fn expected_answer_peer(&self) -> Option<&SwmExpectedAnswerPeer> {
        self.expected_answer_peer.as_ref()
    }

    /// Attach trusted local mobility configuration to this request boundary.
    ///
    /// This does not add a `MIP6-Feature-Vector` to the DER. It is consulted
    /// only when a correlated DEA supplies no explicit mobility selection;
    /// an explicit AAA selection always takes precedence.
    #[must_use]
    pub const fn with_locally_configured_mobility_mode(
        mut self,
        mode: SwmLocallyConfiguredMobilityMode,
    ) -> Self {
        self.locally_configured_mobility_mode = Some(mode);
        self
    }

    /// Return trusted local mobility provenance, if the application attached it.
    #[must_use]
    pub const fn locally_configured_mobility_mode(
        &self,
    ) -> Option<SwmLocallyConfiguredMobilityMode> {
        self.locally_configured_mobility_mode
    }

    /// Borrow the typed DER facts.
    pub const fn request(&self) -> &SwmDiameterEapRequest {
        &self.request
    }

    /// Return the transaction IDs from the validated Diameter header.
    pub const fn transaction(&self) -> SwmDiameterTransaction {
        self.transaction
    }

    /// Return whether this request carries RFC 6733's T bit.
    #[must_use]
    pub const fn is_potentially_retransmitted(&self) -> bool {
        self.potentially_retransmitted
    }

    /// Return the ordered private Proxy-Info count.
    #[must_use]
    pub fn proxy_info_count(&self) -> usize {
        self.proxy_infos.len()
    }

    /// Mark a pending request for failover retransmission.
    ///
    /// The End-to-End identifier and payload stay fixed while the transport
    /// supplies a fresh Hop-by-Hop identifier and authenticated connection.
    pub fn mark_for_failover_retransmission(
        &mut self,
        replacement_hop_by_hop_identifier: u32,
        new_peer: SwmExpectedAnswerPeer,
    ) {
        self.transaction = SwmDiameterTransaction::new(
            replacement_hop_by_hop_identifier,
            self.transaction.end_to_end_identifier(),
        );
        self.potentially_retransmitted = true;
        self.expected_answer_peer = Some(new_peer);
    }

    /// Compare immutable duplicate-cache payload facts.
    ///
    /// Hop-by-Hop, T, and connection generation are intentionally excluded;
    /// End-to-End, P, typed request facts, trusted local mobility context,
    /// Route-Record, extensions, and exact ordered Proxy-Info bytes are
    /// included.
    #[must_use]
    pub fn same_replay_payload(&self, other: &Self) -> bool {
        self.transaction.end_to_end_identifier() == other.transaction.end_to_end_identifier()
            && self.proxiable == other.proxiable
            && self.locally_configured_mobility_mode == other.locally_configured_mobility_mode
            && self.request == other.request
            && lifecycle::additional_avp_sequences_match(&self.proxy_infos, &other.proxy_infos)
    }

    /// Consume a DEA envelope and bind it to this request.
    ///
    /// This checks both Diameter identifiers plus Session-Id, application, and
    /// Auth-Request-Type. Live transports must consume their pending-request
    /// entry before calling this codec-level correlation step.
    pub fn correlate_answer(
        self,
        answer: SwmDiameterEapAnswerEnvelope,
    ) -> Result<SwmCorrelatedDiameterEapExchange, SwmEmergencyAuthorizationError> {
        ensure_correlated_answer(&self, &answer)?;
        let effective_mobility_mode = effective_mobility_mode(&self, answer.answer());
        let mobility_mode_source =
            effective_mobility_mode_source(&self, answer.answer(), effective_mobility_mode);
        Ok(SwmCorrelatedDiameterEapExchange {
            request: self,
            answer,
            effective_mobility_mode,
            mobility_mode_source,
        })
    }

    /// Correlate a response received on an authenticated Diameter connection.
    ///
    /// This is the only API that exposes parsed redirect targets. It checks
    /// connection generation, both transaction identifiers, P, exact ordered
    /// Proxy-Info, and Session-Id when the generic grammar carried it. Exact
    /// 3002/3004 delivery failures require Session-Id plus the separately
    /// configured authenticated-agent Origin pair. The transport must
    /// atomically consume the matching pending entry before calling this
    /// codec-level correlation step.
    pub fn correlate_response(
        self,
        response: SwmDiameterEapResponseEnvelope,
    ) -> Result<SwmCorrelatedDiameterEapResponse, SwmDiameterEapCorrelationError> {
        ensure_correlated_response(&self, &response)?;
        Ok(SwmCorrelatedDiameterEapResponse {
            request: self,
            response,
        })
    }
}

impl fmt::Debug for SwmDiameterEapRequestEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwmDiameterEapRequestEnvelope")
            .field("transaction", &self.transaction)
            .field("proxiable", &self.proxiable)
            .field("potentially_retransmitted", &self.potentially_retransmitted)
            .field("expected_answer_peer", &self.expected_answer_peer)
            .field(
                "locally_configured_mobility_mode",
                &self.locally_configured_mobility_mode,
            )
            .field("request", &self.request)
            .field("proxy_info_count", &self.proxy_infos.len())
            .finish()
    }
}

/// A parsed SWm DEA together with its immutable Diameter transaction IDs.
#[derive(PartialEq, Eq)]
pub struct SwmDiameterEapAnswerEnvelope {
    transaction: SwmDiameterTransaction,
    proxiable: bool,
    answer: SwmDiameterEapAnswer,
    proxy_infos: Vec<SwmAdditionalAvp>,
    provenance: SwmDiameterEapAnswerEnvelopeProvenance,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SwmDiameterEapAnswerEnvelopeProvenance {
    Parsed,
    Outbound,
}

/// Opaque request/answer pair with all SWm and Diameter correlation checked.
pub struct SwmCorrelatedDiameterEapExchange {
    request: SwmDiameterEapRequestEnvelope,
    answer: SwmDiameterEapAnswerEnvelope,
    effective_mobility_mode: Option<SwmLocallyConfiguredMobilityMode>,
    mobility_mode_source: Option<SwmConditionalValueSource>,
}

impl SwmCorrelatedDiameterEapExchange {
    /// Borrow the correlated DER facts.
    pub const fn request(&self) -> &SwmDiameterEapRequest {
        self.request.request()
    }

    /// Borrow the correlated DEA facts.
    pub const fn answer(&self) -> &SwmDiameterEapAnswer {
        self.answer.answer()
    }

    /// Return the identifiers shared by the correlated DER and DEA.
    pub const fn transaction(&self) -> SwmDiameterTransaction {
        self.request.transaction()
    }

    /// Authorize the optional top-level Serving-GW identity after exact DER/DEA
    /// correlation and a caller assertion that this is a chained S2b-S8 flow.
    pub fn authorize_chained_s2b_s8_gateway(
        &self,
        authorization: SwmChainedS2bS8Authorization,
    ) -> Result<Option<SwmAuthorizedGateway<'_>>, SwmGatewayContextError> {
        mobility::authorize_chained_gateway(self.answer(), authorization)
    }

    /// Authorize the emergency PDN-GW after exact DER/DEA correlation and a
    /// caller assertion of authenticated non-roaming HSS provenance.
    pub fn authorize_authenticated_non_roaming_emergency_gateway(
        &self,
        authorization: SwmAuthenticatedNonRoamingEmergencyAuthorization,
    ) -> Result<SwmAuthorizedGateway<'_>, SwmGatewayContextError> {
        mobility::authorize_emergency_gateway(self.request(), self.answer(), authorization)
    }

    /// Return the effective mobility-mode provenance for this exchange.
    ///
    /// An explicit DEA `MIP6-Feature-Vector` is AAA-derived and takes
    /// precedence. Otherwise this reports trusted local configuration attached
    /// to the request envelope, or `None` when neither source exists.
    #[must_use]
    pub const fn mobility_mode_source(&self) -> Option<SwmConditionalValueSource> {
        self.mobility_mode_source
    }

    /// Return the effective mobility mode after applying AAA precedence.
    ///
    /// Explicit DEA network-based bits select `NetworkBased`; explicit
    /// `ASSIGN_LOCAL_IP` selects `LocalIpAddressAssignment`; an explicit vector
    /// containing neither selection produces `None` without falling back to
    /// local configuration. When the DEA omits the vector, the trusted local
    /// request-envelope mode is used.
    #[must_use]
    pub const fn effective_mobility_mode(&self) -> Option<SwmLocallyConfiguredMobilityMode> {
        self.effective_mobility_mode
    }

    /// Return the raw local mobility input retained with the request.
    ///
    /// Inspect [`Self::answer`] for an explicit AAA `MIP6-Feature-Vector`; that
    /// value takes precedence over this retained fallback, as indicated by
    /// [`Self::mobility_mode_source`].
    #[must_use]
    pub const fn local_mobility_mode_input(&self) -> Option<SwmLocallyConfiguredMobilityMode> {
        self.request.locally_configured_mobility_mode()
    }
}

impl fmt::Debug for SwmCorrelatedDiameterEapExchange {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwmCorrelatedDiameterEapExchange")
            .field("transaction", &self.transaction())
            .field("request", &self.request())
            .field("answer", &self.answer())
            .field("effective_mobility_mode", &self.effective_mobility_mode)
            .field("mobility_mode_source", &self.mobility_mode_source)
            .finish()
    }
}

impl SwmDiameterEapAnswerEnvelope {
    /// Bind outbound DEA facts to the request identifiers they answer.
    ///
    /// The caller must pass these same identifiers to
    /// [`build_swm_diameter_eap_answer`]. Parsed inbound messages should use
    /// [`parse_swm_diameter_eap_answer_envelope`] instead.
    pub fn for_outbound(answer: SwmDiameterEapAnswer, transaction: SwmDiameterTransaction) -> Self {
        Self {
            transaction,
            proxiable: true,
            answer,
            proxy_infos: Vec::new(),
            provenance: SwmDiameterEapAnswerEnvelopeProvenance::Outbound,
        }
    }

    /// Borrow the typed DEA facts.
    pub const fn answer(&self) -> &SwmDiameterEapAnswer {
        &self.answer
    }

    /// Return the transaction IDs from the validated Diameter header.
    pub const fn transaction(&self) -> SwmDiameterTransaction {
        self.transaction
    }

    /// Return the private ordered Proxy-Info count.
    #[must_use]
    pub fn proxy_info_count(&self) -> usize {
        self.proxy_infos.len()
    }
}

impl fmt::Debug for SwmDiameterEapAnswerEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwmDiameterEapAnswerEnvelope")
            .field("transaction", &self.transaction)
            .field("proxiable", &self.proxiable)
            .field("answer", &self.answer)
            .field("proxy_info_count", &self.proxy_infos.len())
            .finish()
    }
}

/// A parsed Diameter-EAP response bound to its authenticated connection.
#[derive(Clone)]
pub struct SwmDiameterEapResponseEnvelope {
    transaction: SwmDiameterTransaction,
    proxiable: bool,
    received_on: SwmDiameterConnectionToken,
    response: SwmDiameterEapResponse,
    proxy_infos: Vec<SwmAdditionalAvp>,
}

impl SwmDiameterEapResponseEnvelope {
    /// Borrow the typed response without exposing uncorrelated redirect hosts.
    #[must_use]
    pub const fn response(&self) -> &SwmDiameterEapResponse {
        &self.response
    }

    /// Return the Diameter transaction identifiers.
    #[must_use]
    pub const fn transaction(&self) -> SwmDiameterTransaction {
        self.transaction
    }

    /// Return the authenticated connection generation.
    #[must_use]
    pub const fn received_on(&self) -> SwmDiameterConnectionToken {
        self.received_on
    }

    /// Return the private ordered Proxy-Info count.
    #[must_use]
    pub fn proxy_info_count(&self) -> usize {
        self.proxy_infos.len()
    }
}

impl fmt::Debug for SwmDiameterEapResponseEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwmDiameterEapResponseEnvelope")
            .field("transaction", &self.transaction)
            .field("proxiable", &self.proxiable)
            .field("received_on", &self.received_on)
            .field("response", &self.response)
            .field("proxy_info_count", &self.proxy_infos.len())
            .finish()
    }
}

/// Strict response-correlation failure for Diameter-EAP routing decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SwmDiameterEapCorrelationError {
    /// The request lacks authenticated connection evidence.
    PeerBindingMissing,
    /// The answer arrived on a different connection generation.
    PeerConnectionMismatch,
    /// Hop-by-Hop or End-to-End identifiers differ.
    TransactionMismatch,
    /// The answer did not preserve the P bit.
    ProxiableMismatch,
    /// The ordered Proxy-Info chain differs.
    ProxyInfoMismatch,
    /// Session-Id correlation failed.
    SessionMismatch,
    /// A 3002/3004 answer has no authenticated agent Origin authority.
    AgentAuthorityMissing,
    /// A 3002/3004 answer does not match the authenticated agent Origin.
    AgentIdentityMismatch,
    /// An ordinary answer violates its trusted logical-origin policy.
    PeerIdentityMismatch,
    /// Ordinary application correlation fields are inconsistent.
    ApplicationMismatch,
}

impl SwmDiameterEapCorrelationError {
    /// Stable value-free diagnostic code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PeerBindingMissing => "swm_dea_peer_binding_missing",
            Self::PeerConnectionMismatch => "swm_dea_peer_connection_mismatch",
            Self::TransactionMismatch => "swm_dea_transaction_mismatch",
            Self::ProxiableMismatch => "swm_dea_proxiable_mismatch",
            Self::ProxyInfoMismatch => "swm_dea_proxy_info_mismatch",
            Self::SessionMismatch => "swm_dea_session_mismatch",
            Self::AgentAuthorityMissing => "swm_dea_agent_authority_missing",
            Self::AgentIdentityMismatch => "swm_dea_agent_identity_mismatch",
            Self::PeerIdentityMismatch => "swm_dea_peer_identity_mismatch",
            Self::ApplicationMismatch => "swm_dea_application_mismatch",
        }
    }
}

impl fmt::Display for SwmDiameterEapCorrelationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Error for SwmDiameterEapCorrelationError {}

/// Authenticated, transaction-bound Diameter-EAP response.
pub struct SwmCorrelatedDiameterEapResponse {
    request: SwmDiameterEapRequestEnvelope,
    response: SwmDiameterEapResponseEnvelope,
}

/// Correlation-authorized typed view of WLAN location facts from an ordinary DEA.
///
/// This value can be obtained only after authenticated connection-generation,
/// Origin, transaction, application, session, P-bit, and Proxy-Info checks have
/// succeeded. It borrows the parsed response and cannot outlive that evidence.
#[derive(Clone, Copy)]
pub struct SwmCorrelatedWlanLocation<'a> {
    access_network_info: &'a SwmAccessNetworkInfo,
    user_location_info_time: Option<SwmUserLocationInfoTime>,
    user_location_info_time_omission: Option<SwmUserLocationInfoTimeOmission>,
}

impl<'a> SwmCorrelatedWlanLocation<'a> {
    /// Borrow the WLAN SSID, locator, civic, operator, and extension facts.
    #[must_use]
    pub const fn access_network_info(&self) -> &'a SwmAccessNetworkInfo {
        self.access_network_info
    }

    /// Return the last-known WLAN location timestamp when the DEA supplied it.
    #[must_use]
    pub const fn user_location_info_time(&self) -> Option<SwmUserLocationInfoTime> {
        self.user_location_info_time
    }

    /// Return typed evidence that the received or originated location omitted
    /// its timestamp.
    #[must_use]
    pub const fn user_location_info_time_omission(
        &self,
    ) -> Option<SwmUserLocationInfoTimeOmission> {
        self.user_location_info_time_omission
    }
}

impl fmt::Debug for SwmCorrelatedWlanLocation<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwmCorrelatedWlanLocation")
            .field("access_network_info", &self.access_network_info)
            .field(
                "user_location_info_time_present",
                &self.user_location_info_time.is_some(),
            )
            .field(
                "user_location_info_time_omission_present",
                &self.user_location_info_time_omission.is_some(),
            )
            .finish()
    }
}

impl SwmCorrelatedDiameterEapResponse {
    /// Borrow the correlated request.
    #[must_use]
    pub const fn request(&self) -> &SwmDiameterEapRequest {
        self.request.request()
    }

    /// Borrow the correlated response.
    #[must_use]
    pub const fn response(&self) -> &SwmDiameterEapResponse {
        self.response.response()
    }

    /// Borrow WLAN location facts after complete authenticated correlation.
    ///
    /// The raw parsed-answer API exposes only location presence metadata and
    /// has no SSID, BSSID, civic, operator, logical-access, or timestamp value
    /// accessor. Those typed accessors become available only through this
    /// correlated view.
    #[must_use]
    pub fn wlan_location(&self) -> Option<SwmCorrelatedWlanLocation<'_>> {
        let SwmDiameterEapResponse::Application(answer) = self.response() else {
            return None;
        };
        answer
            .extensions
            .access_network_info
            .as_ref()
            .map(|access| SwmCorrelatedWlanLocation {
                access_network_info: access,
                user_location_info_time: answer.extensions.user_location_info_time,
                user_location_info_time_omission: answer
                    .extensions
                    .user_location_info_time_omission,
            })
    }

    /// Borrow correlated typed command-268 trace activation data.
    ///
    /// This value is available only after authenticated connection-generation,
    /// exact Origin, transaction, application, session, P-bit, and Proxy-Info
    /// correlation. The raw DEA surface exposes presence only. This accessor
    /// does not authorize executing the trace: result handling, endpoint trust,
    /// and trace policy remain product-owned. Cloning this receive-derived
    /// value does not make that clone valid for a new origination; canonical
    /// replay remains available only through the parsed envelope. A caller may
    /// explicitly reconstruct fresh values through validated public
    /// constructors when its own policy authorizes a new trace.
    #[must_use]
    pub fn trace_info(&self) -> Option<&SwmTraceInfo> {
        let SwmDiameterEapResponse::Application(answer) = self.response() else {
            return None;
        };
        answer.extensions.trace_info.as_ref()
    }

    /// Return the timeout that applies to the current `EAP-Payload` Request.
    ///
    /// A value is actionable only after complete authenticated response
    /// correlation and only for an ordinary DEA carrying exact base
    /// `DIAMETER_MULTI_ROUND_AUTH` plus one structurally valid EAP Request in
    /// `EAP-Payload`. An EAP Request carried only in `EAP-Reissued-Payload`, a
    /// same-numbered `Experimental-Result`, a final EAP Success or Failure, a
    /// malformed packet, or any other result returns `None`. The raw typed DEA
    /// field remains available to preserve grammar-valid wire facts.
    ///
    /// The returned value applies to this EAP Request alone. Clock selection,
    /// local bounds/defaults, timer scheduling, retransmission, cancellation,
    /// persistence, and attach teardown remain product policy.
    ///
    /// @spec IETF RFC6733 8.19
    /// @spec IETF RFC4072 2.5
    #[must_use]
    pub fn current_eap_request_timeout(&self) -> Option<SwmMultiRoundTimeout> {
        let SwmDiameterEapResponse::Application(answer) = self.response() else {
            return None;
        };
        if answer.authorization_outcome() != SwmAuthorizationOutcome::EapInProgress {
            return None;
        }
        let payload = answer.eap_payload.as_ref()?.as_ref();
        if classify_outer_eap_packet(payload) != Some(OuterEapPacketCode::Request) {
            return None;
        }
        answer.multi_round_timeout
    }

    /// Borrow actionable redirect targets after all correlation checks.
    #[must_use]
    pub fn redirect(&self) -> Option<&SwmDiameterRedirect> {
        match self.response.response() {
            SwmDiameterEapResponse::GenericError(answer) => answer.redirect.as_ref(),
            SwmDiameterEapResponse::Application(_) => None,
        }
    }

    /// Return an actionable DRA delivery failure after complete correlation.
    ///
    /// This accessor recognizes only exact base
    /// `DIAMETER_UNABLE_TO_DELIVER` and `DIAMETER_TOO_BUSY`. Redirect and every
    /// other generic 3xxx result return `None`. Reaching this method proves the
    /// response arrived on the authenticated connection generation to which
    /// the DER was dispatched and matched its transaction, P bit, required
    /// Session-Id, ordered Proxy-Info chain, and separately configured exact
    /// authenticated-agent Origin pair. The transport must atomically consume
    /// its pending entry before correlation; a codec envelope alone cannot
    /// prove liveness or make a duplicate actionable.
    #[must_use]
    pub fn agent_delivery_failure(&self) -> Option<SwmDiameterEapAgentDeliveryFailure> {
        match self.response.response() {
            SwmDiameterEapResponse::GenericError(answer) => {
                SwmDiameterEapAgentDeliveryFailure::from_result_code(answer.result_code)
            }
            SwmDiameterEapResponse::Application(_) => None,
        }
    }

    /// Return the correlated Diameter identifiers.
    #[must_use]
    pub const fn transaction(&self) -> SwmDiameterTransaction {
        self.request.transaction()
    }

    /// Authorize the optional top-level Serving-GW identity after authenticated
    /// connection and exact application-response correlation.
    pub fn authorize_chained_s2b_s8_gateway(
        &self,
        authorization: SwmChainedS2bS8Authorization,
    ) -> Result<Option<SwmAuthorizedGateway<'_>>, SwmGatewayContextError> {
        match self.response() {
            SwmDiameterEapResponse::Application(answer) => {
                mobility::authorize_chained_gateway(answer, authorization)
            }
            SwmDiameterEapResponse::GenericError(_) => Err(mobility::gateway_context_unavailable()),
        }
    }

    /// Authorize the emergency PDN-GW after authenticated connection and exact
    /// application-response correlation.
    pub fn authorize_authenticated_non_roaming_emergency_gateway(
        &self,
        authorization: SwmAuthenticatedNonRoamingEmergencyAuthorization,
    ) -> Result<SwmAuthorizedGateway<'_>, SwmGatewayContextError> {
        match self.response() {
            SwmDiameterEapResponse::Application(answer) => {
                mobility::authorize_emergency_gateway(self.request(), answer, authorization)
            }
            SwmDiameterEapResponse::GenericError(_) => Err(mobility::gateway_context_unavailable()),
        }
    }
}

impl fmt::Debug for SwmCorrelatedDiameterEapResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwmCorrelatedDiameterEapResponse")
            .field("transaction", &self.transaction())
            .field("request", &self.request())
            .field("response", &self.response())
            .field("redirect_present", &self.redirect().is_some())
            .field("wlan_location_present", &self.wlan_location().is_some())
            .field("trace_info_present", &self.trace_info().is_some())
            .field(
                "current_eap_request_timeout_present",
                &self.current_eap_request_timeout().is_some(),
            )
            .field(
                "agent_delivery_failure_present",
                &self.agent_delivery_failure().is_some(),
            )
            .finish()
    }
}

/// Standards path that produced emergency authorization evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SwmEmergencyAuthorizationPath {
    /// A UICC-less UE supplied its IMEI Emergency NAI in the initial exchange.
    DirectEmergencyIdentity,
    /// The ePDG recovered IMEI after a 3GPP vendor-10415/code-5001 response.
    RecoveredDeviceIdentity,
}

/// Redaction-safe proof that a correlated emergency exchange returned the
/// exact IMEI-derived MSK required by TS 33.402.
///
/// The request and answer envelopes bind both Diameter identifiers. The caller
/// must additionally have consumed the matching live pending-request entry;
/// parsing a stored answer again is not proof that it is still pending.
pub struct SwmEmergencyAuthorizationEvidence {
    path: SwmEmergencyAuthorizationPath,
    msk: SwmUnauthenticatedEmergencyMsk,
}

impl SwmEmergencyAuthorizationEvidence {
    /// Verify a UICC-less direct emergency exchange.
    pub fn verify_direct(
        exchange: SwmCorrelatedDiameterEapExchange,
        imei: &Imei15,
    ) -> Result<Self, SwmEmergencyAuthorizationError> {
        let request = exchange.request();
        ensure_emergency_request(request)?;
        if request.terminal_information.is_some() {
            return Err(SwmEmergencyAuthorizationError::InitialTerminalInformationUnexpected);
        }
        let expected_nai = emergency_nai(imei);
        if request
            .user_name
            .as_ref()
            .map(Redacted::as_ref)
            .map(String::as_str)
            != Some(expected_nai.as_str())
        {
            return Err(SwmEmergencyAuthorizationError::InitialIdentityMismatch);
        }
        ensure_eap_response_identity(request, expected_nai.as_bytes())?;
        let msk = verify_final_emergency_answer(&exchange, imei)?;
        Ok(Self {
            path: SwmEmergencyAuthorizationPath::DirectEmergencyIdentity,
            msk,
        })
    }

    /// Verify the IMSI-to-IMEI recovery sequence defined by TS 33.402 §13.3.
    pub fn verify_after_identity_recovery(
        initial_exchange: SwmCorrelatedDiameterEapExchange,
        retry_exchange: SwmCorrelatedDiameterEapExchange,
        imei: &Imei15,
    ) -> Result<Self, SwmEmergencyAuthorizationError> {
        let initial_request = initial_exchange.request();
        let identity_response = initial_exchange.answer();
        let retry_request = retry_exchange.request();
        ensure_emergency_request(initial_request)?;
        if initial_request.terminal_information.is_some() {
            return Err(SwmEmergencyAuthorizationError::InitialTerminalInformationUnexpected);
        }
        let initial_identity = initial_request
            .user_name
            .as_ref()
            .map(Redacted::as_ref)
            .map(String::as_str)
            .ok_or(SwmEmergencyAuthorizationError::IdentityRecoveryInitialIdentityInvalid)?;
        if !is_imsi_emergency_nai(initial_identity) {
            return Err(SwmEmergencyAuthorizationError::IdentityRecoveryInitialIdentityInvalid);
        }
        ensure_eap_response_identity(initial_request, initial_identity.as_bytes())?;
        if !identity_response
            .result
            .requests_emergency_identity_recovery()
        {
            return Err(SwmEmergencyAuthorizationError::IdentityRecoveryNotRequested);
        }
        if identity_response.carries_eap_material()
            || identity_response.mobile_node_identifier.is_some()
        {
            return Err(
                SwmEmergencyAuthorizationError::IdentityRecoveryResponseHasAuthorizationMaterial,
            );
        }
        if !retry_request.requests_emergency_services() {
            return Err(SwmEmergencyAuthorizationError::RetryRequestMismatch);
        }
        retry_request
            .validate_for_encode()
            .map_err(|_| SwmEmergencyAuthorizationError::RetryRequestMismatch)?;
        if initial_request.session_id.as_ref() != retry_request.session_id.as_ref() {
            return Err(SwmEmergencyAuthorizationError::SessionMismatch);
        }
        if initial_exchange.transaction() == retry_exchange.transaction() {
            return Err(SwmEmergencyAuthorizationError::RetryRequestMismatch);
        }
        if initial_request.user_name.as_ref().map(Redacted::as_ref)
            != retry_request.user_name.as_ref().map(Redacted::as_ref)
        {
            return Err(SwmEmergencyAuthorizationError::RetryUserIdentityMismatch);
        }
        if !retry_preserves_initial_request(initial_request, retry_request) {
            return Err(SwmEmergencyAuthorizationError::RetryRequestMismatch);
        }
        let terminal = retry_request
            .terminal_information
            .as_ref()
            .ok_or(SwmEmergencyAuthorizationError::RetryTerminalInformationMissing)?;
        if terminal.imei.as_str() != imei.as_str() {
            return Err(SwmEmergencyAuthorizationError::RetryDeviceIdentityMismatch);
        }
        ensure_eap_response_identity(retry_request, initial_identity.as_bytes())?;
        let msk = verify_final_emergency_answer(&retry_exchange, imei)?;
        Ok(Self {
            path: SwmEmergencyAuthorizationPath::RecoveredDeviceIdentity,
            msk,
        })
    }

    /// Return the standards path used by this exchange.
    pub const fn path(&self) -> SwmEmergencyAuthorizationPath {
        self.path
    }

    /// Borrow the verified IMEI-derived MSK for ordinary IKEv2 method-2 AUTH.
    pub const fn msk(&self) -> &SwmUnauthenticatedEmergencyMsk {
        &self.msk
    }

    /// Stable redaction-safe audit label.
    pub const fn as_str(&self) -> &'static str {
        "emergency_imei_msk_authorized"
    }
}

impl fmt::Debug for SwmEmergencyAuthorizationEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwmEmergencyAuthorizationEvidence")
            .field("path", &self.path)
            .field("msk", &"<redacted>")
            .finish()
    }
}

/// Fail-closed errors while correlating an unauthenticated emergency exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwmEmergencyAuthorizationError {
    /// The initiating DER did not have the required SWm request shape.
    InitialRequestInvalid,
    /// The initiating DER did not request emergency services.
    InitialRequestNotEmergency,
    /// The direct request did not carry the expected IMEI Emergency NAI.
    InitialIdentityMismatch,
    /// The initiating EAP payload was not an exact EAP-Response/Identity.
    InitialEapIdentityInvalid,
    /// EAP-Response/Identity did not equal the correlated User-Name.
    InitialEapIdentityMismatch,
    /// The first DER already contained Terminal-Information.
    InitialTerminalInformationUnexpected,
    /// Recovery did not begin with an exact IMSI-based emergency NAI.
    IdentityRecoveryInitialIdentityInvalid,
    /// Request and answer Session-Id values differ.
    SessionMismatch,
    /// Request and answer Diameter transaction identifiers differ.
    DiameterTransactionMismatch,
    /// An answer changed request-correlated application/authentication fields.
    AnswerRequestMismatch,
    /// An answer violated the typed SWm message invariants.
    AnswerInvalid,
    /// The intermediate answer was not 3GPP vendor 10415/code 5001.
    IdentityRecoveryNotRequested,
    /// The recovery response ambiguously carried authorization material.
    IdentityRecoveryResponseHasAuthorizationMaterial,
    /// The retry changed the original User-Name.
    RetryUserIdentityMismatch,
    /// The retry changed a parameter other than adding Terminal-Information.
    RetryRequestMismatch,
    /// The retry omitted Terminal-Information.
    RetryTerminalInformationMissing,
    /// Terminal-Information did not carry the recovered IMEI.
    RetryDeviceIdentityMismatch,
    /// The final answer was not exact base DIAMETER_SUCCESS.
    FinalResultNotSuccess,
    /// The final answer did not carry an exact four-octet EAP-Success packet.
    FinalEapSuccessMissing,
    /// EAP-Success did not answer the correlated EAP-Response identifier.
    FinalEapIdentifierMismatch,
    /// The final answer also carried a reissued EAP payload.
    FinalEapMaterialAmbiguous,
    /// The final answer omitted its nonempty MSK.
    FinalMskMissing,
    /// The returned MSK differed from the TS 33.402 IMEI-derived value.
    FinalMskMismatch,
    /// The final answer omitted Mobile-Node-Identifier.
    FinalPermanentIdentityMissing,
    /// Mobile-Node-Identifier did not match the recovered IMEI Emergency NAI.
    FinalPermanentIdentityMismatch,
}

impl SwmEmergencyAuthorizationError {
    /// Stable redaction-safe label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InitialRequestInvalid => "swm_emergency_initial_request_invalid",
            Self::InitialRequestNotEmergency => "swm_emergency_request_not_indicated",
            Self::InitialIdentityMismatch => "swm_emergency_initial_identity_mismatch",
            Self::InitialEapIdentityInvalid => "swm_emergency_initial_eap_identity_invalid",
            Self::InitialEapIdentityMismatch => "swm_emergency_initial_eap_identity_mismatch",
            Self::InitialTerminalInformationUnexpected => {
                "swm_emergency_initial_terminal_information_unexpected"
            }
            Self::IdentityRecoveryInitialIdentityInvalid => {
                "swm_emergency_identity_recovery_initial_identity_invalid"
            }
            Self::SessionMismatch => "swm_emergency_session_mismatch",
            Self::DiameterTransactionMismatch => "swm_emergency_transaction_mismatch",
            Self::AnswerRequestMismatch => "swm_emergency_answer_request_mismatch",
            Self::AnswerInvalid => "swm_emergency_answer_invalid",
            Self::IdentityRecoveryNotRequested => "swm_emergency_identity_recovery_not_requested",
            Self::IdentityRecoveryResponseHasAuthorizationMaterial => {
                "swm_emergency_identity_recovery_response_ambiguous"
            }
            Self::RetryUserIdentityMismatch => "swm_emergency_retry_user_identity_mismatch",
            Self::RetryRequestMismatch => "swm_emergency_retry_request_mismatch",
            Self::RetryTerminalInformationMissing => "swm_emergency_terminal_information_missing",
            Self::RetryDeviceIdentityMismatch => "swm_emergency_device_identity_mismatch",
            Self::FinalResultNotSuccess => "swm_emergency_final_result_not_success",
            Self::FinalEapSuccessMissing => "swm_emergency_final_eap_success_missing",
            Self::FinalEapIdentifierMismatch => "swm_emergency_final_eap_identifier_mismatch",
            Self::FinalEapMaterialAmbiguous => "swm_emergency_final_eap_material_ambiguous",
            Self::FinalMskMissing => "swm_emergency_final_msk_missing",
            Self::FinalMskMismatch => "swm_emergency_final_msk_mismatch",
            Self::FinalPermanentIdentityMissing => "swm_emergency_permanent_identity_missing",
            Self::FinalPermanentIdentityMismatch => "swm_emergency_permanent_identity_mismatch",
        }
    }
}

impl fmt::Display for SwmEmergencyAuthorizationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Error for SwmEmergencyAuthorizationError {}

/// Authorization state surfaced from one SWm DEA without exposing key bytes.
///
/// Emergency authorization deliberately requires the correlated evidence
/// constructor above and can never be inferred from this answer-local view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SwmAuthorizationOutcome {
    /// Exact base `DIAMETER_MULTI_ROUND_AUTH` carries one well-formed EAP
    /// Request and no MSK.
    EapInProgress,
    /// Exact `DIAMETER_SUCCESS` carries nonempty MSK bytes.
    ///
    /// This is a wire-material observation, not EAP-method or key-length
    /// validation; the consuming subscriber-auth profile owns those checks.
    MskBearingSuccess,
    /// The answer does not establish either allowed terminal outcome.
    NotAuthorized,
}

impl SwmAuthorizationOutcome {
    /// Stable redaction-safe label for audit records and metrics.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EapInProgress => "eap_in_progress",
            Self::MskBearingSuccess => "msk_bearing_success",
            Self::NotAuthorized => "not_authorized",
        }
    }
}

/// Typed MIP6-Feature-Vector carried by SWm DER/DEA exchanges.
///
/// Despite the legacy name, its GTPv2 bit is independent of bearer IP family
/// and is not limited to IPv6 bearers.
///
/// Unknown bits are retained so a proxy does not erase extensions assigned by
/// a later specification release. Diagnostic output deliberately omits the
/// bitmask because it can fingerprint a deployment's mobility capabilities.
///
/// @spec IETF RFC5447 4.2.5
/// @spec 3GPP TS29273 7.2.3.1
#[derive(Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SwmMip6FeatureVector(u64);

impl SwmMip6FeatureVector {
    /// Integrated MIP6 bootstrap support.
    pub const MIP6_INTEGRATED: u64 = 0x0000_0000_0000_0001;
    /// Local Home Agent assignment support.
    pub const LOCAL_HOME_AGENT_ASSIGNMENT: u64 = 0x0000_0000_0000_0002;
    /// PMIPv6 support.
    pub const PMIP6_SUPPORTED: u64 = 0x0000_0100_0000_0000;
    /// Server selection requiring locally assigned UE addressing.
    pub const ASSIGN_LOCAL_IP: u64 = 0x0000_0800_0000_0000;
    /// MIPv4 support.
    pub const MIP4_SUPPORTED: u64 = 0x0000_1000_0000_0000;
    /// Optimized idle-mode mobility support.
    pub const OPTIMIZED_IDLE_MODE_MOBILITY: u64 = 0x0000_2000_0000_0000;
    /// GTPv2 network-based mobility support.
    pub const GTPV2_SUPPORTED: u64 = 0x0000_4000_0000_0000;

    const ANSWER_ONLY_BITS: u64 = Self::ASSIGN_LOCAL_IP;
    const NETWORK_BASED_MOBILITY_BITS: u64 = Self::PMIP6_SUPPORTED | Self::GTPV2_SUPPORTED;

    /// Retain a complete received or configured feature bitmask.
    pub const fn from_bits_retain(bits: u64) -> Self {
        Self(bits)
    }

    /// Construct the exact GTPv2-only capability vector used by an ePDG.
    pub const fn gtpv2_only() -> Self {
        Self(Self::GTPV2_SUPPORTED)
    }

    /// Return the complete wire bitmask, including unknown extension bits.
    pub const fn bits(self) -> u64 {
        self.0
    }

    /// Return whether every supplied bit is present.
    pub const fn contains(self, bits: u64) -> bool {
        self.0 & bits == bits
    }

    const fn valid_request(self) -> bool {
        self.0 & Self::ANSWER_ONLY_BITS == 0
    }

    const fn valid_answer(self) -> bool {
        !self.contains(Self::ASSIGN_LOCAL_IP) || self.0 & Self::NETWORK_BASED_MOBILITY_BITS == 0
    }
}

impl fmt::Debug for SwmMip6FeatureVector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SwmMip6FeatureVector(<redacted>)")
    }
}

/// One typed identity/value carried inside a 3GPP Supported-Features AVP.
///
/// The `(vendor_id, feature_list_id)` pair is the stable identity used for
/// duplicate detection. Feature bits remain available through an accessor but
/// are omitted from diagnostic output.
///
/// @spec 3GPP TS29229 6.3.29
#[derive(Clone, PartialEq, Eq)]
pub struct SwmSupportedFeatureList {
    vendor_id: VendorId,
    feature_list_id: u32,
    feature_list: u32,
    additional_avps: Vec<SwmAdditionalAvp>,
}

impl SwmSupportedFeatureList {
    /// Construct one vendor/list identity and its feature bitmask.
    pub const fn new(vendor_id: VendorId, feature_list_id: u32, feature_list: u32) -> Self {
        Self {
            vendor_id,
            feature_list_id,
            feature_list,
            additional_avps: Vec::new(),
        }
    }

    /// Construct the exact SWm Release 18 list (`vendor=10415`, `id=1`, `value=0`).
    pub const fn swm() -> Self {
        Self::new(VENDOR_ID_3GPP, SWM_FEATURE_LIST_ID, SWM_FEATURE_LIST)
    }

    /// Return the feature-list vendor identity.
    pub const fn vendor_id(&self) -> VendorId {
        self.vendor_id
    }

    /// Return the vendor-scoped Feature-List-ID.
    pub const fn feature_list_id(&self) -> u32 {
        self.feature_list_id
    }

    /// Return the Feature-List bitmask.
    pub const fn feature_list(&self) -> u32 {
        self.feature_list
    }

    /// Return preserved optional extension children in their original order.
    pub fn additional_avps(&self) -> &[SwmAdditionalAvp] {
        &self.additional_avps
    }

    const fn identity(&self) -> (VendorId, u32) {
        (self.vendor_id, self.feature_list_id)
    }
}

impl fmt::Debug for SwmSupportedFeatureList {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwmSupportedFeatureList")
            .field("vendor_id", &self.vendor_id)
            .field("feature_list_id", &self.feature_list_id)
            .field("feature_list", &"<redacted>")
            .field("additional_avp_count", &self.additional_avps.len())
            .finish()
    }
}

/// M-bit policy for a Supported-Features AVP in a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SwmSupportedFeaturesRequirement {
    /// Set M: an unsupported feature list must fail the request.
    Required,
    /// Clear M on a zero-valued list to discover peer support.
    Discovery,
}

/// Request-side Supported-Features value with an explicit outer M-bit policy.
#[derive(Clone, PartialEq, Eq)]
pub struct SwmRequestedSupportedFeatures {
    features: SwmSupportedFeatureList,
    requirement: SwmSupportedFeaturesRequirement,
}

impl SwmRequestedSupportedFeatures {
    /// Require support for the supplied feature-list value (outer M bit set).
    pub const fn required(features: SwmSupportedFeatureList) -> Self {
        Self {
            features,
            requirement: SwmSupportedFeaturesRequirement::Required,
        }
    }

    /// Discover support for one vendor/list identity (zero list, outer M clear).
    pub const fn discovery(vendor_id: VendorId, feature_list_id: u32) -> Self {
        Self {
            features: SwmSupportedFeatureList::new(vendor_id, feature_list_id, 0),
            requirement: SwmSupportedFeaturesRequirement::Discovery,
        }
    }

    /// Construct the canonical SWm Release 18 discovery request.
    pub const fn swm_discovery() -> Self {
        Self::discovery(VENDOR_ID_3GPP, SWM_FEATURE_LIST_ID)
    }

    /// Return the typed feature-list value.
    pub const fn features(&self) -> &SwmSupportedFeatureList {
        &self.features
    }

    /// Return the request-side M-bit policy.
    pub const fn requirement(&self) -> SwmSupportedFeaturesRequirement {
        self.requirement
    }

    const fn mandatory(&self) -> bool {
        matches!(self.requirement, SwmSupportedFeaturesRequirement::Required)
    }
}

impl fmt::Debug for SwmRequestedSupportedFeatures {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwmRequestedSupportedFeatures")
            .field("features", &self.features)
            .field("requirement", &self.requirement)
            .finish()
    }
}

/// Origin of one conditional value supplied at the DER construction boundary.
///
/// This provenance is application-side metadata. Diameter does not encode it,
/// so the parser deliberately does not invent or reconstruct it from wire
/// bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SwmConditionalValueSource {
    /// Derived from trusted local configuration or local node capabilities.
    LocallyConfigured,
    /// Supplied by, or directly observed from, the UE-facing access boundary.
    UeProvided,
    /// Derived from authenticated AAA state or an AAA transport outcome.
    AaaDerived,
}

/// One optional conditional value with explicit application-side provenance.
///
/// `Debug` reports only presence and source; the value is always redacted.
#[derive(Clone, PartialEq, Eq, Default)]
pub enum SwmConditionalValue<T> {
    /// The condition does not apply or the value is unavailable.
    #[default]
    Absent,
    /// A trusted local configuration or capability value.
    LocallyConfigured(T),
    /// A value supplied by, or directly observed from, the UE.
    UeProvided(T),
    /// A value derived from authenticated AAA state or a transport outcome.
    AaaDerived(T),
}

impl<T> SwmConditionalValue<T> {
    /// Return the provenance when a value is present.
    #[must_use]
    pub const fn source(&self) -> Option<SwmConditionalValueSource> {
        match self {
            Self::Absent => None,
            Self::LocallyConfigured(_) => Some(SwmConditionalValueSource::LocallyConfigured),
            Self::UeProvided(_) => Some(SwmConditionalValueSource::UeProvided),
            Self::AaaDerived(_) => Some(SwmConditionalValueSource::AaaDerived),
        }
    }

    /// Borrow the value without discarding its provenance.
    #[must_use]
    pub const fn value(&self) -> Option<&T> {
        match self {
            Self::Absent => None,
            Self::LocallyConfigured(value) | Self::UeProvided(value) | Self::AaaDerived(value) => {
                Some(value)
            }
        }
    }
}

impl<T> fmt::Debug for SwmConditionalValue<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Absent => formatter.write_str("Absent"),
            Self::LocallyConfigured(_) => formatter.write_str("LocallyConfigured(<redacted>)"),
            Self::UeProvided(_) => formatter.write_str("UeProvided(<redacted>)"),
            Self::AaaDerived(_) => formatter.write_str("AaaDerived(<redacted>)"),
        }
    }
}

/// Field identifying a redaction-safe DER access-context validation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SwmDerAccessContextField {
    /// RAT-Type.
    RatType,
    /// Service-Selection.
    ServiceSelection,
    /// MIP6-Feature-Vector.
    Mip6FeatureVector,
    /// QoS-Capability.
    QosCapability,
    /// Visited-Network-Identifier.
    VisitedNetworkIdentifier,
    /// AAA-Failure-Indication.
    AaaFailureIndication,
    /// Supported-Features.
    SupportedFeatures,
    /// UE-Local-IP-Address.
    UeLocalIpAddress,
    /// OC-Supported-Features.
    OcSupportedFeatures,
    /// Terminal-Information.
    TerminalInformation,
    /// Emergency-Services.
    EmergencyServices,
    /// High-Priority-Access-Info.
    HighPriorityAccessInfo,
}

/// Stable failure classes for DER access-context construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SwmDerAccessContextErrorCode {
    /// A checked build was given a request with an already populated context field.
    PrepopulatedField,
    /// A field was supplied from a source prohibited by its 3GPP condition.
    InvalidProvenance,
    /// A PLMN-derived visited-network identifier is malformed.
    InvalidVisitedNetworkIdentifier,
    /// QoS-Capability contains no profile template.
    EmptyQosCapability,
    /// QoS-Capability exceeds the defensive profile-template bound.
    TooManyQosProfiles,
    /// A present Supported-Features collection contains no group.
    EmptySupportedFeatures,
    /// A presence-significant indication is present without its defined bit.
    InactiveIndication,
    /// Two individually valid conditional values cannot appear together.
    ContradictoryValues,
    /// A typed enum value aliases another canonical variant.
    NonCanonicalValue,
}

/// Redaction-safe DER access-context construction failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SwmDerAccessContextError {
    code: SwmDerAccessContextErrorCode,
    field: SwmDerAccessContextField,
}

impl SwmDerAccessContextError {
    const fn new(code: SwmDerAccessContextErrorCode, field: SwmDerAccessContextField) -> Self {
        Self { code, field }
    }

    /// Return the stable failure class.
    #[must_use]
    pub const fn code(self) -> SwmDerAccessContextErrorCode {
        self.code
    }

    /// Return the field that failed validation.
    #[must_use]
    pub const fn field(self) -> SwmDerAccessContextField {
        self.field
    }
}

impl fmt::Display for SwmDerAccessContextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid SWm DER access context ({:?}, {:?})",
            self.field, self.code
        )
    }
}

impl Error for SwmDerAccessContextError {}

/// Canonical TS 29.273 visited-network domain derived from a PLMN.
///
/// The wire value is sensitive topology context and is redacted from `Debug`.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct SwmVisitedNetworkIdentifier(String);

impl SwmVisitedNetworkIdentifier {
    /// Construct `mnc<MNC>.mcc<MCC>.3gppnetwork.org` from decimal PLMN parts.
    ///
    /// MCC must contain three digits. MNC may contain two or three digits; a
    /// two-digit MNC is canonicalized with the required leading zero.
    pub fn new(mcc: &str, mnc: &str) -> Result<Self, SwmDerAccessContextError> {
        let valid_mcc = mcc.len() == 3 && mcc.as_bytes().iter().all(u8::is_ascii_digit);
        let valid_mnc = matches!(mnc.len(), 2 | 3) && mnc.as_bytes().iter().all(u8::is_ascii_digit);
        if !valid_mcc || !valid_mnc {
            return Err(SwmDerAccessContextError::new(
                SwmDerAccessContextErrorCode::InvalidVisitedNetworkIdentifier,
                SwmDerAccessContextField::VisitedNetworkIdentifier,
            ));
        }
        let normalized_mnc = if mnc.len() == 2 {
            format!("0{mnc}")
        } else {
            mnc.to_owned()
        };
        Ok(Self(format!(
            "mnc{normalized_mnc}.mcc{mcc}.3gppnetwork.org"
        )))
    }

    /// Return the canonical wire value.
    ///
    /// Callers must treat this as sensitive network-topology data.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(super) fn from_wire(value: &[u8], value_offset: usize) -> Result<Self, DecodeError> {
        const WIRE_LEN: usize = 29;
        let valid = value.len() == WIRE_LEN
            && &value[0..3] == b"mnc"
            && value[3..6].iter().all(u8::is_ascii_digit)
            && value[6] == b'.'
            && &value[7..10] == b"mcc"
            && value[10..13].iter().all(u8::is_ascii_digit)
            && value[13] == b'.'
            && &value[14..] == b"3gppnetwork.org";
        if !valid {
            return Err(DecodeError::new(
                DecodeErrorCode::Structural {
                    reason:
                        "Visited-Network-Identifier must use the canonical 3GPP PLMN domain form",
                },
                value_offset,
            )
            .with_spec_ref(SpecRef::new("3gpp", "TS29273", "9.2.3.1.2")));
        }
        let value = std::str::from_utf8(value).map_err(|_| {
            DecodeError::new(
                DecodeErrorCode::Structural {
                    reason: "Visited-Network-Identifier must contain ASCII",
                },
                value_offset,
            )
            .with_spec_ref(SpecRef::new("3gpp", "TS29273", "9.2.3.1.2"))
        })?;
        Ok(Self(value.to_owned()))
    }
}

impl fmt::Debug for SwmVisitedNetworkIdentifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SwmVisitedNetworkIdentifier(<redacted>)")
    }
}

/// Typed AAA-Failure-Indication asserting that an assigned AAA server failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SwmAaaFailureIndication;

impl SwmAaaFailureIndication {
    /// Construct the defined `AAA Failure` indication (bit zero).
    #[must_use]
    pub const fn previously_assigned_server_unavailable() -> Self {
        Self
    }

    const fn value(self) -> u32 {
        1
    }
}

/// One `(Vendor-Id, QoS-Profile-Id)` capability template.
#[derive(Clone, PartialEq, Eq)]
pub struct SwmQosProfileTemplate {
    vendor_id: VendorId,
    profile_id: u32,
    additional_avps: Vec<SwmAdditionalAvp>,
}

impl SwmQosProfileTemplate {
    /// Construct a profile-template identity without extension children.
    #[must_use]
    pub const fn new(vendor_id: VendorId, profile_id: u32) -> Self {
        Self {
            vendor_id,
            profile_id,
            additional_avps: Vec::new(),
        }
    }

    /// Construct the IETF Diameter QoS profile defined by RFC 5624.
    #[must_use]
    pub const fn ietf_diameter() -> Self {
        Self::new(VendorId::new(0), 0)
    }

    /// Return the profile namespace.
    #[must_use]
    pub const fn vendor_id(&self) -> VendorId {
        self.vendor_id
    }

    /// Return the profile identifier within its vendor namespace.
    #[must_use]
    pub const fn profile_id(&self) -> u32 {
        self.profile_id
    }

    /// Return preserved optional extension children in wire order.
    #[must_use]
    pub fn additional_avps(&self) -> &[SwmAdditionalAvp] {
        &self.additional_avps
    }
}

impl fmt::Debug for SwmQosProfileTemplate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwmQosProfileTemplate")
            .field("vendor_id", &self.vendor_id)
            .field("profile_id", &"<redacted>")
            .field("additional_avp_count", &self.additional_avps.len())
            .finish()
    }
}

/// Bounded ordered QoS profile capabilities carried by a DER.
#[derive(Clone, PartialEq, Eq)]
pub struct SwmQosCapability {
    profiles: Vec<SwmQosProfileTemplate>,
    additional_avps: Vec<SwmAdditionalAvp>,
}

impl SwmQosCapability {
    /// Construct a non-empty, bounded QoS capability list.
    pub fn new(profiles: Vec<SwmQosProfileTemplate>) -> Result<Self, SwmDerAccessContextError> {
        validate_qos_profiles(&profiles)?;
        Ok(Self {
            profiles,
            additional_avps: Vec::new(),
        })
    }

    /// Return ordered profile templates.
    #[must_use]
    pub fn profiles(&self) -> &[SwmQosProfileTemplate] {
        &self.profiles
    }

    /// Return preserved optional extension children in wire order.
    #[must_use]
    pub fn additional_avps(&self) -> &[SwmAdditionalAvp] {
        &self.additional_avps
    }
}

impl fmt::Debug for SwmQosCapability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwmQosCapability")
            .field("profile_count", &self.profiles.len())
            .field("additional_avp_count", &self.additional_avps.len())
            .finish()
    }
}

/// Informational source snapshot retained by a checked outbound DER build.
///
/// Diameter does not carry this metadata. The parser therefore returns only
/// the typed wire values and cannot create this snapshot. This type has no
/// public constructor; it is produced together with the exact encoded request
/// by [`build_swm_diameter_eap_request_with_access_context`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SwmDerAccessContextSourceSnapshot {
    rat_type: Option<SwmConditionalValueSource>,
    service_selection: Option<SwmConditionalValueSource>,
    mip6_feature_vector: Option<SwmConditionalValueSource>,
    qos_capability: Option<SwmConditionalValueSource>,
    visited_network_identifier: Option<SwmConditionalValueSource>,
    aaa_failure_indication: Option<SwmConditionalValueSource>,
    supported_features: Option<SwmConditionalValueSource>,
    ue_local_ip_address: Option<SwmConditionalValueSource>,
    oc_supported_features: Option<SwmConditionalValueSource>,
    terminal_information: Option<SwmConditionalValueSource>,
    emergency_services: Option<SwmConditionalValueSource>,
    high_priority_access_info: Option<SwmConditionalValueSource>,
}

impl SwmDerAccessContextSourceSnapshot {
    /// Return the RAT-Type source, or `None` when absent.
    #[must_use]
    pub const fn rat_type(self) -> Option<SwmConditionalValueSource> {
        self.rat_type
    }

    /// Return the Service-Selection source, or `None` when absent.
    #[must_use]
    pub const fn service_selection(self) -> Option<SwmConditionalValueSource> {
        self.service_selection
    }

    /// Return the MIP6-Feature-Vector source, or `None` when absent.
    #[must_use]
    pub const fn mip6_feature_vector(self) -> Option<SwmConditionalValueSource> {
        self.mip6_feature_vector
    }

    /// Return the QoS-Capability source, or `None` when absent.
    #[must_use]
    pub const fn qos_capability(self) -> Option<SwmConditionalValueSource> {
        self.qos_capability
    }

    /// Return the Visited-Network-Identifier source, or `None` when absent.
    #[must_use]
    pub const fn visited_network_identifier(self) -> Option<SwmConditionalValueSource> {
        self.visited_network_identifier
    }

    /// Return the AAA-Failure-Indication source, or `None` when absent.
    #[must_use]
    pub const fn aaa_failure_indication(self) -> Option<SwmConditionalValueSource> {
        self.aaa_failure_indication
    }

    /// Return the Supported-Features source, or `None` when absent.
    #[must_use]
    pub const fn supported_features(self) -> Option<SwmConditionalValueSource> {
        self.supported_features
    }

    /// Return the UE-Local-IP-Address source, or `None` when absent.
    #[must_use]
    pub const fn ue_local_ip_address(self) -> Option<SwmConditionalValueSource> {
        self.ue_local_ip_address
    }

    /// Return the OC-Supported-Features source, or `None` when absent.
    #[must_use]
    pub const fn oc_supported_features(self) -> Option<SwmConditionalValueSource> {
        self.oc_supported_features
    }

    /// Return the Terminal-Information source, or `None` when absent.
    #[must_use]
    pub const fn terminal_information(self) -> Option<SwmConditionalValueSource> {
        self.terminal_information
    }

    /// Return the Emergency-Services source, or `None` when absent.
    #[must_use]
    pub const fn emergency_services(self) -> Option<SwmConditionalValueSource> {
        self.emergency_services
    }

    /// Return the High-Priority-Access-Info source, or `None` when absent.
    #[must_use]
    pub const fn high_priority_access_info(self) -> Option<SwmConditionalValueSource> {
        self.high_priority_access_info
    }
}

/// Product-neutral application-side inputs for conditional DER access AVPs.
///
/// The checked outbound builder covers every conditional authorization-context
/// row in TS 29.273 table 7.1.2.1.1/1. It distinguishes local capability and
/// configuration, authenticated AAA transport state, and values supplied by or
/// observed at the UE-facing access boundary. It rejects every prohibited
/// source before encoding. The request's public wire fields remain directly
/// accessible for parser replay and API compatibility; direct assignment is
/// source-agnostic and produces no source snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SwmDerAccessContext {
    /// UE-facing access type, or locally configured `VIRTUAL` fallback.
    pub rat_type: SwmConditionalValue<SwmRatType>,
    /// UE-requested APN for a non-emergency session.
    pub service_selection: SwmConditionalValue<Redacted<String>>,
    /// Locally configured mobility capabilities.
    pub mip6_feature_vector: SwmConditionalValue<SwmMip6FeatureVector>,
    /// Locally configured QoS profile capabilities.
    pub qos_capability: SwmConditionalValue<SwmQosCapability>,
    /// Locally configured visited PLMN identity; absent for home access.
    pub visited_network_identifier: SwmConditionalValue<SwmVisitedNetworkIdentifier>,
    /// AAA-derived evidence that the previously assigned server is unavailable.
    pub aaa_failure_indication: SwmConditionalValue<SwmAaaFailureIndication>,
    /// Locally configured ordered feature declarations for this Diameter session.
    pub supported_features: SwmConditionalValue<Vec<SwmRequestedSupportedFeatures>>,
    /// UE source address observed at the protected access boundary.
    pub ue_local_ip_address: SwmConditionalValue<IpAddr>,
    /// Locally configured RFC 7683 overload-control capability.
    pub oc_supported_features: SwmConditionalValue<SwmOcSupportedFeatures>,
    /// UE-provided equipment identity, when available.
    pub terminal_information: SwmConditionalValue<SwmTerminalInformation>,
    /// UE-provided emergency-session indication.
    pub emergency_services: SwmConditionalValue<SwmEmergencyServices>,
    /// UE-provided access-priority indication admitted by local policy.
    pub high_priority_access_info: SwmConditionalValue<SwmHighPriorityAccessInfo>,
}

impl SwmDerAccessContext {
    fn apply_to(
        self,
        request: &mut SwmDiameterEapRequest,
    ) -> Result<SwmDerAccessContextSourceSnapshot, SwmDerAccessContextError> {
        for (present, field) in [
            (
                request.rat_type.is_some(),
                SwmDerAccessContextField::RatType,
            ),
            (
                request.service_selection.is_some(),
                SwmDerAccessContextField::ServiceSelection,
            ),
            (
                request.mip6_feature_vector.is_some(),
                SwmDerAccessContextField::Mip6FeatureVector,
            ),
            (
                request.qos_capability.is_some(),
                SwmDerAccessContextField::QosCapability,
            ),
            (
                request.visited_network_identifier.is_some(),
                SwmDerAccessContextField::VisitedNetworkIdentifier,
            ),
            (
                request.aaa_failure_indication.is_some(),
                SwmDerAccessContextField::AaaFailureIndication,
            ),
            (
                !request.supported_features.is_empty(),
                SwmDerAccessContextField::SupportedFeatures,
            ),
            (
                request.ue_local_ip_address.is_some(),
                SwmDerAccessContextField::UeLocalIpAddress,
            ),
            (
                request.oc_supported_features.is_some(),
                SwmDerAccessContextField::OcSupportedFeatures,
            ),
            (
                request.terminal_information.is_some(),
                SwmDerAccessContextField::TerminalInformation,
            ),
            (
                request.emergency_services.is_some(),
                SwmDerAccessContextField::EmergencyServices,
            ),
            (
                request.high_priority_access_info.is_some(),
                SwmDerAccessContextField::HighPriorityAccessInfo,
            ),
        ] {
            if present {
                return Err(SwmDerAccessContextError::new(
                    SwmDerAccessContextErrorCode::PrepopulatedField,
                    field,
                ));
            }
        }

        let source_snapshot = SwmDerAccessContextSourceSnapshot {
            rat_type: self.rat_type.source(),
            service_selection: self.service_selection.source(),
            mip6_feature_vector: self.mip6_feature_vector.source(),
            qos_capability: self.qos_capability.source(),
            visited_network_identifier: self.visited_network_identifier.source(),
            aaa_failure_indication: self.aaa_failure_indication.source(),
            supported_features: self.supported_features.source(),
            ue_local_ip_address: self.ue_local_ip_address.source(),
            oc_supported_features: self.oc_supported_features.source(),
            terminal_information: self.terminal_information.source(),
            emergency_services: self.emergency_services.source(),
            high_priority_access_info: self.high_priority_access_info.source(),
        };
        let rat_type = rat_type_from_allowed_source(self.rat_type)?;
        let service_selection = value_from_expected_source(
            self.service_selection,
            SwmConditionalValueSource::UeProvided,
            SwmDerAccessContextField::ServiceSelection,
        )?;
        let mip6_feature_vector = value_from_expected_source(
            self.mip6_feature_vector,
            SwmConditionalValueSource::LocallyConfigured,
            SwmDerAccessContextField::Mip6FeatureVector,
        )?;
        let qos_capability = value_from_expected_source(
            self.qos_capability,
            SwmConditionalValueSource::LocallyConfigured,
            SwmDerAccessContextField::QosCapability,
        )?;
        if let Some(capability) = qos_capability.as_ref() {
            validate_qos_profiles(capability.profiles())?;
        }
        let visited_network_identifier = value_from_expected_source(
            self.visited_network_identifier,
            SwmConditionalValueSource::LocallyConfigured,
            SwmDerAccessContextField::VisitedNetworkIdentifier,
        )?;
        let aaa_failure_indication = value_from_expected_source(
            self.aaa_failure_indication,
            SwmConditionalValueSource::AaaDerived,
            SwmDerAccessContextField::AaaFailureIndication,
        )?;
        let supported_features = value_from_expected_source(
            self.supported_features,
            SwmConditionalValueSource::LocallyConfigured,
            SwmDerAccessContextField::SupportedFeatures,
        )?;
        if supported_features.as_ref().is_some_and(Vec::is_empty) {
            return Err(SwmDerAccessContextError::new(
                SwmDerAccessContextErrorCode::EmptySupportedFeatures,
                SwmDerAccessContextField::SupportedFeatures,
            ));
        }
        let ue_local_ip_address = value_from_expected_source(
            self.ue_local_ip_address,
            SwmConditionalValueSource::UeProvided,
            SwmDerAccessContextField::UeLocalIpAddress,
        )?;
        let oc_supported_features = value_from_expected_source(
            self.oc_supported_features,
            SwmConditionalValueSource::LocallyConfigured,
            SwmDerAccessContextField::OcSupportedFeatures,
        )?;
        let terminal_information = value_from_expected_source(
            self.terminal_information,
            SwmConditionalValueSource::UeProvided,
            SwmDerAccessContextField::TerminalInformation,
        )?;
        let emergency_services = value_from_expected_source(
            self.emergency_services,
            SwmConditionalValueSource::UeProvided,
            SwmDerAccessContextField::EmergencyServices,
        )?;
        if emergency_services.is_some_and(|services| !services.is_emergency_indicated()) {
            return Err(SwmDerAccessContextError::new(
                SwmDerAccessContextErrorCode::InactiveIndication,
                SwmDerAccessContextField::EmergencyServices,
            ));
        }
        let high_priority_access_info = value_from_expected_source(
            self.high_priority_access_info,
            SwmConditionalValueSource::UeProvided,
            SwmDerAccessContextField::HighPriorityAccessInfo,
        )?;
        if high_priority_access_info.is_some_and(|information| !information.is_configured()) {
            return Err(SwmDerAccessContextError::new(
                SwmDerAccessContextErrorCode::InactiveIndication,
                SwmDerAccessContextField::HighPriorityAccessInfo,
            ));
        }
        if service_selection.is_some() && emergency_services.is_some() {
            return Err(SwmDerAccessContextError::new(
                SwmDerAccessContextErrorCode::ContradictoryValues,
                SwmDerAccessContextField::ServiceSelection,
            ));
        }

        request.rat_type = rat_type;
        request.service_selection = service_selection;
        request.mip6_feature_vector = mip6_feature_vector;
        request.qos_capability = qos_capability;
        request.visited_network_identifier = visited_network_identifier;
        request.aaa_failure_indication = aaa_failure_indication;
        request.supported_features = supported_features.unwrap_or_default();
        request.ue_local_ip_address = ue_local_ip_address;
        request.oc_supported_features = oc_supported_features;
        request.terminal_information = terminal_information;
        request.emergency_services = emergency_services;
        request.high_priority_access_info = high_priority_access_info;
        Ok(source_snapshot)
    }
}

/// Checked outbound DER request with its informational source snapshot.
///
/// The typed request, encoded message, and source snapshot are created in one
/// operation and exposed immutably while this wrapper is retained.
pub struct SwmBuiltDerAccessContextRequest {
    request: SwmDiameterEapRequest,
    message: OwnedMessage,
    source_snapshot: SwmDerAccessContextSourceSnapshot,
}

impl SwmBuiltDerAccessContextRequest {
    /// Borrow the exact typed request that was encoded.
    #[must_use]
    pub const fn request(&self) -> &SwmDiameterEapRequest {
        &self.request
    }

    /// Borrow the exact encoded Diameter request.
    #[must_use]
    pub const fn message(&self) -> &OwnedMessage {
        &self.message
    }

    /// Return the informational source snapshot captured during construction.
    #[must_use]
    pub const fn source_snapshot(&self) -> SwmDerAccessContextSourceSnapshot {
        self.source_snapshot
    }

    /// Consume the wrapper and recover its original construction outputs.
    ///
    /// After separation, the SDK can no longer keep later request mutations
    /// coupled to the snapshot; the snapshot describes only the returned
    /// encoded message and request at construction time.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        SwmDiameterEapRequest,
        OwnedMessage,
        SwmDerAccessContextSourceSnapshot,
    ) {
        (self.request, self.message, self.source_snapshot)
    }
}

impl fmt::Debug for SwmBuiltDerAccessContextRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwmBuiltDerAccessContextRequest")
            .field("request", &"<redacted>")
            .field("message", &"<redacted>")
            .field("source_snapshot", &self.source_snapshot)
            .finish()
    }
}

/// Failure from checked outbound DER access-context construction.
#[derive(Debug)]
pub enum SwmDerAccessContextBuildError {
    /// The conditional values or their source metadata were invalid.
    Context(SwmDerAccessContextError),
    /// The resulting typed request could not be encoded.
    Encode(EncodeError),
}

impl SwmDerAccessContextBuildError {
    /// Borrow the access-context error, when validation failed before encoding.
    #[must_use]
    pub const fn context_error(&self) -> Option<SwmDerAccessContextError> {
        match self {
            Self::Context(error) => Some(*error),
            Self::Encode(_) => None,
        }
    }
}

impl fmt::Display for SwmDerAccessContextBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Context(error) => error.fmt(formatter),
            Self::Encode(error) => error.fmt(formatter),
        }
    }
}

impl Error for SwmDerAccessContextBuildError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Context(error) => Some(error),
            Self::Encode(error) => Some(error),
        }
    }
}

impl From<SwmDerAccessContextError> for SwmDerAccessContextBuildError {
    fn from(error: SwmDerAccessContextError) -> Self {
        Self::Context(error)
    }
}

impl From<EncodeError> for SwmDerAccessContextBuildError {
    fn from(error: EncodeError) -> Self {
        Self::Encode(error)
    }
}

fn value_from_expected_source<T>(
    value: SwmConditionalValue<T>,
    expected: SwmConditionalValueSource,
    field: SwmDerAccessContextField,
) -> Result<Option<T>, SwmDerAccessContextError> {
    match value {
        SwmConditionalValue::Absent => Ok(None),
        SwmConditionalValue::LocallyConfigured(value)
            if expected == SwmConditionalValueSource::LocallyConfigured =>
        {
            Ok(Some(value))
        }
        SwmConditionalValue::UeProvided(value)
            if expected == SwmConditionalValueSource::UeProvided =>
        {
            Ok(Some(value))
        }
        SwmConditionalValue::AaaDerived(value)
            if expected == SwmConditionalValueSource::AaaDerived =>
        {
            Ok(Some(value))
        }
        SwmConditionalValue::LocallyConfigured(_)
        | SwmConditionalValue::UeProvided(_)
        | SwmConditionalValue::AaaDerived(_) => Err(SwmDerAccessContextError::new(
            SwmDerAccessContextErrorCode::InvalidProvenance,
            field,
        )),
    }
}

fn rat_type_from_allowed_source(
    value: SwmConditionalValue<SwmRatType>,
) -> Result<Option<SwmRatType>, SwmDerAccessContextError> {
    match value {
        SwmConditionalValue::Absent => Ok(None),
        SwmConditionalValue::LocallyConfigured(SwmRatType::Other(0 | 1))
        | SwmConditionalValue::UeProvided(SwmRatType::Other(0 | 1))
        | SwmConditionalValue::AaaDerived(SwmRatType::Other(0 | 1)) => {
            Err(SwmDerAccessContextError::new(
                SwmDerAccessContextErrorCode::NonCanonicalValue,
                SwmDerAccessContextField::RatType,
            ))
        }
        SwmConditionalValue::UeProvided(value @ (SwmRatType::Wlan | SwmRatType::Other(_)))
        | SwmConditionalValue::LocallyConfigured(value @ SwmRatType::Virtual) => Ok(Some(value)),
        SwmConditionalValue::LocallyConfigured(_)
        | SwmConditionalValue::UeProvided(_)
        | SwmConditionalValue::AaaDerived(_) => Err(SwmDerAccessContextError::new(
            SwmDerAccessContextErrorCode::InvalidProvenance,
            SwmDerAccessContextField::RatType,
        )),
    }
}

fn validate_qos_profiles(
    profiles: &[SwmQosProfileTemplate],
) -> Result<(), SwmDerAccessContextError> {
    if profiles.is_empty() {
        return Err(SwmDerAccessContextError::new(
            SwmDerAccessContextErrorCode::EmptyQosCapability,
            SwmDerAccessContextField::QosCapability,
        ));
    }
    if profiles.len() > MAX_SWM_QOS_PROFILE_TEMPLATES {
        return Err(SwmDerAccessContextError::new(
            SwmDerAccessContextErrorCode::TooManyQosProfiles,
            SwmDerAccessContextField::QosCapability,
        ));
    }
    Ok(())
}

/// PDN-Type values (3GPP TS 29.272 §7.3.62).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PdnType {
    /// IPv4 only.
    Ipv4,
    /// IPv6 only.
    Ipv6,
    /// IPv4v6 dual stack.
    Ipv4v6,
    /// IPv4 or IPv6.
    Ipv4OrIpv6,
    /// Unknown or application-specific value.
    Other(u32),
}

impl PdnType {
    /// Return the wire value.
    pub const fn value(self) -> u32 {
        match self {
            Self::Ipv4 => 0,
            Self::Ipv6 => 1,
            Self::Ipv4v6 => 2,
            Self::Ipv4OrIpv6 => 3,
            Self::Other(v) => v,
        }
    }

    /// Parse from a wire value.
    pub const fn from_value(value: u32) -> Self {
        match value {
            0 => Self::Ipv4,
            1 => Self::Ipv6,
            2 => Self::Ipv4v6,
            3 => Self::Ipv4OrIpv6,
            other => Self::Other(other),
        }
    }
}

/// Stable class for an invalid SWm APN QoS value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SwmQosValueError {
    /// The QCI value is not standardized by the supported release.
    UnsupportedQosClassIdentifier,
    /// ARP Priority-Level is outside 1 through 15.
    InvalidPriorityLevel,
    /// A pre-emption enumerated value is not 0 or 1.
    InvalidPreemptionValue,
    /// Bandwidth was zero, outside the wire range, or in the unrepresentable gap.
    InvalidBandwidth,
    /// Extended bandwidth was present without the required saturated base value.
    InconsistentExtendedBandwidth,
}

impl SwmQosValueError {
    /// Return a value-free machine-readable error label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedQosClassIdentifier => "swm_qos_class_identifier_unsupported",
            Self::InvalidPriorityLevel => "swm_qos_priority_level_invalid",
            Self::InvalidPreemptionValue => "swm_qos_preemption_value_invalid",
            Self::InvalidBandwidth => "swm_ambr_bandwidth_invalid",
            Self::InconsistentExtendedBandwidth => "swm_ambr_extended_bandwidth_inconsistent",
        }
    }
}

impl fmt::Display for SwmQosValueError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Error for SwmQosValueError {}

/// Assigned QoS-Class-Identifier accepted by the supported TS 29.212 release.
///
/// Standardized and operator-specific (128 through 254) assignments are
/// representable; reserved and spare values fail closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SwmQosClassIdentifier(u32);

impl SwmQosClassIdentifier {
    /// Validate one standardized or operator-specific QCI assignment.
    pub const fn new(value: u32) -> Result<Self, SwmQosValueError> {
        if matches!(
            value,
            1..=9 | 65..=67 | 69..=76 | 79 | 80 | 82..=85 | 128..=254
        ) {
            Ok(Self(value))
        } else {
            Err(SwmQosValueError::UnsupportedQosClassIdentifier)
        }
    }

    /// Return the Diameter Enumerated value.
    #[must_use]
    pub const fn value(self) -> u32 {
        self.0
    }
}

/// Allocation and retention priority level (1 is highest, 15 is lowest).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SwmPriorityLevel(u8);

impl SwmPriorityLevel {
    /// Validate a TS 29.212 Priority-Level.
    pub const fn new(value: u32) -> Result<Self, SwmQosValueError> {
        if value >= 1 && value <= 15 {
            Ok(Self(value as u8))
        } else {
            Err(SwmQosValueError::InvalidPriorityLevel)
        }
    }

    /// Return the Diameter Unsigned32 value.
    #[must_use]
    pub const fn value(self) -> u32 {
        self.0 as u32
    }
}

/// Whether a bearer may pre-empt another bearer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SwmPreemptionCapability {
    /// Pre-emption capability is enabled (wire value 0).
    Enabled,
    /// Pre-emption capability is disabled (wire value 1, absent default).
    Disabled,
}

impl SwmPreemptionCapability {
    const fn from_value(value: u32) -> Result<Self, SwmQosValueError> {
        match value {
            0 => Ok(Self::Enabled),
            1 => Ok(Self::Disabled),
            _ => Err(SwmQosValueError::InvalidPreemptionValue),
        }
    }

    const fn value(self) -> u32 {
        match self {
            Self::Enabled => 0,
            Self::Disabled => 1,
        }
    }
}

/// Whether a bearer may be pre-empted by another bearer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SwmPreemptionVulnerability {
    /// Pre-emption vulnerability is enabled (wire value 0, absent default).
    Enabled,
    /// Pre-emption vulnerability is disabled (wire value 1).
    Disabled,
}

impl SwmPreemptionVulnerability {
    const fn from_value(value: u32) -> Result<Self, SwmQosValueError> {
        match value {
            0 => Ok(Self::Enabled),
            1 => Ok(Self::Disabled),
            _ => Err(SwmQosValueError::InvalidPreemptionValue),
        }
    }

    const fn value(self) -> u32 {
        match self {
            Self::Enabled => 0,
            Self::Disabled => 1,
        }
    }
}

/// Allocation-Retention-Priority grouped AVP (3GPP TS 29.212 §5.3.32).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AllocationRetentionPriority {
    /// Priority-Level.
    pub priority_level: SwmPriorityLevel,
    /// Pre-emption-Capability; absence means disabled.
    pub pre_emption_capability: Option<SwmPreemptionCapability>,
    /// Pre-emption-Vulnerability; absence means enabled.
    pub pre_emption_vulnerability: Option<SwmPreemptionVulnerability>,
}

/// EPS-Subscribed-QoS-Profile grouped AVP (3GPP TS 29.272 §7.3.37).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpsSubscribedQosProfile {
    /// QoS-Class-Identifier.
    pub qos_class_identifier: SwmQosClassIdentifier,
    /// Allocation-Retention-Priority grouped child.
    pub allocation_retention_priority: AllocationRetentionPriority,
}

/// Exactly representable AMBR bandwidth in bits per second.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SwmBandwidth(u64);

impl SwmBandwidth {
    const MAX_BASE: u64 = u32::MAX as u64;
    const MIN_EXTENDED_KBPS: u64 = 4_294_968;
    const MAX_EXTENDED_BPS: u64 = u32::MAX as u64 * 1_000;

    /// Validate an AMBR bandwidth representable by TS 29.272 §7.3.41.
    pub const fn new(bits_per_second: u64) -> Result<Self, SwmQosValueError> {
        if bits_per_second == 0 || bits_per_second > Self::MAX_EXTENDED_BPS {
            return Err(SwmQosValueError::InvalidBandwidth);
        }
        if bits_per_second > Self::MAX_BASE
            && (!bits_per_second.is_multiple_of(1_000)
                || bits_per_second / 1_000 < Self::MIN_EXTENDED_KBPS)
        {
            return Err(SwmQosValueError::InvalidBandwidth);
        }
        Ok(Self(bits_per_second))
    }

    /// Return the authorized bandwidth in bits per second.
    #[must_use]
    pub const fn bits_per_second(self) -> u64 {
        self.0
    }

    const fn wire_values(self) -> (u32, Option<u32>) {
        if self.0 <= Self::MAX_BASE {
            (self.0 as u32, None)
        } else {
            (u32::MAX, Some((self.0 / 1_000) as u32))
        }
    }

    const fn from_wire(base: u32, extended: Option<u32>) -> Result<Self, SwmQosValueError> {
        match extended {
            None => Self::new(base as u64),
            Some(value) if base == u32::MAX && value as u64 >= Self::MIN_EXTENDED_KBPS => {
                Self::new(value as u64 * 1_000)
            }
            Some(_) => Err(SwmQosValueError::InconsistentExtendedBandwidth),
        }
    }
}

/// AMBR grouped AVP (3GPP TS 29.272 §7.3.41).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ambr {
    /// Maximum requested uplink bandwidth.
    pub max_requested_bandwidth_ul: SwmBandwidth,
    /// Maximum requested downlink bandwidth.
    pub max_requested_bandwidth_dl: SwmBandwidth,
}

impl Ambr {
    /// Construct a validated AMBR from bit-per-second values.
    pub const fn new(
        uplink_bits_per_second: u64,
        downlink_bits_per_second: u64,
    ) -> Result<Self, SwmQosValueError> {
        Ok(Self {
            max_requested_bandwidth_ul: match SwmBandwidth::new(uplink_bits_per_second) {
                Ok(value) => value,
                Err(error) => return Err(error),
            },
            max_requested_bandwidth_dl: match SwmBandwidth::new(downlink_bits_per_second) {
                Ok(value) => value,
                Err(error) => return Err(error),
            },
        })
    }
}

/// APN-Configuration grouped AVP (3GPP TS 29.272 §7.3.35).
///
/// This typed wire core retains the fields that predate the complete SWm
/// authorization profile. Use [`SwmAuthorizedApnConfiguration`] to
/// originate standardized supplemental children and
/// [`SwmCorrelatedDiameterEapResponse::apn_configuration_views`] to inspect
/// parsed supplemental values after authenticated response correlation.
/// The ordered supplemental state is sealed so a reordered or mutated public
/// core cannot silently acquire another APN's addresses or gateway identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApnConfiguration {
    /// Context-Identifier.
    pub context_identifier: u32,
    /// Service-Selection / APN name (redacted in diagnostic output).
    pub service_selection: Redacted<String>,
    /// PDN-Type.
    pub pdn_type: PdnType,
    /// EPS-Subscribed-QoS-Profile grouped child.
    pub eps_subscribed_qos_profile: Option<EpsSubscribedQosProfile>,
    /// AMBR grouped child.
    pub ambr: Option<Ambr>,
}

/// Copy-only, value-free metadata for one parser-retained SWm DER/DEA AVP.
///
/// The opaque value and its owning [`SwmAdditionalAvp`] wrapper are never
/// exposed by the sealed Diameter-EAP extension collections.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SwmDiameterEapExtensionMetadata {
    code: AvpCode,
    vendor_id: Option<VendorId>,
    flags: crate::AvpFlags,
    value_len: usize,
}

impl SwmDiameterEapExtensionMetadata {
    fn from_retained(avp: &SwmAdditionalAvp) -> Self {
        Self {
            code: avp.code(),
            vendor_id: avp.vendor_id(),
            flags: avp.header().flags,
            value_len: avp.value_len(),
        }
    }

    /// Return the AVP code.
    #[must_use]
    pub const fn code(self) -> AvpCode {
        self.code
    }

    /// Return the optional Vendor-Id.
    #[must_use]
    pub const fn vendor_id(self) -> Option<VendorId> {
        self.vendor_id
    }

    /// Return the received AVP flags.
    #[must_use]
    pub const fn flags(self) -> crate::AvpFlags {
        self.flags
    }

    /// Return the opaque value length in octets.
    #[must_use]
    pub const fn value_len(self) -> usize {
        self.value_len
    }
}

/// Parser-retained optional top-level AVPs from a SWm DER.
///
/// The collection is sealed against raw outbound intake: locally originated
/// requests use [`Default::default`], while the DER parser alone can populate
/// entries. Callers may inspect copy-only, redaction-safe metadata through
/// [`Self::metadata`] and may clone a parsed collection when rebuilding that
/// endpoint message.
/// Typed rebuilding canonicalizes retained extensions to the trailing command
/// wildcard; use [`Message`] directly when an exact relay/proxy byte stream is
/// required.
///
/// ```compile_fail
/// use opc_proto_diameter::apps::swm::SwmDiameterEapRequestExtensions;
///
/// let extensions = SwmDiameterEapRequestExtensions::default();
/// let _raw_wrappers = extensions.avps();
/// ```
#[derive(Default, Clone, PartialEq, Eq)]
pub struct SwmDiameterEapRequestExtensions {
    avps: Vec<SwmAdditionalAvp>,
}

impl SwmDiameterEapRequestExtensions {
    /// Iterate over ordered copy-only metadata without exposing retained values.
    pub fn metadata(&self) -> impl ExactSizeIterator<Item = SwmDiameterEapExtensionMetadata> + '_ {
        self.avps
            .iter()
            .map(SwmDiameterEapExtensionMetadata::from_retained)
    }

    /// Return the number of retained AVPs.
    #[must_use]
    pub fn len(&self) -> usize {
        self.avps.len()
    }

    /// Return whether no optional AVPs were retained.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.avps.is_empty()
    }

    fn retained_avps(&self) -> &[SwmAdditionalAvp] {
        &self.avps
    }
}

impl fmt::Debug for SwmDiameterEapRequestExtensions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwmDiameterEapRequestExtensions")
            .field("avp_count", &self.avps.len())
            .finish()
    }
}

/// Parser-retained optional top-level AVPs from a SWm DEA.
///
/// The collection is sealed against raw outbound intake: locally originated
/// answers use [`Default::default`], while the DEA parser alone can populate
/// entries. Callers may inspect copy-only, redaction-safe metadata through
/// [`Self::metadata`] and may clone a parsed collection when rebuilding that
/// endpoint message.
/// Typed rebuilding canonicalizes retained extensions to the trailing command
/// wildcard; use [`Message`] directly when an exact relay/proxy byte stream is
/// required.
///
/// A parsed ordinary answer can retain repeated RFC 4072 `Failed-AVP` values
/// for value-free metadata, but the typed answer builder deliberately refuses
/// to re-originate those mandatory evidence AVPs. Cache and replay the original
/// [`OwnedMessage`] for exact retransmission; use
/// [`crate::error_answer::build_diameter_error_answer`] for a newly originated
/// request-bound failure.
#[derive(Default, Clone, PartialEq, Eq)]
pub struct SwmDiameterEapAnswerExtensions {
    avps: Vec<SwmAdditionalAvp>,
    gateway_context: SwmDeaGatewayContext,
    apn_configurations: Vec<SwmApnConfigurationSupplement>,
    access_network_info: Option<SwmAccessNetworkInfo>,
    user_location_info_time: Option<SwmUserLocationInfoTime>,
    user_location_info_time_omission: Option<SwmUserLocationInfoTimeOmission>,
    trace_info: Option<SwmTraceInfo>,
}

impl SwmDiameterEapAnswerExtensions {
    /// Iterate over ordered copy-only metadata without exposing retained values.
    pub fn metadata(&self) -> impl ExactSizeIterator<Item = SwmDiameterEapExtensionMetadata> + '_ {
        self.avps
            .iter()
            .map(SwmDiameterEapExtensionMetadata::from_retained)
    }

    /// Return the number of retained AVPs.
    #[must_use]
    pub fn len(&self) -> usize {
        self.avps.len()
    }

    /// Return whether no optional AVPs were retained.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.avps.is_empty()
    }

    fn retained_avps(&self) -> &[SwmAdditionalAvp] {
        &self.avps
    }
}

impl fmt::Debug for SwmDiameterEapAnswerExtensions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwmDiameterEapAnswerExtensions")
            .field("avp_count", &self.avps.len())
            .field("gateway_context", &self.gateway_context)
            .field("apn_configuration_count", &self.apn_configurations.len())
            .field(
                "access_network_info_present",
                &self.access_network_info.is_some(),
            )
            .field(
                "user_location_info_time_present",
                &self.user_location_info_time.is_some(),
            )
            .field(
                "user_location_info_time_omission_present",
                &self.user_location_info_time_omission.is_some(),
            )
            .field("trace_info_present", &self.trace_info.is_some())
            .finish()
    }
}

/// RFC 6733 section 7.2 generic error answer carried by the Diameter-EAP
/// command code.
///
/// This grammar deliberately omits application-only fields such as
/// Auth-Application-Id and Auth-Request-Type. The base Result-Code is retained
/// separately from [`SwmDiameterResult`] so an Experimental-Result with the
/// same numeric value can never claim the E bit.
///
/// Parsed redirect values are deliberately sealed until strict request
/// correlation succeeds:
///
/// ```compile_fail
/// use opc_proto_diameter::apps::swm::SwmDiameterEapResponse;
///
/// fn expose_uncorrelated(response: &SwmDiameterEapResponse) {
///     if let SwmDiameterEapResponse::GenericError(answer) = response {
///         let _targets = &answer.redirect;
///     }
/// }
/// ```
#[derive(Clone)]
pub struct SwmDiameterEapGenericErrorAnswer {
    /// Optional Session-Id copied when it was present on the request.
    pub session_id: Option<Redacted<String>>,
    /// Mandatory base Result-Code used with RFC 6733's E-bit grammar.
    ///
    /// This includes 3xxx protocol errors and the explicit 5xxx/unrecognized
    /// fallback permitted by RFC 6733 section 7.1.5.
    pub result_code: u32,
    /// Origin-Host of the server or Diameter agent producing the error.
    pub origin_host: Redacted<String>,
    /// Origin-Realm of the server or Diameter agent producing the error.
    pub origin_realm: Redacted<String>,
    /// Typed redirect context for exact `DIAMETER_REDIRECT_INDICATION`.
    redirect: Option<SwmDiameterRedirect>,
    /// Optional redacted Error-Message.
    pub error_message: Option<Redacted<String>>,
    /// Optional redacted Error-Reporting-Host.
    pub error_reporting_host: Option<Redacted<String>>,
    /// Optional Origin-State-Id.
    pub origin_state_id: Option<u32>,
    /// Optional Experimental-Result retained in addition to mandatory base
    /// Result-Code.
    pub experimental_result: Option<SwmDiameterResult>,
    /// Ordered validated Failed-AVP values. Raw values remain private.
    failed_avps: Vec<SwmAdditionalAvp>,
    /// Ordered, sealed generic-wildcard AVPs.
    additional_avps: Vec<SwmAdditionalAvp>,
    provenance: SwmDiameterEapGenericErrorAnswerProvenance,
}

#[derive(Clone)]
enum SwmDiameterEapGenericErrorAnswerProvenance {
    OutboundRedirect,
    OutboundAgentDeliveryFailure {
        failure: SwmDiameterEapAgentDeliveryFailure,
        request_binding: SwmDiameterEapAgentErrorRequestBinding,
    },
    Parsed,
}

#[derive(Clone)]
struct SwmDiameterEapAgentErrorRequestBinding {
    transaction: SwmDiameterTransaction,
    proxiable: bool,
    request_digest: Zeroizing<[u8; 32]>,
}

impl SwmDiameterEapAgentErrorRequestBinding {
    fn for_request(request: &SwmDiameterEapRequestEnvelope) -> Result<Self, EncodeError> {
        let mut flags = builder_helpers::app_request_flags();
        if request.potentially_retransmitted {
            flags = crate::CommandFlags::from_bits(
                flags.bits() | crate::CommandFlags::POTENTIALLY_RETRANSMITTED,
            );
        }
        let message = build_swm_diameter_eap_request_internal(
            &request.request,
            &request.proxy_infos,
            flags,
            request.transaction.hop_by_hop_identifier(),
            request.transaction.end_to_end_identifier(),
            EncodeContext {
                max_message_len: crate::MAX_U24 as usize,
                ..EncodeContext::default()
            },
        )?;
        let mut hasher = Sha256::new();
        hasher.update(b"opc-swm-agent-error-request-binding-v1\0");
        hasher.update([message.header.version, message.header.flags.bits()]);
        hasher.update(message.header.length.to_be_bytes());
        hasher.update(message.header.command_code.get().to_be_bytes());
        hasher.update(message.header.application_id.get().to_be_bytes());
        hasher.update(message.header.hop_by_hop_identifier.to_be_bytes());
        hasher.update(message.header.end_to_end_identifier.to_be_bytes());
        hasher.update(&message.raw_avps);
        let mut output = hasher.finalize();
        let mut request_digest = [0_u8; 32];
        request_digest.copy_from_slice(&output);
        output.as_mut_slice().zeroize();
        Ok(Self {
            transaction: request.transaction,
            proxiable: request.proxiable,
            request_digest: Zeroizing::new(request_digest),
        })
    }

    fn matches(&self, request: &SwmDiameterEapRequestEnvelope) -> Result<bool, EncodeError> {
        if self.transaction != request.transaction || self.proxiable != request.proxiable {
            return Ok(false);
        }
        let candidate = Self::for_request(request)?;
        Ok(bool::from(
            self.request_digest
                .as_slice()
                .ct_eq(candidate.request_digest.as_slice()),
        ))
    }
}

impl fmt::Debug for SwmDiameterEapGenericErrorAnswer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwmDiameterEapGenericErrorAnswer")
            .field("session_id", &self.session_id)
            .field("result_code", &self.result_code)
            .field("origin_host", &self.origin_host)
            .field("origin_realm", &self.origin_realm)
            .field("redirect", &self.redirect)
            .field("error_message_present", &self.error_message.is_some())
            .field(
                "error_reporting_host_present",
                &self.error_reporting_host.is_some(),
            )
            .field("origin_state_id_present", &self.origin_state_id.is_some())
            .field(
                "experimental_result_present",
                &self.experimental_result.is_some(),
            )
            .field("failed_avp_count", &self.failed_avps.len())
            .field("additional_avp_count", &self.additional_avps.len())
            .finish()
    }
}

impl SwmDiameterEapGenericErrorAnswer {
    /// Construct an RFC 6733 redirect-indication answer.
    ///
    /// The required Session-Id is copied from the SWm DER. Other originated
    /// generic errors must use the request-bound
    /// [`crate::error_answer::build_diameter_error_answer`] boundary so mandatory
    /// Failed-AVP evidence cannot be omitted. Parsed generic errors remain
    /// receive-capable for every supported E-bit result family.
    pub fn new_redirect(
        session_id: impl Into<Redacted<String>>,
        origin_host: impl Into<Redacted<String>>,
        origin_realm: impl Into<Redacted<String>>,
        redirect: SwmDiameterRedirect,
    ) -> Result<Self, EncodeError> {
        let answer = Self {
            session_id: Some(session_id.into()),
            result_code: DIAMETER_REDIRECT_INDICATION,
            origin_host: origin_host.into(),
            origin_realm: origin_realm.into(),
            redirect: Some(redirect),
            error_message: None,
            error_reporting_host: None,
            origin_state_id: None,
            experimental_result: None,
            failed_avps: Vec::new(),
            additional_avps: Vec::new(),
            provenance: SwmDiameterEapGenericErrorAnswerProvenance::OutboundRedirect,
        };
        answer.validate_for_encode()?;
        Ok(answer)
    }

    /// Construct a DRA-generated delivery failure for one exact SWm DER.
    ///
    /// The request binding covers the complete canonical DER, both transaction
    /// identifiers, P/T, and ordered `Proxy-Info`. The generic response builder
    /// checks that binding before writing response bytes and then copies the
    /// request's Session-Id, P bit, identifiers, and proxy chain. Only
    /// [`SwmDiameterEapAgentDeliveryFailure::UnableToDeliver`] and
    /// [`SwmDiameterEapAgentDeliveryFailure::TooBusy`] are representable. The
    /// latter is rejected unless the retained DER contains `Destination-Host`,
    /// as required by RFC 6733 section 7.1.3.
    pub fn new_agent_delivery_failure_for(
        request: &SwmDiameterEapRequestEnvelope,
        failure: SwmDiameterEapAgentDeliveryFailure,
        origin_host: impl Into<Redacted<String>>,
        origin_realm: impl Into<Redacted<String>>,
    ) -> Result<Self, EncodeError> {
        if !failure.is_valid_for(request.request()) {
            return Err(encode_structural_error(
                "DIAMETER_TOO_BUSY requires a SWm DER with Destination-Host",
                "7.1.3",
            ));
        }
        let request_binding = SwmDiameterEapAgentErrorRequestBinding::for_request(request)?;
        let answer = Self {
            session_id: Some(request.request.session_id.clone()),
            result_code: failure.result_code(),
            origin_host: origin_host.into(),
            origin_realm: origin_realm.into(),
            redirect: None,
            error_message: None,
            error_reporting_host: None,
            origin_state_id: None,
            experimental_result: None,
            failed_avps: Vec::new(),
            additional_avps: Vec::new(),
            provenance: SwmDiameterEapGenericErrorAnswerProvenance::OutboundAgentDeliveryFailure {
                failure,
                request_binding,
            },
        };
        answer.validate_for_encode()?;
        Ok(answer)
    }

    /// Return whether this answer contains redirect targets.
    ///
    /// Target values remain sealed until a
    /// [`SwmCorrelatedDiameterEapResponse`] is produced.
    #[must_use]
    pub const fn has_redirect(&self) -> bool {
        self.redirect.is_some()
    }

    /// Return the number of validated Failed-AVP values.
    #[must_use]
    pub fn failed_avp_count(&self) -> usize {
        self.failed_avps.len()
    }

    /// Return the number of sealed generic-wildcard AVPs.
    #[must_use]
    pub fn additional_avp_count(&self) -> usize {
        self.additional_avps.len()
    }

    fn validate_for_encode(&self) -> Result<(), EncodeError> {
        match &self.provenance {
            SwmDiameterEapGenericErrorAnswerProvenance::Parsed => {
                return Err(encode_structural_error(
                    "parsed generic SWm DEA cannot be re-originated",
                    "7.2",
                ));
            }
            SwmDiameterEapGenericErrorAnswerProvenance::OutboundRedirect => {
                if self.result_code != DIAMETER_REDIRECT_INDICATION {
                    return Err(encode_structural_error(
                        "outbound redirect SWm DEA requires DIAMETER_REDIRECT_INDICATION",
                        "6.12",
                    ));
                }
            }
            SwmDiameterEapGenericErrorAnswerProvenance::OutboundAgentDeliveryFailure {
                failure,
                ..
            } => {
                if self.result_code != failure.result_code() {
                    return Err(encode_structural_error(
                        "outbound SWm agent delivery failure Result-Code changed after binding",
                        "7.1.3",
                    ));
                }
                if self.redirect.is_some()
                    || self.experimental_result.is_some()
                    || !self.failed_avps.is_empty()
                    || !self.additional_avps.is_empty()
                {
                    return Err(encode_structural_error(
                        "outbound SWm agent delivery failure contains non-delivery context",
                        "7.2",
                    ));
                }
            }
        }
        if self
            .session_id
            .as_ref()
            .is_some_and(|session_id| session_id.as_ref().is_empty())
        {
            return Err(encode_structural_error(
                "generic SWm DEA Session-Id must not be empty when present",
                "7.2",
            ));
        }
        if self.origin_host.as_ref().is_empty()
            || !self.origin_host.as_ref().is_ascii()
            || self.origin_realm.as_ref().is_empty()
            || !self.origin_realm.as_ref().is_ascii()
        {
            return Err(encode_structural_error(
                "generic SWm DEA Origin identities must be nonempty ASCII",
                "7.2",
            ));
        }
        if self
            .error_reporting_host
            .as_ref()
            .is_some_and(|host| host.as_ref().is_empty() || !host.as_ref().is_ascii())
        {
            return Err(encode_structural_error(
                "generic SWm DEA Error-Reporting-Host must be a nonempty ASCII DiameterIdentity",
                "7.4",
            ));
        }
        if !result_code_allows_generic_error_bit(self.result_code) {
            return Err(encode_structural_error(
                "generic SWm DEA Result-Code cannot use the E bit",
                "7.1",
            ));
        }
        if self.result_code == DIAMETER_REDIRECT_INDICATION {
            let redirect = self.redirect.as_ref().ok_or_else(|| {
                encode_structural_error(
                    "DIAMETER_REDIRECT_INDICATION requires Redirect-Host",
                    "6.12",
                )
            })?;
            validate_redirect_values(
                redirect.hosts(),
                redirect.usage(),
                redirect.max_cache_time(),
            )
            .map_err(|_| {
                encode_structural_error("generic SWm DEA redirect context is invalid", "6.12")
            })?;
        } else if self.redirect.is_some() {
            return Err(encode_structural_error(
                "Redirect AVPs require DIAMETER_REDIRECT_INDICATION",
                "6.12",
            ));
        }
        match self.experimental_result {
            Some(SwmDiameterResult::Base(_)) => {
                return Err(encode_structural_error(
                    "generic SWm DEA experimental result must use Experimental-Result",
                    "7.6",
                ));
            }
            Some(SwmDiameterResult::Experimental { vendor_id, .. }) if vendor_id.get() == 0 => {
                return Err(encode_structural_error(
                    "generic SWm DEA Experimental-Result Vendor-Id must not be zero",
                    "7.6",
                ));
            }
            None | Some(SwmDiameterResult::Experimental { .. }) => {}
        }
        validate_diameter_eap_routing_for_encode(
            self.failed_avps.len(),
            &[],
            self.additional_avps.len(),
            "7.2",
        )?;
        Ok(())
    }
}

const fn result_code_allows_generic_error_bit(result_code: u32) -> bool {
    result_code >= 1000 && !matches!(result_code / 1000, 1 | 2 | 4)
}

const fn result_code_requires_failed_avp(result_code: u32) -> bool {
    matches!(
        result_code,
        base::RESULT_CODE_DIAMETER_AVP_UNSUPPORTED
            | base::RESULT_CODE_DIAMETER_INVALID_AVP_VALUE
            | base::RESULT_CODE_DIAMETER_CONTRADICTING_AVPS
            | base::RESULT_CODE_DIAMETER_AVP_NOT_ALLOWED
            | base::RESULT_CODE_DIAMETER_AVP_OCCURS_TOO_MANY_TIMES
            | base::RESULT_CODE_DIAMETER_INVALID_AVP_LENGTH
            | base::RESULT_CODE_DIAMETER_INVALID_AVP_BIT_COMBO
    )
}

/// Typed Diameter-EAP response grammar selected by the Diameter E bit.
#[derive(Clone)]
pub enum SwmDiameterEapResponse {
    /// Ordinary TS 29.273 DEA application grammar (E clear).
    Application(Box<SwmDiameterEapAnswer>),
    /// RFC 6733 section 7.2 generic error grammar (E set).
    GenericError(Box<SwmDiameterEapGenericErrorAnswer>),
}

impl SwmDiameterEapResponse {
    /// Return whether this response uses RFC 6733's generic error grammar.
    #[must_use]
    pub const fn uses_generic_error_grammar(&self) -> bool {
        matches!(self, Self::GenericError(_))
    }

    fn session_id(&self) -> Option<&str> {
        match self {
            Self::Application(answer) => Some(answer.session_id.as_ref()),
            Self::GenericError(answer) => answer.session_id.as_deref().map(String::as_str),
        }
    }
}

impl fmt::Debug for SwmDiameterEapResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Application(answer) => {
                formatter.debug_tuple("Application").field(answer).finish()
            }
            Self::GenericError(answer) => {
                formatter.debug_tuple("GenericError").field(answer).finish()
            }
        }
    }
}

/// A SWm Diameter-EAP-Request (DER).
#[derive(Clone, PartialEq, Eq)]
pub struct SwmDiameterEapRequest {
    /// Session-Id (redacted in diagnostic output).
    pub session_id: Redacted<String>,
    /// Auth-Application-Id (must be the SWm application id).
    pub auth_application_id: u32,
    /// Origin-Host (redacted in diagnostic output).
    pub origin_host: Redacted<String>,
    /// Origin-Realm (redacted in diagnostic output).
    pub origin_realm: Redacted<String>,
    /// Destination-Realm (redacted in diagnostic output).
    pub destination_realm: Redacted<String>,
    /// Destination-Host (redacted in diagnostic output).
    pub destination_host: Option<Redacted<String>>,
    /// User-Name (redacted in diagnostic output).
    pub user_name: Option<Redacted<String>>,
    /// Serving access RAT, or `VIRTUAL` when the ePDG does not know it.
    pub rat_type: Option<SwmRatType>,
    /// UE-requested APN for a non-emergency attach (redacted in diagnostics).
    ///
    /// A present value must use the ASCII, dot-separated DNS label form used
    /// by an APN and must not contain empty or overlong labels.
    pub service_selection: Option<Redacted<String>>,
    /// Mobility capabilities advertised to the AAA server.
    pub mip6_feature_vector: Option<SwmMip6FeatureVector>,
    /// Ordered QoS profile templates supported by this ePDG.
    pub qos_capability: Option<SwmQosCapability>,
    /// Visited PLMN identifier; present only for roaming access.
    pub visited_network_identifier: Option<SwmVisitedNetworkIdentifier>,
    /// Indication that a previously assigned AAA server is unavailable.
    pub aaa_failure_indication: Option<SwmAaaFailureIndication>,
    /// Ordered 3GPP Supported-Features groups offered to the AAA server.
    pub supported_features: Vec<SwmRequestedSupportedFeatures>,
    /// UE local address used for this access (presence-only in diagnostics).
    pub ue_local_ip_address: Option<IpAddr>,
    /// RFC 7683 overload-control capability offered for this transaction.
    ///
    /// Absence remains wire-compatible with peers that do not use DOIC. The
    /// SDK currently originates only the default loss algorithm.
    pub oc_supported_features: Option<SwmOcSupportedFeatures>,
    /// Auth-Request-Type.
    pub auth_request_type: AuthRequestType,
    /// EAP-Payload (redacted in diagnostic output).
    pub eap_payload: Redacted<Vec<u8>>,
    /// Optional Emergency-Services request bitmask.
    pub emergency_services: Option<SwmEmergencyServices>,
    /// Optional device identity forwarded after DEVICE_IDENTITY recovery.
    pub terminal_information: Option<SwmTerminalInformation>,
    /// UE access-priority indication admitted by local policy.
    pub high_priority_access_info: Option<SwmHighPriorityAccessInfo>,
    /// Ordered opaque State AVP values (only their count appears in diagnostics).
    pub state_avps: Vec<Vec<u8>>,
    /// Ordered Route-Record identities (values are redacted in diagnostics).
    pub route_records: Vec<Redacted<String>>,
    /// Parser-retained optional AVPs from the trailing DER extension wildcard.
    ///
    /// Use the empty default for locally originated requests. Nonempty values
    /// can only originate from a successful typed DER parse.
    pub extensions: SwmDiameterEapRequestExtensions,
}

impl std::fmt::Debug for SwmDiameterEapRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SwmDiameterEapRequest")
            .field("session_id", &self.session_id)
            .field("auth_application_id", &self.auth_application_id)
            .field("origin_host", &self.origin_host)
            .field("origin_realm", &self.origin_realm)
            .field("destination_realm", &self.destination_realm)
            .field("destination_host", &self.destination_host)
            .field("user_name", &self.user_name)
            .field("rat_type", &self.rat_type)
            .field("service_selection", &self.service_selection)
            .field(
                "mip6_feature_vector",
                &self.mip6_feature_vector.map(|_| "<redacted>"),
            )
            .field(
                "qos_capability",
                &self.qos_capability.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "visited_network_identifier",
                &self
                    .visited_network_identifier
                    .as_ref()
                    .map(|_| "<redacted>"),
            )
            .field("aaa_failure_indication", &self.aaa_failure_indication)
            .field("supported_features", &self.supported_features.len())
            .field(
                "ue_local_ip_address",
                &self.ue_local_ip_address.map(|_| "<redacted>"),
            )
            .field("oc_supported_features", &self.oc_supported_features)
            .field("auth_request_type", &self.auth_request_type)
            .field("eap_payload", &self.eap_payload)
            .field("emergency_services", &self.emergency_services)
            .field("terminal_information", &self.terminal_information)
            .field("high_priority_access_info", &self.high_priority_access_info)
            .field("state_avps", &self.state_avps.len())
            .field("route_record_count", &self.route_records.len())
            .field("extensions", &self.extensions)
            .finish()
    }
}

/// A SWm Diameter-EAP-Answer (DEA).
///
/// Parsed WLAN location values have no raw-answer accessor. Raw answers expose
/// location presence metadata; typed value access requires authenticated
/// response correlation:
///
/// ```compile_fail
/// use opc_proto_diameter::apps::swm::SwmDiameterEapAnswer;
///
/// fn bypass_correlation(answer: &SwmDiameterEapAnswer) {
///     let _ = &answer.extensions.access_network_info;
/// }
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct SwmDiameterEapAnswer {
    /// Session-Id (redacted in diagnostic output).
    pub session_id: Redacted<String>,
    /// Auth-Application-Id (must be the SWm application id).
    pub auth_application_id: u32,
    /// Auth-Request-Type.
    pub auth_request_type: AuthRequestType,
    /// Exactly one base or experimental Diameter result.
    pub result: SwmDiameterResult,
    /// Origin-Host (redacted in diagnostic output).
    pub origin_host: Redacted<String>,
    /// Origin-Realm (redacted in diagnostic output).
    pub origin_realm: Redacted<String>,
    /// User-Name (redacted in diagnostic output).
    pub user_name: Option<Redacted<String>>,
    /// Optional subscriber authorization facts from an ordinary DEA.
    ///
    /// Identity, charging, usage, restriction, and priority values remain
    /// redacted in diagnostic output. APN-OI-Replacement is additionally
    /// trusted only when the request-bound effective mobility mode is
    /// network-based. An explicit DEA feature vector takes precedence; only
    /// when it is absent may the request envelope's trusted local mobility
    /// provenance supply that effective mode. Presence of these facts does not
    /// itself imply successful authorization.
    pub subscriber_authorization: SwmDeaSubscriberAuthorization,
    /// Mobility capabilities selected or authorized by the AAA server.
    pub mip6_feature_vector: Option<SwmMip6FeatureVector>,
    /// Ordered Supported-Features groups returned by the AAA server.
    pub supported_features: Vec<SwmSupportedFeatureList>,
    /// RFC 7683 overload-control algorithm selected by the AAA server.
    pub oc_supported_features: Option<SwmOcSupportedFeatures>,
    /// Optional RFC 7683 overload report.
    pub oc_olr: Option<SwmOcOlr>,
    /// Ordered, bounded RFC 8583 load reports.
    pub load_reports: Vec<SwmLoad>,
    /// Top-level Service-Selection (redacted in diagnostic output).
    ///
    /// This is distinct from the subscription default APN pointer carried by
    /// [`Self::default_context_identifier`].
    pub service_selection: Option<Redacted<String>>,
    /// Optional extension Context-Identifier selecting the subscription's
    /// default APN-Configuration.
    ///
    /// TS 29.272 defines this pointer inside an APN-Configuration-Profile. Some
    /// AAA profiles project it into the SWm DEA's extension AVPs; the baseline
    /// SWm DEA command ABNF does not enumerate it. Emit it only when peer
    /// support is part of the deployment profile. When this pointer is
    /// present, validation requires it to resolve to exactly one supplied,
    /// nonzero child Context-Identifier. Use
    /// [`Self::default_apn_configuration`] instead of matching it manually.
    pub default_context_identifier: Option<u32>,
    /// Raw wire-compatible APN-Configuration cores (only their count appears
    /// in diagnostic output).
    ///
    /// These public cores are untrusted wire facts and deliberately do not
    /// expose supplemental authorization fields. Product authorization must
    /// use [`SwmCorrelatedDiameterEapResponse::authorized_apn_configurations`]
    /// after authenticated connection, Origin, and request correlation.
    /// Mutating, reordering, or transplanting a core invalidates typed
    /// re-encoding and cannot expose its sealed supplement.
    pub apn_configurations: Vec<ApnConfiguration>,
    /// Permanent identity returned as Mobile-Node-Identifier.
    pub mobile_node_identifier: Option<Redacted<String>>,
    /// Maximum authorized service lifetime for exact base `DIAMETER_SUCCESS`.
    ///
    /// `None` preserves compatibility with peers that omit the conditional
    /// field. An explicit `SwmSessionTimeout::unlimited()` preserves the RFC
    /// 6733 zero value.
    pub session_timeout: Option<SwmSessionTimeout>,
    /// Optional maximum response time for the current multi-round EAP Request.
    ///
    /// Every `Unsigned32` value is retained exactly, including zero. This raw
    /// grammar fact does not imply that the timer is applicable; received
    /// clients must use
    /// [`SwmCorrelatedDiameterEapResponse::current_eap_request_timeout`] for
    /// the request-correlated, exact-result classification.
    pub multi_round_timeout: Option<SwmMultiRoundTimeout>,
    /// Optional RFC 6733 authorization lifetime, in seconds.
    ///
    /// A positive value requires [`SwmReAuthRequestType`]. Diagnostics expose
    /// only presence, not the policy value.
    pub authorization_lifetime: Option<u32>,
    /// Optional RFC 6733 grace period, in seconds.
    ///
    /// This value is reported without inventing a relationship to the other
    /// timers. Diagnostics expose only presence.
    pub auth_grace_period: Option<u32>,
    /// Re-authorization action associated with a positive lifetime.
    pub re_auth_request_type: Option<SwmReAuthRequestType>,
    /// EAP-Payload (redacted in diagnostic output).
    pub eap_payload: Option<Redacted<Vec<u8>>>,
    /// EAP-Reissued-Payload (redacted in diagnostic output).
    pub eap_reissued_payload: Option<Redacted<Vec<u8>>>,
    /// Error-Message.
    pub error_message: Option<String>,
    /// Ordered opaque State AVP values (only their count appears in diagnostics).
    pub state_avps: Vec<Vec<u8>>,
    /// EAP-Master-Session-Key (redacted in diagnostic output).
    pub eap_master_session_key: Option<Redacted<Vec<u8>>>,
    /// Parser-retained optional AVPs from the trailing DEA extension wildcard.
    ///
    /// Use the empty default for locally originated answers. Nonempty values
    /// can only originate from a successful typed DEA parse.
    pub extensions: SwmDiameterEapAnswerExtensions,
}

impl std::fmt::Debug for SwmDiameterEapAnswer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SwmDiameterEapAnswer")
            .field("session_id", &self.session_id)
            .field("auth_application_id", &self.auth_application_id)
            .field("auth_request_type", &self.auth_request_type)
            .field("result", &self.result)
            .field("origin_host", &self.origin_host)
            .field("origin_realm", &self.origin_realm)
            .field("user_name", &self.user_name)
            .field("subscriber_authorization", &self.subscriber_authorization)
            .field(
                "mip6_feature_vector",
                &self.mip6_feature_vector.map(|_| "<redacted>"),
            )
            .field("supported_features", &self.supported_features.len())
            .field("oc_supported_features", &self.oc_supported_features)
            .field("oc_olr", &self.oc_olr)
            .field("load_reports", &self.load_reports.len())
            .field("service_selection", &self.service_selection)
            .field(
                "default_context_identifier",
                &self.default_context_identifier,
            )
            .field("apn_configurations", &self.apn_configurations.len())
            .field("mobile_node_identifier", &self.mobile_node_identifier)
            .field(
                "session_timeout",
                &self.session_timeout.map(|_| "<redacted>"),
            )
            .field(
                "multi_round_timeout_present",
                &self.multi_round_timeout.is_some(),
            )
            .field(
                "authorization_lifetime_present",
                &self.authorization_lifetime.is_some(),
            )
            .field(
                "auth_grace_period_present",
                &self.auth_grace_period.is_some(),
            )
            .field(
                "re_auth_request_type_present",
                &self.re_auth_request_type.is_some(),
            )
            .field("eap_payload", &self.eap_payload)
            .field("eap_reissued_payload", &self.eap_reissued_payload)
            .field("error_message_present", &self.error_message.is_some())
            .field("state_avps", &self.state_avps.len())
            .field("eap_master_session_key", &self.eap_master_session_key)
            .field("extensions", &self.extensions)
            .finish()
    }
}

impl SwmDiameterEapRequest {
    fn validate_for_encode(&self) -> Result<(), EncodeError> {
        if self.session_id.as_ref().is_empty() {
            return Err(encode_structural_error(
                "SWm DER Session-Id must not be empty",
                "DER",
            ));
        }
        if self.origin_host.as_ref().is_empty() {
            return Err(encode_structural_error(
                "SWm DER Origin-Host must not be empty",
                "DER",
            ));
        }
        if self.origin_realm.as_ref().is_empty() {
            return Err(encode_structural_error(
                "SWm DER Origin-Realm must not be empty",
                "DER",
            ));
        }
        if self.destination_realm.as_ref().is_empty() {
            return Err(encode_structural_error(
                "SWm DER Destination-Realm must not be empty",
                "DER",
            ));
        }
        if let Some(destination_host) = self.destination_host.as_ref() {
            if destination_host.as_ref().is_empty() {
                return Err(encode_structural_error(
                    "SWm DER Destination-Host must not be empty when present",
                    "DER",
                ));
            }
        }
        if let Some(user_name) = self.user_name.as_ref() {
            if user_name.as_ref().is_empty() {
                return Err(encode_structural_error(
                    "SWm DER User-Name must not be empty when present",
                    "DER",
                ));
            }
        }
        if self
            .rat_type
            .is_some_and(|rat_type| !rat_type.is_canonical())
        {
            return Err(encode_structural_error(
                "SWm DER RAT-Type must use its canonical typed variant",
                "7.1.2.1.1",
            ));
        }
        if let Some(service_selection) = self.service_selection.as_ref() {
            if !valid_service_selection(service_selection.as_ref()) {
                return Err(encode_structural_error(
                    "SWm DER Service-Selection must be a valid APN when present",
                    "7.1.2.1.1",
                ));
            }
            if self
                .emergency_services
                .is_some_and(SwmEmergencyServices::is_emergency_indicated)
            {
                return Err(encode_structural_error(
                    "SWm DER Service-Selection must be absent for an emergency session",
                    "7.1.2.1.1",
                ));
            }
        }
        if self.auth_application_id != APPLICATION_ID.get() {
            return Err(encode_structural_error(
                "SWm DER Auth-Application-Id must be the SWm application id",
                "DER",
            ));
        }
        if !self.auth_request_type.is_authorize_authenticate() {
            return Err(encode_structural_error(
                "SWm DER Auth-Request-Type must be AUTHORIZE_AUTHENTICATE",
                "DER",
            ));
        }
        if self.eap_payload.as_ref().is_empty() {
            return Err(encode_structural_error(
                "SWm DER EAP-Payload must not be empty",
                "DER",
            ));
        }
        if self.state_avps.iter().any(Vec::is_empty) {
            return Err(encode_structural_error(
                "SWm DER State AVPs must not be empty",
                "DER",
            ));
        }
        validate_request_mobility_features(self.mip6_feature_vector)
            .map_err(|reason| encode_structural_error(reason, "7.2.3.1"))?;
        if let Some(qos_capability) = self.qos_capability.as_ref() {
            validate_qos_profiles(qos_capability.profiles()).map_err(|error| {
                let reason = match error.code() {
                    SwmDerAccessContextErrorCode::EmptyQosCapability => {
                        "SWm DER QoS-Capability requires at least one profile template"
                    }
                    SwmDerAccessContextErrorCode::TooManyQosProfiles => {
                        "SWm DER QoS-Capability contains too many profile templates"
                    }
                    SwmDerAccessContextErrorCode::InactiveIndication => {
                        "SWm DER QoS-Capability is invalid"
                    }
                    SwmDerAccessContextErrorCode::PrepopulatedField
                    | SwmDerAccessContextErrorCode::InvalidProvenance
                    | SwmDerAccessContextErrorCode::InvalidVisitedNetworkIdentifier
                    | SwmDerAccessContextErrorCode::EmptySupportedFeatures
                    | SwmDerAccessContextErrorCode::ContradictoryValues
                    | SwmDerAccessContextErrorCode::NonCanonicalValue => {
                        "SWm DER QoS-Capability is invalid"
                    }
                };
                encode_structural_error(reason, "6")
            })?;
        }
        validate_requested_supported_features(&self.supported_features)
            .map_err(|reason| encode_structural_error(reason, "6.3.29"))?;
        if self
            .oc_supported_features
            .as_ref()
            .is_some_and(|features| features.effective_feature_vector() != SWM_OC_LOSS_ALGORITHM)
        {
            return Err(encode_structural_error(
                "SWm DER OC-Supported-Features may advertise only the executable loss algorithm",
                "RFC7683-5.1.1",
            ));
        }
        if self
            .high_priority_access_info
            .is_some_and(|info| !info.is_configured())
        {
            return Err(encode_structural_error(
                "SWm DER High-Priority-Access-Info must set HPA_Configured when present",
                "5.2.3.36",
            ));
        }
        if let Some(terminal) = self.terminal_information.as_ref() {
            if let Some(software_version) = terminal.software_version.as_ref() {
                let value = software_version.as_ref().as_bytes();
                if value.len() != 2 || !value.iter().all(u8::is_ascii_digit) {
                    return Err(encode_structural_error(
                        "SWm DER Software-Version must contain exactly two decimal digits",
                        "7.3.5",
                    ));
                }
            }
        }
        Ok(())
    }

    /// Return whether the DER requests a PDN connection for emergency services.
    pub fn requests_emergency_services(&self) -> bool {
        self.emergency_services
            .is_some_and(SwmEmergencyServices::is_emergency_indicated)
    }
}

impl SwmDiameterEapAnswer {
    /// Return whether the DEA contains sealed WLAN access-location context.
    ///
    /// Received values remain unavailable until the response is authenticated
    /// and correlated through [`SwmCorrelatedDiameterEapResponse::wlan_location`].
    #[must_use]
    pub const fn has_wlan_location(&self) -> bool {
        self.extensions.access_network_info.is_some()
    }

    /// Return whether the sealed WLAN context includes a last-known timestamp.
    #[must_use]
    pub const fn has_wlan_location_time(&self) -> bool {
        self.extensions.user_location_info_time.is_some()
    }

    /// Return whether the DEA contains sealed subscriber/equipment trace data.
    ///
    /// Received values remain unavailable until the response is authenticated
    /// and correlated through [`SwmCorrelatedDiameterEapResponse::trace_info`].
    #[must_use]
    pub const fn has_trace_info(&self) -> bool {
        self.extensions.trace_info.is_some()
    }

    /// Attach one locally originated command-268 trace activation.
    ///
    /// A trace value produced by the parser remains receive-derived after
    /// cloning and is rejected here. Replay a received answer only through
    /// [`build_swm_diameter_eap_answer_envelope`].
    pub fn set_trace_info(&mut self, trace_info: SwmTraceInfo) -> Result<(), SwmTraceValueError> {
        trace_info.validate_for_encode(trace::SwmTraceEncodePurpose::Origination)?;
        self.extensions.trace_info = Some(trace_info);
        Ok(())
    }

    /// Remove an originated trace directive.
    pub fn clear_trace_info(&mut self) {
        self.extensions.trace_info = None;
    }

    /// Set an originated WLAN location with its last-known timestamp.
    ///
    /// Parsed receive-only values and retained nested extensions cannot be
    /// transplanted through this boundary.
    pub fn set_wlan_location_with_time(
        &mut self,
        access_network_info: SwmAccessNetworkInfo,
        time: SwmUserLocationInfoTime,
    ) -> Result<(), SwmLocationContextError> {
        access_network_info.validate_for_encode(location::SwmLocationEncodePurpose::Origination)?;
        self.extensions.access_network_info = Some(access_network_info);
        self.extensions.user_location_info_time = Some(time);
        self.extensions.user_location_info_time_omission = None;
        Ok(())
    }

    /// Set an originated WLAN location whose timestamp is unavailable.
    ///
    /// The typed omission evidence must originate locally; receive-derived
    /// omission provenance is rejected.
    pub fn set_wlan_location_without_time(
        &mut self,
        access_network_info: SwmAccessNetworkInfo,
        omission: SwmUserLocationInfoTimeOmission,
    ) -> Result<(), SwmLocationContextError> {
        access_network_info.validate_for_encode(location::SwmLocationEncodePurpose::Origination)?;
        if omission.was_absent_on_receive() {
            return Err(SwmLocationContextError::new(
                SwmLocationContextErrorCode::InvalidReplayProvenance,
            ));
        }
        self.extensions.access_network_info = Some(access_network_info);
        self.extensions.user_location_info_time = None;
        self.extensions.user_location_info_time_omission = Some(omission);
        Ok(())
    }

    /// Remove all originated WLAN location context.
    pub fn clear_wlan_location(&mut self) {
        self.extensions.access_network_info = None;
        self.extensions.user_location_info_time = None;
        self.extensions.user_location_info_time_omission = None;
    }

    /// Borrow typed serving/emergency gateway facts carried by the DEA.
    ///
    /// Parsed values are wire facts, not authorization. Received clients
    /// should use the authenticated [`SwmCorrelatedDiameterEapResponse`]
    /// authorization helpers. A trusted originated/server boundary can use
    /// [`SwmCorrelatedDiameterEapExchange`].
    #[must_use]
    pub const fn gateway_context(&self) -> &SwmDeaGatewayContext {
        &self.extensions.gateway_context
    }

    fn validate_for_encode(&self) -> Result<(), EncodeError> {
        self.validate_with_load_purpose(
            true,
            location::SwmLocationEncodePurpose::Origination,
            trace::SwmTraceEncodePurpose::Origination,
        )
    }

    fn validate_for_correlation(&self) -> Result<(), EncodeError> {
        self.validate_with_load_purpose(
            false,
            location::SwmLocationEncodePurpose::ParsedReplay,
            trace::SwmTraceEncodePurpose::ParsedReplay,
        )
    }

    fn validate_with_load_purpose(
        &self,
        require_complete_originated_loads: bool,
        location_purpose: location::SwmLocationEncodePurpose,
        trace_purpose: trace::SwmTraceEncodePurpose,
    ) -> Result<(), EncodeError> {
        if self.session_id.as_ref().is_empty() {
            return Err(encode_structural_error(
                "SWm DEA Session-Id must not be empty",
                "DEA",
            ));
        }
        if self.origin_host.as_ref().is_empty() {
            return Err(encode_structural_error(
                "SWm DEA Origin-Host must not be empty",
                "DEA",
            ));
        }
        if self.origin_realm.as_ref().is_empty() {
            return Err(encode_structural_error(
                "SWm DEA Origin-Realm must not be empty",
                "DEA",
            ));
        }
        if let Some(user_name) = self.user_name.as_ref() {
            if user_name.as_ref().is_empty() {
                return Err(encode_structural_error(
                    "SWm DEA User-Name must not be empty when present",
                    "DEA",
                ));
            }
        }
        if let Some(service_selection) = self.service_selection.as_ref() {
            if !valid_service_selection(service_selection.as_ref()) {
                return Err(encode_structural_error(
                    "SWm DEA Service-Selection must be a valid APN when present",
                    "DEA",
                ));
            }
        }
        validate_apn_profile(self).map_err(|reason| encode_structural_error(reason, "DEA"))?;
        if self.auth_application_id != APPLICATION_ID.get() {
            return Err(encode_structural_error(
                "SWm DEA Auth-Application-Id must be the SWm application id",
                "DEA",
            ));
        }
        dea_authorization::validate_result_conditions(
            &self.subscriber_authorization,
            self.result.is_diameter_success(),
        )
        .map_err(|reason| encode_structural_error(reason, "7.1.2.1.2"))?;
        if matches!(
            self.result,
            SwmDiameterResult::Base(code)
                if builder_helpers::result_code_requires_error_bit(code)
        ) {
            return Err(encode_structural_error(
                "base 3xxx SWm DEA requires the generic E-bit response grammar",
                "7.2",
            ));
        }
        if !self.auth_request_type.is_authorize_authenticate() {
            return Err(encode_structural_error(
                "SWm DEA Auth-Request-Type must be AUTHORIZE_AUTHENTICATE",
                "DEA",
            ));
        }
        if option_redacted_bytes_is_empty(&self.eap_payload) {
            return Err(encode_structural_error(
                "SWm DEA EAP-Payload must not be empty when present",
                "DEA",
            ));
        }
        if option_redacted_bytes_is_empty(&self.eap_reissued_payload) {
            return Err(encode_structural_error(
                "SWm DEA EAP-Reissued-Payload must not be empty when present",
                "DEA",
            ));
        }
        if option_redacted_bytes_is_empty(&self.eap_master_session_key) {
            return Err(encode_structural_error(
                "SWm DEA EAP-Master-Session-Key must not be empty when present",
                "DEA",
            ));
        }
        if let Some(mobile_node_identifier) = self.mobile_node_identifier.as_ref() {
            if mobile_node_identifier.as_ref().is_empty() {
                return Err(encode_structural_error(
                    "SWm DEA Mobile-Node-Identifier must not be empty when present",
                    "DEA",
                ));
            }
        }
        if self.state_avps.iter().any(Vec::is_empty) {
            return Err(encode_structural_error(
                "SWm DEA State AVPs must not be empty",
                "DEA",
            ));
        }
        validate_answer_mobility_features(self.mip6_feature_vector)
            .map_err(|reason| encode_structural_error(reason, "7.2.3.1"))?;
        if !self.result.is_diameter_success() && self.mip6_feature_vector.is_some() {
            return Err(encode_structural_error(
                "non-success SWm DEA must not carry MIP6-Feature-Vector",
                "7.1.2.1.2",
            ));
        }
        if !self.result.is_diameter_success() && !self.gateway_context().is_empty() {
            return Err(encode_structural_error(
                "non-success SWm DEA must not carry serving or emergency gateway context",
                "7.1.2.1.2",
            ));
        }
        validate_answer_supported_features(&self.supported_features)
            .map_err(|reason| encode_structural_error(reason, "6.3.29"))?;
        if self
            .oc_supported_features
            .as_ref()
            .is_some_and(|features| features.effective_feature_vector() != SWM_OC_LOSS_ALGORITHM)
        {
            return Err(encode_structural_error(
                "SWm DEA OC-Supported-Features may select only the executable loss algorithm",
                "RFC7683-5.1.2",
            ));
        }
        lifecycle::validate_diameter_eap_answer_overload_control(
            self.oc_supported_features.as_ref(),
            self.oc_olr.as_ref(),
        )
        .map_err(|_| {
            encode_structural_error(
                "SWm DEA overload-control values are internally inconsistent",
                "RFC7683-5.1.2",
            )
        })?;
        if self.load_reports.len() > MAX_SWM_LOAD_REPORTS {
            return Err(encode_structural_error(
                "SWm DEA contains too many Load AVPs",
                "RFC8583-7.1",
            ));
        }
        if require_complete_originated_loads
            && self
                .load_reports
                .iter()
                .any(|load| load.complete_tuple().is_none())
        {
            return Err(encode_structural_error(
                "originated SWm DEA Load requires Load-Type, Load-Value, and SourceID",
                "RFC8583-6.1",
            ));
        }
        if let Some(access_network_info) = self.extensions.access_network_info.as_ref() {
            access_network_info
                .validate_for_encode(location_purpose)
                .map_err(location::location_encode_error)?;
        }
        if let Some(trace_info) = self.extensions.trace_info.as_ref() {
            trace_info
                .validate_for_encode(trace_purpose)
                .map_err(trace::trace_encode_error)?;
        }
        match (
            location_purpose,
            self.extensions.access_network_info.is_some(),
            self.extensions.user_location_info_time.is_some(),
            self.extensions.user_location_info_time_omission,
        ) {
            (_, false, false, None) | (_, true, true, None) => {}
            (location::SwmLocationEncodePurpose::Origination, true, false, Some(omission))
                if !omission.was_absent_on_receive() => {}
            (location::SwmLocationEncodePurpose::ParsedReplay, true, false, Some(omission))
                if omission.was_absent_on_receive() => {}
            (_, false, true, _) => {
                return Err(encode_structural_error(
                    "SWm DEA User-Location-Info-Time requires Access-Network-Info",
                    "7.2.2.1.2",
                ));
            }
            (_, true, false, None) => {
                return Err(encode_structural_error(
                    "originated SWm DEA location without time requires omission evidence",
                    "7.2.2.1.2",
                ));
            }
            _ => {
                return Err(encode_structural_error(
                    "SWm DEA location-time omission evidence is internally inconsistent",
                    "7.2.2.1.2",
                ));
            }
        }
        validate_dea_timers(self).map_err(|reason| encode_structural_error(reason, "7.2.2.1.2"))?;
        if self.result_category() == SwmResultCategory::Success && !self.carries_eap_material() {
            return Err(encode_structural_error(
                "SWm DEA success must carry EAP or MSK material",
                "DEA",
            ));
        }
        Ok(())
    }

    /// Return the result-code family category.
    pub fn result_category(&self) -> SwmResultCategory {
        self.result.category()
    }

    /// Return true when the answer carries EAP challenge/reissued payload or
    /// master session key material.
    pub fn carries_eap_material(&self) -> bool {
        option_redacted_bytes_has_material(&self.eap_payload)
            || option_redacted_bytes_has_material(&self.eap_reissued_payload)
            || option_redacted_bytes_has_material(&self.eap_master_session_key)
    }

    /// Derive a redaction-safe, fail-closed authorization outcome.
    ///
    /// Only exact base `DIAMETER_SUCCESS` with nonempty MSK can reach the
    /// terminal success observation. When an EAP packet accompanies that
    /// result, it must be a well-formed EAP-Success in `EAP-Payload`.
    /// `EapInProgress` requires exact base `DIAMETER_MULTI_ROUND_AUTH`, no MSK,
    /// and exactly one well-formed EAP Request in either `EAP-Payload` or
    /// `EAP-Reissued-Payload`. Malformed packets and contradictory AVP/result
    /// combinations return `NotAuthorized`; EAP method Type-Data stays opaque.
    /// Emergency access requires the separate request-correlated evidence
    /// constructor.
    pub fn authorization_outcome(&self) -> SwmAuthorizationOutcome {
        let msk_present = option_redacted_bytes_has_material(&self.eap_master_session_key);
        let eap_payload = self
            .eap_payload
            .as_ref()
            .map(Redacted::as_ref)
            .map(Vec::as_slice);
        let reissued_payload = self
            .eap_reissued_payload
            .as_ref()
            .map(Redacted::as_ref)
            .map(Vec::as_slice);

        if self.result.is_diameter_success() && msk_present && reissued_payload.is_none() {
            return match eap_payload.map(classify_outer_eap_packet) {
                None | Some(Some(OuterEapPacketCode::Success)) => {
                    SwmAuthorizationOutcome::MskBearingSuccess
                }
                Some(Some(
                    OuterEapPacketCode::Request
                    | OuterEapPacketCode::Response
                    | OuterEapPacketCode::Failure,
                ))
                | Some(None) => SwmAuthorizationOutcome::NotAuthorized,
            };
        }

        if self.eap_master_session_key.is_none()
            && matches!(
                self.result,
                SwmDiameterResult::Base(DIAMETER_MULTI_ROUND_AUTH)
            )
        {
            let ongoing_packet = match (eap_payload, reissued_payload) {
                (Some(payload), None) | (None, Some(payload)) => classify_outer_eap_packet(payload),
                (None, None) | (Some(_), Some(_)) => None,
            };
            if ongoing_packet == Some(OuterEapPacketCode::Request) {
                return SwmAuthorizationOutcome::EapInProgress;
            }
        }

        SwmAuthorizationOutcome::NotAuthorized
    }

    /// Resolve the declared subscription default APN configuration.
    ///
    /// This accessor fails safe and returns `None` unless the answer carries
    /// exact `DIAMETER_SUCCESS` and the profile has a pointer that resolves
    /// without violating any child identifier or Service-Selection invariant.
    /// Its return value is still an uncorrelated wire core; authorization code
    /// must use the correlated exchange's checked APN surface.
    pub fn default_apn_configuration(&self) -> Option<&ApnConfiguration> {
        validate_apn_profile(self).ok()?;
        let default_context_identifier = self.default_context_identifier?;
        self.apn_configurations
            .iter()
            .find(|apn| apn.context_identifier == default_context_identifier)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum OuterEapPacketCode {
    Request,
    Response,
    Success,
    Failure,
}

fn classify_outer_eap_packet(payload: &[u8]) -> Option<OuterEapPacketCode> {
    const EAP_HEADER_LEN: usize = 4;
    const EAP_TYPED_PACKET_MIN_LEN: usize = EAP_HEADER_LEN + 1;

    if payload.len() < EAP_HEADER_LEN {
        return None;
    }
    let declared_len = usize::from(u16::from_be_bytes([payload[2], payload[3]]));
    if declared_len != payload.len() {
        return None;
    }

    match payload[0] {
        1 if payload.len() >= EAP_TYPED_PACKET_MIN_LEN => Some(OuterEapPacketCode::Request),
        2 if payload.len() >= EAP_TYPED_PACKET_MIN_LEN => Some(OuterEapPacketCode::Response),
        3 if payload.len() == EAP_HEADER_LEN => Some(OuterEapPacketCode::Success),
        4 if payload.len() == EAP_HEADER_LEN => Some(OuterEapPacketCode::Failure),
        _ => None,
    }
}

fn retain_diameter_eap_extension(
    ctx: DecodeContext,
    avp: &RawAvp<'_>,
    offset: usize,
    section: &'static str,
    seen_keys: &mut HashSet<AvpKey>,
    retention: &mut DiameterEapRetention,
    retained: &mut Vec<SwmAdditionalAvp>,
) -> Result<(), DecodeError> {
    builder_helpers::handle_unknown_avp(ctx, avp, offset, section)?;

    let key = avp.header.key();
    if ctx.duplicate_ie_policy == DuplicateIePolicy::Reject && !seen_keys.insert(key) {
        return Err(DecodeError::new(DecodeErrorCode::DuplicateIe, offset)
            .with_spec_ref(SpecRef::new("ietf", "RFC6733", "4.1")));
    }

    if ctx.unknown_ie_policy != UnknownIePolicy::Preserve {
        return Ok(());
    }
    retention.account(avp, offset, section, ctx)?;

    retained.push(SwmAdditionalAvp::from_raw_exact(avp));
    Ok(())
}

#[derive(Default)]
struct DiameterEapRetention {
    count: usize,
    bytes: usize,
}

impl DiameterEapRetention {
    fn account(
        &mut self,
        avp: &RawAvp<'_>,
        offset: usize,
        section: &'static str,
        ctx: DecodeContext,
    ) -> Result<(), DecodeError> {
        if self.count >= MAX_SWM_DIAMETER_EAP_ROUTING_AVPS {
            return Err(DecodeError::new(DecodeErrorCode::IeCountExceeded, offset)
                .with_spec_ref(SpecRef::new("3gpp", "TS29273", section)));
        }
        let retained_avp_bytes = avp
            .header
            .header_len()
            .checked_add(avp.value.len())
            .and_then(|len| len.checked_add(avp.padding.len()))
            .ok_or_else(|| {
                DecodeError::new(DecodeErrorCode::LengthOverflow, offset)
                    .with_spec_ref(SpecRef::new("ietf", "RFC6733", "4"))
            })?;
        let next_retained_bytes = self.bytes.checked_add(retained_avp_bytes).ok_or_else(|| {
            DecodeError::new(DecodeErrorCode::LengthOverflow, offset)
                .with_spec_ref(SpecRef::new("ietf", "RFC6733", "4"))
        })?;
        if next_retained_bytes > ctx.max_message_len {
            return Err(
                DecodeError::new(DecodeErrorCode::MessageLengthExceeded, offset)
                    .with_spec_ref(SpecRef::new("ietf", "RFC6733", "3")),
            );
        }

        self.bytes = next_retained_bytes;
        self.count = self.count.checked_add(1).ok_or_else(|| {
            DecodeError::new(DecodeErrorCode::LengthOverflow, offset)
                .with_spec_ref(SpecRef::new("ietf", "RFC6733", "4"))
        })?;
        Ok(())
    }
}

fn retain_diameter_eap_proxy_info(
    avp: &RawAvp<'_>,
    ctx: DecodeContext,
    offset: usize,
    value_offset: usize,
    section: &'static str,
    retention: &mut DiameterEapRetention,
    proxy_infos: &mut Vec<SwmAdditionalAvp>,
) -> Result<(), DecodeError> {
    lifecycle::validate_proxy_info(avp, ctx, offset, value_offset)?;
    retention.account(avp, offset, section, ctx)?;
    proxy_infos.push(SwmAdditionalAvp::from_raw_exact(avp));
    Ok(())
}

fn retain_diameter_eap_route_record(
    avp: &RawAvp<'_>,
    ctx: DecodeContext,
    offset: usize,
    value_offset: usize,
    section: &'static str,
    retention: &mut DiameterEapRetention,
    route_records: &mut Vec<Redacted<String>>,
) -> Result<(), DecodeError> {
    lifecycle::validate_base_definition(avp, offset)?;
    builder_helpers::validate_known_avp_value(
        avp.value,
        AvpDataType::DiameterIdentity,
        ctx,
        value_offset,
        "6.7.1",
    )?;
    let value = builder_helpers::parse_string_value(avp.value, value_offset, "6.7.1")?;
    if value.is_empty() {
        return Err(decode_structural_error_at(
            "SWm DER Route-Record must be a nonempty DiameterIdentity",
            offset,
            "6.7.1",
        ));
    }
    retention.account(avp, offset, section, ctx)?;
    route_records.push(Redacted::from(value));
    Ok(())
}

fn validate_diameter_eap_request_header(message: &Message<'_>) -> Result<(), DecodeError> {
    let flags = message.header.flags;
    if !flags.is_proxiable() || flags.is_error() {
        return Err(decode_structural_error_at(
            "SWm DER must set P and clear E",
            4,
            "DER",
        ));
    }
    Ok(())
}

fn validate_diameter_eap_answer_header(message: &Message<'_>) -> Result<(), DecodeError> {
    let flags = message.header.flags;
    if !flags.is_proxiable() || flags.is_potentially_retransmitted() {
        return Err(decode_structural_error_at(
            "SWm DEA must set P and clear T",
            4,
            "DEA",
        ));
    }
    Ok(())
}

fn validate_redirect_values(
    hosts: &[Redacted<String>],
    usage: Option<SwmRedirectHostUsage>,
    max_cache_time: Option<u32>,
) -> Result<(), SwmDiameterRedirectError> {
    if hosts.is_empty() {
        return Err(SwmDiameterRedirectError::MissingHost);
    }
    if hosts.len() > MAX_SWM_REDIRECT_HOSTS {
        return Err(SwmDiameterRedirectError::TooManyHosts);
    }
    let redirect_avp_count = hosts
        .len()
        .checked_add(usize::from(usage.is_some()))
        .and_then(|count| count.checked_add(usize::from(max_cache_time.is_some())))
        .ok_or(SwmDiameterRedirectError::TooManyAvps)?;
    if redirect_avp_count > MAX_SWM_DIAMETER_EAP_ROUTING_AVPS {
        return Err(SwmDiameterRedirectError::TooManyAvps);
    }
    for host in hosts {
        builder_helpers::validate_known_avp_value(
            host.as_ref().as_bytes(),
            AvpDataType::DiameterUri,
            DecodeContext::default(),
            0,
            "6.12",
        )
        .map_err(|_| SwmDiameterRedirectError::InvalidHost)?;
    }
    if usage.is_some_and(SwmRedirectHostUsage::is_cacheable) && max_cache_time.is_none() {
        return Err(SwmDiameterRedirectError::MissingMaxCacheTime);
    }
    Ok(())
}

fn validate_diameter_eap_routing_for_encode(
    proxy_count: usize,
    route_records: &[Redacted<String>],
    extension_count: usize,
    section: &'static str,
) -> Result<(), EncodeError> {
    let total = proxy_count
        .checked_add(route_records.len())
        .and_then(|count| count.checked_add(extension_count))
        .ok_or_else(EncodeError::length_overflow)?;
    if total > MAX_SWM_DIAMETER_EAP_ROUTING_AVPS {
        return Err(encode_structural_error(
            "SWm Diameter-EAP routing and extension count exceeds its bound",
            section,
        ));
    }
    if route_records
        .iter()
        .any(|record| record.as_ref().is_empty() || !record.as_ref().is_ascii())
    {
        return Err(encode_structural_error(
            "SWm DER Route-Record must be a nonempty ASCII DiameterIdentity",
            "6.7.1",
        ));
    }
    Ok(())
}

fn append_diameter_eap_extensions(
    dst: &mut BytesMut,
    extensions: &[SwmAdditionalAvp],
    ctx: EncodeContext,
    section: &'static str,
) -> Result<(), EncodeError> {
    if extensions.len() > MAX_SWM_DIAMETER_EAP_EXTENSIONS {
        return Err(encode_structural_error(
            "SWm Diameter-EAP extension count exceeds its bound",
            section,
        ));
    }
    for extension in extensions {
        if extension.header().flags.is_mandatory() {
            return Err(encode_structural_error(
                "SWm Diameter-EAP retained extension must clear the M bit",
                section,
            ));
        }
        extension.append_to(dst, ctx)?;
    }
    Ok(())
}

/// Build a SWm Diameter-EAP-Request message from its typed wire model.
///
/// This compatibility and parser-replay boundary validates wire semantics but
/// has no knowledge of where conditional access-context values originated.
/// New outbound integrations that supply those values should use
/// [`build_swm_diameter_eap_request_with_access_context`] instead.
pub fn build_swm_diameter_eap_request(
    request: &SwmDiameterEapRequest,
    hop_by_hop_identifier: u32,
    end_to_end_identifier: u32,
    ctx: EncodeContext,
) -> Result<OwnedMessage, EncodeError> {
    build_swm_diameter_eap_request_internal(
        request,
        &[],
        builder_helpers::app_request_flags(),
        hop_by_hop_identifier,
        end_to_end_identifier,
        ctx,
    )
}

fn build_swm_diameter_eap_request_internal(
    request: &SwmDiameterEapRequest,
    proxy_infos: &[SwmAdditionalAvp],
    flags: crate::CommandFlags,
    hop_by_hop_identifier: u32,
    end_to_end_identifier: u32,
    ctx: EncodeContext,
) -> Result<OwnedMessage, EncodeError> {
    request.validate_for_encode()?;
    validate_diameter_eap_routing_for_encode(
        proxy_infos.len(),
        &request.route_records,
        request.extensions.len(),
        "DER",
    )?;
    let mut raw_avps = BytesMut::new();
    builder_helpers::append_utf8_avp(
        &mut raw_avps,
        base::AVP_SESSION_ID,
        request.session_id.as_ref(),
        true,
        ctx,
    )?;
    builder_helpers::append_u32_avp(
        &mut raw_avps,
        base::AVP_AUTH_APPLICATION_ID,
        APPLICATION_ID.get(),
        true,
        ctx,
    )?;
    builder_helpers::append_utf8_avp(
        &mut raw_avps,
        base::AVP_ORIGIN_HOST,
        request.origin_host.as_ref(),
        true,
        ctx,
    )?;
    builder_helpers::append_utf8_avp(
        &mut raw_avps,
        base::AVP_ORIGIN_REALM,
        request.origin_realm.as_ref(),
        true,
        ctx,
    )?;
    builder_helpers::append_utf8_avp(
        &mut raw_avps,
        base::AVP_DESTINATION_REALM,
        request.destination_realm.as_ref(),
        true,
        ctx,
    )?;
    if let Some(destination_host) = request.destination_host.as_ref() {
        builder_helpers::append_utf8_avp(
            &mut raw_avps,
            base::AVP_DESTINATION_HOST,
            destination_host.as_ref(),
            true,
            ctx,
        )?;
    }
    builder_helpers::append_u32_avp(
        &mut raw_avps,
        AVP_AUTH_REQUEST_TYPE,
        request.auth_request_type.value(),
        true,
        ctx,
    )?;
    if let Some(user_name) = request.user_name.as_ref() {
        builder_helpers::append_utf8_avp(
            &mut raw_avps,
            base::AVP_USER_NAME,
            user_name.as_ref(),
            true,
            ctx,
        )?;
    }
    if let Some(rat_type) = request.rat_type {
        builder_helpers::append_vendor_u32_avp(
            &mut raw_avps,
            AVP_RAT_TYPE,
            VENDOR_ID_3GPP,
            rat_type.value(),
            true,
            ctx,
        )?;
    }
    if let Some(service_selection) = request.service_selection.as_ref() {
        builder_helpers::append_utf8_avp(
            &mut raw_avps,
            AVP_SERVICE_SELECTION,
            service_selection.as_ref(),
            true,
            ctx,
        )?;
    }
    if let Some(features) = request.mip6_feature_vector {
        builder_helpers::append_u64_avp(
            &mut raw_avps,
            AVP_MIP6_FEATURE_VECTOR,
            features.bits(),
            true,
            ctx,
        )?;
    }
    if let Some(qos_capability) = request.qos_capability.as_ref() {
        append_qos_capability_avp(&mut raw_avps, qos_capability, ctx)?;
    }
    if let Some(visited_network_identifier) = request.visited_network_identifier.as_ref() {
        builder_helpers::append_avp(
            &mut raw_avps,
            AvpHeader::vendor(AVP_VISITED_NETWORK_IDENTIFIER, VENDOR_ID_3GPP, true),
            visited_network_identifier.as_str().as_bytes(),
            ctx,
        )?;
    }
    if let Some(aaa_failure_indication) = request.aaa_failure_indication {
        builder_helpers::append_vendor_u32_avp(
            &mut raw_avps,
            AVP_AAA_FAILURE_INDICATION,
            VENDOR_ID_3GPP,
            aaa_failure_indication.value(),
            false,
            ctx,
        )?;
    }
    for supported_features in &request.supported_features {
        append_supported_features_avp(
            &mut raw_avps,
            supported_features.features(),
            supported_features.mandatory(),
            ctx,
        )?;
    }
    if let Some(oc_supported_features) = request.oc_supported_features.as_ref() {
        lifecycle::append_request_oc_supported_features(
            &mut raw_avps,
            oc_supported_features.clone(),
            ctx,
        )?;
    }
    if let Some(address) = request.ue_local_ip_address {
        let mut value = BytesMut::new();
        builder_helpers::encode_address_value(&mut value, address);
        builder_helpers::append_avp(
            &mut raw_avps,
            AvpHeader::vendor(AVP_UE_LOCAL_IP_ADDRESS, VENDOR_ID_3GPP, false),
            &value,
            ctx,
        )?;
    }
    for state in &request.state_avps {
        builder_helpers::append_octet_string_avp(&mut raw_avps, AVP_STATE, state, true, ctx)?;
    }
    if let Some(emergency_services) = request.emergency_services {
        builder_helpers::append_vendor_u32_avp(
            &mut raw_avps,
            AVP_EMERGENCY_SERVICES,
            VENDOR_ID_3GPP,
            emergency_services.value(),
            false,
            ctx,
        )?;
    }
    if let Some(terminal_information) = request.terminal_information.as_ref() {
        append_terminal_information_avp(&mut raw_avps, terminal_information, ctx)?;
    }
    if let Some(high_priority_access_info) = request.high_priority_access_info {
        builder_helpers::append_vendor_u32_avp(
            &mut raw_avps,
            AVP_HIGH_PRIORITY_ACCESS_INFO,
            VENDOR_ID_3GPP,
            high_priority_access_info.value(),
            false,
            ctx,
        )?;
    }
    builder_helpers::append_octet_string_avp(
        &mut raw_avps,
        AVP_EAP_PAYLOAD,
        request.eap_payload.as_ref(),
        true,
        ctx,
    )?;
    for proxy_info in proxy_infos {
        proxy_info.append_to(&mut raw_avps, ctx)?;
    }
    for route_record in &request.route_records {
        builder_helpers::append_utf8_avp(
            &mut raw_avps,
            base::AVP_ROUTE_RECORD,
            route_record.as_ref(),
            true,
            ctx,
        )?;
    }
    append_diameter_eap_extensions(
        &mut raw_avps,
        request.extensions.retained_avps(),
        ctx,
        "DER",
    )?;
    builder_helpers::build_message(
        flags,
        COMMAND_DIAMETER_EAP,
        APPLICATION_ID,
        raw_avps,
        hop_by_hop_identifier,
        end_to_end_identifier,
        ctx,
        "DER",
    )
}

/// Build one retained DER envelope, including exact Proxy-Info and failover T.
///
/// This is the request retransmission/rebuild boundary. It requires an
/// authenticated expected-answer binding so the resulting response can be
/// correlated before redirect targets become actionable.
pub fn build_swm_diameter_eap_request_envelope(
    envelope: &SwmDiameterEapRequestEnvelope,
    ctx: EncodeContext,
) -> Result<OwnedMessage, EncodeError> {
    let expected_peer = envelope.expected_answer_peer.as_ref().ok_or_else(|| {
        encode_structural_error(
            "outbound SWm DER requires an authenticated answer-peer binding",
            "6.2.1",
        )
    })?;
    expected_peer.validate_for_encode()?;
    if !envelope.proxiable {
        return Err(encode_structural_error(
            "SWm DER must preserve the P bit",
            "DER",
        ));
    }
    let mut flags = builder_helpers::app_request_flags();
    if envelope.potentially_retransmitted {
        flags = crate::CommandFlags::from_bits(
            flags.bits() | crate::CommandFlags::POTENTIALLY_RETRANSMITTED,
        );
    }
    build_swm_diameter_eap_request_internal(
        &envelope.request,
        &envelope.proxy_infos,
        flags,
        envelope.transaction.hop_by_hop_identifier(),
        envelope.transaction.end_to_end_identifier(),
        ctx,
    )
}

/// Validate conditional access-context sources and build one outbound DER.
///
/// All twelve conditional authorization-context fields on `request` must
/// initially be absent. This
/// prevents checked context from being silently combined with independently
/// populated wire fields. Validation and application happen on a clone, so a
/// failure never modifies the caller's request.
pub fn build_swm_diameter_eap_request_with_access_context(
    request: &SwmDiameterEapRequest,
    access_context: SwmDerAccessContext,
    hop_by_hop_identifier: u32,
    end_to_end_identifier: u32,
    ctx: EncodeContext,
) -> Result<SwmBuiltDerAccessContextRequest, SwmDerAccessContextBuildError> {
    let mut request = request.clone();
    let source_snapshot = access_context.apply_to(&mut request)?;
    let message = build_swm_diameter_eap_request(
        &request,
        hop_by_hop_identifier,
        end_to_end_identifier,
        ctx,
    )?;
    Ok(SwmBuiltDerAccessContextRequest {
        request,
        message,
        source_snapshot,
    })
}

/// Parse a SWm Diameter-EAP-Request message.
pub fn parse_swm_diameter_eap_request(
    message: &Message<'_>,
    ctx: DecodeContext,
) -> Result<SwmDiameterEapRequest, DecodeError> {
    parse_swm_diameter_eap_request_with_provenance(message, ctx)
        .map_err(DiameterParserError::into_decode_error)
}

/// Parse a SWm Diameter-EAP-Request while retaining typed provenance for an
/// omitted mandatory AVP.
pub fn parse_swm_diameter_eap_request_with_provenance(
    message: &Message<'_>,
    ctx: DecodeContext,
) -> Result<SwmDiameterEapRequest, DiameterParserError> {
    parse_swm_diameter_eap_request_parts(message, ctx).map(|parts| parts.request)
}

struct ParsedSwmDiameterEapRequestParts {
    request: SwmDiameterEapRequest,
    proxy_infos: Vec<SwmAdditionalAvp>,
}

fn parse_swm_diameter_eap_request_parts(
    message: &Message<'_>,
    ctx: DecodeContext,
) -> Result<ParsedSwmDiameterEapRequestParts, DiameterParserError> {
    builder_helpers::ensure_app_header(
        message,
        COMMAND_DIAMETER_EAP,
        APPLICATION_ID,
        CommandKind::Request,
        "DER",
    )
    .map_err(|error| DiameterParserError::decoded(message, error))?;
    validate_diameter_eap_request_header(message)
        .map_err(|error| DiameterParserError::decoded(message, error))?;
    let mut session_id = None;
    let mut auth_application_id = None;
    let mut origin_host = None;
    let mut origin_realm = None;
    let mut destination_realm = None;
    let mut destination_host = None;
    let mut user_name = None;
    let mut rat_type = None;
    let mut service_selection = None;
    let mut mip6_feature_vector = None;
    let mut qos_capability = None;
    let mut visited_network_identifier = None;
    let mut aaa_failure_indication = None;
    let mut supported_features = Vec::new();
    let mut ue_local_ip_address = None;
    let mut oc_supported_features = None;
    let mut auth_request_type = None;
    let mut eap_payload = None;
    let mut emergency_services = None;
    let mut terminal_information = None;
    let mut high_priority_access_info = None;
    let mut state_avps = Vec::new();
    let mut route_records = Vec::new();
    let mut proxy_infos = Vec::new();
    let mut terminal_missing_imei = None;
    let mut supported_features_missing_child = None;
    let mut qos_missing_child = None;
    let mut extensions = Vec::new();
    let mut extension_keys = HashSet::new();
    let mut retention = DiameterEapRetention::default();
    let parse_result = builder_helpers::for_each_avp(
        message.raw_avps,
        ctx,
        crate::DIAMETER_HEADER_LEN,
        0,
        |offset, avp| {
            let value_offset = builder_helpers::offset_add(offset, avp.header.header_len(), "DER")?;
            let code = avp.header.code;
            dea_authorization::validate_top_level_identity(&avp.header, offset)?;
            if let Some(vendor_id) = avp.header.vendor_id {
                if vendor_id.get() == 0 {
                    return Err(DecodeError::new(
                        DecodeErrorCode::Structural {
                            reason: "SWm DER Vendor-Id field must not contain zero",
                        },
                        offset,
                    )
                    .with_spec_ref(SpecRef::new("ietf", "RFC6733", "4.1.1")));
                }
                if code == AVP_EMERGENCY_SERVICES && vendor_id == VENDOR_ID_3GPP {
                    validate_emergency_services_flags(&avp.header, offset, "DER")?;
                    let value =
                        builder_helpers::parse_u32_value(avp.value, value_offset, "7.2.3.4")?;
                    builder_helpers::set_once(
                        &mut emergency_services,
                        SwmEmergencyServices::from_value(value),
                        offset,
                        "7.2.3.4",
                    )?;
                } else if code == AVP_RAT_TYPE && vendor_id == VENDOR_ID_3GPP {
                    validate_3gpp_mandatory_flags(&avp.header, offset, "5.3.31")?;
                    let value =
                        builder_helpers::parse_u32_value(avp.value, value_offset, "5.3.31")?;
                    builder_helpers::set_once(
                        &mut rat_type,
                        SwmRatType::from_value(value),
                        offset,
                        "5.3.31",
                    )?;
                } else if code == AVP_VISITED_NETWORK_IDENTIFIER && vendor_id == VENDOR_ID_3GPP {
                    validate_3gpp_m_bit_agnostic_flags(
                        &avp.header,
                        offset,
                        "TS29273",
                        "9.2.3.1.2",
                    )?;
                    let value = SwmVisitedNetworkIdentifier::from_wire(avp.value, value_offset)?;
                    builder_helpers::set_once(
                        &mut visited_network_identifier,
                        value,
                        offset,
                        "9.2.3.1.2",
                    )?;
                } else if code == AVP_AAA_FAILURE_INDICATION && vendor_id == VENDOR_ID_3GPP {
                    validate_3gpp_m_bit_agnostic_flags(&avp.header, offset, "TS29273", "8.2.3.21")?;
                    let value =
                        builder_helpers::parse_u32_value(avp.value, value_offset, "8.2.3.21")?;
                    if value & 1 == 0 {
                        return Err(DecodeError::new(
                            DecodeErrorCode::Structural {
                                reason:
                                    "AAA-Failure-Indication must set the defined AAA Failure bit",
                            },
                            value_offset,
                        )
                        .with_spec_ref(SpecRef::new("3gpp", "TS29273", "8.2.3.21")));
                    }
                    builder_helpers::set_once(
                        &mut aaa_failure_indication,
                        SwmAaaFailureIndication::previously_assigned_server_unavailable(),
                        offset,
                        "8.2.3.21",
                    )?;
                } else if code == AVP_TERMINAL_INFORMATION && vendor_id == VENDOR_ID_3GPP {
                    validate_3gpp_mandatory_flags(&avp.header, offset, "7.3.3")?;
                    match parse_terminal_information(avp.value, ctx, value_offset, 1) {
                        Ok(terminal) => builder_helpers::set_once(
                            &mut terminal_information,
                            terminal,
                            offset,
                            "7.3.3",
                        )?,
                        Err(TerminalInformationParseError::MissingImei(error)) => {
                            terminal_missing_imei = Some((error.clone(), offset));
                            return Err(error);
                        }
                        Err(TerminalInformationParseError::Decode(error)) => return Err(error),
                    }
                } else if code == AVP_SUPPORTED_FEATURES && vendor_id == VENDOR_ID_3GPP {
                    if supported_features.len() >= MAX_SWM_SUPPORTED_FEATURES {
                        return Err(DecodeError::new(DecodeErrorCode::IeCountExceeded, offset)
                            .with_spec_ref(SpecRef::new("3gpp", "TS29229", "6.3.29")));
                    }
                    match parse_requested_supported_features(&avp, ctx, value_offset, 1, offset) {
                        Ok(features) => supported_features.push(features),
                        Err(SupportedFeaturesParseError::Missing { error, key }) => {
                            supported_features_missing_child = Some((error.clone(), key, offset));
                            return Err(error);
                        }
                        Err(SupportedFeaturesParseError::Decode(error)) => return Err(error),
                    }
                } else if code == AVP_UE_LOCAL_IP_ADDRESS && vendor_id == VENDOR_ID_3GPP {
                    validate_3gpp_m_bit_agnostic_flags(&avp.header, offset, "TS29273", "7.2.3.1")?;
                    let value =
                        builder_helpers::parse_address_value(avp.value, value_offset, "5.3.96")
                            .map_err(|error| {
                                error.with_spec_ref(SpecRef::new("3gpp", "TS29212", "5.3.96"))
                            })?;
                    builder_helpers::set_once(&mut ue_local_ip_address, value, offset, "DER")
                        .map_err(|error| {
                            error.with_spec_ref(SpecRef::new("3gpp", "TS29212", "5.3.96"))
                        })?;
                } else if code == AVP_HIGH_PRIORITY_ACCESS_INFO && vendor_id == VENDOR_ID_3GPP {
                    validate_3gpp_m_bit_agnostic_flags(&avp.header, offset, "TS29273", "5.2.3.36")?;
                    let value =
                        builder_helpers::parse_u32_value(avp.value, value_offset, "5.2.3.36")?;
                    if value & 1 == 0 {
                        return Err(DecodeError::new(
                            DecodeErrorCode::Structural {
                                reason: "High-Priority-Access-Info must set HPA_Configured when present",
                            },
                            value_offset,
                        )
                        .with_spec_ref(SpecRef::new("3gpp", "TS29273", "5.2.3.36")));
                    }
                    builder_helpers::set_once(
                        &mut high_priority_access_info,
                        SwmHighPriorityAccessInfo::from_value(value),
                        offset,
                        "5.2.3.36",
                    )?;
                } else if vendor_id == VENDOR_ID_3GPP
                    && matches!(
                        code,
                        AVP_APN_OI_REPLACEMENT
                            | AVP_3GPP_CHARGING_CHARACTERISTICS
                            | AVP_UE_USAGE_TYPE
                            | AVP_CORE_NETWORK_RESTRICTIONS
                            | AVP_MPS_PRIORITY
                    )
                {
                    return Err(decode_structural_error_at(
                        "answer-only subscriber authorization AVP appears in SWm DER",
                        offset,
                        "7.2.2.1.1",
                    ));
                } else if trace::is_trace_avp_code(code) {
                    return Err(decode_structural_error_at(
                        "answer-only trace AVP is not valid in SWm DER grammar",
                        offset,
                        "7.2.2.1.1",
                    ));
                } else {
                    retain_diameter_eap_extension(
                        ctx,
                        &avp,
                        offset,
                        "DER",
                        &mut extension_keys,
                        &mut retention,
                        &mut extensions,
                    )?;
                }
                return Ok(());
            }
            if code == base::AVP_SESSION_ID {
                let value = builder_helpers::parse_string_value(avp.value, value_offset, "8.8")?;
                builder_helpers::set_once(&mut session_id, Redacted::from(value), offset, "8.8")?;
            } else if code == base::AVP_ORIGIN_HOST {
                let value = builder_helpers::parse_string_value(avp.value, value_offset, "6.3")?;
                builder_helpers::set_once(&mut origin_host, Redacted::from(value), offset, "6.3")?;
            } else if code == base::AVP_ORIGIN_REALM {
                let value = builder_helpers::parse_string_value(avp.value, value_offset, "6.4")?;
                builder_helpers::set_once(&mut origin_realm, Redacted::from(value), offset, "6.4")?;
            } else if code == base::AVP_AUTH_APPLICATION_ID {
                let value = builder_helpers::parse_u32_value(avp.value, value_offset, "6.8")?;
                builder_helpers::set_once(&mut auth_application_id, value, offset, "6.8")?;
            } else if code == base::AVP_DESTINATION_REALM {
                let value = builder_helpers::parse_string_value(avp.value, value_offset, "6.6")?;
                builder_helpers::set_once(
                    &mut destination_realm,
                    Redacted::from(value),
                    offset,
                    "6.6",
                )?;
            } else if code == base::AVP_DESTINATION_HOST {
                let value = builder_helpers::parse_string_value(avp.value, value_offset, "6.5")?;
                builder_helpers::set_once(
                    &mut destination_host,
                    Redacted::from(value),
                    offset,
                    "6.5",
                )?;
            } else if code == base::AVP_USER_NAME {
                let value = builder_helpers::parse_string_value(avp.value, value_offset, "8.14")?;
                builder_helpers::set_once(&mut user_name, Redacted::from(value), offset, "8.14")?;
            } else if code == AVP_SUBSCRIPTION_ID {
                return Err(decode_structural_error_at(
                    "answer-only Subscription-Id appears in SWm DER",
                    offset,
                    "7.2.2.1.1",
                ));
            } else if code == AVP_SERVICE_SELECTION {
                validate_base_mandatory_flags(&avp.header, offset, "6.2")?;
                let value = apn::parse_requested_apn_wire_value(avp.value, value_offset)?;
                builder_helpers::set_once(&mut service_selection, value, offset, "6.2")?;
            } else if code == AVP_MIP6_FEATURE_VECTOR {
                validate_base_m_bit_agnostic_flags(&avp.header, offset, "4.2.5")?;
                let value = builder_helpers::parse_u64_value(avp.value, value_offset, "4.2.5")?;
                builder_helpers::set_once(
                    &mut mip6_feature_vector,
                    SwmMip6FeatureVector::from_bits_retain(value),
                    offset,
                    "4.2.5",
                )?;
            } else if code == AVP_QOS_CAPABILITY {
                validate_base_m_bit_agnostic_flags_for(&avp.header, offset, "RFC5777", "6")?;
                match parse_qos_capability(avp.value, ctx, value_offset, 1) {
                    Ok(value) => {
                        builder_helpers::set_once(&mut qos_capability, value, offset, "6")?
                    }
                    Err(QosCapabilityParseError::Missing {
                        error,
                        key,
                        profile_offset,
                    }) => {
                        let error = *error;
                        qos_missing_child = Some((error.clone(), key, offset, profile_offset));
                        return Err(error);
                    }
                    Err(QosCapabilityParseError::Decode(error)) => return Err(error),
                }
            } else if code == AVP_OC_SUPPORTED_FEATURES {
                let value = lifecycle::parse_diameter_eap_request_oc_supported_features(
                    &avp,
                    ctx,
                    offset,
                    value_offset,
                )?;
                builder_helpers::set_once(
                    &mut oc_supported_features,
                    value,
                    offset,
                    "RFC7683-7.1",
                )?;
            } else if is_forbidden_der_overload_avp(code) {
                return Err(DecodeError::new(
                    DecodeErrorCode::Structural {
                        reason: "answer-only or grouped overload AVP appears at DER top level",
                    },
                    offset,
                )
                .with_spec_ref(SpecRef::new("3gpp", "TS29273", "7.2.2.1.1")));
            } else if code == base::AVP_MULTI_ROUND_TIME_OUT {
                return Err(DecodeError::new(
                    DecodeErrorCode::Structural {
                        reason: "Multi-Round-Time-Out is forbidden in Diameter-EAP-Request",
                    },
                    offset,
                )
                .with_spec_ref(SpecRef::new("ietf", "RFC4072", "5")));
            } else if code == AVP_AUTH_REQUEST_TYPE {
                let value = builder_helpers::parse_u32_value(avp.value, value_offset, "8.7")?;
                builder_helpers::set_once(
                    &mut auth_request_type,
                    AuthRequestType::from_value(value),
                    offset,
                    "8.7",
                )?;
            } else if code == AVP_EAP_PAYLOAD {
                builder_helpers::set_once(
                    &mut eap_payload,
                    Redacted::from(avp.value.to_vec()),
                    offset,
                    "4.1",
                )?;
            } else if avp.header.key() == AvpKey::ietf(base::AVP_PROXY_INFO) {
                retain_diameter_eap_proxy_info(
                    &avp,
                    ctx,
                    offset,
                    value_offset,
                    "DER",
                    &mut retention,
                    &mut proxy_infos,
                )?;
            } else if avp.header.key() == AvpKey::ietf(base::AVP_ROUTE_RECORD) {
                retain_diameter_eap_route_record(
                    &avp,
                    ctx,
                    offset,
                    value_offset,
                    "DER",
                    &mut retention,
                    &mut route_records,
                )?;
            } else if matches!(
                avp.header.key(),
                key if key == AvpKey::ietf(base::AVP_RESULT_CODE)
                    || key == AvpKey::ietf(base::AVP_EXPERIMENTAL_RESULT)
                    || key == AvpKey::ietf(base::AVP_REDIRECT_HOST)
                    || key == AvpKey::ietf(base::AVP_REDIRECT_HOST_USAGE)
                    || key == AvpKey::ietf(base::AVP_REDIRECT_MAX_CACHE_TIME)
                    || key == AvpKey::ietf(base::AVP_FAILED_AVP)
            ) {
                return Err(decode_structural_error_at(
                    "answer-only routing or error AVP is not valid in SWm DER grammar",
                    offset,
                    "7.2",
                ));
            } else if code == AVP_STATE {
                state_avps.push(avp.value.to_vec());
            } else if trace::is_trace_avp_code(code) {
                return Err(decode_structural_error_at(
                    "trace AVP uses the wrong vendor identity in SWm DER",
                    offset,
                    "7.2.2.1.1",
                ));
            } else {
                retain_diameter_eap_extension(
                    ctx,
                    &avp,
                    offset,
                    "DER",
                    &mut extension_keys,
                    &mut retention,
                    &mut extensions,
                )?;
            }
            Ok(())
        },
    );
    if let Err(error) = parse_result {
        if let Some((missing_error, key, capability_offset, profile_offset)) = qos_missing_child {
            let child = base::dictionary()
                .find_avp(key)
                .or_else(|| dictionary().find_avp(key));
            let capability = dictionary().find_avp(AvpKey::ietf(AVP_QOS_CAPABILITY));
            let profile = dictionary().find_avp(AvpKey::ietf(AVP_QOS_PROFILE_TEMPLATE));
            return Err(match (child, capability, profile_offset, profile) {
                (
                    Some(definition),
                    Some(capability_definition),
                    Some(profile_offset),
                    Some(profile_definition),
                ) => DiameterParserError::missing_with_ancestors(
                    message,
                    missing_error,
                    definition,
                    &[
                        (capability_definition, capability_offset),
                        (profile_definition, profile_offset),
                    ],
                    APPLICATION_ID,
                    COMMAND_DIAMETER_EAP,
                ),
                (Some(definition), Some(capability_definition), None, _) => {
                    DiameterParserError::missing_with_parent(
                        message,
                        missing_error,
                        definition,
                        capability_definition,
                        capability_offset,
                        APPLICATION_ID,
                        COMMAND_DIAMETER_EAP,
                    )
                }
                _ => DiameterParserError::decoded(message, error),
            });
        }
        if let Some((missing_error, key, parent_offset)) = supported_features_missing_child {
            let child = base::dictionary()
                .find_avp(key)
                .or_else(|| dictionary().find_avp(key));
            let parent =
                dictionary().find_avp(AvpKey::vendor(AVP_SUPPORTED_FEATURES, VENDOR_ID_3GPP));
            return Err(match (child, parent) {
                (Some(definition), Some(parent_definition)) => {
                    DiameterParserError::missing_with_parent(
                        message,
                        missing_error,
                        definition,
                        parent_definition,
                        parent_offset,
                        APPLICATION_ID,
                        COMMAND_DIAMETER_EAP,
                    )
                }
                _ => DiameterParserError::decoded(message, error),
            });
        }
        if let Some((missing_error, parent_offset)) = terminal_missing_imei {
            let imei = dictionary().find_avp(AvpKey::vendor(AVP_IMEI, VENDOR_ID_3GPP));
            let parent =
                dictionary().find_avp(AvpKey::vendor(AVP_TERMINAL_INFORMATION, VENDOR_ID_3GPP));
            return Err(match (imei, parent) {
                (Some(definition), Some(parent_definition)) => {
                    DiameterParserError::missing_with_parent(
                        message,
                        missing_error,
                        definition,
                        parent_definition,
                        parent_offset,
                        APPLICATION_ID,
                        COMMAND_DIAMETER_EAP,
                    )
                }
                _ => DiameterParserError::decoded(message, error),
            });
        }
        return Err(DiameterParserError::decoded(message, error));
    }
    let auth_application_id = require_swm_request_field(
        auth_application_id,
        "SWm DER requires Auth-Application-Id",
        AvpKey::ietf(base::AVP_AUTH_APPLICATION_ID),
        message,
        "DER",
    )?;
    if auth_application_id != APPLICATION_ID.get() {
        return Err(DiameterParserError::decoded(
            message,
            DecodeError::new(
                DecodeErrorCode::Structural {
                    reason: "SWm DER Auth-Application-Id does not match the SWm application id",
                },
                crate::DIAMETER_HEADER_LEN,
            )
            .with_spec_ref(SpecRef::new("3gpp", "TS29273", "DER")),
        ));
    }
    let request = SwmDiameterEapRequest {
        session_id: require_swm_request_field(
            session_id,
            "SWm DER requires Session-Id",
            AvpKey::ietf(base::AVP_SESSION_ID),
            message,
            "DER",
        )?,
        auth_application_id,
        origin_host: require_swm_request_field(
            origin_host,
            "SWm DER requires Origin-Host",
            AvpKey::ietf(base::AVP_ORIGIN_HOST),
            message,
            "DER",
        )?,
        origin_realm: require_swm_request_field(
            origin_realm,
            "SWm DER requires Origin-Realm",
            AvpKey::ietf(base::AVP_ORIGIN_REALM),
            message,
            "DER",
        )?,
        destination_realm: require_swm_request_field(
            destination_realm,
            "SWm DER requires Destination-Realm",
            AvpKey::ietf(base::AVP_DESTINATION_REALM),
            message,
            "DER",
        )?,
        destination_host,
        user_name,
        rat_type,
        service_selection,
        mip6_feature_vector,
        qos_capability,
        visited_network_identifier,
        aaa_failure_indication,
        supported_features,
        ue_local_ip_address,
        oc_supported_features,
        auth_request_type: require_swm_request_field(
            auth_request_type,
            "SWm DER requires Auth-Request-Type",
            AvpKey::ietf(AVP_AUTH_REQUEST_TYPE),
            message,
            "DER",
        )?,
        eap_payload: require_swm_request_field(
            eap_payload,
            "SWm DER requires EAP-Payload",
            AvpKey::ietf(AVP_EAP_PAYLOAD),
            message,
            "DER",
        )?,
        emergency_services,
        terminal_information,
        high_priority_access_info,
        state_avps,
        route_records,
        extensions: SwmDiameterEapRequestExtensions { avps: extensions },
    };
    validate_decoded_request(&request)
        .map_err(|error| DiameterParserError::decoded(message, error))?;
    Ok(ParsedSwmDiameterEapRequestParts {
        request,
        proxy_infos,
    })
}

fn require_swm_request_field<T>(
    field: Option<T>,
    reason: &'static str,
    key: AvpKey,
    message: &Message<'_>,
    section: &'static str,
) -> Result<T, DiameterParserError> {
    field.ok_or_else(|| {
        let error = decode_structural_error(reason, section);
        match base::dictionary()
            .find_avp(key)
            .or_else(|| dictionary().find_avp(key))
        {
            Some(definition) => DiameterParserError::missing_for_definition(
                message,
                error,
                definition,
                APPLICATION_ID,
                COMMAND_DIAMETER_EAP,
            ),
            None => DiameterParserError::decoded(message, error),
        }
    })
}

/// Parse a SWm DER while retaining its Diameter transaction identifiers.
///
/// Emergency authorization requires this envelope rather than answer-local
/// facts so a stale or out-of-order DEA cannot be correlated by Session-Id
/// alone.
pub fn parse_swm_diameter_eap_request_envelope(
    message: &Message<'_>,
    ctx: DecodeContext,
) -> Result<SwmDiameterEapRequestEnvelope, DecodeError> {
    parse_swm_diameter_eap_request_envelope_with_provenance(message, ctx)
        .map_err(DiameterParserError::into_decode_error)
}

/// Parse a SWm DER transaction envelope while retaining typed provenance for
/// an omitted mandatory AVP.
pub fn parse_swm_diameter_eap_request_envelope_with_provenance(
    message: &Message<'_>,
    ctx: DecodeContext,
) -> Result<SwmDiameterEapRequestEnvelope, DiameterParserError> {
    let transaction = SwmDiameterTransaction::from_message(message);
    let parts = parse_swm_diameter_eap_request_parts(message, ctx)?;
    Ok(SwmDiameterEapRequestEnvelope {
        transaction,
        proxiable: message.header.flags.is_proxiable(),
        potentially_retransmitted: message.header.flags.is_potentially_retransmitted(),
        expected_answer_peer: None,
        locally_configured_mobility_mode: None,
        request: parts.request,
        proxy_infos: parts.proxy_infos,
    })
}

/// Build a SWm Diameter-EAP-Answer message.
///
/// RFC 7683 overload-control response AVPs are request-conditioned and are
/// therefore rejected at this answer-local compatibility boundary. Use
/// [`build_swm_diameter_eap_answer_for`] when `oc_supported_features` or
/// `oc_olr` is present. RFC 8583 Load reports are independent and remain
/// available here.
pub fn build_swm_diameter_eap_answer(
    answer: &SwmDiameterEapAnswer,
    hop_by_hop_identifier: u32,
    end_to_end_identifier: u32,
    ctx: EncodeContext,
) -> Result<OwnedMessage, EncodeError> {
    if !answer.gateway_context().is_empty() {
        return Err(encode_structural_error(
            "SWm DEA gateway context requires the request-bound answer builder",
            "7.1.2.1.2",
        ));
    }
    build_swm_diameter_eap_answer_internal(
        answer,
        &[],
        true,
        hop_by_hop_identifier,
        end_to_end_identifier,
        SwmDiameterEapAnswerBuildMode {
            request_conditioned: false,
            location_purpose: location::SwmLocationEncodePurpose::Origination,
            trace_purpose: trace::SwmTraceEncodePurpose::Origination,
        },
        ctx,
    )
}

/// Canonically rebuild one immutable parsed SWm DEA envelope.
///
/// This is the only encoding boundary that accepts receive-only location
/// provenance such as an SSID-only `Access-Network-Info` or a received
/// location without `User-Location-Info-Time`. The sealed envelope prevents
/// those exceptions from being copied into or mutating a newly originated
/// answer. Known AVP flags are emitted canonically, while retained optional
/// extensions and the exact Diameter transaction and Proxy-Info chain are
/// preserved.
pub fn build_swm_diameter_eap_answer_envelope(
    envelope: &SwmDiameterEapAnswerEnvelope,
    ctx: EncodeContext,
) -> Result<OwnedMessage, EncodeError> {
    if envelope.provenance != SwmDiameterEapAnswerEnvelopeProvenance::Parsed {
        return Err(encode_structural_error(
            "SWm DEA replay requires an immutable parsed answer envelope",
            "DEA",
        ));
    }
    build_swm_diameter_eap_answer_internal(
        &envelope.answer,
        &envelope.proxy_infos,
        envelope.proxiable,
        envelope.transaction.hop_by_hop_identifier(),
        envelope.transaction.end_to_end_identifier(),
        SwmDiameterEapAnswerBuildMode {
            request_conditioned: true,
            location_purpose: location::SwmLocationEncodePurpose::ParsedReplay,
            trace_purpose: trace::SwmTraceEncodePurpose::ParsedReplay,
        },
        ctx,
    )
}

#[derive(Clone, Copy)]
struct SwmDiameterEapAnswerBuildMode {
    request_conditioned: bool,
    location_purpose: location::SwmLocationEncodePurpose,
    trace_purpose: trace::SwmTraceEncodePurpose,
}

fn build_swm_diameter_eap_answer_internal(
    answer: &SwmDiameterEapAnswer,
    proxy_infos: &[SwmAdditionalAvp],
    proxiable: bool,
    hop_by_hop_identifier: u32,
    end_to_end_identifier: u32,
    mode: SwmDiameterEapAnswerBuildMode,
    ctx: EncodeContext,
) -> Result<OwnedMessage, EncodeError> {
    answer.validate_with_load_purpose(
        mode.location_purpose == location::SwmLocationEncodePurpose::Origination,
        mode.location_purpose,
        mode.trace_purpose,
    )?;
    let retained_extension_count = answer
        .extensions
        .len()
        .checked_add(
            answer
                .extensions
                .access_network_info
                .as_ref()
                .map_or(0, |access| access.extensions().len()),
        )
        .and_then(|count| {
            answer
                .extensions
                .trace_info
                .as_ref()
                .map_or(Some(count), |trace_info| {
                    trace_info
                        .retained_avp_count()
                        .and_then(|trace_count| count.checked_add(trace_count))
                })
        })
        .ok_or_else(EncodeError::length_overflow)?;
    validate_diameter_eap_routing_for_encode(
        proxy_infos.len(),
        &[],
        retained_extension_count,
        "DEA",
    )?;
    if !mode.request_conditioned
        && (answer.oc_supported_features.is_some() || answer.oc_olr.is_some())
    {
        return Err(encode_structural_error(
            "SWm DEA overload-control response requires a correlated DER capability offer",
            "RFC7683-5.1.2",
        ));
    }
    if !mode.request_conditioned
        && dea_authorization::has_request_conditioned_values(&answer.subscriber_authorization)
    {
        return Err(encode_structural_error(
            "SWm DEA APN-OI-Replacement requires a correlated DER",
            "7.1.2.1.2",
        ));
    }
    let mut raw_avps = BytesMut::new();
    builder_helpers::append_utf8_avp(
        &mut raw_avps,
        base::AVP_SESSION_ID,
        answer.session_id.as_ref(),
        true,
        ctx,
    )?;
    builder_helpers::append_u32_avp(
        &mut raw_avps,
        base::AVP_AUTH_APPLICATION_ID,
        answer.auth_application_id,
        true,
        ctx,
    )?;
    builder_helpers::append_u32_avp(
        &mut raw_avps,
        AVP_AUTH_REQUEST_TYPE,
        answer.auth_request_type.value(),
        true,
        ctx,
    )?;
    match answer.result {
        SwmDiameterResult::Base(code) => {
            builder_helpers::append_u32_avp(&mut raw_avps, base::AVP_RESULT_CODE, code, true, ctx)?
        }
        SwmDiameterResult::Experimental { vendor_id, code } => {
            append_experimental_result_avp(&mut raw_avps, vendor_id, code, ctx)?;
        }
    }
    builder_helpers::append_utf8_avp(
        &mut raw_avps,
        base::AVP_ORIGIN_HOST,
        answer.origin_host.as_ref(),
        true,
        ctx,
    )?;
    builder_helpers::append_utf8_avp(
        &mut raw_avps,
        base::AVP_ORIGIN_REALM,
        answer.origin_realm.as_ref(),
        true,
        ctx,
    )?;
    if let Some(user_name) = answer.user_name.as_ref() {
        builder_helpers::append_utf8_avp(
            &mut raw_avps,
            base::AVP_USER_NAME,
            user_name.as_ref(),
            true,
            ctx,
        )?;
    }
    dea_authorization::append_authorization(&mut raw_avps, &answer.subscriber_authorization, ctx)?;
    if let Some(features) = answer.mip6_feature_vector {
        builder_helpers::append_u64_avp(
            &mut raw_avps,
            AVP_MIP6_FEATURE_VECTOR,
            features.bits(),
            true,
            ctx,
        )?;
    }
    mobility::append_gateway_context(&mut raw_avps, answer.gateway_context(), ctx)?;
    for supported_features in &answer.supported_features {
        append_supported_features_avp(&mut raw_avps, supported_features, false, ctx)?;
    }
    if let Some(oc_supported_features) = answer.oc_supported_features.as_ref() {
        lifecycle::append_answer_oc_supported_features(
            &mut raw_avps,
            oc_supported_features.clone(),
            ctx,
        )?;
    }
    if let Some(oc_olr) = answer.oc_olr.as_ref() {
        lifecycle::append_oc_olr(&mut raw_avps, oc_olr.clone(), ctx)?;
    }
    for load in &answer.load_reports {
        lifecycle::append_load(&mut raw_avps, load, ctx)?;
    }
    if let Some(access_network_info) = answer.extensions.access_network_info.as_ref() {
        location::append_access_network_info_avp(
            &mut raw_avps,
            access_network_info,
            mode.location_purpose,
            ctx,
        )?;
    }
    if let Some(user_location_info_time) = answer.extensions.user_location_info_time {
        location::append_user_location_info_time_avp(&mut raw_avps, user_location_info_time, ctx)?;
    }
    if let Some(trace_info) = answer.extensions.trace_info.as_ref() {
        trace::append_trace_info(&mut raw_avps, trace_info, mode.trace_purpose, ctx)?;
    }
    if let Some(default_context_identifier) = answer.default_context_identifier {
        builder_helpers::append_vendor_u32_avp(
            &mut raw_avps,
            AVP_CONTEXT_IDENTIFIER,
            VENDOR_ID_3GPP,
            default_context_identifier,
            true,
            ctx,
        )?;
    }
    if let Some(service_selection) = answer.service_selection.as_ref() {
        builder_helpers::append_utf8_avp(
            &mut raw_avps,
            AVP_SERVICE_SELECTION,
            service_selection.as_ref(),
            true,
            ctx,
        )?;
    }
    for (index, apn_configuration) in answer.apn_configurations.iter().enumerate() {
        let supplement = answer.extensions.apn_configurations.get(index);
        apn::append_apn_configuration_avp(&mut raw_avps, apn_configuration, supplement, ctx)?;
    }
    if let Some(mobile_node_identifier) = answer.mobile_node_identifier.as_ref() {
        builder_helpers::append_utf8_avp(
            &mut raw_avps,
            AVP_MOBILE_NODE_IDENTIFIER,
            mobile_node_identifier.as_ref(),
            true,
            ctx,
        )?;
    }
    if let Some(session_timeout) = answer.session_timeout {
        builder_helpers::append_u32_avp(
            &mut raw_avps,
            base::AVP_SESSION_TIMEOUT,
            session_timeout.seconds(),
            true,
            ctx,
        )?;
    }
    if let Some(multi_round_timeout) = answer.multi_round_timeout {
        builder_helpers::append_u32_avp(
            &mut raw_avps,
            base::AVP_MULTI_ROUND_TIME_OUT,
            multi_round_timeout.seconds(),
            true,
            ctx,
        )?;
    }
    if let Some(re_auth_request_type) = answer.re_auth_request_type {
        builder_helpers::append_u32_avp(
            &mut raw_avps,
            base::AVP_RE_AUTH_REQUEST_TYPE,
            re_auth_request_type.value(),
            true,
            ctx,
        )?;
    }
    if let Some(authorization_lifetime) = answer.authorization_lifetime {
        builder_helpers::append_u32_avp(
            &mut raw_avps,
            base::AVP_AUTHORIZATION_LIFETIME,
            authorization_lifetime,
            true,
            ctx,
        )?;
    }
    if let Some(auth_grace_period) = answer.auth_grace_period {
        builder_helpers::append_u32_avp(
            &mut raw_avps,
            base::AVP_AUTH_GRACE_PERIOD,
            auth_grace_period,
            true,
            ctx,
        )?;
    }
    if let Some(eap_payload) = answer.eap_payload.as_ref() {
        builder_helpers::append_octet_string_avp(
            &mut raw_avps,
            AVP_EAP_PAYLOAD,
            eap_payload.as_ref(),
            true,
            ctx,
        )?;
    }
    if let Some(eap_reissued_payload) = answer.eap_reissued_payload.as_ref() {
        builder_helpers::append_octet_string_avp(
            &mut raw_avps,
            AVP_EAP_REISSUED_PAYLOAD,
            eap_reissued_payload.as_ref(),
            false,
            ctx,
        )?;
    }
    if let Some(error_message) = answer.error_message.as_ref() {
        builder_helpers::append_utf8_avp(
            &mut raw_avps,
            base::AVP_ERROR_MESSAGE,
            error_message,
            false,
            ctx,
        )?;
    }
    for state in &answer.state_avps {
        builder_helpers::append_octet_string_avp(&mut raw_avps, AVP_STATE, state, true, ctx)?;
    }
    if let Some(eap_master_session_key) = answer.eap_master_session_key.as_ref() {
        builder_helpers::append_octet_string_avp(
            &mut raw_avps,
            AVP_EAP_MASTER_SESSION_KEY,
            eap_master_session_key.as_ref(),
            false,
            ctx,
        )?;
    }
    for proxy_info in proxy_infos {
        proxy_info.append_to(&mut raw_avps, ctx)?;
    }
    append_diameter_eap_extensions(&mut raw_avps, answer.extensions.retained_avps(), ctx, "DEA")?;
    builder_helpers::build_message(
        crate::CommandFlags::answer(proxiable, false),
        COMMAND_DIAMETER_EAP,
        APPLICATION_ID,
        raw_avps,
        hop_by_hop_identifier,
        end_to_end_identifier,
        ctx,
        "DEA",
    )
}

/// Build a SWm DEA for one parsed or retained request transaction.
///
/// This helper copies both Diameter correlation identifiers from `request`
/// and rejects mismatched application-level request facts before encoding.
pub fn build_swm_diameter_eap_answer_for(
    request: &SwmDiameterEapRequestEnvelope,
    answer: &SwmDiameterEapAnswer,
    ctx: EncodeContext,
) -> Result<OwnedMessage, EncodeError> {
    if !answer.gateway_context().is_empty() {
        return Err(encode_structural_error(
            "SWm DEA gateway context requires explicit request-bound provenance",
            "7.1.2.1.2",
        ));
    }
    validate_swm_diameter_eap_answer_for(request, answer)?;
    build_swm_diameter_eap_answer_for_validated(request, answer, ctx)
}

/// Build a SWm DEA with standards-conditioned serving/emergency gateway
/// context bound to one exact retained DER.
///
/// The typed context constructor records whether the caller is asserting a
/// chained S2b-S8 serving gateway or HSS-derived authenticated non-roaming
/// emergency gateway. This builder verifies the exact DER binding and exact
/// base `DIAMETER_SUCCESS` before emitting either AVP.
pub fn build_swm_diameter_eap_answer_for_with_gateway_context(
    request: &SwmDiameterEapRequestEnvelope,
    answer: &SwmDiameterEapAnswer,
    gateway_context: &SwmRequestBoundDeaGatewayContext,
    ctx: EncodeContext,
) -> Result<OwnedMessage, EncodeError> {
    if !answer.gateway_context().is_empty() && answer.gateway_context() != gateway_context.context()
    {
        return Err(encode_structural_error(
            "SWm DEA parsed and request-bound gateway contexts differ",
            "7.1.2.1.2",
        ));
    }
    gateway_context
        .validate_for(request, answer.result)
        .map_err(|_| {
            encode_structural_error(
                "SWm DEA request-bound gateway context is invalid",
                "7.1.2.1.2",
            )
        })?;
    validate_swm_diameter_eap_answer_for(request, answer)?;
    let mut answer = answer.clone();
    answer.extensions.gateway_context = gateway_context.context().clone();
    build_swm_diameter_eap_answer_for_validated(request, &answer, ctx)
}

fn validate_swm_diameter_eap_answer_for(
    request: &SwmDiameterEapRequestEnvelope,
    answer: &SwmDiameterEapAnswer,
) -> Result<(), EncodeError> {
    let request_facts = request.request();
    if request_facts.session_id.as_ref() != answer.session_id.as_ref()
        || request_facts.auth_application_id != answer.auth_application_id
        || request_facts.auth_request_type != answer.auth_request_type
        || !mobility_answer_matches_offer(
            request_facts.mip6_feature_vector,
            answer.mip6_feature_vector,
            answer.result.is_diameter_success(),
        )
        || !subscriber_authorization_matches_request(request, answer)
        || lifecycle::validate_diameter_eap_answer_overload_control_for_request(
            request_facts.oc_supported_features.as_ref(),
            answer.oc_supported_features.as_ref(),
            answer.oc_olr.as_ref(),
        )
        .is_err()
        || apn::validate_for_request(request, answer).is_err()
    {
        return Err(encode_structural_error(
            "SWm DEA does not correlate to the supplied DER",
            "DEA",
        ));
    }
    Ok(())
}

fn build_swm_diameter_eap_answer_for_validated(
    request: &SwmDiameterEapRequestEnvelope,
    answer: &SwmDiameterEapAnswer,
    ctx: EncodeContext,
) -> Result<OwnedMessage, EncodeError> {
    let transaction = request.transaction();
    build_swm_diameter_eap_answer_internal(
        answer,
        &request.proxy_infos,
        request.proxiable,
        transaction.hop_by_hop_identifier(),
        transaction.end_to_end_identifier(),
        SwmDiameterEapAnswerBuildMode {
            request_conditioned: true,
            location_purpose: location::SwmLocationEncodePurpose::Origination,
            trace_purpose: trace::SwmTraceEncodePurpose::Origination,
        },
        ctx,
    )
}

/// Build an ordinary or generic Diameter-EAP response for one exact DER.
///
/// The response preserves P and both identifiers, copies the exact ordered
/// Proxy-Info chain, and never reflects request Route-Record values. Generic
/// errors use RFC 6733 section 7.2 grammar and do not acquire application-only
/// fields.
pub fn build_swm_diameter_eap_response_for(
    request: &SwmDiameterEapRequestEnvelope,
    response: &SwmDiameterEapResponse,
    ctx: EncodeContext,
) -> Result<OwnedMessage, EncodeError> {
    match response {
        SwmDiameterEapResponse::Application(answer) => {
            build_swm_diameter_eap_answer_for(request, answer, ctx)
        }
        SwmDiameterEapResponse::GenericError(answer) => {
            build_swm_diameter_eap_generic_error_for(request, answer, ctx)
        }
    }
}

fn build_swm_diameter_eap_generic_error_for(
    request: &SwmDiameterEapRequestEnvelope,
    answer: &SwmDiameterEapGenericErrorAnswer,
    ctx: EncodeContext,
) -> Result<OwnedMessage, EncodeError> {
    answer.validate_for_encode()?;
    if let SwmDiameterEapGenericErrorAnswerProvenance::OutboundAgentDeliveryFailure {
        request_binding,
        ..
    } = &answer.provenance
    {
        if !request_binding.matches(request)? {
            return Err(encode_structural_error(
                "SWm agent delivery failure does not match its bound DER envelope",
                "7.2",
            ));
        }
    }
    if answer.session_id.as_deref().map(String::as_str) != Some(request.request.session_id.as_ref())
    {
        return Err(encode_structural_error(
            "request-bound generic SWm DEA must copy Session-Id",
            "6.2",
        ));
    }
    let redirect_avp_count = answer.redirect.as_ref().map_or(0, |redirect| {
        redirect.hosts().len()
            + usize::from(redirect.usage().is_some())
            + usize::from(redirect.max_cache_time().is_some())
    });
    let retained_count = request
        .proxy_infos
        .len()
        .checked_add(answer.failed_avps.len())
        .and_then(|count| count.checked_add(answer.additional_avps.len()))
        .and_then(|count| count.checked_add(redirect_avp_count))
        .ok_or_else(EncodeError::length_overflow)?;
    if retained_count > MAX_SWM_DIAMETER_EAP_ROUTING_AVPS {
        return Err(encode_structural_error(
            "generic SWm DEA routing and extension count exceeds its bound",
            "7.2",
        ));
    }

    let mut raw_avps = BytesMut::new();
    if let Some(session_id) = answer.session_id.as_ref() {
        builder_helpers::append_utf8_avp(
            &mut raw_avps,
            base::AVP_SESSION_ID,
            session_id.as_ref(),
            true,
            ctx,
        )?;
    }
    builder_helpers::append_utf8_avp(
        &mut raw_avps,
        base::AVP_ORIGIN_HOST,
        answer.origin_host.as_ref(),
        true,
        ctx,
    )?;
    builder_helpers::append_utf8_avp(
        &mut raw_avps,
        base::AVP_ORIGIN_REALM,
        answer.origin_realm.as_ref(),
        true,
        ctx,
    )?;
    builder_helpers::append_u32_avp(
        &mut raw_avps,
        base::AVP_RESULT_CODE,
        answer.result_code,
        true,
        ctx,
    )?;
    if let Some(origin_state_id) = answer.origin_state_id {
        builder_helpers::append_u32_avp(
            &mut raw_avps,
            base::AVP_ORIGIN_STATE_ID,
            origin_state_id,
            true,
            ctx,
        )?;
    }
    if let Some(error_message) = answer.error_message.as_ref() {
        builder_helpers::append_utf8_avp(
            &mut raw_avps,
            base::AVP_ERROR_MESSAGE,
            error_message.as_ref(),
            false,
            ctx,
        )?;
    }
    if let Some(error_reporting_host) = answer.error_reporting_host.as_ref() {
        builder_helpers::append_utf8_avp(
            &mut raw_avps,
            base::AVP_ERROR_REPORTING_HOST,
            error_reporting_host.as_ref(),
            false,
            ctx,
        )?;
    }
    for failed_avp in &answer.failed_avps {
        failed_avp.append_to(&mut raw_avps, ctx)?;
    }
    if let Some(SwmDiameterResult::Experimental { vendor_id, code }) = answer.experimental_result {
        append_experimental_result_avp(&mut raw_avps, vendor_id, code, ctx)?;
    }
    for proxy_info in &request.proxy_infos {
        proxy_info.append_to(&mut raw_avps, ctx)?;
    }
    if let Some(redirect) = answer.redirect.as_ref() {
        for host in redirect.hosts() {
            builder_helpers::append_utf8_avp(
                &mut raw_avps,
                base::AVP_REDIRECT_HOST,
                host.as_ref(),
                true,
                ctx,
            )?;
        }
        if let Some(usage) = redirect.usage() {
            builder_helpers::append_u32_avp(
                &mut raw_avps,
                base::AVP_REDIRECT_HOST_USAGE,
                usage.value(),
                true,
                ctx,
            )?;
        }
        if let Some(max_cache_time) = redirect.max_cache_time() {
            builder_helpers::append_u32_avp(
                &mut raw_avps,
                base::AVP_REDIRECT_MAX_CACHE_TIME,
                max_cache_time,
                true,
                ctx,
            )?;
        }
    }
    for avp in &answer.additional_avps {
        avp.append_to(&mut raw_avps, ctx)?;
    }
    let transaction = request.transaction;
    builder_helpers::build_message(
        crate::CommandFlags::answer(request.proxiable, true),
        COMMAND_DIAMETER_EAP,
        APPLICATION_ID,
        raw_avps,
        transaction.hop_by_hop_identifier(),
        transaction.end_to_end_identifier(),
        ctx,
        "7.2",
    )
}

/// Parse a SWm Diameter-EAP-Answer message.
pub fn parse_swm_diameter_eap_answer(
    message: &Message<'_>,
    ctx: DecodeContext,
) -> Result<SwmDiameterEapAnswer, DecodeError> {
    parse_swm_diameter_eap_application_answer_parts(message, ctx).map(|parts| parts.answer)
}

struct ParsedSwmDiameterEapApplicationAnswerParts {
    answer: SwmDiameterEapAnswer,
    proxy_infos: Vec<SwmAdditionalAvp>,
}

fn parse_swm_diameter_eap_application_answer_parts(
    message: &Message<'_>,
    ctx: DecodeContext,
) -> Result<ParsedSwmDiameterEapApplicationAnswerParts, DecodeError> {
    builder_helpers::ensure_app_header(
        message,
        COMMAND_DIAMETER_EAP,
        APPLICATION_ID,
        CommandKind::Answer,
        "DEA",
    )?;
    validate_diameter_eap_answer_header(message)?;
    if message.header.flags.is_error() {
        return Err(decode_structural_error(
            "SWm DEA E-bit response requires the generic response parser",
            "7.2",
        ));
    }
    let mut session_id = None;
    let mut auth_application_id = None;
    let mut auth_request_type = None;
    let mut result_code = None;
    let mut experimental_result = None;
    let mut origin_host = None;
    let mut origin_realm = None;
    let mut user_name = None;
    let mut subscriber_authorization = SwmDeaSubscriberAuthorization::new();
    let mut mip6_feature_vector = None;
    let mut mip6_agent_info = None;
    let mut emergency_info = None;
    let mut supported_features = Vec::new();
    let mut oc_supported_features = None;
    let mut oc_olr = None;
    let mut load_reports = Vec::new();
    let mut access_network_info = None;
    let mut user_location_info_time = None;
    let mut service_selection = None;
    let mut default_context_identifier = None;
    let mut apn_configurations = Vec::new();
    let mut apn_configuration_supplements = Vec::new();
    let mut mobile_node_identifier = None;
    let mut trace_info = None;
    let mut session_timeout = None;
    let mut multi_round_timeout = None;
    let mut authorization_lifetime = None;
    let mut auth_grace_period = None;
    let mut re_auth_request_type = None;
    let mut eap_payload = None;
    let mut eap_reissued_payload = None;
    let mut error_message = None;
    let mut state_avps = Vec::new();
    let mut eap_master_session_key = None;
    let mut proxy_infos = Vec::new();
    let mut extensions = Vec::new();
    let mut extension_keys = HashSet::new();
    let mut retention = DiameterEapRetention::default();
    builder_helpers::for_each_avp(
        message.raw_avps,
        ctx,
        crate::DIAMETER_HEADER_LEN,
        0,
        |offset, avp| {
            let value_offset = builder_helpers::offset_add(offset, avp.header.header_len(), "DEA")?;
            let code = avp.header.code;
            dea_authorization::validate_top_level_identity(&avp.header, offset)?;
            // Vendor-specific AVPs are matched by (vendor-id, code); only
            // genuinely unknown ones fall through to the unknown-AVP policy.
            if let Some(vendor_id) = avp.header.vendor_id {
                if vendor_id.get() == 0 {
                    return Err(DecodeError::new(
                        DecodeErrorCode::Structural {
                            reason: "SWm DEA Vendor-Id field must not contain zero",
                        },
                        offset,
                    )
                    .with_spec_ref(SpecRef::new("ietf", "RFC6733", "4.1.1")));
                }
                if code == AVP_EMERGENCY_INFO && vendor_id == VENDOR_ID_3GPP {
                    let value = mobility::parse_emergency_info(
                        &avp,
                        ctx,
                        offset,
                        value_offset,
                        1,
                        &mut retention,
                    )?;
                    builder_helpers::set_once(&mut emergency_info, value, offset, "7.3.210")?;
                } else if code == AVP_APN_OI_REPLACEMENT && vendor_id == VENDOR_ID_3GPP {
                    let value =
                        dea_authorization::parse_apn_oi_replacement(&avp, offset, value_offset)?;
                    builder_helpers::set_once(
                        &mut subscriber_authorization.apn_oi_replacement,
                        value,
                        offset,
                        "7.3.32",
                    )?;
                } else if code == AVP_3GPP_CHARGING_CHARACTERISTICS && vendor_id == VENDOR_ID_3GPP {
                    let value = dea_authorization::parse_charging_characteristics(
                        &avp,
                        offset,
                        value_offset,
                    )?;
                    builder_helpers::set_once(
                        &mut subscriber_authorization.charging_characteristics,
                        value,
                        offset,
                        "16.4.7",
                    )?;
                } else if code == AVP_UE_USAGE_TYPE && vendor_id == VENDOR_ID_3GPP {
                    let value = dea_authorization::parse_ue_usage_type(&avp, offset, value_offset)?;
                    builder_helpers::set_once(
                        &mut subscriber_authorization.ue_usage_type,
                        value,
                        offset,
                        "7.3.202",
                    )?;
                } else if code == AVP_CORE_NETWORK_RESTRICTIONS && vendor_id == VENDOR_ID_3GPP {
                    let value = dea_authorization::parse_core_network_restrictions(
                        &avp,
                        offset,
                        value_offset,
                    )?;
                    builder_helpers::set_once(
                        &mut subscriber_authorization.core_network_restrictions,
                        value,
                        offset,
                        "7.3.230",
                    )?;
                } else if code == AVP_MPS_PRIORITY && vendor_id == VENDOR_ID_3GPP {
                    let value = dea_authorization::parse_mps_priority(&avp, offset, value_offset)?;
                    builder_helpers::set_once(
                        &mut subscriber_authorization.mps_priority,
                        value,
                        offset,
                        "7.3.131",
                    )?;
                } else if matches!(
                    code,
                    AVP_MIP6_AGENT_INFO
                        | AVP_MIP_HOME_AGENT_ADDRESS
                        | AVP_MIP_HOME_AGENT_HOST
                        | AVP_MIP6_HOME_LINK_PREFIX
                ) || code == AVP_EMERGENCY_INFO
                {
                    return Err(decode_structural_error_at(
                        "SWm DEA mobility AVP uses the wrong vendor identity",
                        offset,
                        "7.1.2.1.2",
                    ));
                } else if code == AVP_CONTEXT_IDENTIFIER && vendor_id == VENDOR_ID_3GPP {
                    let value =
                        builder_helpers::parse_u32_value(avp.value, value_offset, "7.3.27")?;
                    builder_helpers::set_once(
                        &mut default_context_identifier,
                        value,
                        offset,
                        "DEA",
                    )?;
                } else if code == AVP_APN_CONFIGURATION && vendor_id == VENDOR_ID_3GPP {
                    if apn_configurations.len() >= apn::MAX_SWM_APN_CONFIGURATIONS {
                        return Err(DecodeError::new(DecodeErrorCode::IeCountExceeded, offset)
                            .with_spec_ref(SpecRef::new("3gpp", "TS29273", "7.1.2.1.2")));
                    }
                    let (configuration, supplement) = apn::parse_apn_configuration(
                        &avp,
                        ctx,
                        offset,
                        value_offset,
                        1,
                        &mut retention,
                    )?;
                    apn_configurations.push(configuration);
                    apn_configuration_supplements.push(supplement);
                } else if code == AVP_SUPPORTED_FEATURES && vendor_id == VENDOR_ID_3GPP {
                    if supported_features.len() >= MAX_SWM_SUPPORTED_FEATURES {
                        return Err(DecodeError::new(DecodeErrorCode::IeCountExceeded, offset)
                            .with_spec_ref(SpecRef::new("3gpp", "TS29229", "6.3.29")));
                    }
                    supported_features.push(parse_answer_supported_features(
                        &avp,
                        ctx,
                        value_offset,
                        1,
                        offset,
                    )?);
                } else if code == AVP_ACCESS_NETWORK_INFO && vendor_id == VENDOR_ID_3GPP {
                    let value = location::parse_access_network_info(
                        &avp,
                        ctx,
                        offset,
                        value_offset,
                        1,
                        &mut retention,
                    )?;
                    builder_helpers::set_once(&mut access_network_info, value, offset, "5.2.3.24")?;
                } else if code == AVP_USER_LOCATION_INFO_TIME && vendor_id == VENDOR_ID_3GPP {
                    let value =
                        location::parse_user_location_info_time(&avp, offset, value_offset)?;
                    builder_helpers::set_once(
                        &mut user_location_info_time,
                        value,
                        offset,
                        "5.3.101",
                    )?;
                } else if code == AVP_TRACE_INFO && vendor_id == VENDOR_ID_3GPP {
                    let value =
                        trace::parse_trace_info(&avp, ctx, offset, value_offset, &mut retention)?;
                    builder_helpers::set_once(&mut trace_info, value, offset, "8.2.3.13")?;
                } else if trace::is_trace_avp_code(code) {
                    return Err(decode_structural_error_at(
                        "SWm DEA trace AVP uses the wrong vendor identity or nesting",
                        offset,
                        "8.2.3.13",
                    ));
                } else {
                    retain_diameter_eap_extension(
                        ctx,
                        &avp,
                        offset,
                        "DEA",
                        &mut extension_keys,
                        &mut retention,
                        &mut extensions,
                    )?;
                }
                return Ok(());
            }
            if code == base::AVP_SESSION_ID {
                let value = builder_helpers::parse_string_value(avp.value, value_offset, "8.8")?;
                builder_helpers::set_once(&mut session_id, Redacted::from(value), offset, "8.8")?;
            } else if code == base::AVP_AUTH_APPLICATION_ID {
                let value = builder_helpers::parse_u32_value(avp.value, value_offset, "6.8")?;
                builder_helpers::set_once(&mut auth_application_id, value, offset, "6.8")?;
            } else if code == AVP_AUTH_REQUEST_TYPE {
                let value = builder_helpers::parse_u32_value(avp.value, value_offset, "8.7")?;
                builder_helpers::set_once(
                    &mut auth_request_type,
                    AuthRequestType::from_value(value),
                    offset,
                    "8.7",
                )?;
            } else if code == base::AVP_RESULT_CODE {
                validate_base_mandatory_flags(&avp.header, offset, "7.1")?;
                let value = builder_helpers::parse_u32_value(avp.value, value_offset, "7.1")?;
                builder_helpers::set_once(&mut result_code, value, offset, "7.1")?;
            } else if code == base::AVP_EXPERIMENTAL_RESULT {
                validate_base_mandatory_flags(&avp.header, offset, "7.6")?;
                builder_helpers::set_once(
                    &mut experimental_result,
                    parse_experimental_result(avp.value, ctx, value_offset, 1)?,
                    offset,
                    "7.6",
                )?;
            } else if code == base::AVP_ORIGIN_HOST {
                let value = builder_helpers::parse_string_value(avp.value, value_offset, "6.3")?;
                builder_helpers::set_once(&mut origin_host, Redacted::from(value), offset, "6.3")?;
            } else if code == base::AVP_ORIGIN_REALM {
                let value = builder_helpers::parse_string_value(avp.value, value_offset, "6.4")?;
                builder_helpers::set_once(&mut origin_realm, Redacted::from(value), offset, "6.4")?;
            } else if code == base::AVP_USER_NAME {
                let value = builder_helpers::parse_string_value(avp.value, value_offset, "8.14")?;
                builder_helpers::set_once(&mut user_name, Redacted::from(value), offset, "8.14")?;
            } else if code == AVP_SUBSCRIPTION_ID {
                let value = dea_authorization::parse_subscription_id(
                    &avp,
                    ctx,
                    offset,
                    value_offset,
                    &mut retention,
                )?;
                builder_helpers::set_once(
                    &mut subscriber_authorization.subscription_id,
                    value,
                    offset,
                    "8.46",
                )?;
            } else if code == AVP_MIP6_FEATURE_VECTOR {
                validate_base_m_bit_agnostic_flags(&avp.header, offset, "4.2.5")?;
                let value = builder_helpers::parse_u64_value(avp.value, value_offset, "4.2.5")?;
                builder_helpers::set_once(
                    &mut mip6_feature_vector,
                    SwmMip6FeatureVector::from_bits_retain(value),
                    offset,
                    "4.2.5",
                )?;
            } else if code == AVP_MIP6_AGENT_INFO {
                let value = mobility::parse_mip6_agent_info(
                    &avp,
                    ctx,
                    offset,
                    value_offset,
                    1,
                    &mut retention,
                )?;
                builder_helpers::set_once(&mut mip6_agent_info, value, offset, "4.2.1")?;
            } else if matches!(
                code,
                AVP_MIP_HOME_AGENT_ADDRESS
                    | AVP_MIP_HOME_AGENT_HOST
                    | AVP_MIP6_HOME_LINK_PREFIX
                    | AVP_EMERGENCY_INFO
            ) {
                return Err(decode_structural_error_at(
                    "grouped mobility child or vendor AVP appears at DEA top level",
                    offset,
                    "7.1.2.1.2",
                ));
            } else if code == AVP_OC_SUPPORTED_FEATURES {
                let value = lifecycle::parse_diameter_eap_answer_oc_supported_features(
                    &avp,
                    ctx,
                    offset,
                    value_offset,
                )?;
                builder_helpers::set_once(
                    &mut oc_supported_features,
                    value,
                    offset,
                    "RFC7683-7.1",
                )?;
            } else if code == AVP_OC_OLR {
                let value =
                    lifecycle::parse_diameter_eap_answer_oc_olr(&avp, ctx, offset, value_offset)?;
                builder_helpers::set_once(&mut oc_olr, value, offset, "RFC7683-7.3")?;
            } else if code == AVP_LOAD {
                if load_reports.len() >= MAX_SWM_LOAD_REPORTS {
                    return Err(DecodeError::new(DecodeErrorCode::IeCountExceeded, offset)
                        .with_spec_ref(SpecRef::new("ietf", "RFC8583", "7.1")));
                }
                load_reports.push(lifecycle::parse_diameter_eap_answer_load(
                    &avp,
                    ctx,
                    offset,
                    value_offset,
                )?);
            } else if is_overload_grouped_child(code) {
                return Err(DecodeError::new(
                    DecodeErrorCode::Structural {
                        reason: "grouped overload child AVP appears at DEA top level",
                    },
                    offset,
                )
                .with_spec_ref(SpecRef::new("3gpp", "TS29273", "7.2.2.1.2")));
            } else if code == AVP_SERVICE_SELECTION {
                validate_base_mandatory_flags(&avp.header, offset, "6.2")?;
                let value = apn::parse_requested_apn_wire_value(avp.value, value_offset)?;
                builder_helpers::set_once(&mut service_selection, value, offset, "6.2")?;
            } else if code == AVP_MOBILE_NODE_IDENTIFIER {
                validate_base_mandatory_flags(&avp.header, offset, "4.1")?;
                let value = builder_helpers::parse_string_value(avp.value, value_offset, "5.6")?;
                builder_helpers::set_once(
                    &mut mobile_node_identifier,
                    Redacted::from(value),
                    offset,
                    "5.6",
                )?;
            } else if code == base::AVP_SESSION_TIMEOUT {
                validate_base_mandatory_flags(&avp.header, offset, "8.13")?;
                let value = builder_helpers::parse_u32_value(avp.value, value_offset, "8.13")?;
                builder_helpers::set_once(
                    &mut session_timeout,
                    SwmSessionTimeout::from_seconds(value),
                    offset,
                    "8.13",
                )?;
            } else if code == base::AVP_MULTI_ROUND_TIME_OUT {
                validate_base_mandatory_flags(&avp.header, offset, "8.19")?;
                let value = builder_helpers::parse_u32_value(avp.value, value_offset, "8.19")?;
                builder_helpers::set_once(
                    &mut multi_round_timeout,
                    SwmMultiRoundTimeout::from_seconds(value),
                    offset,
                    "8.19",
                )?;
            } else if code == base::AVP_AUTHORIZATION_LIFETIME {
                validate_base_mandatory_flags(&avp.header, offset, "8.9")?;
                let value = builder_helpers::parse_u32_value(avp.value, value_offset, "8.9")?;
                builder_helpers::set_once(&mut authorization_lifetime, value, offset, "8.9")?;
            } else if code == base::AVP_AUTH_GRACE_PERIOD {
                validate_base_mandatory_flags(&avp.header, offset, "8.10")?;
                let value = builder_helpers::parse_u32_value(avp.value, value_offset, "8.10")?;
                builder_helpers::set_once(&mut auth_grace_period, value, offset, "8.10")?;
            } else if code == base::AVP_RE_AUTH_REQUEST_TYPE {
                validate_base_mandatory_flags(&avp.header, offset, "8.12")?;
                let value = builder_helpers::parse_u32_value(avp.value, value_offset, "8.12")?;
                let typed = SwmReAuthRequestType::from_value(value).ok_or_else(|| {
                    DecodeError::new(
                        DecodeErrorCode::InvalidEnumValue {
                            field: "Re-Auth-Request-Type",
                            value: u64::from(value),
                        },
                        value_offset,
                    )
                    .with_spec_ref(SpecRef::new("ietf", "RFC6733", "8.12"))
                })?;
                builder_helpers::set_once(&mut re_auth_request_type, typed, offset, "8.12")?;
            } else if code == base::AVP_AUTH_SESSION_STATE {
                return Err(decode_structural_error_at(
                    "SWm DEA must omit Auth-Session-State",
                    offset,
                    "7.2.4",
                ));
            } else if code == AVP_EAP_PAYLOAD {
                builder_helpers::set_once(
                    &mut eap_payload,
                    Redacted::from(avp.value.to_vec()),
                    offset,
                    "4.1",
                )?;
            } else if code == AVP_EAP_REISSUED_PAYLOAD {
                builder_helpers::set_once(
                    &mut eap_reissued_payload,
                    Redacted::from(avp.value.to_vec()),
                    offset,
                    "4.2",
                )?;
            } else if code == base::AVP_ERROR_MESSAGE {
                let value = builder_helpers::parse_utf8_value(avp.value, value_offset, "7.3")?;
                builder_helpers::set_once(&mut error_message, value, offset, "7.3")?;
            } else if avp.header.key() == AvpKey::ietf(base::AVP_PROXY_INFO) {
                retain_diameter_eap_proxy_info(
                    &avp,
                    ctx,
                    offset,
                    value_offset,
                    "DEA",
                    &mut retention,
                    &mut proxy_infos,
                )?;
            } else if avp.header.key() == AvpKey::ietf(base::AVP_FAILED_AVP) {
                // RFC 4072 section 3.2 permits repeated Failed-AVP values on
                // ordinary E-clear answers. Their inner bytes can describe a
                // malformed or synthesized AVP, so only validate the outer
                // base identity and retain the payload opaquely.
                lifecycle::validate_base_definition(&avp, offset)?;
                retention.account(&avp, offset, "3.2", ctx)?;
                extensions.push(SwmAdditionalAvp::from_raw_exact(&avp));
            } else if matches!(
                avp.header.key(),
                key if key == AvpKey::ietf(base::AVP_ROUTE_RECORD)
                    || key == AvpKey::ietf(base::AVP_DESTINATION_HOST)
                    || key == AvpKey::ietf(base::AVP_DESTINATION_REALM)
                    || key == AvpKey::ietf(base::AVP_REDIRECT_HOST)
                    || key == AvpKey::ietf(base::AVP_REDIRECT_HOST_USAGE)
                    || key == AvpKey::ietf(base::AVP_REDIRECT_MAX_CACHE_TIME)
            ) {
                return Err(decode_structural_error_at(
                    "routing or generic-error AVP is not valid in ordinary SWm DEA grammar",
                    offset,
                    "7.2",
                ));
            } else if code == AVP_STATE {
                state_avps.push(avp.value.to_vec());
            } else if code == AVP_EAP_MASTER_SESSION_KEY {
                builder_helpers::set_once(
                    &mut eap_master_session_key,
                    Redacted::from(avp.value.to_vec()),
                    offset,
                    "4.3",
                )?;
            } else if trace::is_trace_avp_code(code) {
                return Err(decode_structural_error_at(
                    "SWm DEA trace AVP uses the wrong vendor identity or nesting",
                    offset,
                    "8.2.3.13",
                ));
            } else {
                retain_diameter_eap_extension(
                    ctx,
                    &avp,
                    offset,
                    "DEA",
                    &mut extension_keys,
                    &mut retention,
                    &mut extensions,
                )?;
            }
            Ok(())
        },
    )?;
    let auth_application_id = builder_helpers::require_field(
        auth_application_id,
        "SWm DEA requires Auth-Application-Id",
        "DEA",
    )?;
    if auth_application_id != APPLICATION_ID.get() {
        return Err(DecodeError::new(
            DecodeErrorCode::Structural {
                reason: "SWm DEA Auth-Application-Id does not match the SWm application id",
            },
            crate::DIAMETER_HEADER_LEN,
        )
        .with_spec_ref(SpecRef::new("3gpp", "TS29273", "DEA")));
    }
    let result = match (result_code, experimental_result) {
        (Some(code), None) => SwmDiameterResult::Base(code),
        (None, Some(result)) => result,
        (Some(_), Some(_)) => {
            return Err(decode_structural_error(
                "SWm DEA must not contain both Result-Code and Experimental-Result",
                "DEA",
            ));
        }
        (None, None) => {
            return Err(decode_structural_error(
                "SWm DEA requires exactly one Result-Code or Experimental-Result",
                "DEA",
            ));
        }
    };
    if matches!(
        result,
        SwmDiameterResult::Base(code) if builder_helpers::result_code_requires_error_bit(code)
    ) {
        return Err(decode_structural_error(
            "base 3xxx SWm DEA requires the generic E-bit response grammar",
            "7.2",
        ));
    }
    let user_location_info_time_omission =
        if access_network_info.is_some() && user_location_info_time.is_none() {
            Some(SwmUserLocationInfoTimeOmission::received_without_timestamp())
        } else {
            None
        };
    let answer = SwmDiameterEapAnswer {
        session_id: builder_helpers::require_field(
            session_id,
            "SWm DEA requires Session-Id",
            "DEA",
        )?,
        auth_application_id,
        auth_request_type: builder_helpers::require_field(
            auth_request_type,
            "SWm DEA requires Auth-Request-Type",
            "DEA",
        )?,
        result,
        origin_host: builder_helpers::require_field(
            origin_host,
            "SWm DEA requires Origin-Host",
            "DEA",
        )?,
        origin_realm: builder_helpers::require_field(
            origin_realm,
            "SWm DEA requires Origin-Realm",
            "DEA",
        )?,
        user_name,
        subscriber_authorization,
        mip6_feature_vector,
        supported_features,
        oc_supported_features,
        oc_olr,
        load_reports,
        service_selection,
        default_context_identifier,
        apn_configurations,
        mobile_node_identifier,
        session_timeout,
        multi_round_timeout,
        authorization_lifetime,
        auth_grace_period,
        re_auth_request_type,
        eap_payload,
        eap_reissued_payload,
        error_message,
        state_avps,
        eap_master_session_key,
        extensions: SwmDiameterEapAnswerExtensions {
            avps: extensions,
            gateway_context: SwmDeaGatewayContext {
                chained_s2b_s8_serving_gateway: mip6_agent_info,
                emergency_info,
            },
            apn_configurations: apn_configuration_supplements,
            access_network_info,
            user_location_info_time,
            user_location_info_time_omission,
            trace_info,
        },
    };
    lifecycle::validate_diameter_eap_answer_overload_control(
        answer.oc_supported_features.as_ref(),
        answer.oc_olr.as_ref(),
    )?;
    validate_decoded_answer(&answer)?;
    Ok(ParsedSwmDiameterEapApplicationAnswerParts {
        answer,
        proxy_infos,
    })
}

struct ParsedSwmDiameterEapGenericErrorParts {
    answer: SwmDiameterEapGenericErrorAnswer,
    proxy_infos: Vec<SwmAdditionalAvp>,
}

/// Parse either ordinary SWm DEA application grammar or RFC 6733 generic
/// E-bit error grammar.
///
/// Parsed redirect hosts remain sealed in the generic value. Use
/// [`parse_swm_diameter_eap_response_envelope_from_connection`] and correlate
/// it with the retained DER before making a redirect decision.
pub fn parse_swm_diameter_eap_response(
    message: &Message<'_>,
    ctx: DecodeContext,
) -> Result<SwmDiameterEapResponse, DecodeError> {
    if message.header.flags.is_error() {
        parse_swm_diameter_eap_generic_error_parts(message, ctx)
            .map(|parts| SwmDiameterEapResponse::GenericError(Box::new(parts.answer)))
    } else {
        parse_swm_diameter_eap_application_answer_parts(message, ctx)
            .map(|parts| SwmDiameterEapResponse::Application(Box::new(parts.answer)))
    }
}

/// Parse a Diameter-EAP response with authenticated connection evidence.
pub fn parse_swm_diameter_eap_response_envelope_from_connection(
    message: &Message<'_>,
    received_on: SwmDiameterConnectionToken,
    ctx: DecodeContext,
) -> Result<SwmDiameterEapResponseEnvelope, DecodeError> {
    let transaction = SwmDiameterTransaction::from_message(message);
    let (response, proxy_infos) = if message.header.flags.is_error() {
        let parts = parse_swm_diameter_eap_generic_error_parts(message, ctx)?;
        (
            SwmDiameterEapResponse::GenericError(Box::new(parts.answer)),
            parts.proxy_infos,
        )
    } else {
        let parts = parse_swm_diameter_eap_application_answer_parts(message, ctx)?;
        (
            SwmDiameterEapResponse::Application(Box::new(parts.answer)),
            parts.proxy_infos,
        )
    };
    Ok(SwmDiameterEapResponseEnvelope {
        transaction,
        proxiable: message.header.flags.is_proxiable(),
        received_on,
        response,
        proxy_infos,
    })
}

fn parse_swm_diameter_eap_generic_error_parts(
    message: &Message<'_>,
    ctx: DecodeContext,
) -> Result<ParsedSwmDiameterEapGenericErrorParts, DecodeError> {
    builder_helpers::ensure_app_header(
        message,
        COMMAND_DIAMETER_EAP,
        APPLICATION_ID,
        CommandKind::Answer,
        "7.2",
    )?;
    validate_diameter_eap_answer_header(message)?;
    if !message.header.flags.is_error() {
        return Err(decode_structural_error(
            "generic SWm DEA requires the E bit",
            "7.2",
        ));
    }

    let mut session_id = None;
    let mut result_code = None;
    let mut origin_host = None;
    let mut origin_realm = None;
    let mut redirect_hosts = Vec::new();
    let mut redirect_usage = None;
    let mut redirect_max_cache_time = None;
    let mut error_message = None;
    let mut error_reporting_host = None;
    let mut origin_state_id = None;
    let mut experimental_result = None;
    let mut failed_avps = Vec::new();
    let mut proxy_infos = Vec::new();
    let mut additional_avps = Vec::new();
    let mut generic_auth_application_id = None;
    let mut retention = DiameterEapRetention::default();

    builder_helpers::for_each_avp(
        message.raw_avps,
        ctx,
        crate::DIAMETER_HEADER_LEN,
        0,
        |offset, avp| {
            let value_offset = builder_helpers::offset_add(offset, avp.header.header_len(), "7.2")?;
            if avp
                .header
                .vendor_id
                .is_some_and(|vendor_id| vendor_id.get() == 0)
            {
                return Err(DecodeError::new(
                    DecodeErrorCode::Structural {
                        reason: "generic SWm DEA Vendor-Id field must not contain zero",
                    },
                    offset,
                )
                .with_spec_ref(SpecRef::new("ietf", "RFC6733", "4.1.1")));
            }
            let key = avp.header.key();
            if key == AvpKey::ietf(base::AVP_SESSION_ID) {
                lifecycle::validate_base_definition(&avp, offset)?;
                let value = builder_helpers::parse_string_value(avp.value, value_offset, "8.8")?;
                if value.is_empty() {
                    return Err(decode_structural_error_at(
                        "generic SWm DEA Session-Id must not be empty",
                        offset,
                        "8.8",
                    ));
                }
                builder_helpers::set_once(&mut session_id, Redacted::from(value), offset, "8.8")?;
            } else if key == AvpKey::ietf(base::AVP_ORIGIN_HOST) {
                let value = parse_required_base_identity(&avp, ctx, offset, value_offset, "6.3")?;
                builder_helpers::set_once(&mut origin_host, value, offset, "6.3")?;
            } else if key == AvpKey::ietf(base::AVP_ORIGIN_REALM) {
                let value = parse_required_base_identity(&avp, ctx, offset, value_offset, "6.4")?;
                builder_helpers::set_once(&mut origin_realm, value, offset, "6.4")?;
            } else if key == AvpKey::ietf(base::AVP_RESULT_CODE) {
                lifecycle::validate_base_definition(&avp, offset)?;
                let value = builder_helpers::parse_u32_value(avp.value, value_offset, "7.1")?;
                builder_helpers::set_once(&mut result_code, value, offset, "7.1")?;
            } else if key == AvpKey::ietf(base::AVP_ORIGIN_STATE_ID) {
                lifecycle::validate_base_definition(&avp, offset)?;
                let value = builder_helpers::parse_u32_value(avp.value, value_offset, "8.16")?;
                builder_helpers::set_once(&mut origin_state_id, value, offset, "8.16")?;
            } else if key == AvpKey::ietf(base::AVP_ERROR_MESSAGE) {
                lifecycle::validate_base_definition(&avp, offset)?;
                let value = builder_helpers::parse_utf8_value(avp.value, value_offset, "7.3")?;
                builder_helpers::set_once(
                    &mut error_message,
                    Redacted::from(value),
                    offset,
                    "7.3",
                )?;
            } else if key == AvpKey::ietf(base::AVP_ERROR_REPORTING_HOST) {
                let value = parse_required_base_identity(&avp, ctx, offset, value_offset, "7.4")?;
                builder_helpers::set_once(&mut error_reporting_host, value, offset, "7.4")?;
            } else if key == AvpKey::ietf(base::AVP_EXPERIMENTAL_RESULT) {
                lifecycle::validate_base_definition(&avp, offset)?;
                let value = parse_experimental_result(avp.value, ctx, value_offset, 1)?;
                builder_helpers::set_once(&mut experimental_result, value, offset, "7.6")?;
            } else if key == AvpKey::ietf(base::AVP_FAILED_AVP) {
                // RFC 6733 section 7.5 permits synthesized and zero-filled
                // offending AVP representations. Validate only the trusted
                // outer identity/flags and retain the value opaquely.
                lifecycle::validate_base_definition(&avp, offset)?;
                retention.account(&avp, offset, "7.5", ctx)?;
                failed_avps.push(SwmAdditionalAvp::from_raw_exact(&avp));
            } else if key == AvpKey::ietf(base::AVP_REDIRECT_HOST) {
                lifecycle::validate_base_definition(&avp, offset)?;
                builder_helpers::validate_known_avp_value(
                    avp.value,
                    AvpDataType::DiameterUri,
                    ctx,
                    value_offset,
                    "6.12",
                )?;
                if redirect_hosts.len() >= MAX_SWM_REDIRECT_HOSTS {
                    return Err(DecodeError::new(DecodeErrorCode::IeCountExceeded, offset)
                        .with_spec_ref(SpecRef::new("ietf", "RFC6733", "6.12")));
                }
                retention.account(&avp, offset, "6.12", ctx)?;
                let value = builder_helpers::parse_string_value(avp.value, value_offset, "6.12")?;
                redirect_hosts.push(Redacted::from(value));
            } else if key == AvpKey::ietf(base::AVP_REDIRECT_HOST_USAGE) {
                lifecycle::validate_base_definition(&avp, offset)?;
                let value = builder_helpers::parse_u32_value(avp.value, value_offset, "6.13")?;
                let usage = SwmRedirectHostUsage::from_value(value).ok_or_else(|| {
                    DecodeError::new(
                        DecodeErrorCode::InvalidEnumValue {
                            field: "Redirect-Host-Usage",
                            value: u64::from(value),
                        },
                        value_offset,
                    )
                    .with_spec_ref(SpecRef::new("ietf", "RFC6733", "6.13"))
                })?;
                builder_helpers::set_once(&mut redirect_usage, usage, offset, "6.13")?;
                retention.account(&avp, offset, "6.13", ctx)?;
            } else if key == AvpKey::ietf(base::AVP_REDIRECT_MAX_CACHE_TIME) {
                lifecycle::validate_base_definition(&avp, offset)?;
                let value = builder_helpers::parse_u32_value(avp.value, value_offset, "6.14")?;
                builder_helpers::set_once(&mut redirect_max_cache_time, value, offset, "6.14")?;
                retention.account(&avp, offset, "6.14", ctx)?;
            } else if key == AvpKey::ietf(base::AVP_AUTH_APPLICATION_ID) {
                lifecycle::validate_base_definition(&avp, offset)?;
                let value = builder_helpers::parse_u32_value(avp.value, value_offset, "6.8")?;
                if value != APPLICATION_ID.get() {
                    return Err(decode_structural_error_at(
                        "generic SWm DEA Auth-Application-Id must match the header application",
                        offset,
                        "6.8",
                    ));
                }
                builder_helpers::set_once(&mut generic_auth_application_id, value, offset, "6.8")?;
                retention.account(&avp, offset, "7.2", ctx)?;
                additional_avps.push(SwmAdditionalAvp::from_raw_exact(&avp));
            } else if key == AvpKey::ietf(base::AVP_PROXY_INFO) {
                retain_diameter_eap_proxy_info(
                    &avp,
                    ctx,
                    offset,
                    value_offset,
                    "7.2",
                    &mut retention,
                    &mut proxy_infos,
                )?;
            } else if key == AvpKey::ietf(base::AVP_ROUTE_RECORD) {
                return Err(decode_structural_error_at(
                    "SWm DEA must not contain Route-Record",
                    offset,
                    "6.7.1",
                ));
            } else if key == AvpKey::ietf(base::AVP_DESTINATION_HOST)
                || key == AvpKey::ietf(base::AVP_DESTINATION_REALM)
            {
                return Err(decode_structural_error_at(
                    "Diameter answers must not contain Destination-Host or Destination-Realm",
                    offset,
                    "6.2",
                ));
            } else {
                retain_generic_error_wildcard_avp(
                    &avp,
                    ctx,
                    offset,
                    value_offset,
                    &mut retention,
                    &mut additional_avps,
                )?;
            }
            Ok(())
        },
    )?;

    let result_code = builder_helpers::require_field(
        result_code,
        "generic SWm DEA requires base Result-Code",
        "7.2",
    )?;
    if !result_code_allows_generic_error_bit(result_code) {
        return Err(decode_structural_error(
            "generic SWm DEA E bit is invalid for this Result-Code family",
            "7.1",
        ));
    }
    if result_code_requires_failed_avp(result_code) && failed_avps.is_empty() {
        return Err(decode_structural_error(
            "generic SWm DEA Result-Code requires Failed-AVP evidence",
            "7.5",
        ));
    }
    if SwmDiameterEapAgentDeliveryFailure::from_result_code(result_code).is_some()
        && additional_avps
            .iter()
            .any(is_known_agent_delivery_application_avp)
    {
        return Err(decode_structural_error(
            "SWm agent delivery failure must omit application-only AVPs",
            "7.2",
        ));
    }
    let has_redirect_context =
        !redirect_hosts.is_empty() || redirect_usage.is_some() || redirect_max_cache_time.is_some();
    let redirect = if result_code == DIAMETER_REDIRECT_INDICATION {
        Some(
            SwmDiameterRedirect::new(redirect_hosts, redirect_usage, redirect_max_cache_time)
                .map_err(|_| {
                    decode_structural_error("generic SWm DEA redirect context is invalid", "6.12")
                })?,
        )
    } else if has_redirect_context {
        return Err(decode_structural_error(
            "Redirect AVPs require DIAMETER_REDIRECT_INDICATION",
            "6.12",
        ));
    } else {
        None
    };

    Ok(ParsedSwmDiameterEapGenericErrorParts {
        answer: SwmDiameterEapGenericErrorAnswer {
            session_id,
            result_code,
            origin_host: builder_helpers::require_field(
                origin_host,
                "generic SWm DEA requires Origin-Host",
                "7.2",
            )?,
            origin_realm: builder_helpers::require_field(
                origin_realm,
                "generic SWm DEA requires Origin-Realm",
                "7.2",
            )?,
            redirect,
            error_message,
            error_reporting_host,
            origin_state_id,
            experimental_result,
            failed_avps,
            additional_avps,
            provenance: SwmDiameterEapGenericErrorAnswerProvenance::Parsed,
        },
        proxy_infos,
    })
}

fn is_known_agent_delivery_application_avp(avp: &SwmAdditionalAvp) -> bool {
    let header = avp.header();
    match header.vendor_id {
        None => matches!(
            header.code,
            base::AVP_AUTH_APPLICATION_ID
                | base::AVP_AUTH_GRACE_PERIOD
                | base::AVP_AUTH_SESSION_STATE
                | base::AVP_AUTHORIZATION_LIFETIME
                | base::AVP_CLASS
                | base::AVP_RE_AUTH_REQUEST_TYPE
                | base::AVP_SESSION_TIMEOUT
                | base::AVP_MULTI_ROUND_TIME_OUT
                | base::AVP_USER_NAME
                | AVP_AUTH_REQUEST_TYPE
                | AVP_EAP_MASTER_SESSION_KEY
                | AVP_EAP_PAYLOAD
                | AVP_EAP_REISSUED_PAYLOAD
                | AVP_MIP6_AGENT_INFO
                | AVP_MIP6_FEATURE_VECTOR
                | AVP_MIP6_HOME_LINK_PREFIX
                | AVP_MIP_HOME_AGENT_ADDRESS
                | AVP_MIP_HOME_AGENT_HOST
                | AVP_MOBILE_NODE_IDENTIFIER
                | AVP_QOS_CAPABILITY
                | AVP_QOS_PROFILE_ID
                | AVP_QOS_PROFILE_TEMPLATE
                | AVP_REPLY_MESSAGE
                | AVP_SERVICE_SELECTION
                | AVP_STATE
                | AVP_SUBSCRIPTION_ID
                | AVP_SUBSCRIPTION_ID_DATA
                | AVP_SUBSCRIPTION_ID_TYPE
        ),
        Some(vendor_id) if vendor_id == VENDOR_ID_3GPP => matches!(
            header.code,
            AVP_3GPP_CHARGING_CHARACTERISTICS
                | AVP_AAA_FAILURE_INDICATION
                | AVP_AAR_FLAGS
                | AVP_ALLOCATION_RETENTION_PRIORITY
                | AVP_AMBR
                | AVP_APN_CONFIGURATION
                | AVP_APN_OI_REPLACEMENT
                | AVP_CONTEXT_IDENTIFIER
                | AVP_CORE_NETWORK_RESTRICTIONS
                | AVP_EMERGENCY_INFO
                | AVP_EMERGENCY_SERVICES
                | AVP_EPS_SUBSCRIBED_QOS_PROFILE
                | AVP_EXTENDED_MAX_REQUESTED_BANDWIDTH_DL
                | AVP_EXTENDED_MAX_REQUESTED_BANDWIDTH_UL
                | AVP_FEATURE_LIST
                | AVP_FEATURE_LIST_ID
                | AVP_HIGH_PRIORITY_ACCESS_INFO
                | AVP_IMEI
                | AVP_INTERWORKING_5GS_INDICATOR
                | AVP_MAX_REQUESTED_BANDWIDTH_DL
                | AVP_MAX_REQUESTED_BANDWIDTH_UL
                | AVP_MPS_PRIORITY
                | AVP_PDN_GW_ALLOCATION_TYPE
                | AVP_PDN_TYPE
                | AVP_PRE_EMPTION_CAPABILITY
                | AVP_PRE_EMPTION_VULNERABILITY
                | AVP_PRIORITY_LEVEL
                | AVP_QOS_CLASS_IDENTIFIER
                | AVP_RAT_TYPE
                | AVP_SERVED_PARTY_IP_ADDRESS
                | AVP_SOFTWARE_VERSION
                | AVP_SPECIFIC_APN_INFO
                | AVP_SUPPORTED_FEATURES
                | AVP_TERMINAL_INFORMATION
                | AVP_TRACE_COLLECTION_ENTITY
                | AVP_TRACE_DATA
                | AVP_TRACE_DEPTH
                | AVP_TRACE_EVENT_LIST
                | AVP_TRACE_INFO
                | AVP_TRACE_INTERFACE_LIST
                | AVP_TRACE_NE_TYPE_LIST
                | AVP_TRACE_REFERENCE
                | AVP_TRACE_REPORTING_CONSUMER_URI
                | AVP_UE_LOCAL_IP_ADDRESS
                | AVP_UE_USAGE_TYPE
                | AVP_VISITED_NETWORK_IDENTIFIER
                | AVP_VPLMN_DYNAMIC_ADDRESS_ALLOWED
        ),
        Some(_) => false,
    }
}

fn parse_required_base_identity(
    avp: &RawAvp<'_>,
    ctx: DecodeContext,
    offset: usize,
    value_offset: usize,
    section: &'static str,
) -> Result<Redacted<String>, DecodeError> {
    lifecycle::validate_base_definition(avp, offset)?;
    builder_helpers::validate_known_avp_value(
        avp.value,
        AvpDataType::DiameterIdentity,
        ctx,
        value_offset,
        section,
    )?;
    let value = builder_helpers::parse_string_value(avp.value, value_offset, section)?;
    if value.is_empty() {
        return Err(decode_structural_error_at(
            "DiameterIdentity must not be empty",
            offset,
            section,
        ));
    }
    Ok(Redacted::from(value))
}

fn retain_generic_error_wildcard_avp(
    avp: &RawAvp<'_>,
    ctx: DecodeContext,
    offset: usize,
    value_offset: usize,
    retention: &mut DiameterEapRetention,
    retained: &mut Vec<SwmAdditionalAvp>,
) -> Result<(), DecodeError> {
    let definition = base::dictionary()
        .find_avp(avp.header.key())
        .or_else(|| dictionary().find_avp(avp.header.key()));
    if let Some(definition) = definition {
        lifecycle::validate_flags(&avp.header, definition.flags(), offset, "7.2")?;
        builder_helpers::validate_known_avp_value(
            avp.value,
            definition.data_type(),
            ctx,
            value_offset,
            "7.2",
        )?;
    } else {
        builder_helpers::handle_unknown_avp(ctx, avp, offset, "7.2")?;
        if ctx.unknown_ie_policy != UnknownIePolicy::Preserve {
            return Ok(());
        }
    }
    retention.account(avp, offset, "7.2", ctx)?;
    retained.push(SwmAdditionalAvp::from_raw_exact(avp));
    Ok(())
}

/// Parse a SWm DEA while retaining its Diameter transaction identifiers.
///
/// Use this envelope for emergency authorization correlation. The ordinary
/// typed answer parser remains available for answer-local observations.
pub fn parse_swm_diameter_eap_answer_envelope(
    message: &Message<'_>,
    ctx: DecodeContext,
) -> Result<SwmDiameterEapAnswerEnvelope, DecodeError> {
    let transaction = SwmDiameterTransaction::from_message(message);
    let parts = parse_swm_diameter_eap_application_answer_parts(message, ctx)?;
    Ok(SwmDiameterEapAnswerEnvelope {
        transaction,
        proxiable: message.header.flags.is_proxiable(),
        answer: parts.answer,
        proxy_infos: parts.proxy_infos,
        provenance: SwmDiameterEapAnswerEnvelopeProvenance::Parsed,
    })
}

fn validate_emergency_services_flags(
    header: &AvpHeader,
    offset: usize,
    section: &'static str,
) -> Result<(), DecodeError> {
    if header.flags.is_mandatory() || header.flags.is_protected() {
        return Err(DecodeError::new(
            DecodeErrorCode::Structural {
                reason: "SWm Emergency-Services AVP must clear the M and P bits",
            },
            builder_helpers::offset_add(offset, 4, section)?,
        )
        .with_spec_ref(SpecRef::new("3gpp", "TS29273", "7.2.3.1")));
    }
    Ok(())
}

fn validate_3gpp_mandatory_flags(
    header: &AvpHeader,
    offset: usize,
    section: &'static str,
) -> Result<(), DecodeError> {
    if !header.flags.is_mandatory() || header.flags.is_protected() {
        return Err(DecodeError::new(
            DecodeErrorCode::Structural {
                reason: "3GPP AVP must set the M bit and clear the P bit",
            },
            builder_helpers::offset_add(offset, 4, section)?,
        )
        .with_spec_ref(SpecRef::new("3gpp", "TS29272", section)));
    }
    Ok(())
}

fn validate_base_mandatory_flags(
    header: &AvpHeader,
    offset: usize,
    section: &'static str,
) -> Result<(), DecodeError> {
    validate_base_mandatory_flags_for(header, offset, "RFC6733", section)
}

fn validate_base_mandatory_flags_for(
    header: &AvpHeader,
    offset: usize,
    document: &'static str,
    section: &'static str,
) -> Result<(), DecodeError> {
    if header.vendor_id.is_some() || !header.flags.is_mandatory() || header.flags.is_protected() {
        return Err(DecodeError::new(
            DecodeErrorCode::Structural {
                reason: "base AVP must clear V/P and set M",
            },
            builder_helpers::offset_add(offset, 4, section)?,
        )
        .with_spec_ref(SpecRef::new("ietf", document, section)));
    }
    Ok(())
}

fn validate_base_m_bit_agnostic_flags(
    header: &AvpHeader,
    offset: usize,
    section: &'static str,
) -> Result<(), DecodeError> {
    validate_base_m_bit_agnostic_flags_for(header, offset, "RFC5447", section)
}

fn validate_base_m_bit_agnostic_flags_for(
    header: &AvpHeader,
    offset: usize,
    document: &'static str,
    section: &'static str,
) -> Result<(), DecodeError> {
    if header.vendor_id.is_some() || header.flags.is_protected() {
        return Err(DecodeError::new(
            DecodeErrorCode::Structural {
                reason: "understood base AVP must clear V/P",
            },
            builder_helpers::offset_add(offset, 4, section)?,
        )
        .with_spec_ref(SpecRef::new("ietf", document, section)));
    }
    Ok(())
}

fn validate_3gpp_m_bit_agnostic_flags(
    header: &AvpHeader,
    offset: usize,
    document: &'static str,
    section: &'static str,
) -> Result<(), DecodeError> {
    if header.vendor_id != Some(VENDOR_ID_3GPP) || header.flags.is_protected() {
        return Err(DecodeError::new(
            DecodeErrorCode::Structural {
                reason: "understood 3GPP AVP must set V and clear P",
            },
            builder_helpers::offset_add(offset, 4, section)?,
        )
        .with_spec_ref(SpecRef::new("3gpp", document, section)));
    }
    Ok(())
}

fn validate_supported_features_outer_flags(
    header: &AvpHeader,
    request: bool,
    offset: usize,
) -> Result<SwmSupportedFeaturesRequirement, DecodeError> {
    if header.vendor_id != Some(VENDOR_ID_3GPP) || header.flags.is_protected() {
        return Err(DecodeError::new(
            DecodeErrorCode::Structural {
                reason: "Supported-Features must set V for 3GPP and clear P",
            },
            builder_helpers::offset_add(offset, 4, "6.3.29")?,
        )
        .with_spec_ref(SpecRef::new("3gpp", "TS29229", "6.3.29")));
    }
    if !request && header.flags.is_mandatory() {
        return Err(DecodeError::new(
            DecodeErrorCode::Structural {
                reason: "Supported-Features answer AVP must clear M",
            },
            builder_helpers::offset_add(offset, 4, "6.3.29")?,
        )
        .with_spec_ref(SpecRef::new("3gpp", "TS29229", "6.3.29")));
    }
    Ok(if header.flags.is_mandatory() {
        SwmSupportedFeaturesRequirement::Required
    } else {
        SwmSupportedFeaturesRequirement::Discovery
    })
}

fn append_qos_capability_avp(
    dst: &mut BytesMut,
    capability: &SwmQosCapability,
    ctx: EncodeContext,
) -> Result<(), EncodeError> {
    let mut value = BytesMut::new();
    for profile in capability.profiles() {
        let mut profile_value = BytesMut::new();
        builder_helpers::append_u32_avp(
            &mut profile_value,
            base::AVP_VENDOR_ID,
            profile.vendor_id().get(),
            true,
            ctx,
        )?;
        builder_helpers::append_u32_avp(
            &mut profile_value,
            AVP_QOS_PROFILE_ID,
            profile.profile_id(),
            true,
            ctx,
        )?;
        for additional in profile.additional_avps() {
            if additional.header().flags.is_mandatory() {
                return Err(encode_structural_error(
                    "unknown QoS-Profile-Template extension child must clear M",
                    "5.3",
                ));
            }
            additional.append_to(&mut profile_value, ctx)?;
        }
        builder_helpers::append_avp(
            &mut value,
            AvpHeader::ietf(AVP_QOS_PROFILE_TEMPLATE, true),
            &profile_value,
            ctx,
        )?;
    }
    for additional in capability.additional_avps() {
        if additional.header().flags.is_mandatory() {
            return Err(encode_structural_error(
                "unknown QoS-Capability extension child must clear M",
                "6",
            ));
        }
        additional.append_to(&mut value, ctx)?;
    }
    builder_helpers::append_avp(dst, AvpHeader::ietf(AVP_QOS_CAPABILITY, true), &value, ctx)
}

enum QosProfileTemplateParseError {
    Decode(DecodeError),
    Missing { error: DecodeError, key: AvpKey },
}

impl From<DecodeError> for QosProfileTemplateParseError {
    fn from(error: DecodeError) -> Self {
        Self::Decode(error)
    }
}

enum QosCapabilityParseError {
    Decode(DecodeError),
    Missing {
        error: Box<DecodeError>,
        key: AvpKey,
        profile_offset: Option<usize>,
    },
}

impl From<DecodeError> for QosCapabilityParseError {
    fn from(error: DecodeError) -> Self {
        Self::Decode(error)
    }
}

fn parse_qos_capability(
    value: &[u8],
    ctx: DecodeContext,
    base_offset: usize,
    depth: usize,
) -> Result<SwmQosCapability, QosCapabilityParseError> {
    let mut profiles = Vec::new();
    let mut additional_avps = Vec::new();
    let mut additional_keys = HashSet::new();
    let mut child_count = 0usize;
    let mut missing_child = None;
    let parse_result =
        builder_helpers::for_each_avp(value, ctx, base_offset, depth, |offset, child| {
            if child_count >= MAX_SWM_QOS_GROUP_CHILDREN {
                return Err(DecodeError::new(DecodeErrorCode::IeCountExceeded, offset)
                    .with_spec_ref(SpecRef::new("ietf", "RFC5777", "6")));
            }
            child_count += 1;
            let child_value_offset =
                builder_helpers::offset_add(offset, child.header.header_len(), "6")?;
            if child.header.code == AVP_QOS_PROFILE_TEMPLATE && child.header.vendor_id.is_none() {
                validate_base_mandatory_flags_for(&child.header, offset, "RFC5777", "5.3")?;
                if profiles.len() >= MAX_SWM_QOS_PROFILE_TEMPLATES {
                    return Err(DecodeError::new(DecodeErrorCode::IeCountExceeded, offset)
                        .with_spec_ref(SpecRef::new("ietf", "RFC5777", "6")));
                }
                match parse_qos_profile_template(child.value, ctx, child_value_offset, depth + 1) {
                    Ok(profile) => profiles.push(profile),
                    Err(QosProfileTemplateParseError::Missing { error, key }) => {
                        missing_child = Some((error.clone(), key, offset));
                        return Err(error);
                    }
                    Err(QosProfileTemplateParseError::Decode(error)) => return Err(error),
                }
            } else if child.header.flags.is_mandatory()
                || ctx.unknown_ie_policy == UnknownIePolicy::Reject
            {
                builder_helpers::handle_unknown_avp(ctx, &child, offset, "6")?;
            } else {
                if ctx.duplicate_ie_policy == DuplicateIePolicy::Reject
                    && !additional_keys.insert(child.header.key())
                {
                    return Err(DecodeError::new(DecodeErrorCode::DuplicateIe, offset)
                        .with_spec_ref(SpecRef::new("ietf", "RFC5777", "6")));
                }
                if ctx.unknown_ie_policy == UnknownIePolicy::Preserve {
                    if additional_avps.len() >= MAX_SWM_QOS_GROUP_CHILDREN {
                        return Err(DecodeError::new(DecodeErrorCode::IeCountExceeded, offset)
                            .with_spec_ref(SpecRef::new("ietf", "RFC5777", "6")));
                    }
                    additional_avps.push(SwmAdditionalAvp::from_raw_exact(&child));
                }
            }
            Ok(())
        });
    if let Err(error) = parse_result {
        return Err(if let Some((error, key, profile_offset)) = missing_child {
            QosCapabilityParseError::Missing {
                error: Box::new(error),
                key,
                profile_offset: Some(profile_offset),
            }
        } else {
            QosCapabilityParseError::Decode(error)
        });
    }
    if profiles.is_empty() {
        return Err(QosCapabilityParseError::Missing {
            error: Box::new(
                missing_child_error(base_offset, "missing QoS-Profile-Template child AVP")
                    .with_spec_ref(SpecRef::new("ietf", "RFC5777", "6")),
            ),
            key: AvpKey::ietf(AVP_QOS_PROFILE_TEMPLATE),
            profile_offset: None,
        });
    }
    validate_qos_profiles(&profiles).map_err(|error| {
        let reason = match error.code() {
            SwmDerAccessContextErrorCode::EmptyQosCapability => {
                "QoS-Capability requires at least one QoS-Profile-Template"
            }
            SwmDerAccessContextErrorCode::TooManyQosProfiles => {
                "QoS-Capability contains too many profile templates"
            }
            SwmDerAccessContextErrorCode::InactiveIndication => "QoS-Capability is invalid",
            SwmDerAccessContextErrorCode::PrepopulatedField
            | SwmDerAccessContextErrorCode::InvalidProvenance
            | SwmDerAccessContextErrorCode::InvalidVisitedNetworkIdentifier
            | SwmDerAccessContextErrorCode::EmptySupportedFeatures
            | SwmDerAccessContextErrorCode::ContradictoryValues
            | SwmDerAccessContextErrorCode::NonCanonicalValue => "QoS-Capability is invalid",
        };
        QosCapabilityParseError::Decode(
            DecodeError::new(DecodeErrorCode::Structural { reason }, base_offset)
                .with_spec_ref(SpecRef::new("ietf", "RFC5777", "6")),
        )
    })?;
    Ok(SwmQosCapability {
        profiles,
        additional_avps,
    })
}

fn parse_qos_profile_template(
    value: &[u8],
    ctx: DecodeContext,
    base_offset: usize,
    depth: usize,
) -> Result<SwmQosProfileTemplate, QosProfileTemplateParseError> {
    let mut vendor_id = None;
    let mut profile_id = None;
    let mut additional_avps = Vec::new();
    let mut additional_keys = HashSet::new();
    let mut child_count = 0usize;
    builder_helpers::for_each_avp(value, ctx, base_offset, depth, |offset, child| {
        if child_count >= MAX_SWM_QOS_GROUP_CHILDREN {
            return Err(DecodeError::new(DecodeErrorCode::IeCountExceeded, offset)
                .with_spec_ref(SpecRef::new("ietf", "RFC5777", "5.3")));
        }
        child_count += 1;
        let child_value_offset =
            builder_helpers::offset_add(offset, child.header.header_len(), "5.3")?;
        if child.header.code == base::AVP_VENDOR_ID && child.header.vendor_id.is_none() {
            validate_base_mandatory_flags_for(&child.header, offset, "RFC5777", "5.3")?;
            let value = builder_helpers::parse_u32_value(child.value, child_value_offset, "5.3")?;
            builder_helpers::set_once(&mut vendor_id, VendorId::new(value), offset, "5.3")?;
        } else if child.header.code == AVP_QOS_PROFILE_ID && child.header.vendor_id.is_none() {
            validate_base_mandatory_flags_for(&child.header, offset, "RFC5777", "5.2")?;
            let value = builder_helpers::parse_u32_value(child.value, child_value_offset, "5.2")?;
            builder_helpers::set_once(&mut profile_id, value, offset, "5.2")?;
        } else if child.header.flags.is_mandatory()
            || ctx.unknown_ie_policy == UnknownIePolicy::Reject
        {
            builder_helpers::handle_unknown_avp(ctx, &child, offset, "5.3")?;
        } else {
            if ctx.duplicate_ie_policy == DuplicateIePolicy::Reject
                && !additional_keys.insert(child.header.key())
            {
                return Err(DecodeError::new(DecodeErrorCode::DuplicateIe, offset)
                    .with_spec_ref(SpecRef::new("ietf", "RFC5777", "5.3")));
            }
            if ctx.unknown_ie_policy == UnknownIePolicy::Preserve {
                if additional_avps.len() >= MAX_SWM_QOS_GROUP_CHILDREN {
                    return Err(DecodeError::new(DecodeErrorCode::IeCountExceeded, offset)
                        .with_spec_ref(SpecRef::new("ietf", "RFC5777", "5.3")));
                }
                additional_avps.push(SwmAdditionalAvp::from_raw_exact(&child));
            }
        }
        Ok(())
    })?;
    let vendor_id = vendor_id.ok_or_else(|| QosProfileTemplateParseError::Missing {
        error: missing_child_error(
            base_offset,
            "missing QoS-Profile-Template Vendor-Id child AVP",
        )
        .with_spec_ref(SpecRef::new("ietf", "RFC5777", "5.3")),
        key: AvpKey::ietf(base::AVP_VENDOR_ID),
    })?;
    let profile_id = profile_id.ok_or_else(|| QosProfileTemplateParseError::Missing {
        error: missing_child_error(
            base_offset,
            "missing QoS-Profile-Template QoS-Profile-Id child AVP",
        )
        .with_spec_ref(SpecRef::new("ietf", "RFC5777", "5.3")),
        key: AvpKey::ietf(AVP_QOS_PROFILE_ID),
    })?;
    Ok(SwmQosProfileTemplate {
        vendor_id,
        profile_id,
        additional_avps,
    })
}

fn append_supported_features_avp(
    dst: &mut BytesMut,
    features: &SwmSupportedFeatureList,
    mandatory: bool,
    ctx: EncodeContext,
) -> Result<(), EncodeError> {
    let mut value = BytesMut::new();
    builder_helpers::append_u32_avp(
        &mut value,
        base::AVP_VENDOR_ID,
        features.vendor_id().get(),
        true,
        ctx,
    )?;
    builder_helpers::append_vendor_u32_avp(
        &mut value,
        AVP_FEATURE_LIST_ID,
        VENDOR_ID_3GPP,
        features.feature_list_id(),
        false,
        ctx,
    )?;
    builder_helpers::append_vendor_u32_avp(
        &mut value,
        AVP_FEATURE_LIST,
        VENDOR_ID_3GPP,
        features.feature_list(),
        false,
        ctx,
    )?;
    for additional in features.additional_avps() {
        if additional.header().flags.is_mandatory() {
            return Err(encode_structural_error(
                "unknown Supported-Features extension child must clear M",
                "6.3.29",
            ));
        }
        additional.append_to(&mut value, ctx)?;
    }
    builder_helpers::append_avp(
        dst,
        AvpHeader::vendor(AVP_SUPPORTED_FEATURES, VENDOR_ID_3GPP, mandatory),
        &value,
        ctx,
    )
}

enum SupportedFeaturesParseError {
    Decode(DecodeError),
    Missing { error: DecodeError, key: AvpKey },
}

impl From<DecodeError> for SupportedFeaturesParseError {
    fn from(error: DecodeError) -> Self {
        Self::Decode(error)
    }
}

impl SupportedFeaturesParseError {
    fn into_decode_error(self) -> DecodeError {
        match self {
            Self::Decode(error) | Self::Missing { error, .. } => error,
        }
    }
}

fn parse_supported_feature_list(
    avp: &crate::RawAvp<'_>,
    ctx: DecodeContext,
    base_offset: usize,
    depth: usize,
) -> Result<SwmSupportedFeatureList, SupportedFeaturesParseError> {
    let mut vendor_id = None;
    let mut feature_list_id = None;
    let mut feature_list = None;
    let mut additional_avps = Vec::new();
    let mut additional_keys = HashSet::new();
    builder_helpers::for_each_avp(avp.value, ctx, base_offset, depth, |offset, child| {
        let value_offset = builder_helpers::offset_add(offset, child.header.header_len(), "6.3.29")
            .map_err(|error| error.with_spec_ref(SpecRef::new("3gpp", "TS29229", "6.3.29")))?;
        let code = child.header.code;
        if code == base::AVP_VENDOR_ID && child.header.vendor_id.is_none() {
            validate_base_mandatory_flags(&child.header, offset, "5.3.3")?;
            let value = builder_helpers::parse_u32_value(child.value, value_offset, "5.3.3")?;
            builder_helpers::set_once(&mut vendor_id, VendorId::new(value), offset, "6.3.29")
                .map_err(|error| error.with_spec_ref(SpecRef::new("3gpp", "TS29229", "6.3.29")))?;
        } else if code == AVP_FEATURE_LIST_ID && child.header.vendor_id == Some(VENDOR_ID_3GPP) {
            validate_3gpp_m_bit_agnostic_flags(&child.header, offset, "TS29229", "6.3.30")?;
            let value = builder_helpers::parse_u32_value(child.value, value_offset, "6.3.30")
                .map_err(|error| error.with_spec_ref(SpecRef::new("3gpp", "TS29229", "6.3.30")))?;
            builder_helpers::set_once(&mut feature_list_id, value, offset, "6.3.30")
                .map_err(|error| error.with_spec_ref(SpecRef::new("3gpp", "TS29229", "6.3.30")))?;
        } else if code == AVP_FEATURE_LIST && child.header.vendor_id == Some(VENDOR_ID_3GPP) {
            validate_3gpp_m_bit_agnostic_flags(&child.header, offset, "TS29229", "6.3.31")?;
            let value = builder_helpers::parse_u32_value(child.value, value_offset, "6.3.31")
                .map_err(|error| error.with_spec_ref(SpecRef::new("3gpp", "TS29229", "6.3.31")))?;
            builder_helpers::set_once(&mut feature_list, value, offset, "6.3.31")
                .map_err(|error| error.with_spec_ref(SpecRef::new("3gpp", "TS29229", "6.3.31")))?;
        } else {
            if child.header.flags.is_mandatory() || ctx.unknown_ie_policy == UnknownIePolicy::Reject
            {
                builder_helpers::handle_unknown_avp(ctx, &child, offset, "6.3.29")?;
            } else {
                if ctx.duplicate_ie_policy == DuplicateIePolicy::Reject
                    && !additional_keys.insert(child.header.key())
                {
                    return Err(DecodeError::new(DecodeErrorCode::DuplicateIe, offset)
                        .with_spec_ref(SpecRef::new("3gpp", "TS29229", "6.3.29")));
                }
                if ctx.unknown_ie_policy == UnknownIePolicy::Preserve {
                    if additional_avps.len() >= MAX_SWM_SUPPORTED_FEATURES {
                        return Err(DecodeError::new(DecodeErrorCode::IeCountExceeded, offset)
                            .with_spec_ref(SpecRef::new("3gpp", "TS29229", "6.3.29")));
                    }
                    additional_avps.push(SwmAdditionalAvp::from_raw_exact(&child));
                }
            }
        }
        Ok(())
    })?;
    let vendor_id = vendor_id.ok_or_else(|| SupportedFeaturesParseError::Missing {
        error: missing_child_error(
            base_offset,
            "missing Supported-Features Vendor-Id child AVP",
        ),
        key: AvpKey::ietf(base::AVP_VENDOR_ID),
    })?;
    let feature_list_id = feature_list_id.ok_or_else(|| SupportedFeaturesParseError::Missing {
        error: missing_child_error(
            base_offset,
            "missing Supported-Features Feature-List-ID child AVP",
        ),
        key: AvpKey::vendor(AVP_FEATURE_LIST_ID, VENDOR_ID_3GPP),
    })?;
    let feature_list = feature_list.ok_or_else(|| SupportedFeaturesParseError::Missing {
        error: missing_child_error(
            base_offset,
            "missing Supported-Features Feature-List child AVP",
        ),
        key: AvpKey::vendor(AVP_FEATURE_LIST, VENDOR_ID_3GPP),
    })?;
    Ok(SwmSupportedFeatureList {
        vendor_id,
        feature_list_id,
        feature_list,
        additional_avps,
    })
}

fn parse_requested_supported_features(
    avp: &crate::RawAvp<'_>,
    ctx: DecodeContext,
    base_offset: usize,
    depth: usize,
    outer_offset: usize,
) -> Result<SwmRequestedSupportedFeatures, SupportedFeaturesParseError> {
    let requirement = validate_supported_features_outer_flags(&avp.header, true, outer_offset)?;
    let features = parse_supported_feature_list(avp, ctx, base_offset, depth)?;
    if requirement == SwmSupportedFeaturesRequirement::Discovery && features.feature_list() != 0 {
        return Err(DecodeError::new(
            DecodeErrorCode::Structural {
                reason: "M-clear Supported-Features request must carry a zero Feature-List",
            },
            outer_offset,
        )
        .with_spec_ref(SpecRef::new("3gpp", "TS29229", "6.3.29"))
        .into());
    }
    Ok(SwmRequestedSupportedFeatures {
        features,
        requirement,
    })
}

fn parse_answer_supported_features(
    avp: &crate::RawAvp<'_>,
    ctx: DecodeContext,
    base_offset: usize,
    depth: usize,
    outer_offset: usize,
) -> Result<SwmSupportedFeatureList, DecodeError> {
    validate_supported_features_outer_flags(&avp.header, false, outer_offset)?;
    parse_supported_feature_list(avp, ctx, base_offset, depth)
        .map_err(SupportedFeaturesParseError::into_decode_error)
}

pub(super) fn append_experimental_result_avp(
    dst: &mut BytesMut,
    vendor_id: VendorId,
    code: u32,
    ctx: EncodeContext,
) -> Result<(), EncodeError> {
    if vendor_id.get() == 0 {
        return Err(encode_structural_error(
            "Experimental-Result Vendor-Id must not be zero",
            "7.6",
        ));
    }
    let mut value = BytesMut::new();
    builder_helpers::append_u32_avp(&mut value, base::AVP_VENDOR_ID, vendor_id.get(), true, ctx)?;
    builder_helpers::append_u32_avp(
        &mut value,
        base::AVP_EXPERIMENTAL_RESULT_CODE,
        code,
        true,
        ctx,
    )?;
    builder_helpers::append_avp(
        dst,
        AvpHeader::ietf(base::AVP_EXPERIMENTAL_RESULT, true),
        &value,
        ctx,
    )
}

pub(super) fn parse_experimental_result(
    value: &[u8],
    ctx: DecodeContext,
    base_offset: usize,
    depth: usize,
) -> Result<SwmDiameterResult, DecodeError> {
    let mut vendor_id = None;
    let mut code = None;
    builder_helpers::for_each_avp(value, ctx, base_offset, depth, |offset, avp| {
        validate_base_mandatory_flags(&avp.header, offset, "7.6")?;
        let value_offset = builder_helpers::offset_add(offset, avp.header.header_len(), "7.6")?;
        if avp.header.code == base::AVP_VENDOR_ID {
            let value = builder_helpers::parse_u32_value(avp.value, value_offset, "5.3.3")?;
            builder_helpers::set_once(&mut vendor_id, value, offset, "7.6")?;
        } else if avp.header.code == base::AVP_EXPERIMENTAL_RESULT_CODE {
            let value = builder_helpers::parse_u32_value(avp.value, value_offset, "7.7")?;
            builder_helpers::set_once(&mut code, value, offset, "7.6")?;
        } else {
            builder_helpers::handle_unknown_avp(ctx, &avp, offset, "7.6")?;
        }
        Ok(())
    })?;
    let vendor_id =
        vendor_id.ok_or_else(|| missing_child_error(base_offset, "missing Vendor-Id child AVP"))?;
    if vendor_id == 0 {
        return Err(decode_structural_error_at(
            "Experimental-Result Vendor-Id must not be zero",
            base_offset,
            "7.6",
        ));
    }
    Ok(SwmDiameterResult::Experimental {
        vendor_id: VendorId::new(vendor_id),
        code: code.ok_or_else(|| {
            missing_child_error(base_offset, "missing Experimental-Result-Code child AVP")
        })?,
    })
}

fn append_terminal_information_avp(
    dst: &mut BytesMut,
    terminal: &SwmTerminalInformation,
    ctx: EncodeContext,
) -> Result<(), EncodeError> {
    let mut value = BytesMut::new();
    builder_helpers::append_vendor_octet_string_avp(
        &mut value,
        AVP_IMEI,
        VENDOR_ID_3GPP,
        terminal.imei.as_str().as_bytes(),
        true,
        ctx,
    )?;
    if let Some(software_version) = terminal.software_version.as_ref() {
        builder_helpers::append_vendor_octet_string_avp(
            &mut value,
            AVP_SOFTWARE_VERSION,
            VENDOR_ID_3GPP,
            software_version.as_ref().as_bytes(),
            true,
            ctx,
        )?;
    }
    builder_helpers::append_avp(
        dst,
        AvpHeader::vendor(AVP_TERMINAL_INFORMATION, VENDOR_ID_3GPP, true),
        &value,
        ctx,
    )
}

enum TerminalInformationParseError {
    Decode(DecodeError),
    MissingImei(DecodeError),
}

impl From<DecodeError> for TerminalInformationParseError {
    fn from(error: DecodeError) -> Self {
        Self::Decode(error)
    }
}

fn parse_terminal_information(
    value: &[u8],
    ctx: DecodeContext,
    base_offset: usize,
    depth: usize,
) -> Result<SwmTerminalInformation, TerminalInformationParseError> {
    let mut imei = None;
    let mut software_version = None;
    builder_helpers::for_each_avp(value, ctx, base_offset, depth, |offset, avp| {
        let value_offset = builder_helpers::offset_add(offset, avp.header.header_len(), "7.3.3")?;
        if avp.header.vendor_id == Some(VENDOR_ID_3GPP) && avp.header.code == AVP_IMEI {
            validate_3gpp_mandatory_flags(&avp.header, offset, "7.3.4")?;
            let value = builder_helpers::parse_string_value(avp.value, value_offset, "7.3.4")?;
            let value = Imei::new(value).map_err(|_| {
                DecodeError::new(
                    DecodeErrorCode::Structural {
                        reason: "Terminal-Information IMEI must contain 14 or 15 decimal digits",
                    },
                    value_offset,
                )
                .with_spec_ref(SpecRef::new("3gpp", "TS29272", "7.3.4"))
            })?;
            builder_helpers::set_once(&mut imei, value, offset, "7.3.3")?;
        } else if avp.header.vendor_id == Some(VENDOR_ID_3GPP)
            && avp.header.code == AVP_SOFTWARE_VERSION
        {
            validate_3gpp_mandatory_flags(&avp.header, offset, "7.3.5")?;
            let value = builder_helpers::parse_string_value(avp.value, value_offset, "7.3.5")?;
            if value.len() != 2 || !value.as_bytes().iter().all(u8::is_ascii_digit) {
                return Err(DecodeError::new(
                    DecodeErrorCode::Structural {
                        reason: "Software-Version must contain exactly two decimal digits",
                    },
                    value_offset,
                )
                .with_spec_ref(SpecRef::new("3gpp", "TS29272", "7.3.5")));
            }
            builder_helpers::set_once(
                &mut software_version,
                Redacted::from(value),
                offset,
                "7.3.3",
            )?;
        } else {
            builder_helpers::handle_unknown_avp(ctx, &avp, offset, "7.3.3")?;
        }
        Ok(())
    })?;
    let imei = imei.ok_or_else(|| {
        TerminalInformationParseError::MissingImei(missing_child_error(
            base_offset,
            "missing IMEI child AVP",
        ))
    })?;
    Ok(SwmTerminalInformation {
        imei,
        software_version,
    })
}

fn append_eps_subscribed_qos_profile_avp(
    dst: &mut BytesMut,
    profile: &EpsSubscribedQosProfile,
    ctx: EncodeContext,
) -> Result<(), EncodeError> {
    let mut value = BytesMut::new();
    builder_helpers::append_vendor_u32_avp(
        &mut value,
        AVP_QOS_CLASS_IDENTIFIER,
        VENDOR_ID_3GPP,
        profile.qos_class_identifier.value(),
        true,
        ctx,
    )?;
    append_allocation_retention_priority_avp(
        &mut value,
        &profile.allocation_retention_priority,
        ctx,
    )?;
    builder_helpers::append_avp(
        dst,
        AvpHeader::vendor(AVP_EPS_SUBSCRIBED_QOS_PROFILE, VENDOR_ID_3GPP, true),
        &value,
        ctx,
    )
}

fn parse_eps_subscribed_qos_profile(
    value: &[u8],
    ctx: DecodeContext,
    base_offset: usize,
    depth: usize,
) -> Result<EpsSubscribedQosProfile, DecodeError> {
    let mut qos_class_identifier = None;
    let mut allocation_retention_priority = None;
    builder_helpers::for_each_avp(value, ctx, base_offset, depth, |offset, avp| {
        let value_offset = builder_helpers::offset_add(offset, avp.header.header_len(), "7.3.37")?;
        let code = avp.header.code;
        let vendor_id = avp.header.vendor_id;
        reject_zero_vendor_id(&avp, offset, "7.3.37")?;
        if code == AVP_QOS_CLASS_IDENTIFIER && vendor_id == Some(VENDOR_ID_3GPP) {
            validate_swm_apn_qos_child_flags(&avp, offset, "5.3.17")?;
            let value = builder_helpers::parse_u32_value(avp.value, value_offset, "5.3.17")?;
            let value = SwmQosClassIdentifier::new(value)
                .map_err(|error| qos_value_decode_error(error, value_offset, "5.3.17"))?;
            builder_helpers::set_once(&mut qos_class_identifier, value, offset, "7.3.37")?;
        } else if code == AVP_ALLOCATION_RETENTION_PRIORITY && vendor_id == Some(VENDOR_ID_3GPP) {
            validate_swm_apn_qos_child_flags(&avp, offset, "5.3.32")?;
            builder_helpers::set_once(
                &mut allocation_retention_priority,
                parse_allocation_retention_priority(avp.value, ctx, value_offset, depth + 1)?,
                offset,
                "7.3.37",
            )?;
        } else {
            builder_helpers::handle_unknown_avp(ctx, &avp, offset, "7.3.37")?;
        }
        Ok(())
    })?;
    Ok(EpsSubscribedQosProfile {
        qos_class_identifier: qos_class_identifier.ok_or_else(|| {
            missing_child_error(base_offset, "missing QoS-Class-Identifier child AVP")
        })?,
        allocation_retention_priority: allocation_retention_priority.ok_or_else(|| {
            missing_child_error(
                base_offset,
                "missing Allocation-Retention-Priority child AVP",
            )
        })?,
    })
}

fn append_allocation_retention_priority_avp(
    dst: &mut BytesMut,
    arp: &AllocationRetentionPriority,
    ctx: EncodeContext,
) -> Result<(), EncodeError> {
    let mut value = BytesMut::new();
    builder_helpers::append_vendor_u32_avp(
        &mut value,
        AVP_PRIORITY_LEVEL,
        VENDOR_ID_3GPP,
        arp.priority_level.value(),
        true,
        ctx,
    )?;
    if let Some(pre_emption_capability) = arp.pre_emption_capability {
        builder_helpers::append_vendor_u32_avp(
            &mut value,
            AVP_PRE_EMPTION_CAPABILITY,
            VENDOR_ID_3GPP,
            pre_emption_capability.value(),
            true,
            ctx,
        )?;
    }
    if let Some(pre_emption_vulnerability) = arp.pre_emption_vulnerability {
        builder_helpers::append_vendor_u32_avp(
            &mut value,
            AVP_PRE_EMPTION_VULNERABILITY,
            VENDOR_ID_3GPP,
            pre_emption_vulnerability.value(),
            true,
            ctx,
        )?;
    }
    builder_helpers::append_avp(
        dst,
        AvpHeader::vendor(AVP_ALLOCATION_RETENTION_PRIORITY, VENDOR_ID_3GPP, true),
        &value,
        ctx,
    )
}

fn parse_allocation_retention_priority(
    value: &[u8],
    ctx: DecodeContext,
    base_offset: usize,
    depth: usize,
) -> Result<AllocationRetentionPriority, DecodeError> {
    let mut priority_level = None;
    let mut pre_emption_capability = None;
    let mut pre_emption_vulnerability = None;
    builder_helpers::for_each_avp(value, ctx, base_offset, depth, |offset, avp| {
        let value_offset = builder_helpers::offset_add(offset, avp.header.header_len(), "5.3.32")?;
        let code = avp.header.code;
        let vendor_id = avp.header.vendor_id;
        reject_zero_vendor_id(&avp, offset, "5.3.32")?;
        if code == AVP_PRIORITY_LEVEL && vendor_id == Some(VENDOR_ID_3GPP) {
            validate_swm_apn_qos_child_flags(&avp, offset, "5.3.45")?;
            let value = builder_helpers::parse_u32_value(avp.value, value_offset, "5.3.45")?;
            let value = SwmPriorityLevel::new(value)
                .map_err(|error| qos_value_decode_error(error, value_offset, "5.3.45"))?;
            builder_helpers::set_once(&mut priority_level, value, offset, "5.3.32")?;
        } else if code == AVP_PRE_EMPTION_CAPABILITY && vendor_id == Some(VENDOR_ID_3GPP) {
            validate_swm_apn_qos_child_flags(&avp, offset, "5.3.46")?;
            let value = builder_helpers::parse_u32_value(avp.value, value_offset, "5.3.46")?;
            let value = SwmPreemptionCapability::from_value(value)
                .map_err(|error| qos_value_decode_error(error, value_offset, "5.3.46"))?;
            builder_helpers::set_once(&mut pre_emption_capability, value, offset, "5.3.32")?;
        } else if code == AVP_PRE_EMPTION_VULNERABILITY && vendor_id == Some(VENDOR_ID_3GPP) {
            validate_swm_apn_qos_child_flags(&avp, offset, "5.3.47")?;
            let value = builder_helpers::parse_u32_value(avp.value, value_offset, "5.3.47")?;
            let value = SwmPreemptionVulnerability::from_value(value)
                .map_err(|error| qos_value_decode_error(error, value_offset, "5.3.47"))?;
            builder_helpers::set_once(&mut pre_emption_vulnerability, value, offset, "5.3.32")?;
        } else {
            builder_helpers::handle_unknown_avp(ctx, &avp, offset, "5.3.32")?;
        }
        Ok(())
    })?;
    Ok(AllocationRetentionPriority {
        priority_level: priority_level
            .ok_or_else(|| missing_child_error(base_offset, "missing Priority-Level child AVP"))?,
        pre_emption_capability,
        pre_emption_vulnerability,
    })
}

fn append_ambr_avp(dst: &mut BytesMut, ambr: &Ambr, ctx: EncodeContext) -> Result<(), EncodeError> {
    let mut value = BytesMut::new();
    let (uplink, extended_uplink) = ambr.max_requested_bandwidth_ul.wire_values();
    let (downlink, extended_downlink) = ambr.max_requested_bandwidth_dl.wire_values();
    builder_helpers::append_vendor_u32_avp(
        &mut value,
        AVP_MAX_REQUESTED_BANDWIDTH_UL,
        VENDOR_ID_3GPP,
        uplink,
        true,
        ctx,
    )?;
    builder_helpers::append_vendor_u32_avp(
        &mut value,
        AVP_MAX_REQUESTED_BANDWIDTH_DL,
        VENDOR_ID_3GPP,
        downlink,
        true,
        ctx,
    )?;
    if let Some(extended_uplink) = extended_uplink {
        builder_helpers::append_vendor_u32_avp(
            &mut value,
            AVP_EXTENDED_MAX_REQUESTED_BANDWIDTH_UL,
            VENDOR_ID_3GPP,
            extended_uplink,
            true,
            ctx,
        )?;
    }
    if let Some(extended_downlink) = extended_downlink {
        builder_helpers::append_vendor_u32_avp(
            &mut value,
            AVP_EXTENDED_MAX_REQUESTED_BANDWIDTH_DL,
            VENDOR_ID_3GPP,
            extended_downlink,
            true,
            ctx,
        )?;
    }
    builder_helpers::append_avp(
        dst,
        AvpHeader::vendor(AVP_AMBR, VENDOR_ID_3GPP, true),
        &value,
        ctx,
    )
}

fn parse_ambr(
    value: &[u8],
    ctx: DecodeContext,
    base_offset: usize,
    depth: usize,
) -> Result<Ambr, DecodeError> {
    let mut max_requested_bandwidth_ul = None;
    let mut max_requested_bandwidth_dl = None;
    let mut extended_max_requested_bandwidth_ul = None;
    let mut extended_max_requested_bandwidth_dl = None;
    builder_helpers::for_each_avp(value, ctx, base_offset, depth, |offset, avp| {
        let value_offset = builder_helpers::offset_add(offset, avp.header.header_len(), "7.3.41")?;
        let code = avp.header.code;
        let vendor_id = avp.header.vendor_id;
        reject_zero_vendor_id(&avp, offset, "7.3.41")?;
        if code == AVP_MAX_REQUESTED_BANDWIDTH_UL && vendor_id == Some(VENDOR_ID_3GPP) {
            validate_swm_apn_qos_child_flags(&avp, offset, "5.3.15")?;
            let value = builder_helpers::parse_u32_value(avp.value, value_offset, "5.3.15")?;
            builder_helpers::set_once(&mut max_requested_bandwidth_ul, value, offset, "7.3.41")?;
        } else if code == AVP_MAX_REQUESTED_BANDWIDTH_DL && vendor_id == Some(VENDOR_ID_3GPP) {
            validate_swm_apn_qos_child_flags(&avp, offset, "5.3.14")?;
            let value = builder_helpers::parse_u32_value(avp.value, value_offset, "5.3.14")?;
            builder_helpers::set_once(&mut max_requested_bandwidth_dl, value, offset, "7.3.41")?;
        } else if code == AVP_EXTENDED_MAX_REQUESTED_BANDWIDTH_UL
            && vendor_id == Some(VENDOR_ID_3GPP)
        {
            validate_swm_apn_qos_child_flags(&avp, offset, "5.3.53")?;
            let value = builder_helpers::parse_u32_value(avp.value, value_offset, "5.3.53")?;
            builder_helpers::set_once(
                &mut extended_max_requested_bandwidth_ul,
                value,
                offset,
                "7.3.41",
            )?;
        } else if code == AVP_EXTENDED_MAX_REQUESTED_BANDWIDTH_DL
            && vendor_id == Some(VENDOR_ID_3GPP)
        {
            validate_swm_apn_qos_child_flags(&avp, offset, "5.3.52")?;
            let value = builder_helpers::parse_u32_value(avp.value, value_offset, "5.3.52")?;
            builder_helpers::set_once(
                &mut extended_max_requested_bandwidth_dl,
                value,
                offset,
                "7.3.41",
            )?;
        } else {
            builder_helpers::handle_unknown_avp(ctx, &avp, offset, "7.3.41")?;
        }
        Ok(())
    })?;
    let max_requested_bandwidth_ul = max_requested_bandwidth_ul.ok_or_else(|| {
        missing_child_error(base_offset, "missing Max-Requested-Bandwidth-UL child AVP")
    })?;
    let max_requested_bandwidth_dl = max_requested_bandwidth_dl.ok_or_else(|| {
        missing_child_error(base_offset, "missing Max-Requested-Bandwidth-DL child AVP")
    })?;
    Ok(Ambr {
        max_requested_bandwidth_ul: SwmBandwidth::from_wire(
            max_requested_bandwidth_ul,
            extended_max_requested_bandwidth_ul,
        )
        .map_err(|error| qos_value_decode_error(error, base_offset, "7.3.41"))?,
        max_requested_bandwidth_dl: SwmBandwidth::from_wire(
            max_requested_bandwidth_dl,
            extended_max_requested_bandwidth_dl,
        )
        .map_err(|error| qos_value_decode_error(error, base_offset, "7.3.41"))?,
    })
}

fn validate_swm_apn_qos_child_flags(
    avp: &RawAvp<'_>,
    offset: usize,
    section: &'static str,
) -> Result<(), DecodeError> {
    if avp.header.vendor_id != Some(VENDOR_ID_3GPP) || avp.header.flags.is_protected() {
        return Err(
            DecodeError::new(
                DecodeErrorCode::Structural {
                    reason:
                        "SWm APN QoS child must set 3GPP V and clear P; received M is application-agnostic",
                },
                offset,
            )
            .with_spec_ref(SpecRef::new("3gpp", "TS29272", section)),
        );
    }
    Ok(())
}

fn reject_zero_vendor_id(
    avp: &RawAvp<'_>,
    offset: usize,
    section: &'static str,
) -> Result<(), DecodeError> {
    if avp.header.vendor_id.is_some_and(|vendor| vendor.get() == 0) {
        return Err(DecodeError::new(
            DecodeErrorCode::Structural {
                reason: "Diameter AVP Vendor-Id field must not contain zero",
            },
            offset,
        )
        .with_spec_ref(SpecRef::new("ietf", "RFC6733", section)));
    }
    Ok(())
}

fn qos_value_decode_error(
    error: SwmQosValueError,
    offset: usize,
    section: &'static str,
) -> DecodeError {
    DecodeError::new(
        DecodeErrorCode::Structural {
            reason: error.as_str(),
        },
        offset,
    )
    .with_spec_ref(SpecRef::new("3gpp", "TS29272", section))
}

fn missing_child_error(base_offset: usize, reason: &'static str) -> DecodeError {
    DecodeError::new(DecodeErrorCode::Structural { reason }, base_offset)
        .with_spec_ref(SpecRef::new("ietf", "RFC6733", "grouped"))
}

fn encode_structural_error(reason: &'static str, section: &'static str) -> EncodeError {
    EncodeError::new(EncodeErrorCode::Structural { reason })
        .with_spec_ref(SpecRef::new("3gpp", "TS29273", section))
}

fn valid_service_selection(value: &str) -> bool {
    apn::valid_requested_apn(value)
}

fn validate_request_mobility_features(
    features: Option<SwmMip6FeatureVector>,
) -> Result<(), &'static str> {
    if features.is_some_and(|features| !features.valid_request()) {
        return Err("SWm DER MIP6-Feature-Vector contains an answer-only selection bit");
    }
    Ok(())
}

fn validate_answer_mobility_features(
    features: Option<SwmMip6FeatureVector>,
) -> Result<(), &'static str> {
    if features.is_some_and(|features| !features.valid_answer()) {
        return Err(
            "SWm DEA MIP6-Feature-Vector combines ASSIGN_LOCAL_IP with network-based mobility",
        );
    }
    Ok(())
}

fn validate_requested_supported_features(
    entries: &[SwmRequestedSupportedFeatures],
) -> Result<(), &'static str> {
    if entries.len() > MAX_SWM_SUPPORTED_FEATURES {
        return Err("SWm DER contains too many Supported-Features AVPs");
    }
    let mut identities = HashSet::with_capacity(entries.len());
    for entry in entries {
        if entry.requirement() == SwmSupportedFeaturesRequirement::Discovery
            && entry.features().feature_list() != 0
        {
            return Err("M-clear Supported-Features request must carry a zero Feature-List");
        }
        if !identities.insert(entry.features().identity()) {
            return Err("SWm DER contains duplicate Supported-Features identities");
        }
    }
    Ok(())
}

fn validate_answer_supported_features(
    entries: &[SwmSupportedFeatureList],
) -> Result<(), &'static str> {
    if entries.len() > MAX_SWM_SUPPORTED_FEATURES {
        return Err("SWm DEA contains too many Supported-Features AVPs");
    }
    let mut identities = HashSet::with_capacity(entries.len());
    if entries
        .iter()
        .any(|entry| !identities.insert(entry.identity()))
    {
        return Err("SWm DEA contains duplicate Supported-Features identities");
    }
    Ok(())
}

fn mobility_answer_matches_offer(
    offered: Option<SwmMip6FeatureVector>,
    authorized: Option<SwmMip6FeatureVector>,
    exact_success: bool,
) -> bool {
    if !exact_success {
        return authorized.is_none();
    }
    match (offered, authorized) {
        (None, None) => true,
        (Some(_), None) => false,
        (None, Some(_)) => false,
        (Some(offered), Some(authorized)) => {
            let offered_nbm = offered.bits() & SwmMip6FeatureVector::NETWORK_BASED_MOBILITY_BITS;
            let authorized_nbm =
                authorized.bits() & SwmMip6FeatureVector::NETWORK_BASED_MOBILITY_BITS;
            let authorized_other = authorized.bits()
                & !(SwmMip6FeatureVector::NETWORK_BASED_MOBILITY_BITS
                    | SwmMip6FeatureVector::ANSWER_ONLY_BITS);
            let offered_other = offered.bits() & !SwmMip6FeatureVector::NETWORK_BASED_MOBILITY_BITS;
            (authorized_nbm == 0 || offered_nbm != 0)
                && authorized_other & !offered_other == 0
                && authorized.valid_answer()
        }
    }
}

fn subscriber_authorization_matches_request(
    request: &SwmDiameterEapRequestEnvelope,
    answer: &SwmDiameterEapAnswer,
) -> bool {
    let network_based_mobility_authorized = match answer.mip6_feature_vector {
        Some(features) => features.bits() & SwmMip6FeatureVector::NETWORK_BASED_MOBILITY_BITS != 0,
        None => matches!(
            request.locally_configured_mobility_mode(),
            Some(SwmLocallyConfiguredMobilityMode::NetworkBased)
        ),
    };
    dea_authorization::validate_for_request(
        &answer.subscriber_authorization,
        answer.result.is_diameter_success(),
        request.request().requests_emergency_services(),
        network_based_mobility_authorized,
    )
    .is_ok()
}

fn effective_mobility_mode_source(
    request: &SwmDiameterEapRequestEnvelope,
    answer: &SwmDiameterEapAnswer,
    effective_mode: Option<SwmLocallyConfiguredMobilityMode>,
) -> Option<SwmConditionalValueSource> {
    match answer.mip6_feature_vector {
        Some(_) if effective_mode.is_some() => Some(SwmConditionalValueSource::AaaDerived),
        Some(_) => None,
        None if request.locally_configured_mobility_mode().is_some() => {
            Some(SwmConditionalValueSource::LocallyConfigured)
        }
        None => None,
    }
}

fn effective_mobility_mode(
    request: &SwmDiameterEapRequestEnvelope,
    answer: &SwmDiameterEapAnswer,
) -> Option<SwmLocallyConfiguredMobilityMode> {
    match answer.mip6_feature_vector {
        Some(features)
            if features.bits() & SwmMip6FeatureVector::NETWORK_BASED_MOBILITY_BITS != 0 =>
        {
            Some(SwmLocallyConfiguredMobilityMode::NetworkBased)
        }
        Some(features) if features.contains(SwmMip6FeatureVector::ASSIGN_LOCAL_IP) => {
            Some(SwmLocallyConfiguredMobilityMode::LocalIpAddressAssignment)
        }
        Some(_) => None,
        None => request.locally_configured_mobility_mode(),
    }
}

fn validate_decoded_request(request: &SwmDiameterEapRequest) -> Result<(), DecodeError> {
    if request.session_id.as_ref().is_empty() {
        return Err(decode_structural_error(
            "SWm DER Session-Id must not be empty",
            "DER",
        ));
    }
    if request.origin_host.as_ref().is_empty() {
        return Err(decode_structural_error(
            "SWm DER Origin-Host must not be empty",
            "DER",
        ));
    }
    if request.origin_realm.as_ref().is_empty() {
        return Err(decode_structural_error(
            "SWm DER Origin-Realm must not be empty",
            "DER",
        ));
    }
    if request.destination_realm.as_ref().is_empty() {
        return Err(decode_structural_error(
            "SWm DER Destination-Realm must not be empty",
            "DER",
        ));
    }
    if let Some(destination_host) = request.destination_host.as_ref() {
        if destination_host.as_ref().is_empty() {
            return Err(decode_structural_error(
                "SWm DER Destination-Host must not be empty when present",
                "DER",
            ));
        }
    }
    if let Some(user_name) = request.user_name.as_ref() {
        if user_name.as_ref().is_empty() {
            return Err(decode_structural_error(
                "SWm DER User-Name must not be empty when present",
                "DER",
            ));
        }
    }
    if request
        .rat_type
        .is_some_and(|rat_type| !rat_type.is_canonical())
    {
        return Err(decode_structural_error(
            "SWm DER RAT-Type must use its canonical typed variant",
            "7.1.2.1.1",
        ));
    }
    if let Some(service_selection) = request.service_selection.as_ref() {
        if !valid_service_selection(service_selection.as_ref()) {
            return Err(decode_structural_error(
                "SWm DER Service-Selection must be a valid APN when present",
                "7.1.2.1.1",
            ));
        }
        if request
            .emergency_services
            .is_some_and(SwmEmergencyServices::is_emergency_indicated)
        {
            return Err(decode_structural_error(
                "SWm DER Service-Selection must be absent for an emergency session",
                "7.1.2.1.1",
            ));
        }
    }
    if !request.auth_request_type.is_authorize_authenticate() {
        return Err(decode_structural_error(
            "SWm DER Auth-Request-Type must be AUTHORIZE_AUTHENTICATE",
            "DER",
        ));
    }
    if request.eap_payload.as_ref().is_empty() {
        return Err(decode_structural_error(
            "SWm DER EAP-Payload must not be empty",
            "DER",
        ));
    }
    if request.state_avps.iter().any(Vec::is_empty) {
        return Err(decode_structural_error(
            "SWm DER State AVPs must not be empty",
            "DER",
        ));
    }
    validate_request_mobility_features(request.mip6_feature_vector)
        .map_err(|reason| decode_structural_error(reason, "7.2.3.1"))?;
    if let Some(qos_capability) = request.qos_capability.as_ref() {
        validate_qos_profiles(qos_capability.profiles()).map_err(|error| {
            let reason = match error.code() {
                SwmDerAccessContextErrorCode::EmptyQosCapability => {
                    "SWm DER QoS-Capability requires at least one profile template"
                }
                SwmDerAccessContextErrorCode::TooManyQosProfiles => {
                    "SWm DER QoS-Capability contains too many profile templates"
                }
                SwmDerAccessContextErrorCode::InactiveIndication => {
                    "SWm DER QoS-Capability is invalid"
                }
                SwmDerAccessContextErrorCode::PrepopulatedField
                | SwmDerAccessContextErrorCode::InvalidProvenance
                | SwmDerAccessContextErrorCode::InvalidVisitedNetworkIdentifier
                | SwmDerAccessContextErrorCode::EmptySupportedFeatures
                | SwmDerAccessContextErrorCode::ContradictoryValues
                | SwmDerAccessContextErrorCode::NonCanonicalValue => {
                    "SWm DER QoS-Capability is invalid"
                }
            };
            decode_structural_error(reason, "6")
        })?;
    }
    validate_requested_supported_features(&request.supported_features)
        .map_err(|reason| decode_structural_error(reason, "6.3.29"))?;
    if request
        .high_priority_access_info
        .is_some_and(|info| !info.is_configured())
    {
        return Err(decode_structural_error(
            "SWm DER High-Priority-Access-Info must set HPA_Configured when present",
            "5.2.3.36",
        ));
    }
    if let Some(terminal) = request.terminal_information.as_ref() {
        if let Some(software_version) = terminal.software_version.as_ref() {
            let value = software_version.as_ref().as_bytes();
            if value.len() != 2 || !value.iter().all(u8::is_ascii_digit) {
                return Err(decode_structural_error(
                    "SWm DER Software-Version must contain exactly two decimal digits",
                    "7.3.5",
                ));
            }
        }
    }
    Ok(())
}

fn validate_decoded_answer(answer: &SwmDiameterEapAnswer) -> Result<(), DecodeError> {
    if answer.session_id.as_ref().is_empty() {
        return Err(decode_structural_error(
            "SWm DEA Session-Id must not be empty",
            "DEA",
        ));
    }
    if answer.origin_host.as_ref().is_empty() {
        return Err(decode_structural_error(
            "SWm DEA Origin-Host must not be empty",
            "DEA",
        ));
    }
    if answer.origin_realm.as_ref().is_empty() {
        return Err(decode_structural_error(
            "SWm DEA Origin-Realm must not be empty",
            "DEA",
        ));
    }
    if let Some(user_name) = answer.user_name.as_ref() {
        if user_name.as_ref().is_empty() {
            return Err(decode_structural_error(
                "SWm DEA User-Name must not be empty when present",
                "DEA",
            ));
        }
    }
    if let Some(service_selection) = answer.service_selection.as_ref() {
        if !valid_service_selection(service_selection.as_ref()) {
            return Err(decode_structural_error(
                "SWm DEA Service-Selection must be a valid APN when present",
                "DEA",
            ));
        }
    }
    validate_apn_profile(answer).map_err(|reason| decode_structural_error(reason, "DEA"))?;
    dea_authorization::validate_result_conditions(
        &answer.subscriber_authorization,
        answer.result.is_diameter_success(),
    )
    .map_err(|reason| decode_structural_error(reason, "7.1.2.1.2"))?;
    if !answer.auth_request_type.is_authorize_authenticate() {
        return Err(decode_structural_error(
            "SWm DEA Auth-Request-Type must be AUTHORIZE_AUTHENTICATE",
            "DEA",
        ));
    }
    if option_redacted_bytes_is_empty(&answer.eap_payload) {
        return Err(decode_structural_error(
            "SWm DEA EAP-Payload must not be empty when present",
            "DEA",
        ));
    }
    if option_redacted_bytes_is_empty(&answer.eap_reissued_payload) {
        return Err(decode_structural_error(
            "SWm DEA EAP-Reissued-Payload must not be empty when present",
            "DEA",
        ));
    }
    if option_redacted_bytes_is_empty(&answer.eap_master_session_key) {
        return Err(decode_structural_error(
            "SWm DEA EAP-Master-Session-Key must not be empty when present",
            "DEA",
        ));
    }
    if let Some(mobile_node_identifier) = answer.mobile_node_identifier.as_ref() {
        if mobile_node_identifier.as_ref().is_empty() {
            return Err(decode_structural_error(
                "SWm DEA Mobile-Node-Identifier must not be empty when present",
                "DEA",
            ));
        }
    }
    if answer.state_avps.iter().any(Vec::is_empty) {
        return Err(decode_structural_error(
            "SWm DEA State AVPs must not be empty",
            "DEA",
        ));
    }
    validate_answer_mobility_features(answer.mip6_feature_vector)
        .map_err(|reason| decode_structural_error(reason, "7.2.3.1"))?;
    if !answer.result.is_diameter_success() && answer.mip6_feature_vector.is_some() {
        return Err(decode_structural_error(
            "non-success SWm DEA must not carry MIP6-Feature-Vector",
            "7.1.2.1.2",
        ));
    }
    if !answer.result.is_diameter_success() && !answer.gateway_context().is_empty() {
        return Err(decode_structural_error(
            "non-success SWm DEA must not carry serving or emergency gateway context",
            "7.1.2.1.2",
        ));
    }
    validate_answer_supported_features(&answer.supported_features)
        .map_err(|reason| decode_structural_error(reason, "6.3.29"))?;
    if let Some(access_network_info) = answer.extensions.access_network_info.as_ref() {
        access_network_info
            .validate_received()
            .map_err(|error| location::location_decode_error(error, crate::DIAMETER_HEADER_LEN))?;
    }
    match (
        answer.extensions.access_network_info.is_some(),
        answer.extensions.user_location_info_time.is_some(),
        answer.extensions.user_location_info_time_omission,
    ) {
        (false, false, None) | (true, true, None) => {}
        (true, false, Some(omission)) if omission.was_absent_on_receive() => {}
        (false, true, _) => {
            return Err(decode_structural_error(
                "SWm DEA User-Location-Info-Time requires Access-Network-Info",
                "7.2.2.1.2",
            ));
        }
        _ => {
            return Err(decode_structural_error(
                "decoded SWm DEA location-time provenance is inconsistent",
                "7.2.2.1.2",
            ));
        }
    }
    validate_dea_timers(answer).map_err(|reason| decode_structural_error(reason, "7.2.2.1.2"))?;
    if answer.result_category() == SwmResultCategory::Success && !answer.carries_eap_material() {
        return Err(decode_structural_error(
            "SWm DEA success must carry EAP or MSK material",
            "DEA",
        ));
    }
    Ok(())
}

fn ensure_emergency_request(
    request: &SwmDiameterEapRequest,
) -> Result<(), SwmEmergencyAuthorizationError> {
    request
        .validate_for_encode()
        .map_err(|_| SwmEmergencyAuthorizationError::InitialRequestInvalid)?;
    if !request.requests_emergency_services() {
        return Err(SwmEmergencyAuthorizationError::InitialRequestNotEmergency);
    }
    Ok(())
}

fn ensure_same_session(
    request: &SwmDiameterEapRequest,
    answer: &SwmDiameterEapAnswer,
) -> Result<(), SwmEmergencyAuthorizationError> {
    if request.session_id.as_ref() == answer.session_id.as_ref() {
        Ok(())
    } else {
        Err(SwmEmergencyAuthorizationError::SessionMismatch)
    }
}

fn ensure_correlated_answer(
    request_envelope: &SwmDiameterEapRequestEnvelope,
    answer_envelope: &SwmDiameterEapAnswerEnvelope,
) -> Result<(), SwmEmergencyAuthorizationError> {
    if request_envelope.transaction() != answer_envelope.transaction() {
        return Err(SwmEmergencyAuthorizationError::DiameterTransactionMismatch);
    }
    if request_envelope.proxiable != answer_envelope.proxiable
        || !lifecycle::additional_avp_sequences_match(
            &request_envelope.proxy_infos,
            &answer_envelope.proxy_infos,
        )
    {
        return Err(SwmEmergencyAuthorizationError::AnswerRequestMismatch);
    }
    let request = request_envelope.request();
    let answer = answer_envelope.answer();
    ensure_same_session(request, answer)?;
    if request.auth_application_id != answer.auth_application_id
        || request.auth_request_type != answer.auth_request_type
        || !mobility_answer_matches_offer(
            request.mip6_feature_vector,
            answer.mip6_feature_vector,
            answer.result.is_diameter_success(),
        )
        || !subscriber_authorization_matches_request(request_envelope, answer)
        || lifecycle::validate_diameter_eap_answer_overload_control_for_request(
            request.oc_supported_features.as_ref(),
            answer.oc_supported_features.as_ref(),
            answer.oc_olr.as_ref(),
        )
        .is_err()
        || apn::validate_for_request(request_envelope, answer).is_err()
    {
        return Err(SwmEmergencyAuthorizationError::AnswerRequestMismatch);
    }
    match answer_envelope.provenance {
        SwmDiameterEapAnswerEnvelopeProvenance::Parsed => answer.validate_for_correlation(),
        SwmDiameterEapAnswerEnvelopeProvenance::Outbound => answer.validate_for_encode(),
    }
    .map_err(|_| SwmEmergencyAuthorizationError::AnswerInvalid)?;
    Ok(())
}

fn ensure_correlated_response(
    request_envelope: &SwmDiameterEapRequestEnvelope,
    response_envelope: &SwmDiameterEapResponseEnvelope,
) -> Result<(), SwmDiameterEapCorrelationError> {
    let expected_peer = request_envelope
        .expected_answer_peer
        .as_ref()
        .ok_or(SwmDiameterEapCorrelationError::PeerBindingMissing)?;
    if expected_peer.connection() != response_envelope.received_on {
        return Err(SwmDiameterEapCorrelationError::PeerConnectionMismatch);
    }
    if request_envelope.transaction != response_envelope.transaction {
        return Err(SwmDiameterEapCorrelationError::TransactionMismatch);
    }
    if request_envelope.proxiable != response_envelope.proxiable {
        return Err(SwmDiameterEapCorrelationError::ProxiableMismatch);
    }
    if !lifecycle::additional_avp_sequences_match(
        &request_envelope.proxy_infos,
        &response_envelope.proxy_infos,
    ) {
        return Err(SwmDiameterEapCorrelationError::ProxyInfoMismatch);
    }
    if response_envelope
        .response
        .session_id()
        .is_some_and(|session_id| session_id != request_envelope.request.session_id.as_ref())
    {
        return Err(SwmDiameterEapCorrelationError::SessionMismatch);
    }

    if let SwmDiameterEapResponse::GenericError(answer) = &response_envelope.response {
        if let Some(failure) =
            SwmDiameterEapAgentDeliveryFailure::from_result_code(answer.result_code)
        {
            if !failure.is_valid_for(request_envelope.request()) {
                return Err(SwmDiameterEapCorrelationError::ApplicationMismatch);
            }
            if answer.session_id.as_deref().map(String::as_str)
                != Some(request_envelope.request.session_id.as_ref())
            {
                return Err(SwmDiameterEapCorrelationError::SessionMismatch);
            }
            match expected_peer.matches_authenticated_agent_origin(
                answer.origin_host.as_ref(),
                answer.origin_realm.as_ref(),
            ) {
                None => return Err(SwmDiameterEapCorrelationError::AgentAuthorityMissing),
                Some(false) => return Err(SwmDiameterEapCorrelationError::AgentIdentityMismatch),
                Some(true) => {}
            }
        }
    }

    if let SwmDiameterEapResponse::Application(answer) = &response_envelope.response {
        if !expected_peer.matches_origin(answer.origin_host.as_ref(), answer.origin_realm.as_ref())
        {
            return Err(SwmDiameterEapCorrelationError::PeerIdentityMismatch);
        }
        let request = &request_envelope.request;
        if request.auth_application_id != answer.auth_application_id
            || request.auth_request_type != answer.auth_request_type
            || !mobility_answer_matches_offer(
                request.mip6_feature_vector,
                answer.mip6_feature_vector,
                answer.result.is_diameter_success(),
            )
            || !subscriber_authorization_matches_request(request_envelope, answer)
            || lifecycle::validate_diameter_eap_answer_overload_control_for_request(
                request.oc_supported_features.as_ref(),
                answer.oc_supported_features.as_ref(),
                answer.oc_olr.as_ref(),
            )
            .is_err()
            || apn::validate_for_request(request_envelope, answer).is_err()
            || answer.validate_for_correlation().is_err()
        {
            return Err(SwmDiameterEapCorrelationError::ApplicationMismatch);
        }
    }
    Ok(())
}

fn ensure_eap_response_identity(
    request: &SwmDiameterEapRequest,
    expected_identity: &[u8],
) -> Result<u8, SwmEmergencyAuthorizationError> {
    let (identifier, identity) = eap_response_identity(request.eap_payload.as_ref())
        .ok_or(SwmEmergencyAuthorizationError::InitialEapIdentityInvalid)?;
    if identity != expected_identity {
        return Err(SwmEmergencyAuthorizationError::InitialEapIdentityMismatch);
    }
    Ok(identifier)
}

fn retry_preserves_initial_request(
    initial_request: &SwmDiameterEapRequest,
    retry_request: &SwmDiameterEapRequest,
) -> bool {
    initial_request.auth_application_id == retry_request.auth_application_id
        && initial_request.origin_host == retry_request.origin_host
        && initial_request.origin_realm == retry_request.origin_realm
        && initial_request.destination_realm == retry_request.destination_realm
        && initial_request.destination_host == retry_request.destination_host
        && initial_request.rat_type == retry_request.rat_type
        && initial_request.service_selection == retry_request.service_selection
        && initial_request.mip6_feature_vector == retry_request.mip6_feature_vector
        && initial_request.qos_capability == retry_request.qos_capability
        && initial_request.visited_network_identifier == retry_request.visited_network_identifier
        && initial_request.aaa_failure_indication == retry_request.aaa_failure_indication
        && initial_request.supported_features == retry_request.supported_features
        && initial_request.ue_local_ip_address == retry_request.ue_local_ip_address
        && initial_request.oc_supported_features == retry_request.oc_supported_features
        && initial_request.auth_request_type == retry_request.auth_request_type
        && initial_request.eap_payload == retry_request.eap_payload
        && initial_request.emergency_services == retry_request.emergency_services
        && initial_request.high_priority_access_info == retry_request.high_priority_access_info
        && initial_request.state_avps == retry_request.state_avps
        && initial_request.extensions == retry_request.extensions
}

fn verify_final_emergency_answer(
    exchange: &SwmCorrelatedDiameterEapExchange,
    imei: &Imei15,
) -> Result<SwmUnauthenticatedEmergencyMsk, SwmEmergencyAuthorizationError> {
    let request = exchange.request();
    let answer = exchange.answer();
    if !answer.result.is_diameter_success() {
        return Err(SwmEmergencyAuthorizationError::FinalResultNotSuccess);
    }
    let success_identifier = answer
        .eap_payload
        .as_ref()
        .and_then(|payload| eap_success_identifier(payload.as_ref()))
        .ok_or(SwmEmergencyAuthorizationError::FinalEapSuccessMissing)?;
    let response_identifier = eap_response_identity(request.eap_payload.as_ref())
        .map(|(identifier, _)| identifier)
        .ok_or(SwmEmergencyAuthorizationError::InitialEapIdentityInvalid)?;
    if success_identifier != response_identifier {
        return Err(SwmEmergencyAuthorizationError::FinalEapIdentifierMismatch);
    }
    if answer.eap_reissued_payload.is_some() {
        return Err(SwmEmergencyAuthorizationError::FinalEapMaterialAmbiguous);
    }
    let returned_msk = answer
        .eap_master_session_key
        .as_ref()
        .map(Redacted::as_ref)
        .filter(|msk| !msk.is_empty())
        .ok_or(SwmEmergencyAuthorizationError::FinalMskMissing)?;
    let derived_msk = derive_unauthenticated_emergency_msk(imei);
    if !bool::from(returned_msk.as_slice().ct_eq(derived_msk.as_bytes())) {
        return Err(SwmEmergencyAuthorizationError::FinalMskMismatch);
    }
    let permanent_identity = answer
        .mobile_node_identifier
        .as_ref()
        .map(Redacted::as_ref)
        .filter(|identity| !identity.is_empty())
        .ok_or(SwmEmergencyAuthorizationError::FinalPermanentIdentityMissing)?;
    if permanent_identity.as_str() != emergency_nai(imei) {
        return Err(SwmEmergencyAuthorizationError::FinalPermanentIdentityMismatch);
    }
    Ok(derived_msk)
}

fn eap_response_identity(payload: &[u8]) -> Option<(u8, &[u8])> {
    if payload.len() < 5
        || payload[0] != 2
        || usize::from(u16::from_be_bytes([payload[2], payload[3]])) != payload.len()
        || payload[4] != 1
    {
        return None;
    }
    Some((payload[1], &payload[5..]))
}

fn eap_success_identifier(payload: &[u8]) -> Option<u8> {
    (payload.len() == 4 && payload[0] == 3 && u16::from_be_bytes([payload[2], payload[3]]) == 4)
        .then_some(payload[1])
}

/// Build the canonical TS 23.003 IMEI Emergency NAI used by TS 33.402.
///
/// The returned string contains the equipment identity and must be handled as
/// sensitive subscriber data. Pass its exact bytes to
/// [`build_eap_response_identity`] and use the same string as the SWm
/// `User-Name`; emergency authorization compares both values byte-for-byte.
#[must_use]
pub fn emergency_nai(imei: &Imei15) -> String {
    format!("imei{}@sos.invalid", imei.as_str())
}

/// Build an exact RFC 3748 EAP-Response/Identity packet.
///
/// `identity` is copied verbatim into the Type-Data field. Callers building a
/// SWm emergency DER must also place those exact bytes in `User-Name` (normally
/// by passing [`emergency_nai`] for the direct IMEI path or the canonical IMSI
/// Emergency NAI for identity recovery). The helper accepts an empty identity,
/// as RFC 3748 permits, but the SWm emergency verifier rejects it because it
/// cannot match a required emergency identity.
///
/// # Errors
///
/// Returns [`SwmEapResponseIdentityBuildError::IdentityTooLong`] before
/// allocation when the identity plus the five-octet fixed prefix cannot fit
/// EAP's two-octet packet-length field.
pub fn build_eap_response_identity(
    identifier: u8,
    identity: &[u8],
) -> Result<Vec<u8>, SwmEapResponseIdentityBuildError> {
    let packet_len = 5_usize
        .checked_add(identity.len())
        .filter(|length| *length <= usize::from(u16::MAX))
        .ok_or(SwmEapResponseIdentityBuildError::IdentityTooLong)?;
    let packet_len =
        u16::try_from(packet_len).map_err(|_| SwmEapResponseIdentityBuildError::IdentityTooLong)?;
    let mut payload = Vec::with_capacity(usize::from(packet_len));
    payload.extend_from_slice(&[2, identifier]);
    payload.extend_from_slice(&packet_len.to_be_bytes());
    payload.push(1);
    payload.extend_from_slice(identity);
    Ok(payload)
}

/// Fail-closed error returned by [`build_eap_response_identity`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwmEapResponseIdentityBuildError {
    /// The identity cannot fit EAP's two-octet packet-length field.
    IdentityTooLong,
}

impl SwmEapResponseIdentityBuildError {
    /// Stable redaction-safe label suitable for metrics and audit events.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::IdentityTooLong => "swm_eap_response_identity_too_long",
        }
    }
}

impl fmt::Display for SwmEapResponseIdentityBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Error for SwmEapResponseIdentityBuildError {}

fn is_imsi_emergency_nai(identity: &str) -> bool {
    let Some((username, realm)) = identity.split_once('@') else {
        return false;
    };
    if realm.contains('@') || username.len() < 6 || username.len() > 16 {
        return false;
    }
    if !matches!(username.as_bytes().first(), Some(b'0') | Some(b'6')) {
        return false;
    }
    let imsi = &username[1..];
    if imsi.len() < 5 || imsi.len() > 15 || !imsi.as_bytes().iter().all(u8::is_ascii_digit) {
        return false;
    }

    let mut labels = realm.split('.');
    let (
        Some(sos),
        Some(nai),
        Some(epc),
        Some(mnc_label),
        Some(mcc_label),
        Some(network),
        Some(org),
    ) = (
        labels.next(),
        labels.next(),
        labels.next(),
        labels.next(),
        labels.next(),
        labels.next(),
        labels.next(),
    )
    else {
        return false;
    };
    if labels.next().is_some()
        || !sos.eq_ignore_ascii_case("sos")
        || !nai.eq_ignore_ascii_case("nai")
        || !epc.eq_ignore_ascii_case("epc")
        || !network.eq_ignore_ascii_case("3gppnetwork")
        || !org.eq_ignore_ascii_case("org")
    {
        return false;
    }
    let Some(mnc_prefix) = mnc_label.get(..3) else {
        return false;
    };
    let Some(mcc_prefix) = mcc_label.get(..3) else {
        return false;
    };
    if !mnc_prefix.eq_ignore_ascii_case("mnc") || !mcc_prefix.eq_ignore_ascii_case("mcc") {
        return false;
    }
    let mnc = &mnc_label[3..];
    let mcc = &mcc_label[3..];
    if mnc.len() != 3
        || mcc.len() != 3
        || !mnc.as_bytes().iter().all(u8::is_ascii_digit)
        || !mcc.as_bytes().iter().all(u8::is_ascii_digit)
        || imsi.get(..3) != Some(mcc)
    {
        return false;
    }

    (imsi.len() > 6 && imsi.get(3..6) == Some(mnc))
        || (imsi.len() > 5 && mnc.starts_with('0') && imsi.get(3..5) == mnc.get(1..))
}

fn validate_apn_profile(answer: &SwmDiameterEapAnswer) -> Result<(), &'static str> {
    apn::validate_profile(answer)
}

fn validate_dea_timers(answer: &SwmDiameterEapAnswer) -> Result<(), &'static str> {
    if answer.session_timeout.is_some() && !answer.result.is_diameter_success() {
        return Err("SWm DEA Session-Timeout requires base DIAMETER_SUCCESS");
    }
    authorization::validate_answer_timer_values(
        answer.authorization_lifetime,
        answer.session_timeout.map(SwmSessionTimeout::seconds),
        answer.re_auth_request_type,
    )
}

fn option_redacted_bytes_is_empty(value: &Option<Redacted<Vec<u8>>>) -> bool {
    value
        .as_ref()
        .map(|bytes| bytes.as_ref().is_empty())
        .unwrap_or(false)
}

fn option_redacted_bytes_has_material(value: &Option<Redacted<Vec<u8>>>) -> bool {
    value
        .as_ref()
        .map(|bytes| !bytes.as_ref().is_empty())
        .unwrap_or(false)
}

fn decode_structural_error(reason: &'static str, section: &'static str) -> DecodeError {
    DecodeError::new(
        DecodeErrorCode::Structural { reason },
        crate::DIAMETER_HEADER_LEN,
    )
    .with_spec_ref(SpecRef::new("3gpp", "TS29273", section))
}

fn decode_structural_error_at(
    reason: &'static str,
    offset: usize,
    section: &'static str,
) -> DecodeError {
    DecodeError::new(DecodeErrorCode::Structural { reason }, offset)
        .with_spec_ref(SpecRef::new("3gpp", "TS29273", section))
}
