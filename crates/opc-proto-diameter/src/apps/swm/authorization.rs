//! Typed SWm authorization-information update boundary.
//!
//! This module owns the TS 29.273 RAR/RAA and AAR/AAA command grammar,
//! request/answer correlation, and the two-step update sequence. Session
//! lookup, authorization policy, routing, retry timers, and application-side
//! mutation remain product responsibilities.

use bytes::BytesMut;
use opc_protocol::{
    DecodeContext, DecodeError, DecodeErrorCode, EncodeContext, EncodeError, EncodeErrorCode,
    SpecRef, UnknownIePolicy,
};
use std::{collections::HashSet, error::Error, fmt, net::IpAddr};

use super::lifecycle::{
    self, SwmAdditionalAvp, SwmDiameterConnectionToken, SwmExpectedAnswerPeer,
    SwmRoutingMessagePriority, ValueValidationPurpose,
};
use super::{
    append_apn_configuration_avp, append_experimental_result_avp, builder_helpers,
    parse_apn_configuration, parse_experimental_result, ApnConfiguration, AuthRequestType,
    Redacted, SwmApnConfigurationView, SwmAuthorizedApnConfiguration, SwmDiameterResult,
    SwmDiameterTransaction, SwmResultCategory, APPLICATION_ID, AVP_AAR_FLAGS,
    AVP_AUTH_REQUEST_TYPE, AVP_DRMP, AVP_HIGH_PRIORITY_ACCESS_INFO, AVP_LOAD, AVP_OC_OLR,
    AVP_OC_SUPPORTED_FEATURES, AVP_UE_LOCAL_IP_ADDRESS,
};
use crate::apps::VENDOR_ID_3GPP;
use crate::base;
use crate::dictionary::{
    AvpCardinality, AvpDefinition, AvpKey, CommandAvpRule, CommandDefinition, CommandKind,
};
use crate::end_to_end::{DiameterEndToEndIdentifierError, DiameterEndToEndRequestIdentity};
use crate::parser_error::DiameterParserError;
use crate::{AvpCode, AvpHeader, CommandCode, Message, OwnedMessage, RawAvp, DIAMETER_HEADER_LEN};

/// Re-Auth command code (RFC 4005 sections 3.3 and 3.4).
pub const COMMAND_RE_AUTH: CommandCode = CommandCode::new(258);
/// AA command code (RFC 4005 sections 3.1 and 3.2).
pub const COMMAND_AA: CommandCode = CommandCode::new(265);

const MAX_ROUTE_RECORDS: usize = 128;
const MAX_PROXY_INFOS: usize = 128;
const MAX_ADDITIONAL_AVPS: usize = 128;
const RESULT_CODE_REDIRECT_INDICATION: u32 = 3006;

static RE_AUTH_REQUEST_AVP_RULES: [CommandAvpRule; 33] = [
    singleton(base::AVP_SESSION_ID),
    singleton(base::AVP_ORIGIN_HOST),
    singleton(base::AVP_ORIGIN_REALM),
    singleton(base::AVP_DESTINATION_REALM),
    singleton(base::AVP_DESTINATION_HOST),
    singleton(base::AVP_AUTH_APPLICATION_ID),
    singleton(base::AVP_RE_AUTH_REQUEST_TYPE),
    singleton(base::AVP_USER_NAME),
    singleton(AVP_DRMP),
    singleton(AVP_OC_SUPPORTED_FEATURES),
    singleton(base::AVP_ORIGIN_STATE_ID),
    singleton(super::AVP_STATE),
    singleton(super::AVP_REPLY_MESSAGE),
    repeatable(base::AVP_CLASS),
    forbidden(base::AVP_SESSION_BINDING),
    forbidden(base::AVP_SESSION_SERVER_FAILOVER),
    repeatable(base::AVP_PROXY_INFO),
    repeatable(base::AVP_ROUTE_RECORD),
    forbidden(base::AVP_RESULT_CODE),
    forbidden(base::AVP_EXPERIMENTAL_RESULT),
    forbidden(base::AVP_ERROR_MESSAGE),
    forbidden(base::AVP_ERROR_REPORTING_HOST),
    forbidden(base::AVP_FAILED_AVP),
    forbidden(base::AVP_REDIRECT_HOST),
    forbidden(base::AVP_REDIRECT_HOST_USAGE),
    forbidden(base::AVP_REDIRECT_MAX_CACHE_TIME),
    forbidden(base::AVP_AUTH_SESSION_STATE),
    forbidden(base::AVP_AUTHORIZATION_LIFETIME),
    forbidden(base::AVP_AUTH_GRACE_PERIOD),
    forbidden(base::AVP_SESSION_TIMEOUT),
    forbidden(base::AVP_TERMINATION_CAUSE),
    forbidden(AVP_OC_OLR),
    forbidden(AVP_LOAD),
];

static RE_AUTH_ANSWER_AVP_RULES: [CommandAvpRule; 32] = [
    singleton(base::AVP_SESSION_ID),
    singleton(base::AVP_RESULT_CODE),
    singleton(base::AVP_ORIGIN_HOST),
    singleton(base::AVP_ORIGIN_REALM),
    singleton(base::AVP_USER_NAME),
    singleton(AVP_DRMP),
    singleton(AVP_OC_SUPPORTED_FEATURES),
    singleton(AVP_OC_OLR),
    singleton(base::AVP_ORIGIN_STATE_ID),
    singleton(base::AVP_ERROR_MESSAGE),
    singleton(base::AVP_ERROR_REPORTING_HOST),
    repeatable(base::AVP_REDIRECT_HOST),
    singleton(base::AVP_REDIRECT_HOST_USAGE),
    singleton(base::AVP_REDIRECT_MAX_CACHE_TIME),
    singleton(super::AVP_STATE),
    repeatable(super::AVP_REPLY_MESSAGE),
    repeatable(AVP_LOAD),
    repeatable(base::AVP_FAILED_AVP),
    repeatable(base::AVP_CLASS),
    forbidden(base::AVP_SESSION_BINDING),
    forbidden(base::AVP_SESSION_SERVER_FAILOVER),
    repeatable(base::AVP_PROXY_INFO),
    forbidden(base::AVP_DESTINATION_REALM),
    forbidden(base::AVP_DESTINATION_HOST),
    forbidden(base::AVP_AUTH_APPLICATION_ID),
    singleton(base::AVP_RE_AUTH_REQUEST_TYPE),
    singleton(base::AVP_AUTHORIZATION_LIFETIME),
    singleton(base::AVP_AUTH_GRACE_PERIOD),
    forbidden(base::AVP_SESSION_TIMEOUT),
    forbidden(base::AVP_ROUTE_RECORD),
    forbidden(base::AVP_AUTH_SESSION_STATE),
    forbidden(base::AVP_TERMINATION_CAUSE),
];

static AA_REQUEST_AVP_RULES: [CommandAvpRule; 37] = [
    singleton(base::AVP_SESSION_ID),
    singleton(base::AVP_AUTH_APPLICATION_ID),
    singleton(base::AVP_ORIGIN_HOST),
    singleton(base::AVP_ORIGIN_REALM),
    singleton(base::AVP_DESTINATION_REALM),
    singleton(base::AVP_DESTINATION_HOST),
    singleton(AVP_AUTH_REQUEST_TYPE),
    singleton(base::AVP_USER_NAME),
    singleton(AVP_DRMP),
    singleton(AVP_OC_SUPPORTED_FEATURES),
    singleton(base::AVP_ORIGIN_STATE_ID),
    singleton(super::AVP_STATE),
    CommandAvpRule::new(
        AvpKey::vendor(AVP_AAR_FLAGS, VENDOR_ID_3GPP),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::vendor(AVP_UE_LOCAL_IP_ADDRESS, VENDOR_ID_3GPP),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::vendor(AVP_HIGH_PRIORITY_ACCESS_INFO, VENDOR_ID_3GPP),
        AvpCardinality::ZeroOrOne,
    ),
    forbidden(base::AVP_CLASS),
    forbidden(base::AVP_SESSION_BINDING),
    forbidden(base::AVP_SESSION_SERVER_FAILOVER),
    repeatable(base::AVP_PROXY_INFO),
    repeatable(base::AVP_ROUTE_RECORD),
    forbidden(base::AVP_RESULT_CODE),
    forbidden(base::AVP_EXPERIMENTAL_RESULT),
    forbidden(base::AVP_ERROR_MESSAGE),
    forbidden(base::AVP_ERROR_REPORTING_HOST),
    forbidden(base::AVP_FAILED_AVP),
    forbidden(base::AVP_REDIRECT_HOST),
    forbidden(base::AVP_REDIRECT_HOST_USAGE),
    forbidden(base::AVP_REDIRECT_MAX_CACHE_TIME),
    forbidden(base::AVP_RE_AUTH_REQUEST_TYPE),
    singleton(base::AVP_AUTHORIZATION_LIFETIME),
    singleton(base::AVP_AUTH_GRACE_PERIOD),
    forbidden(base::AVP_SESSION_TIMEOUT),
    forbidden(base::AVP_AUTH_SESSION_STATE),
    forbidden(base::AVP_TERMINATION_CAUSE),
    forbidden(AVP_OC_OLR),
    forbidden(AVP_LOAD),
    CommandAvpRule::new(
        AvpKey::vendor(super::AVP_APN_CONFIGURATION, VENDOR_ID_3GPP),
        AvpCardinality::Forbidden,
    ),
];

static AA_ANSWER_AVP_RULES: [CommandAvpRule; 38] = [
    singleton(base::AVP_SESSION_ID),
    singleton(base::AVP_AUTH_APPLICATION_ID),
    singleton(AVP_AUTH_REQUEST_TYPE),
    singleton(base::AVP_RESULT_CODE),
    singleton(base::AVP_EXPERIMENTAL_RESULT),
    singleton(base::AVP_ORIGIN_HOST),
    singleton(base::AVP_ORIGIN_REALM),
    singleton(base::AVP_USER_NAME),
    singleton(AVP_DRMP),
    singleton(AVP_OC_SUPPORTED_FEATURES),
    singleton(AVP_OC_OLR),
    singleton(base::AVP_ORIGIN_STATE_ID),
    singleton(base::AVP_ERROR_MESSAGE),
    singleton(base::AVP_ERROR_REPORTING_HOST),
    repeatable(base::AVP_REDIRECT_HOST),
    singleton(base::AVP_REDIRECT_HOST_USAGE),
    singleton(base::AVP_REDIRECT_MAX_CACHE_TIME),
    singleton(super::AVP_STATE),
    repeatable(super::AVP_REPLY_MESSAGE),
    repeatable(AVP_LOAD),
    repeatable(base::AVP_FAILED_AVP),
    CommandAvpRule::new(
        AvpKey::vendor(super::AVP_APN_CONFIGURATION, VENDOR_ID_3GPP),
        AvpCardinality::ZeroOrOne,
    ),
    repeatable(base::AVP_CLASS),
    forbidden(base::AVP_SESSION_BINDING),
    forbidden(base::AVP_SESSION_SERVER_FAILOVER),
    repeatable(base::AVP_PROXY_INFO),
    forbidden(base::AVP_DESTINATION_REALM),
    forbidden(base::AVP_DESTINATION_HOST),
    singleton(base::AVP_RE_AUTH_REQUEST_TYPE),
    singleton(base::AVP_AUTHORIZATION_LIFETIME),
    singleton(base::AVP_AUTH_GRACE_PERIOD),
    singleton(base::AVP_SESSION_TIMEOUT),
    forbidden(base::AVP_AUTH_SESSION_STATE),
    forbidden(base::AVP_ROUTE_RECORD),
    CommandAvpRule::new(
        AvpKey::vendor(AVP_AAR_FLAGS, VENDOR_ID_3GPP),
        AvpCardinality::Forbidden,
    ),
    CommandAvpRule::new(
        AvpKey::vendor(AVP_UE_LOCAL_IP_ADDRESS, VENDOR_ID_3GPP),
        AvpCardinality::Forbidden,
    ),
    CommandAvpRule::new(
        AvpKey::vendor(AVP_HIGH_PRIORITY_ACCESS_INFO, VENDOR_ID_3GPP),
        AvpCardinality::Forbidden,
    ),
    forbidden(base::AVP_TERMINATION_CAUSE),
];

const fn singleton(code: AvpCode) -> CommandAvpRule {
    CommandAvpRule::new(AvpKey::ietf(code), AvpCardinality::ZeroOrOne)
}

const fn repeatable(code: AvpCode) -> CommandAvpRule {
    CommandAvpRule::new(AvpKey::ietf(code), AvpCardinality::ZeroOrMore)
}

const fn forbidden(code: AvpCode) -> CommandAvpRule {
    CommandAvpRule::new(AvpKey::ietf(code), AvpCardinality::Forbidden)
}

/// SWm Re-Auth-Request command definition.
pub const COMMAND_RE_AUTH_REQUEST: CommandDefinition = CommandDefinition::new(
    COMMAND_RE_AUTH,
    "Re-Auth-Request",
    CommandKind::Request,
    APPLICATION_ID,
    true,
    SpecRef::new("3gpp", "TS29273", "7.2.2.4.1"),
)
.with_avp_rules(&RE_AUTH_REQUEST_AVP_RULES);

/// SWm Re-Auth-Answer command definition.
pub const COMMAND_RE_AUTH_ANSWER: CommandDefinition = CommandDefinition::new(
    COMMAND_RE_AUTH,
    "Re-Auth-Answer",
    CommandKind::Answer,
    APPLICATION_ID,
    true,
    SpecRef::new("3gpp", "TS29273", "7.2.2.4.2"),
)
.with_avp_rules(&RE_AUTH_ANSWER_AVP_RULES);

/// SWm AA-Request command definition.
pub const COMMAND_AA_REQUEST: CommandDefinition = CommandDefinition::new(
    COMMAND_AA,
    "AA-Request",
    CommandKind::Request,
    APPLICATION_ID,
    true,
    SpecRef::new("3gpp", "TS29273", "7.2.2.1.3"),
)
.with_avp_rules(&AA_REQUEST_AVP_RULES);

/// SWm AA-Answer command definition.
///
/// TS 29.273 section 7.2.2.1.4 prose requires R=0. The displayed ABNF's REQ
/// token is an editorial error and is deliberately not represented here.
pub const COMMAND_AA_ANSWER: CommandDefinition = CommandDefinition::new(
    COMMAND_AA,
    "AA-Answer",
    CommandKind::Answer,
    APPLICATION_ID,
    true,
    SpecRef::new("3gpp", "TS29273", "7.2.2.1.4"),
)
.with_avp_rules(&AA_ANSWER_AVP_RULES);

/// Re-Auth-Request-Type values defined by RFC 6733 section 8.12.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SwmReAuthRequestType {
    /// AUTHORIZE_ONLY (0).
    AuthorizeOnly,
    /// AUTHORIZE_AUTHENTICATE (1).
    AuthorizeAuthenticate,
}

impl SwmReAuthRequestType {
    /// Parse an assigned RFC 6733 value.
    #[must_use]
    pub const fn from_value(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::AuthorizeOnly),
            1 => Some(Self::AuthorizeAuthenticate),
            _ => None,
        }
    }

    /// Return the RFC 6733 wire value.
    #[must_use]
    pub const fn value(self) -> u32 {
        match self {
            Self::AuthorizeOnly => 0,
            Self::AuthorizeAuthenticate => 1,
        }
    }
}

/// Typed AAR-Flags bitmask.
///
/// Release 19 defines only bit zero. Undefined received bits are discarded and
/// builders never emit them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct SwmAarFlags {
    wlan_location_info_request: bool,
}

impl SwmAarFlags {
    /// Construct a request for the most recent WLAN location information.
    #[must_use]
    pub const fn wlan_location_info_request() -> Self {
        Self {
            wlan_location_info_request: true,
        }
    }

    /// Parse a received bitmask while discarding undefined bits.
    #[must_use]
    pub const fn from_value(value: u32) -> Self {
        Self {
            wlan_location_info_request: value & 1 != 0,
        }
    }

    /// Return the canonical bitmask.
    #[must_use]
    pub const fn value(self) -> u32 {
        if self.wlan_location_info_request {
            1
        } else {
            0
        }
    }

    /// Return whether WLAN location information is requested.
    #[must_use]
    pub const fn requests_wlan_location_info(self) -> bool {
        self.wlan_location_info_request
    }
}

/// Typed High-Priority-Access-Info bitmask.
///
/// Release 19 defines only bit zero. Undefined received bits are discarded and
/// builders never emit them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct SwmHighPriorityAccessInfo {
    configured: bool,
}

impl SwmHighPriorityAccessInfo {
    /// Construct the HPA_Configured indication.
    #[must_use]
    pub const fn configured() -> Self {
        Self { configured: true }
    }

    /// Parse a received bitmask while discarding undefined bits.
    #[must_use]
    pub const fn from_value(value: u32) -> Self {
        Self {
            configured: value & 1 != 0,
        }
    }

    /// Return the canonical bitmask.
    #[must_use]
    pub const fn value(self) -> u32 {
        if self.configured {
            1
        } else {
            0
        }
    }

    /// Return whether high-priority access is configured.
    #[must_use]
    pub const fn is_configured(self) -> bool {
        self.configured
    }
}

/// Result-Code projection for the SWm RAA boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SwmReAuthResult {
    /// DIAMETER_SUCCESS (2001).
    Success,
    /// DIAMETER_UNKNOWN_SESSION_ID (5002).
    UnknownSession,
    /// DIAMETER_UNABLE_TO_COMPLY (5012).
    UnableToComply,
    /// Another received base Diameter result code.
    ///
    /// This receive-side variant preserves generic RFC 6733 E-bit errors and
    /// forward-compatible result codes. The typed RAA builder rejects it
    /// because arbitrary result-specific AVPs are not modeled.
    Other(u32),
}

impl SwmReAuthResult {
    /// Project a received base Result-Code.
    #[must_use]
    pub const fn from_result_code(code: u32) -> Self {
        match code {
            base::RESULT_CODE_DIAMETER_SUCCESS => Self::Success,
            base::RESULT_CODE_DIAMETER_UNKNOWN_SESSION_ID => Self::UnknownSession,
            base::RESULT_CODE_DIAMETER_UNABLE_TO_COMPLY => Self::UnableToComply,
            other => Self::Other(other),
        }
    }

    /// Return the base Result-Code.
    #[must_use]
    pub const fn result_code(self) -> u32 {
        match self {
            Self::Success => base::RESULT_CODE_DIAMETER_SUCCESS,
            Self::UnknownSession => base::RESULT_CODE_DIAMETER_UNKNOWN_SESSION_ID,
            Self::UnableToComply => base::RESULT_CODE_DIAMETER_UNABLE_TO_COMPLY,
            Self::Other(result_code) => result_code,
        }
    }
}

/// AAA-server-originated SWm authorization-information update request.
#[derive(Clone, PartialEq, Eq)]
pub struct SwmReAuthRequest {
    /// Session-Id; diagnostic formatting is redacted.
    pub session_id: Redacted<String>,
    /// Origin-Host; diagnostic formatting is redacted.
    pub origin_host: Redacted<String>,
    /// Origin-Realm; diagnostic formatting is redacted.
    pub origin_realm: Redacted<String>,
    /// Destination-Realm; diagnostic formatting is redacted.
    pub destination_realm: Redacted<String>,
    /// Required Destination-Host; diagnostic formatting is redacted.
    pub destination_host: Redacted<String>,
    /// The request type; SWm authorization updates require AuthorizeOnly.
    pub re_auth_request_type: SwmReAuthRequestType,
    /// Required permanent user identity; diagnostic formatting is redacted.
    pub user_name: Redacted<String>,
    /// Optional RFC 7944 routing priority.
    pub drmp: Option<SwmRoutingMessagePriority>,
    /// Ordered Route-Record identities; diagnostic formatting is redacted.
    pub route_records: Vec<Redacted<String>>,
    /// Ordered, validated extension AVPs.
    pub additional_avps: Vec<SwmAdditionalAvp>,
}

impl SwmReAuthRequest {
    fn has_same_replay_fields(&self, other: &Self) -> bool {
        self.session_id == other.session_id
            && self.origin_host == other.origin_host
            && self.origin_realm == other.origin_realm
            && self.destination_realm == other.destination_realm
            && self.destination_host == other.destination_host
            && self.re_auth_request_type == other.re_auth_request_type
            && self.user_name == other.user_name
            && self.drmp == other.drmp
            && self.route_records == other.route_records
            && lifecycle::additional_avp_sequences_match(
                &self.additional_avps,
                &other.additional_avps,
            )
    }
}

impl fmt::Debug for SwmReAuthRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwmReAuthRequest")
            .field("session_id", &self.session_id)
            .field("origin_host", &self.origin_host)
            .field("origin_realm", &self.origin_realm)
            .field("destination_realm", &self.destination_realm)
            .field("destination_host", &self.destination_host)
            .field("re_auth_request_type", &self.re_auth_request_type)
            .field("user_name", &self.user_name)
            .field("drmp", &self.drmp)
            .field("route_record_count", &self.route_records.len())
            .field("additional_avp_count", &self.additional_avps.len())
            .finish()
    }
}

/// ePDG-originated response to an SWm authorization-information update.
#[derive(Clone, PartialEq, Eq)]
pub struct SwmReAuthAnswer {
    /// Session-Id copied from the request.
    ///
    /// It may be absent only on a received RFC 6733 generic E-bit answer.
    /// Diagnostic formatting is redacted when present.
    pub session_id: Option<Redacted<String>>,
    /// Result-Code projection.
    pub result: SwmReAuthResult,
    /// Optional action to take when the Authorization-Lifetime expires.
    pub re_auth_request_type: Option<SwmReAuthRequestType>,
    /// Optional maximum authorized service lifetime in seconds.
    ///
    /// Zero requests immediate re-authorization; `u32::MAX` or absence means
    /// no re-authorization is expected.
    pub authorization_lifetime: Option<u32>,
    /// Optional grace period, in seconds, after Authorization-Lifetime expiry.
    pub auth_grace_period: Option<u32>,
    /// Origin-Host; diagnostic formatting is redacted.
    pub origin_host: Redacted<String>,
    /// Origin-Realm; diagnostic formatting is redacted.
    pub origin_realm: Redacted<String>,
    /// Permanent user identity copied from the request.
    ///
    /// It may be absent only on a received RFC 6733 generic E-bit answer.
    pub user_name: Option<Redacted<String>>,
    /// Optional RFC 7944 routing priority.
    pub drmp: Option<SwmRoutingMessagePriority>,
    /// Ordered, validated extension AVPs.
    pub additional_avps: Vec<SwmAdditionalAvp>,
}

impl SwmReAuthAnswer {
    /// Construct an answer bound to the exact request Session-Id and User-Name.
    #[must_use]
    pub fn for_request(
        request: &SwmReAuthRequestEnvelope,
        result: SwmReAuthResult,
        origin_host: impl Into<Redacted<String>>,
        origin_realm: impl Into<Redacted<String>>,
    ) -> Self {
        Self {
            session_id: Some(request.request.session_id.clone()),
            result,
            re_auth_request_type: None,
            authorization_lifetime: None,
            auth_grace_period: None,
            origin_host: origin_host.into(),
            origin_realm: origin_realm.into(),
            user_name: Some(request.request.user_name.clone()),
            drmp: None,
            additional_avps: Vec::new(),
        }
    }
}

impl fmt::Debug for SwmReAuthAnswer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwmReAuthAnswer")
            .field("session_id", &self.session_id)
            .field("result", &self.result)
            .field("re_auth_request_type", &self.re_auth_request_type)
            .field(
                "authorization_lifetime_present",
                &self.authorization_lifetime.is_some(),
            )
            .field(
                "auth_grace_period_present",
                &self.auth_grace_period.is_some(),
            )
            .field("origin_host", &self.origin_host)
            .field("origin_realm", &self.origin_realm)
            .field("user_name", &self.user_name)
            .field("drmp", &self.drmp)
            .field("additional_avp_count", &self.additional_avps.len())
            .finish()
    }
}

/// ePDG-originated SWm authorization request.
#[derive(Clone, PartialEq, Eq)]
pub struct SwmAuthorizationRequest {
    /// Session-Id; diagnostic formatting is redacted.
    pub session_id: Redacted<String>,
    /// Origin-Host; diagnostic formatting is redacted.
    pub origin_host: Redacted<String>,
    /// Origin-Realm; diagnostic formatting is redacted.
    pub origin_realm: Redacted<String>,
    /// Destination-Realm; diagnostic formatting is redacted.
    pub destination_realm: Redacted<String>,
    /// Optional Destination-Host; diagnostic formatting is redacted.
    pub destination_host: Option<Redacted<String>>,
    /// Required permanent user identity; diagnostic formatting is redacted.
    pub user_name: Redacted<String>,
    /// Auth-Request-Type; SWm AAR requires AuthorizeOnly.
    pub auth_request_type: AuthRequestType,
    /// Optional client hint for the maximum authorization lifetime in seconds.
    ///
    /// Zero requests immediate re-authorization; `u32::MAX` means no
    /// re-authorization is expected.
    pub authorization_lifetime: Option<u32>,
    /// Optional requested grace period in seconds.
    pub auth_grace_period: Option<u32>,
    /// Optional AAR-Flags bitmask.
    pub aar_flags: Option<SwmAarFlags>,
    /// Optional changed UE local IP address.
    pub ue_local_ip_address: Option<IpAddr>,
    /// Optional high-priority access indication.
    pub high_priority_access_info: Option<SwmHighPriorityAccessInfo>,
    /// Optional RFC 7944 routing priority.
    pub drmp: Option<SwmRoutingMessagePriority>,
    /// Ordered Route-Record identities; diagnostic formatting is redacted.
    pub route_records: Vec<Redacted<String>>,
    /// Ordered, validated extension AVPs.
    pub additional_avps: Vec<SwmAdditionalAvp>,
}

impl fmt::Debug for SwmAuthorizationRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwmAuthorizationRequest")
            .field("session_id", &self.session_id)
            .field("origin_host", &self.origin_host)
            .field("origin_realm", &self.origin_realm)
            .field("destination_realm", &self.destination_realm)
            .field("destination_host", &self.destination_host)
            .field("user_name", &self.user_name)
            .field("auth_request_type", &self.auth_request_type)
            .field(
                "authorization_lifetime_present",
                &self.authorization_lifetime.is_some(),
            )
            .field(
                "auth_grace_period_present",
                &self.auth_grace_period.is_some(),
            )
            .field("aar_flags", &self.aar_flags)
            .field(
                "ue_local_ip_address",
                &self.ue_local_ip_address.map(|_| "<redacted>"),
            )
            .field("high_priority_access_info", &self.high_priority_access_info)
            .field("drmp", &self.drmp)
            .field("route_record_count", &self.route_records.len())
            .field("additional_avp_count", &self.additional_avps.len())
            .finish()
    }
}

/// AAA-server response to one SWm authorization request.
#[derive(Clone, PartialEq, Eq)]
pub struct SwmAuthorizationAnswer {
    /// Session-Id copied from the request.
    ///
    /// It may be absent only on a received RFC 6733 generic E-bit answer.
    /// Diagnostic formatting is redacted when present.
    pub session_id: Option<Redacted<String>>,
    /// Auth-Request-Type; ordinary SWm AAA requires AuthorizeOnly.
    ///
    /// It may be absent only on a received RFC 6733 generic E-bit answer.
    pub auth_request_type: Option<AuthRequestType>,
    /// Exactly one base or experimental result.
    pub result: SwmDiameterResult,
    /// Optional action to take when the Authorization-Lifetime expires.
    pub re_auth_request_type: Option<SwmReAuthRequestType>,
    /// Optional maximum authorized service lifetime in seconds.
    ///
    /// Zero requests immediate re-authorization; `u32::MAX` or absence means
    /// no re-authorization is expected. When the correlated AAR supplied an
    /// authorization-lifetime maximum, every success-class answer must include
    /// a value no greater than that maximum.
    pub authorization_lifetime: Option<u32>,
    /// Optional grace period, in seconds, after Authorization-Lifetime expiry.
    pub auth_grace_period: Option<u32>,
    /// Optional maximum remaining session lifetime in seconds.
    ///
    /// Zero or absence means the session has no time limit.
    pub session_timeout: Option<u32>,
    /// Origin-Host; diagnostic formatting is redacted.
    pub origin_host: Redacted<String>,
    /// Origin-Realm; diagnostic formatting is redacted.
    pub origin_realm: Redacted<String>,
    /// Required permanent user identity; diagnostic formatting is redacted.
    ///
    /// It may be absent only on a received RFC 6733 generic E-bit answer.
    pub user_name: Option<Redacted<String>>,
    /// Optional complete, validated APN subscription projection from the AAA.
    ///
    /// The value retains every modeled and safely preserved APN child. The
    /// raw legacy [`ApnConfiguration`] remains available through
    /// [`SwmAuthorizedApnConfiguration::core`], but cannot be mutated or
    /// detached from its sealed supplemental authorization facts. A plain
    /// parsed answer deliberately cannot inspect the supplement:
    ///
    /// ```compile_fail
    /// use opc_proto_diameter::apps::swm::SwmAuthorizationAnswer;
    ///
    /// fn inspect_uncorrelated(answer: &SwmAuthorizationAnswer) {
    ///     if let Some(configuration) = answer.apn_configuration.as_ref() {
    ///         let _ = configuration.as_view();
    ///     }
    /// }
    /// ```
    ///
    /// Use [`SwmCorrelatedAuthorizationExchange::apn_configuration_view`]
    /// after connection, Origin, and request correlation.
    pub apn_configuration: Option<SwmAuthorizedApnConfiguration>,
    /// Optional RFC 7944 routing priority.
    pub drmp: Option<SwmRoutingMessagePriority>,
    /// Ordered, validated extension AVPs.
    pub additional_avps: Vec<SwmAdditionalAvp>,
}

impl SwmAuthorizationAnswer {
    /// Construct a base-result answer bound to the exact AAR facts.
    #[must_use]
    pub fn for_request(
        request: &SwmAuthorizationRequestEnvelope,
        result: SwmDiameterResult,
        origin_host: impl Into<Redacted<String>>,
        origin_realm: impl Into<Redacted<String>>,
    ) -> Self {
        Self {
            session_id: Some(request.request.session_id.clone()),
            auth_request_type: Some(request.request.auth_request_type),
            result,
            re_auth_request_type: None,
            authorization_lifetime: None,
            auth_grace_period: None,
            session_timeout: None,
            origin_host: origin_host.into(),
            origin_realm: origin_realm.into(),
            user_name: Some(request.request.user_name.clone()),
            apn_configuration: None,
            drmp: None,
            additional_avps: Vec::new(),
        }
    }
}

impl fmt::Debug for SwmAuthorizationAnswer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwmAuthorizationAnswer")
            .field("session_id", &self.session_id)
            .field("auth_request_type", &self.auth_request_type)
            .field("result", &self.result)
            .field("re_auth_request_type", &self.re_auth_request_type)
            .field(
                "authorization_lifetime_present",
                &self.authorization_lifetime.is_some(),
            )
            .field(
                "auth_grace_period_present",
                &self.auth_grace_period.is_some(),
            )
            .field("session_timeout_present", &self.session_timeout.is_some())
            .field("origin_host", &self.origin_host)
            .field("origin_realm", &self.origin_realm)
            .field("user_name", &self.user_name)
            .field(
                "apn_configuration_present",
                &self.apn_configuration.is_some(),
            )
            .field("drmp", &self.drmp)
            .field("additional_avp_count", &self.additional_avps.len())
            .finish()
    }
}

/// Parsed or outbound RAR plus immutable response-correlation facts.
#[derive(Clone, PartialEq, Eq)]
pub struct SwmReAuthRequestEnvelope {
    transaction: SwmDiameterTransaction,
    proxiable: bool,
    potentially_retransmitted: bool,
    expected_answer_peer: Option<SwmExpectedAnswerPeer>,
    request: SwmReAuthRequest,
    proxy_infos: Vec<SwmAdditionalAvp>,
}

impl SwmReAuthRequestEnvelope {
    /// Bind outbound RAR facts to caller-supplied raw identifiers.
    ///
    /// This is an unchecked compatibility path. New originators should use
    /// [`Self::for_originating_request`].
    #[must_use]
    pub fn for_outbound(
        request: SwmReAuthRequest,
        transaction: SwmDiameterTransaction,
        expected_answer_peer: SwmExpectedAnswerPeer,
    ) -> Self {
        Self {
            transaction,
            proxiable: true,
            potentially_retransmitted: false,
            expected_answer_peer: Some(expected_answer_peer),
            request,
            proxy_infos: Vec::new(),
        }
    }

    /// Bind a new RAR's affine identity to its typed Origin-Host.
    ///
    /// This checked originating boundary reads `request.origin_host` itself,
    /// consumes `identity`, and installs the authenticated expected-answer
    /// connection in the same retained envelope.
    ///
    /// # Errors
    ///
    /// Returns a typed, value-free error when the request Origin-Host is
    /// invalid or does not match the authority that allocated `identity`.
    pub fn for_originating_request(
        request: SwmReAuthRequest,
        hop_by_hop_identifier: u32,
        identity: DiameterEndToEndRequestIdentity,
        expected_answer_peer: SwmExpectedAnswerPeer,
    ) -> Result<Self, DiameterEndToEndIdentifierError> {
        let transaction = SwmDiameterTransaction::from_end_to_end_identity(
            hop_by_hop_identifier,
            request.origin_host.as_str(),
            identity,
        )?;
        Ok(Self::for_outbound(
            request,
            transaction,
            expected_answer_peer,
        ))
    }

    /// Replace trusted expected-answer evidence for this retained request.
    ///
    /// The binding must come from authenticated transport and trusted routing
    /// state, never from the uncorrelated answer being checked. Destination
    /// AVPs are routing inputs and are not authentication evidence.
    #[must_use]
    pub fn with_expected_answer_peer(mut self, peer: SwmExpectedAnswerPeer) -> Self {
        self.expected_answer_peer = Some(peer);
        self
    }

    /// Borrow the redaction-safe answer-path binding.
    #[must_use]
    pub const fn expected_answer_peer(&self) -> Option<&SwmExpectedAnswerPeer> {
        self.expected_answer_peer.as_ref()
    }

    /// Borrow the typed RAR facts.
    #[must_use]
    pub const fn request(&self) -> &SwmReAuthRequest {
        &self.request
    }

    /// Return the request transaction identifiers.
    #[must_use]
    pub const fn transaction(&self) -> SwmDiameterTransaction {
        self.transaction
    }

    /// Return whether this RAR carries the RFC 6733 T bit.
    #[must_use]
    pub const fn is_potentially_retransmitted(&self) -> bool {
        self.potentially_retransmitted
    }

    /// Mark a queued, unacknowledged RAR for resend after link failover.
    ///
    /// The initial transmission always clears T. RFC 6733 sections 3 and 5.5.4
    /// permit this one-way transition only when resending pending state after
    /// link failover or equivalent recovery; ordinary timer retries must not
    /// call it. The End-to-End Identifier and AVPs remain unchanged. The
    /// caller must reserve a new Hop-by-Hop Identifier on the replacement
    /// connection and provide its authenticated peer binding atomically.
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

    /// Return the ordered Proxy-Info count.
    #[must_use]
    pub fn proxy_info_count(&self) -> usize {
        self.proxy_infos.len()
    }

    /// Return whether `other` carries the same immutable RAR replay payload.
    ///
    /// RFC 6733 sections 3 and 5.5.4 define duplicate identity and the
    /// hop-local fields that may change during failover. This SDK operation
    /// adds a stricter typed-payload guard for duplicate caches. It includes
    /// the End-to-End Identifier, P bit, every typed request fact, ordered
    /// Route-Record and extension AVPs, and the exact ordered Proxy-Info chain.
    /// It deliberately ignores the Hop-by-Hop Identifier, T bit, and
    /// expected-answer peer binding. Derived AVP length fields are also ignored
    /// because encoding computes them from the retained value.
    ///
    /// The result is only a boolean and exposes no retained AVP value. Active
    /// session ownership, duplicate-cache lifetime, and replay disposition
    /// remain consumer policy.
    #[must_use]
    pub fn same_replay_payload(&self, other: &Self) -> bool {
        self.transaction.end_to_end_identifier() == other.transaction.end_to_end_identifier()
            && self.proxiable == other.proxiable
            && self.request.has_same_replay_fields(&other.request)
            && lifecycle::additional_avp_sequences_match(&self.proxy_infos, &other.proxy_infos)
    }

    /// Consume and correlate a parsed RAA with this exact RAR.
    pub fn correlate_answer(
        self,
        answer: SwmReAuthAnswerEnvelope,
    ) -> Result<SwmCorrelatedReAuthExchange, SwmAuthorizationCorrelationError> {
        correlate_common(
            AuthorizationRequestCorrelationFacts {
                transaction: self.transaction,
                proxiable: self.proxiable,
                session: self.request.session_id.as_ref(),
                user: self.request.user_name.as_ref(),
                expected_answer_peer: self.expected_answer_peer.as_ref(),
                proxy_infos: &self.proxy_infos,
                additional_avps: &self.request.additional_avps,
            },
            AuthorizationAnswerCorrelationFacts {
                transaction: answer.transaction,
                proxiable: answer.proxiable,
                received_on: answer.received_on,
                generic_error: answer.generic_error,
                session: answer.answer.session_id.as_deref().map(String::as_str),
                user: answer.answer.user_name.as_deref().map(String::as_str),
                origin_host: answer.answer.origin_host.as_ref(),
                origin_realm: answer.answer.origin_realm.as_ref(),
                proxy_infos: &answer.proxy_infos,
                additional_avps: &answer.answer.additional_avps,
            },
        )?;
        Ok(SwmCorrelatedReAuthExchange {
            request: self,
            answer,
        })
    }
}

impl fmt::Debug for SwmReAuthRequestEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwmReAuthRequestEnvelope")
            .field("transaction", &self.transaction)
            .field("proxiable", &self.proxiable)
            .field("potentially_retransmitted", &self.potentially_retransmitted)
            .field("expected_answer_peer", &self.expected_answer_peer)
            .field("request", &self.request)
            .field("proxy_info_count", &self.proxy_infos.len())
            .finish()
    }
}

/// Parsed RAA plus immutable request-correlation facts.
#[derive(Clone, PartialEq, Eq)]
pub struct SwmReAuthAnswerEnvelope {
    transaction: SwmDiameterTransaction,
    proxiable: bool,
    received_on: SwmDiameterConnectionToken,
    generic_error: bool,
    answer: SwmReAuthAnswer,
    proxy_infos: Vec<SwmAdditionalAvp>,
}

impl SwmReAuthAnswerEnvelope {
    /// Borrow the typed RAA facts.
    #[must_use]
    pub const fn answer(&self) -> &SwmReAuthAnswer {
        &self.answer
    }

    /// Return the answer transaction identifiers.
    #[must_use]
    pub const fn transaction(&self) -> SwmDiameterTransaction {
        self.transaction
    }

    /// Return the authenticated connection generation that carried this RAA.
    #[must_use]
    pub const fn received_on(&self) -> SwmDiameterConnectionToken {
        self.received_on
    }

    /// Return whether the received RAA used RFC 6733's generic E-bit grammar.
    #[must_use]
    pub const fn uses_generic_error_grammar(&self) -> bool {
        self.generic_error
    }

    /// Return the ordered Proxy-Info count retained for correlation.
    #[must_use]
    pub fn proxy_info_count(&self) -> usize {
        self.proxy_infos.len()
    }
}

impl fmt::Debug for SwmReAuthAnswerEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwmReAuthAnswerEnvelope")
            .field("transaction", &self.transaction)
            .field("proxiable", &self.proxiable)
            .field("received_on", &self.received_on)
            .field("generic_error", &self.generic_error)
            .field("answer", &self.answer)
            .field("proxy_info_count", &self.proxy_infos.len())
            .finish()
    }
}

/// Fully correlated RAR/RAA exchange.
pub struct SwmCorrelatedReAuthExchange {
    request: SwmReAuthRequestEnvelope,
    answer: SwmReAuthAnswerEnvelope,
}

impl SwmCorrelatedReAuthExchange {
    /// Borrow the correlated RAR.
    #[must_use]
    pub const fn request(&self) -> &SwmReAuthRequest {
        self.request.request()
    }

    /// Borrow the correlated RAA.
    #[must_use]
    pub const fn answer(&self) -> &SwmReAuthAnswer {
        self.answer.answer()
    }

    /// Return the explicit RFC 6733 Class replacement from this RAA.
    ///
    /// An ordinary answer containing Class returns `Replace`; an ordinary
    /// answer without Class or a generic E-bit answer returns `Unchanged`.
    pub fn class_avp_update(
        &self,
    ) -> Result<super::SwmClassAvpUpdate, super::SwmSessionStateError> {
        if self.answer.generic_error {
            Ok(super::SwmClassAvpUpdate::Unchanged)
        } else {
            super::SwmClassAvpUpdate::from_additional_avps(&self.answer.answer.additional_avps)
        }
    }

    /// Return the identifiers shared by the exchange.
    #[must_use]
    pub const fn transaction(&self) -> SwmDiameterTransaction {
        self.request.transaction()
    }
}

impl fmt::Debug for SwmCorrelatedReAuthExchange {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwmCorrelatedReAuthExchange")
            .field("transaction", &self.transaction())
            .field("request", &self.request())
            .field("answer", &self.answer())
            .finish()
    }
}

/// Parsed or outbound AAR plus immutable response-correlation facts.
#[derive(Clone, PartialEq, Eq)]
pub struct SwmAuthorizationRequestEnvelope {
    transaction: SwmDiameterTransaction,
    proxiable: bool,
    potentially_retransmitted: bool,
    expected_answer_peer: Option<SwmExpectedAnswerPeer>,
    request: SwmAuthorizationRequest,
    proxy_infos: Vec<SwmAdditionalAvp>,
}

impl SwmAuthorizationRequestEnvelope {
    /// Bind outbound AAR facts to caller-supplied raw identifiers.
    ///
    /// This is an unchecked compatibility path. New originators should use
    /// [`Self::for_originating_request`].
    #[must_use]
    pub fn for_outbound(
        request: SwmAuthorizationRequest,
        transaction: SwmDiameterTransaction,
        expected_answer_peer: SwmExpectedAnswerPeer,
    ) -> Self {
        Self {
            transaction,
            proxiable: true,
            potentially_retransmitted: false,
            expected_answer_peer: Some(expected_answer_peer),
            request,
            proxy_infos: Vec::new(),
        }
    }

    /// Bind a new AAR's affine identity to its typed Origin-Host.
    ///
    /// This checked originating boundary reads `request.origin_host` itself,
    /// consumes `identity`, and installs the authenticated expected-answer
    /// connection in the same retained envelope.
    ///
    /// # Errors
    ///
    /// Returns a typed, value-free error when the request Origin-Host is
    /// invalid or does not match the authority that allocated `identity`.
    pub fn for_originating_request(
        request: SwmAuthorizationRequest,
        hop_by_hop_identifier: u32,
        identity: DiameterEndToEndRequestIdentity,
        expected_answer_peer: SwmExpectedAnswerPeer,
    ) -> Result<Self, DiameterEndToEndIdentifierError> {
        let transaction = SwmDiameterTransaction::from_end_to_end_identity(
            hop_by_hop_identifier,
            request.origin_host.as_str(),
            identity,
        )?;
        Ok(Self::for_outbound(
            request,
            transaction,
            expected_answer_peer,
        ))
    }

    /// Replace trusted expected-answer evidence for this retained request.
    ///
    /// Use [`SwmExpectedAnswerPeer::routed`] for an AAR sent through a DRA,
    /// because its ordinary AAA can carry the final AAA server's Origin rather
    /// than the DRA identity present in request routing AVPs.
    #[must_use]
    pub fn with_expected_answer_peer(mut self, peer: SwmExpectedAnswerPeer) -> Self {
        self.expected_answer_peer = Some(peer);
        self
    }

    /// Borrow the redaction-safe answer-path binding.
    #[must_use]
    pub const fn expected_answer_peer(&self) -> Option<&SwmExpectedAnswerPeer> {
        self.expected_answer_peer.as_ref()
    }

    /// Borrow the typed AAR facts.
    #[must_use]
    pub const fn request(&self) -> &SwmAuthorizationRequest {
        &self.request
    }

    /// Return the request transaction identifiers.
    #[must_use]
    pub const fn transaction(&self) -> SwmDiameterTransaction {
        self.transaction
    }

    /// Return whether this AAR carries the RFC 6733 T bit.
    #[must_use]
    pub const fn is_potentially_retransmitted(&self) -> bool {
        self.potentially_retransmitted
    }

    /// Mark a queued, unacknowledged AAR for resend after link failover.
    ///
    /// The initial transmission always clears T. RFC 6733 sections 3 and 5.5.4
    /// permit this one-way transition only when resending pending state after
    /// link failover or equivalent recovery; ordinary timer retries must not
    /// call it. The End-to-End Identifier and AVPs remain unchanged. The
    /// caller must reserve a new Hop-by-Hop Identifier on the replacement
    /// connection and provide its authenticated peer binding atomically.
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

    /// Return the ordered Proxy-Info count.
    #[must_use]
    pub fn proxy_info_count(&self) -> usize {
        self.proxy_infos.len()
    }

    /// Consume and correlate a parsed AAA with this exact AAR.
    pub fn correlate_answer(
        self,
        answer: SwmAuthorizationAnswerEnvelope,
    ) -> Result<SwmCorrelatedAuthorizationExchange, SwmAuthorizationCorrelationError> {
        correlate_common(
            AuthorizationRequestCorrelationFacts {
                transaction: self.transaction,
                proxiable: self.proxiable,
                session: self.request.session_id.as_ref(),
                user: self.request.user_name.as_ref(),
                expected_answer_peer: self.expected_answer_peer.as_ref(),
                proxy_infos: &self.proxy_infos,
                additional_avps: &self.request.additional_avps,
            },
            AuthorizationAnswerCorrelationFacts {
                transaction: answer.transaction,
                proxiable: answer.proxiable,
                received_on: answer.received_on,
                generic_error: answer.generic_error,
                session: answer.answer.session_id.as_deref().map(String::as_str),
                user: answer.answer.user_name.as_deref().map(String::as_str),
                origin_host: answer.answer.origin_host.as_ref(),
                origin_realm: answer.answer.origin_realm.as_ref(),
                proxy_infos: &answer.proxy_infos,
                additional_avps: &answer.answer.additional_avps,
            },
        )?;
        if answer
            .answer
            .auth_request_type
            .is_some_and(|request_type| request_type != self.request.auth_request_type)
            || (answer.answer.auth_request_type.is_none() && !answer.generic_error)
        {
            return Err(SwmAuthorizationCorrelationError::RequestTypeMismatch);
        }
        if !answer.generic_error
            && answer.answer.result.category() == SwmResultCategory::Success
            && !authorization_lifetime_satisfies_hint(
                self.request.authorization_lifetime,
                answer.answer.authorization_lifetime,
            )
        {
            return Err(SwmAuthorizationCorrelationError::AuthorizationLifetimeMismatch);
        }
        Ok(SwmCorrelatedAuthorizationExchange {
            request: self,
            answer,
        })
    }
}

impl fmt::Debug for SwmAuthorizationRequestEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwmAuthorizationRequestEnvelope")
            .field("transaction", &self.transaction)
            .field("proxiable", &self.proxiable)
            .field("potentially_retransmitted", &self.potentially_retransmitted)
            .field("expected_answer_peer", &self.expected_answer_peer)
            .field("request", &self.request)
            .field("proxy_info_count", &self.proxy_infos.len())
            .finish()
    }
}

/// Parsed AAA plus immutable request-correlation facts.
#[derive(Clone, PartialEq, Eq)]
pub struct SwmAuthorizationAnswerEnvelope {
    transaction: SwmDiameterTransaction,
    proxiable: bool,
    received_on: SwmDiameterConnectionToken,
    generic_error: bool,
    answer: SwmAuthorizationAnswer,
    proxy_infos: Vec<SwmAdditionalAvp>,
}

impl SwmAuthorizationAnswerEnvelope {
    /// Borrow the typed AAA facts.
    #[must_use]
    pub const fn answer(&self) -> &SwmAuthorizationAnswer {
        &self.answer
    }

    /// Return the answer transaction identifiers.
    #[must_use]
    pub const fn transaction(&self) -> SwmDiameterTransaction {
        self.transaction
    }

    /// Return the authenticated connection generation that carried this AAA.
    #[must_use]
    pub const fn received_on(&self) -> SwmDiameterConnectionToken {
        self.received_on
    }

    /// Return whether the received AAA used RFC 6733's generic E-bit grammar.
    #[must_use]
    pub const fn uses_generic_error_grammar(&self) -> bool {
        self.generic_error
    }

    /// Return the ordered Proxy-Info count retained for correlation.
    #[must_use]
    pub fn proxy_info_count(&self) -> usize {
        self.proxy_infos.len()
    }
}

impl fmt::Debug for SwmAuthorizationAnswerEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwmAuthorizationAnswerEnvelope")
            .field("transaction", &self.transaction)
            .field("proxiable", &self.proxiable)
            .field("received_on", &self.received_on)
            .field("generic_error", &self.generic_error)
            .field("answer", &self.answer)
            .field("proxy_info_count", &self.proxy_infos.len())
            .finish()
    }
}

/// Fully correlated AAR/AAA exchange.
pub struct SwmCorrelatedAuthorizationExchange {
    request: SwmAuthorizationRequestEnvelope,
    answer: SwmAuthorizationAnswerEnvelope,
}

impl SwmCorrelatedAuthorizationExchange {
    /// Borrow the correlated AAR.
    #[must_use]
    pub const fn request(&self) -> &SwmAuthorizationRequest {
        self.request.request()
    }

    /// Borrow the correlated AAA.
    #[must_use]
    pub const fn answer(&self) -> &SwmAuthorizationAnswer {
        self.answer.answer()
    }

    /// Return the explicit RFC 6733 Class replacement from this AAA.
    ///
    /// An ordinary answer containing Class returns `Replace`; an ordinary
    /// answer without Class or a generic E-bit answer returns `Unchanged`.
    pub fn class_avp_update(
        &self,
    ) -> Result<super::SwmClassAvpUpdate, super::SwmSessionStateError> {
        if self.answer.generic_error {
            Ok(super::SwmClassAvpUpdate::Unchanged)
        } else {
            super::SwmClassAvpUpdate::from_additional_avps(&self.answer.answer.additional_avps)
        }
    }

    /// Borrow the complete AAA APN authorization only after strict correlation.
    ///
    /// The correlated exchange proves the authenticated connection generation,
    /// expected Origin-Host/Realm, transaction, application, session, request
    /// type, user, proxy chain, and request-specific constraints.
    #[must_use]
    pub fn apn_configuration_view(&self) -> Option<SwmApnConfigurationView<'_>> {
        self.answer()
            .apn_configuration
            .as_ref()
            .map(SwmAuthorizedApnConfiguration::as_view)
    }

    /// Return the identifiers shared by the exchange.
    #[must_use]
    pub const fn transaction(&self) -> SwmDiameterTransaction {
        self.request.transaction()
    }
}

impl fmt::Debug for SwmCorrelatedAuthorizationExchange {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwmCorrelatedAuthorizationExchange")
            .field("transaction", &self.transaction())
            .field("request", &self.request())
            .field("answer", &self.answer())
            .finish()
    }
}

/// Redaction-safe request/answer correlation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SwmAuthorizationCorrelationError {
    /// Hop-by-Hop or End-to-End identifier mismatch.
    TransactionMismatch,
    /// Session-Id mismatch.
    SessionMismatch,
    /// User-Name mismatch.
    UserMismatch,
    /// Auth-Request-Type mismatch.
    RequestTypeMismatch,
    /// A success-class answer omitted or exceeded the request's lifetime ceiling.
    AuthorizationLifetimeMismatch,
    /// The answer did not preserve the request P bit.
    ProxiableMismatch,
    /// The request was not bound to an authenticated answer connection.
    PeerBindingMissing,
    /// The answer arrived on a different authenticated connection generation.
    PeerConnectionMismatch,
    /// An ordinary answer Origin violates the explicit logical-origin policy.
    PeerIdentityMismatch,
    /// The answer did not echo the ordered Proxy-Info chain byte-for-byte.
    ProxyInfoMismatch,
    /// Request/answer overload-control state is inconsistent.
    OverloadControlMismatch,
}

impl SwmAuthorizationCorrelationError {
    /// Stable code for logs and metrics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TransactionMismatch => "swm_authorization_transaction_mismatch",
            Self::SessionMismatch => "swm_authorization_session_mismatch",
            Self::UserMismatch => "swm_authorization_user_mismatch",
            Self::RequestTypeMismatch => "swm_authorization_request_type_mismatch",
            Self::AuthorizationLifetimeMismatch => "swm_authorization_lifetime_mismatch",
            Self::ProxiableMismatch => "swm_authorization_proxiable_mismatch",
            Self::PeerBindingMissing => "swm_authorization_peer_binding_missing",
            Self::PeerConnectionMismatch => "swm_authorization_peer_connection_mismatch",
            Self::PeerIdentityMismatch => "swm_authorization_peer_identity_mismatch",
            Self::ProxyInfoMismatch => "swm_authorization_proxy_info_mismatch",
            Self::OverloadControlMismatch => "swm_authorization_overload_control_mismatch",
        }
    }
}

impl fmt::Display for SwmAuthorizationCorrelationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Error for SwmAuthorizationCorrelationError {}

struct AuthorizationRequestCorrelationFacts<'a> {
    transaction: SwmDiameterTransaction,
    proxiable: bool,
    session: &'a str,
    user: &'a str,
    expected_answer_peer: Option<&'a SwmExpectedAnswerPeer>,
    proxy_infos: &'a [SwmAdditionalAvp],
    additional_avps: &'a [SwmAdditionalAvp],
}

struct AuthorizationAnswerCorrelationFacts<'a> {
    transaction: SwmDiameterTransaction,
    proxiable: bool,
    received_on: SwmDiameterConnectionToken,
    generic_error: bool,
    session: Option<&'a str>,
    user: Option<&'a str>,
    origin_host: &'a str,
    origin_realm: &'a str,
    proxy_infos: &'a [SwmAdditionalAvp],
    additional_avps: &'a [SwmAdditionalAvp],
}

fn correlate_common(
    request: AuthorizationRequestCorrelationFacts<'_>,
    answer: AuthorizationAnswerCorrelationFacts<'_>,
) -> Result<(), SwmAuthorizationCorrelationError> {
    let expected_answer_peer = request
        .expected_answer_peer
        .ok_or(SwmAuthorizationCorrelationError::PeerBindingMissing)?;
    if expected_answer_peer.connection() != answer.received_on {
        return Err(SwmAuthorizationCorrelationError::PeerConnectionMismatch);
    }
    if request.transaction != answer.transaction {
        return Err(SwmAuthorizationCorrelationError::TransactionMismatch);
    }
    if request.proxiable != answer.proxiable {
        return Err(SwmAuthorizationCorrelationError::ProxiableMismatch);
    }
    if let Some(answer_session) = answer.session {
        if request.session != answer_session {
            return Err(SwmAuthorizationCorrelationError::SessionMismatch);
        }
    } else if !answer.generic_error {
        return Err(SwmAuthorizationCorrelationError::SessionMismatch);
    }
    if let Some(answer_user) = answer.user {
        if request.user != answer_user {
            return Err(SwmAuthorizationCorrelationError::UserMismatch);
        }
    } else if !answer.generic_error {
        return Err(SwmAuthorizationCorrelationError::UserMismatch);
    }
    if !answer.generic_error
        && !expected_answer_peer.matches_origin(answer.origin_host, answer.origin_realm)
    {
        return Err(SwmAuthorizationCorrelationError::PeerIdentityMismatch);
    }
    if request.proxy_infos != answer.proxy_infos {
        return Err(SwmAuthorizationCorrelationError::ProxyInfoMismatch);
    }
    lifecycle::validate_offered_overload_control(
        request.additional_avps,
        answer.additional_avps,
        DecodeContext::default(),
    )
    .map_err(|_| SwmAuthorizationCorrelationError::OverloadControlMismatch)
}

/// Accepted first step of a two-step SWm authorization-information update.
///
/// The exact already-built RAA is retained for byte-identical duplicate replay.
/// Debug output never includes its AVPs.
pub struct SwmAcceptedAuthorizationUpdate {
    request: SwmReAuthRequestEnvelope,
    answer: SwmReAuthAnswer,
    committed_answer: OwnedMessage,
}

impl SwmAcceptedAuthorizationUpdate {
    /// Validate and commit a successful RAA for one exact RAR.
    pub fn accept(
        request: SwmReAuthRequestEnvelope,
        answer: SwmReAuthAnswer,
        ctx: EncodeContext,
    ) -> Result<Self, SwmAuthorizationUpdateError> {
        if answer.result != SwmReAuthResult::Success {
            return Err(SwmAuthorizationUpdateError::ReAuthNotAccepted);
        }
        let committed_answer = build_swm_re_auth_answer(&request, &answer, ctx)
            .map_err(SwmAuthorizationUpdateError::Encode)?;
        Ok(Self {
            request,
            answer,
            committed_answer,
        })
    }

    /// Return a clone of the committed RAA for byte-identical replay.
    ///
    /// OwnedMessage contains raw AVP bytes and must not be logged.
    #[must_use]
    pub fn replay_re_auth_answer(&self) -> OwnedMessage {
        self.committed_answer.clone()
    }

    /// Consume the accepted first step and commit the follow-up AAR.
    ///
    /// The supplied AAR must preserve the exact RAR Session-Id and User-Name.
    pub fn begin_authorization(
        self,
        request: SwmAuthorizationRequest,
        transaction: SwmDiameterTransaction,
        expected_answer_peer: SwmExpectedAnswerPeer,
        ctx: EncodeContext,
    ) -> Result<SwmPendingAuthorizationUpdate, SwmAuthorizationUpdateError> {
        if self.request.request.session_id.as_ref() != request.session_id.as_ref() {
            return Err(SwmAuthorizationUpdateError::SessionMismatch);
        }
        if self.request.request.user_name.as_ref() != request.user_name.as_ref() {
            return Err(SwmAuthorizationUpdateError::UserMismatch);
        }
        let request = SwmAuthorizationRequestEnvelope::for_outbound(
            request,
            transaction,
            expected_answer_peer,
        );
        let committed_initial_request = build_swm_authorization_request(&request, ctx)
            .map_err(SwmAuthorizationUpdateError::Encode)?;
        let committed_retransmission = committed_initial_request.clone();
        Ok(SwmPendingAuthorizationUpdate {
            re_auth_transaction: self.request.transaction,
            re_auth_answer: self.answer,
            committed_re_auth_answer: self.committed_answer,
            request,
            committed_initial_request,
            committed_retransmission,
        })
    }
}

impl fmt::Debug for SwmAcceptedAuthorizationUpdate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwmAcceptedAuthorizationUpdate")
            .field("re_auth_transaction", &self.request.transaction)
            .field("re_auth_result", &self.answer.result)
            .field("committed_answer_len", &self.committed_answer.header.length)
            .finish()
    }
}

/// Pending second step of an SWm authorization-information update.
///
/// Exact committed RAA and AAR messages are retained for retransmission.
pub struct SwmPendingAuthorizationUpdate {
    re_auth_transaction: SwmDiameterTransaction,
    re_auth_answer: SwmReAuthAnswer,
    committed_re_auth_answer: OwnedMessage,
    request: SwmAuthorizationRequestEnvelope,
    committed_initial_request: OwnedMessage,
    committed_retransmission: OwnedMessage,
}

impl SwmPendingAuthorizationUpdate {
    /// Return a clone of the committed RAA for duplicate RAR replay.
    ///
    /// OwnedMessage contains raw AVP bytes and must not be logged.
    #[must_use]
    pub fn replay_re_auth_answer(&self) -> OwnedMessage {
        self.committed_re_auth_answer.clone()
    }

    /// Return a clone of the initial committed AAR with T clear.
    ///
    /// OwnedMessage contains raw AVP bytes and must not be logged.
    #[must_use]
    pub fn initial_authorization_request(&self) -> OwnedMessage {
        self.committed_initial_request.clone()
    }

    /// Return the cached AAR bytes for an ordinary timer retransmission.
    ///
    /// This is byte-identical to the initial request, including T clear. After
    /// [`Self::mark_for_failover_retransmission`] succeeds, it instead returns
    /// the stable T-set form permitted for resending queued state after link
    /// failover. OwnedMessage contains raw AVP bytes and must not be logged.
    #[must_use]
    pub fn retransmit_authorization_request(&self) -> OwnedMessage {
        self.committed_retransmission.clone()
    }

    /// Transition the queued AAR to RFC 6733 failover-retransmission form.
    ///
    /// This must be called only after link failover or equivalent recovery,
    /// never for an ordinary timer retry. The update is atomic: an encode
    /// failure preserves the previous cached request and typed state.
    pub fn mark_for_failover_retransmission(
        &mut self,
        replacement_hop_by_hop_identifier: u32,
        new_peer: SwmExpectedAnswerPeer,
        ctx: EncodeContext,
    ) -> Result<(), SwmAuthorizationUpdateError> {
        let mut request = self.request.clone();
        request.mark_for_failover_retransmission(replacement_hop_by_hop_identifier, new_peer);
        let committed = build_swm_authorization_request(&request, ctx)
            .map_err(SwmAuthorizationUpdateError::Encode)?;
        self.request = request;
        self.committed_retransmission = committed;
        Ok(())
    }

    /// Borrow the typed AAR facts.
    #[must_use]
    pub const fn authorization_request(&self) -> &SwmAuthorizationRequest {
        self.request.request()
    }

    /// Consume and correlate the terminal AAA.
    pub fn complete(
        self,
        answer: SwmAuthorizationAnswerEnvelope,
    ) -> Result<SwmCompletedAuthorizationUpdate, SwmAuthorizationCorrelationError> {
        let exchange = self.request.correlate_answer(answer)?;
        Ok(SwmCompletedAuthorizationUpdate {
            re_auth_transaction: self.re_auth_transaction,
            re_auth_answer: self.re_auth_answer,
            authorization: exchange,
        })
    }
}

impl fmt::Debug for SwmPendingAuthorizationUpdate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwmPendingAuthorizationUpdate")
            .field("re_auth_transaction", &self.re_auth_transaction)
            .field("authorization_transaction", &self.request.transaction)
            .field(
                "committed_re_auth_answer_len",
                &self.committed_re_auth_answer.header.length,
            )
            .field(
                "committed_initial_request_len",
                &self.committed_initial_request.header.length,
            )
            .field(
                "committed_retransmission_len",
                &self.committed_retransmission.header.length,
            )
            .finish()
    }
}

/// Completed, correlated RAR/RAA followed by AAR/AAA update sequence.
pub struct SwmCompletedAuthorizationUpdate {
    re_auth_transaction: SwmDiameterTransaction,
    re_auth_answer: SwmReAuthAnswer,
    authorization: SwmCorrelatedAuthorizationExchange,
}

impl SwmCompletedAuthorizationUpdate {
    /// Borrow the committed RAA facts.
    #[must_use]
    pub const fn re_auth_answer(&self) -> &SwmReAuthAnswer {
        &self.re_auth_answer
    }

    /// Borrow the terminal authorization exchange.
    #[must_use]
    pub const fn authorization(&self) -> &SwmCorrelatedAuthorizationExchange {
        &self.authorization
    }
}

impl fmt::Debug for SwmCompletedAuthorizationUpdate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwmCompletedAuthorizationUpdate")
            .field("re_auth_transaction", &self.re_auth_transaction)
            .field("re_auth_result", &self.re_auth_answer.result)
            .field(
                "authorization_transaction",
                &self.authorization.transaction(),
            )
            .field("authorization_result", &self.authorization.answer().result)
            .finish()
    }
}

/// Redaction-safe failure to advance the public update sequence.
#[derive(Debug)]
pub enum SwmAuthorizationUpdateError {
    /// Only a successful RAA can advance to AAR.
    ReAuthNotAccepted,
    /// The AAR changed the RAR Session-Id.
    SessionMismatch,
    /// The AAR changed the RAR User-Name.
    UserMismatch,
    /// The committed message could not be encoded.
    Encode(EncodeError),
}

impl SwmAuthorizationUpdateError {
    /// Stable code for logs and metrics.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::ReAuthNotAccepted => "swm_authorization_update_re_auth_not_accepted",
            Self::SessionMismatch => "swm_authorization_update_session_mismatch",
            Self::UserMismatch => "swm_authorization_update_user_mismatch",
            Self::Encode(_) => "swm_authorization_update_encode_failure",
        }
    }
}

impl fmt::Display for SwmAuthorizationUpdateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Error for SwmAuthorizationUpdateError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Encode(error) => Some(error),
            Self::ReAuthNotAccepted | Self::SessionMismatch | Self::UserMismatch => None,
        }
    }
}

/// Build one outbound SWm RAR.
pub fn build_swm_re_auth_request(
    envelope: &SwmReAuthRequestEnvelope,
    ctx: EncodeContext,
) -> Result<OwnedMessage, EncodeError> {
    validate_re_auth_request_for_encode(&envelope.request, ctx)?;
    let expected_answer_peer = envelope.expected_answer_peer.as_ref().ok_or_else(|| {
        encode_error(
            "outbound SWm RAR requires an authenticated answer-peer binding",
            "6.2.1",
        )
    })?;
    expected_answer_peer.validate_for_encode()?;
    validate_envelope_for_encode(envelope.proxiable, envelope.proxy_infos.len(), "7.2.2.4.1")?;
    let request = &envelope.request;
    let mut avps = BytesMut::new();
    append_string(
        &mut avps,
        base::AVP_SESSION_ID,
        request.session_id.as_ref(),
        ctx,
    )?;
    append_optional_drmp(&mut avps, request.drmp, ctx)?;
    append_string(
        &mut avps,
        base::AVP_ORIGIN_HOST,
        request.origin_host.as_ref(),
        ctx,
    )?;
    append_string(
        &mut avps,
        base::AVP_ORIGIN_REALM,
        request.origin_realm.as_ref(),
        ctx,
    )?;
    append_string(
        &mut avps,
        base::AVP_DESTINATION_REALM,
        request.destination_realm.as_ref(),
        ctx,
    )?;
    append_string(
        &mut avps,
        base::AVP_DESTINATION_HOST,
        request.destination_host.as_ref(),
        ctx,
    )?;
    builder_helpers::append_u32_avp(
        &mut avps,
        base::AVP_AUTH_APPLICATION_ID,
        APPLICATION_ID.get(),
        true,
        ctx,
    )?;
    builder_helpers::append_u32_avp(
        &mut avps,
        base::AVP_RE_AUTH_REQUEST_TYPE,
        request.re_auth_request_type.value(),
        true,
        ctx,
    )?;
    append_string(
        &mut avps,
        base::AVP_USER_NAME,
        request.user_name.as_ref(),
        ctx,
    )?;
    append_routing_and_additional(
        &mut avps,
        &envelope.proxy_infos,
        &request.route_records,
        &request.additional_avps,
        ctx,
    )?;
    build_message(
        authorization_request_flags(envelope.potentially_retransmitted),
        COMMAND_RE_AUTH,
        avps,
        envelope.transaction,
        ctx,
        "7.2.2.4.1",
    )
}

/// Build one RAA bound to the exact RAR identifiers, P bit, Session-Id,
/// User-Name, and ordered Proxy-Info chain.
pub fn build_swm_re_auth_answer(
    request: &SwmReAuthRequestEnvelope,
    answer: &SwmReAuthAnswer,
    ctx: EncodeContext,
) -> Result<OwnedMessage, EncodeError> {
    validate_re_auth_answer_for_encode(request, answer, ctx)?;
    let session_id = answer
        .session_id
        .as_ref()
        .ok_or_else(|| encode_error("originated SWm RAA requires Session-Id", "7.2.2.4.2"))?;
    let user_name = answer
        .user_name
        .as_ref()
        .ok_or_else(|| encode_error("originated SWm RAA requires User-Name", "7.2.2.4.2"))?;
    let mut avps = BytesMut::new();
    append_string(&mut avps, base::AVP_SESSION_ID, session_id.as_ref(), ctx)?;
    append_optional_drmp(&mut avps, answer.drmp, ctx)?;
    builder_helpers::append_u32_avp(
        &mut avps,
        base::AVP_RESULT_CODE,
        answer.result.result_code(),
        true,
        ctx,
    )?;
    if let Some(re_auth_request_type) = answer.re_auth_request_type {
        builder_helpers::append_u32_avp(
            &mut avps,
            base::AVP_RE_AUTH_REQUEST_TYPE,
            re_auth_request_type.value(),
            true,
            ctx,
        )?;
    }
    append_optional_base_u32(
        &mut avps,
        base::AVP_AUTHORIZATION_LIFETIME,
        answer.authorization_lifetime,
        ctx,
    )?;
    append_optional_base_u32(
        &mut avps,
        base::AVP_AUTH_GRACE_PERIOD,
        answer.auth_grace_period,
        ctx,
    )?;
    append_string(
        &mut avps,
        base::AVP_ORIGIN_HOST,
        answer.origin_host.as_ref(),
        ctx,
    )?;
    append_string(
        &mut avps,
        base::AVP_ORIGIN_REALM,
        answer.origin_realm.as_ref(),
        ctx,
    )?;
    append_string(&mut avps, base::AVP_USER_NAME, user_name.as_ref(), ctx)?;
    append_additional(&mut avps, &answer.additional_avps, ctx)?;
    append_additional(&mut avps, &request.proxy_infos, ctx)?;
    build_message(
        builder_helpers::app_answer_flags(builder_helpers::result_code_requires_error_bit(
            answer.result.result_code(),
        )),
        COMMAND_RE_AUTH,
        avps,
        request.transaction,
        ctx,
        "7.2.2.4.2",
    )
}

/// Build one outbound SWm AAR.
pub fn build_swm_authorization_request(
    envelope: &SwmAuthorizationRequestEnvelope,
    ctx: EncodeContext,
) -> Result<OwnedMessage, EncodeError> {
    validate_authorization_request_for_encode(&envelope.request, ctx)?;
    let expected_answer_peer = envelope.expected_answer_peer.as_ref().ok_or_else(|| {
        encode_error(
            "outbound SWm AAR requires an authenticated answer-peer binding",
            "6.2.1",
        )
    })?;
    expected_answer_peer.validate_for_encode()?;
    validate_envelope_for_encode(envelope.proxiable, envelope.proxy_infos.len(), "7.2.2.1.3")?;
    let request = &envelope.request;
    let mut avps = BytesMut::new();
    append_string(
        &mut avps,
        base::AVP_SESSION_ID,
        request.session_id.as_ref(),
        ctx,
    )?;
    append_optional_drmp(&mut avps, request.drmp, ctx)?;
    builder_helpers::append_u32_avp(
        &mut avps,
        base::AVP_AUTH_APPLICATION_ID,
        APPLICATION_ID.get(),
        true,
        ctx,
    )?;
    append_string(
        &mut avps,
        base::AVP_ORIGIN_HOST,
        request.origin_host.as_ref(),
        ctx,
    )?;
    append_string(
        &mut avps,
        base::AVP_ORIGIN_REALM,
        request.origin_realm.as_ref(),
        ctx,
    )?;
    append_string(
        &mut avps,
        base::AVP_DESTINATION_REALM,
        request.destination_realm.as_ref(),
        ctx,
    )?;
    if let Some(destination_host) = request.destination_host.as_ref() {
        append_string(
            &mut avps,
            base::AVP_DESTINATION_HOST,
            destination_host.as_ref(),
            ctx,
        )?;
    }
    builder_helpers::append_u32_avp(
        &mut avps,
        AVP_AUTH_REQUEST_TYPE,
        request.auth_request_type.value(),
        true,
        ctx,
    )?;
    append_string(
        &mut avps,
        base::AVP_USER_NAME,
        request.user_name.as_ref(),
        ctx,
    )?;
    append_optional_base_u32(
        &mut avps,
        base::AVP_AUTHORIZATION_LIFETIME,
        request.authorization_lifetime,
        ctx,
    )?;
    append_optional_base_u32(
        &mut avps,
        base::AVP_AUTH_GRACE_PERIOD,
        request.auth_grace_period,
        ctx,
    )?;
    if let Some(flags) = request.aar_flags {
        builder_helpers::append_vendor_u32_avp(
            &mut avps,
            AVP_AAR_FLAGS,
            VENDOR_ID_3GPP,
            flags.value(),
            false,
            ctx,
        )?;
    }
    if let Some(address) = request.ue_local_ip_address {
        let mut value = BytesMut::new();
        builder_helpers::encode_address_value(&mut value, address);
        builder_helpers::append_avp(
            &mut avps,
            AvpHeader::vendor(AVP_UE_LOCAL_IP_ADDRESS, VENDOR_ID_3GPP, false),
            &value,
            ctx,
        )?;
    }
    if let Some(high_priority) = request.high_priority_access_info {
        builder_helpers::append_vendor_u32_avp(
            &mut avps,
            AVP_HIGH_PRIORITY_ACCESS_INFO,
            VENDOR_ID_3GPP,
            high_priority.value(),
            false,
            ctx,
        )?;
    }
    append_routing_and_additional(
        &mut avps,
        &envelope.proxy_infos,
        &request.route_records,
        &request.additional_avps,
        ctx,
    )?;
    build_message(
        authorization_request_flags(envelope.potentially_retransmitted),
        COMMAND_AA,
        avps,
        envelope.transaction,
        ctx,
        "7.2.2.1.3",
    )
}

/// Build one AAA bound to the exact AAR identifiers, P bit, Session-Id,
/// Auth-Request-Type, User-Name, and ordered Proxy-Info chain.
pub fn build_swm_authorization_answer(
    request: &SwmAuthorizationRequestEnvelope,
    answer: &SwmAuthorizationAnswer,
    ctx: EncodeContext,
) -> Result<OwnedMessage, EncodeError> {
    validate_authorization_answer_for_encode(request, answer, ctx)?;
    let session_id = answer
        .session_id
        .as_ref()
        .ok_or_else(|| encode_error("originated SWm AAA requires Session-Id", "7.2.2.1.4"))?;
    let auth_request_type = answer.auth_request_type.ok_or_else(|| {
        encode_error("originated SWm AAA requires Auth-Request-Type", "7.2.2.1.4")
    })?;
    let user_name = answer
        .user_name
        .as_ref()
        .ok_or_else(|| encode_error("originated SWm AAA requires User-Name", "7.2.2.1.4"))?;
    let mut avps = BytesMut::new();
    append_string(&mut avps, base::AVP_SESSION_ID, session_id.as_ref(), ctx)?;
    append_optional_drmp(&mut avps, answer.drmp, ctx)?;
    builder_helpers::append_u32_avp(
        &mut avps,
        base::AVP_AUTH_APPLICATION_ID,
        APPLICATION_ID.get(),
        true,
        ctx,
    )?;
    builder_helpers::append_u32_avp(
        &mut avps,
        AVP_AUTH_REQUEST_TYPE,
        auth_request_type.value(),
        true,
        ctx,
    )?;
    append_diameter_result(&mut avps, answer.result, ctx)?;
    if let Some(re_auth_request_type) = answer.re_auth_request_type {
        builder_helpers::append_u32_avp(
            &mut avps,
            base::AVP_RE_AUTH_REQUEST_TYPE,
            re_auth_request_type.value(),
            true,
            ctx,
        )?;
    }
    append_optional_base_u32(
        &mut avps,
        base::AVP_AUTHORIZATION_LIFETIME,
        answer.authorization_lifetime,
        ctx,
    )?;
    append_optional_base_u32(
        &mut avps,
        base::AVP_AUTH_GRACE_PERIOD,
        answer.auth_grace_period,
        ctx,
    )?;
    append_optional_base_u32(
        &mut avps,
        base::AVP_SESSION_TIMEOUT,
        answer.session_timeout,
        ctx,
    )?;
    append_string(
        &mut avps,
        base::AVP_ORIGIN_HOST,
        answer.origin_host.as_ref(),
        ctx,
    )?;
    append_string(
        &mut avps,
        base::AVP_ORIGIN_REALM,
        answer.origin_realm.as_ref(),
        ctx,
    )?;
    append_string(&mut avps, base::AVP_USER_NAME, user_name.as_ref(), ctx)?;
    if let Some(apn) = answer.apn_configuration.as_ref() {
        append_apn_configuration_avp(&mut avps, apn.core(), Some(apn.supplement()), ctx)?;
    }
    append_additional(&mut avps, &answer.additional_avps, ctx)?;
    append_additional(&mut avps, &request.proxy_infos, ctx)?;
    build_message(
        builder_helpers::app_answer_flags(builder_helpers::result_code_requires_error_bit(
            answer.result.code(),
        )),
        COMMAND_AA,
        avps,
        request.transaction,
        ctx,
        "7.2.2.1.4",
    )
}

fn append_diameter_result(
    dst: &mut BytesMut,
    result: SwmDiameterResult,
    ctx: EncodeContext,
) -> Result<(), EncodeError> {
    match result {
        SwmDiameterResult::Base(code) => {
            builder_helpers::append_u32_avp(dst, base::AVP_RESULT_CODE, code, true, ctx)
        }
        SwmDiameterResult::Experimental { vendor_id, code } => {
            append_experimental_result_avp(dst, vendor_id, code, ctx)
        }
    }
}

fn append_optional_base_u32(
    dst: &mut BytesMut,
    code: AvpCode,
    value: Option<u32>,
    ctx: EncodeContext,
) -> Result<(), EncodeError> {
    match value {
        Some(value) => builder_helpers::append_u32_avp(dst, code, value, true, ctx),
        None => Ok(()),
    }
}

const fn authorization_request_flags(potentially_retransmitted: bool) -> crate::CommandFlags {
    let mut bits = builder_helpers::app_request_flags().bits();
    if potentially_retransmitted {
        bits |= crate::CommandFlags::POTENTIALLY_RETRANSMITTED;
    }
    crate::CommandFlags::from_bits(bits)
}

fn append_string(
    dst: &mut BytesMut,
    code: AvpCode,
    value: &str,
    ctx: EncodeContext,
) -> Result<(), EncodeError> {
    builder_helpers::append_utf8_avp(dst, code, value, true, ctx)
}

fn append_optional_drmp(
    dst: &mut BytesMut,
    drmp: Option<SwmRoutingMessagePriority>,
    ctx: EncodeContext,
) -> Result<(), EncodeError> {
    if let Some(priority) = drmp {
        builder_helpers::append_u32_avp(dst, AVP_DRMP, u32::from(priority.value()), false, ctx)?;
    }
    Ok(())
}

fn append_routing_and_additional(
    dst: &mut BytesMut,
    proxy_infos: &[SwmAdditionalAvp],
    route_records: &[Redacted<String>],
    additional_avps: &[SwmAdditionalAvp],
    ctx: EncodeContext,
) -> Result<(), EncodeError> {
    append_additional(dst, proxy_infos, ctx)?;
    for route_record in route_records {
        append_string(dst, base::AVP_ROUTE_RECORD, route_record.as_ref(), ctx)?;
    }
    append_additional(dst, additional_avps, ctx)
}

fn append_additional(
    dst: &mut BytesMut,
    avps: &[SwmAdditionalAvp],
    ctx: EncodeContext,
) -> Result<(), EncodeError> {
    for avp in avps {
        avp.append_to(dst, ctx)?;
    }
    Ok(())
}

fn build_message(
    flags: crate::CommandFlags,
    command: CommandCode,
    avps: BytesMut,
    transaction: SwmDiameterTransaction,
    ctx: EncodeContext,
    section: &'static str,
) -> Result<OwnedMessage, EncodeError> {
    builder_helpers::build_message(
        flags,
        command,
        APPLICATION_ID,
        avps,
        transaction.hop_by_hop_identifier(),
        transaction.end_to_end_identifier(),
        ctx,
        section,
    )
}

/// Parse one SWm RAR, returning the legacy structured decode error surface.
pub fn parse_swm_re_auth_request(
    message: &Message<'_>,
    ctx: DecodeContext,
) -> Result<SwmReAuthRequest, DecodeError> {
    parse_swm_re_auth_request_with_provenance(message, ctx)
        .map_err(DiameterParserError::into_decode_error)
}

/// Parse one SWm RAR with sealed missing-AVP provenance.
pub fn parse_swm_re_auth_request_with_provenance(
    message: &Message<'_>,
    ctx: DecodeContext,
) -> Result<SwmReAuthRequest, DiameterParserError> {
    parse_re_auth_request_parts(message, ctx).map(|parts| parts.request)
}

/// Parse one inbound SWm RAR while retaining response-construction facts.
///
/// The returned server-side envelope has no expected answer peer. A caller
/// inspecting a previously originated outbound request can attach trusted
/// transport evidence with [`SwmReAuthRequestEnvelope::with_expected_answer_peer`].
pub fn parse_swm_re_auth_request_envelope(
    message: &Message<'_>,
    ctx: DecodeContext,
) -> Result<SwmReAuthRequestEnvelope, DecodeError> {
    parse_swm_re_auth_request_envelope_with_provenance(message, ctx)
        .map_err(DiameterParserError::into_decode_error)
}

/// Provenance-aware form of [`parse_swm_re_auth_request_envelope`].
pub fn parse_swm_re_auth_request_envelope_with_provenance(
    message: &Message<'_>,
    ctx: DecodeContext,
) -> Result<SwmReAuthRequestEnvelope, DiameterParserError> {
    let parts = parse_re_auth_request_parts(message, ctx)?;
    Ok(SwmReAuthRequestEnvelope {
        transaction: SwmDiameterTransaction::from_message(message),
        proxiable: message.header.flags.is_proxiable(),
        potentially_retransmitted: message.header.flags.is_potentially_retransmitted(),
        expected_answer_peer: None,
        request: parts.request,
        proxy_infos: parts.proxy_infos,
    })
}

/// Parse one SWm RAA.
pub fn parse_swm_re_auth_answer(
    message: &Message<'_>,
    ctx: DecodeContext,
) -> Result<SwmReAuthAnswer, DecodeError> {
    parse_re_auth_answer_parts(message, ctx).map(|parts| parts.answer)
}

/// Parse one SWm RAA while retaining its authenticated connection generation
/// and exact transaction identifiers.
pub fn parse_swm_re_auth_answer_envelope_from_connection(
    message: &Message<'_>,
    received_on: SwmDiameterConnectionToken,
    ctx: DecodeContext,
) -> Result<SwmReAuthAnswerEnvelope, DecodeError> {
    let parts = parse_re_auth_answer_parts(message, ctx)?;
    Ok(SwmReAuthAnswerEnvelope {
        transaction: SwmDiameterTransaction::from_message(message),
        proxiable: message.header.flags.is_proxiable(),
        received_on,
        generic_error: message.header.flags.is_error(),
        answer: parts.answer,
        proxy_infos: parts.proxy_infos,
    })
}

/// Parse one SWm AAR, returning the legacy structured decode error surface.
pub fn parse_swm_authorization_request(
    message: &Message<'_>,
    ctx: DecodeContext,
) -> Result<SwmAuthorizationRequest, DecodeError> {
    parse_swm_authorization_request_with_provenance(message, ctx)
        .map_err(DiameterParserError::into_decode_error)
}

/// Parse one SWm AAR with sealed missing-AVP provenance.
pub fn parse_swm_authorization_request_with_provenance(
    message: &Message<'_>,
    ctx: DecodeContext,
) -> Result<SwmAuthorizationRequest, DiameterParserError> {
    parse_authorization_request_parts(message, ctx).map(|parts| parts.request)
}

/// Parse one inbound SWm AAR while retaining response-construction facts.
///
/// The returned server-side envelope has no expected answer peer. A caller
/// inspecting a previously originated outbound request can attach trusted
/// transport evidence with
/// [`SwmAuthorizationRequestEnvelope::with_expected_answer_peer`].
pub fn parse_swm_authorization_request_envelope(
    message: &Message<'_>,
    ctx: DecodeContext,
) -> Result<SwmAuthorizationRequestEnvelope, DecodeError> {
    parse_swm_authorization_request_envelope_with_provenance(message, ctx)
        .map_err(DiameterParserError::into_decode_error)
}

/// Provenance-aware form of [`parse_swm_authorization_request_envelope`].
pub fn parse_swm_authorization_request_envelope_with_provenance(
    message: &Message<'_>,
    ctx: DecodeContext,
) -> Result<SwmAuthorizationRequestEnvelope, DiameterParserError> {
    let parts = parse_authorization_request_parts(message, ctx)?;
    Ok(SwmAuthorizationRequestEnvelope {
        transaction: SwmDiameterTransaction::from_message(message),
        proxiable: message.header.flags.is_proxiable(),
        potentially_retransmitted: message.header.flags.is_potentially_retransmitted(),
        expected_answer_peer: None,
        request: parts.request,
        proxy_infos: parts.proxy_infos,
    })
}

/// Parse one SWm AAA.
pub fn parse_swm_authorization_answer(
    message: &Message<'_>,
    ctx: DecodeContext,
) -> Result<SwmAuthorizationAnswer, DecodeError> {
    parse_authorization_answer_parts(message, ctx).map(|parts| parts.answer)
}

/// Parse one SWm AAA while retaining its authenticated connection generation
/// and exact transaction identifiers.
pub fn parse_swm_authorization_answer_envelope_from_connection(
    message: &Message<'_>,
    received_on: SwmDiameterConnectionToken,
    ctx: DecodeContext,
) -> Result<SwmAuthorizationAnswerEnvelope, DecodeError> {
    let parts = parse_authorization_answer_parts(message, ctx)?;
    Ok(SwmAuthorizationAnswerEnvelope {
        transaction: SwmDiameterTransaction::from_message(message),
        proxiable: message.header.flags.is_proxiable(),
        received_on,
        generic_error: message.header.flags.is_error(),
        answer: parts.answer,
        proxy_infos: parts.proxy_infos,
    })
}

struct ParsedReAuthRequestParts {
    request: SwmReAuthRequest,
    proxy_infos: Vec<SwmAdditionalAvp>,
}

fn parse_re_auth_request_parts(
    message: &Message<'_>,
    ctx: DecodeContext,
) -> Result<ParsedReAuthRequestParts, DiameterParserError> {
    ensure_authorization_header(message, COMMAND_RE_AUTH, AuthorizationRole::RarRequest)
        .map_err(|error| DiameterParserError::decoded(message, error))?;

    let mut session_id = None;
    let mut origin_host = None;
    let mut origin_realm = None;
    let mut destination_realm = None;
    let mut destination_host = None;
    let mut auth_application_id = None;
    let mut re_auth_request_type = None;
    let mut user_name = None;
    let mut drmp = None;
    let mut route_records = Vec::new();
    let mut proxy_infos = Vec::new();
    let mut additional_avps = Vec::new();
    let mut additional_keys = HashSet::new();

    builder_helpers::for_each_avp(
        message.raw_avps,
        ctx,
        DIAMETER_HEADER_LEN,
        0,
        |offset, avp| {
            let value_offset = builder_helpers::offset_add(
                offset,
                avp.header.header_len(),
                AuthorizationRole::RarRequest.section(),
            )?;
            let key = avp.header.key();
            if key == AvpKey::ietf(base::AVP_SESSION_ID) {
                parse_required_string(&avp, offset, value_offset, &mut session_id)?;
            } else if key == AvpKey::ietf(base::AVP_ORIGIN_HOST) {
                parse_required_string(&avp, offset, value_offset, &mut origin_host)?;
            } else if key == AvpKey::ietf(base::AVP_ORIGIN_REALM) {
                parse_required_string(&avp, offset, value_offset, &mut origin_realm)?;
            } else if key == AvpKey::ietf(base::AVP_DESTINATION_REALM) {
                parse_required_string(&avp, offset, value_offset, &mut destination_realm)?;
            } else if key == AvpKey::ietf(base::AVP_DESTINATION_HOST) {
                parse_required_string(&avp, offset, value_offset, &mut destination_host)?;
            } else if key == AvpKey::ietf(base::AVP_AUTH_APPLICATION_ID) {
                lifecycle::validate_base_definition(&avp, offset)?;
                let value = builder_helpers::parse_u32_value(avp.value, value_offset, "6.8")?;
                builder_helpers::set_once(&mut auth_application_id, value, offset, "7.2.2.4.1")?;
            } else if key == AvpKey::ietf(base::AVP_RE_AUTH_REQUEST_TYPE) {
                lifecycle::validate_base_definition(&avp, offset)?;
                let value = builder_helpers::parse_u32_value(avp.value, value_offset, "8.12")?;
                let typed = SwmReAuthRequestType::from_value(value).ok_or_else(|| {
                    enum_error(
                        "Re-Auth-Request-Type",
                        value,
                        value_offset,
                        "RFC6733",
                        "8.12",
                    )
                })?;
                builder_helpers::set_once(&mut re_auth_request_type, typed, offset, "7.2.2.4.1")?;
            } else if key == AvpKey::ietf(base::AVP_USER_NAME) {
                parse_required_string(&avp, offset, value_offset, &mut user_name)?;
            } else if key == AvpKey::ietf(AVP_DRMP) {
                parse_drmp(&avp, offset, value_offset, &mut drmp)?;
            } else if key == AvpKey::ietf(base::AVP_PROXY_INFO) {
                parse_proxy_info(&avp, ctx, offset, value_offset, &mut proxy_infos)?;
            } else if key == AvpKey::ietf(base::AVP_ROUTE_RECORD) {
                parse_route_record(&avp, offset, value_offset, &mut route_records)?;
            } else if let Some(additional) = parse_additional_avp(
                &avp,
                ctx,
                offset,
                value_offset,
                AuthorizationRole::RarRequest,
            )? {
                push_additional(
                    additional,
                    key,
                    offset,
                    AuthorizationRole::RarRequest,
                    &mut additional_avps,
                    &mut additional_keys,
                )?;
            }
            Ok(())
        },
    )
    .map_err(|error| DiameterParserError::decoded(message, error))?;

    let auth_application_id = require_request_field(
        auth_application_id,
        base::AVP_AUTH_APPLICATION_ID,
        "SWm RAR requires Auth-Application-Id",
        message,
        COMMAND_RE_AUTH,
        "7.2.2.4.1",
    )?;
    if auth_application_id != APPLICATION_ID.get() {
        return Err(DiameterParserError::decoded(
            message,
            decode_error(
                "SWm RAR Auth-Application-Id does not match SWm",
                DIAMETER_HEADER_LEN,
                "7.2.2.4.1",
            ),
        ));
    }
    let re_auth_request_type = require_request_field(
        re_auth_request_type,
        base::AVP_RE_AUTH_REQUEST_TYPE,
        "SWm RAR requires Re-Auth-Request-Type",
        message,
        COMMAND_RE_AUTH,
        "7.2.2.4.1",
    )?;
    if re_auth_request_type != SwmReAuthRequestType::AuthorizeOnly {
        return Err(DiameterParserError::decoded(
            message,
            decode_error(
                "SWm authorization-update RAR requires AUTHORIZE_ONLY",
                DIAMETER_HEADER_LEN,
                "7.1.2.5",
            ),
        ));
    }

    Ok(ParsedReAuthRequestParts {
        request: SwmReAuthRequest {
            session_id: require_request_field(
                session_id,
                base::AVP_SESSION_ID,
                "SWm RAR requires Session-Id",
                message,
                COMMAND_RE_AUTH,
                "7.2.2.4.1",
            )?,
            origin_host: require_request_field(
                origin_host,
                base::AVP_ORIGIN_HOST,
                "SWm RAR requires Origin-Host",
                message,
                COMMAND_RE_AUTH,
                "7.2.2.4.1",
            )?,
            origin_realm: require_request_field(
                origin_realm,
                base::AVP_ORIGIN_REALM,
                "SWm RAR requires Origin-Realm",
                message,
                COMMAND_RE_AUTH,
                "7.2.2.4.1",
            )?,
            destination_realm: require_request_field(
                destination_realm,
                base::AVP_DESTINATION_REALM,
                "SWm RAR requires Destination-Realm",
                message,
                COMMAND_RE_AUTH,
                "7.2.2.4.1",
            )?,
            destination_host: require_request_field(
                destination_host,
                base::AVP_DESTINATION_HOST,
                "SWm authorization-update RAR requires Destination-Host",
                message,
                COMMAND_RE_AUTH,
                "7.1.2.5",
            )?,
            re_auth_request_type,
            user_name: require_request_field(
                user_name,
                base::AVP_USER_NAME,
                "SWm authorization-update RAR requires User-Name",
                message,
                COMMAND_RE_AUTH,
                "7.1.2.5",
            )?,
            drmp,
            route_records,
            additional_avps,
        },
        proxy_infos,
    })
}

struct ParsedReAuthAnswerParts {
    answer: SwmReAuthAnswer,
    proxy_infos: Vec<SwmAdditionalAvp>,
}

fn parse_re_auth_answer_parts(
    message: &Message<'_>,
    ctx: DecodeContext,
) -> Result<ParsedReAuthAnswerParts, DecodeError> {
    ensure_authorization_header(message, COMMAND_RE_AUTH, AuthorizationRole::RaaAnswer)?;
    let mut session_id = None;
    let mut result_code = None;
    let mut re_auth_request_type = None;
    let mut authorization_lifetime = None;
    let mut auth_grace_period = None;
    let mut origin_host = None;
    let mut origin_realm = None;
    let mut user_name = None;
    let mut drmp = None;
    let mut proxy_infos = Vec::new();
    let mut additional_avps = Vec::new();
    let mut additional_keys = HashSet::new();
    for_each_authorization_avp(
        message,
        ctx,
        AuthorizationRole::RaaAnswer,
        |offset, avp, value_offset| {
            let key = avp.header.key();
            if key == AvpKey::ietf(base::AVP_SESSION_ID) {
                parse_required_string(&avp, offset, value_offset, &mut session_id)?;
            } else if key == AvpKey::ietf(base::AVP_RESULT_CODE) {
                lifecycle::validate_base_definition(&avp, offset)?;
                let value = builder_helpers::parse_u32_value(avp.value, value_offset, "7.1")?;
                builder_helpers::set_once(&mut result_code, value, offset, "7.2.2.4.2")?;
            } else if key == AvpKey::ietf(base::AVP_RE_AUTH_REQUEST_TYPE) {
                lifecycle::validate_base_definition(&avp, offset)?;
                let value = builder_helpers::parse_u32_value(avp.value, value_offset, "8.12")?;
                let typed = SwmReAuthRequestType::from_value(value).ok_or_else(|| {
                    enum_error(
                        "Re-Auth-Request-Type",
                        value,
                        value_offset,
                        "RFC6733",
                        "8.12",
                    )
                })?;
                builder_helpers::set_once(&mut re_auth_request_type, typed, offset, "7.2.2.4.2")?;
            } else if key == AvpKey::ietf(base::AVP_AUTHORIZATION_LIFETIME) {
                parse_base_u32(
                    &avp,
                    offset,
                    value_offset,
                    &mut authorization_lifetime,
                    "8.9",
                    "7.2.2.4.2",
                )?;
            } else if key == AvpKey::ietf(base::AVP_AUTH_GRACE_PERIOD) {
                parse_base_u32(
                    &avp,
                    offset,
                    value_offset,
                    &mut auth_grace_period,
                    "8.10",
                    "7.2.2.4.2",
                )?;
            } else if key == AvpKey::ietf(base::AVP_EXPERIMENTAL_RESULT)
                && message.header.flags.is_error()
            {
                lifecycle::validate_base_definition(&avp, offset)?;
                parse_experimental_result(avp.value, ctx, value_offset, 1)?;
                let additional = lifecycle::retain_additional_avp(&avp, ctx, value_offset)?;
                push_additional(
                    additional,
                    key,
                    offset,
                    AuthorizationRole::RaaAnswer,
                    &mut additional_avps,
                    &mut additional_keys,
                )?;
            } else if key == AvpKey::ietf(base::AVP_ORIGIN_HOST) {
                parse_required_string(&avp, offset, value_offset, &mut origin_host)?;
            } else if key == AvpKey::ietf(base::AVP_ORIGIN_REALM) {
                parse_required_string(&avp, offset, value_offset, &mut origin_realm)?;
            } else if key == AvpKey::ietf(base::AVP_USER_NAME) {
                parse_required_string(&avp, offset, value_offset, &mut user_name)?;
            } else if key == AvpKey::ietf(AVP_DRMP) {
                parse_drmp(&avp, offset, value_offset, &mut drmp)?;
            } else if key == AvpKey::ietf(base::AVP_PROXY_INFO) {
                parse_proxy_info(&avp, ctx, offset, value_offset, &mut proxy_infos)?;
            } else if let Some(additional) = parse_additional_avp(
                &avp,
                ctx,
                offset,
                value_offset,
                AuthorizationRole::RaaAnswer,
            )? {
                push_additional(
                    additional,
                    key,
                    offset,
                    AuthorizationRole::RaaAnswer,
                    &mut additional_avps,
                    &mut additional_keys,
                )?;
            }
            Ok(())
        },
    )?;
    super::session_state::validate_class_additional_avps_for_decode(
        &additional_avps,
        DIAMETER_HEADER_LEN,
    )?;
    let result_code =
        require_answer_field(result_code, "SWm RAA requires Result-Code", "7.2.2.4.2")?;
    validate_result_code_decode(result_code, "7.2.2.4.2")?;
    if result_code == RESULT_CODE_REDIRECT_INDICATION || contains_redirect_avp(&additional_avps) {
        return Err(decode_error(
            "typed SWm RAA does not support redirect result context",
            DIAMETER_HEADER_LEN,
            "7.2.2.4.2",
        ));
    }
    validate_result_error_bit(message, result_code, "7.2.2.4.2")?;
    validate_answer_timers_decode(
        authorization_lifetime,
        None,
        re_auth_request_type,
        "7.2.2.4.2",
    )?;
    lifecycle::validate_answer_overload_control_decode(&additional_avps, ctx)?;
    let generic_error = message.header.flags.is_error();
    let session_id = if generic_error {
        session_id
    } else {
        Some(require_answer_field(
            session_id,
            "SWm RAA requires Session-Id",
            "7.2.2.4.2",
        )?)
    };
    let user_name = if generic_error {
        user_name
    } else {
        Some(require_answer_field(
            user_name,
            "SWm RAA requires User-Name",
            "7.2.2.4.2",
        )?)
    };
    Ok(ParsedReAuthAnswerParts {
        answer: SwmReAuthAnswer {
            session_id,
            result: SwmReAuthResult::from_result_code(result_code),
            re_auth_request_type,
            authorization_lifetime,
            auth_grace_period,
            origin_host: require_answer_field(
                origin_host,
                "SWm RAA requires Origin-Host",
                "7.2.2.4.2",
            )?,
            origin_realm: require_answer_field(
                origin_realm,
                "SWm RAA requires Origin-Realm",
                "7.2.2.4.2",
            )?,
            user_name,
            drmp,
            additional_avps,
        },
        proxy_infos,
    })
}

struct ParsedAuthorizationRequestParts {
    request: SwmAuthorizationRequest,
    proxy_infos: Vec<SwmAdditionalAvp>,
}

fn parse_authorization_request_parts(
    message: &Message<'_>,
    ctx: DecodeContext,
) -> Result<ParsedAuthorizationRequestParts, DiameterParserError> {
    ensure_authorization_header(message, COMMAND_AA, AuthorizationRole::AarRequest)
        .map_err(|error| DiameterParserError::decoded(message, error))?;
    let mut session_id = None;
    let mut auth_application_id = None;
    let mut origin_host = None;
    let mut origin_realm = None;
    let mut destination_realm = None;
    let mut destination_host = None;
    let mut auth_request_type = None;
    let mut user_name = None;
    let mut authorization_lifetime = None;
    let mut auth_grace_period = None;
    let mut aar_flags = None;
    let mut ue_local_ip_address = None;
    let mut high_priority_access_info = None;
    let mut drmp = None;
    let mut route_records = Vec::new();
    let mut proxy_infos = Vec::new();
    let mut additional_avps = Vec::new();
    let mut additional_keys = HashSet::new();

    for_each_authorization_avp(
        message,
        ctx,
        AuthorizationRole::AarRequest,
        |offset, avp, value_offset| {
            let key = avp.header.key();
            if key == AvpKey::ietf(base::AVP_SESSION_ID) {
                parse_required_string(&avp, offset, value_offset, &mut session_id)?;
            } else if key == AvpKey::ietf(base::AVP_AUTH_APPLICATION_ID) {
                lifecycle::validate_base_definition(&avp, offset)?;
                let value = builder_helpers::parse_u32_value(avp.value, value_offset, "6.8")?;
                builder_helpers::set_once(&mut auth_application_id, value, offset, "7.2.2.1.3")?;
            } else if key == AvpKey::ietf(base::AVP_ORIGIN_HOST) {
                parse_required_string(&avp, offset, value_offset, &mut origin_host)?;
            } else if key == AvpKey::ietf(base::AVP_ORIGIN_REALM) {
                parse_required_string(&avp, offset, value_offset, &mut origin_realm)?;
            } else if key == AvpKey::ietf(base::AVP_DESTINATION_REALM) {
                parse_required_string(&avp, offset, value_offset, &mut destination_realm)?;
            } else if key == AvpKey::ietf(base::AVP_DESTINATION_HOST) {
                parse_required_string(&avp, offset, value_offset, &mut destination_host)?;
            } else if key == AvpKey::ietf(AVP_AUTH_REQUEST_TYPE) {
                validate_dictionary_definition(&avp, offset, "8.7")?;
                let value = builder_helpers::parse_u32_value(avp.value, value_offset, "8.7")?;
                builder_helpers::set_once(
                    &mut auth_request_type,
                    AuthRequestType::from_value(value),
                    offset,
                    "7.2.2.1.3",
                )?;
            } else if key == AvpKey::ietf(base::AVP_USER_NAME) {
                parse_required_string(&avp, offset, value_offset, &mut user_name)?;
            } else if key == AvpKey::ietf(base::AVP_AUTHORIZATION_LIFETIME) {
                parse_base_u32(
                    &avp,
                    offset,
                    value_offset,
                    &mut authorization_lifetime,
                    "8.9",
                    "7.2.2.1.3",
                )?;
            } else if key == AvpKey::ietf(base::AVP_AUTH_GRACE_PERIOD) {
                parse_base_u32(
                    &avp,
                    offset,
                    value_offset,
                    &mut auth_grace_period,
                    "8.10",
                    "7.2.2.1.3",
                )?;
            } else if key == AvpKey::vendor(AVP_AAR_FLAGS, VENDOR_ID_3GPP) {
                validate_vendor_definition(&avp, offset)?;
                let value = builder_helpers::parse_u32_value(avp.value, value_offset, "7.3.103")?;
                builder_helpers::set_once(
                    &mut aar_flags,
                    SwmAarFlags::from_value(value),
                    offset,
                    "7.2.2.1.3",
                )?;
            } else if key == AvpKey::vendor(AVP_UE_LOCAL_IP_ADDRESS, VENDOR_ID_3GPP) {
                validate_vendor_definition(&avp, offset)?;
                let value =
                    builder_helpers::parse_address_value(avp.value, value_offset, "5.3.96")?;
                builder_helpers::set_once(&mut ue_local_ip_address, value, offset, "7.2.2.1.3")?;
            } else if key == AvpKey::vendor(AVP_HIGH_PRIORITY_ACCESS_INFO, VENDOR_ID_3GPP) {
                validate_vendor_definition(&avp, offset)?;
                let value = builder_helpers::parse_u32_value(avp.value, value_offset, "7.3.105")?;
                builder_helpers::set_once(
                    &mut high_priority_access_info,
                    SwmHighPriorityAccessInfo::from_value(value),
                    offset,
                    "7.2.2.1.3",
                )?;
            } else if key == AvpKey::ietf(AVP_DRMP) {
                parse_drmp(&avp, offset, value_offset, &mut drmp)?;
            } else if key == AvpKey::ietf(base::AVP_PROXY_INFO) {
                parse_proxy_info(&avp, ctx, offset, value_offset, &mut proxy_infos)?;
            } else if key == AvpKey::ietf(base::AVP_ROUTE_RECORD) {
                parse_route_record(&avp, offset, value_offset, &mut route_records)?;
            } else if let Some(additional) = parse_additional_avp(
                &avp,
                ctx,
                offset,
                value_offset,
                AuthorizationRole::AarRequest,
            )? {
                push_additional(
                    additional,
                    key,
                    offset,
                    AuthorizationRole::AarRequest,
                    &mut additional_avps,
                    &mut additional_keys,
                )?;
            }
            Ok(())
        },
    )
    .map_err(|error| DiameterParserError::decoded(message, error))?;

    let auth_application_id = require_request_field(
        auth_application_id,
        base::AVP_AUTH_APPLICATION_ID,
        "SWm AAR requires Auth-Application-Id",
        message,
        COMMAND_AA,
        "7.2.2.1.3",
    )?;
    if auth_application_id != APPLICATION_ID.get() {
        return Err(DiameterParserError::decoded(
            message,
            decode_error(
                "SWm AAR Auth-Application-Id does not match SWm",
                DIAMETER_HEADER_LEN,
                "7.2.2.1.3",
            ),
        ));
    }
    let auth_request_type = require_request_field(
        auth_request_type,
        AVP_AUTH_REQUEST_TYPE,
        "SWm AAR requires Auth-Request-Type",
        message,
        COMMAND_AA,
        "7.2.2.1.3",
    )?;
    if !auth_request_type.is_authorize_only() {
        return Err(DiameterParserError::decoded(
            message,
            decode_error(
                "SWm authorization-update AAR requires AUTHORIZE_ONLY",
                DIAMETER_HEADER_LEN,
                "7.1.2.5",
            ),
        ));
    }
    Ok(ParsedAuthorizationRequestParts {
        request: SwmAuthorizationRequest {
            session_id: require_request_field(
                session_id,
                base::AVP_SESSION_ID,
                "SWm AAR requires Session-Id",
                message,
                COMMAND_AA,
                "7.2.2.1.3",
            )?,
            origin_host: require_request_field(
                origin_host,
                base::AVP_ORIGIN_HOST,
                "SWm AAR requires Origin-Host",
                message,
                COMMAND_AA,
                "7.2.2.1.3",
            )?,
            origin_realm: require_request_field(
                origin_realm,
                base::AVP_ORIGIN_REALM,
                "SWm AAR requires Origin-Realm",
                message,
                COMMAND_AA,
                "7.2.2.1.3",
            )?,
            destination_realm: require_request_field(
                destination_realm,
                base::AVP_DESTINATION_REALM,
                "SWm AAR requires Destination-Realm",
                message,
                COMMAND_AA,
                "7.2.2.1.3",
            )?,
            destination_host,
            user_name: require_request_field(
                user_name,
                base::AVP_USER_NAME,
                "SWm AAR requires User-Name",
                message,
                COMMAND_AA,
                "7.2.2.1.3",
            )?,
            auth_request_type,
            authorization_lifetime,
            auth_grace_period,
            aar_flags,
            ue_local_ip_address,
            high_priority_access_info,
            drmp,
            route_records,
            additional_avps,
        },
        proxy_infos,
    })
}

struct ParsedAuthorizationAnswerParts {
    answer: SwmAuthorizationAnswer,
    proxy_infos: Vec<SwmAdditionalAvp>,
}

fn parse_authorization_answer_parts(
    message: &Message<'_>,
    ctx: DecodeContext,
) -> Result<ParsedAuthorizationAnswerParts, DecodeError> {
    ensure_authorization_header(message, COMMAND_AA, AuthorizationRole::AaaAnswer)?;
    let mut session_id = None;
    let mut auth_application_id = None;
    let mut auth_request_type = None;
    let mut result = None;
    let mut re_auth_request_type = None;
    let mut authorization_lifetime = None;
    let mut auth_grace_period = None;
    let mut session_timeout = None;
    let mut origin_host = None;
    let mut origin_realm = None;
    let mut user_name = None;
    let mut apn_configuration = None;
    let mut drmp = None;
    let mut proxy_infos = Vec::new();
    let mut additional_avps = Vec::new();
    let mut additional_keys = HashSet::new();
    for_each_authorization_avp(
        message,
        ctx,
        AuthorizationRole::AaaAnswer,
        |offset, avp, value_offset| {
            let key = avp.header.key();
            if key == AvpKey::ietf(base::AVP_SESSION_ID) {
                parse_required_string(&avp, offset, value_offset, &mut session_id)?;
            } else if key == AvpKey::ietf(base::AVP_AUTH_APPLICATION_ID) {
                lifecycle::validate_base_definition(&avp, offset)?;
                let value = builder_helpers::parse_u32_value(avp.value, value_offset, "6.8")?;
                builder_helpers::set_once(&mut auth_application_id, value, offset, "7.2.2.1.4")?;
            } else if key == AvpKey::ietf(AVP_AUTH_REQUEST_TYPE) {
                validate_dictionary_definition(&avp, offset, "8.7")?;
                let value = builder_helpers::parse_u32_value(avp.value, value_offset, "8.7")?;
                builder_helpers::set_once(
                    &mut auth_request_type,
                    AuthRequestType::from_value(value),
                    offset,
                    "7.2.2.1.4",
                )?;
            } else if key == AvpKey::ietf(base::AVP_RESULT_CODE) {
                lifecycle::validate_base_definition(&avp, offset)?;
                let value = builder_helpers::parse_u32_value(avp.value, value_offset, "7.1")?;
                builder_helpers::set_once(
                    &mut result,
                    SwmDiameterResult::Base(value),
                    offset,
                    "7.2.2.1.4",
                )?;
            } else if key == AvpKey::ietf(base::AVP_RE_AUTH_REQUEST_TYPE) {
                lifecycle::validate_base_definition(&avp, offset)?;
                let value = builder_helpers::parse_u32_value(avp.value, value_offset, "8.12")?;
                let typed = SwmReAuthRequestType::from_value(value).ok_or_else(|| {
                    enum_error(
                        "Re-Auth-Request-Type",
                        value,
                        value_offset,
                        "RFC6733",
                        "8.12",
                    )
                })?;
                builder_helpers::set_once(&mut re_auth_request_type, typed, offset, "7.2.2.1.4")?;
            } else if key == AvpKey::ietf(base::AVP_AUTHORIZATION_LIFETIME) {
                parse_base_u32(
                    &avp,
                    offset,
                    value_offset,
                    &mut authorization_lifetime,
                    "8.9",
                    "7.2.2.1.4",
                )?;
            } else if key == AvpKey::ietf(base::AVP_AUTH_GRACE_PERIOD) {
                parse_base_u32(
                    &avp,
                    offset,
                    value_offset,
                    &mut auth_grace_period,
                    "8.10",
                    "7.2.2.1.4",
                )?;
            } else if key == AvpKey::ietf(base::AVP_SESSION_TIMEOUT) {
                parse_base_u32(
                    &avp,
                    offset,
                    value_offset,
                    &mut session_timeout,
                    "8.13",
                    "7.2.2.1.4",
                )?;
            } else if key == AvpKey::ietf(base::AVP_EXPERIMENTAL_RESULT) {
                lifecycle::validate_base_definition(&avp, offset)?;
                if message.header.flags.is_error() {
                    parse_experimental_result(avp.value, ctx, value_offset, 1)?;
                    let additional = lifecycle::retain_additional_avp(&avp, ctx, value_offset)?;
                    push_additional(
                        additional,
                        key,
                        offset,
                        AuthorizationRole::AaaAnswer,
                        &mut additional_avps,
                        &mut additional_keys,
                    )?;
                } else {
                    let value = parse_experimental_result(avp.value, ctx, value_offset, 1)?;
                    builder_helpers::set_once(&mut result, value, offset, "7.2.2.1.4")?;
                }
            } else if key == AvpKey::ietf(base::AVP_ORIGIN_HOST) {
                parse_required_string(&avp, offset, value_offset, &mut origin_host)?;
            } else if key == AvpKey::ietf(base::AVP_ORIGIN_REALM) {
                parse_required_string(&avp, offset, value_offset, &mut origin_realm)?;
            } else if key == AvpKey::ietf(base::AVP_USER_NAME) {
                parse_required_string(&avp, offset, value_offset, &mut user_name)?;
            } else if key == AvpKey::vendor(super::AVP_APN_CONFIGURATION, VENDOR_ID_3GPP) {
                validate_vendor_definition(&avp, offset)?;
                let mut retention = super::DiameterEapRetention::default();
                let (value, supplement) =
                    parse_apn_configuration(&avp, ctx, offset, value_offset, 1, &mut retention)?;
                validate_authorization_apn(&value)
                    .map_err(|reason| decode_error(reason, offset, "7.2.2.1.4"))?;
                let authorized = SwmAuthorizedApnConfiguration::from_parsed(value, supplement)
                    .map_err(|_| {
                        decode_error(
                            "SWm AAA APN-Configuration is not safe for authorization",
                            offset,
                            "7.2.2.1.4",
                        )
                    })?;
                builder_helpers::set_once(&mut apn_configuration, authorized, offset, "7.2.2.1.4")?;
            } else if key == AvpKey::ietf(AVP_DRMP) {
                parse_drmp(&avp, offset, value_offset, &mut drmp)?;
            } else if key == AvpKey::ietf(base::AVP_PROXY_INFO) {
                parse_proxy_info(&avp, ctx, offset, value_offset, &mut proxy_infos)?;
            } else if let Some(additional) = parse_additional_avp(
                &avp,
                ctx,
                offset,
                value_offset,
                AuthorizationRole::AaaAnswer,
            )? {
                push_additional(
                    additional,
                    key,
                    offset,
                    AuthorizationRole::AaaAnswer,
                    &mut additional_avps,
                    &mut additional_keys,
                )?;
            }
            Ok(())
        },
    )?;
    super::session_state::validate_class_additional_avps_for_decode(
        &additional_avps,
        DIAMETER_HEADER_LEN,
    )?;
    let generic_error = message.header.flags.is_error();
    if !generic_error && auth_application_id.is_none() {
        return Err(decode_error(
            "SWm AAA requires Auth-Application-Id",
            DIAMETER_HEADER_LEN,
            "7.2.2.1.4",
        ));
    }
    if auth_application_id.is_some_and(|value| value != APPLICATION_ID.get()) {
        return Err(decode_error(
            "SWm AAA Auth-Application-Id does not match SWm",
            DIAMETER_HEADER_LEN,
            "7.2.2.1.4",
        ));
    }
    if !generic_error && auth_request_type.is_none() {
        return Err(decode_error(
            "SWm AAA requires Auth-Request-Type",
            DIAMETER_HEADER_LEN,
            "7.2.2.1.4",
        ));
    }
    if auth_request_type.is_some_and(|request_type| !request_type.is_authorize_only()) {
        return Err(decode_error(
            "SWm authorization-update AAA requires AUTHORIZE_ONLY",
            DIAMETER_HEADER_LEN,
            "7.1.2.5",
        ));
    }
    let result = require_answer_field(
        result,
        "SWm AAA requires exactly one result AVP",
        "7.2.2.1.4",
    )?;
    validate_result_code_decode(result.code(), "7.2.2.1.4")?;
    if result.code() == RESULT_CODE_REDIRECT_INDICATION || contains_redirect_avp(&additional_avps) {
        return Err(decode_error(
            "typed SWm AAA does not support redirect result context",
            DIAMETER_HEADER_LEN,
            "7.2.2.1.4",
        ));
    }
    validate_result_error_bit(message, result.code(), "7.2.2.1.4")?;
    validate_answer_timers_decode(
        authorization_lifetime,
        session_timeout,
        re_auth_request_type,
        "7.2.2.1.4",
    )?;
    if apn_configuration.is_some() && !result.is_diameter_success() {
        return Err(decode_error(
            "SWm AAA APN-Configuration is valid only with DIAMETER_SUCCESS",
            DIAMETER_HEADER_LEN,
            "7.2.2.1.4",
        ));
    }
    lifecycle::validate_answer_overload_control_decode(&additional_avps, ctx)?;
    let session_id = if generic_error {
        session_id
    } else {
        Some(require_answer_field(
            session_id,
            "SWm AAA requires Session-Id",
            "7.2.2.1.4",
        )?)
    };
    let user_name = if generic_error {
        user_name
    } else {
        Some(require_answer_field(
            user_name,
            "SWm AAA requires User-Name",
            "7.2.2.1.4",
        )?)
    };
    Ok(ParsedAuthorizationAnswerParts {
        answer: SwmAuthorizationAnswer {
            session_id,
            auth_request_type,
            result,
            re_auth_request_type,
            authorization_lifetime,
            auth_grace_period,
            session_timeout,
            origin_host: require_answer_field(
                origin_host,
                "SWm AAA requires Origin-Host",
                "7.2.2.1.4",
            )?,
            origin_realm: require_answer_field(
                origin_realm,
                "SWm AAA requires Origin-Realm",
                "7.2.2.1.4",
            )?,
            user_name,
            apn_configuration,
            drmp,
            additional_avps,
        },
        proxy_infos,
    })
}

fn ensure_authorization_header(
    message: &Message<'_>,
    command: CommandCode,
    role: AuthorizationRole,
) -> Result<(), DecodeError> {
    builder_helpers::ensure_app_header(
        message,
        command,
        APPLICATION_ID,
        if role.is_answer() {
            CommandKind::Answer
        } else {
            CommandKind::Request
        },
        role.section(),
    )?;
    let flags = message.header.flags;
    if !flags.is_proxiable() {
        return Err(decode_error(
            "SWm authorization command must set P",
            4,
            role.section(),
        ));
    }
    if role.is_answer() {
        if flags.is_potentially_retransmitted() {
            return Err(decode_error(
                "SWm authorization answer must clear T",
                4,
                role.section(),
            ));
        }
    } else if flags.is_error() {
        return Err(decode_error(
            "SWm authorization request must clear E",
            4,
            role.section(),
        ));
    }
    Ok(())
}

fn for_each_authorization_avp<F>(
    message: &Message<'_>,
    ctx: DecodeContext,
    role: AuthorizationRole,
    mut visit: F,
) -> Result<(), DecodeError>
where
    F: FnMut(usize, RawAvp<'_>, usize) -> Result<(), DecodeError>,
{
    builder_helpers::for_each_avp(
        message.raw_avps,
        ctx,
        DIAMETER_HEADER_LEN,
        0,
        |offset, avp| {
            let value_offset =
                builder_helpers::offset_add(offset, avp.header.header_len(), role.section())?;
            visit(offset, avp, value_offset)
        },
    )
}

fn parse_required_string(
    avp: &RawAvp<'_>,
    offset: usize,
    value_offset: usize,
    field: &mut Option<Redacted<String>>,
) -> Result<(), DecodeError> {
    lifecycle::validate_base_definition(avp, offset)?;
    let definition = base::dictionary()
        .find_avp(avp.header.key())
        .ok_or_else(|| decode_error("SWm core AVP definition is missing", offset, "RFC6733"))?;
    builder_helpers::validate_known_avp_value(
        avp.value,
        definition.data_type(),
        DecodeContext::default(),
        value_offset,
        "RFC6733",
    )?;
    let value = builder_helpers::parse_string_value(avp.value, value_offset, "RFC6733")?;
    builder_helpers::set_once(field, Redacted::from(value), offset, "RFC6733")
}

fn parse_drmp(
    avp: &RawAvp<'_>,
    offset: usize,
    value_offset: usize,
    field: &mut Option<SwmRoutingMessagePriority>,
) -> Result<(), DecodeError> {
    validate_m_bit_agnostic_flags(avp, false, offset, "RFC7944-9.1")?;
    let value = builder_helpers::parse_u32_value(avp.value, value_offset, "9.1")?;
    let priority = SwmRoutingMessagePriority::from_value(value)
        .ok_or_else(|| enum_error("DRMP priority", value, value_offset, "RFC7944", "9.1"))?;
    builder_helpers::set_once(field, priority, offset, "9.1")
}

fn parse_base_u32(
    avp: &RawAvp<'_>,
    offset: usize,
    value_offset: usize,
    field: &mut Option<u32>,
    avp_section: &'static str,
    command_section: &'static str,
) -> Result<(), DecodeError> {
    lifecycle::validate_base_definition(avp, offset)?;
    let value = builder_helpers::parse_u32_value(avp.value, value_offset, avp_section)?;
    builder_helpers::set_once(field, value, offset, command_section)
}

fn parse_proxy_info(
    avp: &RawAvp<'_>,
    ctx: DecodeContext,
    offset: usize,
    value_offset: usize,
    proxy_infos: &mut Vec<SwmAdditionalAvp>,
) -> Result<(), DecodeError> {
    if proxy_infos.len() >= MAX_PROXY_INFOS {
        return Err(count_error(offset));
    }
    lifecycle::validate_proxy_info(avp, ctx, offset, value_offset)?;
    proxy_infos.push(SwmAdditionalAvp::from_raw(avp));
    Ok(())
}

fn parse_route_record(
    avp: &RawAvp<'_>,
    offset: usize,
    value_offset: usize,
    route_records: &mut Vec<Redacted<String>>,
) -> Result<(), DecodeError> {
    if route_records.len() >= MAX_ROUTE_RECORDS {
        return Err(count_error(offset));
    }
    lifecycle::validate_base_definition(avp, offset)?;
    let definition = base::dictionary()
        .find_avp(avp.header.key())
        .ok_or_else(|| decode_error("SWm core AVP definition is missing", offset, "6.7.1"))?;
    builder_helpers::validate_known_avp_value(
        avp.value,
        definition.data_type(),
        DecodeContext::default(),
        value_offset,
        "6.7.1",
    )?;
    let value = builder_helpers::parse_string_value(avp.value, value_offset, "6.7.1")?;
    route_records.push(Redacted::from(value));
    Ok(())
}

fn parse_additional_avp(
    avp: &RawAvp<'_>,
    ctx: DecodeContext,
    offset: usize,
    value_offset: usize,
    role: AuthorizationRole,
) -> Result<Option<SwmAdditionalAvp>, DecodeError> {
    let key = avp.header.key();
    if authorization_core_key(key) || wrong_role_key(key, role) {
        return Err(forbidden_error(offset, role.section()));
    }
    if let Some(definition) = find_definition(key) {
        if key == AvpKey::ietf(AVP_LOAD) {
            validate_m_bit_agnostic_flags(avp, false, offset, role.section())?;
        } else {
            lifecycle::validate_flags(&avp.header, definition.flags(), offset, role.section())?;
        }
        validate_known_extension_value(
            avp,
            definition,
            ctx,
            value_offset,
            role,
            ValueValidationPurpose::Decode,
        )?;
        return lifecycle::retain_additional_avp(avp, ctx, value_offset).map(Some);
    }
    if avp.header.flags.is_mandatory() || ctx.unknown_ie_policy == UnknownIePolicy::Reject {
        return Err(DecodeError::new(DecodeErrorCode::UnknownCriticalIe, offset)
            .with_spec_ref(SpecRef::new("ietf", "RFC6733", "4.1")));
    }
    if ctx.unknown_ie_policy == UnknownIePolicy::Drop {
        Ok(None)
    } else {
        Ok(Some(SwmAdditionalAvp::from_raw(avp)))
    }
}

fn push_additional(
    avp: SwmAdditionalAvp,
    key: AvpKey,
    offset: usize,
    role: AuthorizationRole,
    avps: &mut Vec<SwmAdditionalAvp>,
    keys: &mut HashSet<AvpKey>,
) -> Result<(), DecodeError> {
    if avps.len() >= MAX_ADDITIONAL_AVPS {
        return Err(count_error(offset));
    }
    if !additional_key_is_repeatable(key, role) && !keys.insert(key) {
        return Err(duplicate_error(offset));
    }
    avps.push(avp);
    Ok(())
}

fn validate_vendor_definition(avp: &RawAvp<'_>, offset: usize) -> Result<(), DecodeError> {
    if super::dictionary().find_avp(avp.header.key()).is_none() {
        return Err(decode_error(
            "SWm authorization vendor AVP definition is missing",
            offset,
            "7.3",
        ));
    }
    validate_m_bit_agnostic_flags(avp, true, offset, "7.2.3.1")
}

fn validate_m_bit_agnostic_flags(
    avp: &RawAvp<'_>,
    vendor_specific: bool,
    offset: usize,
    section: &'static str,
) -> Result<(), DecodeError> {
    if avp.header.flags.is_vendor_specific() != vendor_specific || avp.header.flags.is_protected() {
        return Err(decode_error(
            "SWm authorization AVP must use the specified V/P flags",
            offset.saturating_add(4),
            section,
        ));
    }
    Ok(())
}

fn validate_dictionary_definition(
    avp: &RawAvp<'_>,
    offset: usize,
    section: &'static str,
) -> Result<(), DecodeError> {
    let definition = find_definition(avp.header.key()).ok_or_else(|| {
        decode_error(
            "SWm authorization AVP definition is missing",
            offset,
            section,
        )
    })?;
    lifecycle::validate_flags(&avp.header, definition.flags(), offset, section)
}

fn require_request_field<T>(
    field: Option<T>,
    code: AvpCode,
    reason: &'static str,
    message: &Message<'_>,
    command: CommandCode,
    section: &'static str,
) -> Result<T, DiameterParserError> {
    field.ok_or_else(|| {
        let error = decode_error(reason, DIAMETER_HEADER_LEN, section);
        match find_definition(AvpKey::ietf(code)) {
            Some(definition) => DiameterParserError::missing_for_definition(
                message,
                error,
                definition,
                APPLICATION_ID,
                command,
            ),
            None => DiameterParserError::decoded(message, error),
        }
    })
}

fn require_answer_field<T>(
    field: Option<T>,
    reason: &'static str,
    section: &'static str,
) -> Result<T, DecodeError> {
    field.ok_or_else(|| decode_error(reason, DIAMETER_HEADER_LEN, section))
}

fn validate_result_code_decode(result_code: u32, section: &'static str) -> Result<(), DecodeError> {
    if result_code < 1000 {
        Err(enum_error(
            "Diameter Result-Code",
            result_code,
            DIAMETER_HEADER_LEN,
            "RFC6733",
            section,
        ))
    } else {
        Ok(())
    }
}

fn validate_result_error_bit(
    message: &Message<'_>,
    result_code: u32,
    section: &'static str,
) -> Result<(), DecodeError> {
    let error_bit = message.header.flags.is_error();
    let valid = match result_code / 1000 {
        3 => error_bit,
        1 | 2 | 4 => !error_bit,
        // RFC 6733 sections 7.1 and 7.1.5 treat 5xxx and unrecognized
        // families as permanent failures. They normally use the application
        // CCF with E clear, but may use generic section 7.2 E-bit grammar when
        // that command-specific answer cannot be composed.
        _ => true,
    };
    if !valid {
        Err(decode_error(
            "SWm authorization answer E bit does not match result family",
            4,
            section,
        ))
    } else {
        Ok(())
    }
}

fn enum_error(
    field: &'static str,
    value: u32,
    offset: usize,
    document: &'static str,
    section: &'static str,
) -> DecodeError {
    DecodeError::new(
        DecodeErrorCode::InvalidEnumValue {
            field,
            value: u64::from(value),
        },
        offset,
    )
    .with_spec_ref(SpecRef::new("ietf", document, section))
}

fn forbidden_error(offset: usize, section: &'static str) -> DecodeError {
    decode_error(
        "SWm authorization AVP is forbidden, has the wrong role, or has the wrong vendor",
        offset,
        section,
    )
}

fn count_error(offset: usize) -> DecodeError {
    DecodeError::new(DecodeErrorCode::IeCountExceeded, offset)
        .with_spec_ref(SpecRef::new("3gpp", "TS29273", "7.2.2"))
}

fn duplicate_error(offset: usize) -> DecodeError {
    DecodeError::new(DecodeErrorCode::DuplicateIe, offset)
        .with_spec_ref(SpecRef::new("3gpp", "TS29273", "7.2.2"))
}

fn decode_error(reason: &'static str, offset: usize, section: &'static str) -> DecodeError {
    DecodeError::new(DecodeErrorCode::Structural { reason }, offset)
        .with_spec_ref(SpecRef::new("3gpp", "TS29273", section))
}

fn validate_re_auth_request_for_encode(
    request: &SwmReAuthRequest,
    ctx: EncodeContext,
) -> Result<(), EncodeError> {
    validate_identity_fields(
        &[request.session_id.as_ref(), request.user_name.as_ref()],
        "SWm RAR Session-Id and User-Name must not be empty",
        "7.2.2.4.1",
    )?;
    validate_diameter_identity_fields(
        &[
            request.origin_host.as_ref(),
            request.origin_realm.as_ref(),
            request.destination_realm.as_ref(),
            request.destination_host.as_ref(),
        ],
        "SWm RAR routing identities must be nonempty ASCII DiameterIdentity values",
        "7.2.2.4.1",
    )?;
    if request.re_auth_request_type != SwmReAuthRequestType::AuthorizeOnly {
        return Err(encode_error(
            "SWm authorization-update RAR requires AUTHORIZE_ONLY",
            "7.1.2.5",
        ));
    }
    validate_route_records(&request.route_records, "7.2.2.4.1")?;
    validate_additional_for_encode(
        &request.additional_avps,
        AuthorizationRole::RarRequest,
        None,
        ctx,
    )
}

fn validate_re_auth_answer_for_encode(
    request: &SwmReAuthRequestEnvelope,
    answer: &SwmReAuthAnswer,
    ctx: EncodeContext,
) -> Result<(), EncodeError> {
    validate_envelope_for_encode(request.proxiable, request.proxy_infos.len(), "7.2.2.4.2")?;
    let session_id = answer
        .session_id
        .as_ref()
        .ok_or_else(|| encode_error("originated SWm RAA requires Session-Id", "7.2.2.4.2"))?;
    let user_name = answer
        .user_name
        .as_ref()
        .ok_or_else(|| encode_error("originated SWm RAA requires User-Name", "7.2.2.4.2"))?;
    validate_identity_fields(
        &[session_id.as_ref(), user_name.as_ref()],
        "SWm RAA Session-Id and User-Name must not be empty",
        "7.2.2.4.2",
    )?;
    validate_diameter_identity_fields(
        &[answer.origin_host.as_ref(), answer.origin_realm.as_ref()],
        "SWm RAA origin identities must be nonempty ASCII DiameterIdentity values",
        "7.2.2.4.2",
    )?;
    if session_id != &request.request.session_id {
        return Err(encode_error(
            "SWm RAA Session-Id does not match its RAR",
            "7.2.2.4.2",
        ));
    }
    if user_name != &request.request.user_name {
        return Err(encode_error(
            "SWm RAA User-Name does not match its RAR",
            "7.2.2.4.2",
        ));
    }
    if matches!(answer.result, SwmReAuthResult::Other(_)) {
        return Err(encode_error(
            "typed SWm RAA builder supports only fully modeled authorization-update results",
            "7.2.2.4.2",
        ));
    }
    if contains_redirect_avp(&answer.additional_avps) {
        return Err(encode_error(
            "typed SWm RAA builder does not originate redirect AVP context",
            "7.2.2.4.2",
        ));
    }
    validate_answer_timers_for_encode(
        answer.authorization_lifetime,
        None,
        answer.re_auth_request_type,
        "7.2.2.4.2",
    )?;
    validate_result_code_for_encode(answer.result.result_code(), "7.2.2.4.2")?;
    validate_additional_for_encode(
        &answer.additional_avps,
        AuthorizationRole::RaaAnswer,
        Some(&request.request.additional_avps),
        ctx,
    )
}

fn validate_authorization_request_for_encode(
    request: &SwmAuthorizationRequest,
    ctx: EncodeContext,
) -> Result<(), EncodeError> {
    validate_identity_fields(
        &[request.session_id.as_ref(), request.user_name.as_ref()],
        "SWm AAR Session-Id and User-Name must not be empty",
        "7.2.2.1.3",
    )?;
    validate_diameter_identity_fields(
        &[
            request.origin_host.as_ref(),
            request.origin_realm.as_ref(),
            request.destination_realm.as_ref(),
        ],
        "SWm AAR routing identities must be nonempty ASCII DiameterIdentity values",
        "7.2.2.1.3",
    )?;
    if request
        .destination_host
        .as_ref()
        .is_some_and(|value| value.as_ref().is_empty() || !value.as_ref().is_ascii())
    {
        return Err(encode_error(
            "SWm AAR Destination-Host must be a nonempty ASCII DiameterIdentity",
            "7.2.2.1.3",
        ));
    }
    if !request.auth_request_type.is_authorize_only() {
        return Err(encode_error(
            "SWm authorization-update AAR requires AUTHORIZE_ONLY",
            "7.1.2.5",
        ));
    }
    validate_route_records(&request.route_records, "7.2.2.1.3")?;
    validate_additional_for_encode(
        &request.additional_avps,
        AuthorizationRole::AarRequest,
        None,
        ctx,
    )
}

fn validate_authorization_answer_for_encode(
    request: &SwmAuthorizationRequestEnvelope,
    answer: &SwmAuthorizationAnswer,
    ctx: EncodeContext,
) -> Result<(), EncodeError> {
    validate_envelope_for_encode(request.proxiable, request.proxy_infos.len(), "7.2.2.1.4")?;
    let session_id = answer
        .session_id
        .as_ref()
        .ok_or_else(|| encode_error("originated SWm AAA requires Session-Id", "7.2.2.1.4"))?;
    let auth_request_type = answer.auth_request_type.ok_or_else(|| {
        encode_error("originated SWm AAA requires Auth-Request-Type", "7.2.2.1.4")
    })?;
    let user_name = answer
        .user_name
        .as_ref()
        .ok_or_else(|| encode_error("originated SWm AAA requires User-Name", "7.2.2.1.4"))?;
    validate_identity_fields(
        &[session_id.as_ref(), user_name.as_ref()],
        "SWm AAA Session-Id and User-Name must not be empty",
        "7.2.2.1.4",
    )?;
    validate_diameter_identity_fields(
        &[answer.origin_host.as_ref(), answer.origin_realm.as_ref()],
        "SWm AAA origin identities must be nonempty ASCII DiameterIdentity values",
        "7.2.2.1.4",
    )?;
    if session_id != &request.request.session_id {
        return Err(encode_error(
            "SWm AAA Session-Id does not match its AAR",
            "7.2.2.1.4",
        ));
    }
    if user_name != &request.request.user_name {
        return Err(encode_error(
            "SWm AAA User-Name does not match its AAR",
            "7.2.2.1.4",
        ));
    }
    if auth_request_type != request.request.auth_request_type
        || !auth_request_type.is_authorize_only()
    {
        return Err(encode_error(
            "SWm AAA Auth-Request-Type does not match its AAR",
            "7.2.2.1.4",
        ));
    }
    if answer.result.category() == SwmResultCategory::Success
        && !authorization_lifetime_satisfies_hint(
            request.request.authorization_lifetime,
            answer.authorization_lifetime,
        )
    {
        return Err(encode_error(
            "success-class SWm AAA must honor the AAR Authorization-Lifetime ceiling",
            "8.9",
        ));
    }
    validate_result_code_for_encode(answer.result.code(), "7.2.2.1.4")?;
    if matches!(answer.result, SwmDiameterResult::Experimental { code, .. }
        if builder_helpers::result_code_requires_error_bit(code))
    {
        return Err(encode_error(
            "SWm AAA cannot encode a protocol-error class Experimental-Result without the generic Result-Code grammar",
            "7.2.2.1.4",
        ));
    }
    if answer.result.code() == RESULT_CODE_REDIRECT_INDICATION
        || contains_redirect_avp(&answer.additional_avps)
    {
        return Err(encode_error(
            "typed SWm AAA builder does not originate redirect result context",
            "7.2.2.1.4",
        ));
    }
    if answer.apn_configuration.is_some() && !answer.result.is_diameter_success() {
        return Err(encode_error(
            "SWm AAA APN-Configuration is valid only with DIAMETER_SUCCESS",
            "7.2.2.1.4",
        ));
    }
    validate_answer_timers_for_encode(
        answer.authorization_lifetime,
        answer.session_timeout,
        answer.re_auth_request_type,
        "7.2.2.1.4",
    )?;
    if let Some(apn) = answer.apn_configuration.as_ref() {
        validate_authorization_apn(apn.core())
            .map_err(|reason| encode_error(reason, "7.2.2.1.4"))?;
    }
    validate_additional_for_encode(
        &answer.additional_avps,
        AuthorizationRole::AaaAnswer,
        Some(&request.request.additional_avps),
        ctx,
    )
}

fn validate_authorization_apn(apn: &ApnConfiguration) -> Result<(), &'static str> {
    if apn.context_identifier == 0 {
        return Err("SWm AAA APN-Configuration Context-Identifier must not be zero");
    }
    if apn.service_selection.as_ref().is_empty() {
        return Err("SWm AAA APN-Configuration Service-Selection must not be empty");
    }
    Ok(())
}

fn validate_answer_timers_for_encode(
    authorization_lifetime: Option<u32>,
    session_timeout: Option<u32>,
    re_auth_request_type: Option<SwmReAuthRequestType>,
    section: &'static str,
) -> Result<(), EncodeError> {
    validate_answer_timer_values(
        authorization_lifetime,
        session_timeout,
        re_auth_request_type,
    )
    .map_err(|reason| encode_error(reason, section))
}

fn validate_answer_timers_decode(
    authorization_lifetime: Option<u32>,
    session_timeout: Option<u32>,
    re_auth_request_type: Option<SwmReAuthRequestType>,
    section: &'static str,
) -> Result<(), DecodeError> {
    validate_answer_timer_values(
        authorization_lifetime,
        session_timeout,
        re_auth_request_type,
    )
    .map_err(|reason| decode_error(reason, DIAMETER_HEADER_LEN, section))
}

pub(super) fn validate_answer_timer_values(
    authorization_lifetime: Option<u32>,
    session_timeout: Option<u32>,
    re_auth_request_type: Option<SwmReAuthRequestType>,
) -> Result<(), &'static str> {
    if authorization_lifetime.is_some_and(|lifetime| lifetime > 0) && re_auth_request_type.is_none()
    {
        return Err("positive Authorization-Lifetime in an answer requires Re-Auth-Request-Type");
    }
    if matches!(
        (authorization_lifetime, session_timeout),
        (Some(lifetime), Some(timeout)) if timeout != 0 && timeout < lifetime
    ) {
        return Err("Session-Timeout must not be smaller than Authorization-Lifetime");
    }
    Ok(())
}

fn authorization_lifetime_satisfies_hint(
    requested_maximum: Option<u32>,
    answered_lifetime: Option<u32>,
) -> bool {
    match requested_maximum {
        Some(maximum) => answered_lifetime.is_some_and(|lifetime| lifetime <= maximum),
        None => true,
    }
}

fn contains_redirect_avp(avps: &[SwmAdditionalAvp]) -> bool {
    avps.iter().any(|avp| {
        matches!(
            avp.header().key(),
            key if key == AvpKey::ietf(base::AVP_REDIRECT_HOST)
                || key == AvpKey::ietf(base::AVP_REDIRECT_HOST_USAGE)
                || key == AvpKey::ietf(base::AVP_REDIRECT_MAX_CACHE_TIME)
        )
    })
}

fn validate_envelope_for_encode(
    proxiable: bool,
    proxy_count: usize,
    section: &'static str,
) -> Result<(), EncodeError> {
    if !proxiable {
        return Err(encode_error(
            "SWm authorization command must preserve the P bit",
            section,
        ));
    }
    if proxy_count > MAX_PROXY_INFOS {
        return Err(encode_error(
            "SWm authorization Proxy-Info count exceeds the typed boundary",
            section,
        ));
    }
    Ok(())
}

fn validate_identity_fields(
    values: &[&str],
    reason: &'static str,
    section: &'static str,
) -> Result<(), EncodeError> {
    if values.iter().any(|value| value.is_empty()) {
        Err(encode_error(reason, section))
    } else {
        Ok(())
    }
}

fn validate_diameter_identity_fields(
    values: &[&str],
    reason: &'static str,
    section: &'static str,
) -> Result<(), EncodeError> {
    if values
        .iter()
        .any(|value| value.is_empty() || !value.is_ascii())
    {
        Err(encode_error(reason, section))
    } else {
        Ok(())
    }
}

fn validate_route_records(
    records: &[Redacted<String>],
    section: &'static str,
) -> Result<(), EncodeError> {
    if records.len() > MAX_ROUTE_RECORDS {
        return Err(encode_error(
            "SWm authorization Route-Record count exceeds the typed boundary",
            section,
        ));
    }
    if records
        .iter()
        .any(|record| record.as_ref().is_empty() || !record.as_ref().is_ascii())
    {
        return Err(encode_error(
            "SWm authorization Route-Record must be a nonempty ASCII DiameterIdentity",
            section,
        ));
    }
    Ok(())
}

fn validate_result_code_for_encode(
    result_code: u32,
    section: &'static str,
) -> Result<(), EncodeError> {
    if result_code < 1000 {
        Err(encode_error(
            "SWm authorization result is outside Diameter result ranges",
            section,
        ))
    } else {
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthorizationRole {
    RarRequest,
    RaaAnswer,
    AarRequest,
    AaaAnswer,
}

impl AuthorizationRole {
    const fn section(self) -> &'static str {
        match self {
            Self::RarRequest => "7.2.2.4.1",
            Self::RaaAnswer => "7.2.2.4.2",
            Self::AarRequest => "7.2.2.1.3",
            Self::AaaAnswer => "7.2.2.1.4",
        }
    }

    const fn is_answer(self) -> bool {
        matches!(self, Self::RaaAnswer | Self::AaaAnswer)
    }

    const fn command_definition(self) -> &'static CommandDefinition {
        match self {
            Self::RarRequest => &COMMAND_RE_AUTH_REQUEST,
            Self::RaaAnswer => &COMMAND_RE_AUTH_ANSWER,
            Self::AarRequest => &COMMAND_AA_REQUEST,
            Self::AaaAnswer => &COMMAND_AA_ANSWER,
        }
    }
}

fn validate_additional_for_encode(
    avps: &[SwmAdditionalAvp],
    role: AuthorizationRole,
    request_avps: Option<&[SwmAdditionalAvp]>,
    ctx: EncodeContext,
) -> Result<(), EncodeError> {
    if avps.len() > MAX_ADDITIONAL_AVPS {
        return Err(encode_error(
            "SWm authorization additional AVP count exceeds the typed boundary",
            role.section(),
        ));
    }
    super::session_state::validate_class_additional_avps_for_encode(avps)?;
    let mut seen = HashSet::new();
    for avp in avps {
        let key = avp.header().key();
        if authorization_core_key(key) || key == AvpKey::ietf(base::AVP_PROXY_INFO) {
            return Err(encode_error(
                "SWm authorization additional AVP duplicates command-owned state",
                role.section(),
            ));
        }
        if wrong_role_key(key, role) {
            return Err(encode_error(
                "SWm authorization additional AVP is invalid for this command role",
                role.section(),
            ));
        }
        if !additional_key_is_repeatable(key, role) && !seen.insert(key) {
            return Err(encode_error(
                "SWm authorization additional singleton AVP is duplicated",
                role.section(),
            ));
        }
        validate_additional_for_encode_one(avp, role, ctx)?;
    }
    if let Some(request_avps) = request_avps {
        lifecycle::validate_offered_overload_control(
            request_avps,
            avps,
            DecodeContext {
                max_message_len: ctx.max_message_len,
                unknown_ie_policy: UnknownIePolicy::Preserve,
                ..DecodeContext::default()
            },
        )
        .map_err(|_| {
            encode_error(
                "SWm authorization answer overload-control state is inconsistent",
                role.section(),
            )
        })?;
    }
    Ok(())
}

fn validate_additional_for_encode_one(
    avp: &SwmAdditionalAvp,
    role: AuthorizationRole,
    ctx: EncodeContext,
) -> Result<(), EncodeError> {
    if avp.header().key() == AvpKey::ietf(AVP_LOAD) && avp.header().flags.is_mandatory() {
        return Err(encode_error(
            "SWm authorization Load must clear M when encoded",
            role.section(),
        ));
    }
    if let Some(definition) = find_definition(avp.header().key()) {
        lifecycle::validate_flags_for_encode(avp.header(), definition.flags(), role.section())?;
        let raw = RawAvp {
            header: avp.header().clone(),
            value: avp.value(),
            padding: &[],
        };
        validate_known_extension_value(
            &raw,
            definition,
            DecodeContext {
                max_message_len: ctx.max_message_len,
                unknown_ie_policy: UnknownIePolicy::Preserve,
                ..DecodeContext::default()
            },
            0,
            role,
            ValueValidationPurpose::Encode,
        )
        .map_err(|_| {
            encode_error(
                "SWm authorization known additional AVP violates its dictionary type",
                role.section(),
            )
        })?;
    } else if avp.header().flags.is_mandatory() {
        return Err(encode_error(
            "SWm authorization unknown extension AVP must clear the M bit",
            role.section(),
        ));
    }
    let mut proof = BytesMut::new();
    avp.append_to(&mut proof, ctx)
}

fn authorization_core_key(key: AvpKey) -> bool {
    matches!(
        key,
        key if key == AvpKey::ietf(base::AVP_SESSION_ID)
            || key == AvpKey::ietf(base::AVP_ORIGIN_HOST)
            || key == AvpKey::ietf(base::AVP_ORIGIN_REALM)
            || key == AvpKey::ietf(base::AVP_DESTINATION_REALM)
            || key == AvpKey::ietf(base::AVP_DESTINATION_HOST)
            || key == AvpKey::ietf(base::AVP_AUTH_APPLICATION_ID)
            || key == AvpKey::ietf(base::AVP_RE_AUTH_REQUEST_TYPE)
            || key == AvpKey::ietf(base::AVP_AUTHORIZATION_LIFETIME)
            || key == AvpKey::ietf(base::AVP_AUTH_GRACE_PERIOD)
            || key == AvpKey::ietf(base::AVP_SESSION_TIMEOUT)
            || key == AvpKey::ietf(AVP_AUTH_REQUEST_TYPE)
            || key == AvpKey::ietf(base::AVP_USER_NAME)
            || key == AvpKey::ietf(base::AVP_RESULT_CODE)
            || key == AvpKey::ietf(base::AVP_EXPERIMENTAL_RESULT)
            || key == AvpKey::ietf(AVP_DRMP)
            || key == AvpKey::ietf(base::AVP_ROUTE_RECORD)
            || key == AvpKey::vendor(AVP_AAR_FLAGS, VENDOR_ID_3GPP)
            || key == AvpKey::vendor(AVP_UE_LOCAL_IP_ADDRESS, VENDOR_ID_3GPP)
            || key == AvpKey::vendor(AVP_HIGH_PRIORITY_ACCESS_INFO, VENDOR_ID_3GPP)
            || key == AvpKey::vendor(super::AVP_APN_CONFIGURATION, VENDOR_ID_3GPP)
    )
}

fn wrong_role_key(key: AvpKey, role: AuthorizationRole) -> bool {
    role.command_definition()
        .find_avp_rule(key)
        .is_some_and(|rule| rule.cardinality().is_forbidden())
}

fn additional_key_is_repeatable(key: AvpKey, role: AuthorizationRole) -> bool {
    role.command_definition().allows_multiple(key)
}

fn validate_known_extension_value(
    avp: &RawAvp<'_>,
    definition: &AvpDefinition,
    ctx: DecodeContext,
    value_offset: usize,
    role: AuthorizationRole,
    purpose: ValueValidationPurpose,
) -> Result<(), DecodeError> {
    if role.is_answer() {
        lifecycle::validate_known_answer_extension_value(
            avp,
            definition,
            ctx,
            value_offset,
            purpose,
        )
    } else {
        lifecycle::validate_known_request_extension_value(
            avp,
            definition,
            ctx,
            value_offset,
            purpose,
        )
    }?;
    Ok(())
}

fn find_definition(key: AvpKey) -> Option<&'static AvpDefinition> {
    base::dictionary()
        .find_avp(key)
        .or_else(|| super::dictionary().find_avp(key))
}

fn encode_error(reason: &'static str, section: &'static str) -> EncodeError {
    EncodeError::new(EncodeErrorCode::Structural { reason })
        .with_spec_ref(SpecRef::new("3gpp", "TS29273", section))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn re_auth_replay_payload_requires_the_same_proxiable_bit() {
        let initial = SwmReAuthRequestEnvelope {
            transaction: SwmDiameterTransaction::new(1, 2),
            proxiable: true,
            potentially_retransmitted: false,
            expected_answer_peer: None,
            request: SwmReAuthRequest {
                session_id: Redacted::from("synthetic-session.example"),
                origin_host: Redacted::from("origin-host.example"),
                origin_realm: Redacted::from("origin-realm.example"),
                destination_realm: Redacted::from("destination-realm.example"),
                destination_host: Redacted::from("destination-host.example"),
                re_auth_request_type: SwmReAuthRequestType::AuthorizeOnly,
                user_name: Redacted::from("synthetic-user@identity.example"),
                drmp: None,
                route_records: Vec::new(),
                additional_avps: Vec::new(),
            },
            proxy_infos: Vec::new(),
        };
        let mut changed = initial.clone();
        changed.proxiable = false;

        assert!(!initial.same_replay_payload(&changed));
    }
}
