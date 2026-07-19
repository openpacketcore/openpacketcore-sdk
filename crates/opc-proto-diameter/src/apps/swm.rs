//! 3GPP SWm Diameter dictionary subset and typed helpers.
//!
//! This module covers the ePDG-restricted SWm DER/DEA exchange that carries
//! EAP payloads between the ePDG and an AAA/DRA peer, the request-bound
//! Session-Termination STR/STA lifecycle exchange, plus a bounded
//! subscription-profile extension surface for APN-Configuration, its default
//! Context-Identifier, Service-Selection, and the TS 29.273 emergency attach
//! sequence. The top-level default pointer is accepted under the DEA
//! extension-AVP wildcard; it is not part of the baseline SWm DEA command ABNF.
//! This module does not implement transport state, realm routing, local
//! emergency-access policy, or IKEv2 policy. A live Diameter client must still
//! consume a pending request keyed by peer connection and Hop-by-Hop Identifier
//! before passing the parsed transaction envelopes to emergency evidence; the
//! codec enforces identifier equality but cannot prove transport liveness.
//!
//! @spec 3GPP TS29273
//! @spec 3GPP TS29272 7.3
//! @spec IETF RFC4072
//! @spec IETF RFC5778
//! @conformance scaffold — see CONFORMANCE.md

use bytes::BytesMut;
use hmac::{Hmac, Mac};
use opc_protocol::{
    DecodeContext, DecodeError, DecodeErrorCode, EncodeContext, EncodeError, EncodeErrorCode,
    SpecRef,
};
use opc_types::{Imei, Imei15};
use sha2::Sha256;
use std::{collections::HashSet, error::Error, fmt};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use super::builder_helpers;
use super::VENDOR_ID_3GPP;
use crate::avp::dictionary::Redacted;
use crate::base;
use crate::dictionary::{
    ApplicationDefinition, AvpCardinality, AvpDataType, AvpDefinition, AvpFlagRules, AvpKey,
    CommandAvpRule, CommandDefinition, CommandKind, Dictionary, FlagRequirement,
};
use crate::parser_error::DiameterParserError;
use crate::{ApplicationId, AvpCode, AvpHeader, CommandCode, Message, OwnedMessage, VendorId};

mod lifecycle;

pub use lifecycle::*;

/// 3GPP SWm application identifier.
pub const APPLICATION_ID: ApplicationId = ApplicationId::new(16_777_264);

/// Diameter-EAP command code (RFC 4072).
pub const COMMAND_DIAMETER_EAP: CommandCode = CommandCode::new(268);

/// EAP-Payload AVP code (RFC 4072).
pub const AVP_EAP_PAYLOAD: AvpCode = AvpCode::new(462);
/// EAP-Reissued-Payload AVP code (RFC 4072).
pub const AVP_EAP_REISSUED_PAYLOAD: AvpCode = AvpCode::new(463);
/// EAP-Master-Session-Key AVP code (RFC 4072).
pub const AVP_EAP_MASTER_SESSION_KEY: AvpCode = AvpCode::new(464);
/// Auth-Request-Type AVP code.
pub const AVP_AUTH_REQUEST_TYPE: AvpCode = AvpCode::new(274);
/// State AVP code.
pub const AVP_STATE: AvpCode = AvpCode::new(24);
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

/// Emergency-Indication bit in the Emergency-Services AVP.
pub const EMERGENCY_SERVICES_EMERGENCY_INDICATION: u32 = 1 << 0;

/// 3GPP experimental result requesting emergency IMEI recovery.
pub const DIAMETER_ERROR_USER_UNKNOWN: u32 = 5001;
/// Width of the TS 33.402 Annex A.4 unauthenticated-emergency MSK.
pub const UNAUTHENTICATED_EMERGENCY_MSK_LEN: usize = 32;
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

/// Auth-Request-Type value for AUTHORIZE_AUTHENTICATE.
pub const AUTH_REQUEST_TYPE_AUTHORIZE_AUTHENTICATE: u32 = 3;

/// 3GPP SWm application definition.
pub const APPLICATION: ApplicationDefinition = ApplicationDefinition::new(
    APPLICATION_ID,
    "3GPP SWm",
    Some(VENDOR_ID_3GPP),
    SpecRef::new("3gpp", "TS29273", "SWm Diameter application"),
);

static SWM_REQUEST_AVP_RULES: [CommandAvpRule; 5] = [
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
        AvpKey::ietf(base::AVP_RESULT_CODE),
        AvpCardinality::Forbidden,
    ),
];

static SWM_ANSWER_AVP_RULES: [CommandAvpRule; 6] = [
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
];

static SWM_PROJECTED_PROFILE_ANSWER_AVP_RULES: [CommandAvpRule; 6] = [
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

const SWM_AVPS: [AvpDefinition; 35] = [
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
        SpecRef::new("ietf", "RFC6733", "6.12"),
    ),
    AvpDefinition::new(
        AvpKey::ietf(AVP_STATE),
        "State",
        AvpDataType::OctetString,
        AvpFlagRules::base_optional(),
        SpecRef::new("ietf", "RFC6733", "6.38"),
    ),
    AvpDefinition::new(
        AvpKey::ietf(AVP_DRMP),
        "DRMP",
        AvpDataType::Enumerated,
        AvpFlagRules::base_must_not_set_m(),
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
        AvpFlagRules::base_must_not_set_m(),
        SpecRef::new("3gpp", "TS29273", "7.2.3.1"),
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
        AvpFlagRules::base_mandatory(),
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
    ),
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
        AvpKey::vendor(AVP_EPS_SUBSCRIBED_QOS_PROFILE, VENDOR_ID_3GPP),
        "EPS-Subscribed-QoS-Profile",
        AvpDataType::Grouped,
        AvpFlagRules::vendor_specific(),
        SpecRef::new("3gpp", "TS29272", "7.3.37"),
    ),
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
    ),
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
    ),
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
];

const SWM_COMMANDS: [CommandDefinition; 4] = [
    COMMAND_DIAMETER_EAP_REQUEST,
    COMMAND_DIAMETER_EAP_ANSWER,
    COMMAND_SESSION_TERMINATION_REQUEST,
    COMMAND_SESSION_TERMINATION_ANSWER,
];

const SWM_PROJECTED_PROFILE_COMMANDS: [CommandDefinition; 4] = [
    COMMAND_DIAMETER_EAP_REQUEST,
    COMMAND_DIAMETER_EAP_ANSWER_PROJECTED_PROFILE,
    COMMAND_SESSION_TERMINATION_REQUEST,
    COMMAND_SESSION_TERMINATION_ANSWER,
];

/// Static SWm dictionary covering DER/DEA and the typed STR/STA lifecycle slice.
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
    /// AUTHORIZE_AUTHENTICATE.
    AuthorizeAuthenticate,
    /// Unknown or application-specific value.
    Other(u32),
}

impl AuthRequestType {
    /// Return the wire value.
    pub const fn value(self) -> u32 {
        match self {
            Self::AuthorizeAuthenticate => AUTH_REQUEST_TYPE_AUTHORIZE_AUTHENTICATE,
            Self::Other(v) => v,
        }
    }

    /// Parse from a wire value.
    pub const fn from_value(value: u32) -> Self {
        if value == AUTH_REQUEST_TYPE_AUTHORIZE_AUTHENTICATE {
            Self::AuthorizeAuthenticate
        } else {
            Self::Other(value)
        }
    }

    /// Return true for AUTHORIZE_AUTHENTICATE.
    pub const fn is_authorize_authenticate(self) -> bool {
        matches!(self, Self::AuthorizeAuthenticate)
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

/// A parsed SWm DER together with its immutable Diameter transaction IDs.
#[derive(PartialEq, Eq)]
pub struct SwmDiameterEapRequestEnvelope {
    transaction: SwmDiameterTransaction,
    request: SwmDiameterEapRequest,
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
            request,
        }
    }

    /// Borrow the typed DER facts.
    pub const fn request(&self) -> &SwmDiameterEapRequest {
        &self.request
    }

    /// Return the transaction IDs from the validated Diameter header.
    pub const fn transaction(&self) -> SwmDiameterTransaction {
        self.transaction
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
        Ok(SwmCorrelatedDiameterEapExchange {
            request: self,
            answer,
        })
    }
}

impl fmt::Debug for SwmDiameterEapRequestEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwmDiameterEapRequestEnvelope")
            .field("transaction", &self.transaction)
            .field("request", &self.request)
            .finish()
    }
}

/// A parsed SWm DEA together with its immutable Diameter transaction IDs.
#[derive(PartialEq, Eq)]
pub struct SwmDiameterEapAnswerEnvelope {
    transaction: SwmDiameterTransaction,
    answer: SwmDiameterEapAnswer,
}

/// Opaque request/answer pair with all SWm and Diameter correlation checked.
pub struct SwmCorrelatedDiameterEapExchange {
    request: SwmDiameterEapRequestEnvelope,
    answer: SwmDiameterEapAnswerEnvelope,
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
}

impl fmt::Debug for SwmCorrelatedDiameterEapExchange {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwmCorrelatedDiameterEapExchange")
            .field("transaction", &self.transaction())
            .field("request", &self.request())
            .field("answer", &self.answer())
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
            answer,
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
}

impl fmt::Debug for SwmDiameterEapAnswerEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwmDiameterEapAnswerEnvelope")
            .field("transaction", &self.transaction)
            .field("answer", &self.answer)
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
    /// The exchange carries another EAP round but no terminal authorization.
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

/// Allocation-Retention-Priority grouped AVP (3GPP TS 29.212 §5.3.32).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AllocationRetentionPriority {
    /// Priority-Level.
    pub priority_level: u32,
    /// Pre-emption-Capability.
    pub pre_emption_capability: Option<u32>,
    /// Pre-emption-Vulnerability.
    pub pre_emption_vulnerability: Option<u32>,
}

/// EPS-Subscribed-QoS-Profile grouped AVP (3GPP TS 29.272 §7.3.37).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpsSubscribedQosProfile {
    /// QoS-Class-Identifier.
    pub qos_class_identifier: u32,
    /// Allocation-Retention-Priority grouped child.
    pub allocation_retention_priority: AllocationRetentionPriority,
}

/// AMBR grouped AVP (3GPP TS 29.272 §7.3.41).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ambr {
    /// Max-Requested-Bandwidth-UL in bits per second.
    pub max_requested_bandwidth_ul: u32,
    /// Max-Requested-Bandwidth-DL in bits per second.
    pub max_requested_bandwidth_dl: u32,
}

/// APN-Configuration grouped AVP (3GPP TS 29.272 §7.3.35).
///
/// Models the minimal subscription subset useful on a SWm DEA:
/// Context-Identifier, Service-Selection, PDN-Type, and the optional
/// EPS-Subscribed-QoS-Profile and AMBR children. The remaining TS 29.272
/// children (for example VPLMN-Dynamic-Address-Allowed, PDN-GW-Allocation-Type,
/// MIP6-Agent-Info, and 3GPP-Charging-Characteristics) are deliberately not
/// modeled yet; they fall through to the unknown-AVP policy.
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
    /// Auth-Request-Type.
    pub auth_request_type: AuthRequestType,
    /// EAP-Payload (redacted in diagnostic output).
    pub eap_payload: Redacted<Vec<u8>>,
    /// Optional Emergency-Services request bitmask.
    pub emergency_services: Option<SwmEmergencyServices>,
    /// Optional device identity forwarded after DEVICE_IDENTITY recovery.
    pub terminal_information: Option<SwmTerminalInformation>,
    /// State AVP values.
    pub state_avps: Vec<Vec<u8>>,
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
            .field("auth_request_type", &self.auth_request_type)
            .field("eap_payload", &self.eap_payload)
            .field("emergency_services", &self.emergency_services)
            .field("terminal_information", &self.terminal_information)
            .field("state_avps", &self.state_avps.len())
            .finish()
    }
}

/// A SWm Diameter-EAP-Answer (DEA).
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
    /// APN-Configuration grouped AVPs (only their count appears in
    /// diagnostic output).
    pub apn_configurations: Vec<ApnConfiguration>,
    /// Permanent identity returned as Mobile-Node-Identifier.
    pub mobile_node_identifier: Option<Redacted<String>>,
    /// EAP-Payload (redacted in diagnostic output).
    pub eap_payload: Option<Redacted<Vec<u8>>>,
    /// EAP-Reissued-Payload (redacted in diagnostic output).
    pub eap_reissued_payload: Option<Redacted<Vec<u8>>>,
    /// Error-Message.
    pub error_message: Option<String>,
    /// State AVP values.
    pub state_avps: Vec<Vec<u8>>,
    /// EAP-Master-Session-Key (redacted in diagnostic output).
    pub eap_master_session_key: Option<Redacted<Vec<u8>>>,
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
            .field("service_selection", &self.service_selection)
            .field(
                "default_context_identifier",
                &self.default_context_identifier,
            )
            .field("apn_configurations", &self.apn_configurations.len())
            .field("mobile_node_identifier", &self.mobile_node_identifier)
            .field("eap_payload", &self.eap_payload)
            .field("eap_reissued_payload", &self.eap_reissued_payload)
            .field("error_message", &self.error_message)
            .field("state_avps", &self.state_avps.len())
            .field("eap_master_session_key", &self.eap_master_session_key)
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
    fn validate_for_encode(&self) -> Result<(), EncodeError> {
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
            if service_selection.as_ref().is_empty() {
                return Err(encode_structural_error(
                    "SWm DEA Service-Selection must not be empty when present",
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
    /// terminal success observation. Emergency access requires the separate
    /// request-correlated evidence constructor.
    pub fn authorization_outcome(&self) -> SwmAuthorizationOutcome {
        if self.result.is_diameter_success()
            && option_redacted_bytes_has_material(&self.eap_master_session_key)
        {
            return SwmAuthorizationOutcome::MskBearingSuccess;
        }
        if option_redacted_bytes_has_material(&self.eap_payload)
            || option_redacted_bytes_has_material(&self.eap_reissued_payload)
        {
            SwmAuthorizationOutcome::EapInProgress
        } else {
            SwmAuthorizationOutcome::NotAuthorized
        }
    }

    /// Resolve the declared subscription default APN configuration.
    ///
    /// This accessor fails safe and returns `None` unless the answer carries
    /// exact `DIAMETER_SUCCESS` and the profile has a pointer that resolves
    /// without violating any child identifier or Service-Selection invariant.
    pub fn default_apn_configuration(&self) -> Option<&ApnConfiguration> {
        validate_apn_profile(self).ok()?;
        let default_context_identifier = self.default_context_identifier?;
        self.apn_configurations
            .iter()
            .find(|apn| apn.context_identifier == default_context_identifier)
    }
}

/// Build a SWm Diameter-EAP-Request message.
pub fn build_swm_diameter_eap_request(
    request: &SwmDiameterEapRequest,
    hop_by_hop_identifier: u32,
    end_to_end_identifier: u32,
    ctx: EncodeContext,
) -> Result<OwnedMessage, EncodeError> {
    request.validate_for_encode()?;
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
    for state in &request.state_avps {
        builder_helpers::append_octet_string_avp(&mut raw_avps, AVP_STATE, state, false, ctx)?;
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
    builder_helpers::append_octet_string_avp(
        &mut raw_avps,
        AVP_EAP_PAYLOAD,
        request.eap_payload.as_ref(),
        true,
        ctx,
    )?;
    builder_helpers::build_message(
        builder_helpers::app_request_flags(),
        COMMAND_DIAMETER_EAP,
        APPLICATION_ID,
        raw_avps,
        hop_by_hop_identifier,
        end_to_end_identifier,
        ctx,
        "DER",
    )
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
    builder_helpers::ensure_app_header(
        message,
        COMMAND_DIAMETER_EAP,
        APPLICATION_ID,
        CommandKind::Request,
        "DER",
    )
    .map_err(|error| DiameterParserError::decoded(message, error))?;
    let mut session_id = None;
    let mut auth_application_id = None;
    let mut origin_host = None;
    let mut origin_realm = None;
    let mut destination_realm = None;
    let mut destination_host = None;
    let mut user_name = None;
    let mut auth_request_type = None;
    let mut eap_payload = None;
    let mut emergency_services = None;
    let mut terminal_information = None;
    let mut state_avps = Vec::new();
    let mut terminal_missing_imei = None;
    let parse_result = builder_helpers::for_each_avp(
        message.raw_avps,
        ctx,
        crate::DIAMETER_HEADER_LEN,
        0,
        |offset, avp| {
            let value_offset = builder_helpers::offset_add(offset, avp.header.header_len(), "DER")?;
            let code = avp.header.code;
            if let Some(vendor_id) = avp.header.vendor_id {
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
                } else {
                    builder_helpers::handle_unknown_avp(ctx, &avp, offset, "DER")?;
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
            } else if code == AVP_AUTH_REQUEST_TYPE {
                let value = builder_helpers::parse_u32_value(avp.value, value_offset, "6.12")?;
                builder_helpers::set_once(
                    &mut auth_request_type,
                    AuthRequestType::from_value(value),
                    offset,
                    "6.12",
                )?;
            } else if code == AVP_EAP_PAYLOAD {
                builder_helpers::set_once(
                    &mut eap_payload,
                    Redacted::from(avp.value.to_vec()),
                    offset,
                    "4.1",
                )?;
            } else if code == AVP_STATE {
                state_avps.push(avp.value.to_vec());
            } else {
                builder_helpers::handle_unknown_avp(ctx, &avp, offset, "DER")?;
            }
            Ok(())
        },
    );
    if let Err(error) = parse_result {
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
        state_avps,
    };
    validate_decoded_request(&request)
        .map_err(|error| DiameterParserError::decoded(message, error))?;
    Ok(request)
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
    let request = parse_swm_diameter_eap_request_with_provenance(message, ctx)?;
    Ok(SwmDiameterEapRequestEnvelope {
        transaction,
        request,
    })
}

/// Build a SWm Diameter-EAP-Answer message.
pub fn build_swm_diameter_eap_answer(
    answer: &SwmDiameterEapAnswer,
    hop_by_hop_identifier: u32,
    end_to_end_identifier: u32,
    ctx: EncodeContext,
) -> Result<OwnedMessage, EncodeError> {
    answer.validate_for_encode()?;
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
    for apn_configuration in &answer.apn_configurations {
        append_apn_configuration_avp(&mut raw_avps, apn_configuration, ctx)?;
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
        builder_helpers::append_octet_string_avp(&mut raw_avps, AVP_STATE, state, false, ctx)?;
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
    builder_helpers::build_message(
        builder_helpers::app_answer_flags(builder_helpers::result_code_requires_error_bit(
            answer.result.code(),
        )),
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
    let request_facts = request.request();
    if request_facts.session_id.as_ref() != answer.session_id.as_ref()
        || request_facts.auth_application_id != answer.auth_application_id
        || request_facts.auth_request_type != answer.auth_request_type
    {
        return Err(encode_structural_error(
            "SWm DEA does not correlate to the supplied DER",
            "DEA",
        ));
    }
    let transaction = request.transaction();
    build_swm_diameter_eap_answer(
        answer,
        transaction.hop_by_hop_identifier(),
        transaction.end_to_end_identifier(),
        ctx,
    )
}

/// Parse a SWm Diameter-EAP-Answer message.
pub fn parse_swm_diameter_eap_answer(
    message: &Message<'_>,
    ctx: DecodeContext,
) -> Result<SwmDiameterEapAnswer, DecodeError> {
    builder_helpers::ensure_app_header(
        message,
        COMMAND_DIAMETER_EAP,
        APPLICATION_ID,
        CommandKind::Answer,
        "DEA",
    )?;
    let mut session_id = None;
    let mut auth_application_id = None;
    let mut auth_request_type = None;
    let mut result_code = None;
    let mut experimental_result = None;
    let mut origin_host = None;
    let mut origin_realm = None;
    let mut user_name = None;
    let mut service_selection = None;
    let mut default_context_identifier = None;
    let mut apn_configurations = Vec::new();
    let mut mobile_node_identifier = None;
    let mut eap_payload = None;
    let mut eap_reissued_payload = None;
    let mut error_message = None;
    let mut state_avps = Vec::new();
    let mut eap_master_session_key = None;
    builder_helpers::for_each_avp(
        message.raw_avps,
        ctx,
        crate::DIAMETER_HEADER_LEN,
        0,
        |offset, avp| {
            let value_offset = builder_helpers::offset_add(offset, avp.header.header_len(), "DEA")?;
            let code = avp.header.code;
            // Vendor-specific AVPs are matched by (vendor-id, code); only
            // genuinely unknown ones fall through to the unknown-AVP policy.
            if let Some(vendor_id) = avp.header.vendor_id {
                if code == AVP_CONTEXT_IDENTIFIER && vendor_id == VENDOR_ID_3GPP {
                    let value =
                        builder_helpers::parse_u32_value(avp.value, value_offset, "7.3.27")?;
                    builder_helpers::set_once(
                        &mut default_context_identifier,
                        value,
                        offset,
                        "DEA",
                    )?;
                } else if code == AVP_APN_CONFIGURATION && vendor_id == VENDOR_ID_3GPP {
                    apn_configurations.push(parse_apn_configuration(
                        avp.value,
                        ctx,
                        value_offset,
                        1,
                    )?);
                } else {
                    builder_helpers::handle_unknown_avp(ctx, &avp, offset, "DEA")?;
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
                let value = builder_helpers::parse_u32_value(avp.value, value_offset, "6.12")?;
                builder_helpers::set_once(
                    &mut auth_request_type,
                    AuthRequestType::from_value(value),
                    offset,
                    "6.12",
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
            } else if code == AVP_SERVICE_SELECTION {
                let value = builder_helpers::parse_string_value(avp.value, value_offset, "6.2")?;
                builder_helpers::set_once(
                    &mut service_selection,
                    Redacted::from(value),
                    offset,
                    "6.2",
                )?;
            } else if code == AVP_MOBILE_NODE_IDENTIFIER {
                validate_base_mandatory_flags(&avp.header, offset, "4.1")?;
                let value = builder_helpers::parse_string_value(avp.value, value_offset, "5.6")?;
                builder_helpers::set_once(
                    &mut mobile_node_identifier,
                    Redacted::from(value),
                    offset,
                    "5.6",
                )?;
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
            } else if code == AVP_STATE {
                state_avps.push(avp.value.to_vec());
            } else if code == AVP_EAP_MASTER_SESSION_KEY {
                builder_helpers::set_once(
                    &mut eap_master_session_key,
                    Redacted::from(avp.value.to_vec()),
                    offset,
                    "4.3",
                )?;
            } else {
                builder_helpers::handle_unknown_avp(ctx, &avp, offset, "DEA")?;
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
    if message.header.flags.is_error()
        != builder_helpers::result_code_requires_error_bit(result.code())
    {
        return Err(decode_structural_error(
            "SWm DEA E bit does not match the result-code family",
            "7.2",
        ));
    }
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
        service_selection,
        default_context_identifier,
        apn_configurations,
        mobile_node_identifier,
        eap_payload,
        eap_reissued_payload,
        error_message,
        state_avps,
        eap_master_session_key,
    };
    validate_decoded_answer(&answer)?;
    Ok(answer)
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
    let answer = parse_swm_diameter_eap_answer(message, ctx)?;
    Ok(SwmDiameterEapAnswerEnvelope {
        transaction,
        answer,
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
    if header.vendor_id.is_some() || !header.flags.is_mandatory() || header.flags.is_protected() {
        return Err(DecodeError::new(
            DecodeErrorCode::Structural {
                reason: "base AVP must clear V/P and set M",
            },
            builder_helpers::offset_add(offset, 4, section)?,
        )
        .with_spec_ref(SpecRef::new("ietf", "RFC6733", section)));
    }
    Ok(())
}

fn append_experimental_result_avp(
    dst: &mut BytesMut,
    vendor_id: VendorId,
    code: u32,
    ctx: EncodeContext,
) -> Result<(), EncodeError> {
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

fn parse_experimental_result(
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
    Ok(SwmDiameterResult::Experimental {
        vendor_id: VendorId::new(
            vendor_id
                .ok_or_else(|| missing_child_error(base_offset, "missing Vendor-Id child AVP"))?,
        ),
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

fn append_apn_configuration_avp(
    dst: &mut BytesMut,
    apn: &ApnConfiguration,
    ctx: EncodeContext,
) -> Result<(), EncodeError> {
    let mut value = BytesMut::new();
    builder_helpers::append_vendor_u32_avp(
        &mut value,
        AVP_CONTEXT_IDENTIFIER,
        VENDOR_ID_3GPP,
        apn.context_identifier,
        true,
        ctx,
    )?;
    builder_helpers::append_vendor_u32_avp(
        &mut value,
        AVP_PDN_TYPE,
        VENDOR_ID_3GPP,
        apn.pdn_type.value(),
        true,
        ctx,
    )?;
    builder_helpers::append_utf8_avp(
        &mut value,
        AVP_SERVICE_SELECTION,
        apn.service_selection.as_ref(),
        true,
        ctx,
    )?;
    if let Some(profile) = apn.eps_subscribed_qos_profile.as_ref() {
        append_eps_subscribed_qos_profile_avp(&mut value, profile, ctx)?;
    }
    if let Some(ambr) = apn.ambr.as_ref() {
        append_ambr_avp(&mut value, ambr, ctx)?;
    }
    builder_helpers::append_avp(
        dst,
        AvpHeader::vendor(AVP_APN_CONFIGURATION, VENDOR_ID_3GPP, true),
        &value,
        ctx,
    )
}

fn parse_apn_configuration(
    value: &[u8],
    ctx: DecodeContext,
    base_offset: usize,
    depth: usize,
) -> Result<ApnConfiguration, DecodeError> {
    let mut context_identifier = None;
    let mut service_selection = None;
    let mut pdn_type = None;
    let mut eps_subscribed_qos_profile = None;
    let mut ambr = None;
    builder_helpers::for_each_avp(value, ctx, base_offset, depth, |offset, avp| {
        let value_offset = builder_helpers::offset_add(offset, avp.header.header_len(), "7.3.35")?;
        let code = avp.header.code;
        let vendor_id = avp.header.vendor_id;
        if code == AVP_CONTEXT_IDENTIFIER && vendor_id == Some(VENDOR_ID_3GPP) {
            let value = builder_helpers::parse_u32_value(avp.value, value_offset, "7.3.27")?;
            builder_helpers::set_once(&mut context_identifier, value, offset, "7.3.35")?;
        } else if code == AVP_PDN_TYPE && vendor_id == Some(VENDOR_ID_3GPP) {
            let value = builder_helpers::parse_u32_value(avp.value, value_offset, "7.3.62")?;
            builder_helpers::set_once(&mut pdn_type, PdnType::from_value(value), offset, "7.3.35")?;
        } else if code == AVP_SERVICE_SELECTION && vendor_id.is_none() {
            let value = builder_helpers::parse_string_value(avp.value, value_offset, "6.2")?;
            builder_helpers::set_once(
                &mut service_selection,
                Redacted::from(value),
                offset,
                "7.3.35",
            )?;
        } else if code == AVP_EPS_SUBSCRIBED_QOS_PROFILE && vendor_id == Some(VENDOR_ID_3GPP) {
            builder_helpers::set_once(
                &mut eps_subscribed_qos_profile,
                parse_eps_subscribed_qos_profile(avp.value, ctx, value_offset, depth + 1)?,
                offset,
                "7.3.35",
            )?;
        } else if code == AVP_AMBR && vendor_id == Some(VENDOR_ID_3GPP) {
            builder_helpers::set_once(
                &mut ambr,
                parse_ambr(avp.value, ctx, value_offset, depth + 1)?,
                offset,
                "7.3.35",
            )?;
        } else {
            builder_helpers::handle_unknown_avp(ctx, &avp, offset, "7.3.35")?;
        }
        Ok(())
    })?;
    Ok(ApnConfiguration {
        context_identifier: context_identifier.ok_or_else(|| {
            missing_child_error(base_offset, "missing Context-Identifier child AVP")
        })?,
        service_selection: service_selection.ok_or_else(|| {
            missing_child_error(base_offset, "missing Service-Selection child AVP")
        })?,
        pdn_type: pdn_type
            .ok_or_else(|| missing_child_error(base_offset, "missing PDN-Type child AVP"))?,
        eps_subscribed_qos_profile,
        ambr,
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
        profile.qos_class_identifier,
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
        if code == AVP_QOS_CLASS_IDENTIFIER && vendor_id == Some(VENDOR_ID_3GPP) {
            let value = builder_helpers::parse_u32_value(avp.value, value_offset, "5.3.17")?;
            builder_helpers::set_once(&mut qos_class_identifier, value, offset, "7.3.37")?;
        } else if code == AVP_ALLOCATION_RETENTION_PRIORITY && vendor_id == Some(VENDOR_ID_3GPP) {
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
        arp.priority_level,
        true,
        ctx,
    )?;
    if let Some(pre_emption_capability) = arp.pre_emption_capability {
        builder_helpers::append_vendor_u32_avp(
            &mut value,
            AVP_PRE_EMPTION_CAPABILITY,
            VENDOR_ID_3GPP,
            pre_emption_capability,
            true,
            ctx,
        )?;
    }
    if let Some(pre_emption_vulnerability) = arp.pre_emption_vulnerability {
        builder_helpers::append_vendor_u32_avp(
            &mut value,
            AVP_PRE_EMPTION_VULNERABILITY,
            VENDOR_ID_3GPP,
            pre_emption_vulnerability,
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
        if code == AVP_PRIORITY_LEVEL && vendor_id == Some(VENDOR_ID_3GPP) {
            let value = builder_helpers::parse_u32_value(avp.value, value_offset, "5.3.45")?;
            builder_helpers::set_once(&mut priority_level, value, offset, "5.3.32")?;
        } else if code == AVP_PRE_EMPTION_CAPABILITY && vendor_id == Some(VENDOR_ID_3GPP) {
            let value = builder_helpers::parse_u32_value(avp.value, value_offset, "5.3.46")?;
            builder_helpers::set_once(&mut pre_emption_capability, value, offset, "5.3.32")?;
        } else if code == AVP_PRE_EMPTION_VULNERABILITY && vendor_id == Some(VENDOR_ID_3GPP) {
            let value = builder_helpers::parse_u32_value(avp.value, value_offset, "5.3.47")?;
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
    builder_helpers::append_vendor_u32_avp(
        &mut value,
        AVP_MAX_REQUESTED_BANDWIDTH_UL,
        VENDOR_ID_3GPP,
        ambr.max_requested_bandwidth_ul,
        true,
        ctx,
    )?;
    builder_helpers::append_vendor_u32_avp(
        &mut value,
        AVP_MAX_REQUESTED_BANDWIDTH_DL,
        VENDOR_ID_3GPP,
        ambr.max_requested_bandwidth_dl,
        true,
        ctx,
    )?;
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
    builder_helpers::for_each_avp(value, ctx, base_offset, depth, |offset, avp| {
        let value_offset = builder_helpers::offset_add(offset, avp.header.header_len(), "7.3.41")?;
        let code = avp.header.code;
        let vendor_id = avp.header.vendor_id;
        if code == AVP_MAX_REQUESTED_BANDWIDTH_UL && vendor_id == Some(VENDOR_ID_3GPP) {
            let value = builder_helpers::parse_u32_value(avp.value, value_offset, "5.3.15")?;
            builder_helpers::set_once(&mut max_requested_bandwidth_ul, value, offset, "7.3.41")?;
        } else if code == AVP_MAX_REQUESTED_BANDWIDTH_DL && vendor_id == Some(VENDOR_ID_3GPP) {
            let value = builder_helpers::parse_u32_value(avp.value, value_offset, "5.3.14")?;
            builder_helpers::set_once(&mut max_requested_bandwidth_dl, value, offset, "7.3.41")?;
        } else {
            builder_helpers::handle_unknown_avp(ctx, &avp, offset, "7.3.41")?;
        }
        Ok(())
    })?;
    Ok(Ambr {
        max_requested_bandwidth_ul: max_requested_bandwidth_ul.ok_or_else(|| {
            missing_child_error(base_offset, "missing Max-Requested-Bandwidth-UL child AVP")
        })?,
        max_requested_bandwidth_dl: max_requested_bandwidth_dl.ok_or_else(|| {
            missing_child_error(base_offset, "missing Max-Requested-Bandwidth-DL child AVP")
        })?,
    })
}

fn missing_child_error(base_offset: usize, reason: &'static str) -> DecodeError {
    DecodeError::new(DecodeErrorCode::Structural { reason }, base_offset)
        .with_spec_ref(SpecRef::new("ietf", "RFC6733", "grouped"))
}

fn encode_structural_error(reason: &'static str, section: &'static str) -> EncodeError {
    EncodeError::new(EncodeErrorCode::Structural { reason })
        .with_spec_ref(SpecRef::new("3gpp", "TS29273", section))
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
        if service_selection.as_ref().is_empty() {
            return Err(decode_structural_error(
                "SWm DEA Service-Selection must not be empty when present",
                "DEA",
            ));
        }
    }
    validate_apn_profile(answer).map_err(|reason| decode_structural_error(reason, "DEA"))?;
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
    let request = request_envelope.request();
    let answer = answer_envelope.answer();
    ensure_same_session(request, answer)?;
    if request.auth_application_id != answer.auth_application_id
        || request.auth_request_type != answer.auth_request_type
    {
        return Err(SwmEmergencyAuthorizationError::AnswerRequestMismatch);
    }
    answer
        .validate_for_encode()
        .map_err(|_| SwmEmergencyAuthorizationError::AnswerInvalid)?;
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
        && initial_request.auth_request_type == retry_request.auth_request_type
        && initial_request.eap_payload == retry_request.eap_payload
        && initial_request.emergency_services == retry_request.emergency_services
        && initial_request.state_avps == retry_request.state_avps
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
    if !answer.result.is_diameter_success()
        && (answer.default_context_identifier.is_some() || !answer.apn_configurations.is_empty())
    {
        return Err("SWm DEA APN profile material requires DIAMETER_SUCCESS");
    }
    if answer.default_context_identifier == Some(0) {
        return Err("SWm DEA default Context-Identifier must not be zero");
    }

    let mut context_identifiers = HashSet::new();
    let mut service_selections = HashSet::new();
    for apn in &answer.apn_configurations {
        if apn.context_identifier == 0 {
            return Err("SWm DEA APN-Configuration Context-Identifier must not be zero");
        }
        if !context_identifiers.insert(apn.context_identifier) {
            return Err("SWm DEA APN-Configuration Context-Identifier values must be unique");
        }
        if apn.service_selection.as_ref().is_empty() {
            return Err("SWm DEA APN-Configuration Service-Selection must not be empty");
        }
        if !service_selections.insert(apn.service_selection.as_ref().as_str()) {
            return Err("SWm DEA APN-Configuration Service-Selection values must be unique");
        }
    }

    if let Some(default_context_identifier) = answer.default_context_identifier {
        if !context_identifiers.contains(&default_context_identifier) {
            return Err("SWm DEA default Context-Identifier must identify an APN-Configuration");
        }
    }

    Ok(())
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
