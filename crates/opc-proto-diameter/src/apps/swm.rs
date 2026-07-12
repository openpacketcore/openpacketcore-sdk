//! 3GPP SWm Diameter-EAP dictionary subset and typed helpers.
//!
//! This module covers the ePDG-restricted SWm DER/DEA exchange that carries
//! EAP payloads between the ePDG and an AAA/DRA peer, plus a bounded
//! subscription-profile extension surface for APN-Configuration, its default
//! Context-Identifier, and Service-Selection. The top-level default pointer is
//! accepted under the DEA extension-AVP wildcard; it is not part of the
//! baseline SWm DEA command ABNF. This module does not implement transport
//! state, realm routing, or IKEv2 policy.
//!
//! @spec 3GPP TS29273
//! @spec 3GPP TS29272 7.3
//! @spec IETF RFC4072
//! @spec IETF RFC5778
//! @conformance scaffold — see CONFORMANCE.md

use bytes::BytesMut;
use opc_protocol::{
    DecodeContext, DecodeError, DecodeErrorCode, EncodeContext, EncodeError, EncodeErrorCode,
    SpecRef,
};
use std::collections::HashSet;

use super::builder_helpers;
use super::VENDOR_ID_3GPP;
use crate::avp::dictionary::Redacted;
use crate::base;
use crate::dictionary::{
    ApplicationDefinition, AvpDataType, AvpDefinition, AvpFlagRules, AvpKey, CommandDefinition,
    CommandKind, Dictionary,
};
use crate::{ApplicationId, AvpCode, AvpHeader, CommandCode, Message, OwnedMessage};

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

/// SWm Diameter-EAP-Request command definition.
pub const COMMAND_DIAMETER_EAP_REQUEST: CommandDefinition = CommandDefinition::new(
    COMMAND_DIAMETER_EAP,
    "Diameter-EAP-Request",
    CommandKind::Request,
    APPLICATION_ID,
    true,
    SpecRef::new("3gpp", "TS29273", "DER"),
);

/// SWm Diameter-EAP-Answer command definition.
pub const COMMAND_DIAMETER_EAP_ANSWER: CommandDefinition = CommandDefinition::new(
    COMMAND_DIAMETER_EAP,
    "Diameter-EAP-Answer",
    CommandKind::Answer,
    APPLICATION_ID,
    true,
    SpecRef::new("3gpp", "TS29273", "DEA"),
);

const SWM_AVPS: [AvpDefinition; 18] = [
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
        AvpKey::ietf(AVP_SERVICE_SELECTION),
        "Service-Selection",
        AvpDataType::Utf8String,
        AvpFlagRules::base_mandatory(),
        SpecRef::new("ietf", "RFC5778", "6.2"),
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

/// Static SWm dictionary covering the ePDG-required DER/DEA subset.
pub static DICTIONARY: Dictionary = Dictionary::new(
    "diameter-3gpp-swm-subset",
    &[APPLICATION],
    &[COMMAND_DIAMETER_EAP_REQUEST, COMMAND_DIAMETER_EAP_ANSWER],
    &SWM_AVPS,
);

/// Return the static SWm dictionary subset.
pub const fn dictionary() -> &'static Dictionary {
    &DICTIONARY
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
    /// Result-Code.
    pub result_code: u32,
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
            .field("result_code", &self.result_code)
            .field("origin_host", &self.origin_host)
            .field("origin_realm", &self.origin_realm)
            .field("user_name", &self.user_name)
            .field("service_selection", &self.service_selection)
            .field(
                "default_context_identifier",
                &self.default_context_identifier,
            )
            .field("apn_configurations", &self.apn_configurations.len())
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
        Ok(())
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
        SwmResultCategory::from_result_code(self.result_code)
    }

    /// Return true when the answer carries EAP challenge/reissued payload or
    /// master session key material.
    pub fn carries_eap_material(&self) -> bool {
        option_redacted_bytes_has_material(&self.eap_payload)
            || option_redacted_bytes_has_material(&self.eap_reissued_payload)
            || option_redacted_bytes_has_material(&self.eap_master_session_key)
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
    builder_helpers::ensure_app_header(
        message,
        COMMAND_DIAMETER_EAP,
        APPLICATION_ID,
        CommandKind::Request,
        "DER",
    )?;
    let mut session_id = None;
    let mut auth_application_id = None;
    let mut origin_host = None;
    let mut origin_realm = None;
    let mut destination_realm = None;
    let mut destination_host = None;
    let mut user_name = None;
    let mut auth_request_type = None;
    let mut eap_payload = None;
    let mut state_avps = Vec::new();
    builder_helpers::for_each_avp(
        message.raw_avps,
        ctx,
        crate::DIAMETER_HEADER_LEN,
        0,
        |offset, avp| {
            let value_offset = builder_helpers::offset_add(offset, avp.header.header_len(), "DER")?;
            let code = avp.header.code;
            if avp.header.vendor_id.is_some() {
                return builder_helpers::handle_unknown_avp(ctx, &avp, offset, "DER");
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
    )?;
    let auth_application_id = builder_helpers::require_field(
        auth_application_id,
        "SWm DER requires Auth-Application-Id",
        "DER",
    )?;
    if auth_application_id != APPLICATION_ID.get() {
        return Err(DecodeError::new(
            DecodeErrorCode::Structural {
                reason: "SWm DER Auth-Application-Id does not match the SWm application id",
            },
            crate::DIAMETER_HEADER_LEN,
        )
        .with_spec_ref(SpecRef::new("3gpp", "TS29273", "DER")));
    }
    let request = SwmDiameterEapRequest {
        session_id: builder_helpers::require_field(
            session_id,
            "SWm DER requires Session-Id",
            "DER",
        )?,
        auth_application_id,
        origin_host: builder_helpers::require_field(
            origin_host,
            "SWm DER requires Origin-Host",
            "DER",
        )?,
        origin_realm: builder_helpers::require_field(
            origin_realm,
            "SWm DER requires Origin-Realm",
            "DER",
        )?,
        destination_realm: builder_helpers::require_field(
            destination_realm,
            "SWm DER requires Destination-Realm",
            "DER",
        )?,
        destination_host,
        user_name,
        auth_request_type: builder_helpers::require_field(
            auth_request_type,
            "SWm DER requires Auth-Request-Type",
            "DER",
        )?,
        eap_payload: builder_helpers::require_field(
            eap_payload,
            "SWm DER requires EAP-Payload",
            "DER",
        )?,
        state_avps,
    };
    validate_decoded_request(&request)?;
    Ok(request)
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
    builder_helpers::append_u32_avp(
        &mut raw_avps,
        base::AVP_RESULT_CODE,
        answer.result_code,
        true,
        ctx,
    )?;
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
            answer.result_code,
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
    let mut origin_host = None;
    let mut origin_realm = None;
    let mut user_name = None;
    let mut service_selection = None;
    let mut default_context_identifier = None;
    let mut apn_configurations = Vec::new();
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
                let value = builder_helpers::parse_u32_value(avp.value, value_offset, "7.1")?;
                builder_helpers::set_once(&mut result_code, value, offset, "7.1")?;
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
        result_code: builder_helpers::require_field(
            result_code,
            "SWm DEA requires Result-Code",
            "DEA",
        )?,
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
        eap_payload,
        eap_reissued_payload,
        error_message,
        state_avps,
        eap_master_session_key,
    };
    validate_decoded_answer(&answer)?;
    Ok(answer)
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

fn validate_apn_profile(answer: &SwmDiameterEapAnswer) -> Result<(), &'static str> {
    if answer.result_code != base::RESULT_CODE_DIAMETER_SUCCESS
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
