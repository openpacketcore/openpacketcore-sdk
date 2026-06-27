//! 3GPP SWm Diameter-EAP dictionary subset and typed helpers.
//!
//! This module covers the ePDG-restricted SWm DER/DEA exchange that carries
//! EAP payloads between the ePDG and an AAA/DRA peer. It does not implement
//! transport state, realm routing, or IKEv2 policy.
//!
//! @spec 3GPP TS29273
//! @spec IETF RFC4072
//! @conformance scaffold — see CONFORMANCE.md

use bytes::BytesMut;
use opc_protocol::{
    DecodeContext, DecodeError, DecodeErrorCode, EncodeContext, EncodeError, EncodeErrorCode,
    SpecRef,
};

use super::builder_helpers;
use super::VENDOR_ID_3GPP;
use crate::avp::dictionary::Redacted;
use crate::base;
use crate::dictionary::{
    ApplicationDefinition, AvpDataType, AvpDefinition, AvpFlagRules, AvpKey, CommandDefinition,
    CommandKind, Dictionary,
};
use crate::{ApplicationId, AvpCode, CommandCode, Message, OwnedMessage};

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

const SWM_AVPS: [AvpDefinition; 5] = [
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
            ));
        }
        if self.origin_host.as_ref().is_empty() {
            return Err(encode_structural_error(
                "SWm DER Origin-Host must not be empty",
            ));
        }
        if self.origin_realm.as_ref().is_empty() {
            return Err(encode_structural_error(
                "SWm DER Origin-Realm must not be empty",
            ));
        }
        if self.destination_realm.as_ref().is_empty() {
            return Err(encode_structural_error(
                "SWm DER Destination-Realm must not be empty",
            ));
        }
        if self.auth_application_id != APPLICATION_ID.get() {
            return Err(encode_structural_error(
                "SWm DER Auth-Application-Id must be the SWm application id",
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
            ));
        }
        if self.origin_host.as_ref().is_empty() {
            return Err(encode_structural_error(
                "SWm DEA Origin-Host must not be empty",
            ));
        }
        if self.origin_realm.as_ref().is_empty() {
            return Err(encode_structural_error(
                "SWm DEA Origin-Realm must not be empty",
            ));
        }
        if self.auth_application_id != APPLICATION_ID.get() {
            return Err(encode_structural_error(
                "SWm DEA Auth-Application-Id must be the SWm application id",
            ));
        }
        Ok(())
    }

    /// Return the result-code family category.
    pub fn result_category(&self) -> SwmResultCategory {
        SwmResultCategory::from_result_code(self.result_code)
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
    Ok(SwmDiameterEapRequest {
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
            if avp.header.vendor_id.is_some() {
                return builder_helpers::handle_unknown_avp(ctx, &avp, offset, "DEA");
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
    Ok(SwmDiameterEapAnswer {
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
        eap_payload,
        eap_reissued_payload,
        error_message,
        state_avps,
        eap_master_session_key,
    })
}

fn encode_structural_error(reason: &'static str) -> EncodeError {
    EncodeError::new(EncodeErrorCode::Structural { reason })
        .with_spec_ref(SpecRef::new("3gpp", "TS29273", "DER"))
}
