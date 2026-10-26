//! 3GPP Rf offline-charging dictionary subset and typed helpers.
//!
//! This module covers the ePDG-restricted Rf Accounting-Request /
//! Accounting-Answer subset used for START, INTERIM, STOP, and EVENT records.
//! It does not implement CGF selection, delivery policy, or charging decisions.
//!
//! @spec 3GPP TS32299
//! @spec IETF RFC6733 7
//! @spec IETF RFC4006
//! @conformance scaffold — see CONFORMANCE.md

use std::net::IpAddr;

use bytes::BytesMut;
use opc_protocol::{
    DecodeContext, DecodeError, DecodeErrorCode, EncodeContext, EncodeError, EncodeErrorCode,
    SpecRef,
};

use super::builder_helpers;
use super::subscription_id::{append_subscription_id_avp, parse_subscription_id};
pub use super::subscription_id::{
    SubscriptionId, SubscriptionIdType, AVP_SUBSCRIPTION_ID, AVP_SUBSCRIPTION_ID_DATA,
    AVP_SUBSCRIPTION_ID_TYPE,
};
use super::VENDOR_ID_3GPP;
use crate::avp::dictionary::Redacted;
use crate::base;
use crate::dictionary::{
    ApplicationDefinition, AvpDataType, AvpDefinition, AvpFlagRules, AvpKey, CommandDefinition,
    CommandKind, Dictionary, FlagRequirement,
};
use crate::{ApplicationId, AvpCode, AvpHeader, CommandCode, Message, OwnedMessage};

/// Diameter accounting application identifier used by 3GPP Rf.
pub const APPLICATION_ID: ApplicationId = ApplicationId::new(3);

/// Rf Accounting command code (RFC 6733 §7).
pub const COMMAND_ACCOUNTING: CommandCode = CommandCode::new(271);

/// Accounting-Record-Type AVP code (RFC 6733 §9.8.1).
pub const AVP_ACCOUNTING_RECORD_TYPE: AvpCode = AvpCode::new(480);
/// Accounting-Record-Number AVP code (RFC 6733 §9.8.3).
pub const AVP_ACCOUNTING_RECORD_NUMBER: AvpCode = AvpCode::new(485);
/// Event-Timestamp AVP code (RFC 6733 §5.3.2).
pub const AVP_EVENT_TIMESTAMP: AvpCode = AvpCode::new(55);
/// Service-Information grouped AVP (TS 32.299 section 7.2.192).
pub const AVP_SERVICE_INFORMATION: AvpCode = AvpCode::new(873);
/// Service-Data-Container grouped AVP (TS 32.299 section 7.2.189).
pub const AVP_SERVICE_DATA_CONTAINER: AvpCode = AvpCode::new(2040);
/// Accounting-Input-Octets (RFC 4005 section 8.1).
pub const AVP_ACCOUNTING_INPUT_OCTETS: AvpCode = AvpCode::new(363);
/// Accounting-Output-Octets (RFC 4005 section 8.2).
pub const AVP_ACCOUNTING_OUTPUT_OCTETS: AvpCode = AvpCode::new(364);
/// Time-Usage (TS 32.299 section 7.2.232).
pub const AVP_TIME_USAGE: AvpCode = AvpCode::new(2045);
/// Rating-Group AVP code (RFC 4006 §8.29).
pub const AVP_RATING_GROUP: AvpCode = AvpCode::new(432);
/// Service-Identifier AVP code (RFC 4006 §8.28).
pub const AVP_SERVICE_IDENTIFIER: AvpCode = AvpCode::new(439);
/// Service-Context-Id AVP code (RFC 4006 §8.6).
pub const AVP_SERVICE_CONTEXT_ID: AvpCode = AvpCode::new(461);

/// PS-Information grouped AVP code (3GPP TS 32.299).
pub const AVP_PS_INFORMATION: AvpCode = AvpCode::new(874);
/// 3GPP-Charging-Id AVP code (3GPP TS 32.299).
pub const AVP_3GPP_CHARGING_ID: AvpCode = AvpCode::new(2);
/// 3GPP-PDP-Type AVP code (3GPP TS 32.299).
pub const AVP_3GPP_PDP_TYPE: AvpCode = AvpCode::new(3);
/// SGSN-Address AVP code (3GPP TS 32.299).
pub const AVP_SGSN_ADDRESS: AvpCode = AvpCode::new(1228);
/// GGSN-Address AVP code (3GPP TS 32.299).
pub const AVP_GGSN_ADDRESS: AvpCode = AvpCode::new(847);

/// 3GPP Rf accounting application definition.
pub const APPLICATION: ApplicationDefinition = ApplicationDefinition::new(
    APPLICATION_ID,
    "3GPP Rf accounting over Diameter accounting",
    Some(VENDOR_ID_3GPP),
    SpecRef::new("3gpp", "TS32299", "Rf Diameter application"),
);

/// Rf Accounting-Request command definition.
pub const COMMAND_ACCOUNTING_REQUEST: CommandDefinition = CommandDefinition::new(
    COMMAND_ACCOUNTING,
    "Accounting-Request",
    CommandKind::Request,
    APPLICATION_ID,
    true,
    SpecRef::new("ietf", "RFC6733", "7"),
);

/// Rf Accounting-Answer command definition.
pub const COMMAND_ACCOUNTING_ANSWER: CommandDefinition = CommandDefinition::new(
    COMMAND_ACCOUNTING,
    "Accounting-Answer",
    CommandKind::Answer,
    APPLICATION_ID,
    true,
    SpecRef::new("ietf", "RFC6733", "7"),
);

const RF_AVPS: [AvpDefinition; 19] = [
    AvpDefinition::new(
        AvpKey::ietf(AVP_ACCOUNTING_RECORD_TYPE),
        "Accounting-Record-Type",
        AvpDataType::Enumerated,
        AvpFlagRules::base_mandatory(),
        SpecRef::new("ietf", "RFC6733", "9.8.1"),
    ),
    AvpDefinition::new(
        AvpKey::ietf(AVP_ACCOUNTING_RECORD_NUMBER),
        "Accounting-Record-Number",
        AvpDataType::Unsigned32,
        AvpFlagRules::base_mandatory(),
        SpecRef::new("ietf", "RFC6733", "9.8.3"),
    ),
    AvpDefinition::new(
        AvpKey::ietf(AVP_EVENT_TIMESTAMP),
        "Event-Timestamp",
        AvpDataType::Time,
        AvpFlagRules::base_mandatory(),
        SpecRef::new("ietf", "RFC6733", "5.3.2"),
    ),
    AvpDefinition::new(
        AvpKey::ietf(AVP_SERVICE_CONTEXT_ID),
        "Service-Context-Id",
        AvpDataType::Utf8String,
        AvpFlagRules::base_mandatory(),
        SpecRef::new("ietf", "RFC4006", "8.6"),
    ),
    AvpDefinition::new(
        AvpKey::ietf(AVP_SUBSCRIPTION_ID),
        "Subscription-Id",
        AvpDataType::Grouped,
        AvpFlagRules::new(
            FlagRequirement::MustBeUnset,
            FlagRequirement::MustBeSet,
            FlagRequirement::MayBeSet,
        ),
        SpecRef::new("ietf", "RFC4006", "8.46"),
    ),
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
        AvpKey::vendor(AVP_SERVICE_INFORMATION, VENDOR_ID_3GPP),
        "Service-Information",
        AvpDataType::Grouped,
        AvpFlagRules::vendor_specific(),
        SpecRef::new("3gpp", "TS32299", "7.2.192"),
    ),
    AvpDefinition::new(
        AvpKey::vendor(AVP_SERVICE_DATA_CONTAINER, VENDOR_ID_3GPP),
        "Service-Data-Container",
        AvpDataType::Grouped,
        AvpFlagRules::vendor_specific(),
        SpecRef::new("3gpp", "TS32299", "7.2.189"),
    ),
    AvpDefinition::new(
        AvpKey::ietf(AVP_ACCOUNTING_INPUT_OCTETS),
        "Accounting-Input-Octets",
        AvpDataType::Unsigned64,
        AvpFlagRules::base_mandatory(),
        SpecRef::new("ietf", "RFC4005", "8.1"),
    ),
    AvpDefinition::new(
        AvpKey::ietf(AVP_ACCOUNTING_OUTPUT_OCTETS),
        "Accounting-Output-Octets",
        AvpDataType::Unsigned64,
        AvpFlagRules::base_mandatory(),
        SpecRef::new("ietf", "RFC4005", "8.2"),
    ),
    AvpDefinition::new(
        AvpKey::vendor(AVP_TIME_USAGE, VENDOR_ID_3GPP),
        "Time-Usage",
        AvpDataType::Unsigned32,
        AvpFlagRules::vendor_specific(),
        SpecRef::new("3gpp", "TS32299", "7.2.232"),
    ),
    AvpDefinition::new(
        AvpKey::ietf(AVP_RATING_GROUP),
        "Rating-Group",
        AvpDataType::Unsigned32,
        AvpFlagRules::base_optional(),
        SpecRef::new("ietf", "RFC4006", "8.29"),
    ),
    AvpDefinition::new(
        AvpKey::ietf(AVP_SERVICE_IDENTIFIER),
        "Service-Identifier",
        AvpDataType::Unsigned32,
        AvpFlagRules::base_optional(),
        SpecRef::new("ietf", "RFC4006", "8.28"),
    ),
    AvpDefinition::new(
        AvpKey::vendor(AVP_PS_INFORMATION, VENDOR_ID_3GPP),
        "PS-Information",
        AvpDataType::Grouped,
        AvpFlagRules::vendor_specific(),
        SpecRef::new("3gpp", "TS32299", "PS-Information"),
    ),
    AvpDefinition::new(
        AvpKey::vendor(AVP_3GPP_CHARGING_ID, VENDOR_ID_3GPP),
        "3GPP-Charging-Id",
        AvpDataType::OctetString,
        AvpFlagRules::new(
            FlagRequirement::MustBeSet,
            FlagRequirement::MustBeUnset,
            FlagRequirement::MayBeSet,
        ),
        SpecRef::new("3gpp", "TS29061", "16.4.7"),
    ),
    AvpDefinition::new(
        AvpKey::vendor(AVP_3GPP_PDP_TYPE, VENDOR_ID_3GPP),
        "3GPP-PDP-Type",
        AvpDataType::Enumerated,
        AvpFlagRules::new(
            FlagRequirement::MustBeSet,
            FlagRequirement::MustBeUnset,
            FlagRequirement::MayBeSet,
        ),
        SpecRef::new("3gpp", "TS29061", "16.4.7"),
    ),
    AvpDefinition::new(
        AvpKey::vendor(AVP_SGSN_ADDRESS, VENDOR_ID_3GPP),
        "SGSN-Address",
        AvpDataType::Address,
        AvpFlagRules::vendor_specific(),
        SpecRef::new("3gpp", "TS32299", "7.2.199"),
    ),
    AvpDefinition::new(
        AvpKey::vendor(AVP_GGSN_ADDRESS, VENDOR_ID_3GPP),
        "GGSN-Address",
        AvpDataType::Address,
        AvpFlagRules::vendor_specific(),
        SpecRef::new("3gpp", "TS32299", "7.2.68"),
    ),
];

/// Static Rf dictionary covering the ePDG-required subset.
pub static DICTIONARY: Dictionary = Dictionary::new(
    "diameter-3gpp-rf-subset",
    &[APPLICATION],
    &[COMMAND_ACCOUNTING_REQUEST, COMMAND_ACCOUNTING_ANSWER],
    &RF_AVPS,
);

/// Return the static Rf dictionary subset.
pub const fn dictionary() -> &'static Dictionary {
    &DICTIONARY
}

/// Accounting record type values used by Rf.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AccountingRecordType {
    /// Event record.
    EventRecord,
    /// Start record.
    StartRecord,
    /// Interim record.
    InterimRecord,
    /// Stop record.
    StopRecord,
    /// Unknown or application-specific value.
    Other(u32),
}

impl AccountingRecordType {
    /// Return the wire value for this record type.
    pub const fn value(self) -> u32 {
        match self {
            Self::EventRecord => 1,
            Self::StartRecord => 2,
            Self::InterimRecord => 3,
            Self::StopRecord => 4,
            Self::Other(v) => v,
        }
    }

    /// Parse a record type from its wire value.
    pub const fn from_value(value: u32) -> Self {
        match value {
            1 => Self::EventRecord,
            2 => Self::StartRecord,
            3 => Self::InterimRecord,
            4 => Self::StopRecord,
            other => Self::Other(other),
        }
    }
}

/// Offline per-service usage (TS 32.299 section 7.2.189).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceDataContainer {
    /// Uplink octets during this reporting interval.
    pub accounting_input_octets: Option<u64>,
    /// Downlink octets during this reporting interval.
    pub accounting_output_octets: Option<u64>,
    /// Effective service usage in seconds.
    pub time_usage: Option<u32>,
    /// Rating-Group.
    pub rating_group: Option<u32>,
    /// Service-Identifier.
    pub service_identifier: Option<u32>,
}

/// PS-Information grouped AVP (3GPP TS 32.299).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PsInformation {
    /// 3GPP-Charging-Id.
    pub charging_id: Option<u32>,
    /// 3GPP-PDP-Type.
    pub pdp_type: Option<u32>,
    /// SGSN-Address (redacted in diagnostic output).
    pub sgsn_address: Option<Redacted<IpAddr>>,
    /// GGSN-Address (redacted in diagnostic output).
    pub ggsn_address: Option<Redacted<IpAddr>>,
    /// Repeated offline per-service usage containers.
    pub service_data_containers: Vec<ServiceDataContainer>,
}

/// Rf Accounting-Request (ACR) for START, INTERIM, STOP, and EVENT records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RfAccountingRequest {
    /// Session-Id (redacted in diagnostic output).
    pub session_id: Redacted<String>,
    /// Origin-Host (redacted in diagnostic output).
    pub origin_host: Redacted<String>,
    /// Origin-Realm (redacted in diagnostic output).
    pub origin_realm: Redacted<String>,
    /// Destination-Realm (redacted in diagnostic output).
    pub destination_realm: Redacted<String>,
    /// Destination-Host (redacted in diagnostic output).
    pub destination_host: Option<Redacted<String>>,
    /// Accounting record type.
    pub accounting_record_type: AccountingRecordType,
    /// Accounting record number.
    pub accounting_record_number: u32,
    /// Acct-Application-Id (must be the Rf accounting application id).
    pub acct_application_id: u32,
    /// User-Name (redacted in diagnostic output).
    pub user_name: Option<Redacted<String>>,
    /// Origin-State-Id.
    pub origin_state_id: Option<u32>,
    /// Event-Timestamp.
    pub event_timestamp: Option<u32>,
    /// Service-Context-Id.
    pub service_context_id: String,
    /// Subscription-Id groups nested in Service-Information.
    pub subscription_ids: Vec<SubscriptionId>,
    /// PS-Information nested in Service-Information.
    pub ps_information: Option<PsInformation>,
}

/// Rf Accounting-Answer (ACA).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RfAccountingAnswer {
    /// Session-Id (redacted in diagnostic output).
    pub session_id: Redacted<String>,
    /// Result-Code.
    pub result_code: u32,
    /// Origin-Host (redacted in diagnostic output).
    pub origin_host: Redacted<String>,
    /// Origin-Realm (redacted in diagnostic output).
    pub origin_realm: Redacted<String>,
    /// Accounting record type.
    pub accounting_record_type: AccountingRecordType,
    /// Accounting record number.
    pub accounting_record_number: u32,
    /// Acct-Application-Id.
    pub acct_application_id: u32,
    /// Origin-State-Id.
    pub origin_state_id: Option<u32>,
    /// Event-Timestamp.
    pub event_timestamp: Option<u32>,
}

impl RfAccountingRequest {
    fn validate_for_encode(&self) -> Result<(), EncodeError> {
        if self.session_id.as_ref().is_empty() {
            return Err(encode_structural_error(
                "Rf ACR Session-Id must not be empty",
            ));
        }
        if self.origin_host.as_ref().is_empty() {
            return Err(encode_structural_error(
                "Rf ACR Origin-Host must not be empty",
            ));
        }
        if self.origin_realm.as_ref().is_empty() {
            return Err(encode_structural_error(
                "Rf ACR Origin-Realm must not be empty",
            ));
        }
        if self.destination_realm.as_ref().is_empty() {
            return Err(encode_structural_error(
                "Rf ACR Destination-Realm must not be empty",
            ));
        }
        if self.service_context_id.is_empty() {
            return Err(encode_structural_error(
                "Rf ACR Service-Context-Id must not be empty",
            ));
        }
        if self.acct_application_id != APPLICATION_ID.get() {
            return Err(encode_structural_error(
                "Rf ACR Acct-Application-Id must be the Rf accounting application id",
            ));
        }
        Ok(())
    }
}

impl RfAccountingAnswer {
    fn validate_for_encode(&self) -> Result<(), EncodeError> {
        if self.session_id.as_ref().is_empty() {
            return Err(encode_structural_error(
                "Rf ACA Session-Id must not be empty",
            ));
        }
        if self.origin_host.as_ref().is_empty() {
            return Err(encode_structural_error(
                "Rf ACA Origin-Host must not be empty",
            ));
        }
        if self.origin_realm.as_ref().is_empty() {
            return Err(encode_structural_error(
                "Rf ACA Origin-Realm must not be empty",
            ));
        }
        if self.acct_application_id != APPLICATION_ID.get() {
            return Err(encode_structural_error(
                "Rf ACA Acct-Application-Id must be the Rf accounting application id",
            ));
        }
        Ok(())
    }
}

/// Build a raw Rf Accounting-Request message.
pub fn build_rf_accounting_request(
    request: &RfAccountingRequest,
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
        AVP_ACCOUNTING_RECORD_TYPE,
        request.accounting_record_type.value(),
        true,
        ctx,
    )?;
    builder_helpers::append_u32_avp(
        &mut raw_avps,
        AVP_ACCOUNTING_RECORD_NUMBER,
        request.accounting_record_number,
        true,
        ctx,
    )?;
    builder_helpers::append_u32_avp(
        &mut raw_avps,
        base::AVP_ACCT_APPLICATION_ID,
        request.acct_application_id,
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
    if let Some(origin_state_id) = request.origin_state_id {
        builder_helpers::append_u32_avp(
            &mut raw_avps,
            base::AVP_ORIGIN_STATE_ID,
            origin_state_id,
            true,
            ctx,
        )?;
    }
    if let Some(event_timestamp) = request.event_timestamp {
        builder_helpers::append_u32_avp(
            &mut raw_avps,
            AVP_EVENT_TIMESTAMP,
            event_timestamp,
            true,
            ctx,
        )?;
    }
    builder_helpers::append_utf8_avp(
        &mut raw_avps,
        AVP_SERVICE_CONTEXT_ID,
        &request.service_context_id,
        true,
        ctx,
    )?;
    if !request.subscription_ids.is_empty() || request.ps_information.is_some() {
        let mut service_information = BytesMut::new();
        for subscription_id in &request.subscription_ids {
            append_subscription_id_avp(&mut service_information, subscription_id, ctx)?;
        }
        if let Some(ps_information) = request.ps_information.as_ref() {
            append_ps_information_avp(&mut service_information, ps_information, ctx)?;
        }
        builder_helpers::append_avp(
            &mut raw_avps,
            AvpHeader::vendor(AVP_SERVICE_INFORMATION, VENDOR_ID_3GPP, true),
            &service_information,
            ctx,
        )?;
    }
    builder_helpers::build_message(
        builder_helpers::app_request_flags(),
        COMMAND_ACCOUNTING,
        APPLICATION_ID,
        raw_avps,
        hop_by_hop_identifier,
        end_to_end_identifier,
        ctx,
        "7",
    )
}

/// Parse a raw Rf Accounting-Request message.
pub fn parse_rf_accounting_request(
    message: &Message<'_>,
    ctx: DecodeContext,
) -> Result<RfAccountingRequest, DecodeError> {
    builder_helpers::ensure_app_header(
        message,
        COMMAND_ACCOUNTING,
        APPLICATION_ID,
        CommandKind::Request,
        "7",
    )?;
    let mut session_id = None;
    let mut origin_host = None;
    let mut origin_realm = None;
    let mut destination_realm = None;
    let mut destination_host = None;
    let mut accounting_record_type = None;
    let mut accounting_record_number = None;
    let mut acct_application_id = None;
    let mut user_name = None;
    let mut origin_state_id = None;
    let mut event_timestamp = None;
    let mut service_context_id = None;
    let mut service_information = None;
    builder_helpers::for_each_avp(
        message.raw_avps,
        ctx,
        crate::DIAMETER_HEADER_LEN,
        0,
        |offset, avp| {
            let value_offset = builder_helpers::offset_add(offset, avp.header.header_len(), "7")?;
            let code = avp.header.code;
            if let Some(vendor_id) = avp.header.vendor_id {
                if code == AVP_SERVICE_INFORMATION && vendor_id == VENDOR_ID_3GPP {
                    builder_helpers::set_once(
                        &mut service_information,
                        parse_service_information(avp.value, ctx, value_offset, 1)?,
                        offset,
                        "TS32299",
                    )?;
                } else {
                    builder_helpers::handle_unknown_avp(ctx, &avp, offset, "7")?;
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
            } else if code == AVP_ACCOUNTING_RECORD_TYPE {
                let value = builder_helpers::parse_u32_value(avp.value, value_offset, "9.8.1")?;
                builder_helpers::set_once(
                    &mut accounting_record_type,
                    AccountingRecordType::from_value(value),
                    offset,
                    "9.8.1",
                )?;
            } else if code == AVP_ACCOUNTING_RECORD_NUMBER {
                let value = builder_helpers::parse_u32_value(avp.value, value_offset, "9.8.3")?;
                builder_helpers::set_once(&mut accounting_record_number, value, offset, "9.8.3")?;
            } else if code == base::AVP_ACCT_APPLICATION_ID {
                let value = builder_helpers::parse_u32_value(avp.value, value_offset, "6.9")?;
                builder_helpers::set_once(&mut acct_application_id, value, offset, "6.9")?;
            } else if code == base::AVP_USER_NAME {
                let value = builder_helpers::parse_string_value(avp.value, value_offset, "8.14")?;
                builder_helpers::set_once(&mut user_name, Redacted::from(value), offset, "8.14")?;
            } else if code == base::AVP_ORIGIN_STATE_ID {
                let value = builder_helpers::parse_u32_value(avp.value, value_offset, "8.16")?;
                builder_helpers::set_once(&mut origin_state_id, value, offset, "8.16")?;
            } else if code == AVP_EVENT_TIMESTAMP {
                let value = builder_helpers::parse_u32_value(avp.value, value_offset, "5.3.2")?;
                builder_helpers::set_once(&mut event_timestamp, value, offset, "5.3.2")?;
            } else if code == AVP_SERVICE_CONTEXT_ID {
                let value = builder_helpers::parse_string_value(avp.value, value_offset, "8.6")?;
                builder_helpers::set_once(&mut service_context_id, value, offset, "8.6")?;
            } else {
                builder_helpers::handle_unknown_avp(ctx, &avp, offset, "7")?;
            }
            Ok(())
        },
    )?;
    let acct_application_id = builder_helpers::require_field(
        acct_application_id,
        "Rf ACR requires Acct-Application-Id",
        "7",
    )?;
    if acct_application_id != APPLICATION_ID.get() {
        return Err(DecodeError::new(
            DecodeErrorCode::Structural {
                reason:
                    "Rf ACR Acct-Application-Id does not match the Rf accounting application id",
            },
            crate::DIAMETER_HEADER_LEN,
        )
        .with_spec_ref(SpecRef::new("ietf", "RFC6733", "7")));
    }
    let (subscription_ids, ps_information) = service_information.unwrap_or_default();
    Ok(RfAccountingRequest {
        session_id: builder_helpers::require_field(session_id, "Rf ACR requires Session-Id", "7")?,
        origin_host: builder_helpers::require_field(
            origin_host,
            "Rf ACR requires Origin-Host",
            "7",
        )?,
        origin_realm: builder_helpers::require_field(
            origin_realm,
            "Rf ACR requires Origin-Realm",
            "7",
        )?,
        destination_realm: builder_helpers::require_field(
            destination_realm,
            "Rf ACR requires Destination-Realm",
            "7",
        )?,
        destination_host,
        accounting_record_type: builder_helpers::require_field(
            accounting_record_type,
            "Rf ACR requires Accounting-Record-Type",
            "7",
        )?,
        accounting_record_number: builder_helpers::require_field(
            accounting_record_number,
            "Rf ACR requires Accounting-Record-Number",
            "7",
        )?,
        acct_application_id,
        user_name,
        origin_state_id,
        event_timestamp,
        service_context_id: builder_helpers::require_field(
            service_context_id,
            "Rf ACR requires Service-Context-Id",
            "7",
        )?,
        subscription_ids,
        ps_information,
    })
}

fn validate_subscription_id_outer_flags(
    header: &AvpHeader,
    offset: usize,
) -> Result<(), DecodeError> {
    if header.vendor_id.is_some() || !header.flags.is_mandatory() {
        return Err(DecodeError::new(
            DecodeErrorCode::Structural {
                reason: "Rf Subscription-Id must clear V and set M",
            },
            offset.saturating_add(4),
        )
        .with_spec_ref(SpecRef::new("ietf", "RFC4006", "8.46")));
    }
    Ok(())
}

/// Build a raw Rf Accounting-Answer message.
pub fn build_rf_accounting_answer(
    answer: &RfAccountingAnswer,
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
    builder_helpers::append_u32_avp(
        &mut raw_avps,
        AVP_ACCOUNTING_RECORD_TYPE,
        answer.accounting_record_type.value(),
        true,
        ctx,
    )?;
    builder_helpers::append_u32_avp(
        &mut raw_avps,
        AVP_ACCOUNTING_RECORD_NUMBER,
        answer.accounting_record_number,
        true,
        ctx,
    )?;
    builder_helpers::append_u32_avp(
        &mut raw_avps,
        base::AVP_ACCT_APPLICATION_ID,
        answer.acct_application_id,
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
    if let Some(event_timestamp) = answer.event_timestamp {
        builder_helpers::append_u32_avp(
            &mut raw_avps,
            AVP_EVENT_TIMESTAMP,
            event_timestamp,
            true,
            ctx,
        )?;
    }
    builder_helpers::build_message(
        builder_helpers::app_answer_flags(builder_helpers::result_code_requires_error_bit(
            answer.result_code,
        )),
        COMMAND_ACCOUNTING,
        APPLICATION_ID,
        raw_avps,
        hop_by_hop_identifier,
        end_to_end_identifier,
        ctx,
        "7",
    )
}

/// Parse a raw Rf Accounting-Answer message.
pub fn parse_rf_accounting_answer(
    message: &Message<'_>,
    ctx: DecodeContext,
) -> Result<RfAccountingAnswer, DecodeError> {
    builder_helpers::ensure_app_header(
        message,
        COMMAND_ACCOUNTING,
        APPLICATION_ID,
        CommandKind::Answer,
        "7",
    )?;
    let mut session_id = None;
    let mut result_code = None;
    let mut origin_host = None;
    let mut origin_realm = None;
    let mut accounting_record_type = None;
    let mut accounting_record_number = None;
    let mut acct_application_id = None;
    let mut origin_state_id = None;
    let mut event_timestamp = None;
    builder_helpers::for_each_avp(
        message.raw_avps,
        ctx,
        crate::DIAMETER_HEADER_LEN,
        0,
        |offset, avp| {
            let value_offset = builder_helpers::offset_add(offset, avp.header.header_len(), "7")?;
            let code = avp.header.code;
            if avp.header.vendor_id.is_some() {
                return builder_helpers::handle_unknown_avp(ctx, &avp, offset, "7");
            }
            if code == base::AVP_SESSION_ID {
                let value = builder_helpers::parse_string_value(avp.value, value_offset, "8.8")?;
                builder_helpers::set_once(&mut session_id, Redacted::from(value), offset, "8.8")?;
            } else if code == base::AVP_RESULT_CODE {
                let value = builder_helpers::parse_u32_value(avp.value, value_offset, "7.1")?;
                builder_helpers::set_once(&mut result_code, value, offset, "7.1")?;
            } else if code == base::AVP_ORIGIN_HOST {
                let value = builder_helpers::parse_string_value(avp.value, value_offset, "6.3")?;
                builder_helpers::set_once(&mut origin_host, Redacted::from(value), offset, "6.3")?;
            } else if code == base::AVP_ORIGIN_REALM {
                let value = builder_helpers::parse_string_value(avp.value, value_offset, "6.4")?;
                builder_helpers::set_once(&mut origin_realm, Redacted::from(value), offset, "6.4")?;
            } else if code == AVP_ACCOUNTING_RECORD_TYPE {
                let value = builder_helpers::parse_u32_value(avp.value, value_offset, "9.8.1")?;
                builder_helpers::set_once(
                    &mut accounting_record_type,
                    AccountingRecordType::from_value(value),
                    offset,
                    "9.8.1",
                )?;
            } else if code == AVP_ACCOUNTING_RECORD_NUMBER {
                let value = builder_helpers::parse_u32_value(avp.value, value_offset, "9.8.3")?;
                builder_helpers::set_once(&mut accounting_record_number, value, offset, "9.8.3")?;
            } else if code == base::AVP_ACCT_APPLICATION_ID {
                let value = builder_helpers::parse_u32_value(avp.value, value_offset, "6.9")?;
                builder_helpers::set_once(&mut acct_application_id, value, offset, "6.9")?;
            } else if code == base::AVP_ORIGIN_STATE_ID {
                let value = builder_helpers::parse_u32_value(avp.value, value_offset, "8.16")?;
                builder_helpers::set_once(&mut origin_state_id, value, offset, "8.16")?;
            } else if code == AVP_EVENT_TIMESTAMP {
                let value = builder_helpers::parse_u32_value(avp.value, value_offset, "5.3.2")?;
                builder_helpers::set_once(&mut event_timestamp, value, offset, "5.3.2")?;
            } else {
                builder_helpers::handle_unknown_avp(ctx, &avp, offset, "7")?;
            }
            Ok(())
        },
    )?;
    let acct_application_id = builder_helpers::require_field(
        acct_application_id,
        "Rf ACA requires Acct-Application-Id",
        "7",
    )?;
    if acct_application_id != APPLICATION_ID.get() {
        return Err(DecodeError::new(
            DecodeErrorCode::Structural {
                reason:
                    "Rf ACA Acct-Application-Id does not match the Rf accounting application id",
            },
            crate::DIAMETER_HEADER_LEN,
        )
        .with_spec_ref(SpecRef::new("ietf", "RFC6733", "7")));
    }
    Ok(RfAccountingAnswer {
        session_id: builder_helpers::require_field(session_id, "Rf ACA requires Session-Id", "7")?,
        result_code: builder_helpers::require_field(
            result_code,
            "Rf ACA requires Result-Code",
            "7",
        )?,
        origin_host: builder_helpers::require_field(
            origin_host,
            "Rf ACA requires Origin-Host",
            "7",
        )?,
        origin_realm: builder_helpers::require_field(
            origin_realm,
            "Rf ACA requires Origin-Realm",
            "7",
        )?,
        accounting_record_type: builder_helpers::require_field(
            accounting_record_type,
            "Rf ACA requires Accounting-Record-Type",
            "7",
        )?,
        accounting_record_number: builder_helpers::require_field(
            accounting_record_number,
            "Rf ACA requires Accounting-Record-Number",
            "7",
        )?,
        acct_application_id,
        origin_state_id,
        event_timestamp,
    })
}

fn parse_service_information(
    value: &[u8],
    ctx: DecodeContext,
    base_offset: usize,
    depth: usize,
) -> Result<(Vec<SubscriptionId>, Option<PsInformation>), DecodeError> {
    let mut subscription_ids = Vec::new();
    let mut ps_information = None;
    builder_helpers::for_each_avp(value, ctx, base_offset, depth, |offset, avp| {
        let value_offset = builder_helpers::offset_add(offset, avp.header.header_len(), "7.2.192")?;
        if avp.header.code == AVP_SUBSCRIPTION_ID && avp.header.vendor_id.is_none() {
            validate_subscription_id_outer_flags(&avp.header, offset)?;
            subscription_ids.push(parse_subscription_id(
                avp.value,
                ctx,
                value_offset,
                depth + 1,
            )?);
        } else if avp.header.code == AVP_PS_INFORMATION
            && avp.header.vendor_id == Some(VENDOR_ID_3GPP)
        {
            builder_helpers::set_once(
                &mut ps_information,
                parse_ps_information(avp.value, ctx, value_offset, depth + 1)?,
                offset,
                "7.2.192",
            )?;
        } else {
            builder_helpers::handle_unknown_avp(ctx, &avp, offset, "7.2.192")?;
        }
        Ok(())
    })?;
    Ok((subscription_ids, ps_information))
}

fn append_service_data_container_avp(
    dst: &mut BytesMut,
    usage: &ServiceDataContainer,
    ctx: EncodeContext,
) -> Result<(), EncodeError> {
    let mut value = BytesMut::new();
    for (code, count) in [
        (AVP_ACCOUNTING_INPUT_OCTETS, usage.accounting_input_octets),
        (AVP_ACCOUNTING_OUTPUT_OCTETS, usage.accounting_output_octets),
    ] {
        if let Some(count) = count {
            builder_helpers::append_u64_avp(&mut value, code, count, true, ctx)?;
        }
    }
    for (code, field) in [
        (AVP_RATING_GROUP, usage.rating_group),
        (AVP_SERVICE_IDENTIFIER, usage.service_identifier),
    ] {
        if let Some(field) = field {
            builder_helpers::append_u32_avp(&mut value, code, field, true, ctx)?;
        }
    }
    if let Some(time) = usage.time_usage {
        builder_helpers::append_vendor_u32_avp(
            &mut value,
            AVP_TIME_USAGE,
            VENDOR_ID_3GPP,
            time,
            true,
            ctx,
        )?;
    }
    builder_helpers::append_avp(
        dst,
        AvpHeader::vendor(AVP_SERVICE_DATA_CONTAINER, VENDOR_ID_3GPP, true),
        &value,
        ctx,
    )
}

fn parse_service_data_container(
    value: &[u8],
    ctx: DecodeContext,
    base_offset: usize,
    depth: usize,
) -> Result<ServiceDataContainer, DecodeError> {
    let mut usage = ServiceDataContainer {
        accounting_input_octets: None,
        accounting_output_octets: None,
        time_usage: None,
        rating_group: None,
        service_identifier: None,
    };
    builder_helpers::for_each_avp(value, ctx, base_offset, depth, |offset, avp| {
        let value_offset = builder_helpers::offset_add(offset, avp.header.header_len(), "7.2.189")?;
        let key = match avp.header.vendor_id {
            Some(vendor) => AvpKey::vendor(avp.header.code, vendor),
            None => AvpKey::ietf(avp.header.code),
        };
        if key == AvpKey::ietf(AVP_ACCOUNTING_INPUT_OCTETS)
            || key == AvpKey::ietf(AVP_ACCOUNTING_OUTPUT_OCTETS)
        {
            let slot = if key.code() == AVP_ACCOUNTING_INPUT_OCTETS {
                &mut usage.accounting_input_octets
            } else {
                &mut usage.accounting_output_octets
            };
            builder_helpers::set_once(
                slot,
                builder_helpers::parse_u64_value(avp.value, value_offset, "7.2.189")?,
                offset,
                "7.2.189",
            )?;
        } else if key == AvpKey::ietf(AVP_RATING_GROUP)
            || key == AvpKey::ietf(AVP_SERVICE_IDENTIFIER)
            || key == AvpKey::vendor(AVP_TIME_USAGE, VENDOR_ID_3GPP)
        {
            let slot = if key.code() == AVP_RATING_GROUP {
                &mut usage.rating_group
            } else if key.code() == AVP_SERVICE_IDENTIFIER {
                &mut usage.service_identifier
            } else {
                &mut usage.time_usage
            };
            builder_helpers::set_once(
                slot,
                builder_helpers::parse_u32_value(avp.value, value_offset, "7.2.189")?,
                offset,
                "7.2.189",
            )?;
        } else {
            builder_helpers::handle_unknown_avp(ctx, &avp, offset, "7.2.189")?;
        }
        Ok(())
    })?;
    Ok(usage)
}

fn append_ps_information_avp(
    dst: &mut BytesMut,
    ps: &PsInformation,
    ctx: EncodeContext,
) -> Result<(), EncodeError> {
    let mut value = BytesMut::new();
    if let Some(charging_id) = ps.charging_id {
        builder_helpers::append_vendor_u32_avp(
            &mut value,
            AVP_3GPP_CHARGING_ID,
            VENDOR_ID_3GPP,
            charging_id,
            false,
            ctx,
        )?;
    }
    if let Some(pdp_type) = ps.pdp_type {
        builder_helpers::append_vendor_u32_avp(
            &mut value,
            AVP_3GPP_PDP_TYPE,
            VENDOR_ID_3GPP,
            pdp_type,
            false,
            ctx,
        )?;
    }
    if let Some(sgsn_address) = ps.sgsn_address.as_ref() {
        let mut address_value = BytesMut::new();
        builder_helpers::encode_address_value(&mut address_value, **sgsn_address);
        builder_helpers::append_vendor_octet_string_avp(
            &mut value,
            AVP_SGSN_ADDRESS,
            VENDOR_ID_3GPP,
            &address_value,
            true,
            ctx,
        )?;
    }
    if let Some(ggsn_address) = ps.ggsn_address.as_ref() {
        let mut address_value = BytesMut::new();
        builder_helpers::encode_address_value(&mut address_value, **ggsn_address);
        builder_helpers::append_vendor_octet_string_avp(
            &mut value,
            AVP_GGSN_ADDRESS,
            VENDOR_ID_3GPP,
            &address_value,
            true,
            ctx,
        )?;
    }
    for usage in &ps.service_data_containers {
        append_service_data_container_avp(&mut value, usage, ctx)?;
    }
    builder_helpers::append_avp(
        dst,
        AvpHeader::vendor(AVP_PS_INFORMATION, VENDOR_ID_3GPP, true),
        &value,
        ctx,
    )
}

fn parse_ps_information(
    value: &[u8],
    ctx: DecodeContext,
    base_offset: usize,
    depth: usize,
) -> Result<PsInformation, DecodeError> {
    let mut charging_id = None;
    let mut pdp_type = None;
    let mut sgsn_address = None;
    let mut ggsn_address = None;
    let mut service_data_containers = Vec::new();
    builder_helpers::for_each_avp(value, ctx, base_offset, depth, |offset, avp| {
        let value_offset = builder_helpers::offset_add(offset, avp.header.header_len(), "TS32299")?;
        let code = avp.header.code;
        let vendor_id = avp.header.vendor_id;
        if code == AVP_3GPP_CHARGING_ID && vendor_id == Some(VENDOR_ID_3GPP) {
            let value = builder_helpers::parse_u32_value(avp.value, value_offset, "TS32299")?;
            builder_helpers::set_once(&mut charging_id, value, offset, "TS32299")?;
        } else if code == AVP_3GPP_PDP_TYPE && vendor_id == Some(VENDOR_ID_3GPP) {
            let value = builder_helpers::parse_u32_value(avp.value, value_offset, "TS32299")?;
            builder_helpers::set_once(&mut pdp_type, value, offset, "TS32299")?;
        } else if code == AVP_SGSN_ADDRESS && vendor_id == Some(VENDOR_ID_3GPP) {
            builder_helpers::set_once(
                &mut sgsn_address,
                Redacted::new(builder_helpers::parse_address_value(
                    avp.value,
                    value_offset,
                    "TS32299",
                )?),
                offset,
                "TS32299",
            )?;
        } else if code == AVP_GGSN_ADDRESS && vendor_id == Some(VENDOR_ID_3GPP) {
            builder_helpers::set_once(
                &mut ggsn_address,
                Redacted::new(builder_helpers::parse_address_value(
                    avp.value,
                    value_offset,
                    "TS32299",
                )?),
                offset,
                "TS32299",
            )?;
        } else if code == AVP_SERVICE_DATA_CONTAINER && vendor_id == Some(VENDOR_ID_3GPP) {
            service_data_containers.push(parse_service_data_container(
                avp.value,
                ctx,
                value_offset,
                depth + 1,
            )?);
        } else {
            builder_helpers::handle_unknown_avp(ctx, &avp, offset, "TS32299")?;
        }
        Ok(())
    })?;
    Ok(PsInformation {
        charging_id,
        pdp_type,
        sgsn_address,
        ggsn_address,
        service_data_containers,
    })
}

fn encode_structural_error(reason: &'static str) -> EncodeError {
    EncodeError::new(EncodeErrorCode::Structural { reason })
        .with_spec_ref(SpecRef::new("ietf", "RFC6733", "7"))
}
