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
use super::VENDOR_ID_3GPP;
use crate::avp::dictionary::Redacted;
use crate::base;
use crate::dictionary::{
    ApplicationDefinition, AvpDataType, AvpDefinition, AvpFlagRules, AvpKey, CommandDefinition,
    CommandKind, Dictionary,
};
use crate::{ApplicationId, AvpCode, AvpHeader, CommandCode, Message, OwnedMessage};

/// Diameter accounting application identifier used by 3GPP Rf.
pub const APPLICATION_ID: ApplicationId = ApplicationId::new(3);

/// Rf Accounting command code (RFC 6733 §7).
pub const COMMAND_ACCOUNTING: CommandCode = CommandCode::new(271);

/// Accounting-Record-Type AVP code (RFC 6733 §9.8.1).
pub const AVP_ACCOUNTING_RECORD_TYPE: AvpCode = AvpCode::new(480);
/// Accounting-Record-Number AVP code (RFC 6733 §9.8.2).
pub const AVP_ACCOUNTING_RECORD_NUMBER: AvpCode = AvpCode::new(485);
/// Event-Timestamp AVP code (RFC 6733 §5.3.2).
pub const AVP_EVENT_TIMESTAMP: AvpCode = AvpCode::new(55);
/// Subscription-Id grouped AVP code (RFC 4006 §8.46).
pub const AVP_SUBSCRIPTION_ID: AvpCode = AvpCode::new(443);
/// Subscription-Id-Data AVP code (RFC 4006 §8.47).
pub const AVP_SUBSCRIPTION_ID_DATA: AvpCode = AvpCode::new(444);
/// Subscription-Id-Type AVP code (RFC 4006 §8.48).
pub const AVP_SUBSCRIPTION_ID_TYPE: AvpCode = AvpCode::new(450);
/// Multiple-Services-Credit-Control grouped AVP code (RFC 4006 §8.16).
pub const AVP_MULTIPLE_SERVICES_CREDIT_CONTROL: AvpCode = AvpCode::new(456);
/// Used-Service-Unit grouped AVP code (RFC 4006 §8.19).
pub const AVP_USED_SERVICE_UNIT: AvpCode = AvpCode::new(446);
/// CC-Time AVP code (RFC 4006 §8.21).
pub const AVP_CC_TIME: AvpCode = AvpCode::new(420);
/// CC-Total-Octets AVP code (RFC 4006 §8.22).
pub const AVP_CC_TOTAL_OCTETS: AvpCode = AvpCode::new(421);
/// CC-Input-Octets AVP code (RFC 4006 §8.23).
pub const AVP_CC_INPUT_OCTETS: AvpCode = AvpCode::new(412);
/// CC-Output-Octets AVP code (RFC 4006 §8.24).
pub const AVP_CC_OUTPUT_OCTETS: AvpCode = AvpCode::new(414);
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
pub const AVP_3GPP_SGSN_ADDRESS: AvpCode = AvpCode::new(6);
/// GGSN-Address AVP code (3GPP TS 32.299).
pub const AVP_3GPP_GGSN_ADDRESS: AvpCode = AvpCode::new(7);

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

const RF_AVPS: [AvpDefinition; 20] = [
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
        SpecRef::new("ietf", "RFC6733", "9.8.2"),
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
        AvpFlagRules::base_mandatory(),
        SpecRef::new("ietf", "RFC4006", "8.46"),
    ),
    AvpDefinition::new(
        AvpKey::ietf(AVP_SUBSCRIPTION_ID_TYPE),
        "Subscription-Id-Type",
        AvpDataType::Enumerated,
        AvpFlagRules::base_mandatory(),
        SpecRef::new("ietf", "RFC4006", "8.47"),
    ),
    AvpDefinition::new(
        AvpKey::ietf(AVP_SUBSCRIPTION_ID_DATA),
        "Subscription-Id-Data",
        AvpDataType::Utf8String,
        AvpFlagRules::base_mandatory(),
        SpecRef::new("ietf", "RFC4006", "8.48"),
    ),
    AvpDefinition::new(
        AvpKey::ietf(AVP_USED_SERVICE_UNIT),
        "Used-Service-Unit",
        AvpDataType::Grouped,
        AvpFlagRules::base_optional(),
        SpecRef::new("ietf", "RFC4006", "8.19"),
    ),
    AvpDefinition::new(
        AvpKey::ietf(AVP_CC_TIME),
        "CC-Time",
        AvpDataType::Unsigned32,
        AvpFlagRules::base_optional(),
        SpecRef::new("ietf", "RFC4006", "8.21"),
    ),
    AvpDefinition::new(
        AvpKey::ietf(AVP_CC_TOTAL_OCTETS),
        "CC-Total-Octets",
        AvpDataType::Unsigned64,
        AvpFlagRules::base_optional(),
        SpecRef::new("ietf", "RFC4006", "8.22"),
    ),
    AvpDefinition::new(
        AvpKey::ietf(AVP_CC_INPUT_OCTETS),
        "CC-Input-Octets",
        AvpDataType::Unsigned64,
        AvpFlagRules::base_optional(),
        SpecRef::new("ietf", "RFC4006", "8.23"),
    ),
    AvpDefinition::new(
        AvpKey::ietf(AVP_CC_OUTPUT_OCTETS),
        "CC-Output-Octets",
        AvpDataType::Unsigned64,
        AvpFlagRules::base_optional(),
        SpecRef::new("ietf", "RFC4006", "8.24"),
    ),
    AvpDefinition::new(
        AvpKey::ietf(AVP_MULTIPLE_SERVICES_CREDIT_CONTROL),
        "Multiple-Services-Credit-Control",
        AvpDataType::Grouped,
        AvpFlagRules::base_optional(),
        SpecRef::new("ietf", "RFC4006", "8.16"),
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
        AvpDataType::Unsigned32,
        AvpFlagRules::vendor_specific(),
        SpecRef::new("3gpp", "TS32299", "3GPP-Charging-Id"),
    ),
    AvpDefinition::new(
        AvpKey::vendor(AVP_3GPP_PDP_TYPE, VENDOR_ID_3GPP),
        "3GPP-PDP-Type",
        AvpDataType::Unsigned32,
        AvpFlagRules::vendor_specific(),
        SpecRef::new("3gpp", "TS32299", "3GPP-PDP-Type"),
    ),
    AvpDefinition::new(
        AvpKey::vendor(AVP_3GPP_SGSN_ADDRESS, VENDOR_ID_3GPP),
        "SGSN-Address",
        AvpDataType::Address,
        AvpFlagRules::vendor_specific(),
        SpecRef::new("3gpp", "TS32299", "SGSN-Address"),
    ),
    AvpDefinition::new(
        AvpKey::vendor(AVP_3GPP_GGSN_ADDRESS, VENDOR_ID_3GPP),
        "GGSN-Address",
        AvpDataType::Address,
        AvpFlagRules::vendor_specific(),
        SpecRef::new("3gpp", "TS32299", "GGSN-Address"),
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

/// Subscription-Id-Type values from RFC 4006 §8.47.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SubscriptionIdType {
    /// End User E.164.
    EndUserE164,
    /// End User IMSI.
    EndUserImsi,
    /// End User SIP URI.
    EndUserSipUri,
    /// End User NAI.
    EndUserNai,
    /// End User Private.
    EndUserPrivate,
    /// Unknown or application-specific value.
    Other(u32),
}

impl SubscriptionIdType {
    /// Return the wire value for this subscription-id type.
    pub const fn value(self) -> u32 {
        match self {
            Self::EndUserE164 => 0,
            Self::EndUserImsi => 1,
            Self::EndUserSipUri => 2,
            Self::EndUserNai => 3,
            Self::EndUserPrivate => 4,
            Self::Other(v) => v,
        }
    }

    /// Parse a subscription-id type from its wire value.
    pub const fn from_value(value: u32) -> Self {
        match value {
            0 => Self::EndUserE164,
            1 => Self::EndUserImsi,
            2 => Self::EndUserSipUri,
            3 => Self::EndUserNai,
            4 => Self::EndUserPrivate,
            other => Self::Other(other),
        }
    }
}

/// A single subscription identifier carried inside a Subscription-Id grouped AVP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionId {
    /// Type of subscription identifier.
    pub subscription_id_type: SubscriptionIdType,
    /// Subscription identifier value (redacted in diagnostic output).
    pub subscription_id_data: Redacted<String>,
}

/// Used-Service-Unit grouped AVP (RFC 4006 §8.19).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsedServiceUnit {
    /// CC-Time in seconds.
    pub cc_time: Option<u32>,
    /// CC-Total-Octets.
    pub cc_total_octets: Option<u64>,
    /// CC-Input-Octets.
    pub cc_input_octets: Option<u64>,
    /// CC-Output-Octets.
    pub cc_output_octets: Option<u64>,
}

/// Multiple-Services-Credit-Control grouped AVP (RFC 4006 §8.16).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultipleServicesCreditControl {
    /// Used-Service-Unit child.
    pub used_service_unit: Option<UsedServiceUnit>,
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
    /// Subscription-Id grouped AVPs.
    pub subscription_ids: Vec<SubscriptionId>,
    /// Multiple-Services-Credit-Control grouped AVPs.
    pub multiple_services_credit_controls: Vec<MultipleServicesCreditControl>,
    /// PS-Information grouped AVP.
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
    for subscription_id in &request.subscription_ids {
        append_subscription_id_avp(&mut raw_avps, subscription_id, ctx)?;
    }
    for mscc in &request.multiple_services_credit_controls {
        append_multiple_services_credit_control_avp(&mut raw_avps, mscc, ctx)?;
    }
    if let Some(ps_information) = request.ps_information.as_ref() {
        append_ps_information_avp(&mut raw_avps, ps_information, ctx)?;
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
    let mut subscription_ids = Vec::new();
    let mut multiple_services_credit_controls = Vec::new();
    let mut ps_information = None;
    builder_helpers::for_each_avp(
        message.raw_avps,
        ctx,
        crate::DIAMETER_HEADER_LEN,
        0,
        |offset, avp| {
            let value_offset = builder_helpers::offset_add(offset, avp.header.header_len(), "7")?;
            let code = avp.header.code;
            if let Some(vendor_id) = avp.header.vendor_id {
                if code == AVP_PS_INFORMATION && vendor_id == VENDOR_ID_3GPP {
                    builder_helpers::set_once(
                        &mut ps_information,
                        parse_ps_information(avp.value, ctx, value_offset, 1)?,
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
                let value = builder_helpers::parse_u32_value(avp.value, value_offset, "9.8.2")?;
                builder_helpers::set_once(&mut accounting_record_number, value, offset, "9.8.2")?;
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
            } else if code == AVP_SUBSCRIPTION_ID {
                subscription_ids.push(parse_subscription_id(avp.value, ctx, value_offset, 1)?);
            } else if code == AVP_MULTIPLE_SERVICES_CREDIT_CONTROL {
                multiple_services_credit_controls.push(parse_multiple_services_credit_control(
                    avp.value,
                    ctx,
                    value_offset,
                    1,
                )?);
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
        multiple_services_credit_controls,
        ps_information,
    })
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
                let value = builder_helpers::parse_u32_value(avp.value, value_offset, "9.8.2")?;
                builder_helpers::set_once(&mut accounting_record_number, value, offset, "9.8.2")?;
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

fn append_subscription_id_avp(
    dst: &mut BytesMut,
    subscription_id: &SubscriptionId,
    ctx: EncodeContext,
) -> Result<(), EncodeError> {
    let mut value = BytesMut::new();
    builder_helpers::append_u32_avp(
        &mut value,
        AVP_SUBSCRIPTION_ID_TYPE,
        subscription_id.subscription_id_type.value(),
        true,
        ctx,
    )?;
    builder_helpers::append_utf8_avp(
        &mut value,
        AVP_SUBSCRIPTION_ID_DATA,
        subscription_id.subscription_id_data.as_ref(),
        true,
        ctx,
    )?;
    builder_helpers::append_avp(dst, AvpHeader::ietf(AVP_SUBSCRIPTION_ID, true), &value, ctx)
}

fn parse_subscription_id(
    value: &[u8],
    ctx: DecodeContext,
    base_offset: usize,
    depth: usize,
) -> Result<SubscriptionId, DecodeError> {
    let mut subscription_id_type = None;
    let mut subscription_id_data = None;
    builder_helpers::for_each_avp(value, ctx, base_offset, depth, |offset, avp| {
        let value_offset = builder_helpers::offset_add(offset, avp.header.header_len(), "8.46")?;
        let code = avp.header.code;
        if avp.header.vendor_id.is_some() {
            return builder_helpers::handle_unknown_avp(ctx, &avp, offset, "8.46");
        }
        if code == AVP_SUBSCRIPTION_ID_TYPE {
            let value = builder_helpers::parse_u32_value(avp.value, value_offset, "8.47")?;
            builder_helpers::set_once(
                &mut subscription_id_type,
                SubscriptionIdType::from_value(value),
                offset,
                "8.46",
            )?;
        } else if code == AVP_SUBSCRIPTION_ID_DATA {
            let value = builder_helpers::parse_string_value(avp.value, value_offset, "8.48")?;
            builder_helpers::set_once(
                &mut subscription_id_data,
                Redacted::from(value),
                offset,
                "8.46",
            )?;
        } else {
            builder_helpers::handle_unknown_avp(ctx, &avp, offset, "8.46")?;
        }
        Ok(())
    })?;
    Ok(SubscriptionId {
        subscription_id_type: subscription_id_type.ok_or_else(|| {
            missing_child_error(base_offset, "missing Subscription-Id-Type child AVP")
        })?,
        subscription_id_data: subscription_id_data.ok_or_else(|| {
            missing_child_error(base_offset, "missing Subscription-Id-Data child AVP")
        })?,
    })
}

fn append_used_service_unit_avp(
    dst: &mut BytesMut,
    usu: &UsedServiceUnit,
    ctx: EncodeContext,
) -> Result<(), EncodeError> {
    let mut value = BytesMut::new();
    if let Some(cc_time) = usu.cc_time {
        builder_helpers::append_u32_avp(&mut value, AVP_CC_TIME, cc_time, true, ctx)?;
    }
    if let Some(cc_total_octets) = usu.cc_total_octets {
        builder_helpers::append_u64_avp(
            &mut value,
            AVP_CC_TOTAL_OCTETS,
            cc_total_octets,
            true,
            ctx,
        )?;
    }
    if let Some(cc_input_octets) = usu.cc_input_octets {
        builder_helpers::append_u64_avp(
            &mut value,
            AVP_CC_INPUT_OCTETS,
            cc_input_octets,
            true,
            ctx,
        )?;
    }
    if let Some(cc_output_octets) = usu.cc_output_octets {
        builder_helpers::append_u64_avp(
            &mut value,
            AVP_CC_OUTPUT_OCTETS,
            cc_output_octets,
            true,
            ctx,
        )?;
    }
    builder_helpers::append_avp(
        dst,
        AvpHeader::ietf(AVP_USED_SERVICE_UNIT, true),
        &value,
        ctx,
    )
}

fn parse_used_service_unit(
    value: &[u8],
    ctx: DecodeContext,
    base_offset: usize,
    depth: usize,
) -> Result<UsedServiceUnit, DecodeError> {
    let mut cc_time = None;
    let mut cc_total_octets = None;
    let mut cc_input_octets = None;
    let mut cc_output_octets = None;
    builder_helpers::for_each_avp(value, ctx, base_offset, depth, |offset, avp| {
        let value_offset = builder_helpers::offset_add(offset, avp.header.header_len(), "8.19")?;
        let code = avp.header.code;
        if avp.header.vendor_id.is_some() {
            return builder_helpers::handle_unknown_avp(ctx, &avp, offset, "8.19");
        }
        if code == AVP_CC_TIME {
            let value = builder_helpers::parse_u32_value(avp.value, value_offset, "8.21")?;
            builder_helpers::set_once(&mut cc_time, value, offset, "8.19")?;
        } else if code == AVP_CC_TOTAL_OCTETS {
            let value = builder_helpers::parse_u64_value(avp.value, value_offset, "8.22")?;
            builder_helpers::set_once(&mut cc_total_octets, value, offset, "8.19")?;
        } else if code == AVP_CC_INPUT_OCTETS {
            let value = builder_helpers::parse_u64_value(avp.value, value_offset, "8.23")?;
            builder_helpers::set_once(&mut cc_input_octets, value, offset, "8.19")?;
        } else if code == AVP_CC_OUTPUT_OCTETS {
            let value = builder_helpers::parse_u64_value(avp.value, value_offset, "8.24")?;
            builder_helpers::set_once(&mut cc_output_octets, value, offset, "8.19")?;
        } else {
            builder_helpers::handle_unknown_avp(ctx, &avp, offset, "8.19")?;
        }
        Ok(())
    })?;
    Ok(UsedServiceUnit {
        cc_time,
        cc_total_octets,
        cc_input_octets,
        cc_output_octets,
    })
}

fn append_multiple_services_credit_control_avp(
    dst: &mut BytesMut,
    mscc: &MultipleServicesCreditControl,
    ctx: EncodeContext,
) -> Result<(), EncodeError> {
    let mut value = BytesMut::new();
    if let Some(usu) = mscc.used_service_unit.as_ref() {
        append_used_service_unit_avp(&mut value, usu, ctx)?;
    }
    if let Some(rating_group) = mscc.rating_group {
        builder_helpers::append_u32_avp(&mut value, AVP_RATING_GROUP, rating_group, true, ctx)?;
    }
    if let Some(service_identifier) = mscc.service_identifier {
        builder_helpers::append_u32_avp(
            &mut value,
            AVP_SERVICE_IDENTIFIER,
            service_identifier,
            true,
            ctx,
        )?;
    }
    builder_helpers::append_avp(
        dst,
        AvpHeader::ietf(AVP_MULTIPLE_SERVICES_CREDIT_CONTROL, true),
        &value,
        ctx,
    )
}

fn parse_multiple_services_credit_control(
    value: &[u8],
    ctx: DecodeContext,
    base_offset: usize,
    depth: usize,
) -> Result<MultipleServicesCreditControl, DecodeError> {
    let mut used_service_unit = None;
    let mut rating_group = None;
    let mut service_identifier = None;
    builder_helpers::for_each_avp(value, ctx, base_offset, depth, |offset, avp| {
        let value_offset = builder_helpers::offset_add(offset, avp.header.header_len(), "8.16")?;
        let code = avp.header.code;
        if avp.header.vendor_id.is_some() {
            return builder_helpers::handle_unknown_avp(ctx, &avp, offset, "8.16");
        }
        if code == AVP_USED_SERVICE_UNIT {
            builder_helpers::set_once(
                &mut used_service_unit,
                parse_used_service_unit(avp.value, ctx, value_offset, depth + 1)?,
                offset,
                "8.16",
            )?;
        } else if code == AVP_RATING_GROUP {
            let value = builder_helpers::parse_u32_value(avp.value, value_offset, "8.29")?;
            builder_helpers::set_once(&mut rating_group, value, offset, "8.16")?;
        } else if code == AVP_SERVICE_IDENTIFIER {
            let value = builder_helpers::parse_u32_value(avp.value, value_offset, "8.28")?;
            builder_helpers::set_once(&mut service_identifier, value, offset, "8.16")?;
        } else {
            builder_helpers::handle_unknown_avp(ctx, &avp, offset, "8.16")?;
        }
        Ok(())
    })?;
    Ok(MultipleServicesCreditControl {
        used_service_unit,
        rating_group,
        service_identifier,
    })
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
            true,
            ctx,
        )?;
    }
    if let Some(pdp_type) = ps.pdp_type {
        builder_helpers::append_vendor_u32_avp(
            &mut value,
            AVP_3GPP_PDP_TYPE,
            VENDOR_ID_3GPP,
            pdp_type,
            true,
            ctx,
        )?;
    }
    if let Some(sgsn_address) = ps.sgsn_address.as_ref() {
        let mut address_value = BytesMut::new();
        builder_helpers::encode_address_value(&mut address_value, **sgsn_address);
        builder_helpers::append_vendor_octet_string_avp(
            &mut value,
            AVP_3GPP_SGSN_ADDRESS,
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
            AVP_3GPP_GGSN_ADDRESS,
            VENDOR_ID_3GPP,
            &address_value,
            true,
            ctx,
        )?;
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
        } else if code == AVP_3GPP_SGSN_ADDRESS && vendor_id == Some(VENDOR_ID_3GPP) {
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
        } else if code == AVP_3GPP_GGSN_ADDRESS && vendor_id == Some(VENDOR_ID_3GPP) {
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
    })
}

fn missing_child_error(base_offset: usize, reason: &'static str) -> DecodeError {
    DecodeError::new(DecodeErrorCode::Structural { reason }, base_offset)
        .with_spec_ref(SpecRef::new("ietf", "RFC6733", "grouped"))
}

fn encode_structural_error(reason: &'static str) -> EncodeError {
    EncodeError::new(EncodeErrorCode::Structural { reason })
        .with_spec_ref(SpecRef::new("ietf", "RFC6733", "7"))
}
