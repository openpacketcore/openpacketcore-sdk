use bytes::BytesMut;
use opc_proto_gtpv2c::{
    s2b_create_session_accepted_response, s2b_create_session_rejected_response,
    s2b_create_session_request, s2b_delete_session_request, s2b_delete_session_response,
    s2b_echo_request, s2b_echo_response, s2b_modify_bearer_response,
    s2b_ue_ipsec_tunnel_update_request, s2b_update_bearer_request, s2b_update_bearer_response,
    AccessPointName, AggregateMaximumBitRate, BearerContext, CauseValue, EpsBearerId,
    FullyQualifiedTeid, MessageDirection, MessageType, OwnedMessage, PdnAddressAllocation, PlmnId,
    RatType, RatTypeValue, Recovery, S2bCreateSessionAcceptedResponse,
    S2bCreateSessionRejectedResponse, S2bCreateSessionRequest, S2bDeleteSessionRequest,
    S2bDeleteSessionResponse, S2bMessage, S2bModifyBearerResponse, S2bUeIpsecTunnelUpdateEndpoint,
    S2bUeIpsecTunnelUpdateRequest, S2bUpdateBearerRequest, S2bUpdateBearerRequestContext,
    S2bUpdateBearerResponse, S2bUpdateBearerResult, SelectionMode, SelectionModeValue,
    ServingNetwork, TbcdDigits, TypedIe, TypedIeValue,
};
use opc_protocol::{DecodeContext, DuplicateIePolicy, Encode, EncodeContext, ValidationLevel};
use std::io::{Error as IoError, ErrorKind};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    round_trip_profile_message(
        s2b_echo_request(0x010201, Recovery { restart_counter: 7 })?,
        MessageType::EchoRequest,
        MessageDirection::Request,
    )?;
    round_trip_profile_message(
        s2b_echo_response(0x010201, Recovery { restart_counter: 8 })?,
        MessageType::EchoResponse,
        MessageDirection::Response,
    )?;

    round_trip_profile_message(
        s2b_create_session_request(S2bCreateSessionRequest {
            sequence_number: 0x010202,
            imsi: TbcdDigits::new("001010123456789"),
            rat_type: RatType {
                value: RatTypeValue::Wlan,
            },
            serving_network: ServingNetwork {
                plmn: PlmnId::new("001", "01"),
            },
            sender_f_teid: sender_f_teid(0x1020_3040),
            apn: AccessPointName::new(vec!["internet".to_string()]),
            selection_mode: SelectionMode {
                value: SelectionModeValue::MsOrNetworkProvidedSubscriptionVerified,
            },
            paa: PdnAddressAllocation::static_ipv4([10, 0, 0, 1])?,
            bearer_context: bearer_context(5),
            additional_ies: Vec::new(),
        })?,
        MessageType::CreateSessionRequest,
        MessageDirection::Request,
    )?;

    round_trip_profile_message(
        s2b_create_session_accepted_response(S2bCreateSessionAcceptedResponse {
            sequence_number: 0x010203,
            response_teid: 0x5566_7788,
            pgw_control_f_teid: pgw_control_f_teid(0x2030_4050),
            bearer_context: bearer_context(5),
            additional_ies: Vec::new(),
        })?,
        MessageType::CreateSessionResponse,
        MessageDirection::Response,
    )?;

    round_trip_profile_message(
        s2b_create_session_rejected_response(S2bCreateSessionRejectedResponse {
            sequence_number: 0x010204,
            response_teid: 0x5566_7788,
            cause: CauseValue::InvalidMessageFormat,
            additional_ies: Vec::new(),
        })?,
        MessageType::CreateSessionResponse,
        MessageDirection::Response,
    )?;

    round_trip_profile_message(
        s2b_ue_ipsec_tunnel_update_request(S2bUeIpsecTunnelUpdateRequest {
            sequence_number: 0x010205,
            teid: 0x0102_0304,
            wlan_location: None,
            wlan_location_timestamp: None,
            endpoint: S2bUeIpsecTunnelUpdateEndpoint::General,
            additional_ies: Vec::new(),
        })?,
        MessageType::ModifyBearerRequest,
        MessageDirection::Request,
    )?;
    round_trip_profile_message(
        s2b_modify_bearer_response(S2bModifyBearerResponse {
            sequence_number: 0x010206,
            teid: 0x0102_0304,
            cause: CauseValue::RequestAccepted,
            additional_ies: Vec::new(),
        })?,
        MessageType::ModifyBearerResponse,
        MessageDirection::Response,
    )?;

    round_trip_profile_message(
        s2b_delete_session_request(S2bDeleteSessionRequest {
            sequence_number: 0x010207,
            teid: 0x0102_0304,
            linked_ebi: EpsBearerId { value: 5 },
            additional_ies: Vec::new(),
        })?,
        MessageType::DeleteSessionRequest,
        MessageDirection::Request,
    )?;
    round_trip_profile_message(
        s2b_delete_session_response(S2bDeleteSessionResponse {
            sequence_number: 0x010208,
            teid: 0x0102_0304,
            cause: CauseValue::RequestAccepted,
            additional_ies: Vec::new(),
        })?,
        MessageType::DeleteSessionResponse,
        MessageDirection::Response,
    )?;

    round_trip_profile_message(
        s2b_update_bearer_request(S2bUpdateBearerRequest {
            sequence_number: 0x010209,
            teid: 0x0102_0304,
            message_priority: None,
            apn_ambr: AggregateMaximumBitRate {
                uplink: 64_000,
                downlink: 128_000,
            },
            bearer_contexts: vec![S2bUpdateBearerRequestContext {
                ebi: EpsBearerId { value: 7 },
                tft: None,
                bearer_qos: None,
                additional_ies: Vec::new(),
            }],
            additional_ies: Vec::new(),
        })?,
        MessageType::UpdateBearerRequest,
        MessageDirection::Request,
    )?;
    round_trip_profile_message(
        s2b_update_bearer_response(S2bUpdateBearerResponse {
            sequence_number: 0x01020a,
            teid: 0x0102_0304,
            message_priority: None,
            cause: CauseValue::RequestAccepted,
            bearer_contexts: vec![S2bUpdateBearerResult {
                ebi: EpsBearerId { value: 7 },
                cause: CauseValue::RequestAccepted,
                additional_ies: Vec::new(),
            }],
            additional_ies: Vec::new(),
        })?,
        MessageType::UpdateBearerResponse,
        MessageDirection::Response,
    )?;

    Ok(())
}

fn round_trip_profile_message(
    message: OwnedMessage,
    expected_type: MessageType,
    expected_direction: MessageDirection,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut encoded = BytesMut::new();
    message.encode(&mut encoded, EncodeContext::default())?;

    let (tail, decoded) = S2bMessage::decode(&encoded, procedure_context())?;
    if !tail.is_empty() {
        return Err(invalid_data("profile decode left trailing bytes").into());
    }
    if decoded.message_type() != expected_type {
        return Err(invalid_data(format!(
            "decoded {:?}, expected {:?}",
            decoded.message_type(),
            expected_type
        ))
        .into());
    }

    let view = decoded
        .as_view()
        .ok_or_else(|| invalid_data("profile decode returned raw fallback"))?;
    if view.direction != expected_direction {
        return Err(invalid_data(format!(
            "decoded {:?}, expected {:?}",
            view.direction, expected_direction
        ))
        .into());
    }

    Ok(())
}

fn procedure_context() -> DecodeContext {
    DecodeContext {
        validation_level: ValidationLevel::ProcedureAware,
        duplicate_ie_policy: DuplicateIePolicy::Reject,
        ..DecodeContext::default()
    }
}

fn sender_f_teid(teid: u32) -> FullyQualifiedTeid {
    FullyQualifiedTeid {
        interface_type: 11,
        teid,
        ipv4: Some([192, 0, 2, 1]),
        ipv6: None,
    }
}

fn pgw_control_f_teid(teid: u32) -> FullyQualifiedTeid {
    FullyQualifiedTeid {
        interface_type: opc_proto_gtpv2c::INTERFACE_TYPE_S2B_PGW_GTP_C,
        teid,
        ipv4: Some([192, 0, 2, 2]),
        ipv6: None,
    }
}

fn bearer_context(ebi: u8) -> BearerContext<'static> {
    BearerContext {
        members: vec![TypedIe {
            instance: 0,
            value: TypedIeValue::EpsBearerId(EpsBearerId { value: ebi }),
        }],
    }
}

fn invalid_data(message: impl Into<String>) -> IoError {
    IoError::new(ErrorKind::InvalidData, message.into())
}
