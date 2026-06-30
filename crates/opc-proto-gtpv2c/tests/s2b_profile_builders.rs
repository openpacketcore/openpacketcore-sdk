use bytes::BytesMut;
use opc_proto_gtpv2c::{
    decode_echo_message_evidence, s2b_create_session_accepted_response,
    s2b_create_session_rejected_response, s2b_create_session_request, s2b_echo_request,
    s2b_echo_response, AccessPointName, BearerContext, CauseValue, EpsBearerId, FullyQualifiedTeid,
    MessageDirection, PdnAddressAllocation, PdnType, PdnTypeValue, PlmnId, RatType, RatTypeValue,
    Recovery, S2bCreateSessionAcceptedResponse, S2bCreateSessionRejectedResponse,
    S2bCreateSessionRequest, S2bMessage, S2bProfileBuildError, SelectionMode, SelectionModeValue,
    ServingNetwork, TbcdDigits, TypedIe, TypedIeValue,
};
use opc_protocol::{DecodeContext, DecodeErrorCode, Encode, EncodeContext, ValidationLevel};

fn procedure_context() -> DecodeContext {
    DecodeContext {
        validation_level: ValidationLevel::ProcedureAware,
        ..DecodeContext::default()
    }
}

fn encode(message: &opc_proto_gtpv2c::OwnedMessage) -> BytesMut {
    let mut encoded = BytesMut::new();
    message
        .encode(&mut encoded, EncodeContext::default())
        .expect("profile message encodes");
    encoded
}

fn imsi() -> TbcdDigits {
    TbcdDigits::new("001010123456789")
}

fn serving_network() -> ServingNetwork {
    ServingNetwork {
        plmn: PlmnId::new("001", "01"),
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

fn bearer_context(ebi: u8) -> BearerContext<'static> {
    BearerContext {
        members: vec![TypedIe {
            instance: 0,
            value: TypedIeValue::EpsBearerId(EpsBearerId { value: ebi }),
        }],
    }
}

fn create_session_request_input() -> S2bCreateSessionRequest<'static> {
    S2bCreateSessionRequest {
        sequence_number: 0x010203,
        imsi: imsi(),
        rat_type: RatType {
            value: RatTypeValue::Wlan,
        },
        serving_network: serving_network(),
        sender_f_teid: sender_f_teid(0x1020_3040),
        apn: AccessPointName::new(vec!["internet".to_string()]),
        selection_mode: SelectionMode {
            value: SelectionModeValue::MsOrNetworkProvidedSubscriptionVerified,
        },
        pdn_type: PdnType {
            value: PdnTypeValue::Ipv4,
        },
        paa: PdnAddressAllocation {
            pdn_type: PdnTypeValue::Ipv4,
            ipv6_prefix_length: None,
            ipv6_prefix: None,
            ipv4: Some([10, 0, 0, 1]),
        },
        bearer_context: bearer_context(5),
        additional_ies: Vec::new(),
    }
}

#[test]
fn echo_builders_roundtrip_through_procedure_aware_decode() {
    let request =
        s2b_echo_request(0x010203, Recovery { restart_counter: 7 }).expect("echo request builds");
    let encoded_request = encode(&request);
    let request_evidence = decode_echo_message_evidence(&encoded_request, procedure_context())
        .expect("echo request evidence decodes");
    assert_eq!(request_evidence.direction, MessageDirection::Request);
    assert_eq!(request_evidence.sequence_number, 0x010203);
    assert_eq!(request_evidence.restart_counter, 7);

    let response =
        s2b_echo_response(0x010203, Recovery { restart_counter: 8 }).expect("echo response builds");
    let encoded_response = encode(&response);
    let response_evidence = decode_echo_message_evidence(&encoded_response, procedure_context())
        .expect("echo response evidence decodes");
    assert_eq!(response_evidence.direction, MessageDirection::Response);
    assert_eq!(response_evidence.sequence_number, 0x010203);
    assert_eq!(response_evidence.restart_counter, 8);
}

#[test]
fn create_session_request_builder_roundtrips_without_raw_byte_assembly() {
    let request = s2b_create_session_request(create_session_request_input())
        .expect("create session request builds");
    let encoded = encode(&request);

    let (tail, decoded) = S2bMessage::decode(&encoded, procedure_context())
        .expect("procedure-aware create session request decodes");
    assert!(tail.is_empty());
    let view = decoded.as_view().expect("typed S2b view");
    assert_eq!(view.direction, MessageDirection::Request);
    assert_eq!(view.header.sequence_number, 0x010203);
    assert!(matches!(decoded, S2bMessage::CreateSessionRequest(_)));
}

#[test]
fn create_session_response_builders_project_stable_summaries() {
    let accepted = s2b_create_session_accepted_response(S2bCreateSessionAcceptedResponse {
        sequence_number: 0x010204,
        response_teid: 0x5566_7788,
        sender_f_teid: sender_f_teid(0x2030_4050),
        bearer_context: bearer_context(6),
        additional_ies: Vec::new(),
    })
    .expect("accepted response builds");
    let encoded_accepted = encode(&accepted);
    let accepted_summary = match S2bMessage::decode(&encoded_accepted, procedure_context())
        .expect("accepted response decodes")
        .1
        .create_session_response_summary()
        .expect("accepted response projects")
    {
        opc_proto_gtpv2c::CreateSessionResponseSummary::Accepted(summary) => summary,
        opc_proto_gtpv2c::CreateSessionResponseSummary::Rejected(_) => {
            panic!("accepted response projected as rejected")
        }
    };
    assert_eq!(accepted_summary.response_teid, 0x5566_7788);
    assert_eq!(accepted_summary.bearer_ebi.value, 6);

    let rejected = s2b_create_session_rejected_response(S2bCreateSessionRejectedResponse {
        sequence_number: 0x010205,
        response_teid: 0x5566_7788,
        cause: CauseValue::InvalidMessageFormat,
        additional_ies: Vec::new(),
    })
    .expect("rejected response builds");
    let encoded_rejected = encode(&rejected);
    let rejected_summary = match S2bMessage::decode(&encoded_rejected, procedure_context())
        .expect("rejected response decodes")
        .1
        .create_session_response_summary()
        .expect("rejected response projects")
    {
        opc_proto_gtpv2c::CreateSessionResponseSummary::Rejected(summary) => summary,
        opc_proto_gtpv2c::CreateSessionResponseSummary::Accepted(_) => {
            panic!("rejected response projected as accepted")
        }
    };
    assert_eq!(rejected_summary.response_teid, 0x5566_7788);
    assert_eq!(rejected_summary.cause, CauseValue::InvalidMessageFormat);
}

#[test]
fn create_session_request_builder_rejects_duplicate_profile_singletons() {
    let mut request = create_session_request_input();
    request.additional_ies.push(TypedIe {
        instance: 0,
        value: TypedIeValue::Imsi(TbcdDigits::new("001010999999999")),
    });

    let error = s2b_create_session_request(request).expect_err("duplicate IMSI is rejected");
    match error {
        S2bProfileBuildError::Validate(source) => {
            assert_eq!(source.code(), &DecodeErrorCode::DuplicateIe);
        }
        S2bProfileBuildError::Encode(source) => {
            panic!("expected validation error, got encode error: {source}");
        }
    }
}
