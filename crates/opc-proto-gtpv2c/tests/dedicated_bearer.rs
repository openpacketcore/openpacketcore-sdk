//! TS 29.274 Release 18 S2b dedicated-bearer procedure evidence.

use bytes::{Bytes, BytesMut};
use opc_proto_gtpv2c::header::MAX_SEQUENCE_NUMBER;
use opc_proto_gtpv2c::{
    correlate_create_bearer_response, correlate_delete_bearer_response,
    correlate_update_bearer_response, dedicated_bearer_decode_rejection_cause,
    encode_typed_ie_sequence, s2b_create_bearer_request, s2b_create_bearer_response,
    s2b_delete_bearer_request, s2b_delete_bearer_response, s2b_update_bearer_request,
    s2b_update_bearer_response, AdditionalProtocolConfigurationOptions, AggregateMaximumBitRate,
    BearerContext, BearerQos, CauseValue, ChargingId, DedicatedBearerErrorKind, EpsBearerId,
    FullyQualifiedTeid, Gtpv2cMonotonicMillis, Gtpv2cPeerToken, Gtpv2cTriggeredCompletion,
    Gtpv2cTriggeredRequestDisposition, Gtpv2cTriggeredTransactionError,
    Gtpv2cTriggeredTransactionPolicy, Gtpv2cTriggeredTransactions, Header, MessagePriority,
    MessageType, OwnedMessage, Procedure, ProtocolConfigurationOptions, RawIe,
    S2bCreateBearerRequest, S2bCreateBearerRequestContext, S2bCreateBearerResponse,
    S2bCreateBearerResult, S2bDeleteBearerRequest, S2bDeleteBearerResponse,
    S2bDeleteBearerResponseBody, S2bDeleteBearerResult, S2bDeleteBearerTarget, S2bMessage,
    S2bUpdateBearerRequest, S2bUpdateBearerRequestContext, S2bUpdateBearerResponse,
    S2bUpdateBearerResult, TypedIe, TypedIeValue, CREATE_BEARER_REQUEST, CREATE_BEARER_RESPONSE,
    DELETE_BEARER_REQUEST, DELETE_BEARER_RESPONSE, IE_TYPE_LOAD_CONTROL_INFORMATION,
    IE_TYPE_OVERLOAD_CONTROL_INFORMATION, IE_TYPE_PGW_CHANGE_INFO, INTERFACE_TYPE_S2B_U_EPDG_GTP_U,
    INTERFACE_TYPE_S2B_U_PGW_GTP_U, MAX_PGW_APN_LOAD_CONTROL_INFORMATION_IES,
    MAX_PGW_OVERLOAD_CONTROL_INFORMATION_IES, UPDATE_BEARER_REQUEST, UPDATE_BEARER_RESPONSE,
};
use opc_proto_tft::{
    PacketFilter, PacketFilterComponent, PacketFilterDirection, PacketFilterIdentifier,
    TrafficFlowTemplate,
};
use opc_protocol::{DecodeContext, DuplicateIePolicy, Encode, EncodeContext, ValidationLevel};

const REQUEST_TEID: u32 = 0x1020_3040;
const RESPONSE_TEID: u32 = 0x5060_7080;
const SEQUENCE: u32 = 0x01_0203;
const UNKNOWN_TOP_VALUE: &[u8] = &[0xde, 0xad];
const UNKNOWN_NESTED_VALUE: &[u8] = &[0xbe, 0xef];
const PGW_CHANGE_INFO_ONE: &[u8] = &[74, 0, 4, 0, 192, 0, 2, 1];
const PGW_CHANGE_INFO_TWO: &[u8] = &[74, 0, 4, 0, 192, 0, 2, 2];

fn procedure_context() -> DecodeContext {
    DecodeContext {
        duplicate_ie_policy: DuplicateIePolicy::Reject,
        validation_level: ValidationLevel::ProcedureAware,
        ..DecodeContext::default()
    }
}

fn structural_context() -> DecodeContext {
    DecodeContext {
        duplicate_ie_policy: DuplicateIePolicy::Reject,
        validation_level: ValidationLevel::Strict,
        ..DecodeContext::default()
    }
}

fn ebi(value: u8) -> EpsBearerId {
    EpsBearerId { value }
}

fn qos(qci: u8) -> BearerQos {
    BearerQos {
        // PCI=1, PL=3, PVI=1; ARP spare bits 8 and 2 are zero.
        priority_flags: 0x4d,
        qci,
        maximum_bitrate_uplink: 1_000_000,
        maximum_bitrate_downlink: 2_000_000,
        guaranteed_bitrate_uplink: 512_000,
        guaranteed_bitrate_downlink: 768_000,
    }
}

fn f_teid(interface_type: u8, teid: u32, host: u8) -> FullyQualifiedTeid {
    FullyQualifiedTeid {
        interface_type,
        teid,
        ipv4: Some([192, 0, 2, host]),
        ipv6: None,
    }
}

fn tft(identifier: u8, precedence: u8, remote_port: u16) -> TrafficFlowTemplate {
    let identifier = PacketFilterIdentifier::new(identifier)
        .expect("fixture packet-filter identifier must be valid");
    let filter = PacketFilter::new(
        identifier,
        PacketFilterDirection::Bidirectional,
        precedence,
        vec![
            PacketFilterComponent::ProtocolIdentifierNextHeader(17),
            PacketFilterComponent::SingleRemotePort(remote_port),
        ],
    )
    .expect("fixture packet filter must be valid");
    TrafficFlowTemplate::create_new(vec![filter], Vec::new()).expect("fixture TFT must be valid")
}

fn raw_ie(ie_type: u8, instance: u8, value: &'static [u8]) -> TypedIe<'static> {
    TypedIe {
        instance,
        value: TypedIeValue::Raw(RawIe {
            ie_type,
            instance,
            spare: 0,
            value,
        }),
    }
}

fn request_context(index: u8) -> S2bCreateBearerRequestContext<'static> {
    S2bCreateBearerRequestContext {
        tft: tft(
            index,
            10u8.saturating_add(index),
            4_500u16.saturating_add(u16::from(index)),
        ),
        bearer_qos: qos(index.min(4)),
        pgw_f_teid: f_teid(
            INTERFACE_TYPE_S2B_U_PGW_GTP_U,
            0x1000_0000u32.saturating_add(u32::from(index)),
            10u8.saturating_add(index),
        ),
        charging_id: ChargingId {
            value: 0x2000_0000u32.saturating_add(u32::from(index)),
        },
        additional_ies: vec![raw_ie(250, 2, UNKNOWN_NESTED_VALUE)],
    }
}

fn create_request(context_count: u8, sequence_number: u32) -> S2bCreateBearerRequest<'static> {
    S2bCreateBearerRequest {
        sequence_number,
        teid: REQUEST_TEID,
        message_priority: None,
        linked_ebi: ebi(5),
        bearer_contexts: (1..=context_count).map(request_context).collect(),
        additional_ies: vec![raw_ie(251, 3, UNKNOWN_TOP_VALUE)],
    }
}

fn accepted_result(index: u8) -> S2bCreateBearerResult<'static> {
    S2bCreateBearerResult::Accepted {
        ebi: ebi(5u8.saturating_add(index)),
        epdg_f_teid: f_teid(
            INTERFACE_TYPE_S2B_U_EPDG_GTP_U,
            0x3000_0000u32.saturating_add(u32::from(index)),
            20u8.saturating_add(index),
        ),
        pgw_f_teid: request_context(index).pgw_f_teid,
        additional_ies: vec![raw_ie(249, 4, UNKNOWN_NESTED_VALUE)],
    }
}

fn rejected_result(index: u8, cause: CauseValue) -> S2bCreateBearerResult<'static> {
    S2bCreateBearerResult::Rejected {
        ebi: ebi(5u8.saturating_add(index)),
        cause,
        pgw_f_teid: request_context(index).pgw_f_teid,
        additional_ies: vec![raw_ie(249, 4, UNKNOWN_NESTED_VALUE)],
    }
}

fn rejected_create_response(
    message_cause: CauseValue,
    bearer_cause: CauseValue,
) -> S2bCreateBearerResponse<'static> {
    S2bCreateBearerResponse {
        sequence_number: SEQUENCE,
        teid: RESPONSE_TEID,
        message_priority: None,
        cause: message_cause,
        bearer_contexts: vec![rejected_result(1, bearer_cause)],
        additional_ies: Vec::new(),
    }
}

fn rejected_delete_response(
    message_cause: CauseValue,
    bearer_cause: CauseValue,
) -> S2bDeleteBearerResponse<'static> {
    S2bDeleteBearerResponse {
        sequence_number: SEQUENCE,
        teid: RESPONSE_TEID,
        message_priority: None,
        cause: message_cause,
        body: S2bDeleteBearerResponseBody::Dedicated(vec![S2bDeleteBearerResult {
            ebi: ebi(6),
            cause: bearer_cause,
            additional_ies: Vec::new(),
        }]),
        additional_ies: Vec::new(),
    }
}

fn rejected_update_response(
    message_cause: CauseValue,
    bearer_cause: CauseValue,
) -> S2bUpdateBearerResponse<'static> {
    S2bUpdateBearerResponse {
        sequence_number: SEQUENCE,
        teid: RESPONSE_TEID,
        message_priority: None,
        cause: message_cause,
        bearer_contexts: vec![S2bUpdateBearerResult {
            ebi: ebi(6),
            cause: bearer_cause,
            additional_ies: Vec::new(),
        }],
        additional_ies: Vec::new(),
    }
}

fn encode(message: &OwnedMessage) -> Bytes {
    let mut bytes = BytesMut::new();
    message
        .encode(&mut bytes, EncodeContext::default())
        .expect("fixture message must encode");
    bytes.freeze()
}

fn owned_message(message_type: u8, teid: Option<u32>, ies: Vec<TypedIe<'_>>) -> OwnedMessage {
    let mut raw_ies = BytesMut::new();
    encode_typed_ie_sequence(&ies, &mut raw_ies, EncodeContext::default())
        .expect("fixture IEs must encode");
    let header = match teid {
        Some(teid) => Header::with_teid(message_type, teid, SEQUENCE),
        None => Header::without_teid(message_type, SEQUENCE),
    };
    OwnedMessage {
        header,
        raw_ies: raw_ies.freeze(),
    }
}

fn typed(instance: u8, value: TypedIeValue<'static>) -> TypedIe<'static> {
    TypedIe { instance, value }
}

fn valid_request_members() -> Vec<TypedIe<'static>> {
    let context = request_context(1);
    vec![
        typed(0, TypedIeValue::EpsBearerId(ebi(0))),
        typed(0, TypedIeValue::BearerTft(context.tft)),
        typed(0, TypedIeValue::BearerQos(context.bearer_qos)),
        typed(4, TypedIeValue::FullyQualifiedTeid(context.pgw_f_teid)),
        typed(0, TypedIeValue::ChargingId(context.charging_id)),
    ]
}

fn raw_create_request_with_members(members: Vec<TypedIe<'static>>) -> Bytes {
    encode(&owned_message(
        CREATE_BEARER_REQUEST,
        Some(REQUEST_TEID),
        vec![
            typed(0, TypedIeValue::EpsBearerId(ebi(5))),
            typed(0, TypedIeValue::BearerContext(BearerContext { members })),
        ],
    ))
}

#[test]
fn message_type_and_procedure_registry_uses_normative_values() {
    assert_eq!(CREATE_BEARER_REQUEST, 95);
    assert_eq!(CREATE_BEARER_RESPONSE, 96);
    assert_eq!(UPDATE_BEARER_REQUEST, 97);
    assert_eq!(UPDATE_BEARER_RESPONSE, 98);
    assert_eq!(DELETE_BEARER_REQUEST, 99);
    assert_eq!(DELETE_BEARER_RESPONSE, 100);
    assert_eq!(MessageType::from_u8(95), MessageType::CreateBearerRequest);
    assert_eq!(MessageType::from_u8(96), MessageType::CreateBearerResponse);
    assert_eq!(MessageType::from_u8(97), MessageType::UpdateBearerRequest);
    assert_eq!(MessageType::from_u8(98), MessageType::UpdateBearerResponse);
    assert_eq!(MessageType::from_u8(99), MessageType::DeleteBearerRequest);
    assert_eq!(MessageType::from_u8(100), MessageType::DeleteBearerResponse);
    assert_eq!(
        Procedure::CreateBearer.request_message_type(),
        MessageType::CreateBearerRequest
    );
    assert_eq!(
        Procedure::CreateBearer.response_message_type(),
        MessageType::CreateBearerResponse
    );
    assert_eq!(
        Procedure::UpdateSession.request_message_type(),
        MessageType::UpdateBearerRequest
    );
    assert_eq!(
        Procedure::UpdateSession.response_message_type(),
        MessageType::UpdateBearerResponse
    );
    assert_eq!(
        Procedure::DeleteBearer.request_message_type(),
        MessageType::DeleteBearerRequest
    );
    assert_eq!(
        Procedure::DeleteBearer.response_message_type(),
        MessageType::DeleteBearerResponse
    );
}

#[test]
fn create_bearer_request_round_trips_multiple_contexts_and_unknown_ies() {
    let expected = create_request(2, SEQUENCE);
    let bytes =
        encode(&s2b_create_bearer_request(expected.clone()).expect("valid Create Bearer Request"));
    let (tail, decoded) =
        S2bMessage::decode(&bytes, procedure_context()).expect("Create Bearer Request must decode");
    assert!(tail.is_empty());
    let actual = decoded
        .as_view()
        .expect("typed view")
        .create_bearer_request()
        .expect("typed Create Bearer Request projection");
    assert_eq!(actual, expected);
    assert_eq!(actual.bearer_contexts.len(), 2);
    assert_eq!(actual.additional_ies[0].ie_type(), 251);
    assert_eq!(actual.bearer_contexts[0].additional_ies[0].ie_type(), 250);
}

#[test]
fn create_bearer_response_supports_success_rejection_and_partial_acceptance() {
    let request = create_request(2, SEQUENCE);
    let response = S2bCreateBearerResponse {
        sequence_number: SEQUENCE,
        teid: RESPONSE_TEID,
        message_priority: None,
        cause: CauseValue::RequestAcceptedPartially,
        bearer_contexts: vec![
            accepted_result(1),
            rejected_result(2, CauseValue::SemanticErrorsInPacketFilters),
        ],
        additional_ies: vec![raw_ie(248, 5, UNKNOWN_TOP_VALUE)],
    };
    let bytes = encode(
        &s2b_create_bearer_response(response.clone()).expect("valid partial Create response"),
    );
    let (tail, decoded) =
        S2bMessage::decode(&bytes, procedure_context()).expect("Create response must decode");
    assert!(tail.is_empty());
    let actual = decoded
        .as_view()
        .expect("typed view")
        .create_bearer_response()
        .expect("typed Create Bearer Response projection");
    assert_eq!(actual, response);
    correlate_create_bearer_response(&request, &actual).expect("response must correlate");
    assert!(actual.bearer_contexts[0].is_accepted());
    assert!(!actual.bearer_contexts[1].is_accepted());
}

#[test]
fn create_and_delete_bearer_preserve_priority_without_using_it_for_correlation() {
    let request_priority = MessagePriority::new(2).expect("valid request priority");
    let response_priority = MessagePriority::new(9).expect("valid response priority");

    let mut create_request = create_request(1, SEQUENCE);
    create_request.message_priority = Some(request_priority);
    let create_request_bytes =
        encode(&s2b_create_bearer_request(create_request.clone()).expect("valid Create request"));
    let (_, decoded) = S2bMessage::decode(&create_request_bytes, procedure_context())
        .expect("priority-bearing Create request decode");
    let projected_create_request = decoded
        .as_view()
        .expect("typed view")
        .create_bearer_request()
        .expect("priority-bearing Create request projection");
    assert_eq!(
        projected_create_request.message_priority,
        Some(request_priority)
    );

    let create_response = S2bCreateBearerResponse {
        sequence_number: SEQUENCE,
        teid: RESPONSE_TEID,
        message_priority: Some(response_priority),
        cause: CauseValue::RequestAccepted,
        bearer_contexts: vec![accepted_result(1)],
        additional_ies: Vec::new(),
    };
    let create_response_bytes =
        encode(&s2b_create_bearer_response(create_response).expect("valid Create response"));
    let (_, decoded) = S2bMessage::decode(&create_response_bytes, procedure_context())
        .expect("priority-bearing Create response decode");
    let projected_create_response = decoded
        .as_view()
        .expect("typed view")
        .create_bearer_response()
        .expect("priority-bearing Create response projection");
    assert_eq!(
        projected_create_response.message_priority,
        Some(response_priority)
    );
    correlate_create_bearer_response(&projected_create_request, &projected_create_response)
        .expect("PLMN policy may override the Triggered Reply priority");

    let delete_request = S2bDeleteBearerRequest {
        sequence_number: SEQUENCE,
        teid: REQUEST_TEID,
        message_priority: Some(request_priority),
        target: S2bDeleteBearerTarget::Dedicated(vec![ebi(6)]),
        cause: None,
        additional_ies: Vec::new(),
    };
    let delete_request_bytes =
        encode(&s2b_delete_bearer_request(delete_request.clone()).expect("valid Delete request"));
    let (_, decoded) = S2bMessage::decode(&delete_request_bytes, procedure_context())
        .expect("priority-bearing Delete request decode");
    let projected_delete_request = decoded
        .as_view()
        .expect("typed view")
        .delete_bearer_request()
        .expect("priority-bearing Delete request projection");
    assert_eq!(
        projected_delete_request.message_priority,
        Some(request_priority)
    );

    let delete_response = S2bDeleteBearerResponse {
        sequence_number: SEQUENCE,
        teid: RESPONSE_TEID,
        message_priority: None,
        cause: CauseValue::RequestAccepted,
        body: S2bDeleteBearerResponseBody::Dedicated(vec![S2bDeleteBearerResult {
            ebi: ebi(6),
            cause: CauseValue::RequestAccepted,
            additional_ies: Vec::new(),
        }]),
        additional_ies: Vec::new(),
    };
    let delete_response_bytes =
        encode(&s2b_delete_bearer_response(delete_response).expect("valid Delete response"));
    let (_, decoded) = S2bMessage::decode(&delete_response_bytes, procedure_context())
        .expect("priority-stripped Delete response decode");
    let projected_delete_response = decoded
        .as_view()
        .expect("typed view")
        .delete_bearer_response()
        .expect("priority-stripped Delete response projection");
    assert_eq!(projected_delete_response.message_priority, None);
    correlate_delete_bearer_response(&projected_delete_request, &projected_delete_response)
        .expect("PLMN policy may strip the Triggered Reply priority");
}

#[test]
fn update_bearer_round_trips_multiple_contexts_and_partial_results() {
    let priority = MessagePriority::new(3).expect("fixture priority must be valid");
    let request = S2bUpdateBearerRequest {
        sequence_number: SEQUENCE,
        teid: REQUEST_TEID,
        message_priority: Some(priority),
        apn_ambr: AggregateMaximumBitRate {
            uplink: 64_000,
            downlink: 128_000,
        },
        bearer_contexts: vec![
            S2bUpdateBearerRequestContext {
                ebi: ebi(6),
                tft: Some(tft(1, 11, 4_501)),
                bearer_qos: None,
                additional_ies: vec![typed(
                    0,
                    TypedIeValue::AdditionalProtocolConfigurationOptions(
                        AdditionalProtocolConfigurationOptions {
                            value: vec![0x80, 0x21, 0x01],
                        },
                    ),
                )],
            },
            S2bUpdateBearerRequestContext {
                ebi: ebi(7),
                tft: None,
                bearer_qos: Some(qos(1)),
                additional_ies: vec![raw_ie(250, 2, UNKNOWN_NESTED_VALUE)],
            },
        ],
        additional_ies: vec![raw_ie(251, 3, UNKNOWN_TOP_VALUE)],
    };
    let request_bytes =
        encode(&s2b_update_bearer_request(request.clone()).expect("valid Update Bearer Request"));
    let (tail, decoded) =
        S2bMessage::decode(&request_bytes, procedure_context()).expect("Update request decode");
    assert!(tail.is_empty());
    let projected_request = decoded
        .as_view()
        .expect("typed view")
        .update_bearer_request()
        .expect("strict Update request projection");
    assert_eq!(projected_request, request);

    let response = S2bUpdateBearerResponse {
        sequence_number: SEQUENCE,
        teid: RESPONSE_TEID,
        message_priority: Some(priority),
        cause: CauseValue::RequestAcceptedPartially,
        bearer_contexts: vec![
            S2bUpdateBearerResult {
                ebi: ebi(6),
                cause: CauseValue::RequestAccepted,
                additional_ies: Vec::new(),
            },
            S2bUpdateBearerResult {
                ebi: ebi(7),
                cause: CauseValue::SemanticErrorsInPacketFilters,
                additional_ies: vec![raw_ie(249, 4, UNKNOWN_NESTED_VALUE)],
            },
        ],
        additional_ies: vec![raw_ie(248, 5, UNKNOWN_TOP_VALUE)],
    };
    let response_bytes = encode(
        &s2b_update_bearer_response(response.clone()).expect("valid partial Update response"),
    );
    let (tail, decoded) =
        S2bMessage::decode(&response_bytes, procedure_context()).expect("Update response decode");
    assert!(tail.is_empty());
    let projected_response = decoded
        .as_view()
        .expect("typed view")
        .update_bearer_response()
        .expect("strict Update response projection");
    assert_eq!(projected_response, response);
    correlate_update_bearer_response(&projected_request, &projected_response)
        .expect("Update response must correlate by EBI set");

    let mut stripped_priority = projected_response.clone();
    stripped_priority.message_priority = None;
    correlate_update_bearer_response(&projected_request, &stripped_priority)
        .expect("cross-PLMN policy may strip a Triggered Reply priority");
    stripped_priority.message_priority =
        Some(MessagePriority::new(9).expect("override priority must be valid"));
    correlate_update_bearer_response(&projected_request, &stripped_priority)
        .expect("cross-PLMN policy may override a Triggered Reply priority");

    let mut duplicate_request = projected_request.clone();
    duplicate_request.bearer_contexts[1].ebi = duplicate_request.bearer_contexts[0].ebi;
    let error = correlate_update_bearer_response(&duplicate_request, &projected_response)
        .expect_err("direct typed requests must not hide duplicate EBI correlation keys");
    assert_eq!(
        error.kind(),
        DedicatedBearerErrorKind::DuplicateBearerCorrelation
    );

    let mut duplicate_response = projected_response.clone();
    duplicate_response.bearer_contexts[1].ebi = duplicate_response.bearer_contexts[0].ebi;
    let error = correlate_update_bearer_response(&projected_request, &duplicate_response)
        .expect_err("direct typed responses must not hide duplicate EBI correlation keys");
    assert_eq!(
        error.kind(),
        DedicatedBearerErrorKind::DuplicateBearerCorrelation
    );
}

#[test]
fn update_bearer_rejects_missing_mandatory_and_ambiguous_contexts() {
    let request_context = typed(
        0,
        TypedIeValue::BearerContext(BearerContext {
            members: vec![typed(0, TypedIeValue::EpsBearerId(ebi(6)))],
        }),
    );
    let missing_ambr = encode(&owned_message(
        UPDATE_BEARER_REQUEST,
        Some(REQUEST_TEID),
        vec![request_context.clone()],
    ));
    let (_, decoded) =
        S2bMessage::decode(&missing_ambr, structural_context()).expect("structural decode");
    let error = decoded
        .as_view()
        .expect("typed view")
        .update_bearer_request()
        .expect_err("APN-AMBR is mandatory");
    assert_eq!(error.kind(), DedicatedBearerErrorKind::MissingApnAmbr);

    let missing_contexts = encode(&owned_message(
        UPDATE_BEARER_REQUEST,
        Some(REQUEST_TEID),
        vec![typed(
            0,
            TypedIeValue::AggregateMaximumBitRate(AggregateMaximumBitRate {
                uplink: 64_000,
                downlink: 128_000,
            }),
        )],
    ));
    let (_, decoded) =
        S2bMessage::decode(&missing_contexts, structural_context()).expect("structural decode");
    let error = decoded
        .as_view()
        .expect("typed view")
        .update_bearer_request()
        .expect_err("Update request contexts are mandatory");
    assert_eq!(
        error.kind(),
        DedicatedBearerErrorKind::MissingBearerContexts
    );

    let no_modifications = S2bUpdateBearerRequest {
        sequence_number: SEQUENCE,
        teid: REQUEST_TEID,
        message_priority: None,
        apn_ambr: AggregateMaximumBitRate {
            uplink: 64_000,
            downlink: 128_000,
        },
        bearer_contexts: vec![
            S2bUpdateBearerRequestContext {
                ebi: ebi(6),
                tft: None,
                bearer_qos: None,
                additional_ies: Vec::new(),
            },
            S2bUpdateBearerRequestContext {
                ebi: ebi(7),
                tft: None,
                bearer_qos: None,
                additional_ies: Vec::new(),
            },
        ],
        additional_ies: Vec::new(),
    };
    let mut only_one_context_modified = no_modifications.clone();
    only_one_context_modified.bearer_contexts[0].tft = Some(tft(1, 11, 4_501));
    assert!(
        s2b_update_bearer_request(only_one_context_modified).is_err(),
        "every context in a multi-context Update requires TFT or QoS"
    );
    assert!(s2b_update_bearer_request(no_modifications).is_err());

    let missing_response_contexts = encode(&owned_message(
        UPDATE_BEARER_RESPONSE,
        Some(RESPONSE_TEID),
        vec![typed(
            0,
            TypedIeValue::Cause(opc_proto_gtpv2c::Cause {
                value: CauseValue::ContextNotFound,
                flags_octet: 0,
                offending_ie: Vec::new(),
            }),
        )],
    ));
    let (_, decoded) = S2bMessage::decode(&missing_response_contexts, structural_context())
        .expect("structural decode");
    let error = decoded
        .as_view()
        .expect("typed view")
        .update_bearer_response()
        .expect_err("response contexts remain mandatory on rejection");
    assert_eq!(
        error.kind(),
        DedicatedBearerErrorKind::MissingBearerContexts
    );
}

#[test]
fn update_bearer_rejects_wrong_instances_and_invalid_nested_shapes() {
    let ambr = || {
        typed(
            0,
            TypedIeValue::AggregateMaximumBitRate(AggregateMaximumBitRate {
                uplink: 64_000,
                downlink: 128_000,
            }),
        )
    };
    let request_error = |ies| {
        let bytes = encode(&owned_message(
            UPDATE_BEARER_REQUEST,
            Some(REQUEST_TEID),
            ies,
        ));
        let (_, decoded) = S2bMessage::decode(&bytes, structural_context())
            .expect("structural Update request decode");
        decoded
            .as_view()
            .expect("typed view")
            .update_bearer_request()
            .expect_err("malformed Update request must fail")
    };
    let pco = || {
        typed(
            0,
            TypedIeValue::ProtocolConfigurationOptions(ProtocolConfigurationOptions {
                value: vec![0x80],
            }),
        )
    };

    let mut wrong_ambr_instance = ambr();
    wrong_ambr_instance.instance = 1;
    let error = request_error(vec![
        wrong_ambr_instance,
        typed(
            0,
            TypedIeValue::BearerContext(BearerContext {
                members: vec![typed(0, TypedIeValue::EpsBearerId(ebi(6)))],
            }),
        ),
    ]);
    assert_eq!(error.kind(), DedicatedBearerErrorKind::WrongIeInstance);

    let error = request_error(vec![
        ambr(),
        typed(
            0,
            TypedIeValue::BearerContext(BearerContext {
                members: vec![typed(0, TypedIeValue::BearerTft(tft(1, 11, 4_501)))],
            }),
        ),
    ]);
    assert_eq!(error.kind(), DedicatedBearerErrorKind::MissingBearerEbi);

    let error = request_error(vec![
        ambr(),
        typed(
            0,
            TypedIeValue::BearerContext(BearerContext {
                members: vec![
                    typed(0, TypedIeValue::EpsBearerId(ebi(6))),
                    typed(1, TypedIeValue::BearerTft(tft(1, 11, 4_501))),
                ],
            }),
        ),
    ]);
    assert_eq!(error.kind(), DedicatedBearerErrorKind::WrongIeInstance);

    let error = request_error(vec![
        ambr(),
        pco(),
        typed(
            0,
            TypedIeValue::BearerContext(BearerContext {
                members: vec![
                    typed(0, TypedIeValue::EpsBearerId(ebi(6))),
                    typed(0, TypedIeValue::BearerTft(tft(1, 11, 4_501))),
                ],
            }),
        ),
    ]);
    assert_eq!(error.kind(), DedicatedBearerErrorKind::WrongIeInstance);

    let error = request_error(vec![
        ambr(),
        typed(
            0,
            TypedIeValue::BearerContext(BearerContext {
                members: vec![
                    typed(0, TypedIeValue::EpsBearerId(ebi(6))),
                    typed(0, TypedIeValue::BearerTft(tft(1, 11, 4_501))),
                    pco(),
                ],
            }),
        ),
    ]);
    assert_eq!(error.kind(), DedicatedBearerErrorKind::WrongIeInstance);

    let error = request_error(vec![
        ambr(),
        typed(
            0,
            TypedIeValue::BearerContext(BearerContext {
                members: vec![
                    typed(0, TypedIeValue::EpsBearerId(ebi(6))),
                    typed(0, TypedIeValue::BearerTft(tft(1, 11, 4_501))),
                    typed(
                        4,
                        TypedIeValue::FullyQualifiedTeid(f_teid(
                            INTERFACE_TYPE_S2B_U_PGW_GTP_U,
                            0x1000_0001,
                            11,
                        )),
                    ),
                ],
            }),
        ),
    ]);
    assert_eq!(error.kind(), DedicatedBearerErrorKind::WrongIeInstance);

    let missing_nested_cause = encode(&owned_message(
        UPDATE_BEARER_RESPONSE,
        Some(RESPONSE_TEID),
        vec![
            typed(
                0,
                TypedIeValue::Cause(opc_proto_gtpv2c::Cause {
                    value: CauseValue::RequestAccepted,
                    flags_octet: 0,
                    offending_ie: Vec::new(),
                }),
            ),
            typed(
                0,
                TypedIeValue::BearerContext(BearerContext {
                    members: vec![typed(0, TypedIeValue::EpsBearerId(ebi(6)))],
                }),
            ),
        ],
    ));
    let (_, decoded) = S2bMessage::decode(&missing_nested_cause, structural_context())
        .expect("structural Update response decode");
    let error = decoded
        .as_view()
        .expect("typed view")
        .update_bearer_response()
        .expect_err("nested response Cause is mandatory");
    assert_eq!(error.kind(), DedicatedBearerErrorKind::MissingCause);

    let response_error = |mut additional_top_level, mut additional_nested| {
        let mut nested = vec![
            typed(0, TypedIeValue::EpsBearerId(ebi(6))),
            typed(
                0,
                TypedIeValue::Cause(opc_proto_gtpv2c::Cause {
                    value: CauseValue::RequestAccepted,
                    flags_octet: 0,
                    offending_ie: Vec::new(),
                }),
            ),
        ];
        nested.append(&mut additional_nested);
        let mut ies = vec![
            typed(
                0,
                TypedIeValue::Cause(opc_proto_gtpv2c::Cause {
                    value: CauseValue::RequestAccepted,
                    flags_octet: 0,
                    offending_ie: Vec::new(),
                }),
            ),
            typed(
                0,
                TypedIeValue::BearerContext(BearerContext { members: nested }),
            ),
        ];
        ies.append(&mut additional_top_level);
        let bytes = encode(&owned_message(
            UPDATE_BEARER_RESPONSE,
            Some(RESPONSE_TEID),
            ies,
        ));
        let (_, decoded) = S2bMessage::decode(&bytes, structural_context())
            .expect("structural Update response decode");
        decoded
            .as_view()
            .expect("typed view")
            .update_bearer_response()
            .expect_err("S2b Update response PCO must fail")
    };
    assert_eq!(
        response_error(vec![pco()], Vec::new()).kind(),
        DedicatedBearerErrorKind::WrongIeInstance
    );
    assert_eq!(
        response_error(Vec::new(), vec![pco()]).kind(),
        DedicatedBearerErrorKind::WrongIeInstance
    );
}

#[test]
fn delete_bearer_linked_and_dedicated_forms_round_trip_and_correlate() {
    let linked_request = S2bDeleteBearerRequest {
        sequence_number: SEQUENCE,
        teid: REQUEST_TEID,
        message_priority: None,
        target: S2bDeleteBearerTarget::Linked(ebi(5)),
        cause: Some(CauseValue::ReactivationRequested),
        additional_ies: vec![raw_ie(247, 6, UNKNOWN_TOP_VALUE)],
    };
    let linked_response = S2bDeleteBearerResponse {
        sequence_number: SEQUENCE,
        teid: RESPONSE_TEID,
        message_priority: None,
        cause: CauseValue::RequestAccepted,
        body: S2bDeleteBearerResponseBody::Linked(ebi(5)),
        additional_ies: Vec::new(),
    };
    let linked_request_bytes =
        encode(&s2b_delete_bearer_request(linked_request.clone()).expect("valid linked request"));
    let (_, decoded) = S2bMessage::decode(&linked_request_bytes, procedure_context())
        .expect("linked request decode");
    let linked_actual = decoded
        .as_view()
        .expect("typed view")
        .delete_bearer_request()
        .expect("linked projection");
    assert_eq!(linked_actual, linked_request);
    correlate_delete_bearer_response(&linked_actual, &linked_response)
        .expect("linked response correlation");

    // Table 7.2.9.2-1 says "Local release" for this S2b request; Table 8.4-1
    // names the encoded initial Cause 2 "Local Detach".
    assert_eq!(CauseValue::LocalDetach.as_u8(), 2);
    let local_release_request = S2bDeleteBearerRequest {
        cause: Some(CauseValue::LocalDetach),
        additional_ies: Vec::new(),
        ..linked_request
    };
    s2b_delete_bearer_request(local_release_request)
        .expect("S2b local-release request cause must be accepted");

    let dedicated_request = S2bDeleteBearerRequest {
        sequence_number: SEQUENCE,
        teid: REQUEST_TEID,
        message_priority: None,
        target: S2bDeleteBearerTarget::Dedicated(vec![ebi(6), ebi(7)]),
        cause: None,
        additional_ies: Vec::new(),
    };
    let dedicated_response = S2bDeleteBearerResponse {
        sequence_number: SEQUENCE,
        teid: RESPONSE_TEID,
        message_priority: None,
        cause: CauseValue::RequestAcceptedPartially,
        body: S2bDeleteBearerResponseBody::Dedicated(vec![
            S2bDeleteBearerResult {
                ebi: ebi(6),
                cause: CauseValue::RequestAccepted,
                additional_ies: Vec::new(),
            },
            S2bDeleteBearerResult {
                ebi: ebi(7),
                cause: CauseValue::ContextNotFound,
                additional_ies: Vec::new(),
            },
        ]),
        additional_ies: vec![raw_ie(246, 7, UNKNOWN_TOP_VALUE)],
    };
    let dedicated_response_bytes = encode(
        &s2b_delete_bearer_response(dedicated_response.clone())
            .expect("valid partial dedicated response"),
    );
    let (_, decoded) = S2bMessage::decode(&dedicated_response_bytes, procedure_context())
        .expect("dedicated response decode");
    let dedicated_actual = decoded
        .as_view()
        .expect("typed view")
        .delete_bearer_response()
        .expect("dedicated response projection");
    assert_eq!(dedicated_actual, dedicated_response);
    correlate_delete_bearer_response(&dedicated_request, &dedicated_actual)
        .expect("dedicated response correlation");

    let mut duplicate_request = dedicated_request.clone();
    duplicate_request.target = S2bDeleteBearerTarget::Dedicated(vec![ebi(6), ebi(6)]);
    let error = correlate_delete_bearer_response(&duplicate_request, &dedicated_actual)
        .expect_err("direct typed Delete requests must reject duplicate correlation EBIs");
    assert_eq!(
        error.kind(),
        DedicatedBearerErrorKind::DuplicateBearerCorrelation
    );

    let mut duplicate_response = dedicated_actual.clone();
    duplicate_response.body = S2bDeleteBearerResponseBody::Dedicated(vec![
        S2bDeleteBearerResult {
            ebi: ebi(6),
            cause: CauseValue::RequestAccepted,
            additional_ies: Vec::new(),
        },
        S2bDeleteBearerResult {
            ebi: ebi(6),
            cause: CauseValue::ContextNotFound,
            additional_ies: Vec::new(),
        },
    ]);
    let error = correlate_delete_bearer_response(&dedicated_request, &duplicate_response)
        .expect_err("direct typed Delete responses must reject duplicate correlation EBIs");
    assert_eq!(
        error.kind(),
        DedicatedBearerErrorKind::DuplicateBearerCorrelation
    );
}

#[test]
fn create_request_rejects_every_missing_mandatory_nested_ie() {
    let cases = [
        (73u8, DedicatedBearerErrorKind::MissingBearerEbi),
        (84u8, DedicatedBearerErrorKind::MissingBearerTft),
        (80u8, DedicatedBearerErrorKind::MissingBearerQos),
        (87u8, DedicatedBearerErrorKind::MissingPgwFTeid),
        (94u8, DedicatedBearerErrorKind::MissingChargingId),
    ];
    for (missing_type, expected_kind) in cases {
        let members = valid_request_members()
            .into_iter()
            .filter(|ie| ie.ie_type() != missing_type)
            .collect();
        let bytes = raw_create_request_with_members(members);
        let (_, decoded) = S2bMessage::decode(&bytes, structural_context())
            .expect("structural decode should retain procedure view");
        let error = decoded
            .as_view()
            .expect("typed view")
            .create_bearer_request()
            .expect_err("missing nested mandatory IE must fail");
        assert_eq!(
            error.kind(),
            expected_kind,
            "missing IE type {missing_type}"
        );
    }
}

#[test]
fn create_request_rejects_nonzero_request_ebi_and_wrong_s2b_fteid() {
    let mut members = valid_request_members();
    members[0] = typed(0, TypedIeValue::EpsBearerId(ebi(6)));
    let bytes = raw_create_request_with_members(members);
    let (_, decoded) = S2bMessage::decode(&bytes, structural_context()).expect("structural decode");
    let error = decoded
        .as_view()
        .expect("typed view")
        .create_bearer_request()
        .expect_err("nonzero request EBI must fail");
    assert_eq!(
        error.kind(),
        DedicatedBearerErrorKind::CreateRequestEbiNotZero
    );

    let mut members = valid_request_members();
    members[3] = typed(
        4,
        TypedIeValue::FullyQualifiedTeid(f_teid(INTERFACE_TYPE_S2B_U_EPDG_GTP_U, 0x1000_0001, 10)),
    );
    let bytes = raw_create_request_with_members(members);
    let (_, decoded) = S2bMessage::decode(&bytes, structural_context()).expect("structural decode");
    let error = decoded
        .as_view()
        .expect("typed view")
        .create_bearer_request()
        .expect_err("wrong request interface type must fail");
    assert_eq!(error.kind(), DedicatedBearerErrorKind::WrongFTeidInterface);
}

#[test]
fn create_request_requires_create_new_tft_with_uplink_filter_and_maps_causes() {
    let mut members = valid_request_members();
    members[1] = typed(
        0,
        TypedIeValue::BearerTft(TrafficFlowTemplate::delete_existing()),
    );
    let bytes = raw_create_request_with_members(members);
    let (_, decoded) = S2bMessage::decode(&bytes, structural_context()).expect("structural decode");
    let error = decoded
        .as_view()
        .expect("typed view")
        .create_bearer_request()
        .expect_err("activation must use TFT Create New");
    assert_eq!(
        error.kind(),
        DedicatedBearerErrorKind::InvalidCreateBearerTftOperation
    );
    assert_eq!(
        error.request_rejection_cause(),
        Some(CauseValue::SemanticErrorInTftOperation)
    );

    let identifier =
        PacketFilterIdentifier::new(1).expect("fixture packet-filter identifier must be valid");
    let downlink_filter = PacketFilter::new(
        identifier,
        PacketFilterDirection::DownlinkOnly,
        10,
        vec![PacketFilterComponent::ProtocolIdentifierNextHeader(17)],
    )
    .expect("downlink fixture filter must be valid");
    let downlink_only = TrafficFlowTemplate::create_new(vec![downlink_filter], Vec::new())
        .expect("downlink-only TFT must be syntactically valid");
    let mut members = valid_request_members();
    members[1] = typed(0, TypedIeValue::BearerTft(downlink_only));
    let bytes = raw_create_request_with_members(members);
    let (_, decoded) = S2bMessage::decode(&bytes, structural_context()).expect("structural decode");
    let error = decoded
        .as_view()
        .expect("typed view")
        .create_bearer_request()
        .expect_err("activation needs an uplink-applicable packet filter");
    assert_eq!(
        error.kind(),
        DedicatedBearerErrorKind::MissingCreateBearerUplinkFilter
    );
    assert_eq!(
        error.request_rejection_cause(),
        Some(CauseValue::SemanticErrorsInPacketFilters)
    );
}

#[test]
fn malformed_bearer_tft_decode_maps_syntax_and_filter_causes() {
    let classify = |tft_value: &'static [u8]| {
        let members = valid_request_members()
            .into_iter()
            .map(|ie| {
                if ie.ie_type() == 84 {
                    raw_ie(84, 0, tft_value)
                } else {
                    ie
                }
            })
            .collect();
        let bytes = raw_create_request_with_members(members);
        let error = S2bMessage::decode(&bytes, procedure_context())
            .expect_err("malformed Bearer TFT must fail during typed decode");
        dedicated_bearer_decode_rejection_cause(&error)
    };

    assert_eq!(
        classify(&[0xe0]),
        Some(CauseValue::SyntacticErrorInTftOperation)
    );
    assert_eq!(
        classify(&[0x22, 0x31, 1, 2, 0x30, 17, 0x31, 2, 2, 0x30, 6]),
        Some(CauseValue::SyntacticErrorsInPacketFilters)
    );
    assert_eq!(
        classify(&[0x21, 0x31, 0, 8, 0x40, 0, 1, 0x41, 0, 1, 0, 2]),
        Some(CauseValue::SemanticErrorsInPacketFilters)
    );
}

#[test]
fn create_request_rejects_wrong_nested_instance_and_duplicate_correlation_key() {
    let mut members = valid_request_members();
    members[1].instance = 1;
    let bytes = raw_create_request_with_members(members);
    let (_, decoded) = S2bMessage::decode(&bytes, structural_context()).expect("structural decode");
    let error = decoded
        .as_view()
        .expect("typed view")
        .create_bearer_request()
        .expect_err("wrong TFT instance must fail");
    assert_eq!(error.kind(), DedicatedBearerErrorKind::WrongIeInstance);

    let context = BearerContext {
        members: valid_request_members(),
    };
    let bytes = encode(&owned_message(
        CREATE_BEARER_REQUEST,
        Some(REQUEST_TEID),
        vec![
            typed(0, TypedIeValue::EpsBearerId(ebi(5))),
            typed(0, TypedIeValue::BearerContext(context.clone())),
            typed(0, TypedIeValue::BearerContext(context)),
        ],
    ));
    let (_, decoded) = S2bMessage::decode(&bytes, structural_context()).expect("structural decode");
    let error = decoded
        .as_view()
        .expect("typed view")
        .create_bearer_request()
        .expect_err("duplicate PGW F-TEID correlation must fail");
    assert_eq!(
        error.kind(),
        DedicatedBearerErrorKind::DuplicateBearerCorrelation
    );
}

#[test]
fn delete_request_rejects_conflicting_missing_and_duplicate_forms() {
    let conflicting = encode(&owned_message(
        DELETE_BEARER_REQUEST,
        Some(REQUEST_TEID),
        vec![
            typed(0, TypedIeValue::EpsBearerId(ebi(5))),
            typed(1, TypedIeValue::EpsBearerId(ebi(6))),
        ],
    ));
    let (_, decoded) =
        S2bMessage::decode(&conflicting, structural_context()).expect("structural decode");
    let error = decoded
        .as_view()
        .expect("typed view")
        .delete_bearer_request()
        .expect_err("conflicting forms must fail");
    assert_eq!(
        error.kind(),
        DedicatedBearerErrorKind::ConflictingDeleteForms
    );

    let missing = encode(&owned_message(
        DELETE_BEARER_REQUEST,
        Some(REQUEST_TEID),
        Vec::new(),
    ));
    let (_, decoded) =
        S2bMessage::decode(&missing, structural_context()).expect("structural decode");
    let error = decoded
        .as_view()
        .expect("typed view")
        .delete_bearer_request()
        .expect_err("missing form must fail");
    assert_eq!(error.kind(), DedicatedBearerErrorKind::MissingDeleteForm);

    let duplicate = encode(&owned_message(
        DELETE_BEARER_REQUEST,
        Some(REQUEST_TEID),
        vec![
            typed(1, TypedIeValue::EpsBearerId(ebi(6))),
            typed(1, TypedIeValue::EpsBearerId(ebi(6))),
        ],
    ));
    let (_, decoded) =
        S2bMessage::decode(&duplicate, structural_context()).expect("structural decode");
    let error = decoded
        .as_view()
        .expect("typed view")
        .delete_bearer_request()
        .expect_err("duplicate dedicated EBI must fail");
    assert_eq!(
        error.kind(),
        DedicatedBearerErrorKind::DuplicateBearerCorrelation
    );
}

#[test]
fn dedicated_bearer_messages_enforce_teid_header_rules() {
    let messages = vec![
        (
            s2b_create_bearer_request(create_request(1, SEQUENCE)).expect("valid Create request"),
            false,
        ),
        (
            s2b_create_bearer_response(S2bCreateBearerResponse {
                sequence_number: SEQUENCE,
                teid: RESPONSE_TEID,
                message_priority: None,
                cause: CauseValue::RequestAccepted,
                bearer_contexts: vec![accepted_result(1)],
                additional_ies: Vec::new(),
            })
            .expect("valid accepted Create response"),
            false,
        ),
        (
            s2b_create_bearer_response(rejected_create_response(
                CauseValue::RequestRejected,
                CauseValue::ContextNotFound,
            ))
            .expect("valid rejected Create response"),
            true,
        ),
        (
            s2b_update_bearer_request(S2bUpdateBearerRequest {
                sequence_number: SEQUENCE,
                teid: REQUEST_TEID,
                message_priority: None,
                apn_ambr: AggregateMaximumBitRate {
                    uplink: 64_000,
                    downlink: 128_000,
                },
                bearer_contexts: vec![S2bUpdateBearerRequestContext {
                    ebi: ebi(6),
                    tft: Some(tft(1, 11, 4_501)),
                    bearer_qos: None,
                    additional_ies: Vec::new(),
                }],
                additional_ies: Vec::new(),
            })
            .expect("valid Update request"),
            false,
        ),
        (
            s2b_update_bearer_response(S2bUpdateBearerResponse {
                cause: CauseValue::RequestAccepted,
                bearer_contexts: vec![S2bUpdateBearerResult {
                    ebi: ebi(6),
                    cause: CauseValue::RequestAccepted,
                    additional_ies: Vec::new(),
                }],
                ..rejected_update_response(CauseValue::RequestRejected, CauseValue::ContextNotFound)
            })
            .expect("valid accepted Update response"),
            false,
        ),
        (
            s2b_update_bearer_response(rejected_update_response(
                CauseValue::RequestRejected,
                CauseValue::ContextNotFound,
            ))
            .expect("valid rejected Update response"),
            true,
        ),
        (
            s2b_delete_bearer_request(S2bDeleteBearerRequest {
                sequence_number: SEQUENCE,
                teid: REQUEST_TEID,
                message_priority: None,
                target: S2bDeleteBearerTarget::Dedicated(vec![ebi(6)]),
                cause: None,
                additional_ies: Vec::new(),
            })
            .expect("valid Delete request"),
            false,
        ),
        (
            s2b_delete_bearer_response(S2bDeleteBearerResponse {
                cause: CauseValue::RequestAccepted,
                body: S2bDeleteBearerResponseBody::Dedicated(vec![S2bDeleteBearerResult {
                    ebi: ebi(6),
                    cause: CauseValue::RequestAccepted,
                    additional_ies: Vec::new(),
                }]),
                ..rejected_delete_response(CauseValue::RequestRejected, CauseValue::ContextNotFound)
            })
            .expect("valid accepted Delete response"),
            false,
        ),
        (
            s2b_delete_bearer_response(rejected_delete_response(
                CauseValue::RequestRejected,
                CauseValue::ContextNotFound,
            ))
            .expect("valid rejected Delete response"),
            true,
        ),
    ];

    for (message, zero_teid_permitted) in messages {
        let message_type = message.header.message_type;
        let without_teid = OwnedMessage {
            header: Header::without_teid(message_type, SEQUENCE),
            raw_ies: message.raw_ies.clone(),
        };
        let bytes = encode(&without_teid);
        assert!(
            S2bMessage::decode(&bytes, procedure_context()).is_err(),
            "message type {message_type} accepted a missing TEID"
        );

        let zero_teid = OwnedMessage {
            header: Header::with_teid(message_type, 0, SEQUENCE),
            raw_ies: message.raw_ies,
        };
        let bytes = encode(&zero_teid);
        let decoded = S2bMessage::decode(&bytes, procedure_context());
        if zero_teid_permitted {
            assert!(
                decoded.is_ok(),
                "rejected response message type {message_type} rejected permitted TEID zero"
            );
        } else {
            assert!(
                decoded.is_err(),
                "message type {message_type} accepted prohibited TEID zero"
            );
        }
    }
}

#[test]
fn dedicated_bearer_cause_registry_uses_normative_release_18_values() {
    let cases = [
        (CauseValue::LocalDetach, 2),
        (CauseValue::RequestAccepted, 16),
        (CauseValue::RequestAcceptedPartially, 17),
        (CauseValue::SemanticErrorInTftOperation, 74),
        (CauseValue::SyntacticErrorInTftOperation, 75),
        (CauseValue::SemanticErrorsInPacketFilters, 76),
        (CauseValue::SyntacticErrorsInPacketFilters, 77),
        (CauseValue::BearerHandlingNotSupported, 114),
        (CauseValue::TemporarilyRejectedForMobilityProcedure, 110),
    ];
    for (cause, value) in cases {
        assert_eq!(cause.as_u8(), value);
        assert_eq!(CauseValue::from(value), cause);
    }
}

#[test]
fn public_identifier_and_dedicated_bearer_debug_is_redaction_safe() {
    let endpoint = FullyQualifiedTeid {
        interface_type: INTERFACE_TYPE_S2B_U_PGW_GTP_U,
        teid: 0xdeca_fbad,
        ipv4: Some([203, 0, 113, 201]),
        ipv6: None,
    };
    let charging_id = ChargingId { value: 0xfeed_beef };
    let bearer_id = ebi(13);

    let endpoint_debug = format!("{endpoint:?}");
    assert!(endpoint_debug.contains("<redacted>"));
    assert!(endpoint_debug.contains("ipv4_present: true"));
    assert!(!endpoint_debug.contains("3737844653"));
    assert!(!endpoint_debug.contains("203, 0, 113, 201"));
    assert!(!format!("{charging_id:?}").contains("4276993775"));
    assert!(!format!("{bearer_id:?}").contains("value: 13"));

    let request = S2bCreateBearerRequest {
        sequence_number: 0x00_ab_cd_ef,
        teid: 0xdeca_fbad,
        message_priority: None,
        linked_ebi: bearer_id,
        bearer_contexts: vec![S2bCreateBearerRequestContext {
            tft: tft(1, 219, 61_337),
            bearer_qos: qos(211),
            pgw_f_teid: endpoint.clone(),
            charging_id,
            additional_ies: vec![raw_ie(250, 2, &[0xca, 0xfe, 0xba, 0xbe])],
        }],
        additional_ies: vec![raw_ie(251, 3, &[0xba, 0xad, 0xf0, 0x0d])],
    };
    let create_response = S2bCreateBearerResponse {
        sequence_number: request.sequence_number,
        teid: 0xface_cafe,
        message_priority: None,
        cause: CauseValue::RequestAccepted,
        bearer_contexts: vec![S2bCreateBearerResult::Accepted {
            ebi: ebi(14),
            epdg_f_teid: f_teid(INTERFACE_TYPE_S2B_U_EPDG_GTP_U, 0xdec0_de01, 202),
            pgw_f_teid: endpoint,
            additional_ies: vec![raw_ie(249, 4, &[0xde, 0xad, 0xbe, 0xef])],
        }],
        additional_ies: Vec::new(),
    };
    let update_request = S2bUpdateBearerRequest {
        sequence_number: 0x00_ab_cd_ef,
        teid: 0xdeca_fbad,
        message_priority: None,
        apn_ambr: AggregateMaximumBitRate {
            uplink: 61_337,
            downlink: 65_535,
        },
        bearer_contexts: vec![S2bUpdateBearerRequestContext {
            ebi: ebi(13),
            tft: Some(tft(1, 219, 61_337)),
            bearer_qos: Some(qos(211)),
            additional_ies: vec![raw_ie(250, 2, &[0xca, 0xfe, 0xba, 0xbe])],
        }],
        additional_ies: vec![raw_ie(251, 3, &[0xba, 0xad, 0xf0, 0x0d])],
    };
    let update_response = S2bUpdateBearerResponse {
        sequence_number: 0x00_ab_cd_ef,
        teid: 0xface_cafe,
        message_priority: None,
        cause: CauseValue::ContextNotFound,
        bearer_contexts: vec![S2bUpdateBearerResult {
            ebi: ebi(13),
            cause: CauseValue::ContextNotFound,
            additional_ies: vec![raw_ie(249, 4, &[0xde, 0xad, 0xbe, 0xef])],
        }],
        additional_ies: Vec::new(),
    };
    let delete_request = S2bDeleteBearerRequest {
        sequence_number: 0x00_ab_cd_ef,
        teid: 0xdeca_fbad,
        message_priority: None,
        target: S2bDeleteBearerTarget::Dedicated(vec![ebi(13), ebi(14)]),
        cause: Some(CauseValue::LocalDetach),
        additional_ies: vec![raw_ie(248, 5, &[0xca, 0xfe, 0xba, 0xbe])],
    };
    let delete_response = S2bDeleteBearerResponse {
        sequence_number: 0x00_ab_cd_ef,
        teid: 0xface_cafe,
        message_priority: None,
        cause: CauseValue::RequestAcceptedPartially,
        body: S2bDeleteBearerResponseBody::Dedicated(vec![
            S2bDeleteBearerResult {
                ebi: ebi(13),
                cause: CauseValue::RequestAccepted,
                additional_ies: Vec::new(),
            },
            S2bDeleteBearerResult {
                ebi: ebi(14),
                cause: CauseValue::ContextNotFound,
                additional_ies: Vec::new(),
            },
        ]),
        additional_ies: Vec::new(),
    };

    for debug in [
        format!("{request:?}"),
        format!("{:?}", request.bearer_contexts[0]),
        format!("{create_response:?}"),
        format!("{:?}", create_response.bearer_contexts[0]),
        format!("{update_request:?}"),
        format!("{:?}", update_request.bearer_contexts[0]),
        format!("{update_response:?}"),
        format!("{:?}", update_response.bearer_contexts[0]),
        format!("{delete_request:?}"),
        format!("{delete_response:?}"),
        format!("{:?}", delete_response.body),
    ] {
        for forbidden in [
            "3737844653",
            "3737181697",
            "4207856382",
            "4276993775",
            "203, 0, 113, 201",
            "192, 0, 2, 202",
            "TrafficFlowTemplate",
            "FullyQualifiedTeid",
            "ChargingId",
            "EpsBearerId",
            "cafebabe",
            "baadf00d",
            "deadbeef",
        ] {
            assert!(
                !debug.contains(forbidden),
                "Debug output leaked forbidden marker {forbidden}: {debug}"
            );
        }
    }
}

#[test]
fn response_cause_allowlists_accept_generic_and_procedure_specific_causes() {
    // TS 29.274 R18 clause 7.7 protocol errors plus the Table 8.4-1 generic
    // feature, operational, and unspecified-rejection causes.
    let common_rejections = [
        CauseValue::InvalidMessageFormat,
        CauseValue::InvalidLength,
        CauseValue::ServiceNotSupported,
        CauseValue::MandatoryIeIncorrect,
        CauseValue::MandatoryIeMissing,
        CauseValue::SystemFailure,
        CauseValue::NoResourcesAvailable,
        CauseValue::RequestRejected,
        CauseValue::ConditionalIeMissing,
    ];
    for cause in common_rejections {
        s2b_create_bearer_response(rejected_create_response(cause, cause))
            .expect("common Cause must be legal in Create Bearer response positions");
        s2b_update_bearer_response(rejected_update_response(cause, cause))
            .expect("common Cause must be legal in Update Bearer response positions");
        s2b_delete_bearer_response(rejected_delete_response(cause, cause))
            .expect("common Cause must be legal in Delete Bearer response positions");
    }

    // Exact message-specific rejection set from clause 7.2.4.
    let create_rejections = [
        CauseValue::ContextNotFound,
        CauseValue::SemanticErrorInTftOperation,
        CauseValue::SyntacticErrorInTftOperation,
        CauseValue::SemanticErrorsInPacketFilters,
        CauseValue::SyntacticErrorsInPacketFilters,
        CauseValue::UnableToPageUe,
        CauseValue::UeNotResponding,
        CauseValue::UnableToPageUeDueToSuspension,
        CauseValue::UeRefuses,
        CauseValue::DeniedInRat,
        CauseValue::TemporarilyRejectedForMobilityProcedure,
        CauseValue::RefusedDueToVplmnPolicy,
        CauseValue::UeTemporarilyUnreachableDueToPowerSaving,
        CauseValue::RequestRejectedDueToUeCapability,
    ];
    for cause in create_rejections {
        s2b_create_bearer_response(rejected_create_response(cause, cause))
            .expect("clause 7.2.4 Cause must be legal at message and bearer level");
    }

    // Exact message-specific rejection set from clause 7.2.16.
    let update_rejections = [
        CauseValue::ContextNotFound,
        CauseValue::SemanticErrorInTftOperation,
        CauseValue::SyntacticErrorInTftOperation,
        CauseValue::SemanticErrorsInPacketFilters,
        CauseValue::SyntacticErrorsInPacketFilters,
        CauseValue::DeniedInRat,
        CauseValue::UeRefuses,
        CauseValue::UnableToPageUe,
        CauseValue::UeNotResponding,
        CauseValue::UnableToPageUeDueToSuspension,
        CauseValue::TemporarilyRejectedForMobilityProcedure,
        CauseValue::RefusedDueToVplmnPolicy,
        CauseValue::UeTemporarilyUnreachableDueToPowerSaving,
    ];
    for cause in update_rejections {
        s2b_update_bearer_response(rejected_update_response(cause, cause))
            .expect("clause 7.2.16 Cause must be legal at message and bearer level");
    }

    // Exact message-specific rejection set from clause 7.2.10.2.
    for cause in [
        CauseValue::ContextNotFound,
        CauseValue::TemporarilyRejectedForMobilityProcedure,
    ] {
        s2b_delete_bearer_response(rejected_delete_response(cause, cause))
            .expect("clause 7.2.10.2 Cause must be legal at message and bearer level");
    }
}

#[test]
fn response_cause_allowlists_reject_spare_unknown_and_unrelated_causes() {
    let invalid_for_both = [
        CauseValue::Unknown(71),
        CauseValue::Unknown(132),
        CauseValue::BearerHandlingNotSupported,
        CauseValue::UeContextWithoutTftAlreadyActivated,
        CauseValue::CollisionWithNetworkInitiatedRequest,
        CauseValue::LateOverlappingRequest,
        CauseValue::TimedOutRequest,
        CauseValue::MultipleAccessesToPdnConnectionNotAllowed,
    ];
    for cause in invalid_for_both {
        assert!(
            s2b_create_bearer_response(rejected_create_response(
                cause,
                CauseValue::ContextNotFound,
            ))
            .is_err(),
            "Create Bearer message level accepted unrelated Cause {cause:?}"
        );
        assert!(
            s2b_create_bearer_response(rejected_create_response(
                CauseValue::ContextNotFound,
                cause,
            ))
            .is_err(),
            "Create Bearer context level accepted unrelated Cause {cause:?}"
        );
        assert!(
            s2b_delete_bearer_response(rejected_delete_response(
                cause,
                CauseValue::ContextNotFound,
            ))
            .is_err(),
            "Delete Bearer message level accepted unrelated Cause {cause:?}"
        );
        assert!(
            s2b_delete_bearer_response(rejected_delete_response(
                CauseValue::ContextNotFound,
                cause,
            ))
            .is_err(),
            "Delete Bearer context level accepted unrelated Cause {cause:?}"
        );
        assert!(
            s2b_update_bearer_response(rejected_update_response(
                cause,
                CauseValue::ContextNotFound,
            ))
            .is_err(),
            "Update Bearer message level accepted unrelated Cause {cause:?}"
        );
        assert!(
            s2b_update_bearer_response(rejected_update_response(
                CauseValue::ContextNotFound,
                cause,
            ))
            .is_err(),
            "Update Bearer context level accepted unrelated Cause {cause:?}"
        );
    }

    assert!(
        s2b_update_bearer_response(rejected_update_response(
            CauseValue::RequestRejectedDueToUeCapability,
            CauseValue::ContextNotFound,
        ))
        .is_err(),
        "Update Bearer accepted a Create-only UE-capability Cause"
    );

    for cause in [
        CauseValue::SemanticErrorInTftOperation,
        CauseValue::SyntacticErrorsInPacketFilters,
        CauseValue::DeniedInRat,
        CauseValue::UeNotResponding,
        CauseValue::RequestRejectedDueToUeCapability,
    ] {
        assert!(
            s2b_delete_bearer_response(rejected_delete_response(
                cause,
                CauseValue::ContextNotFound,
            ))
            .is_err(),
            "Delete Bearer message level accepted Create-only Cause {cause:?}"
        );
        assert!(
            s2b_delete_bearer_response(rejected_delete_response(
                CauseValue::ContextNotFound,
                cause,
            ))
            .is_err(),
            "Delete Bearer context level accepted Create-only Cause {cause:?}"
        );
    }
}

#[test]
fn triggered_transactions_dispatch_pending_commit_and_exactly_replay() {
    let request = create_request(1, SEQUENCE);
    let request_bytes = encode(&s2b_create_bearer_request(request).expect("valid request"));
    let response = S2bCreateBearerResponse {
        sequence_number: SEQUENCE,
        teid: RESPONSE_TEID,
        message_priority: None,
        cause: CauseValue::RequestAccepted,
        bearer_contexts: vec![accepted_result(1)],
        additional_ies: Vec::new(),
    };
    let response_bytes = encode(
        &s2b_create_bearer_response(response.clone()).expect("valid Create Bearer Response"),
    );
    let mut wrong_routing_response = response;
    wrong_routing_response.teid = RESPONSE_TEID.wrapping_add(1);
    let wrong_routing_bytes = encode(
        &s2b_create_bearer_response(wrong_routing_response)
            .expect("internally valid response with wrong routing"),
    );
    let peer = Gtpv2cPeerToken::new(7);
    let now = Gtpv2cMonotonicMillis::new(1_000);
    let mut transactions = Gtpv2cTriggeredTransactions::default();

    let key = match transactions
        .observe_request(
            peer,
            request_bytes.clone(),
            RESPONSE_TEID,
            now,
            DecodeContext::default(),
        )
        .expect("first observation")
    {
        Gtpv2cTriggeredRequestDisposition::Dispatch(key) => key,
        disposition => panic!("unexpected first disposition: {disposition:?}"),
    };
    assert!(matches!(
        transactions
            .observe_request(
                peer,
                request_bytes.clone(),
                RESPONSE_TEID,
                Gtpv2cMonotonicMillis::new(1_001),
                DecodeContext::default(),
            )
            .expect("pending retransmission"),
        Gtpv2cTriggeredRequestDisposition::Pending(pending) if pending == key
    ));
    assert_eq!(
        transactions
            .commit_response(
                key,
                Gtpv2cTriggeredCompletion::Accepted(wrong_routing_bytes),
                Gtpv2cMonotonicMillis::new(1_002),
                DecodeContext::default(),
            )
            .expect_err("response header TEID must match the required route"),
        Gtpv2cTriggeredTransactionError::ResponseMismatch
    );
    transactions
        .commit_response(
            key,
            Gtpv2cTriggeredCompletion::Accepted(response_bytes.clone()),
            Gtpv2cMonotonicMillis::new(1_003),
            DecodeContext::default(),
        )
        .expect("response commit");
    match transactions
        .observe_request(
            peer,
            request_bytes,
            RESPONSE_TEID,
            Gtpv2cMonotonicMillis::new(1_004),
            DecodeContext::default(),
        )
        .expect("committed retransmission")
    {
        Gtpv2cTriggeredRequestDisposition::Replay {
            key: replay_key,
            response,
        } => {
            assert_eq!(replay_key, key.key);
            assert_eq!(response, response_bytes);
        }
        disposition => panic!("unexpected replay disposition: {disposition:?}"),
    }
    assert_eq!(
        transactions
            .commit_response(
                key,
                Gtpv2cTriggeredCompletion::Accepted(Bytes::new()),
                Gtpv2cMonotonicMillis::new(1_005),
                DecodeContext::default(),
            )
            .expect_err("a committed response cannot be replaced"),
        Gtpv2cTriggeredTransactionError::ResponseAlreadyCommitted
    );
}

#[test]
fn triggered_update_bearer_dispatches_once_and_replays_explicit_priority_override() {
    let request = S2bUpdateBearerRequest {
        sequence_number: SEQUENCE,
        teid: REQUEST_TEID,
        message_priority: Some(MessagePriority::new(2).expect("valid request priority")),
        apn_ambr: AggregateMaximumBitRate {
            uplink: 64_000,
            downlink: 128_000,
        },
        bearer_contexts: vec![S2bUpdateBearerRequestContext {
            ebi: ebi(6),
            tft: Some(tft(1, 11, 4_501)),
            bearer_qos: None,
            additional_ies: Vec::new(),
        }],
        additional_ies: Vec::new(),
    };
    let request_bytes = encode(&s2b_update_bearer_request(request).expect("valid Update request"));
    let response = S2bUpdateBearerResponse {
        sequence_number: SEQUENCE,
        teid: RESPONSE_TEID,
        // TS 29.274 recommends copying priority, but inter-PLMN policy may
        // explicitly strip or override it. The transaction layer must not
        // mistake that policy decision for a correlation failure.
        message_priority: Some(MessagePriority::new(9).expect("valid response priority")),
        cause: CauseValue::RequestAccepted,
        bearer_contexts: vec![S2bUpdateBearerResult {
            ebi: ebi(6),
            cause: CauseValue::RequestAccepted,
            additional_ies: Vec::new(),
        }],
        additional_ies: Vec::new(),
    };
    let response_bytes =
        encode(&s2b_update_bearer_response(response).expect("valid Update response"));
    let peer = Gtpv2cPeerToken::new(27);
    let mut transactions = Gtpv2cTriggeredTransactions::default();
    let work = match transactions
        .observe_request(
            peer,
            request_bytes.clone(),
            RESPONSE_TEID,
            Gtpv2cMonotonicMillis::new(20),
            DecodeContext::default(),
        )
        .expect("first Update observation")
    {
        Gtpv2cTriggeredRequestDisposition::Dispatch(work) => work,
        disposition => panic!("unexpected Update disposition: {disposition:?}"),
    };
    assert!(matches!(
        transactions
            .observe_request(
                peer,
                request_bytes.clone(),
                RESPONSE_TEID,
                Gtpv2cMonotonicMillis::new(21),
                DecodeContext::default(),
            )
            .expect("pending Update retransmission"),
        Gtpv2cTriggeredRequestDisposition::Pending(pending) if pending == work
    ));
    transactions
        .commit_response(
            work,
            Gtpv2cTriggeredCompletion::Accepted(response_bytes.clone()),
            Gtpv2cMonotonicMillis::new(22),
            DecodeContext::default(),
        )
        .expect("priority override must not block Update commit");
    match transactions
        .observe_request(
            peer,
            request_bytes,
            RESPONSE_TEID,
            Gtpv2cMonotonicMillis::new(23),
            DecodeContext::default(),
        )
        .expect("committed Update retransmission")
    {
        Gtpv2cTriggeredRequestDisposition::Replay { response, .. } => {
            assert_eq!(response, response_bytes);
        }
        disposition => panic!("unexpected Update replay disposition: {disposition:?}"),
    }
}

#[test]
fn triggered_transactions_reject_conflict_timeout_and_exhausted_capacity() {
    let policy = Gtpv2cTriggeredTransactionPolicy::new(10, 20, 1, 65_535, 65_535)
        .expect("valid bounded policy");
    let mut transactions = Gtpv2cTriggeredTransactions::new(policy);
    let peer = Gtpv2cPeerToken::new(8);
    let request =
        encode(&s2b_create_bearer_request(create_request(1, SEQUENCE)).expect("valid request"));
    assert_eq!(
        transactions
            .observe_request(
                peer,
                request.clone(),
                0,
                Gtpv2cMonotonicMillis::new(0),
                DecodeContext::default(),
            )
            .expect_err("response routing must never accept a zero TEID"),
        Gtpv2cTriggeredTransactionError::ZeroExpectedResponseTeid
    );
    assert!(transactions.is_empty());
    let key = match transactions
        .observe_request(
            peer,
            request.clone(),
            RESPONSE_TEID,
            Gtpv2cMonotonicMillis::new(0),
            DecodeContext::default(),
        )
        .expect("first observation")
    {
        Gtpv2cTriggeredRequestDisposition::Dispatch(key) => key,
        disposition => panic!("unexpected disposition: {disposition:?}"),
    };
    assert_eq!(
        transactions
            .acknowledge_cancellation(key)
            .expect_err("active work cannot be acknowledged as cancelled"),
        Gtpv2cTriggeredTransactionError::CancellationNotRequired
    );

    let changed = encode(
        &s2b_create_bearer_request(create_request(1, SEQUENCE)).expect("valid changed request"),
    );
    assert_eq!(changed, request);
    assert_eq!(
        transactions
            .observe_request(
                peer,
                changed,
                RESPONSE_TEID.wrapping_add(1),
                Gtpv2cMonotonicMillis::new(1),
                DecodeContext::default(),
            )
            .expect_err("same identity with changed routing must conflict"),
        Gtpv2cTriggeredTransactionError::ConflictingRequest
    );

    let second = encode(
        &s2b_create_bearer_request(create_request(1, SEQUENCE + 1)).expect("second request"),
    );
    assert_eq!(
        transactions
            .observe_request(
                peer,
                second,
                RESPONSE_TEID,
                Gtpv2cMonotonicMillis::new(2),
                DecodeContext::default(),
            )
            .expect_err("capacity is bounded"),
        Gtpv2cTriggeredTransactionError::CapacityExceeded
    );

    assert_eq!(
        transactions
            .commit_response(
                key,
                Gtpv2cTriggeredCompletion::Rejected {
                    cause: CauseValue::ContextNotFound,
                    response: Bytes::new(),
                },
                Gtpv2cMonotonicMillis::new(10),
                DecodeContext::default(),
            )
            .expect_err("pending deadline is exclusive"),
        Gtpv2cTriggeredTransactionError::WorkTimedOut
    );
    assert_eq!(transactions.len(), 1);
    assert_eq!(
        transactions.cancellation_required().collect::<Vec<_>>(),
        vec![key]
    );
    assert!(matches!(
        transactions
            .observe_request(
                peer,
                request.clone(),
                RESPONSE_TEID,
                Gtpv2cMonotonicMillis::new(11),
                DecodeContext::default(),
            )
            .expect("timed-out retransmission remains suppressed"),
        Gtpv2cTriggeredRequestDisposition::CancellationRequired(work) if work == key
    ));
    let second = encode(
        &s2b_create_bearer_request(create_request(1, SEQUENCE + 1)).expect("second request"),
    );
    assert_eq!(
        transactions
            .observe_request(
                peer,
                second,
                RESPONSE_TEID,
                Gtpv2cMonotonicMillis::new(11),
                DecodeContext::default(),
            )
            .expect_err("unacknowledged timeout must retain bounded capacity"),
        Gtpv2cTriggeredTransactionError::CapacityExceeded
    );

    transactions
        .acknowledge_cancellation(key)
        .expect("owner rolled back the exact timed-out generation");
    let replacement = match transactions
        .observe_request(
            peer,
            request,
            RESPONSE_TEID,
            Gtpv2cMonotonicMillis::new(12),
            DecodeContext::default(),
        )
        .expect("safe redispatch after cancellation acknowledgement")
    {
        Gtpv2cTriggeredRequestDisposition::Dispatch(work) => work,
        disposition => panic!("unexpected replacement disposition: {disposition:?}"),
    };
    assert_ne!(replacement.generation, key.generation);
    assert_eq!(
        transactions
            .commit_response(
                key,
                Gtpv2cTriggeredCompletion::Accepted(Bytes::new()),
                Gtpv2cMonotonicMillis::new(13),
                DecodeContext::default(),
            )
            .expect_err("late completion from old owner must not commit"),
        Gtpv2cTriggeredTransactionError::StaleGeneration
    );
}

#[test]
fn triggered_transaction_commit_correlates_each_bearer_with_cached_request() {
    let request = create_request(2, SEQUENCE);
    let request_bytes =
        encode(&s2b_create_bearer_request(request).expect("valid multi-bearer request"));
    let peer = Gtpv2cPeerToken::new(9);
    let mut transactions = Gtpv2cTriggeredTransactions::default();
    let key = match transactions
        .observe_request(
            peer,
            request_bytes,
            RESPONSE_TEID,
            Gtpv2cMonotonicMillis::new(0),
            DecodeContext::default(),
        )
        .expect("request observation")
    {
        Gtpv2cTriggeredRequestDisposition::Dispatch(key) => key,
        disposition => panic!("unexpected disposition: {disposition:?}"),
    };
    let mismatched = S2bCreateBearerResponse {
        sequence_number: SEQUENCE,
        teid: RESPONSE_TEID,
        message_priority: None,
        cause: CauseValue::RequestAccepted,
        bearer_contexts: vec![
            accepted_result(1),
            S2bCreateBearerResult::Accepted {
                ebi: ebi(7),
                epdg_f_teid: f_teid(INTERFACE_TYPE_S2B_U_EPDG_GTP_U, 0x3000_0002, 22),
                pgw_f_teid: f_teid(INTERFACE_TYPE_S2B_U_PGW_GTP_U, 0xdead_beef, 99),
                additional_ies: Vec::new(),
            },
        ],
        additional_ies: Vec::new(),
    };
    let response_bytes = encode(
        &s2b_create_bearer_response(mismatched).expect("internally valid mismatched response"),
    );
    assert_eq!(
        transactions
            .commit_response(
                key,
                Gtpv2cTriggeredCompletion::Accepted(response_bytes),
                Gtpv2cMonotonicMillis::new(1),
                DecodeContext::default(),
            )
            .expect_err("uncorrelated bearer response must not commit"),
        Gtpv2cTriggeredTransactionError::ResponseMismatch
    );
}

#[test]
fn triggered_transaction_keys_are_safe_across_sequence_wrap() {
    let mut transactions = Gtpv2cTriggeredTransactions::default();
    let peer = Gtpv2cPeerToken::new(10);
    let mut generations = Vec::new();
    for (index, sequence_number) in [MAX_SEQUENCE_NUMBER, 0].into_iter().enumerate() {
        let request = encode(
            &s2b_create_bearer_request(create_request(1, sequence_number))
                .expect("boundary sequence request"),
        );
        match transactions
            .observe_request(
                peer,
                request,
                RESPONSE_TEID,
                Gtpv2cMonotonicMillis::new(index as u64),
                DecodeContext::default(),
            )
            .expect("boundary sequence observation")
        {
            Gtpv2cTriggeredRequestDisposition::Dispatch(work) => {
                generations.push(work.generation);
            }
            disposition => panic!("unexpected boundary disposition: {disposition:?}"),
        }
    }
    assert_eq!(transactions.len(), 2);
    assert_ne!(generations[0], generations[1]);
}

#[test]
fn canonical_builders_are_deterministic_for_bounded_context_counts() {
    for context_count in 1..=4 {
        let request = create_request(context_count, u32::from(context_count));
        let first = encode(
            &s2b_create_bearer_request(request.clone()).expect("valid deterministic request"),
        );
        let second = encode(
            &s2b_create_bearer_request(request).expect("valid deterministic request replay"),
        );
        assert_eq!(first, second);
        let (tail, decoded) =
            S2bMessage::decode(&first, procedure_context()).expect("round-trip decode");
        assert!(tail.is_empty());
        assert_eq!(
            decoded
                .as_view()
                .expect("typed view")
                .create_bearer_request()
                .expect("request projection")
                .bearer_contexts
                .len(),
            usize::from(context_count)
        );
    }
}

#[test]
fn procedure_receive_uses_first_wins_for_unknown_singleton_keys() {
    let bytes = encode(&owned_message(
        DELETE_BEARER_REQUEST,
        Some(REQUEST_TEID),
        vec![
            typed(1, TypedIeValue::EpsBearerId(ebi(6))),
            raw_ie(245, 8, UNKNOWN_TOP_VALUE),
            raw_ie(245, 8, UNKNOWN_NESTED_VALUE),
        ],
    ));
    let (_, decoded) = S2bMessage::decode_with_diagnostics(&bytes, procedure_context())
        .expect("ProcedureAware receive uses first-wins even when the key is an extension");
    let evidence = decoded.diagnostics().duplicate_ies();
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].ie_type(), 245);
    assert_eq!(evidence[0].instance(), 8);
}

#[test]
fn pgw_triggered_requests_preserve_table_declared_repeatable_ies_in_order() {
    let repeatable = vec![
        raw_ie(IE_TYPE_LOAD_CONTROL_INFORMATION, 1, &[0x01]),
        raw_ie(IE_TYPE_OVERLOAD_CONTROL_INFORMATION, 0, &[0x02]),
        raw_ie(IE_TYPE_PGW_CHANGE_INFO, 0, PGW_CHANGE_INFO_ONE),
        raw_ie(IE_TYPE_LOAD_CONTROL_INFORMATION, 1, &[0x04]),
        raw_ie(IE_TYPE_OVERLOAD_CONTROL_INFORMATION, 0, &[0x05]),
        raw_ie(IE_TYPE_PGW_CHANGE_INFO, 0, PGW_CHANGE_INFO_TWO),
    ];

    let mut create = create_request(1, SEQUENCE);
    create.additional_ies = repeatable.clone();
    let create_bytes = encode(
        &s2b_create_bearer_request(create).expect("repeatable Create request IEs must build"),
    );
    let (_, create_message) = S2bMessage::decode(&create_bytes, procedure_context())
        .expect("repeatable Create request IEs must decode");
    assert_eq!(
        create_message
            .as_view()
            .expect("typed Create view")
            .create_bearer_request()
            .expect("strict Create projection")
            .additional_ies,
        repeatable
    );

    let update = S2bUpdateBearerRequest {
        sequence_number: SEQUENCE,
        teid: REQUEST_TEID,
        message_priority: None,
        apn_ambr: AggregateMaximumBitRate {
            uplink: 64_000,
            downlink: 128_000,
        },
        bearer_contexts: vec![S2bUpdateBearerRequestContext {
            ebi: ebi(6),
            tft: Some(tft(1, 11, 4_501)),
            bearer_qos: None,
            additional_ies: Vec::new(),
        }],
        additional_ies: repeatable.clone(),
    };
    let update_bytes = encode(
        &s2b_update_bearer_request(update).expect("repeatable Update request IEs must build"),
    );
    let (_, update_message) = S2bMessage::decode(&update_bytes, procedure_context())
        .expect("repeatable Update request IEs must decode");
    assert_eq!(
        update_message
            .as_view()
            .expect("typed Update view")
            .update_bearer_request()
            .expect("strict Update projection")
            .additional_ies,
        repeatable
    );

    let delete = S2bDeleteBearerRequest {
        sequence_number: SEQUENCE,
        teid: REQUEST_TEID,
        message_priority: None,
        target: S2bDeleteBearerTarget::Linked(ebi(5)),
        cause: None,
        additional_ies: repeatable.clone(),
    };
    let delete_bytes = encode(
        &s2b_delete_bearer_request(delete).expect("repeatable Delete request IEs must build"),
    );
    let (_, delete_message) = S2bMessage::decode(&delete_bytes, procedure_context())
        .expect("repeatable Delete request IEs must decode");
    assert_eq!(
        delete_message
            .as_view()
            .expect("typed Delete view")
            .delete_bearer_request()
            .expect("strict Delete projection")
            .additional_ies,
        repeatable
    );

    let mut too_many_load = create_request(1, SEQUENCE);
    too_many_load.additional_ies = vec![
        raw_ie(IE_TYPE_LOAD_CONTROL_INFORMATION, 1, &[0x01]);
        MAX_PGW_APN_LOAD_CONTROL_INFORMATION_IES + 1
    ];
    assert!(s2b_create_bearer_request(too_many_load).is_err());

    let mut too_many_overload = create_request(1, SEQUENCE);
    too_many_overload.additional_ies = vec![
        raw_ie(IE_TYPE_OVERLOAD_CONTROL_INFORMATION, 0, &[0x02]);
        MAX_PGW_OVERLOAD_CONTROL_INFORMATION_IES + 1
    ];
    assert!(s2b_create_bearer_request(too_many_overload).is_err());

    let response = S2bCreateBearerResponse {
        sequence_number: SEQUENCE,
        teid: RESPONSE_TEID,
        message_priority: None,
        cause: CauseValue::RequestAccepted,
        bearer_contexts: vec![accepted_result(1)],
        additional_ies: vec![
            raw_ie(IE_TYPE_LOAD_CONTROL_INFORMATION, 1, &[0x01]),
            raw_ie(IE_TYPE_LOAD_CONTROL_INFORMATION, 1, &[0x02]),
        ],
    };
    assert!(
        s2b_create_bearer_response(response).is_err(),
        "the request-only repeatable profile must not weaken responses"
    );
}

#[test]
fn response_correlation_rejects_default_bearer_as_new_dedicated_bearer() {
    let request = create_request(1, SEQUENCE);
    let response = S2bCreateBearerResponse {
        sequence_number: SEQUENCE,
        teid: RESPONSE_TEID,
        message_priority: None,
        cause: CauseValue::RequestAccepted,
        bearer_contexts: vec![S2bCreateBearerResult::Accepted {
            ebi: request.linked_ebi,
            epdg_f_teid: f_teid(INTERFACE_TYPE_S2B_U_EPDG_GTP_U, 0x3000_0001, 21),
            pgw_f_teid: request.bearer_contexts[0].pgw_f_teid.clone(),
            additional_ies: Vec::new(),
        }],
        additional_ies: Vec::new(),
    };
    let error = correlate_create_bearer_response(&request, &response)
        .expect_err("default EBI cannot be allocated as a dedicated bearer");
    assert_eq!(error.kind(), DedicatedBearerErrorKind::CorrelationMismatch);
}

#[test]
fn specification_authored_fixture_bytes_are_stable() {
    let request = S2bCreateBearerRequest {
        sequence_number: SEQUENCE,
        teid: REQUEST_TEID,
        message_priority: None,
        linked_ebi: ebi(5),
        bearer_contexts: vec![S2bCreateBearerRequestContext {
            tft: tft(1, 10, 4_500),
            bearer_qos: qos(1),
            pgw_f_teid: f_teid(INTERFACE_TYPE_S2B_U_PGW_GTP_U, 0x1000_0001, 11),
            charging_id: ChargingId { value: 0x2000_0001 },
            additional_ies: Vec::new(),
        }],
        additional_ies: Vec::new(),
    };
    let create_request_bytes =
        encode(&s2b_create_bearer_request(request).expect("spec Create request"));
    assert_eq!(create_request_bytes.as_ref(), CREATE_REQUEST_FIXTURE);

    let create_response = S2bCreateBearerResponse {
        sequence_number: SEQUENCE,
        teid: RESPONSE_TEID,
        message_priority: None,
        cause: CauseValue::RequestAccepted,
        bearer_contexts: vec![S2bCreateBearerResult::Accepted {
            ebi: ebi(6),
            epdg_f_teid: f_teid(INTERFACE_TYPE_S2B_U_EPDG_GTP_U, 0x3000_0001, 21),
            pgw_f_teid: f_teid(INTERFACE_TYPE_S2B_U_PGW_GTP_U, 0x1000_0001, 11),
            additional_ies: Vec::new(),
        }],
        additional_ies: Vec::new(),
    };
    let create_response_bytes =
        encode(&s2b_create_bearer_response(create_response).expect("spec Create response"));
    assert_eq!(create_response_bytes.as_ref(), CREATE_RESPONSE_FIXTURE);

    let delete_request = S2bDeleteBearerRequest {
        sequence_number: SEQUENCE,
        teid: REQUEST_TEID,
        message_priority: None,
        target: S2bDeleteBearerTarget::Dedicated(vec![ebi(6), ebi(7)]),
        cause: None,
        additional_ies: Vec::new(),
    };
    let delete_request_bytes =
        encode(&s2b_delete_bearer_request(delete_request).expect("spec Delete request"));
    assert_eq!(delete_request_bytes.as_ref(), DELETE_REQUEST_FIXTURE);

    let delete_response = S2bDeleteBearerResponse {
        sequence_number: SEQUENCE,
        teid: RESPONSE_TEID,
        message_priority: None,
        cause: CauseValue::RequestAcceptedPartially,
        body: S2bDeleteBearerResponseBody::Dedicated(vec![
            S2bDeleteBearerResult {
                ebi: ebi(6),
                cause: CauseValue::RequestAccepted,
                additional_ies: Vec::new(),
            },
            S2bDeleteBearerResult {
                ebi: ebi(7),
                cause: CauseValue::ContextNotFound,
                additional_ies: Vec::new(),
            },
        ]),
        additional_ies: Vec::new(),
    };
    let delete_response_bytes =
        encode(&s2b_delete_bearer_response(delete_response).expect("spec Delete response"));
    assert_eq!(delete_response_bytes.as_ref(), DELETE_RESPONSE_FIXTURE);
}

const CREATE_REQUEST_FIXTURE: &[u8] = include_bytes!("fixtures/spec/create_bearer_request_s2b.bin");
const CREATE_RESPONSE_FIXTURE: &[u8] =
    include_bytes!("fixtures/spec/create_bearer_response_s2b.bin");
const DELETE_REQUEST_FIXTURE: &[u8] =
    include_bytes!("fixtures/spec/delete_bearer_request_dedicated.bin");
const DELETE_RESPONSE_FIXTURE: &[u8] =
    include_bytes!("fixtures/spec/delete_bearer_response_partial.bin");
