//! TS 29.274 Release 18 S2b dedicated-bearer procedure evidence.

use bytes::{Bytes, BytesMut};
use opc_proto_gtpv2c::header::MAX_SEQUENCE_NUMBER;
use opc_proto_gtpv2c::{
    correlate_create_bearer_response, correlate_delete_bearer_response, encode_typed_ie_sequence,
    s2b_create_bearer_request, s2b_create_bearer_response, s2b_delete_bearer_request,
    s2b_delete_bearer_response, BearerContext, BearerQos, CauseValue, ChargingId,
    DedicatedBearerErrorKind, EpsBearerId, FullyQualifiedTeid, Gtpv2cMonotonicMillis,
    Gtpv2cPeerToken, Gtpv2cTriggeredCompletion, Gtpv2cTriggeredRequestDisposition,
    Gtpv2cTriggeredTransactionError, Gtpv2cTriggeredTransactionPolicy, Gtpv2cTriggeredTransactions,
    Header, MessageType, OwnedMessage, Procedure, RawIe, S2bCreateBearerRequest,
    S2bCreateBearerRequestContext, S2bCreateBearerResponse, S2bCreateBearerResult,
    S2bDeleteBearerRequest, S2bDeleteBearerResponse, S2bDeleteBearerResponseBody,
    S2bDeleteBearerResult, S2bDeleteBearerTarget, S2bMessage, TypedIe, TypedIeValue,
    CREATE_BEARER_REQUEST, CREATE_BEARER_RESPONSE, DELETE_BEARER_REQUEST, DELETE_BEARER_RESPONSE,
    INTERFACE_TYPE_S2B_U_EPDG_GTP_U, INTERFACE_TYPE_S2B_U_PGW_GTP_U,
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
        priority_flags: 0x4f,
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
        bearer_qos: qos(1u8.saturating_add(index)),
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
    assert_eq!(DELETE_BEARER_REQUEST, 99);
    assert_eq!(DELETE_BEARER_RESPONSE, 100);
    assert_eq!(MessageType::from_u8(95), MessageType::CreateBearerRequest);
    assert_eq!(MessageType::from_u8(96), MessageType::CreateBearerResponse);
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
fn delete_bearer_linked_and_dedicated_forms_round_trip_and_correlate() {
    let linked_request = S2bDeleteBearerRequest {
        sequence_number: SEQUENCE,
        teid: REQUEST_TEID,
        target: S2bDeleteBearerTarget::Linked(ebi(5)),
        cause: Some(CauseValue::ReactivationRequested),
        additional_ies: vec![raw_ie(247, 6, UNKNOWN_TOP_VALUE)],
    };
    let linked_response = S2bDeleteBearerResponse {
        sequence_number: SEQUENCE,
        teid: RESPONSE_TEID,
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
        target: S2bDeleteBearerTarget::Dedicated(vec![ebi(6), ebi(7)]),
        cause: None,
        additional_ies: Vec::new(),
    };
    let dedicated_response = S2bDeleteBearerResponse {
        sequence_number: SEQUENCE,
        teid: RESPONSE_TEID,
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
    let request = create_request(1, SEQUENCE);
    let built = s2b_create_bearer_request(request).expect("valid request");
    let without_teid = OwnedMessage {
        header: Header::without_teid(CREATE_BEARER_REQUEST, SEQUENCE),
        raw_ies: built.raw_ies.clone(),
    };
    let bytes = encode(&without_teid);
    assert!(S2bMessage::decode(&bytes, procedure_context()).is_err());

    let zero_teid = OwnedMessage {
        header: Header::with_teid(CREATE_BEARER_REQUEST, 0, SEQUENCE),
        raw_ies: built.raw_ies,
    };
    let bytes = encode(&zero_teid);
    assert!(S2bMessage::decode(&bytes, procedure_context()).is_err());
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
fn triggered_transactions_dispatch_pending_commit_and_exactly_replay() {
    let request = create_request(1, SEQUENCE);
    let request_bytes = encode(&s2b_create_bearer_request(request).expect("valid request"));
    let response = S2bCreateBearerResponse {
        sequence_number: SEQUENCE,
        teid: RESPONSE_TEID,
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
            assert_eq!(replay_key, key);
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
        Gtpv2cTriggeredTransactionError::TransactionExpired
    );
    assert!(transactions.is_empty());
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
    for (index, sequence_number) in [MAX_SEQUENCE_NUMBER, 0].into_iter().enumerate() {
        let request = encode(
            &s2b_create_bearer_request(create_request(1, sequence_number))
                .expect("boundary sequence request"),
        );
        assert!(matches!(
            transactions
                .observe_request(
                    peer,
                    request,
                    RESPONSE_TEID,
                    Gtpv2cMonotonicMillis::new(index as u64),
                    DecodeContext::default(),
                )
                .expect("boundary sequence observation"),
            Gtpv2cTriggeredRequestDisposition::Dispatch(_)
        ));
    }
    assert_eq!(transactions.len(), 2);
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
fn raw_unknown_duplicates_still_honor_reject_policy() {
    let bytes = encode(&owned_message(
        DELETE_BEARER_REQUEST,
        Some(REQUEST_TEID),
        vec![
            typed(1, TypedIeValue::EpsBearerId(ebi(6))),
            raw_ie(245, 8, UNKNOWN_TOP_VALUE),
            raw_ie(245, 8, UNKNOWN_NESTED_VALUE),
        ],
    ));
    assert!(S2bMessage::decode(&bytes, procedure_context()).is_err());
}

#[test]
fn response_correlation_rejects_default_bearer_as_new_dedicated_bearer() {
    let request = create_request(1, SEQUENCE);
    let response = S2bCreateBearerResponse {
        sequence_number: SEQUENCE,
        teid: RESPONSE_TEID,
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
