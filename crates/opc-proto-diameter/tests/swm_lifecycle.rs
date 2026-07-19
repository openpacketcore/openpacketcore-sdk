//! Independent wire and failure-boundary evidence for SWm STR/STA.
//!
//! Fixtures in this file are hand-authored from the Diameter framing in RFC
//! 6733 sections 3 and 4 and the command ABNF in 3GPP TS 29.273 sections
//! 7.2.2.2.1 and 7.2.2.2.2. They do not use the SDK builder to produce their
//! input bytes.

use bytes::BytesMut;
use opc_proto_diameter::apps::swm::{
    self, SwmAdditionalAvp, SwmDiameterConnectionToken, SwmDiameterTransaction,
    SwmExpectedAnswerPeer, SwmRoutingMessagePriority, SwmSessionTerminationAnswer,
    SwmSessionTerminationAnswerEnvelope, SwmSessionTerminationCorrelationError,
    SwmSessionTerminationRequestEnvelope, SwmSessionTerminationResult, SwmTerminationCause,
};
use opc_proto_diameter::avp::dictionary::Redacted;
use opc_proto_diameter::base;
use opc_proto_diameter::error_answer::{
    inspect_diameter_request, DiameterRequestFailure, DiameterRequestInspection,
};
use opc_proto_diameter::{
    apps, AvpCode, AvpHeader, AvpKey, Message, OwnedMessage, DIAMETER_HEADER_LEN,
};
use opc_protocol::{
    BorrowDecode, DecodeContext, DecodeErrorCode, DuplicateIePolicy, Encode, EncodeContext,
    UnknownIePolicy,
};
use std::num::NonZeroU64;

const HOP_BY_HOP: u32 = 0x3510_0001;
const FAILOVER_HOP_BY_HOP: u32 = 0x3510_1001;
const END_TO_END: u32 = 0x3510_0002;
const SESSION_ID: &str = "session;private;351";
const USER_NAME: &str = "subscriber-private@example.invalid";
const UNKNOWN_OPTIONAL_AVP: u32 = 9_351;
const CONNECTION_A: SwmDiameterConnectionToken = SwmDiameterConnectionToken::new(NonZeroU64::MIN);
const CONNECTION_B: SwmDiameterConnectionToken = SwmDiameterConnectionToken::new(NonZeroU64::MAX);

fn wire_avp(code: u32, flags: u8, value: &[u8]) -> Vec<u8> {
    let length = 8 + value.len();
    let mut wire = Vec::with_capacity((length + 3) & !3);
    wire.extend_from_slice(&code.to_be_bytes());
    wire.push(flags);
    wire.extend_from_slice(&(length as u32).to_be_bytes()[1..]);
    wire.extend_from_slice(value);
    wire.resize((length + 3) & !3, 0);
    wire
}

fn wire_vendor_avp(code: u32, flags: u8, vendor_id: u32, value: &[u8]) -> Vec<u8> {
    let length = 12 + value.len();
    let mut wire = Vec::with_capacity((length + 3) & !3);
    wire.extend_from_slice(&code.to_be_bytes());
    wire.push(flags | 0x80);
    wire.extend_from_slice(&(length as u32).to_be_bytes()[1..]);
    wire.extend_from_slice(&vendor_id.to_be_bytes());
    wire.extend_from_slice(value);
    wire.resize((length + 3) & !3, 0);
    wire
}

fn wire_message(
    flags: u8,
    hop_by_hop: u32,
    end_to_end: u32,
    avps: impl IntoIterator<Item = Vec<u8>>,
) -> Vec<u8> {
    let avps: Vec<u8> = avps.into_iter().flatten().collect();
    let length = DIAMETER_HEADER_LEN + avps.len();
    let mut wire = Vec::with_capacity(length);
    wire.push(1);
    wire.extend_from_slice(&(length as u32).to_be_bytes()[1..]);
    wire.push(flags);
    wire.extend_from_slice(&275_u32.to_be_bytes()[1..]);
    wire.extend_from_slice(&swm::APPLICATION_ID.get().to_be_bytes());
    wire.extend_from_slice(&hop_by_hop.to_be_bytes());
    wire.extend_from_slice(&end_to_end.to_be_bytes());
    wire.extend_from_slice(&avps);
    wire
}

fn proxy_info(host: &[u8], state: &[u8]) -> Vec<u8> {
    let value: Vec<u8> = [
        wire_avp(base::AVP_PROXY_HOST.get(), 0x40, host),
        wire_avp(base::AVP_PROXY_STATE.get(), 0x40, state),
    ]
    .into_iter()
    .flatten()
    .collect();
    wire_avp(base::AVP_PROXY_INFO.get(), 0x40, &value)
}

fn oc_olr_value() -> Vec<u8> {
    [
        wire_avp(624, 0x00, &1_u64.to_be_bytes()),
        wire_avp(626, 0x00, &0_u32.to_be_bytes()),
    ]
    .into_iter()
    .flatten()
    .collect()
}

fn loss_oc_olr_value() -> Vec<u8> {
    [
        wire_avp(
            swm::AVP_OC_SEQUENCE_NUMBER.get(),
            0x00,
            &1_u64.to_be_bytes(),
        ),
        wire_avp(swm::AVP_OC_REPORT_TYPE.get(), 0x00, &0_u32.to_be_bytes()),
        wire_avp(
            swm::AVP_OC_REDUCTION_PERCENTAGE.get(),
            0x00,
            &25_u32.to_be_bytes(),
        ),
    ]
    .into_iter()
    .flatten()
    .collect()
}

fn oc_supported_value(feature_vector: Option<u64>, child_flags: u8) -> Vec<u8> {
    feature_vector.map_or_else(Vec::new, |value| {
        wire_avp(
            swm::AVP_OC_FEATURE_VECTOR.get(),
            child_flags,
            &value.to_be_bytes(),
        )
    })
}

fn load_value(load_type: u32, load_value: u64, source_id: &[u8]) -> Vec<u8> {
    [
        wire_avp(swm::AVP_LOAD_TYPE.get(), 0x00, &load_type.to_be_bytes()),
        wire_avp(swm::AVP_LOAD_VALUE.get(), 0x00, &load_value.to_be_bytes()),
        wire_avp(swm::AVP_SOURCE_ID.get(), 0x00, source_id),
    ]
    .into_iter()
    .flatten()
    .collect()
}

fn str_avps() -> Vec<Vec<u8>> {
    vec![
        wire_avp(base::AVP_SESSION_ID.get(), 0x40, SESSION_ID.as_bytes()),
        wire_avp(swm::AVP_DRMP.get(), 0x00, &5_u32.to_be_bytes()),
        wire_avp(base::AVP_ORIGIN_HOST.get(), 0x40, b"epdg.private.invalid"),
        wire_avp(base::AVP_ORIGIN_REALM.get(), 0x40, b"private.invalid"),
        wire_avp(
            base::AVP_DESTINATION_REALM.get(),
            0x40,
            b"aaa.private.invalid",
        ),
        wire_avp(
            base::AVP_DESTINATION_HOST.get(),
            0x40,
            b"dra.private.invalid",
        ),
        wire_avp(
            base::AVP_AUTH_APPLICATION_ID.get(),
            0x40,
            &swm::APPLICATION_ID.get().to_be_bytes(),
        ),
        wire_avp(
            base::AVP_TERMINATION_CAUSE.get(),
            0x40,
            &4_u32.to_be_bytes(),
        ),
        wire_avp(base::AVP_USER_NAME.get(), 0x40, USER_NAME.as_bytes()),
        proxy_info(b"proxy-one.private.invalid", b"private-proxy-state-one"),
        proxy_info(b"proxy-two.private.invalid", b"private-proxy-state-two"),
        wire_avp(
            base::AVP_ROUTE_RECORD.get(),
            0x40,
            b"route-one.private.invalid",
        ),
        wire_avp(
            base::AVP_ROUTE_RECORD.get(),
            0x40,
            b"route-two.private.invalid",
        ),
        wire_avp(UNKNOWN_OPTIONAL_AVP, 0x00, b"private-extension-value"),
    ]
}

fn str_wire() -> Vec<u8> {
    wire_message(0xc0, HOP_BY_HOP, END_TO_END, str_avps())
}

fn sta_avps(session_id: &str, result_code: u32) -> Vec<Vec<u8>> {
    vec![
        wire_avp(base::AVP_SESSION_ID.get(), 0x40, session_id.as_bytes()),
        wire_avp(swm::AVP_DRMP.get(), 0x00, &7_u32.to_be_bytes()),
        wire_avp(
            base::AVP_RESULT_CODE.get(),
            0x40,
            &result_code.to_be_bytes(),
        ),
        wire_avp(base::AVP_ORIGIN_HOST.get(), 0x40, b"aaa.private.invalid"),
        wire_avp(base::AVP_ORIGIN_REALM.get(), 0x40, b"private.invalid"),
        wire_avp(UNKNOWN_OPTIONAL_AVP, 0x00, b"private-answer-extension"),
        proxy_info(b"proxy-one.private.invalid", b"private-proxy-state-one"),
        proxy_info(b"proxy-two.private.invalid", b"private-proxy-state-two"),
    ]
}

fn sta_wire(session_id: &str, result_code: u32, hop_by_hop: u32) -> Vec<u8> {
    wire_message(
        0x40,
        hop_by_hop,
        END_TO_END,
        sta_avps(session_id, result_code),
    )
}

fn decode(wire: &[u8]) -> Message<'_> {
    let (tail, message) = Message::decode(wire, DecodeContext::default())
        .expect("hand-authored Diameter fixture must frame");
    assert!(tail.is_empty());
    message
}

fn encode(message: &OwnedMessage) -> Vec<u8> {
    let mut wire = BytesMut::new();
    message
        .encode(&mut wire, EncodeContext::default())
        .expect("typed lifecycle message must encode");
    wire.to_vec()
}

fn parsed_inbound_request_envelope(wire: &[u8]) -> SwmSessionTerminationRequestEnvelope {
    swm::parse_swm_session_termination_request_envelope(&decode(wire), DecodeContext::default())
        .expect("valid STR fixture must parse")
}

fn parsed_request_envelope(wire: &[u8]) -> SwmSessionTerminationRequestEnvelope {
    parsed_inbound_request_envelope(wire)
        .with_expected_answer_peer(SwmExpectedAnswerPeer::routed(CONNECTION_A))
}

fn parsed_answer_envelope(message: &Message<'_>) -> SwmSessionTerminationAnswerEnvelope {
    swm::parse_swm_session_termination_answer_envelope_from_connection(
        message,
        CONNECTION_A,
        DecodeContext::default(),
    )
    .expect("valid STA fixture must parse")
}

#[test]
fn ts29273_str_fixture_parses_and_reencodes_byte_exact() {
    let wire = str_wire();
    let envelope = parsed_request_envelope(&wire);
    let request = envelope.request();

    assert_eq!(request.session_id.as_ref(), SESSION_ID);
    assert_eq!(request.origin_host.as_ref(), "epdg.private.invalid");
    assert_eq!(request.destination_realm.as_ref(), "aaa.private.invalid");
    assert_eq!(request.user_name.as_ref(), USER_NAME);
    assert_eq!(
        request.termination_cause,
        SwmTerminationCause::Administrative
    );
    assert_eq!(request.drmp, SwmRoutingMessagePriority::new(5));
    assert_eq!(request.route_records.len(), 2);
    assert_eq!(request.additional_avps.len(), 1);
    assert_eq!(
        request.additional_avps[0].code().get(),
        UNKNOWN_OPTIONAL_AVP
    );
    assert_eq!(envelope.proxy_info_count(), 2);
    assert_eq!(
        envelope.transaction(),
        SwmDiameterTransaction::new(HOP_BY_HOP, END_TO_END)
    );

    let rebuilt = swm::build_swm_session_termination_request(&envelope, EncodeContext::default())
        .expect("parsed STR must rebuild");
    assert_eq!(encode(&rebuilt), wire);
}

#[test]
fn ts29273_sta_fixture_parses_correlates_and_reencodes_byte_exact() {
    let request_wire = str_wire();
    let request = parsed_request_envelope(&request_wire);
    let answer_wire = sta_wire(SESSION_ID, base::RESULT_CODE_DIAMETER_SUCCESS, HOP_BY_HOP);
    let answer_message = decode(&answer_wire);
    let answer = parsed_answer_envelope(&answer_message);

    assert_eq!(answer.answer().result, SwmSessionTerminationResult::Success);
    assert_eq!(answer.answer().drmp, SwmRoutingMessagePriority::new(7));
    assert_eq!(answer.answer().additional_avps.len(), 1);
    assert_eq!(answer.proxy_info_count(), 2);
    let rebuilt = swm::build_swm_session_termination_answer(
        &request,
        answer.answer(),
        EncodeContext::default(),
    )
    .expect("parsed STA must rebuild against its STR");
    assert_eq!(encode(&rebuilt), answer_wire);

    let exchange = request
        .correlate_answer(answer)
        .expect("exact STR/STA identifiers and Session-Id must correlate");
    assert_eq!(
        exchange.transaction(),
        SwmDiameterTransaction::new(HOP_BY_HOP, END_TO_END)
    );
    assert_eq!(
        exchange.answer().result,
        SwmSessionTerminationResult::Success
    );
}

#[test]
fn recognized_swm_m_bit_overrides_are_tolerated_on_receive_and_cleared_on_send() {
    let mut request_avps = str_avps();
    request_avps[1][4] = 0x40;
    let request_wire = wire_message(0xc0, HOP_BY_HOP, END_TO_END, request_avps);
    let request = parsed_request_envelope(&request_wire);
    assert_eq!(request.request().drmp, SwmRoutingMessagePriority::new(5));

    let rebuilt_request =
        swm::build_swm_session_termination_request(&request, EncodeContext::default())
            .expect("recognized inbound M-set DRMP must rebuild canonically");
    let rebuilt_request_wire = encode(&rebuilt_request);
    let rebuilt_request_message = decode(&rebuilt_request_wire);
    let request_drmp = rebuilt_request_message
        .avps(DecodeContext::default())
        .find_map(|avp| {
            let avp = avp.expect("rebuilt request AVP framing");
            (avp.header.key() == AvpKey::ietf(swm::AVP_DRMP)).then_some(avp)
        })
        .expect("rebuilt request DRMP");
    assert!(!request_drmp.header.flags.is_mandatory());

    let mut answer_avps = sta_avps(SESSION_ID, base::RESULT_CODE_DIAMETER_SUCCESS);
    answer_avps[1][4] = 0x40;
    let answer_wire = wire_message(0x40, HOP_BY_HOP, END_TO_END, answer_avps);
    let answer_message = decode(&answer_wire);
    let answer = parsed_answer_envelope(&answer_message);
    assert_eq!(answer.answer().drmp, SwmRoutingMessagePriority::new(7));

    let rebuilt_answer = swm::build_swm_session_termination_answer(
        &request,
        answer.answer(),
        EncodeContext::default(),
    )
    .expect("recognized inbound M-set DRMP must rebuild canonically");
    let rebuilt_answer_wire = encode(&rebuilt_answer);
    let rebuilt_answer_message = decode(&rebuilt_answer_wire);
    let answer_drmp = rebuilt_answer_message
        .avps(DecodeContext::default())
        .find_map(|avp| {
            let avp = avp.expect("rebuilt answer AVP framing");
            (avp.header.key() == AvpKey::ietf(swm::AVP_DRMP)).then_some(avp)
        })
        .expect("rebuilt answer DRMP");
    assert!(!answer_drmp.header.flags.is_mandatory());
}

#[test]
fn unknown_session_answer_is_request_bound_and_keeps_error_bit_clear() {
    let request = parsed_request_envelope(&str_wire());
    let answer = SwmSessionTerminationAnswer::for_request(
        &request,
        SwmSessionTerminationResult::UnknownSession,
        "aaa.private.invalid",
        "private.invalid",
    );
    let built =
        swm::build_swm_session_termination_answer(&request, &answer, EncodeContext::default())
            .expect("unknown-session STA must build");
    assert!(!built.header.flags.is_error());
    assert_eq!(built.header.hop_by_hop_identifier, HOP_BY_HOP);
    assert_eq!(built.header.end_to_end_identifier, END_TO_END);

    let encoded = encode(&built);
    let parsed =
        swm::parse_swm_session_termination_answer(&decode(&encoded), DecodeContext::default())
            .expect("unknown-session STA must parse");
    assert!(parsed.result.is_unknown_session());
    assert_eq!(
        parsed
            .session_id
            .as_ref()
            .map(|session_id| session_id.as_ref().as_str()),
        Some(SESSION_ID)
    );
}

#[test]
fn duplicate_str_replays_success_and_error_sta_per_rfc6733() {
    let initial_request = parsed_inbound_request_envelope(&str_wire());
    assert!(!initial_request.is_potentially_retransmitted());
    let exact_duplicate_wire = wire_message(0xd0, HOP_BY_HOP, END_TO_END, str_avps());
    let exact_duplicate_request = parsed_inbound_request_envelope(&exact_duplicate_wire);
    assert!(exact_duplicate_request.is_potentially_retransmitted());
    let failover_duplicate_wire = wire_message(0xd0, FAILOVER_HOP_BY_HOP, END_TO_END, str_avps());
    let failover_duplicate_request = parsed_inbound_request_envelope(&failover_duplicate_wire);
    assert!(failover_duplicate_request.is_potentially_retransmitted());

    for result in [
        SwmSessionTerminationResult::Success,
        SwmSessionTerminationResult::UnknownSession,
    ] {
        let committed_answer = SwmSessionTerminationAnswer::for_request(
            &initial_request,
            result,
            "aaa.private.invalid",
            "private.invalid",
        );
        let committed = swm::build_swm_session_termination_answer(
            &initial_request,
            &committed_answer,
            EncodeContext::default(),
        )
        .expect("first STA construction must succeed");
        let exact_duplicate_answer = SwmSessionTerminationAnswer::for_request(
            &exact_duplicate_request,
            result,
            "aaa.private.invalid",
            "private.invalid",
        );
        let exact_replay = swm::build_swm_session_termination_answer(
            &exact_duplicate_request,
            &exact_duplicate_answer,
            EncodeContext::default(),
        )
        .expect("same-hop T-set duplicate STR must reproduce the committed STA");
        assert_eq!(encode(&exact_replay), encode(&committed));

        let failover_duplicate_answer = SwmSessionTerminationAnswer::for_request(
            &failover_duplicate_request,
            result,
            "aaa.private.invalid",
            "private.invalid",
        );
        let failover_replay = swm::build_swm_session_termination_answer(
            &failover_duplicate_request,
            &failover_duplicate_answer,
            EncodeContext::default(),
        )
        .expect("failover duplicate STR must replay the application answer");

        assert_eq!(failover_replay.raw_avps, committed.raw_avps);
        assert_eq!(failover_replay.header.flags, committed.header.flags);
        assert_eq!(
            failover_replay.header.hop_by_hop_identifier,
            FAILOVER_HOP_BY_HOP
        );
        assert_eq!(failover_replay.header.end_to_end_identifier, END_TO_END);
        assert!(!failover_replay.header.flags.is_potentially_retransmitted());
    }
}

#[test]
fn correlation_rejects_transaction_and_session_mismatches_with_stable_codes() {
    let request = parsed_request_envelope(&str_wire());
    let wrong_transaction_wire = sta_wire(
        SESSION_ID,
        base::RESULT_CODE_DIAMETER_SUCCESS,
        HOP_BY_HOP.wrapping_add(1),
    );
    let wrong_transaction = parsed_answer_envelope(&decode(&wrong_transaction_wire));
    let error = request
        .clone()
        .correlate_answer(wrong_transaction)
        .expect_err("wrong transaction must not correlate");
    assert_eq!(
        error,
        SwmSessionTerminationCorrelationError::TransactionMismatch
    );
    assert_eq!(error.as_str(), "swm_str_sta_transaction_mismatch");

    let wrong_session_wire = sta_wire(
        "session;private;different",
        base::RESULT_CODE_DIAMETER_SUCCESS,
        HOP_BY_HOP,
    );
    let wrong_session = parsed_answer_envelope(&decode(&wrong_session_wire));
    let error = request
        .correlate_answer(wrong_session)
        .expect_err("wrong Session-Id must not correlate");
    assert_eq!(
        error,
        SwmSessionTerminationCorrelationError::SessionMismatch
    );
    assert_eq!(error.as_str(), "swm_str_sta_session_mismatch");
}

#[test]
fn direct_and_routed_peer_direction_correlation_is_explicit_and_fail_closed() {
    let parse_answer = |connection, avps, flags| {
        let wire = wire_message(flags, HOP_BY_HOP, END_TO_END, avps);
        swm::parse_swm_session_termination_answer_envelope_from_connection(
            &decode(&wire),
            connection,
            DecodeContext::default(),
        )
        .expect("independently valid STA fixture must parse")
    };

    let inbound_request = parsed_inbound_request_envelope(&str_wire());
    let error = inbound_request
        .clone()
        .correlate_answer(parse_answer(
            CONNECTION_A,
            sta_avps(SESSION_ID, base::RESULT_CODE_DIAMETER_SUCCESS),
            0x40,
        ))
        .expect_err("an inbound server envelope has no outbound peer binding");
    assert_eq!(
        error,
        SwmSessionTerminationCorrelationError::PeerBindingMissing
    );
    assert_eq!(error.as_str(), "swm_str_sta_peer_binding_missing");
    swm::build_swm_session_termination_request(&inbound_request, EncodeContext::default())
        .expect_err("an inbound server envelope cannot be dispatched without route binding");

    let routed_request = inbound_request
        .clone()
        .with_expected_answer_peer(SwmExpectedAnswerPeer::routed(CONNECTION_A));
    routed_request
        .clone()
        .correlate_answer(parse_answer(
            CONNECTION_A,
            sta_avps(SESSION_ID, base::RESULT_CODE_DIAMETER_SUCCESS),
            0x40,
        ))
        .expect("routed DRA request accepts the final AAA Origin on the same connection");

    let error = routed_request
        .clone()
        .correlate_answer(parse_answer(
            CONNECTION_B,
            sta_avps(SESSION_ID, base::RESULT_CODE_DIAMETER_SUCCESS),
            0x40,
        ))
        .expect_err("an answer from another authenticated connection must fail");
    assert_eq!(
        error,
        SwmSessionTerminationCorrelationError::PeerConnectionMismatch
    );
    assert_eq!(error.as_str(), "swm_str_sta_peer_connection_mismatch");

    let direct_request =
        inbound_request
            .clone()
            .with_expected_answer_peer(SwmExpectedAnswerPeer::direct(
                CONNECTION_A,
                "aaa.private.invalid",
                "private.invalid",
            ));
    direct_request
        .clone()
        .correlate_answer(parse_answer(
            CONNECTION_A,
            sta_avps(SESSION_ID, base::RESULT_CODE_DIAMETER_SUCCESS),
            0x40,
        ))
        .expect("direct binding accepts its exact logical Origin");
    let mut differently_cased_origin_avps =
        sta_avps(SESSION_ID, base::RESULT_CODE_DIAMETER_SUCCESS);
    differently_cased_origin_avps[3] =
        wire_avp(base::AVP_ORIGIN_HOST.get(), 0x40, b"AAA.PRIVATE.INVALID");
    differently_cased_origin_avps[4] =
        wire_avp(base::AVP_ORIGIN_REALM.get(), 0x40, b"PRIVATE.INVALID");
    direct_request
        .clone()
        .correlate_answer(parse_answer(
            CONNECTION_A,
            differently_cased_origin_avps,
            0x40,
        ))
        .expect("DiameterIdentity FQDN and realm matching is ASCII case-insensitive");
    let mut wrong_origin_avps = sta_avps(SESSION_ID, base::RESULT_CODE_DIAMETER_SUCCESS);
    wrong_origin_avps[3] = wire_avp(
        base::AVP_ORIGIN_HOST.get(),
        0x40,
        b"different-aaa.private.invalid",
    );
    let error = direct_request
        .clone()
        .correlate_answer(parse_answer(CONNECTION_A, wrong_origin_avps, 0x40))
        .expect_err("direct binding rejects another logical Origin");
    assert_eq!(
        error,
        SwmSessionTerminationCorrelationError::PeerIdentityMismatch
    );
    assert_eq!(error.as_str(), "swm_str_sta_peer_identity_mismatch");

    let realm_bound =
        inbound_request
            .clone()
            .with_expected_answer_peer(SwmExpectedAnswerPeer::routed_in_realm(
                CONNECTION_A,
                "private.invalid",
            ));
    let mut pooled_answer_avps = sta_avps(SESSION_ID, base::RESULT_CODE_DIAMETER_SUCCESS);
    pooled_answer_avps[3] = wire_avp(
        base::AVP_ORIGIN_HOST.get(),
        0x40,
        b"aaa-pool-two.private.invalid",
    );
    realm_bound
        .clone()
        .correlate_answer(parse_answer(CONNECTION_A, pooled_answer_avps, 0x40))
        .expect("realm binding accepts another authenticated server in the realm");
    let mut differently_cased_realm_avps = sta_avps(SESSION_ID, base::RESULT_CODE_DIAMETER_SUCCESS);
    differently_cased_realm_avps[4] =
        wire_avp(base::AVP_ORIGIN_REALM.get(), 0x40, b"PRIVATE.INVALID");
    realm_bound
        .clone()
        .correlate_answer(parse_answer(
            CONNECTION_A,
            differently_cased_realm_avps,
            0x40,
        ))
        .expect("routed realm matching is ASCII case-insensitive");
    let mut wrong_realm_avps = sta_avps(SESSION_ID, base::RESULT_CODE_DIAMETER_SUCCESS);
    wrong_realm_avps[4] = wire_avp(base::AVP_ORIGIN_REALM.get(), 0x40, b"different.invalid");
    let error = realm_bound
        .correlate_answer(parse_answer(CONNECTION_A, wrong_realm_avps, 0x40))
        .expect_err("realm binding rejects a logical Origin outside the realm");
    assert_eq!(
        error,
        SwmSessionTerminationCorrelationError::PeerIdentityMismatch
    );

    let server_answer = SwmSessionTerminationAnswer::for_request(
        &inbound_request,
        SwmSessionTerminationResult::Success,
        "aaa.private.invalid",
        "private.invalid",
    );
    swm::build_swm_session_termination_answer(
        &inbound_request,
        &server_answer,
        EncodeContext::default(),
    )
    .expect("server answer construction does not infer Origin from routed Destination AVPs");

    let mut agent_error_avps = sta_avps(SESSION_ID, 3_002);
    agent_error_avps[3] = wire_avp(
        base::AVP_ORIGIN_HOST.get(),
        0x40,
        b"intermediary.private.invalid",
    );
    agent_error_avps[4] = wire_avp(base::AVP_ORIGIN_REALM.get(), 0x40, b"intermediary.invalid");
    agent_error_avps.retain(|avp| {
        u32::from_be_bytes(avp[0..4].try_into().expect("fixed AVP code"))
            != base::AVP_SESSION_ID.get()
    });
    let agent_error = parse_answer(CONNECTION_A, agent_error_avps.clone(), 0x60);
    assert!(agent_error.is_protocol_error());
    direct_request
        .clone()
        .correlate_answer(agent_error)
        .expect("generic E-bit errors skip only the logical-Origin policy");
    let error = direct_request
        .correlate_answer(parse_answer(CONNECTION_B, agent_error_avps, 0x60))
        .expect_err("generic E-bit errors remain bound to their connection");
    assert_eq!(
        error,
        SwmSessionTerminationCorrelationError::PeerConnectionMismatch
    );

    let direct_debug = format!(
        "{:?}",
        SwmExpectedAnswerPeer::direct(CONNECTION_A, "aaa.private.invalid", "private.invalid")
    );
    assert!(!direct_debug.contains("aaa.private.invalid"));
    assert!(!direct_debug.contains("private.invalid"));
    assert!(!direct_debug.contains(&u64::MAX.to_string()));
    assert_eq!(
        format!("{CONNECTION_A:?}"),
        "SwmDiameterConnectionToken(<redacted>)"
    );
}

#[test]
fn correlation_requires_the_exact_ordered_proxy_info_chain() {
    let request = parsed_request_envelope(&str_wire());
    let parse_answer = |avps| {
        let wire = wire_message(0x40, HOP_BY_HOP, END_TO_END, avps);
        let message = decode(&wire);
        parsed_answer_envelope(&message)
    };

    let mut missing = sta_avps(SESSION_ID, base::RESULT_CODE_DIAMETER_SUCCESS);
    missing.retain(|avp| {
        u32::from_be_bytes(avp[0..4].try_into().expect("fixed AVP code"))
            != base::AVP_PROXY_INFO.get()
    });
    let error = request
        .clone()
        .correlate_answer(parse_answer(missing))
        .expect_err("missing Proxy-Info chain must not correlate");
    assert_eq!(
        error,
        SwmSessionTerminationCorrelationError::ProxyInfoMismatch
    );
    assert_eq!(error.as_str(), "swm_str_sta_proxy_info_mismatch");

    let mut reordered = sta_avps(SESSION_ID, base::RESULT_CODE_DIAMETER_SUCCESS);
    reordered.swap(6, 7);
    assert_eq!(
        request
            .clone()
            .correlate_answer(parse_answer(reordered))
            .expect_err("reordered Proxy-Info chain must not correlate"),
        SwmSessionTerminationCorrelationError::ProxyInfoMismatch
    );

    let mut changed = sta_avps(SESSION_ID, base::RESULT_CODE_DIAMETER_SUCCESS);
    changed.pop();
    changed.push(proxy_info(
        b"proxy-two.private.invalid",
        b"changed-private-proxy-state",
    ));
    assert_eq!(
        request
            .clone()
            .correlate_answer(parse_answer(changed))
            .expect_err("changed Proxy-Info state must not correlate"),
        SwmSessionTerminationCorrelationError::ProxyInfoMismatch
    );

    let mut request_without_proxy = str_avps();
    request_without_proxy.retain(|avp| {
        u32::from_be_bytes(avp[0..4].try_into().expect("fixed AVP code"))
            != base::AVP_PROXY_INFO.get()
    });
    let request_without_proxy = parsed_request_envelope(&wire_message(
        0xc0,
        HOP_BY_HOP,
        END_TO_END,
        request_without_proxy,
    ));
    assert_eq!(
        request_without_proxy
            .correlate_answer(parse_answer(sta_avps(
                SESSION_ID,
                base::RESULT_CODE_DIAMETER_SUCCESS,
            )))
            .expect_err("unsolicited Proxy-Info chain must not correlate"),
        SwmSessionTerminationCorrelationError::ProxyInfoMismatch
    );
}

#[test]
fn duplicate_singletons_and_additional_singletons_fail_closed() {
    let mut duplicate_session = str_avps();
    duplicate_session.push(wire_avp(
        base::AVP_SESSION_ID.get(),
        0x40,
        b"session;private;second",
    ));
    let wire = wire_message(0xc0, HOP_BY_HOP, END_TO_END, duplicate_session);
    let error =
        swm::parse_swm_session_termination_request(&decode(&wire), DecodeContext::default())
            .expect_err("duplicate Session-Id must fail");
    assert_eq!(error.code(), &DecodeErrorCode::DuplicateIe);

    let mut duplicate_extension = str_avps();
    duplicate_extension.push(wire_avp(
        UNKNOWN_OPTIONAL_AVP,
        0x00,
        b"private-second-value",
    ));
    let wire = wire_message(0xc0, HOP_BY_HOP, END_TO_END, duplicate_extension);
    let error =
        swm::parse_swm_session_termination_request(&decode(&wire), DecodeContext::default())
            .expect_err("untrusted duplicate optional singleton must fail");
    assert_eq!(error.code(), &DecodeErrorCode::DuplicateIe);

    let mut duplicate_result = sta_avps(SESSION_ID, base::RESULT_CODE_DIAMETER_SUCCESS);
    duplicate_result.push(wire_avp(
        base::AVP_RESULT_CODE.get(),
        0x40,
        &base::RESULT_CODE_DIAMETER_SUCCESS.to_be_bytes(),
    ));
    let wire = wire_message(0x40, HOP_BY_HOP, END_TO_END, duplicate_result);
    let error = swm::parse_swm_session_termination_answer(&decode(&wire), DecodeContext::default())
        .expect_err("duplicate Result-Code must fail");
    assert_eq!(error.code(), &DecodeErrorCode::DuplicateIe);
}

#[test]
fn dictionary_aware_conservative_decode_allows_only_declared_repetition() {
    let mut ctx = DecodeContext::conservative();
    ctx.unknown_ie_policy = UnknownIePolicy::Preserve;
    let wire = str_wire();
    let (tail, _) = Message::decode_with_dictionary(&wire, ctx, apps::APP_DICTIONARIES)
        .expect("two Proxy-Info and Route-Record AVPs are command-declared repeatable");
    assert!(tail.is_empty());

    let mut duplicate_session = str_avps();
    duplicate_session.push(wire_avp(
        base::AVP_SESSION_ID.get(),
        0x40,
        SESSION_ID.as_bytes(),
    ));
    let wire = wire_message(0xc0, HOP_BY_HOP, END_TO_END, duplicate_session);
    let error = Message::decode_with_dictionary(&wire, ctx, apps::APP_DICTIONARIES)
        .expect_err("command singleton duplication must still fail");
    assert_eq!(error.code(), &DecodeErrorCode::DuplicateIe);
}

#[test]
fn repeated_class_avps_survive_conservative_request_and_answer_paths() {
    let mut request_avps = str_avps();
    request_avps.push(wire_avp(base::AVP_CLASS.get(), 0x40, b"class-state-one"));
    request_avps.push(wire_avp(base::AVP_CLASS.get(), 0x40, b"class-state-two"));
    let request_wire = wire_message(0xc0, HOP_BY_HOP, END_TO_END, request_avps);
    let request_ctx = DecodeContext {
        unknown_ie_policy: UnknownIePolicy::Preserve,
        ..DecodeContext::conservative()
    };
    let (tail, request_message) =
        Message::decode_with_dictionary(&request_wire, request_ctx, apps::APP_DICTIONARIES)
            .expect("RFC 6733 permits repeated Class AVPs on STR");
    assert!(tail.is_empty());
    let request =
        swm::parse_swm_session_termination_request_envelope(&request_message, request_ctx)
            .expect("typed STR must preserve repeated Class AVPs")
            .with_expected_answer_peer(SwmExpectedAnswerPeer::routed(CONNECTION_A));
    let request_classes: Vec<_> = request
        .request()
        .additional_avps
        .iter()
        .filter(|avp| avp.code() == base::AVP_CLASS)
        .map(SwmAdditionalAvp::value_len)
        .collect();
    assert_eq!(request_classes, vec![15, 15]);

    let rebuilt_request =
        swm::build_swm_session_termination_request(&request, EncodeContext::default())
            .expect("repeated request Class AVPs must remain encodable");
    let rebuilt_request_wire = encode(&rebuilt_request);
    let (tail, _) =
        Message::decode_with_dictionary(&rebuilt_request_wire, request_ctx, apps::APP_DICTIONARIES)
            .expect("rebuilt STR must retain command-aware Class repeatability");
    assert!(tail.is_empty());

    let mut answer = SwmSessionTerminationAnswer::for_request(
        &request,
        SwmSessionTerminationResult::Success,
        "aaa.private.invalid",
        "private.invalid",
    );
    answer.additional_avps = [
        b"answer-class-one".as_slice(),
        b"answer-class-two".as_slice(),
    ]
    .into_iter()
    .map(|value| {
        SwmAdditionalAvp::new(
            AvpHeader::ietf(base::AVP_CLASS, true),
            value.to_vec(),
            EncodeContext::default(),
        )
        .expect("Class AVP fixture must encode")
    })
    .collect();
    let built_answer =
        swm::build_swm_session_termination_answer(&request, &answer, EncodeContext::default())
            .expect("repeated answer Class AVPs must remain encodable");
    let built_answer_wire = encode(&built_answer);
    let (tail, answer_message) = Message::decode_with_dictionary(
        &built_answer_wire,
        DecodeContext::conservative(),
        apps::APP_DICTIONARIES,
    )
    .expect("RFC 6733 permits repeated Class AVPs on STA");
    assert!(tail.is_empty());
    let parsed_answer =
        swm::parse_swm_session_termination_answer(&answer_message, DecodeContext::conservative())
            .expect("typed STA must preserve repeated Class AVPs");
    let answer_classes: Vec<_> = parsed_answer
        .additional_avps
        .iter()
        .filter(|avp| avp.code() == base::AVP_CLASS)
        .map(SwmAdditionalAvp::value_len)
        .collect();
    assert_eq!(answer_classes, vec![16, 16]);
}

#[test]
fn malformed_proxy_and_wrong_role_avps_are_rejected() {
    let malformed_proxy = wire_avp(
        base::AVP_PROXY_INFO.get(),
        0x40,
        &wire_avp(base::AVP_PROXY_HOST.get(), 0x40, b"proxy.private.invalid"),
    );
    let mut avps = str_avps();
    avps.retain(|avp| u32::from_be_bytes(avp[0..4].try_into().expect("fixed AVP code")) != 284);
    avps.push(malformed_proxy);
    let wire = wire_message(0xc0, HOP_BY_HOP, END_TO_END, avps);
    assert!(
        swm::parse_swm_session_termination_request(&decode(&wire), DecodeContext::default())
            .is_err()
    );

    let mut avps = str_avps();
    avps.push(wire_avp(base::AVP_EXPERIMENTAL_RESULT.get(), 0x40, &[]));
    let wire = wire_message(0xc0, HOP_BY_HOP, END_TO_END, avps);
    assert!(
        swm::parse_swm_session_termination_request(&decode(&wire), DecodeContext::default())
            .is_err()
    );
}

#[test]
fn wrong_vendor_type_command_and_application_fail_closed() {
    let mut wrong_vendor = str_avps();
    wrong_vendor.retain(|avp| {
        u32::from_be_bytes(avp[0..4].try_into().expect("fixed AVP code"))
            != base::AVP_SESSION_ID.get()
    });
    wrong_vendor.insert(
        0,
        wire_vendor_avp(
            base::AVP_SESSION_ID.get(),
            0x40,
            10_415,
            SESSION_ID.as_bytes(),
        ),
    );
    let wire = wire_message(0xc0, HOP_BY_HOP, END_TO_END, wrong_vendor);
    let error =
        swm::parse_swm_session_termination_request(&decode(&wire), DecodeContext::default())
            .expect_err("vendor-specific Session-Id is not the required base AVP");
    assert_eq!(error.code(), &DecodeErrorCode::UnknownCriticalIe);

    let mut wrong_type = str_avps();
    wrong_type.retain(|avp| {
        u32::from_be_bytes(avp[0..4].try_into().expect("fixed AVP code"))
            != base::AVP_TERMINATION_CAUSE.get()
    });
    wrong_type.push(wire_avp(
        base::AVP_TERMINATION_CAUSE.get(),
        0x40,
        &[0, 0, 4],
    ));
    let wire = wire_message(0xc0, HOP_BY_HOP, END_TO_END, wrong_type);
    assert!(
        swm::parse_swm_session_termination_request(&decode(&wire), DecodeContext::default())
            .is_err()
    );

    let mut wrong_command = str_wire();
    wrong_command[5..8].copy_from_slice(&274_u32.to_be_bytes()[1..]);
    assert!(swm::parse_swm_session_termination_request(
        &decode(&wrong_command),
        DecodeContext::default()
    )
    .is_err());

    let mut wrong_application = str_wire();
    wrong_application[8..12].copy_from_slice(&1_u32.to_be_bytes());
    assert!(swm::parse_swm_session_termination_request(
        &decode(&wrong_application),
        DecodeContext::default()
    )
    .is_err());
}

#[test]
fn missing_required_str_avp_retains_5005_provenance() {
    for missing_code in [
        base::AVP_SESSION_ID.get(),
        base::AVP_ORIGIN_HOST.get(),
        base::AVP_ORIGIN_REALM.get(),
        base::AVP_DESTINATION_REALM.get(),
        base::AVP_AUTH_APPLICATION_ID.get(),
        base::AVP_TERMINATION_CAUSE.get(),
        base::AVP_USER_NAME.get(),
    ] {
        let avps = str_avps()
            .into_iter()
            .filter(|avp| {
                u32::from_be_bytes(avp[0..4].try_into().expect("fixed AVP code")) != missing_code
            })
            .filter(|avp| {
                u32::from_be_bytes(avp[0..4].try_into().expect("fixed AVP code"))
                    != UNKNOWN_OPTIONAL_AVP
            });
        let wire = wire_message(0xc0, HOP_BY_HOP, END_TO_END, avps);
        let parser_error = swm::parse_swm_session_termination_request_with_provenance(
            &decode(&wire),
            DecodeContext::conservative(),
        )
        .expect_err("required STR AVP omission must fail");
        assert_eq!(
            parser_error
                .missing_avp()
                .expect("omission provenance must be sealed")
                .key(),
            AvpKey::ietf(AvpCode::new(missing_code))
        );

        let DiameterRequestInspection::Request(envelope) =
            inspect_diameter_request(&wire, DecodeContext::conservative())
        else {
            panic!("well-framed STR must be answerable");
        };
        let bound = DiameterRequestFailure::from_parser_error(
            &envelope,
            &wire,
            &parser_error,
            DecodeContext::conservative(),
            apps::APP_DICTIONARIES,
            EncodeContext::default(),
        )
        .expect("sealed omission must map to a request-bound failure");
        assert_eq!(bound.result_code(), base::RESULT_CODE_DIAMETER_MISSING_AVP);
        assert!(matches!(
            bound.failure(),
            DiameterRequestFailure::MissingMandatoryAvp(_)
        ));
    }
}

#[test]
fn unknown_critical_and_decode_limits_fail_closed() {
    let mut avps = str_avps();
    avps.push(wire_avp(9_999, 0x40, b"private-critical-value"));
    let wire = wire_message(0xc0, HOP_BY_HOP, END_TO_END, avps);
    let error =
        swm::parse_swm_session_termination_request(&decode(&wire), DecodeContext::default())
            .expect_err("unknown M-bit AVP must fail");
    assert_eq!(error.code(), &DecodeErrorCode::UnknownCriticalIe);

    let wire = str_wire();
    let bounded = DecodeContext {
        max_ies: 4,
        ..DecodeContext::default()
    };
    let (_, message) = Message::decode(
        &wire,
        DecodeContext {
            duplicate_ie_policy: DuplicateIePolicy::First,
            ..DecodeContext::default()
        },
    )
    .expect("framing context must accept fixture");
    let error = swm::parse_swm_session_termination_request(&message, bounded)
        .expect_err("typed parser must honor max_ies");
    assert_eq!(error.code(), &DecodeErrorCode::IeCountExceeded);
}

#[test]
fn failover_and_inbound_str_retransmission_preserve_rfc6733_t_semantics() {
    let mut outbound = parsed_request_envelope(&str_wire());
    assert!(!outbound.is_potentially_retransmitted());
    let initial = swm::build_swm_session_termination_request(&outbound, EncodeContext::default())
        .expect("initial outbound STR must build");
    assert!(!initial.header.flags.is_potentially_retransmitted());

    outbound.mark_for_failover_retransmission(
        FAILOVER_HOP_BY_HOP,
        SwmExpectedAnswerPeer::routed(CONNECTION_B),
    );
    assert!(outbound.is_potentially_retransmitted());
    assert_eq!(
        outbound
            .expected_answer_peer()
            .map(SwmExpectedAnswerPeer::connection),
        Some(CONNECTION_B)
    );
    assert_eq!(
        outbound.transaction(),
        SwmDiameterTransaction::new(FAILOVER_HOP_BY_HOP, END_TO_END)
    );
    let retry = swm::build_swm_session_termination_request(&outbound, EncodeContext::default())
        .expect("queued STR resend after link failover must build");
    assert!(retry.header.flags.is_potentially_retransmitted());
    assert_eq!(retry.header.hop_by_hop_identifier, FAILOVER_HOP_BY_HOP);
    assert_eq!(retry.header.end_to_end_identifier, END_TO_END);
    assert_eq!(retry.raw_avps, initial.raw_avps);

    let answer_wire = sta_wire(SESSION_ID, base::RESULT_CODE_DIAMETER_SUCCESS, HOP_BY_HOP);
    let answer_message = decode(&answer_wire);
    let stale_answer = parsed_answer_envelope(&answer_message);
    assert_eq!(
        outbound
            .clone()
            .correlate_answer(stale_answer)
            .expect_err("failover must reject an answer from the old connection"),
        SwmSessionTerminationCorrelationError::PeerConnectionMismatch
    );
    let stale_identifier_on_replacement =
        swm::parse_swm_session_termination_answer_envelope_from_connection(
            &answer_message,
            CONNECTION_B,
            DecodeContext::default(),
        )
        .expect("the old-hop STA is independently valid on the replacement connection");
    assert_eq!(
        outbound
            .clone()
            .correlate_answer(stale_identifier_on_replacement)
            .expect_err("replacement connection still requires its reserved Hop-by-Hop ID"),
        SwmSessionTerminationCorrelationError::TransactionMismatch
    );
    let replacement_answer_wire = sta_wire(
        SESSION_ID,
        base::RESULT_CODE_DIAMETER_SUCCESS,
        FAILOVER_HOP_BY_HOP,
    );
    let replacement_answer_message = decode(&replacement_answer_wire);
    let replacement_answer = swm::parse_swm_session_termination_answer_envelope_from_connection(
        &replacement_answer_message,
        CONNECTION_B,
        DecodeContext::default(),
    )
    .expect("the replacement STA is independently valid");
    outbound
        .correlate_answer(replacement_answer)
        .expect("failover must accept the correlated answer on the replacement connection");

    let wire = wire_message(0xd0, HOP_BY_HOP, END_TO_END, str_avps());
    let request = parsed_request_envelope(&wire);
    assert!(request.is_potentially_retransmitted());
    let answer = SwmSessionTerminationAnswer::for_request(
        &request,
        SwmSessionTerminationResult::Success,
        "aaa.private.invalid",
        "private.invalid",
    );
    let built =
        swm::build_swm_session_termination_answer(&request, &answer, EncodeContext::default())
            .expect("retransmitted STR receives an ordinary correlated STA");
    assert!(!built.header.flags.is_potentially_retransmitted());
    assert!(built.header.flags.is_proxiable());
}

#[test]
fn generic_results_are_receive_only_and_unable_to_comply_is_fully_typed() {
    let request = parsed_request_envelope(&str_wire());
    let mut protocol_error_avps = sta_avps(SESSION_ID, 3_002);
    protocol_error_avps.retain(|avp| {
        u32::from_be_bytes(avp[0..4].try_into().expect("fixed AVP code"))
            != base::AVP_SESSION_ID.get()
    });
    let protocol_error_wire = wire_message(0x60, HOP_BY_HOP, END_TO_END, protocol_error_avps);
    let protocol_error_message = decode(&protocol_error_wire);
    let parsed = swm::parse_swm_session_termination_answer(
        &protocol_error_message,
        DecodeContext::default(),
    )
    .expect("generic protocol errors may omit Session-Id");
    assert_eq!(parsed.result, SwmSessionTerminationResult::Other(3_002));
    assert!(parsed.session_id.is_none());
    let parsed_envelope = parsed_answer_envelope(&protocol_error_message);
    request
        .clone()
        .correlate_answer(parsed_envelope)
        .expect("Session-Id-free protocol error correlates by request transaction and P");

    let experimental_result = [
        wire_avp(base::AVP_VENDOR_ID.get(), 0x40, &10_415_u32.to_be_bytes()),
        wire_avp(
            base::AVP_EXPERIMENTAL_RESULT_CODE.get(),
            0x40,
            &5_005_u32.to_be_bytes(),
        ),
    ]
    .concat();
    let failed_avp = wire_avp(
        base::AVP_TERMINATION_CAUSE.get(),
        0x40,
        &0_u32.to_be_bytes(),
    );
    for include_session_id in [true, false] {
        let mut fallback_avps = sta_avps(SESSION_ID, base::RESULT_CODE_DIAMETER_MISSING_AVP);
        if !include_session_id {
            fallback_avps.retain(|avp| {
                u32::from_be_bytes(avp[0..4].try_into().expect("fixed AVP code"))
                    != base::AVP_SESSION_ID.get()
            });
        }
        fallback_avps.push(wire_avp(base::AVP_FAILED_AVP.get(), 0x40, &failed_avp));
        fallback_avps.push(wire_avp(
            base::AVP_EXPERIMENTAL_RESULT.get(),
            0x40,
            &experimental_result,
        ));
        let fallback_wire = wire_message(0x60, HOP_BY_HOP, END_TO_END, fallback_avps);
        let fallback_message = decode(&fallback_wire);
        let fallback = parsed_answer_envelope(&fallback_message);
        assert_eq!(
            fallback.answer().result,
            SwmSessionTerminationResult::Other(base::RESULT_CODE_DIAMETER_MISSING_AVP)
        );
        assert_eq!(fallback.answer().session_id.is_some(), include_session_id);
        assert!(fallback
            .answer()
            .additional_avps
            .iter()
            .any(|avp| avp.code() == base::AVP_EXPERIMENTAL_RESULT));
        request
            .clone()
            .correlate_answer(fallback)
            .expect("generic permanent-failure fallback retains exact correlation context");
    }

    let ordinary_with_experimental = wire_message(
        0x40,
        HOP_BY_HOP,
        END_TO_END,
        [
            sta_avps(SESSION_ID, base::RESULT_CODE_DIAMETER_SUCCESS),
            vec![wire_avp(
                base::AVP_EXPERIMENTAL_RESULT.get(),
                0x40,
                &experimental_result,
            )],
        ]
        .concat(),
    );
    swm::parse_swm_session_termination_answer(
        &decode(&ordinary_with_experimental),
        DecodeContext::default(),
    )
    .expect_err("ordinary STA cannot combine Result-Code and Experimental-Result");

    let mut originated_with_experimental = SwmSessionTerminationAnswer::for_request(
        &request,
        SwmSessionTerminationResult::UnableToComply,
        "aaa.private.invalid",
        "private.invalid",
    );
    originated_with_experimental.additional_avps.push(
        SwmAdditionalAvp::new(
            AvpHeader::ietf(base::AVP_EXPERIMENTAL_RESULT, true),
            experimental_result.clone(),
            EncodeContext::default(),
        )
        .expect("valid Experimental-Result is structurally framed"),
    );
    swm::build_swm_session_termination_answer(
        &request,
        &originated_with_experimental,
        EncodeContext::default(),
    )
    .expect_err("typed ordinary STA builder cannot emit generic-error Experimental-Result");

    let malformed_experimental = wire_avp(
        base::AVP_EXPERIMENTAL_RESULT_CODE.get(),
        0x40,
        &5_005_u32.to_be_bytes(),
    );
    let malformed_fallback = wire_message(
        0x60,
        HOP_BY_HOP,
        END_TO_END,
        [
            sta_avps(SESSION_ID, base::RESULT_CODE_DIAMETER_MISSING_AVP),
            vec![wire_avp(
                base::AVP_EXPERIMENTAL_RESULT.get(),
                0x40,
                &malformed_experimental,
            )],
        ]
        .concat(),
    );
    swm::parse_swm_session_termination_answer(
        &decode(&malformed_fallback),
        DecodeContext::default(),
    )
    .expect_err("generic Experimental-Result retains grouped-child validation");

    for (flags, result_code) in [
        (0x40, 3_002),
        (0x60, base::RESULT_CODE_DIAMETER_SUCCESS),
        (0x60, 4_001),
    ] {
        let invalid_error_bit = wire_message(
            flags,
            HOP_BY_HOP,
            END_TO_END,
            sta_avps(SESSION_ID, result_code),
        );
        swm::parse_swm_session_termination_answer(
            &decode(&invalid_error_bit),
            DecodeContext::default(),
        )
        .expect_err("STA E bit must match result families with fixed RFC 6733 semantics");
    }

    let mut missing_success_session = sta_avps(SESSION_ID, base::RESULT_CODE_DIAMETER_SUCCESS);
    missing_success_session.retain(|avp| {
        u32::from_be_bytes(avp[0..4].try_into().expect("fixed AVP code"))
            != base::AVP_SESSION_ID.get()
    });
    let missing_success_session_wire =
        wire_message(0x40, HOP_BY_HOP, END_TO_END, missing_success_session);
    swm::parse_swm_session_termination_answer(
        &decode(&missing_success_session_wire),
        DecodeContext::default(),
    )
    .expect_err("ordinary application STA still requires Session-Id");

    let future_permanent_wire =
        wire_message(0x40, HOP_BY_HOP, END_TO_END, sta_avps(SESSION_ID, 6_001));
    let parsed = swm::parse_swm_session_termination_answer(
        &decode(&future_permanent_wire),
        DecodeContext::default(),
    )
    .expect("future result classes are treated as receive-side permanent failures");
    assert_eq!(parsed.result, SwmSessionTerminationResult::Other(6_001));

    let protocol_error = SwmSessionTerminationAnswer::for_request(
        &request,
        SwmSessionTerminationResult::Other(3_002),
        "aaa.private.invalid",
        "private.invalid",
    );
    assert!(swm::build_swm_session_termination_answer(
        &request,
        &protocol_error,
        EncodeContext::default(),
    )
    .is_err());

    let unable_to_comply = SwmSessionTerminationAnswer::for_request(
        &request,
        SwmSessionTerminationResult::UnableToComply,
        "aaa.private.invalid",
        "private.invalid",
    );
    let built = swm::build_swm_session_termination_answer(
        &request,
        &unable_to_comply,
        EncodeContext::default(),
    )
    .expect("DIAMETER_UNABLE_TO_COMPLY STA must build");
    assert!(!built.header.flags.is_error());
    let parsed = swm::parse_swm_session_termination_answer(
        &decode(&encode(&built)),
        DecodeContext::default(),
    )
    .expect("DIAMETER_UNABLE_TO_COMPLY STA must parse");
    assert_eq!(parsed.result, SwmSessionTerminationResult::UnableToComply);

    for result in [
        SwmSessionTerminationResult::Other(3_006),
        SwmSessionTerminationResult::Other(5_004),
    ] {
        let answer = SwmSessionTerminationAnswer::for_request(
            &request,
            result,
            "aaa.private.invalid",
            "private.invalid",
        );
        assert!(swm::build_swm_session_termination_answer(
            &request,
            &answer,
            EncodeContext::default()
        )
        .is_err());
    }

    let redirect_wire = wire_message(0x60, HOP_BY_HOP, END_TO_END, sta_avps(SESSION_ID, 3_006));
    assert!(swm::parse_swm_session_termination_answer(
        &decode(&redirect_wire),
        DecodeContext::default()
    )
    .is_err());
}

#[test]
fn known_additional_values_are_dictionary_validated_on_decode_and_encode() {
    let request = parsed_request_envelope(&str_wire());
    for (code, value) in [
        (base::AVP_ORIGIN_STATE_ID, vec![0, 0, 1]),
        (base::AVP_USER_NAME, vec![0xff]),
    ] {
        let mut avps = sta_avps(SESSION_ID, base::RESULT_CODE_DIAMETER_SUCCESS);
        avps.push(wire_avp(code.get(), 0x40, &value));
        let wire = wire_message(0x40, HOP_BY_HOP, END_TO_END, avps);
        assert!(swm::parse_swm_session_termination_answer(
            &decode(&wire),
            DecodeContext::default()
        )
        .is_err());

        let mut answer = SwmSessionTerminationAnswer::for_request(
            &request,
            SwmSessionTerminationResult::Success,
            "aaa.private.invalid",
            "private.invalid",
        );
        answer.additional_avps.push(
            SwmAdditionalAvp::new(AvpHeader::ietf(code, true), value, EncodeContext::default())
                .expect("raw additional AVP framing is valid"),
        );
        assert!(swm::build_swm_session_termination_answer(
            &request,
            &answer,
            EncodeContext::default()
        )
        .is_err());
    }

    let mut avps = str_avps();
    avps.push(wire_avp(base::AVP_CLASS.get(), 0x40, &[]));
    let wire = wire_message(0xc0, HOP_BY_HOP, END_TO_END, avps);
    let parsed = parsed_request_envelope(&wire);
    assert!(parsed
        .request()
        .additional_avps
        .iter()
        .any(|avp| avp.code() == base::AVP_CLASS && avp.value_len() == 0));
    swm::build_swm_session_termination_request(&parsed, EncodeContext::default())
        .expect("empty OctetString Class AVP remains valid on encode");

    let mut avps = str_avps();
    avps.push(wire_avp(
        swm::AVP_OC_FEATURE_VECTOR.get(),
        0x00,
        &1_u64.to_be_bytes(),
    ));
    let wire = wire_message(0xc0, HOP_BY_HOP, END_TO_END, avps);
    assert!(
        swm::parse_swm_session_termination_request(&decode(&wire), DecodeContext::default())
            .is_err()
    );

    let mut answer = SwmSessionTerminationAnswer::for_request(
        &request,
        SwmSessionTerminationResult::Success,
        "aaa.private.invalid",
        "private.invalid",
    );
    answer.additional_avps.push(
        SwmAdditionalAvp::new(
            AvpHeader::ietf(swm::AVP_OC_FEATURE_VECTOR, false),
            1_u64.to_be_bytes().to_vec(),
            EncodeContext::default(),
        )
        .expect("top-level grouped-child framing"),
    );
    assert!(
        swm::build_swm_session_termination_answer(&request, &answer, EncodeContext::default())
            .is_err()
    );
}

#[test]
fn core_diameter_identity_fields_reject_non_ascii_on_decode_and_encode() {
    let mut invalid_origin = str_avps();
    invalid_origin.retain(|avp| {
        u32::from_be_bytes(avp[0..4].try_into().expect("fixed AVP code"))
            != base::AVP_ORIGIN_HOST.get()
    });
    invalid_origin.push(wire_avp(
        base::AVP_ORIGIN_HOST.get(),
        0x40,
        "epdg-\u{00e9}.private.invalid".as_bytes(),
    ));
    let invalid_origin_wire = wire_message(0xc0, HOP_BY_HOP, END_TO_END, invalid_origin);
    swm::parse_swm_session_termination_request(
        &decode(&invalid_origin_wire),
        DecodeContext::default(),
    )
    .expect_err("DiameterIdentity wire values must be ASCII");

    let parsed = parsed_request_envelope(&str_wire());
    let mut invalid_request = parsed.request().clone();
    invalid_request.origin_host = "epdg-\u{00e9}.private.invalid".into();
    let invalid_request = SwmSessionTerminationRequestEnvelope::for_outbound(
        invalid_request,
        parsed.transaction(),
        SwmExpectedAnswerPeer::routed(CONNECTION_A),
    );
    swm::build_swm_session_termination_request(&invalid_request, EncodeContext::default())
        .expect_err("typed outbound DiameterIdentity values must be ASCII");

    let mut invalid_answer = SwmSessionTerminationAnswer::for_request(
        &parsed,
        SwmSessionTerminationResult::Success,
        "aaa-\u{00e9}.private.invalid",
        "private.invalid",
    );
    invalid_answer.origin_realm = "realm-\u{00e9}.invalid".into();
    swm::build_swm_session_termination_answer(&parsed, &invalid_answer, EncodeContext::default())
        .expect_err("typed answer DiameterIdentity values must be ASCII");
}

#[test]
fn overload_groups_validate_flags_structure_and_loss_semantics() {
    let invalid_supported = vec![
        wire_avp(
            swm::AVP_OC_SUPPORTED_FEATURES.get(),
            0x00,
            &oc_supported_value(Some(0), 0x00),
        ),
        wire_avp(
            swm::AVP_OC_SUPPORTED_FEATURES.get(),
            0x00,
            &wire_avp(swm::AVP_OC_FEATURE_VECTOR.get(), 0x00, &[0; 7]),
        ),
        wire_avp(
            swm::AVP_OC_SUPPORTED_FEATURES.get(),
            0x00,
            &[
                oc_supported_value(Some(1), 0x00),
                oc_supported_value(Some(1), 0x00),
            ]
            .concat(),
        ),
        wire_avp(
            swm::AVP_OC_SUPPORTED_FEATURES.get(),
            0x00,
            &oc_supported_value(Some(2), 0x00),
        ),
        wire_avp(
            swm::AVP_OC_SUPPORTED_FEATURES.get(),
            0x00,
            &wire_avp(9_999, 0x40, &[]),
        ),
        wire_avp(swm::AVP_OC_SUPPORTED_FEATURES.get(), 0x20, &[]),
        wire_avp(
            swm::AVP_OC_SUPPORTED_FEATURES.get(),
            0x00,
            &oc_supported_value(Some(1), 0x20),
        ),
    ];
    for invalid in invalid_supported {
        let mut avps = str_avps();
        avps.push(invalid);
        let wire = wire_message(0xc0, HOP_BY_HOP, END_TO_END, avps);
        assert!(swm::parse_swm_session_termination_request(
            &decode(&wire),
            DecodeContext::default()
        )
        .is_err());
    }

    let mut offered_avps = str_avps();
    offered_avps.push(wire_avp(
        swm::AVP_OC_SUPPORTED_FEATURES.get(),
        0x40,
        &oc_supported_value(Some(3), 0x40),
    ));
    let offered_wire = wire_message(0xc0, HOP_BY_HOP, END_TO_END, offered_avps);
    let offered = parsed_request_envelope(&offered_wire);
    swm::build_swm_session_termination_request(&offered, EncodeContext::default())
        .expect_err("originated offer cannot advertise an unsupported overload algorithm");

    let invalid_olrs = vec![
        wire_avp(swm::AVP_OC_REPORT_TYPE.get(), 0x00, &0_u32.to_be_bytes()),
        wire_avp(
            swm::AVP_OC_SEQUENCE_NUMBER.get(),
            0x00,
            &1_u64.to_be_bytes(),
        ),
        [
            wire_avp(
                swm::AVP_OC_SEQUENCE_NUMBER.get(),
                0x00,
                &1_u64.to_be_bytes(),
            ),
            wire_avp(
                swm::AVP_OC_SEQUENCE_NUMBER.get(),
                0x00,
                &2_u64.to_be_bytes(),
            ),
            wire_avp(swm::AVP_OC_REPORT_TYPE.get(), 0x00, &0_u32.to_be_bytes()),
        ]
        .concat(),
        [
            wire_avp(swm::AVP_OC_SEQUENCE_NUMBER.get(), 0x00, &[0; 7]),
            wire_avp(swm::AVP_OC_REPORT_TYPE.get(), 0x00, &0_u32.to_be_bytes()),
        ]
        .concat(),
        [
            wire_avp(
                swm::AVP_OC_SEQUENCE_NUMBER.get(),
                0x00,
                &1_u64.to_be_bytes(),
            ),
            wire_avp(swm::AVP_OC_REPORT_TYPE.get(), 0x00, &2_u32.to_be_bytes()),
        ]
        .concat(),
        [oc_olr_value(), wire_avp(9_999, 0x40, &[])].concat(),
    ];
    for invalid in invalid_olrs {
        let mut avps = sta_avps(SESSION_ID, base::RESULT_CODE_DIAMETER_SUCCESS);
        avps.push(wire_avp(swm::AVP_OC_SUPPORTED_FEATURES.get(), 0x00, &[]));
        avps.push(wire_avp(swm::AVP_OC_OLR.get(), 0x00, &invalid));
        let wire = wire_message(0x40, HOP_BY_HOP, END_TO_END, avps);
        assert!(swm::parse_swm_session_termination_answer(
            &decode(&wire),
            DecodeContext::default()
        )
        .is_err());
    }

    let received_olr = [
        oc_olr_value(),
        wire_avp(
            swm::AVP_OC_VALIDITY_DURATION.get(),
            0x00,
            &86_401_u32.to_be_bytes(),
        ),
        wire_avp(
            swm::AVP_OC_REDUCTION_PERCENTAGE.get(),
            0x00,
            &101_u32.to_be_bytes(),
        ),
    ]
    .concat();
    let mut avps = sta_avps(SESSION_ID, base::RESULT_CODE_DIAMETER_SUCCESS);
    avps.push(wire_avp(
        swm::AVP_OC_SUPPORTED_FEATURES.get(),
        0x40,
        &oc_supported_value(Some(1), 0x40),
    ));
    avps.push(wire_avp(swm::AVP_OC_OLR.get(), 0x40, &received_olr));
    let wire = wire_message(0x40, HOP_BY_HOP, END_TO_END, avps);
    swm::parse_swm_session_termination_answer(&decode(&wire), DecodeContext::default())
        .expect("RFC defaults handle out-of-range validity and reduction values");

    let supported = SwmAdditionalAvp::new(
        AvpHeader::ietf(swm::AVP_OC_SUPPORTED_FEATURES, true),
        oc_supported_value(Some(1), 0x40),
        EncodeContext::default(),
    )
    .expect("supported-feature framing");
    for invalid_originated_olr in [
        [
            loss_oc_olr_value(),
            wire_avp(
                swm::AVP_OC_VALIDITY_DURATION.get(),
                0x00,
                &86_401_u32.to_be_bytes(),
            ),
        ]
        .concat(),
        [
            oc_olr_value(),
            wire_avp(
                swm::AVP_OC_REDUCTION_PERCENTAGE.get(),
                0x00,
                &101_u32.to_be_bytes(),
            ),
        ]
        .concat(),
    ] {
        let mut invalid_answer = SwmSessionTerminationAnswer::for_request(
            &offered,
            SwmSessionTerminationResult::Success,
            "aaa.private.invalid",
            "private.invalid",
        );
        invalid_answer.additional_avps = vec![
            supported.clone(),
            SwmAdditionalAvp::new(
                AvpHeader::ietf(swm::AVP_OC_OLR, false),
                invalid_originated_olr,
                EncodeContext::default(),
            )
            .expect("out-of-range OC-OLR is structurally framed"),
        ];
        swm::build_swm_session_termination_answer(
            &offered,
            &invalid_answer,
            EncodeContext::default(),
        )
        .expect_err("originated OC-OLR values must remain in RFC 7683 ranges");
    }
    let incomplete_olr = SwmAdditionalAvp::new(
        AvpHeader::ietf(swm::AVP_OC_OLR, false),
        oc_olr_value(),
        EncodeContext::default(),
    )
    .expect("received OC-OLR framing");
    let mut answer = SwmSessionTerminationAnswer::for_request(
        &offered,
        SwmSessionTerminationResult::Success,
        "aaa.private.invalid",
        "private.invalid",
    );
    answer.additional_avps = vec![supported.clone(), incomplete_olr];
    assert!(
        swm::build_swm_session_termination_answer(&offered, &answer, EncodeContext::default())
            .is_err()
    );

    answer.additional_avps = vec![
        supported,
        SwmAdditionalAvp::new(
            AvpHeader::ietf(swm::AVP_OC_OLR, false),
            loss_oc_olr_value(),
            EncodeContext::default(),
        )
        .expect("complete loss OC-OLR framing"),
    ];
    let built =
        swm::build_swm_session_termination_answer(&offered, &answer, EncodeContext::default())
            .expect("offered loss overload report must build");
    let parsed = parsed_answer_envelope(&decode(&encode(&built)));
    offered
        .correlate_answer(parsed)
        .expect("loss selection and report must correlate to the offer");

    let mut answer_vector_avps = sta_avps(SESSION_ID, base::RESULT_CODE_DIAMETER_SUCCESS);
    answer_vector_avps.push(wire_avp(
        swm::AVP_OC_SUPPORTED_FEATURES.get(),
        0x00,
        &oc_supported_value(Some(3), 0x00),
    ));
    let wire = wire_message(0x40, HOP_BY_HOP, END_TO_END, answer_vector_avps);
    assert!(
        swm::parse_swm_session_termination_answer(&decode(&wire), DecodeContext::default())
            .is_err()
    );
}

#[test]
fn overload_and_load_unknown_children_are_vendor_aware_and_honor_drop() {
    let supported_value = [
        oc_supported_value(Some(1), 0x00),
        wire_vendor_avp(
            swm::AVP_OC_FEATURE_VECTOR.get(),
            0x00,
            10_415,
            b"vendor-private",
        ),
        wire_avp(9_998, 0x00, b"optional-private"),
    ]
    .concat();
    let mut avps = str_avps();
    avps.push(wire_vendor_avp(
        swm::AVP_OC_FEATURE_VECTOR.get(),
        0x00,
        10_415,
        b"top-level-private",
    ));
    avps.push(wire_vendor_avp(
        swm::AVP_OC_SUPPORTED_FEATURES.get(),
        0x00,
        10_415,
        b"outer-private",
    ));
    avps.push(wire_avp(
        swm::AVP_OC_SUPPORTED_FEATURES.get(),
        0x00,
        &supported_value,
    ));
    let wire = wire_message(0xc0, HOP_BY_HOP, END_TO_END, avps);

    let preserved = parsed_request_envelope(&wire);
    let rebuilt = swm::build_swm_session_termination_request(&preserved, EncodeContext::default())
        .expect("M-clear vendor collisions and optional grouped children must preserve");
    assert_eq!(encode(&rebuilt), wire);

    for code in [swm::AVP_OC_FEATURE_VECTOR, swm::AVP_OC_SUPPORTED_FEATURES] {
        let mut critical_avps = str_avps();
        critical_avps.push(wire_vendor_avp(
            code.get(),
            0x40,
            10_415,
            b"critical-private",
        ));
        let critical_wire = wire_message(0xc0, HOP_BY_HOP, END_TO_END, critical_avps);
        let error = swm::parse_swm_session_termination_request(
            &decode(&critical_wire),
            DecodeContext::default(),
        )
        .expect_err("top-level M-set vendor collision is an unknown critical AVP");
        assert_eq!(error.code(), &DecodeErrorCode::UnknownCriticalIe);
    }

    let drop_ctx = DecodeContext {
        unknown_ie_policy: UnknownIePolicy::Drop,
        ..DecodeContext::default()
    };
    let dropped = swm::parse_swm_session_termination_request_envelope(&decode(&wire), drop_ctx)
        .expect("Drop must retain the known overload offer")
        .with_expected_answer_peer(SwmExpectedAnswerPeer::routed(CONNECTION_A));
    let rebuilt = swm::build_swm_session_termination_request(&dropped, EncodeContext::default())
        .expect("sanitized overload offer must build");
    let rebuilt_wire = encode(&rebuilt);
    let rebuilt_message = decode(&rebuilt_wire);
    let supported = rebuilt_message
        .avps(DecodeContext::default())
        .map(|avp| avp.expect("rebuilt AVP framing"))
        .find(|avp| avp.header.key() == AvpKey::ietf(swm::AVP_OC_SUPPORTED_FEATURES))
        .expect("known overload offer remains");
    let children: Vec<_> = supported
        .grouped_avps(DecodeContext::default())
        .map(|child| child.expect("sanitized child framing").header.key())
        .collect();
    assert_eq!(children, vec![AvpKey::ietf(swm::AVP_OC_FEATURE_VECTOR)]);
    assert!(!rebuilt_message
        .avps(DecodeContext::default())
        .map(|avp| avp.expect("rebuilt AVP framing").header.key())
        .any(|key| key.vendor_id().is_some()));

    let mut reject_avps = str_avps();
    reject_avps.retain(|avp| {
        u32::from_be_bytes(avp[0..4].try_into().expect("fixed AVP code")) != UNKNOWN_OPTIONAL_AVP
    });
    reject_avps.push(wire_avp(
        swm::AVP_OC_SUPPORTED_FEATURES.get(),
        0x00,
        &supported_value,
    ));
    let reject_wire = wire_message(0xc0, HOP_BY_HOP, END_TO_END, reject_avps);
    assert!(swm::parse_swm_session_termination_request(
        &decode(&reject_wire),
        DecodeContext {
            unknown_ie_policy: UnknownIePolicy::Reject,
            ..DecodeContext::default()
        }
    )
    .is_err());

    for critical in [
        wire_vendor_avp(
            swm::AVP_OC_FEATURE_VECTOR.get(),
            0x40,
            10_415,
            b"critical-private",
        ),
        wire_avp(9_998, 0x40, b"critical-private"),
    ] {
        let mut request_avps = str_avps();
        request_avps.push(wire_avp(
            swm::AVP_OC_SUPPORTED_FEATURES.get(),
            0x00,
            &[oc_supported_value(Some(1), 0x00), critical].concat(),
        ));
        let request_wire = wire_message(0xc0, HOP_BY_HOP, END_TO_END, request_avps);
        let error = swm::parse_swm_session_termination_request(
            &decode(&request_wire),
            DecodeContext::default(),
        )
        .expect_err("unknown M-set grouped child must fail");
        assert_eq!(error.code(), &DecodeErrorCode::UnknownCriticalIe);
    }

    let vendor_olr_child = wire_vendor_avp(
        swm::AVP_OC_SEQUENCE_NUMBER.get(),
        0x00,
        10_415,
        b"vendor-private",
    );
    let vendor_load_child =
        wire_vendor_avp(swm::AVP_SOURCE_ID.get(), 0x00, 10_415, b"vendor-private");
    let mut answer_avps = sta_avps(SESSION_ID, base::RESULT_CODE_DIAMETER_SUCCESS);
    answer_avps.push(wire_avp(swm::AVP_OC_SUPPORTED_FEATURES.get(), 0x40, &[]));
    answer_avps.push(wire_avp(
        swm::AVP_OC_OLR.get(),
        0x40,
        &[loss_oc_olr_value(), vendor_olr_child].concat(),
    ));
    answer_avps.push(wire_avp(
        swm::AVP_LOAD.get(),
        0x00,
        &[load_value(0, 1, b"node.invalid"), vendor_load_child].concat(),
    ));
    let answer_wire = wire_message(0x40, HOP_BY_HOP, END_TO_END, answer_avps);
    swm::parse_swm_session_termination_answer(&decode(&answer_wire), DecodeContext::default())
        .expect("M-clear vendor collisions inside OC-OLR and Load are unknown optional AVPs");

    let dropped_answer = swm::parse_swm_session_termination_answer(
        &decode(&answer_wire),
        DecodeContext {
            unknown_ie_policy: UnknownIePolicy::Drop,
            ..DecodeContext::default()
        },
    )
    .expect("Drop must sanitize unknown OC-OLR and Load children");
    let mut offered_avps = str_avps();
    offered_avps.push(wire_avp(swm::AVP_OC_SUPPORTED_FEATURES.get(), 0x00, &[]));
    let offered_wire = wire_message(0xc0, HOP_BY_HOP, END_TO_END, offered_avps);
    let offered = parsed_request_envelope(&offered_wire);
    let sanitized = swm::build_swm_session_termination_answer(
        &offered,
        &dropped_answer,
        EncodeContext::default(),
    )
    .expect("sanitized overload and load report must build");
    let sanitized_wire = encode(&sanitized);
    let sanitized_message = decode(&sanitized_wire);
    for outer in sanitized_message
        .avps(DecodeContext::default())
        .map(|avp| avp.expect("sanitized answer AVP framing"))
        .filter(|avp| {
            matches!(
                avp.header.code,
                swm::AVP_OC_SUPPORTED_FEATURES | swm::AVP_OC_OLR | swm::AVP_LOAD
            )
        })
    {
        assert!(outer
            .grouped_avps(DecodeContext::default())
            .map(|child| child.expect("sanitized grouped child framing"))
            .all(|child| child.header.vendor_id.is_none()
                && child.header.code != AvpCode::new(9_998)));
    }

    let m_olr = [
        wire_avp(
            swm::AVP_OC_SEQUENCE_NUMBER.get(),
            0x40,
            &1_u64.to_be_bytes(),
        ),
        wire_avp(swm::AVP_OC_REPORT_TYPE.get(), 0x40, &0_u32.to_be_bytes()),
        wire_avp(
            swm::AVP_OC_REDUCTION_PERCENTAGE.get(),
            0x40,
            &25_u32.to_be_bytes(),
        ),
    ]
    .concat();
    let m_load = [
        wire_avp(swm::AVP_LOAD_TYPE.get(), 0x40, &0_u32.to_be_bytes()),
        wire_avp(swm::AVP_LOAD_VALUE.get(), 0x40, &1_u64.to_be_bytes()),
        wire_avp(swm::AVP_SOURCE_ID.get(), 0x40, b"node.invalid"),
    ]
    .concat();
    let mut answer_avps = sta_avps(SESSION_ID, base::RESULT_CODE_DIAMETER_SUCCESS);
    answer_avps.push(wire_avp(swm::AVP_OC_SUPPORTED_FEATURES.get(), 0x40, &[]));
    answer_avps.push(wire_avp(swm::AVP_OC_OLR.get(), 0x40, &m_olr));
    answer_avps.push(wire_avp(swm::AVP_LOAD.get(), 0x00, &m_load));
    let answer_wire = wire_message(0x40, HOP_BY_HOP, END_TO_END, answer_avps);
    swm::parse_swm_session_termination_answer(&decode(&answer_wire), DecodeContext::default())
        .expect("known OC/Load child M bits follow their defining RFCs");

    let mut m_set_load = sta_avps(SESSION_ID, base::RESULT_CODE_DIAMETER_SUCCESS);
    m_set_load.push(wire_avp(swm::AVP_LOAD.get(), 0x40, &m_load));
    let m_set_load_wire = wire_message(0x40, HOP_BY_HOP, END_TO_END, m_set_load);
    swm::parse_swm_session_termination_answer(&decode(&m_set_load_wire), DecodeContext::default())
        .expect("TS 29.273 requires a receiver that understands Load to ignore its M-bit");

    let request = parsed_request_envelope(&str_wire());
    let mut invalid_originated_load = SwmSessionTerminationAnswer::for_request(
        &request,
        SwmSessionTerminationResult::Success,
        "aaa.private.invalid",
        "private.invalid",
    );
    invalid_originated_load.additional_avps.push(
        SwmAdditionalAvp::new(
            AvpHeader::ietf(swm::AVP_LOAD, true),
            m_load,
            EncodeContext::default(),
        )
        .expect("M-set Load framing remains structurally valid"),
    );
    assert!(swm::build_swm_session_termination_answer(
        &request,
        &invalid_originated_load,
        EncodeContext::default(),
    )
    .is_err());

    for (outer, value) in [
        (
            swm::AVP_OC_OLR,
            [
                loss_oc_olr_value(),
                wire_vendor_avp(
                    swm::AVP_OC_SEQUENCE_NUMBER.get(),
                    0x40,
                    10_415,
                    b"critical-private",
                ),
            ]
            .concat(),
        ),
        (
            swm::AVP_LOAD,
            [
                load_value(0, 1, b"node.invalid"),
                wire_vendor_avp(swm::AVP_SOURCE_ID.get(), 0x40, 10_415, b"critical-private"),
            ]
            .concat(),
        ),
    ] {
        let mut answer_avps = sta_avps(SESSION_ID, base::RESULT_CODE_DIAMETER_SUCCESS);
        answer_avps.push(wire_avp(swm::AVP_OC_SUPPORTED_FEATURES.get(), 0x00, &[]));
        answer_avps.push(wire_avp(outer.get(), 0x00, &value));
        let answer_wire = wire_message(0x40, HOP_BY_HOP, END_TO_END, answer_avps);
        let error = swm::parse_swm_session_termination_answer(
            &decode(&answer_wire),
            DecodeContext::default(),
        )
        .expect_err("M-set vendor collision remains an unknown critical child");
        assert_eq!(error.code(), &DecodeErrorCode::UnknownCriticalIe);
    }
}

#[test]
fn load_groups_validate_received_reports_and_originated_completeness() {
    let invalid_loads = vec![
        load_value(2, 1, b"node.invalid"),
        [
            wire_avp(swm::AVP_LOAD_TYPE.get(), 0x00, &[0; 3]),
            wire_avp(swm::AVP_LOAD_VALUE.get(), 0x00, &1_u64.to_be_bytes()),
            wire_avp(swm::AVP_SOURCE_ID.get(), 0x00, b"node.invalid"),
        ]
        .concat(),
        load_value(0, 65_536, b"node.invalid"),
        [
            wire_avp(swm::AVP_LOAD_TYPE.get(), 0x00, &0_u32.to_be_bytes()),
            wire_avp(swm::AVP_LOAD_VALUE.get(), 0x00, &[0; 7]),
            wire_avp(swm::AVP_SOURCE_ID.get(), 0x00, b"node.invalid"),
        ]
        .concat(),
        load_value(0, 1, b""),
        load_value(0, 1, &[0xff]),
        [
            load_value(0, 1, b"node.invalid"),
            wire_avp(swm::AVP_LOAD_TYPE.get(), 0x00, &0_u32.to_be_bytes()),
        ]
        .concat(),
        [
            load_value(0, 1, b"node.invalid"),
            wire_avp(9_999, 0x40, &[]),
        ]
        .concat(),
        [
            wire_avp(swm::AVP_LOAD_TYPE.get(), 0x20, &0_u32.to_be_bytes()),
            wire_avp(swm::AVP_LOAD_VALUE.get(), 0x00, &1_u64.to_be_bytes()),
            wire_avp(swm::AVP_SOURCE_ID.get(), 0x00, b"node.invalid"),
        ]
        .concat(),
    ];
    for invalid in invalid_loads {
        let mut avps = sta_avps(SESSION_ID, base::RESULT_CODE_DIAMETER_SUCCESS);
        avps.push(wire_avp(swm::AVP_LOAD.get(), 0x00, &invalid));
        let wire = wire_message(0x40, HOP_BY_HOP, END_TO_END, avps);
        assert!(swm::parse_swm_session_termination_answer(
            &decode(&wire),
            DecodeContext::default()
        )
        .is_err());
    }

    let invalid_outer = wire_avp(
        swm::AVP_LOAD.get(),
        0x20,
        &load_value(0, 1, b"node.invalid"),
    );
    let mut avps = sta_avps(SESSION_ID, base::RESULT_CODE_DIAMETER_SUCCESS);
    avps.push(invalid_outer);
    let wire = wire_message(0x40, HOP_BY_HOP, END_TO_END, avps);
    assert!(
        swm::parse_swm_session_termination_answer(&decode(&wire), DecodeContext::default())
            .is_err()
    );

    let mut incomplete_avps = sta_avps(SESSION_ID, base::RESULT_CODE_DIAMETER_SUCCESS);
    let incomplete_value = wire_avp(swm::AVP_LOAD_TYPE.get(), 0x00, &0_u32.to_be_bytes());
    incomplete_avps.push(wire_avp(swm::AVP_LOAD.get(), 0x00, &incomplete_value));
    let incomplete_wire = wire_message(0x40, HOP_BY_HOP, END_TO_END, incomplete_avps);
    swm::parse_swm_session_termination_answer(&decode(&incomplete_wire), DecodeContext::default())
        .expect("received Load children are individually optional");

    let request = parsed_request_envelope(&str_wire());
    let mut answer = SwmSessionTerminationAnswer::for_request(
        &request,
        SwmSessionTerminationResult::Success,
        "aaa.private.invalid",
        "private.invalid",
    );
    answer.additional_avps.push(
        SwmAdditionalAvp::new(
            AvpHeader::ietf(swm::AVP_LOAD, false),
            incomplete_value,
            EncodeContext::default(),
        )
        .expect("incomplete received Load framing"),
    );
    assert!(
        swm::build_swm_session_termination_answer(&request, &answer, EncodeContext::default())
            .is_err()
    );

    answer.additional_avps.clear();
    answer.additional_avps.push(
        SwmAdditionalAvp::new(
            AvpHeader::ietf(swm::AVP_LOAD, false),
            load_value(1, 65_535, b"node.invalid"),
            EncodeContext::default(),
        )
        .expect("complete Load framing"),
    );
    let built =
        swm::build_swm_session_termination_answer(&request, &answer, EncodeContext::default())
            .expect("complete originated Load must build");
    swm::parse_swm_session_termination_answer(&decode(&encode(&built)), DecodeContext::default())
        .expect("complete originated Load must parse");
}

#[test]
fn typed_collection_bounds_reject_the_129th_entry() {
    let ctx = DecodeContext {
        max_ies: 512,
        ..DecodeContext::default()
    };
    let parse = |avps| {
        let wire = wire_message(0xc0, HOP_BY_HOP, END_TO_END, avps);
        let (tail, message) = Message::decode(&wire, ctx).expect("large fixture must frame");
        assert!(tail.is_empty());
        let error = swm::parse_swm_session_termination_request(&message, ctx)
            .expect_err("the 129th typed collection entry must fail");
        assert_eq!(error.code(), &DecodeErrorCode::IeCountExceeded);
    };

    let mut proxies = str_avps();
    proxies
        .extend((0..127).map(|_| proxy_info(b"proxy.private.invalid", b"bounded-private-state")));
    parse(proxies);

    let mut routes = str_avps();
    routes.extend(
        (0..127).map(|_| wire_avp(base::AVP_ROUTE_RECORD.get(), 0x40, b"route.private.invalid")),
    );
    parse(routes);

    let mut additional = str_avps();
    additional.extend((20_000..20_128).map(|code| wire_avp(code, 0x00, &[])));
    parse(additional);

    let mut loads = sta_avps(SESSION_ID, base::RESULT_CODE_DIAMETER_SUCCESS);
    loads.extend((0..128).map(|_| {
        wire_avp(
            swm::AVP_LOAD.get(),
            0x00,
            &wire_avp(swm::AVP_LOAD_TYPE.get(), 0x00, &0_u32.to_be_bytes()),
        )
    }));
    let wire = wire_message(0x40, HOP_BY_HOP, END_TO_END, loads);
    let (tail, message) = Message::decode(&wire, ctx).expect("large STA fixture must frame");
    assert!(tail.is_empty());
    let error = swm::parse_swm_session_termination_answer(&message, ctx)
        .expect_err("the 129th answer additional AVP must fail");
    assert_eq!(error.code(), &DecodeErrorCode::IeCountExceeded);
}

#[test]
fn typed_diagnostics_redact_session_subscriber_topology_and_extensions() {
    let wire = str_wire();
    let request = parsed_request_envelope(&wire);
    let mut answer = SwmSessionTerminationAnswer::for_request(
        &request,
        SwmSessionTerminationResult::Success,
        "aaa.private.invalid",
        "private.invalid",
    );
    answer.additional_avps.push(
        SwmAdditionalAvp::new(
            AvpHeader::ietf(AvpCode::new(9_777), false),
            b"sensitive-answer-value".to_vec(),
            EncodeContext::default(),
        )
        .expect("valid optional extension"),
    );

    let diagnostic = format!("{request:?} {answer:?} {}", answer.additional_avps[0]);
    for sensitive in [
        SESSION_ID,
        USER_NAME,
        "epdg.private.invalid",
        "aaa.private.invalid",
        "private-proxy-state-one",
        "sensitive-answer-value",
    ] {
        assert!(!diagnostic.contains(sensitive), "leaked {sensitive}");
    }
    assert!(diagnostic.contains("REDACTED") || diagnostic.contains("<redacted>"));
}

#[test]
fn answer_builder_rejects_session_mismatch_and_duplicate_extension() {
    let request = parsed_request_envelope(&str_wire());
    let mut answer = SwmSessionTerminationAnswer::for_request(
        &request,
        SwmSessionTerminationResult::Success,
        "aaa.private.invalid",
        "private.invalid",
    );
    answer.session_id = Some(Redacted::from("session;private;wrong"));
    assert!(
        swm::build_swm_session_termination_answer(&request, &answer, EncodeContext::default())
            .is_err()
    );

    answer.session_id = None;
    assert!(
        swm::build_swm_session_termination_answer(&request, &answer, EncodeContext::default())
            .is_err()
    );

    answer.session_id = Some(Redacted::from(SESSION_ID));
    let extension = SwmAdditionalAvp::new(
        AvpHeader::ietf(AvpCode::new(9_778), false),
        b"opaque".to_vec(),
        EncodeContext::default(),
    )
    .expect("valid optional extension");
    answer.additional_avps = vec![extension.clone(), extension];
    assert!(
        swm::build_swm_session_termination_answer(&request, &answer, EncodeContext::default())
            .is_err()
    );
}

#[test]
fn overload_control_answer_requires_an_offer_but_not_a_reporting_node() {
    let request = parsed_request_envelope(&str_wire());
    let supported = SwmAdditionalAvp::new(
        AvpHeader::ietf(swm::AVP_OC_SUPPORTED_FEATURES, false),
        Vec::new(),
        EncodeContext::default(),
    )
    .expect("empty feature vector selects RFC 7683's default algorithm");
    let mut unsolicited = SwmSessionTerminationAnswer::for_request(
        &request,
        SwmSessionTerminationResult::Success,
        "aaa.private.invalid",
        "private.invalid",
    );
    unsolicited.additional_avps.push(supported.clone());
    assert!(swm::build_swm_session_termination_answer(
        &request,
        &unsolicited,
        EncodeContext::default()
    )
    .is_err());

    let mut unsolicited_avps = sta_avps(SESSION_ID, base::RESULT_CODE_DIAMETER_SUCCESS);
    unsolicited_avps.push(wire_avp(swm::AVP_OC_SUPPORTED_FEATURES.get(), 0x00, &[]));
    let unsolicited_wire = wire_message(0x40, HOP_BY_HOP, END_TO_END, unsolicited_avps);
    let unsolicited_envelope = parsed_answer_envelope(&decode(&unsolicited_wire));
    assert_eq!(
        request
            .clone()
            .correlate_answer(unsolicited_envelope)
            .expect_err("unoffered overload control must not correlate"),
        SwmSessionTerminationCorrelationError::UnsolicitedOverloadControl
    );

    let mut offered_avps = str_avps();
    offered_avps.push(wire_avp(swm::AVP_OC_SUPPORTED_FEATURES.get(), 0x00, &[]));
    let offered_wire = wire_message(0xc0, HOP_BY_HOP, END_TO_END, offered_avps);
    let offered_request = parsed_request_envelope(&offered_wire);

    let non_reporting_answer = SwmSessionTerminationAnswer::for_request(
        &offered_request,
        SwmSessionTerminationResult::Success,
        "aaa.private.invalid",
        "private.invalid",
    );
    assert!(swm::build_swm_session_termination_answer(
        &offered_request,
        &non_reporting_answer,
        EncodeContext::default()
    )
    .is_ok());
    let non_reporting_wire = sta_wire(SESSION_ID, base::RESULT_CODE_DIAMETER_SUCCESS, HOP_BY_HOP);
    let non_reporting_envelope = parsed_answer_envelope(&decode(&non_reporting_wire));
    offered_request
        .clone()
        .correlate_answer(non_reporting_envelope)
        .expect("an offered capability may reach a non-reporting server");

    let olr = SwmAdditionalAvp::new(
        AvpHeader::ietf(swm::AVP_OC_OLR, false),
        oc_olr_value(),
        EncodeContext::default(),
    )
    .expect("RFC 7683 OC-OLR fixture must encode");
    let mut olr_without_supported = non_reporting_answer.clone();
    olr_without_supported.additional_avps.push(olr);
    assert!(swm::build_swm_session_termination_answer(
        &offered_request,
        &olr_without_supported,
        EncodeContext::default()
    )
    .is_err());
    let mut olr_only_avps = sta_avps(SESSION_ID, base::RESULT_CODE_DIAMETER_SUCCESS);
    olr_only_avps.push(wire_avp(swm::AVP_OC_OLR.get(), 0x00, &oc_olr_value()));
    let olr_only_wire = wire_message(0x40, HOP_BY_HOP, END_TO_END, olr_only_avps);
    let error = swm::parse_swm_session_termination_answer_envelope_from_connection(
        &decode(&olr_only_wire),
        CONNECTION_A,
        DecodeContext::default(),
    )
    .expect_err("OC-OLR without same-answer capability selection must fail");
    assert!(matches!(error.code(), DecodeErrorCode::Structural { .. }));

    let mut answer = SwmSessionTerminationAnswer::for_request(
        &offered_request,
        SwmSessionTerminationResult::Success,
        "aaa.private.invalid",
        "private.invalid",
    );
    answer.additional_avps.push(supported);
    let built = swm::build_swm_session_termination_answer(
        &offered_request,
        &answer,
        EncodeContext::default(),
    )
    .expect("offered RFC 7683 capability may be echoed");
    let parsed_answer = parsed_answer_envelope(&decode(&encode(&built)));
    offered_request
        .correlate_answer(parsed_answer)
        .expect("offered overload-control STA must correlate");
}

#[test]
fn command_profile_requires_proxiable_and_correct_role() {
    let wire = wire_message(0x80, HOP_BY_HOP, END_TO_END, str_avps());
    assert!(
        swm::parse_swm_session_termination_request(&decode(&wire), DecodeContext::default())
            .is_err()
    );

    let wire = wire_message(0xc0, HOP_BY_HOP, END_TO_END, sta_avps(SESSION_ID, 2001));
    assert!(
        swm::parse_swm_session_termination_answer(&decode(&wire), DecodeContext::default())
            .is_err()
    );
}

#[test]
fn proxy_info_values_are_copied_in_order_without_exposure() {
    let request = parsed_request_envelope(&str_wire());
    let answer = SwmSessionTerminationAnswer::for_request(
        &request,
        SwmSessionTerminationResult::Success,
        "aaa.private.invalid",
        "private.invalid",
    );
    let encoded = encode(
        &swm::build_swm_session_termination_answer(&request, &answer, EncodeContext::default())
            .expect("request-bound answer must build"),
    );
    let message = decode(&encoded);
    let proxy_states: Vec<Vec<u8>> = message
        .avps(DecodeContext::default())
        .map(|avp| avp.expect("valid top-level AVP"))
        .filter(|avp| avp.header.code == base::AVP_PROXY_INFO)
        .map(|proxy| {
            proxy
                .grouped_avps(DecodeContext::default())
                .map(|child| child.expect("valid Proxy-Info child"))
                .find(|child| child.header.code == base::AVP_PROXY_STATE)
                .expect("Proxy-State is required")
                .value
                .to_vec()
        })
        .collect();
    assert_eq!(
        proxy_states,
        vec![
            b"private-proxy-state-one".to_vec(),
            b"private-proxy-state-two".to_vec()
        ]
    );
}
