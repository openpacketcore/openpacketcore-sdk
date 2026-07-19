//! Independent wire and hostile-input evidence for SWm ASR/ASA.
//!
//! Fixtures are hand-authored from RFC 6733 sections 3, 4, 8.5, and 8.11
//! plus 3GPP TS 29.273 V19.2.0 sections 7.2.2.3.1-.2. They do not use the SDK
//! builder to produce their input bytes.

use std::num::NonZeroU64;

use bytes::BytesMut;
use opc_proto_diameter::apps::swm::{
    self, SwmAbortSessionAnswer, SwmAbortSessionCorrelationError, SwmAbortSessionRequest,
    SwmAbortSessionRequestEnvelope, SwmAbortSessionResult, SwmAdditionalAvp, SwmAuthSessionState,
    SwmDiameterConnectionToken, SwmDiameterTransaction, SwmExpectedAnswerPeer,
    SwmPostAbortSessionTermination, SwmRoutingMessagePriority, SwmSessionTerminationAnswer,
    SwmSessionTerminationRequestEnvelope, SwmSessionTerminationResult, SwmTerminationCause,
};
use opc_proto_diameter::base;
use opc_proto_diameter::error_answer::{
    inspect_diameter_request, DiameterRequestFailure, DiameterRequestInspection,
};
use opc_proto_diameter::{
    apps, AvpCode, AvpHeader, AvpKey, Message, OwnedMessage, DIAMETER_HEADER_LEN,
};
use opc_protocol::{
    BorrowDecode, DecodeContext, DecodeErrorCode, Encode, EncodeContext, UnknownIePolicy,
};

const HOP_BY_HOP: u32 = 0x3512_0001;
const END_TO_END: u32 = 0x3512_0002;
const SESSION_ID: &str = "session;private;abort-351";
const USER_NAME: &str = "subscriber-private@example.invalid";
const UNKNOWN_OPTIONAL_AVP: u32 = 9_352;
const EPDG_CONNECTION: u64 = 351_200_001;
const AAA_CONNECTION: u64 = 351_200_002;

fn connection(value: u64) -> SwmDiameterConnectionToken {
    SwmDiameterConnectionToken::new(NonZeroU64::new(value).expect("test token is nonzero"))
}

fn expected_epdg(connection_value: u64) -> SwmExpectedAnswerPeer {
    SwmExpectedAnswerPeer::direct(
        connection(connection_value),
        "epdg.private.invalid",
        "visited.invalid",
    )
}

fn expected_aaa(connection_value: u64) -> SwmExpectedAnswerPeer {
    SwmExpectedAnswerPeer::direct(
        connection(connection_value),
        "aaa.private.invalid",
        "aaa.invalid",
    )
}

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
    wire.extend_from_slice(&274_u32.to_be_bytes()[1..]);
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

fn oc_supported_value() -> Vec<u8> {
    wire_avp(swm::AVP_OC_FEATURE_VECTOR.get(), 0x00, &1_u64.to_be_bytes())
}

fn loss_oc_olr_value() -> Vec<u8> {
    [
        wire_avp(
            swm::AVP_OC_SEQUENCE_NUMBER.get(),
            0x00,
            &9_u64.to_be_bytes(),
        ),
        wire_avp(swm::AVP_OC_REPORT_TYPE.get(), 0x00, &0_u32.to_be_bytes()),
        wire_avp(
            swm::AVP_OC_REDUCTION_PERCENTAGE.get(),
            0x00,
            &25_u32.to_be_bytes(),
        ),
    ]
    .concat()
}

fn load_value() -> Vec<u8> {
    [
        wire_avp(swm::AVP_LOAD_TYPE.get(), 0x00, &0_u32.to_be_bytes()),
        wire_avp(swm::AVP_LOAD_VALUE.get(), 0x00, &55_000_u64.to_be_bytes()),
        wire_avp(swm::AVP_SOURCE_ID.get(), 0x00, b"epdg.private.invalid"),
    ]
    .concat()
}

fn asr_avps(auth_session_state: Option<u32>) -> Vec<Vec<u8>> {
    let mut avps = vec![
        wire_avp(base::AVP_SESSION_ID.get(), 0x40, SESSION_ID.as_bytes()),
        wire_avp(swm::AVP_DRMP.get(), 0x00, &5_u32.to_be_bytes()),
        wire_avp(base::AVP_ORIGIN_HOST.get(), 0x40, b"aaa.private.invalid"),
        wire_avp(base::AVP_ORIGIN_REALM.get(), 0x40, b"aaa.invalid"),
        wire_avp(base::AVP_DESTINATION_REALM.get(), 0x40, b"visited.invalid"),
        wire_avp(
            base::AVP_DESTINATION_HOST.get(),
            0x40,
            b"epdg.private.invalid",
        ),
        wire_avp(
            base::AVP_AUTH_APPLICATION_ID.get(),
            0x40,
            &swm::APPLICATION_ID.get().to_be_bytes(),
        ),
        wire_avp(base::AVP_USER_NAME.get(), 0x40, USER_NAME.as_bytes()),
    ];
    if let Some(value) = auth_session_state {
        avps.push(wire_avp(
            base::AVP_AUTH_SESSION_STATE.get(),
            0x40,
            &value.to_be_bytes(),
        ));
    }
    avps.extend([
        wire_avp(base::AVP_ORIGIN_STATE_ID.get(), 0x40, &77_u32.to_be_bytes()),
        proxy_info(b"proxy-one.private.invalid", b"private-state-one"),
        proxy_info(b"proxy-two.private.invalid", b"private-state-two"),
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
        wire_avp(
            swm::AVP_OC_SUPPORTED_FEATURES.get(),
            0x00,
            &oc_supported_value(),
        ),
        wire_avp(base::AVP_CLASS.get(), 0x40, b"class-state-one"),
        wire_avp(base::AVP_CLASS.get(), 0x40, b"class-state-two"),
        wire_avp(UNKNOWN_OPTIONAL_AVP, 0x00, b"private-extension"),
    ]);
    avps
}

fn asa_avps(result_code: u32) -> Vec<Vec<u8>> {
    vec![
        wire_avp(base::AVP_SESSION_ID.get(), 0x40, SESSION_ID.as_bytes()),
        wire_avp(swm::AVP_DRMP.get(), 0x00, &6_u32.to_be_bytes()),
        wire_avp(
            base::AVP_RESULT_CODE.get(),
            0x40,
            &result_code.to_be_bytes(),
        ),
        wire_avp(base::AVP_ORIGIN_HOST.get(), 0x40, b"epdg.private.invalid"),
        wire_avp(base::AVP_ORIGIN_REALM.get(), 0x40, b"visited.invalid"),
        wire_avp(base::AVP_USER_NAME.get(), 0x40, USER_NAME.as_bytes()),
        wire_avp(base::AVP_ORIGIN_STATE_ID.get(), 0x40, &88_u32.to_be_bytes()),
        wire_avp(
            swm::AVP_OC_SUPPORTED_FEATURES.get(),
            0x00,
            &oc_supported_value(),
        ),
        wire_avp(swm::AVP_OC_OLR.get(), 0x00, &loss_oc_olr_value()),
        wire_avp(swm::AVP_LOAD.get(), 0x00, &load_value()),
        wire_avp(base::AVP_CLASS.get(), 0x40, b"class-answer-one"),
        wire_avp(UNKNOWN_OPTIONAL_AVP, 0x00, b"private-answer-extension"),
        proxy_info(b"proxy-one.private.invalid", b"private-state-one"),
        proxy_info(b"proxy-two.private.invalid", b"private-state-two"),
    ]
}

fn asr_wire(auth_session_state: Option<u32>) -> Vec<u8> {
    wire_message(0xc0, HOP_BY_HOP, END_TO_END, asr_avps(auth_session_state))
}

fn asa_wire(result_code: u32, flags: u8) -> Vec<u8> {
    wire_message(flags, HOP_BY_HOP, END_TO_END, asa_avps(result_code))
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
        .expect("typed Diameter message must encode");
    wire.to_vec()
}

fn parsed_asr(wire: &[u8]) -> SwmAbortSessionRequestEnvelope {
    swm::parse_swm_abort_session_request_envelope(&decode(wire), DecodeContext::default())
        .expect("ASR fixture must parse")
}

fn parsed_outbound_asr(wire: &[u8]) -> SwmAbortSessionRequestEnvelope {
    parsed_asr(wire).with_expected_answer_peer(expected_epdg(EPDG_CONNECTION))
}

fn parsed_asa(wire: &[u8]) -> swm::SwmAbortSessionAnswerEnvelope {
    swm::parse_swm_abort_session_answer_envelope_from_connection(
        &decode(wire),
        connection(EPDG_CONNECTION),
        DecodeContext::default(),
    )
    .expect("ASA fixture must parse")
}

fn asa_for_request(
    request: &SwmAbortSessionRequestEnvelope,
    result: SwmAbortSessionResult,
) -> SwmAbortSessionAnswer {
    SwmAbortSessionAnswer::for_request(request, result, "epdg.private.invalid", "visited.invalid")
}

#[test]
fn hand_authored_asr_and_asa_parse_and_build_byte_exactly() {
    let request_wire = asr_wire(Some(0));
    let request = parsed_asr(&request_wire);
    assert_eq!(request.transaction().hop_by_hop_identifier(), HOP_BY_HOP);
    assert_eq!(request.proxy_info_count(), 2);
    assert_eq!(
        request.request().auth_session_state,
        Some(SwmAuthSessionState::StateMaintained)
    );
    assert_eq!(request.request().route_records.len(), 2);
    assert_eq!(request.request().additional_avps.len(), 4);
    assert!(request.expected_answer_peer().is_none());
    let outbound = request
        .clone()
        .with_expected_answer_peer(expected_epdg(EPDG_CONNECTION));
    assert_eq!(
        encode(
            &swm::build_swm_abort_session_request(&outbound, EncodeContext::default())
                .expect("parsed ASR must rebuild")
        ),
        request_wire
    );

    let answer_wire = asa_wire(base::RESULT_CODE_DIAMETER_SUCCESS, 0x40);
    let answer_message = decode(&answer_wire);
    let answer = swm::parse_swm_abort_session_answer(&answer_message, DecodeContext::default())
        .expect("ASA fixture must parse");
    assert_eq!(answer.result, SwmAbortSessionResult::Success);
    assert_eq!(answer.additional_avps.len(), 5);
    assert_eq!(
        encode(
            &swm::build_swm_abort_session_answer(&request, &answer, EncodeContext::default(),)
                .expect("parsed ASA must rebuild")
        ),
        answer_wire
    );
}

#[test]
fn committed_success_and_default_state_derive_the_administrative_str_at_the_epdg() {
    for state in [None, Some(0)] {
        let request = parsed_asr(&asr_wire(state));
        let answer = SwmAbortSessionAnswer::for_request(
            &request,
            SwmAbortSessionResult::Success,
            "local-epdg.private.invalid",
            "local-visited.invalid",
        );
        let _committed_asa = encode(
            &swm::build_swm_abort_session_answer(&request, &answer, EncodeContext::default())
                .expect("the ePDG must build the successful ASA before deriving STR"),
        );
        let SwmPostAbortSessionTermination::Required(str_request) = request
            .post_abort_session_termination(&answer, EncodeContext::default())
            .expect("the committed successful ASA must produce a disposition")
        else {
            panic!("state-maintained abort must require STR");
        };
        assert_eq!(
            str_request.termination_cause,
            SwmTerminationCause::Administrative
        );
        assert_eq!(str_request.session_id.as_ref(), SESSION_ID);
        assert_eq!(
            str_request.origin_host.as_ref(),
            "local-epdg.private.invalid"
        );
        assert_eq!(str_request.origin_realm.as_ref(), "local-visited.invalid");
        assert_eq!(str_request.destination_realm.as_ref(), "aaa.invalid");
        assert_eq!(
            str_request
                .destination_host
                .as_ref()
                .map(|value| value.as_ref().as_str()),
            Some("aaa.private.invalid")
        );
        let pending = SwmSessionTerminationRequestEnvelope::for_outbound(
            *str_request,
            SwmDiameterTransaction::new(0x3512_0011, 0x3512_0012),
            expected_aaa(AAA_CONNECTION),
        );
        let wire = encode(
            &swm::build_swm_session_termination_request(&pending, EncodeContext::default())
                .expect("derived STR facts must be executable"),
        );
        let received = swm::parse_swm_session_termination_request_envelope(
            &decode(&wire),
            DecodeContext::default(),
        )
        .expect("derived STR must parse at the AAA boundary");
        assert_eq!(
            received.request().termination_cause,
            SwmTerminationCause::Administrative
        );

        let sta = SwmSessionTerminationAnswer::for_request(
            &received,
            SwmSessionTerminationResult::Success,
            "aaa.private.invalid",
            "aaa.invalid",
        );
        let sta_wire = encode(
            &swm::build_swm_session_termination_answer(&received, &sta, EncodeContext::default())
                .expect("the AAA boundary must build the correlated STA"),
        );
        let sta = swm::parse_swm_session_termination_answer_envelope_from_connection(
            &decode(&sta_wire),
            connection(AAA_CONNECTION),
            DecodeContext::default(),
        )
        .expect("the ePDG boundary must parse the correlated STA");
        let completed = pending
            .correlate_answer(sta)
            .expect("the post-abort STR/STA exchange must correlate end to end");
        assert_eq!(
            completed.answer().result,
            SwmSessionTerminationResult::Success
        );
    }
}

#[test]
fn no_state_and_unsuccessful_abort_do_not_derive_str() {
    let request = parsed_asr(&asr_wire(Some(1)));
    let answer = asa_for_request(&request, SwmAbortSessionResult::Success);
    assert!(matches!(
        request
            .post_abort_session_termination(&answer, EncodeContext::default())
            .expect("a valid no-state ASA must produce a disposition"),
        SwmPostAbortSessionTermination::NotRequiredNoState
    ));

    let request = parsed_asr(&asr_wire(Some(0)));
    let answer = asa_for_request(&request, SwmAbortSessionResult::UnknownSession);
    assert!(matches!(
        request
            .post_abort_session_termination(&answer, EncodeContext::default())
            .expect("a valid unsuccessful ASA must produce a disposition"),
        SwmPostAbortSessionTermination::NotRequiredAbortUnsuccessful
    ));
}

#[test]
fn retransmission_t_bit_is_retained_and_outbound_failover_resend_is_explicit() {
    let mut wire = asr_wire(Some(0));
    wire[4] = 0xd0;
    let parsed = parsed_asr(&wire);
    assert!(parsed.is_potentially_retransmitted());
    let parsed = parsed.with_expected_answer_peer(expected_epdg(EPDG_CONNECTION));
    assert_eq!(
        encode(
            &swm::build_swm_abort_session_request(&parsed, EncodeContext::default())
                .expect("retransmitted ASR must rebuild")
        ),
        wire
    );

    let request = SwmAbortSessionRequest {
        session_id: SESSION_ID.into(),
        origin_host: "aaa.private.invalid".into(),
        origin_realm: "aaa.invalid".into(),
        destination_realm: "visited.invalid".into(),
        destination_host: "epdg.private.invalid".into(),
        user_name: USER_NAME.into(),
        auth_session_state: None,
        origin_state_id: None,
        drmp: None,
        route_records: Vec::new(),
        additional_avps: Vec::new(),
    };
    let mut retry = SwmAbortSessionRequestEnvelope::for_outbound(
        request,
        SwmDiameterTransaction::new(HOP_BY_HOP, END_TO_END),
        expected_epdg(EPDG_CONNECTION),
    );
    let initial = swm::build_swm_abort_session_request(&retry, EncodeContext::default())
        .expect("initial outbound ASR must build");
    assert!(!initial.header.flags.is_potentially_retransmitted());
    let replacement_hop_by_hop = 0x3512_00f0;
    let replacement_connection = EPDG_CONNECTION + 1;
    retry.mark_for_failover_retransmission(
        replacement_hop_by_hop,
        expected_epdg(replacement_connection),
    );
    let built = swm::build_swm_abort_session_request(&retry, EncodeContext::default())
        .expect("explicit outbound failover resend must build");
    assert!(built.header.flags.is_potentially_retransmitted());
    assert_eq!(built.header.hop_by_hop_identifier, replacement_hop_by_hop);
    assert_eq!(built.header.end_to_end_identifier, END_TO_END);
    assert_eq!(
        retry
            .expected_answer_peer()
            .expect("outbound failover retains binding")
            .connection(),
        connection(replacement_connection)
    );
}

#[test]
fn correlation_requires_binding_and_exact_connection_generation() {
    let answer_wire = asa_wire(base::RESULT_CODE_DIAMETER_SUCCESS, 0x40);
    let unbound = parsed_asr(&asr_wire(Some(0)));
    assert!(unbound.expected_answer_peer().is_none());
    assert!(
        swm::build_swm_abort_session_request(&unbound, EncodeContext::default()).is_err(),
        "an inbound request cannot silently become an authenticated outbound request"
    );
    assert_eq!(
        unbound
            .correlate_answer(parsed_asa(&answer_wire))
            .expect_err("unbound requests must fail closed"),
        SwmAbortSessionCorrelationError::PeerBindingMissing
    );
    assert_eq!(
        SwmAbortSessionCorrelationError::PeerBindingMissing.as_str(),
        "swm_asr_asa_peer_binding_missing"
    );

    let request = parsed_outbound_asr(&asr_wire(Some(0)));
    let answer = swm::parse_swm_abort_session_answer_envelope_from_connection(
        &decode(&answer_wire),
        connection(EPDG_CONNECTION + 1),
        DecodeContext::default(),
    )
    .expect("ASA fixture must parse on a distinct connection generation");
    assert_eq!(
        request
            .correlate_answer(answer)
            .expect_err("a reconnect cannot satisfy pending work from an old connection"),
        SwmAbortSessionCorrelationError::PeerConnectionMismatch
    );
    assert_eq!(
        SwmAbortSessionCorrelationError::PeerConnectionMismatch.as_str(),
        "swm_asr_asa_peer_connection_mismatch"
    );
}

#[test]
fn direct_and_routed_origin_policies_use_diameter_identity_semantics() {
    let mut uppercase_origin = asa_avps(base::RESULT_CODE_DIAMETER_SUCCESS);
    uppercase_origin[3] = wire_avp(base::AVP_ORIGIN_HOST.get(), 0x40, b"EPDG.PRIVATE.INVALID");
    uppercase_origin[4] = wire_avp(base::AVP_ORIGIN_REALM.get(), 0x40, b"VISITED.INVALID");
    let uppercase_wire = wire_message(0x40, HOP_BY_HOP, END_TO_END, uppercase_origin);
    parsed_outbound_asr(&asr_wire(Some(0)))
        .correlate_answer(parsed_asa(&uppercase_wire))
        .expect("DiameterIdentity matching must be ASCII case-insensitive");

    let mut agent_origin = asa_avps(base::RESULT_CODE_DIAMETER_SUCCESS);
    agent_origin[3] = wire_avp(base::AVP_ORIGIN_HOST.get(), 0x40, b"other.visited.invalid");
    let agent_wire = wire_message(0x40, HOP_BY_HOP, END_TO_END, agent_origin);
    parsed_asr(&asr_wire(Some(0)))
        .with_expected_answer_peer(SwmExpectedAnswerPeer::routed(connection(EPDG_CONNECTION)))
        .correlate_answer(parsed_asa(&agent_wire))
        .expect("a routed request permits any final logical Origin");

    parsed_asr(&asr_wire(Some(0)))
        .with_expected_answer_peer(SwmExpectedAnswerPeer::routed_in_realm(
            connection(EPDG_CONNECTION),
            "VISITED.INVALID",
        ))
        .correlate_answer(parsed_asa(&agent_wire))
        .expect("a realm route permits any host in the case-insensitive realm");

    let mut wrong_realm = asa_avps(base::RESULT_CODE_DIAMETER_SUCCESS);
    wrong_realm[4] = wire_avp(base::AVP_ORIGIN_REALM.get(), 0x40, b"other.invalid");
    let wrong_realm_wire = wire_message(0x40, HOP_BY_HOP, END_TO_END, wrong_realm);
    assert_eq!(
        parsed_asr(&asr_wire(Some(0)))
            .with_expected_answer_peer(SwmExpectedAnswerPeer::routed_in_realm(
                connection(EPDG_CONNECTION),
                "visited.invalid",
            ))
            .correlate_answer(parsed_asa(&wrong_realm_wire))
            .expect_err("a realm route must reject a different logical realm"),
        SwmAbortSessionCorrelationError::PeerIdentityMismatch
    );
}

#[test]
fn failover_replaces_connection_and_hop_by_hop_as_one_transition() {
    let replacement_hop_by_hop = 0x3512_00f1;
    let replacement_connection = EPDG_CONNECTION + 1;
    let mut request = parsed_outbound_asr(&asr_wire(Some(0)));
    request.mark_for_failover_retransmission(
        replacement_hop_by_hop,
        expected_epdg(replacement_connection),
    );

    let mut replacement_answer = asa_wire(base::RESULT_CODE_DIAMETER_SUCCESS, 0x40);
    replacement_answer[12..16].copy_from_slice(&replacement_hop_by_hop.to_be_bytes());
    let old_connection_answer = swm::parse_swm_abort_session_answer_envelope_from_connection(
        &decode(&replacement_answer),
        connection(EPDG_CONNECTION),
        DecodeContext::default(),
    )
    .expect("replacement ASA must parse on the old connection");
    assert_eq!(
        request
            .clone()
            .correlate_answer(old_connection_answer)
            .expect_err("the failed connection must be fenced"),
        SwmAbortSessionCorrelationError::PeerConnectionMismatch
    );

    let old_hop_answer = swm::parse_swm_abort_session_answer_envelope_from_connection(
        &decode(&asa_wire(base::RESULT_CODE_DIAMETER_SUCCESS, 0x40)),
        connection(replacement_connection),
        DecodeContext::default(),
    )
    .expect("old-Hop-by-Hop ASA must still parse");
    assert_eq!(
        request
            .clone()
            .correlate_answer(old_hop_answer)
            .expect_err("the old connection-local transaction must be fenced"),
        SwmAbortSessionCorrelationError::TransactionMismatch
    );

    let replacement_answer = swm::parse_swm_abort_session_answer_envelope_from_connection(
        &decode(&replacement_answer),
        connection(replacement_connection),
        DecodeContext::default(),
    )
    .expect("replacement ASA must parse on the replacement connection");
    request
        .correlate_answer(replacement_answer)
        .expect("only the replacement connection and transaction may complete failover");
}

#[test]
fn retransmitted_asr_rebuilds_the_exact_committed_asa() {
    let request_wire = asr_wire(Some(0));
    let request = parsed_asr(&request_wire);
    let mut answer = asa_for_request(&request, SwmAbortSessionResult::Success);
    answer.additional_avps.push(
        SwmAdditionalAvp::new(
            AvpHeader::ietf(swm::AVP_OC_SUPPORTED_FEATURES, false),
            oc_supported_value(),
            EncodeContext::default(),
        )
        .expect("OC echo must frame"),
    );
    let committed = encode(
        &swm::build_swm_abort_session_answer(&request, &answer, EncodeContext::default())
            .expect("initial request-bound ASA must build"),
    );

    let mut retransmitted_wire = request_wire;
    retransmitted_wire[4] |= 0x10;
    let retransmitted = parsed_asr(&retransmitted_wire);
    assert!(retransmitted.is_potentially_retransmitted());
    let replay = encode(
        &swm::build_swm_abort_session_answer(&retransmitted, &answer, EncodeContext::default())
            .expect("the committed typed ASA must rebuild for a duplicate ASR"),
    );

    assert_eq!(replay, committed);
    let replay_message = decode(&replay);
    assert_eq!(replay_message.header.hop_by_hop_identifier, HOP_BY_HOP);
    assert_eq!(replay_message.header.end_to_end_identifier, END_TO_END);
    assert!(replay_message.header.flags.is_proxiable());
    assert!(!replay_message.header.flags.is_potentially_retransmitted());

    let replacement_hop_by_hop = 0x3512_00f2_u32;
    let mut failover_wire = retransmitted_wire;
    failover_wire[12..16].copy_from_slice(&replacement_hop_by_hop.to_be_bytes());
    let failover = parsed_asr(&failover_wire);
    let failover_replay = encode(
        &swm::build_swm_abort_session_answer(&failover, &answer, EncodeContext::default())
            .expect("the committed typed ASA must rebuild after failover"),
    );
    let failover_message = decode(&failover_replay);
    assert_eq!(
        failover_message.header.hop_by_hop_identifier,
        replacement_hop_by_hop
    );
    assert_eq!(failover_message.header.end_to_end_identifier, END_TO_END);
    assert_eq!(&failover_replay[..12], &committed[..12]);
    assert_eq!(&failover_replay[16..], &committed[16..]);
}

#[test]
fn required_asr_omissions_retain_checked_5005_provenance() {
    for missing_code in [
        base::AVP_SESSION_ID.get(),
        base::AVP_ORIGIN_HOST.get(),
        base::AVP_ORIGIN_REALM.get(),
        base::AVP_DESTINATION_REALM.get(),
        base::AVP_DESTINATION_HOST.get(),
        base::AVP_AUTH_APPLICATION_ID.get(),
        base::AVP_USER_NAME.get(),
    ] {
        let avps = asr_avps(Some(0))
            .into_iter()
            .filter(|avp| {
                u32::from_be_bytes(avp[0..4].try_into().expect("fixed AVP code")) != missing_code
            })
            .filter(|avp| {
                u32::from_be_bytes(avp[0..4].try_into().expect("fixed AVP code"))
                    != UNKNOWN_OPTIONAL_AVP
            });
        let wire = wire_message(0xc0, HOP_BY_HOP, END_TO_END, avps);
        let parser_error = swm::parse_swm_abort_session_request_with_provenance(
            &decode(&wire),
            DecodeContext::conservative(),
        )
        .expect_err("required ASR omission must fail");
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
            panic!("well-framed ASR must be answerable");
        };
        let bound = DiameterRequestFailure::from_parser_error(
            &envelope,
            &wire,
            &parser_error,
            DecodeContext::conservative(),
            apps::APP_DICTIONARIES,
            EncodeContext::default(),
        )
        .expect("sealed ASR omission must map to a request-bound failure");
        assert_eq!(bound.result_code(), base::RESULT_CODE_DIAMETER_MISSING_AVP);
        assert!(matches!(
            bound.failure(),
            DiameterRequestFailure::MissingMandatoryAvp(_)
        ));
    }
}

#[test]
fn duplicate_singletons_and_wrong_vendor_core_fail_closed() {
    let mut duplicate = asr_avps(Some(0));
    duplicate.push(wire_avp(base::AVP_SESSION_ID.get(), 0x40, b"session;other"));
    let error = swm::parse_swm_abort_session_request(
        &decode(&wire_message(0xc0, HOP_BY_HOP, END_TO_END, duplicate)),
        DecodeContext::default(),
    )
    .expect_err("duplicate Session-Id must fail");
    assert_eq!(error.code(), &DecodeErrorCode::DuplicateIe);

    let mut wrong_vendor = asr_avps(Some(0));
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
    assert!(swm::parse_swm_abort_session_request(
        &decode(&wire_message(0xc0, HOP_BY_HOP, END_TO_END, wrong_vendor)),
        DecodeContext::default()
    )
    .is_err());
}

#[test]
fn asa_mandatory_cardinality_type_vendor_and_role_fail_closed() {
    for missing_code in [
        base::AVP_SESSION_ID.get(),
        base::AVP_RESULT_CODE.get(),
        base::AVP_ORIGIN_HOST.get(),
        base::AVP_ORIGIN_REALM.get(),
    ] {
        let avps = asa_avps(base::RESULT_CODE_DIAMETER_SUCCESS)
            .into_iter()
            .filter(|avp| {
                u32::from_be_bytes(avp[0..4].try_into().expect("fixed AVP code")) != missing_code
            });
        assert!(swm::parse_swm_abort_session_answer(
            &decode(&wire_message(0x40, HOP_BY_HOP, END_TO_END, avps)),
            DecodeContext::default()
        )
        .is_err());
    }

    let mut duplicate = asa_avps(base::RESULT_CODE_DIAMETER_SUCCESS);
    duplicate.push(wire_avp(
        base::AVP_RESULT_CODE.get(),
        0x40,
        &base::RESULT_CODE_DIAMETER_SUCCESS.to_be_bytes(),
    ));
    let error = swm::parse_swm_abort_session_answer(
        &decode(&wire_message(0x40, HOP_BY_HOP, END_TO_END, duplicate)),
        DecodeContext::default(),
    )
    .expect_err("duplicate ASA Result-Code must fail");
    assert_eq!(error.code(), &DecodeErrorCode::DuplicateIe);

    let mut invalid_type = asa_avps(base::RESULT_CODE_DIAMETER_SUCCESS);
    invalid_type[2] = wire_avp(base::AVP_RESULT_CODE.get(), 0x40, &[0, 7, 209]);
    assert!(swm::parse_swm_abort_session_answer(
        &decode(&wire_message(0x40, HOP_BY_HOP, END_TO_END, invalid_type)),
        DecodeContext::default()
    )
    .is_err());

    let mut wrong_vendor = asa_avps(base::RESULT_CODE_DIAMETER_SUCCESS);
    wrong_vendor[2] = wire_vendor_avp(
        base::AVP_RESULT_CODE.get(),
        0x40,
        10_415,
        &base::RESULT_CODE_DIAMETER_SUCCESS.to_be_bytes(),
    );
    assert!(swm::parse_swm_abort_session_answer(
        &decode(&wire_message(0x40, HOP_BY_HOP, END_TO_END, wrong_vendor)),
        DecodeContext::default()
    )
    .is_err());

    let mut request_only = asa_avps(base::RESULT_CODE_DIAMETER_SUCCESS);
    request_only.push(wire_avp(
        base::AVP_AUTH_APPLICATION_ID.get(),
        0x40,
        &swm::APPLICATION_ID.get().to_be_bytes(),
    ));
    assert!(swm::parse_swm_abort_session_answer(
        &decode(&wire_message(0x40, HOP_BY_HOP, END_TO_END, request_only)),
        DecodeContext::default()
    )
    .is_err());
}

#[test]
fn invalid_values_roles_headers_and_unknown_m_fail_closed() {
    let mut invalid_state = asr_avps(Some(2));
    let wire = wire_message(0xc0, HOP_BY_HOP, END_TO_END, invalid_state.drain(..));
    let error = swm::parse_swm_abort_session_request(&decode(&wire), DecodeContext::default())
        .expect_err("unknown Auth-Session-State must fail");
    assert!(matches!(
        error.code(),
        DecodeErrorCode::InvalidEnumValue { .. }
    ));

    let mut invalid_identity = asr_avps(Some(0));
    for avp in &mut invalid_identity {
        if u32::from_be_bytes(avp[0..4].try_into().expect("fixed AVP code"))
            == base::AVP_ORIGIN_HOST.get()
        {
            *avp = wire_avp(base::AVP_ORIGIN_HOST.get(), 0x40, "hést".as_bytes());
        }
    }
    assert!(swm::parse_swm_abort_session_request(
        &decode(&wire_message(
            0xc0,
            HOP_BY_HOP,
            END_TO_END,
            invalid_identity
        )),
        DecodeContext::default()
    )
    .is_err());

    let mut answer_only = asr_avps(Some(0));
    answer_only.push(wire_avp(
        base::AVP_RESULT_CODE.get(),
        0x40,
        &base::RESULT_CODE_DIAMETER_SUCCESS.to_be_bytes(),
    ));
    assert!(swm::parse_swm_abort_session_request(
        &decode(&wire_message(0xc0, HOP_BY_HOP, END_TO_END, answer_only)),
        DecodeContext::default()
    )
    .is_err());

    let mut unknown_m = asr_avps(Some(0));
    unknown_m.push(wire_avp(9_999, 0x40, b"private-critical"));
    let error = swm::parse_swm_abort_session_request(
        &decode(&wire_message(0xc0, HOP_BY_HOP, END_TO_END, unknown_m)),
        DecodeContext::default(),
    )
    .expect_err("unknown mandatory AVP must fail");
    assert_eq!(error.code(), &DecodeErrorCode::UnknownCriticalIe);

    let mut wrong_application = asr_wire(Some(0));
    wrong_application[8..12].copy_from_slice(&1_u32.to_be_bytes());
    assert!(swm::parse_swm_abort_session_request(
        &decode(&wrong_application),
        DecodeContext::default()
    )
    .is_err());

    let mut wrong_p = asr_wire(Some(0));
    wrong_p[4] = 0x80;
    assert!(
        swm::parse_swm_abort_session_request(&decode(&wrong_p), DecodeContext::default()).is_err()
    );
}

#[test]
fn asa_result_and_error_bit_contract_is_exact() {
    for result in [
        base::RESULT_CODE_DIAMETER_UNKNOWN_SESSION_ID,
        base::RESULT_CODE_DIAMETER_UNABLE_TO_COMPLY,
    ] {
        let answer = swm::parse_swm_abort_session_answer(
            &decode(&asa_wire(result, 0x40)),
            DecodeContext::default(),
        )
        .expect("ordinary 5xxx ASA keeps E clear");
        assert!(!matches!(answer.result, SwmAbortSessionResult::Other(_)));
        swm::parse_swm_abort_session_answer(
            &decode(&asa_wire(result, 0x60)),
            DecodeContext::default(),
        )
        .expect("RFC 6733 also permits a 5xxx generic E-bit fallback");
    }

    let answer = swm::parse_swm_abort_session_answer(
        &decode(&asa_wire(3_002, 0x60)),
        DecodeContext::default(),
    )
    .expect("3xxx protocol-error ASA must set E");
    assert_eq!(answer.result, SwmAbortSessionResult::Other(3_002));
    for (flags, result_code) in [
        (0x40, 3_002),
        (0x60, base::RESULT_CODE_DIAMETER_SUCCESS),
        (0x60, 4_001),
    ] {
        assert!(swm::parse_swm_abort_session_answer(
            &decode(&asa_wire(result_code, flags)),
            DecodeContext::default()
        )
        .is_err());
    }
}

#[test]
fn correlation_rejects_identifier_session_peer_user_proxy_and_overload_drift() {
    let request_wire = asr_wire(Some(0));

    let mut mismatched_id = asa_wire(base::RESULT_CODE_DIAMETER_SUCCESS, 0x40);
    mismatched_id[12..16].copy_from_slice(&0xdead_beef_u32.to_be_bytes());
    let answer = swm::parse_swm_abort_session_answer_envelope_from_connection(
        &decode(&mismatched_id),
        connection(EPDG_CONNECTION),
        DecodeContext::default(),
    )
    .expect("mismatched transaction ASA still parses");
    assert_eq!(
        parsed_outbound_asr(&request_wire)
            .correlate_answer(answer)
            .expect_err("transaction drift must fail"),
        SwmAbortSessionCorrelationError::TransactionMismatch
    );

    let mut mismatched_session = asa_avps(base::RESULT_CODE_DIAMETER_SUCCESS);
    mismatched_session[0] = wire_avp(base::AVP_SESSION_ID.get(), 0x40, b"session;different");
    let answer = swm::parse_swm_abort_session_answer_envelope_from_connection(
        &decode(&wire_message(
            0x40,
            HOP_BY_HOP,
            END_TO_END,
            mismatched_session,
        )),
        connection(EPDG_CONNECTION),
        DecodeContext::default(),
    )
    .expect("mismatched session ASA still parses");
    assert_eq!(
        parsed_outbound_asr(&request_wire)
            .correlate_answer(answer)
            .expect_err("session drift must fail"),
        SwmAbortSessionCorrelationError::SessionMismatch
    );

    let mut mismatched_peer = asa_avps(base::RESULT_CODE_DIAMETER_SUCCESS);
    mismatched_peer[3] = wire_avp(base::AVP_ORIGIN_HOST.get(), 0x40, b"other.invalid");
    let answer = swm::parse_swm_abort_session_answer_envelope_from_connection(
        &decode(&wire_message(0x40, HOP_BY_HOP, END_TO_END, mismatched_peer)),
        connection(EPDG_CONNECTION),
        DecodeContext::default(),
    )
    .expect("mismatched peer ASA still parses");
    assert_eq!(
        parsed_outbound_asr(&request_wire)
            .correlate_answer(answer)
            .expect_err("peer drift must fail"),
        SwmAbortSessionCorrelationError::PeerIdentityMismatch
    );

    let mut mismatched_user = asa_avps(base::RESULT_CODE_DIAMETER_SUCCESS);
    mismatched_user[5] = wire_avp(
        base::AVP_USER_NAME.get(),
        0x40,
        b"different-subscriber@example.invalid",
    );
    let answer = swm::parse_swm_abort_session_answer_envelope_from_connection(
        &decode(&wire_message(0x40, HOP_BY_HOP, END_TO_END, mismatched_user)),
        connection(EPDG_CONNECTION),
        DecodeContext::default(),
    )
    .expect("mismatched user ASA still parses");
    assert_eq!(
        parsed_outbound_asr(&request_wire)
            .correlate_answer(answer)
            .expect_err("User-Name drift must fail"),
        SwmAbortSessionCorrelationError::UserNameMismatch
    );

    let mut mismatched_proxy = asa_avps(base::RESULT_CODE_DIAMETER_SUCCESS);
    let last = mismatched_proxy.len() - 1;
    mismatched_proxy[last] = proxy_info(b"proxy-two.private.invalid", b"changed-state");
    let answer = swm::parse_swm_abort_session_answer_envelope_from_connection(
        &decode(&wire_message(
            0x40,
            HOP_BY_HOP,
            END_TO_END,
            mismatched_proxy,
        )),
        connection(EPDG_CONNECTION),
        DecodeContext::default(),
    )
    .expect("mismatched proxy ASA still parses");
    assert_eq!(
        parsed_outbound_asr(&request_wire)
            .correlate_answer(answer)
            .expect_err("Proxy-Info drift must fail"),
        SwmAbortSessionCorrelationError::ProxyInfoMismatch
    );

    let mut missing_echo = asa_avps(base::RESULT_CODE_DIAMETER_SUCCESS);
    missing_echo.retain(|avp| {
        !matches!(
            u32::from_be_bytes(avp[0..4].try_into().expect("fixed AVP code")),
            621 | 623
        )
    });
    let answer = swm::parse_swm_abort_session_answer_envelope_from_connection(
        &decode(&wire_message(0x40, HOP_BY_HOP, END_TO_END, missing_echo)),
        connection(EPDG_CONNECTION),
        DecodeContext::default(),
    )
    .expect("ASA without overload echo still frames");
    parsed_outbound_asr(&request_wire)
        .correlate_answer(answer)
        .expect("RFC 7683 permits an answer to decline an offered capability by omitting it");

    let mut no_offer = asr_avps(Some(0));
    no_offer.retain(|avp| {
        u32::from_be_bytes(avp[0..4].try_into().expect("fixed AVP code"))
            != swm::AVP_OC_SUPPORTED_FEATURES.get()
    });
    let answer = swm::parse_swm_abort_session_answer_envelope_from_connection(
        &decode(&asa_wire(base::RESULT_CODE_DIAMETER_SUCCESS, 0x40)),
        connection(EPDG_CONNECTION),
        DecodeContext::default(),
    )
    .expect("ASA overload selection must parse independently");
    assert_eq!(
        parsed_outbound_asr(&wire_message(0xc0, HOP_BY_HOP, END_TO_END, no_offer))
            .correlate_answer(answer)
            .expect_err("unsolicited overload selection must fail correlation"),
        SwmAbortSessionCorrelationError::UnsolicitedOverloadControl
    );
}

#[test]
fn protocol_error_from_an_agent_does_not_claim_final_endpoint_identity() {
    let request = parsed_outbound_asr(&asr_wire(Some(0)));
    let mut avps = asa_avps(3_002);
    avps[3] = wire_avp(base::AVP_ORIGIN_HOST.get(), 0x40, b"agent.private.invalid");
    avps[4] = wire_avp(base::AVP_ORIGIN_REALM.get(), 0x40, b"agent.invalid");
    avps.retain(|avp| {
        u32::from_be_bytes(avp[0..4].try_into().expect("fixed AVP code"))
            != base::AVP_SESSION_ID.get()
    });
    let answer = swm::parse_swm_abort_session_answer_envelope_from_connection(
        &decode(&wire_message(0x60, HOP_BY_HOP, END_TO_END, avps)),
        connection(EPDG_CONNECTION),
        DecodeContext::default(),
    )
    .expect("agent protocol-error ASA must parse");
    assert!(answer.is_protocol_error());
    let exchange = request
        .correlate_answer(answer)
        .expect("agent error remains correlated by transaction, routing, and overload");
    assert_eq!(
        exchange.answer().result,
        SwmAbortSessionResult::Other(3_002)
    );

    let request = parsed_outbound_asr(&asr_wire(Some(0)));
    let mut avps = asa_avps(4_001);
    avps[3] = wire_avp(base::AVP_ORIGIN_HOST.get(), 0x40, b"other.invalid");
    let answer = swm::parse_swm_abort_session_answer_envelope_from_connection(
        &decode(&wire_message(0x40, HOP_BY_HOP, END_TO_END, avps)),
        connection(EPDG_CONNECTION),
        DecodeContext::default(),
    )
    .expect("ordinary transient-failure ASA must parse");
    assert!(!answer.is_protocol_error());
    assert_eq!(
        request
            .correlate_answer(answer)
            .expect_err("an E-clear answer must satisfy the explicit direct-Origin policy"),
        SwmAbortSessionCorrelationError::PeerIdentityMismatch
    );
}

#[test]
fn generic_permanent_failure_may_omit_session_and_retain_experimental_context() {
    let request = parsed_outbound_asr(&asr_wire(Some(0)));
    let experimental_result = [
        wire_avp(base::AVP_VENDOR_ID.get(), 0x40, &10_415_u32.to_be_bytes()),
        wire_avp(
            base::AVP_EXPERIMENTAL_RESULT_CODE.get(),
            0x40,
            &5_005_u32.to_be_bytes(),
        ),
    ]
    .concat();
    let mut avps = asa_avps(base::RESULT_CODE_DIAMETER_MISSING_AVP);
    avps.retain(|avp| {
        u32::from_be_bytes(avp[0..4].try_into().expect("fixed AVP code"))
            != base::AVP_SESSION_ID.get()
    });
    avps[2] = wire_avp(base::AVP_ORIGIN_HOST.get(), 0x40, b"agent.private.invalid");
    avps[3] = wire_avp(base::AVP_ORIGIN_REALM.get(), 0x40, b"agent.invalid");
    avps.push(wire_avp(
        base::AVP_EXPERIMENTAL_RESULT.get(),
        0x40,
        &experimental_result,
    ));

    let answer = swm::parse_swm_abort_session_answer_envelope_from_connection(
        &decode(&wire_message(0x60, HOP_BY_HOP, END_TO_END, avps)),
        connection(EPDG_CONNECTION),
        DecodeContext::default(),
    )
    .expect("generic permanent-failure ASA must retain its RFC 6733 context");
    assert!(answer.is_protocol_error());
    assert!(answer.answer().session_id.is_none());
    assert!(answer
        .answer()
        .additional_avps
        .iter()
        .any(|avp| avp.code() == base::AVP_EXPERIMENTAL_RESULT));

    let mut originated = asa_for_request(&request, SwmAbortSessionResult::UnableToComply);
    originated.additional_avps.push(
        SwmAdditionalAvp::new(
            AvpHeader::ietf(base::AVP_EXPERIMENTAL_RESULT, true),
            experimental_result,
            EncodeContext::default(),
        )
        .expect("valid Experimental-Result is structurally framed"),
    );
    swm::build_swm_abort_session_answer(&request, &originated, EncodeContext::default())
        .expect_err("typed ordinary ASA builder cannot emit generic-error Experimental-Result");

    let exchange = request
        .correlate_answer(answer)
        .expect("generic error correlates by transaction, P, Proxy-Info, and overload state");
    assert_eq!(
        exchange.answer().result,
        SwmAbortSessionResult::Other(base::RESULT_CODE_DIAMETER_MISSING_AVP)
    );
}

#[test]
fn unknown_optional_policy_and_direct_count_bounds_are_enforced() {
    let preserve = swm::parse_swm_abort_session_request(
        &decode(&asr_wire(Some(0))),
        DecodeContext {
            unknown_ie_policy: UnknownIePolicy::Preserve,
            ..DecodeContext::default()
        },
    )
    .expect("unknown optional AVP must preserve");
    assert!(preserve
        .additional_avps
        .iter()
        .any(|avp| avp.code() == AvpCode::new(UNKNOWN_OPTIONAL_AVP)));
    let dropped = swm::parse_swm_abort_session_request(
        &decode(&asr_wire(Some(0))),
        DecodeContext {
            unknown_ie_policy: UnknownIePolicy::Drop,
            ..DecodeContext::default()
        },
    )
    .expect("unknown optional AVP must drop");
    assert!(!dropped
        .additional_avps
        .iter()
        .any(|avp| avp.code() == AvpCode::new(UNKNOWN_OPTIONAL_AVP)));

    for code in [base::AVP_PROXY_INFO, base::AVP_ROUTE_RECORD] {
        let mut avps = asr_avps(Some(0));
        avps.retain(|avp| {
            u32::from_be_bytes(avp[0..4].try_into().expect("fixed AVP code")) != code.get()
        });
        let repeated = if code == base::AVP_PROXY_INFO {
            proxy_info(b"proxy.private.invalid", b"state")
        } else {
            wire_avp(code.get(), 0x40, b"route.private.invalid")
        };
        avps.extend(std::iter::repeat_n(repeated, 129));
        let error = swm::parse_swm_abort_session_request(
            &decode(&wire_message(0xc0, HOP_BY_HOP, END_TO_END, avps)),
            DecodeContext {
                max_ies: 512,
                ..DecodeContext::default()
            },
        )
        .expect_err("129th bounded entry must fail");
        assert_eq!(error.code(), &DecodeErrorCode::IeCountExceeded);
    }

    let mut avps = asr_avps(Some(0));
    avps.retain(|avp| {
        u32::from_be_bytes(avp[0..4].try_into().expect("fixed AVP code")) != UNKNOWN_OPTIONAL_AVP
    });
    avps.extend((0..129).map(|index| wire_avp(10_000 + index, 0x00, b"bounded-private-extension")));
    let error = swm::parse_swm_abort_session_request(
        &decode(&wire_message(0xc0, HOP_BY_HOP, END_TO_END, avps)),
        DecodeContext {
            max_ies: 512,
            ..DecodeContext::default()
        },
    )
    .expect_err("129th additional AVP must fail");
    assert_eq!(error.code(), &DecodeErrorCode::IeCountExceeded);
}

#[test]
fn asa_proxy_and_load_counts_are_bounded_at_the_typed_surface() {
    let core = || {
        vec![
            wire_avp(base::AVP_SESSION_ID.get(), 0x40, SESSION_ID.as_bytes()),
            wire_avp(
                base::AVP_RESULT_CODE.get(),
                0x40,
                &base::RESULT_CODE_DIAMETER_SUCCESS.to_be_bytes(),
            ),
            wire_avp(base::AVP_ORIGIN_HOST.get(), 0x40, b"epdg.private.invalid"),
            wire_avp(base::AVP_ORIGIN_REALM.get(), 0x40, b"visited.invalid"),
        ]
    };

    let mut proxies = core();
    proxies.extend(std::iter::repeat_n(
        proxy_info(b"proxy.private.invalid", b"state"),
        129,
    ));
    let error = swm::parse_swm_abort_session_answer(
        &decode(&wire_message(0x40, HOP_BY_HOP, END_TO_END, proxies)),
        DecodeContext {
            max_ies: 512,
            ..DecodeContext::default()
        },
    )
    .expect_err("129th ASA Proxy-Info must fail");
    assert_eq!(error.code(), &DecodeErrorCode::IeCountExceeded);

    let mut loads = core();
    loads.extend(std::iter::repeat_n(
        wire_avp(swm::AVP_LOAD.get(), 0x00, &load_value()),
        129,
    ));
    let error = swm::parse_swm_abort_session_answer(
        &decode(&wire_message(0x40, HOP_BY_HOP, END_TO_END, loads)),
        DecodeContext {
            max_ies: 512,
            ..DecodeContext::default()
        },
    )
    .expect_err("129th ASA Load/additional AVP must fail");
    assert_eq!(error.code(), &DecodeErrorCode::IeCountExceeded);
}

#[test]
fn grouped_overload_and_load_validation_is_bounded_and_semantic() {
    let mut malformed_offer = asr_avps(Some(0));
    malformed_offer.retain(|avp| {
        u32::from_be_bytes(avp[0..4].try_into().expect("fixed AVP code"))
            != swm::AVP_OC_SUPPORTED_FEATURES.get()
    });
    malformed_offer.push(wire_avp(
        swm::AVP_OC_SUPPORTED_FEATURES.get(),
        0x00,
        &[
            wire_avp(swm::AVP_OC_FEATURE_VECTOR.get(), 0x00, &1_u64.to_be_bytes()),
            wire_avp(swm::AVP_OC_FEATURE_VECTOR.get(), 0x00, &1_u64.to_be_bytes()),
        ]
        .concat(),
    ));
    assert!(swm::parse_swm_abort_session_request(
        &decode(&wire_message(0xc0, HOP_BY_HOP, END_TO_END, malformed_offer,)),
        DecodeContext::default()
    )
    .is_err());

    let mut malformed_load = asa_avps(base::RESULT_CODE_DIAMETER_SUCCESS);
    malformed_load.retain(|avp| {
        u32::from_be_bytes(avp[0..4].try_into().expect("fixed AVP code")) != swm::AVP_LOAD.get()
    });
    malformed_load.push(wire_avp(
        swm::AVP_LOAD.get(),
        0x00,
        &wire_avp(swm::AVP_LOAD_TYPE.get(), 0x00, &2_u32.to_be_bytes()),
    ));
    assert!(swm::parse_swm_abort_session_answer(
        &decode(&wire_message(0x40, HOP_BY_HOP, END_TO_END, malformed_load,)),
        DecodeContext::default()
    )
    .is_err());
}

#[test]
fn received_drmp_and_load_m_mismatches_are_tolerated_but_never_originated() {
    let mut mismatched_drmp = asr_avps(Some(0));
    let drmp = mismatched_drmp
        .iter_mut()
        .find(|avp| {
            u32::from_be_bytes(avp[0..4].try_into().expect("fixed AVP code")) == swm::AVP_DRMP.get()
        })
        .expect("fixture must contain DRMP");
    *drmp = wire_avp(swm::AVP_DRMP.get(), 0x40, &5_u32.to_be_bytes());
    let mismatched_drmp_wire = wire_message(0xc0, HOP_BY_HOP, END_TO_END, mismatched_drmp);
    let parsed =
        parsed_asr(&mismatched_drmp_wire).with_expected_answer_peer(expected_epdg(EPDG_CONNECTION));
    let rebuilt = encode(
        &swm::build_swm_abort_session_request(&parsed, EncodeContext::default())
            .expect("a received DRMP M mismatch must normalize on output"),
    );
    let rebuilt_message = decode(&rebuilt);
    let rebuilt_drmp = rebuilt_message
        .avps(DecodeContext::default())
        .find_map(|avp| {
            let avp = avp.expect("rebuilt AVP framing");
            (avp.header.code == swm::AVP_DRMP).then_some(avp)
        })
        .expect("rebuilt ASR must contain DRMP");
    assert!(!rebuilt_drmp.header.flags.is_mandatory());

    let mut mismatched_load = asa_avps(base::RESULT_CODE_DIAMETER_SUCCESS);
    mismatched_load.retain(|avp| {
        let code = u32::from_be_bytes(avp[0..4].try_into().expect("fixed AVP code"));
        code != swm::AVP_LOAD.get() && code != UNKNOWN_OPTIONAL_AVP
    });
    mismatched_load.push(wire_avp(swm::AVP_LOAD.get(), 0x40, &load_value()));
    let mismatched_load_wire = wire_message(0x40, HOP_BY_HOP, END_TO_END, mismatched_load);
    let parsed_answer = swm::parse_swm_abort_session_answer(
        &decode(&mismatched_load_wire),
        DecodeContext::default(),
    )
    .expect("TS 29.273 requires a known received Load M mismatch to be ignored");
    let mut dictionary_context = DecodeContext::conservative();
    dictionary_context.unknown_ie_policy = UnknownIePolicy::Preserve;
    let (tail, _) = Message::decode_with_dictionary(
        &mismatched_load_wire,
        dictionary_context,
        apps::APP_DICTIONARIES,
    )
    .expect("dictionary decode must apply the same receive-side M-bit tolerance");
    assert!(tail.is_empty());

    let request = parsed_asr(&asr_wire(Some(0)));
    let rebuilt_answer = encode(
        &swm::build_swm_abort_session_answer(&request, &parsed_answer, EncodeContext::default())
            .expect("the encode boundary must normalize a received Load M mismatch"),
    );
    let rebuilt_message = decode(&rebuilt_answer);
    let rebuilt_load = rebuilt_message
        .avps(DecodeContext::default())
        .find_map(|avp| {
            let avp = avp.expect("rebuilt AVP framing");
            (avp.header.code == swm::AVP_LOAD).then_some(avp)
        })
        .expect("rebuilt ASA must contain Load");
    assert!(!rebuilt_load.header.flags.is_mandatory());

    let drop_context = DecodeContext {
        unknown_ie_policy: UnknownIePolicy::Drop,
        ..DecodeContext::default()
    };
    let parsed_answer =
        swm::parse_swm_abort_session_answer(&decode(&mismatched_load_wire), drop_context)
            .expect("receive-only Load M normalization must survive optional-child filtering");
    let rebuilt_answer = encode(
        &swm::build_swm_abort_session_answer(&request, &parsed_answer, EncodeContext::default())
            .expect("a filtered received Load M mismatch must normalize on output"),
    );
    let rebuilt_message = decode(&rebuilt_answer);
    let rebuilt_load = rebuilt_message
        .avps(DecodeContext::default())
        .find_map(|avp| {
            let avp = avp.expect("rebuilt filtered AVP framing");
            (avp.header.code == swm::AVP_LOAD).then_some(avp)
        })
        .expect("rebuilt filtered ASA must contain Load");
    assert!(!rebuilt_load.header.flags.is_mandatory());
}

#[test]
fn answer_builder_is_request_bound_uses_explicit_local_origin_and_emits_complete_results() {
    let request = parsed_asr(&asr_wire(Some(0)));
    let explicit_origin_answer = SwmAbortSessionAnswer::for_request(
        &request,
        SwmAbortSessionResult::Success,
        "local-epdg.private.invalid",
        "local-visited.invalid",
    );
    swm::build_swm_abort_session_answer(
        &request,
        &explicit_origin_answer,
        EncodeContext::default(),
    )
    .expect("ASA local Origin must not be inferred from unauthenticated Destination AVPs");

    let answer = asa_for_request(&request, SwmAbortSessionResult::Success);
    swm::build_swm_abort_session_answer(&request, &answer, EncodeContext::default())
        .expect("ASA may decline an offered overload capability by omitting it");

    for result in [
        SwmAbortSessionResult::Success,
        SwmAbortSessionResult::UnknownSession,
        SwmAbortSessionResult::UnableToComply,
    ] {
        let mut answer = asa_for_request(&request, result);
        if request
            .request()
            .additional_avps
            .iter()
            .any(|avp| avp.code() == swm::AVP_OC_SUPPORTED_FEATURES)
        {
            answer.additional_avps.push(
                SwmAdditionalAvp::new(
                    AvpHeader::ietf(swm::AVP_OC_SUPPORTED_FEATURES, false),
                    oc_supported_value(),
                    EncodeContext::default(),
                )
                .expect("OC echo must frame"),
            );
        }
        let built =
            swm::build_swm_abort_session_answer(&request, &answer, EncodeContext::default())
                .expect("modeled ASA result must build");
        assert!(
            !built.header.flags.is_error(),
            "2001/5002/5012 must keep E clear"
        );
    }

    let answer = asa_for_request(&request, SwmAbortSessionResult::Other(3_002));
    assert!(
        swm::build_swm_abort_session_answer(&request, &answer, EncodeContext::default()).is_err()
    );
}

#[test]
fn diagnostics_redact_session_identity_proxy_and_extension_values() {
    let request = parsed_asr(&asr_wire(Some(0)));
    let debug = format!("{request:?}");
    for sensitive in [
        SESSION_ID,
        USER_NAME,
        "aaa.private.invalid",
        "epdg.private.invalid",
        "private-state-one",
        "private-extension",
    ] {
        assert!(!debug.contains(sensitive));
    }
    let additional = SwmAdditionalAvp::new(
        AvpHeader::ietf(AvpCode::new(UNKNOWN_OPTIONAL_AVP), false),
        b"secret-value".to_vec(),
        EncodeContext::default(),
    )
    .expect("optional AVP must frame");
    assert!(!format!("{additional:?}").contains("secret-value"));
    assert!(!additional.to_string().contains("secret-value"));
}

#[test]
fn dictionary_declares_exact_asr_asa_roles_and_repeatability() {
    let request = swm::dictionary()
        .find_command(
            swm::APPLICATION_ID,
            swm::COMMAND_ABORT_SESSION,
            opc_proto_diameter::CommandKind::Request,
        )
        .expect("ASR command definition must exist");
    let answer = swm::dictionary()
        .find_command(
            swm::APPLICATION_ID,
            swm::COMMAND_ABORT_SESSION,
            opc_proto_diameter::CommandKind::Answer,
        )
        .expect("ASA command definition must exist");
    assert!(request.proxiable());
    assert!(answer.proxiable());
    assert!(request.allows_multiple(AvpKey::ietf(base::AVP_PROXY_INFO)));
    assert!(request.allows_multiple(AvpKey::ietf(base::AVP_ROUTE_RECORD)));
    assert!(request.allows_multiple(AvpKey::ietf(base::AVP_CLASS)));
    assert!(request.allows_multiple(AvpKey::ietf(swm::AVP_REPLY_MESSAGE)));
    assert!(!request.allows_multiple(AvpKey::ietf(swm::AVP_STATE)));
    assert!(!answer.allows_multiple(AvpKey::ietf(base::AVP_CLASS)));
    assert!(!answer.allows_multiple(AvpKey::ietf(swm::AVP_STATE)));
    assert!(answer.allows_multiple(AvpKey::ietf(base::AVP_FAILED_AVP)));
    assert!(answer.allows_multiple(AvpKey::ietf(base::AVP_REDIRECT_HOST)));
    assert!(answer.allows_multiple(AvpKey::ietf(swm::AVP_LOAD)));
    assert!(!request.allows_multiple(AvpKey::ietf(base::AVP_SESSION_ID)));
    assert!(!answer.allows_multiple(AvpKey::ietf(base::AVP_RESULT_CODE)));
    assert!(!answer.allows_multiple(AvpKey::ietf(base::AVP_REDIRECT_HOST_USAGE)));
    assert!(!answer.allows_multiple(AvpKey::ietf(base::AVP_REDIRECT_MAX_CACHE_TIME)));
    for forbidden in [
        base::AVP_ERROR_MESSAGE,
        base::AVP_ERROR_REPORTING_HOST,
        base::AVP_FAILED_AVP,
        base::AVP_REDIRECT_HOST,
        base::AVP_REDIRECT_HOST_USAGE,
        base::AVP_REDIRECT_MAX_CACHE_TIME,
    ] {
        assert!(
            request
                .find_avp_rule(AvpKey::ietf(forbidden))
                .is_some_and(|rule| rule.cardinality().is_forbidden()),
            "ASR must explicitly forbid answer-only AVP {}",
            forbidden.get()
        );
    }
}

#[test]
fn asa_command_cardinality_accepts_declared_repetition_only() {
    let mut avps = asa_avps(base::RESULT_CODE_DIAMETER_UNABLE_TO_COMPLY);
    let proxy_index = avps
        .iter()
        .position(|avp| {
            u32::from_be_bytes(avp[0..4].try_into().expect("fixed AVP code"))
                == base::AVP_PROXY_INFO.get()
        })
        .expect("ASA fixture has Proxy-Info");
    avps.insert(
        proxy_index,
        wire_avp(
            base::AVP_FAILED_AVP.get(),
            0x40,
            &wire_avp(base::AVP_SESSION_ID.get(), 0x40, b"redacted-one"),
        ),
    );
    avps.insert(
        proxy_index + 1,
        wire_avp(
            base::AVP_FAILED_AVP.get(),
            0x40,
            &wire_avp(base::AVP_SESSION_ID.get(), 0x40, b"redacted-two"),
        ),
    );
    let wire = wire_message(0x40, HOP_BY_HOP, END_TO_END, avps);

    let (tail, _) = Message::decode_with_dictionary(
        &wire,
        DecodeContext::conservative(),
        apps::APP_DICTIONARIES,
    )
    .expect("RFC 4005 ASA Failed-AVP is explicitly repeatable");
    assert!(tail.is_empty());

    let parsed = swm::parse_swm_abort_session_answer_envelope_from_connection(
        &decode(&wire),
        connection(EPDG_CONNECTION),
        DecodeContext::default(),
    )
    .expect("typed ASA boundary must retain declared Failed-AVP values");
    assert_eq!(
        parsed
            .answer()
            .additional_avps
            .iter()
            .filter(|avp| avp.code() == base::AVP_FAILED_AVP)
            .count(),
        2
    );
    let request = parsed_asr(&asr_wire(Some(0)));
    assert_eq!(
        encode(
            &swm::build_swm_abort_session_answer(
                &request,
                parsed.answer(),
                EncodeContext::default(),
            )
            .expect("command-derived Failed-AVP repeatability must survive typed rebuild"),
        ),
        wire
    );

    let mut duplicated_wildcard = asa_avps(base::RESULT_CODE_DIAMETER_SUCCESS);
    duplicated_wildcard.push(wire_avp(
        UNKNOWN_OPTIONAL_AVP,
        0x00,
        b"second-private-answer-extension",
    ));
    let error = Message::decode_with_dictionary(
        &wire_message(0x40, HOP_BY_HOP, END_TO_END, duplicated_wildcard),
        DecodeContext::conservative(),
        apps::APP_DICTIONARIES,
    )
    .expect_err("the generic extension wildcard must not imply repeatability");
    assert_eq!(error.code(), &DecodeErrorCode::DuplicateIe);
}

#[test]
fn asa_redirect_cardinality_is_dictionary_visible_but_typed_redirect_is_unsupported() {
    let mut avps = asa_avps(3_006);
    let proxy_index = avps
        .iter()
        .position(|avp| {
            u32::from_be_bytes(avp[0..4].try_into().expect("fixed AVP code"))
                == base::AVP_PROXY_INFO.get()
        })
        .expect("ASA fixture has Proxy-Info");
    avps.insert(
        proxy_index,
        wire_avp(
            base::AVP_REDIRECT_HOST.get(),
            0x40,
            b"aaa://redirect-one.example.invalid",
        ),
    );
    avps.insert(
        proxy_index + 1,
        wire_avp(
            base::AVP_REDIRECT_HOST.get(),
            0x40,
            b"aaa://redirect-two.example.invalid;transport=sctp",
        ),
    );
    avps.insert(
        proxy_index + 2,
        wire_avp(
            base::AVP_REDIRECT_HOST_USAGE.get(),
            0x40,
            &0_u32.to_be_bytes(),
        ),
    );
    avps.insert(
        proxy_index + 3,
        wire_avp(
            base::AVP_REDIRECT_MAX_CACHE_TIME.get(),
            0x40,
            &60_u32.to_be_bytes(),
        ),
    );
    let wire = wire_message(0x60, HOP_BY_HOP, END_TO_END, avps.clone());
    let (tail, _) = Message::decode_with_dictionary(
        &wire,
        DecodeContext::conservative(),
        apps::APP_DICTIONARIES,
    )
    .expect("RFC 4005 ASA Redirect-Host is explicitly repeatable");
    assert!(tail.is_empty());
    swm::parse_swm_abort_session_answer(&decode(&wire), DecodeContext::default())
        .expect_err("typed ASA must reject redirect until its result semantics are modeled");

    avps.insert(
        proxy_index + 4,
        wire_avp(
            base::AVP_REDIRECT_HOST_USAGE.get(),
            0x40,
            &1_u32.to_be_bytes(),
        ),
    );
    let error = Message::decode_with_dictionary(
        &wire_message(0x60, HOP_BY_HOP, END_TO_END, avps),
        DecodeContext::conservative(),
        apps::APP_DICTIONARIES,
    )
    .expect_err("Redirect-Host-Usage remains singleton");
    assert_eq!(error.code(), &DecodeErrorCode::DuplicateIe);

    let mut wrong_flags = asa_avps(3_006);
    wrong_flags.push(wire_avp(
        base::AVP_REDIRECT_HOST.get(),
        0x00,
        b"aaa://redirect.example.invalid",
    ));
    let wrong_flags = wire_message(0x60, HOP_BY_HOP, END_TO_END, wrong_flags);
    swm::parse_swm_abort_session_answer(&decode(&wrong_flags), DecodeContext::default())
        .expect_err("typed Redirect-Host validation must require the RFC 6733 M bit");

    let request = parsed_asr(&asr_wire(Some(0)));
    let mut answer = asa_for_request(&request, SwmAbortSessionResult::Success);
    answer.additional_avps.push(
        SwmAdditionalAvp::new(
            AvpHeader::ietf(base::AVP_REDIRECT_HOST, true),
            b"aaa://redirect.example.invalid".to_vec(),
            EncodeContext::default(),
        )
        .expect("valid Redirect-Host is structurally framed"),
    );
    swm::build_swm_abort_session_answer(&request, &answer, EncodeContext::default())
        .expect_err("typed ASA builder must not originate unsupported redirect context");
}

#[test]
fn asr_rfc_4005_state_and_reply_message_cardinality_round_trip() {
    let mut avps = asr_avps(Some(0));
    let class_index = avps
        .iter()
        .position(|avp| {
            u32::from_be_bytes(avp[0..4].try_into().expect("fixed AVP code"))
                == base::AVP_CLASS.get()
        })
        .expect("ASR fixture has Class");
    avps.insert(
        class_index,
        wire_avp(swm::AVP_STATE.get(), 0x00, b"opaque-state"),
    );
    avps.insert(
        class_index + 1,
        wire_avp(swm::AVP_REPLY_MESSAGE.get(), 0x40, b"first prompt"),
    );
    avps.insert(
        class_index + 2,
        wire_avp(swm::AVP_REPLY_MESSAGE.get(), 0x40, b"second prompt"),
    );
    let wire = wire_message(0xc0, HOP_BY_HOP, END_TO_END, avps.clone());
    let (tail, _) = Message::decode_with_dictionary(
        &wire,
        DecodeContext::conservative(),
        apps::APP_DICTIONARIES,
    )
    .expect("RFC 4005 ASR permits repeated Reply-Message");
    assert!(tail.is_empty());
    let parsed = parsed_outbound_asr(&wire);
    assert_eq!(
        encode(
            &swm::build_swm_abort_session_request(&parsed, EncodeContext::default())
                .expect("State and repeated Reply-Message must rebuild")
        ),
        wire
    );

    avps.push(wire_avp(swm::AVP_STATE.get(), 0x00, b"second-state"));
    let error = Message::decode_with_dictionary(
        &wire_message(0xc0, HOP_BY_HOP, END_TO_END, avps),
        DecodeContext::conservative(),
        apps::APP_DICTIONARIES,
    )
    .expect_err("RFC 4005 ASR State remains singleton");
    assert_eq!(error.code(), &DecodeErrorCode::DuplicateIe);
}

#[test]
fn asr_explicit_answer_only_forbiddens_apply_at_dictionary_decode() {
    for forbidden in [
        wire_avp(base::AVP_ERROR_MESSAGE.get(), 0x00, b"redacted"),
        wire_avp(
            base::AVP_ERROR_REPORTING_HOST.get(),
            0x00,
            b"reporter.example.invalid",
        ),
        wire_avp(
            base::AVP_FAILED_AVP.get(),
            0x40,
            &wire_avp(base::AVP_SESSION_ID.get(), 0x40, b"redacted"),
        ),
        wire_avp(
            base::AVP_REDIRECT_HOST.get(),
            0x40,
            b"aaa://redirect.example.invalid",
        ),
    ] {
        let mut avps = asr_avps(Some(0));
        avps.push(forbidden);
        let error = Message::decode_with_dictionary(
            &wire_message(0xc0, HOP_BY_HOP, END_TO_END, avps),
            DecodeContext::conservative(),
            apps::APP_DICTIONARIES,
        )
        .expect_err("ASR answer-only AVP must be explicitly forbidden");
        assert_eq!(error.code(), &DecodeErrorCode::UnknownCriticalIe);
    }
}

#[test]
fn builder_rejects_non_ascii_diameter_identities_and_unoffered_overload() {
    let request = SwmAbortSessionRequest {
        session_id: SESSION_ID.into(),
        origin_host: "hést.invalid".into(),
        origin_realm: "aaa.invalid".into(),
        destination_realm: "visited.invalid".into(),
        destination_host: "epdg.invalid".into(),
        user_name: USER_NAME.into(),
        auth_session_state: None,
        origin_state_id: None,
        drmp: SwmRoutingMessagePriority::new(5),
        route_records: Vec::new(),
        additional_avps: Vec::new(),
    };
    let pending = SwmAbortSessionRequestEnvelope::for_outbound(
        request,
        SwmDiameterTransaction::new(HOP_BY_HOP, END_TO_END),
        expected_epdg(EPDG_CONNECTION),
    );
    assert!(swm::build_swm_abort_session_request(&pending, EncodeContext::default()).is_err());

    let mut request_avps = asr_avps(Some(0));
    request_avps.retain(|avp| {
        u32::from_be_bytes(avp[0..4].try_into().expect("fixed AVP code"))
            != swm::AVP_OC_SUPPORTED_FEATURES.get()
    });
    let request = parsed_asr(&wire_message(0xc0, HOP_BY_HOP, END_TO_END, request_avps));
    let mut answer = asa_for_request(&request, SwmAbortSessionResult::Success);
    answer.additional_avps.push(
        SwmAdditionalAvp::new(
            AvpHeader::ietf(swm::AVP_OC_SUPPORTED_FEATURES, false),
            oc_supported_value(),
            EncodeContext::default(),
        )
        .expect("OC selection must frame"),
    );
    assert!(
        swm::build_swm_abort_session_answer(&request, &answer, EncodeContext::default()).is_err()
    );
}
