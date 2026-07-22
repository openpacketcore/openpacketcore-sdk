#![cfg(feature = "app-swm")]

use std::{collections::HashMap, num::NonZeroU64};

use bytes::BytesMut;
use opc_proto_diameter::apps::swm::{
    self, SwmDiameterEapAgentDeliveryFailure, SwmDiameterEapCorrelationError,
    SwmDiameterEapGenericErrorAnswer, SwmDiameterEapRequestEnvelope, SwmDiameterEapResponse,
    SwmDiameterResult, SwmExpectedAnswerPeer,
};
use opc_proto_diameter::apps::VENDOR_ID_3GPP;
use opc_proto_diameter::dictionary::AvpKey;
use opc_proto_diameter::{base, AvpCode, AvpFlags, CommandFlags, Message, OwnedMessage, VendorId};
use opc_protocol::{
    BorrowDecode, DecodeContext, DuplicateIePolicy, Encode, EncodeContext, UnknownIePolicy,
};

const HOP_BY_HOP: u32 = 0x1020_3040;
const END_TO_END: u32 = 0x5060_7080;
const SESSION_ID: &[u8] = b"session;synthetic;agent-error";
const OTHER_SESSION_ID: &[u8] = b"session;synthetic;other";
const EPDG_HOST: &[u8] = b"epdg.synthetic.example";
const EPDG_REALM: &[u8] = b"visited.synthetic.example";
const HOME_REALM: &[u8] = b"home.synthetic.example";
const HOME_HOST: &[u8] = b"aaa.synthetic.example";
const DRA_HOST: &[u8] = b"dra.synthetic.example";
const DRA_REALM: &[u8] = b"routing.synthetic.example";
const PROXY_ONE_HOST: &[u8] = b"proxy-one.synthetic.example";
const PROXY_ONE_STATE: &[u8] = b"opaque-proxy-one-state";
const PROXY_TWO_HOST: &[u8] = b"proxy-two.synthetic.example";
const PROXY_TWO_STATE: &[u8] = b"opaque-proxy-two-state";
const CONNECTION_ONE: swm::SwmDiameterConnectionToken =
    swm::SwmDiameterConnectionToken::new(NonZeroU64::MIN);
const CONNECTION_TWO: swm::SwmDiameterConnectionToken =
    swm::SwmDiameterConnectionToken::new(NonZeroU64::new(2).expect("nonzero constant"));

fn put_u24(dst: &mut Vec<u8>, value: usize) {
    let value = u32::try_from(value).expect("synthetic fixture length fits u32");
    dst.extend_from_slice(&value.to_be_bytes()[1..]);
}

fn raw_avp(code: AvpCode, flags: u8, vendor_id: Option<VendorId>, value: &[u8]) -> Vec<u8> {
    assert_eq!(flags & AvpFlags::VENDOR != 0, vendor_id.is_some());
    let header_len = if vendor_id.is_some() { 12 } else { 8 };
    let length = header_len + value.len();
    let mut wire = Vec::with_capacity((length + 3) & !3);
    wire.extend_from_slice(&code.get().to_be_bytes());
    wire.push(flags);
    put_u24(&mut wire, length);
    if let Some(vendor_id) = vendor_id {
        wire.extend_from_slice(&vendor_id.get().to_be_bytes());
    }
    wire.extend_from_slice(value);
    wire.resize((length + 3) & !3, 0);
    wire
}

fn mandatory_avp(code: AvpCode, value: &[u8]) -> Vec<u8> {
    raw_avp(code, AvpFlags::MANDATORY, None, value)
}

fn proxy_info(host: &[u8], state: &[u8]) -> Vec<u8> {
    let mut value = mandatory_avp(base::AVP_PROXY_HOST, host);
    value.extend_from_slice(&mandatory_avp(base::AVP_PROXY_STATE, state));
    mandatory_avp(base::AVP_PROXY_INFO, &value)
}

fn message_wire(
    flags: CommandFlags,
    hop_by_hop: u32,
    end_to_end: u32,
    avps: &[Vec<u8>],
) -> Vec<u8> {
    let raw_avps = avps.iter().flatten().copied().collect::<Vec<_>>();
    let length = 20_usize
        .checked_add(raw_avps.len())
        .expect("synthetic fixture length");
    let mut wire = Vec::with_capacity(length);
    wire.push(1);
    put_u24(&mut wire, length);
    wire.push(flags.bits());
    put_u24(
        &mut wire,
        usize::try_from(swm::COMMAND_DIAMETER_EAP.get()).expect("command code fits usize"),
    );
    wire.extend_from_slice(&swm::APPLICATION_ID.get().to_be_bytes());
    wire.extend_from_slice(&hop_by_hop.to_be_bytes());
    wire.extend_from_slice(&end_to_end.to_be_bytes());
    wire.extend_from_slice(&raw_avps);
    wire
}

fn encode(message: &OwnedMessage) -> Vec<u8> {
    let mut wire = BytesMut::new();
    message
        .encode(&mut wire, EncodeContext::default())
        .expect("synthetic Diameter message encodes");
    wire.to_vec()
}

fn framing_context() -> DecodeContext {
    DecodeContext {
        max_ies: 512,
        max_message_len: 256 * 1024,
        duplicate_ie_policy: DuplicateIePolicy::Last,
        unknown_ie_policy: UnknownIePolicy::Preserve,
        ..DecodeContext::default()
    }
}

fn typed_context(unknown_ie_policy: UnknownIePolicy) -> DecodeContext {
    DecodeContext {
        max_ies: 512,
        max_message_len: 256 * 1024,
        duplicate_ie_policy: DuplicateIePolicy::Last,
        unknown_ie_policy,
        ..DecodeContext::conservative()
    }
}

fn decode(wire: &[u8]) -> Message<'_> {
    let (tail, message) = Message::decode(wire, framing_context()).expect("Diameter framing");
    assert!(tail.is_empty());
    message
}

fn request_avps(
    eap_payload: &[u8],
    destination_host: Option<&[u8]>,
    proxies: &[Vec<u8>],
) -> Vec<Vec<u8>> {
    let mut avps = vec![
        mandatory_avp(base::AVP_SESSION_ID, SESSION_ID),
        mandatory_avp(
            base::AVP_AUTH_APPLICATION_ID,
            &swm::APPLICATION_ID.get().to_be_bytes(),
        ),
        mandatory_avp(base::AVP_ORIGIN_HOST, EPDG_HOST),
        mandatory_avp(base::AVP_ORIGIN_REALM, EPDG_REALM),
        mandatory_avp(base::AVP_DESTINATION_REALM, HOME_REALM),
        mandatory_avp(
            swm::AVP_AUTH_REQUEST_TYPE,
            &swm::AUTH_REQUEST_TYPE_AUTHORIZE_AUTHENTICATE.to_be_bytes(),
        ),
        mandatory_avp(swm::AVP_EAP_PAYLOAD, eap_payload),
    ];
    if let Some(destination_host) = destination_host {
        avps.push(mandatory_avp(base::AVP_DESTINATION_HOST, destination_host));
    }
    avps.extend_from_slice(proxies);
    avps
}

fn parsed_request_without_destination_host(
    hop_by_hop: u32,
    eap_payload: &[u8],
    proxies: &[Vec<u8>],
) -> SwmDiameterEapRequestEnvelope {
    let wire = message_wire(
        CommandFlags::request(true),
        hop_by_hop,
        END_TO_END,
        &request_avps(eap_payload, None, proxies),
    );
    swm::parse_swm_diameter_eap_request_envelope(
        &decode(&wire),
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect("synthetic realm-routed SWm DER")
}

fn request_wire(hop_by_hop: u32, eap_payload: &[u8], proxies: &[Vec<u8>]) -> Vec<u8> {
    message_wire(
        CommandFlags::request(true),
        hop_by_hop,
        END_TO_END,
        &request_avps(eap_payload, Some(HOME_HOST), proxies),
    )
}

fn parsed_request(
    hop_by_hop: u32,
    eap_payload: &[u8],
    proxies: &[Vec<u8>],
) -> SwmDiameterEapRequestEnvelope {
    let wire = request_wire(hop_by_hop, eap_payload, proxies);
    swm::parse_swm_diameter_eap_request_envelope(
        &decode(&wire),
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect("synthetic SWm DER")
}

fn bound_request(
    connection: swm::SwmDiameterConnectionToken,
    hop_by_hop: u32,
    eap_payload: &[u8],
    proxies: &[Vec<u8>],
) -> SwmDiameterEapRequestEnvelope {
    parsed_request(hop_by_hop, eap_payload, proxies).with_expected_answer_peer(
        SwmExpectedAnswerPeer::routed_via(
            connection,
            "dra.synthetic.example",
            "routing.synthetic.example",
        ),
    )
}

fn agent_error_avps_from_origin(
    result_code: u32,
    session_id: Option<&[u8]>,
    origin_host: &[u8],
    origin_realm: &[u8],
    proxies: &[Vec<u8>],
    extras: &[Vec<u8>],
) -> Vec<Vec<u8>> {
    let mut avps = Vec::new();
    if let Some(session_id) = session_id {
        avps.push(mandatory_avp(base::AVP_SESSION_ID, session_id));
    }
    avps.push(mandatory_avp(base::AVP_ORIGIN_HOST, origin_host));
    avps.push(mandatory_avp(base::AVP_ORIGIN_REALM, origin_realm));
    avps.push(mandatory_avp(
        base::AVP_RESULT_CODE,
        &result_code.to_be_bytes(),
    ));
    avps.extend_from_slice(proxies);
    avps.extend_from_slice(extras);
    avps
}

fn agent_error_avps(
    result_code: u32,
    session_id: Option<&[u8]>,
    proxies: &[Vec<u8>],
    extras: &[Vec<u8>],
) -> Vec<Vec<u8>> {
    agent_error_avps_from_origin(
        result_code,
        session_id,
        DRA_HOST,
        DRA_REALM,
        proxies,
        extras,
    )
}

fn agent_error_wire(
    result_code: u32,
    hop_by_hop: u32,
    session_id: Option<&[u8]>,
    proxies: &[Vec<u8>],
    extras: &[Vec<u8>],
) -> Vec<u8> {
    message_wire(
        CommandFlags::answer(true, true),
        hop_by_hop,
        END_TO_END,
        &agent_error_avps(result_code, session_id, proxies, extras),
    )
}

fn agent_error_wire_from_origin(
    result_code: u32,
    hop_by_hop: u32,
    origin_host: &[u8],
    origin_realm: &[u8],
) -> Vec<u8> {
    message_wire(
        CommandFlags::answer(true, true),
        hop_by_hop,
        END_TO_END,
        &agent_error_avps_from_origin(
            result_code,
            Some(SESSION_ID),
            origin_host,
            origin_realm,
            &[],
            &[],
        ),
    )
}

fn build_agent_error(
    request: &SwmDiameterEapRequestEnvelope,
    failure: SwmDiameterEapAgentDeliveryFailure,
) -> OwnedMessage {
    let answer = SwmDiameterEapGenericErrorAnswer::new_agent_delivery_failure_for(
        request,
        failure,
        String::from_utf8(DRA_HOST.to_vec()).expect("ASCII host"),
        String::from_utf8(DRA_REALM.to_vec()).expect("ASCII realm"),
    )
    .expect("request-bound agent error");
    swm::build_swm_diameter_eap_response_for(
        request,
        &SwmDiameterEapResponse::GenericError(Box::new(answer)),
        EncodeContext::default(),
    )
    .expect("request-bound generic response")
}

fn avp_keys(wire: &[u8]) -> Vec<AvpKey> {
    decode(wire)
        .avps(framing_context())
        .map(|avp| avp.expect("framed AVP").header.key())
        .collect()
}

#[test]
fn exact_3002_and_3004_fixtures_preserve_request_envelope_and_generic_grammar() {
    let proxies = vec![
        proxy_info(PROXY_ONE_HOST, PROXY_ONE_STATE),
        proxy_info(PROXY_TWO_HOST, PROXY_TWO_STATE),
    ];
    let request = parsed_request(
        HOP_BY_HOP,
        &[0x02, 0x19, 0x00, 0x08, 0x32, 0xaa, 0xbb, 0xcc],
        &proxies,
    );

    for (failure, expected_result_code) in [
        (
            SwmDiameterEapAgentDeliveryFailure::UnableToDeliver,
            3_002_u32,
        ),
        (SwmDiameterEapAgentDeliveryFailure::TooBusy, 3_004_u32),
    ] {
        let built = build_agent_error(&request, failure);
        let wire = encode(&built);
        let expected = agent_error_wire(
            expected_result_code,
            HOP_BY_HOP,
            Some(SESSION_ID),
            &proxies,
            &[],
        );
        assert_eq!(wire, expected, "independently authored exact wire fixture");
        assert_eq!(failure.result_code(), expected_result_code);
        assert!(!built.header.flags.is_request());
        assert!(built.header.flags.is_proxiable());
        assert!(built.header.flags.is_error());
        assert!(!built.header.flags.is_potentially_retransmitted());
        assert_eq!(built.header.hop_by_hop_identifier, HOP_BY_HOP);
        assert_eq!(built.header.end_to_end_identifier, END_TO_END);

        let keys = avp_keys(&wire);
        assert_eq!(
            keys,
            vec![
                AvpKey::ietf(base::AVP_SESSION_ID),
                AvpKey::ietf(base::AVP_ORIGIN_HOST),
                AvpKey::ietf(base::AVP_ORIGIN_REALM),
                AvpKey::ietf(base::AVP_RESULT_CODE),
                AvpKey::ietf(base::AVP_PROXY_INFO),
                AvpKey::ietf(base::AVP_PROXY_INFO),
            ]
        );
        for omitted in [
            base::AVP_AUTH_APPLICATION_ID,
            swm::AVP_AUTH_REQUEST_TYPE,
            swm::AVP_EAP_PAYLOAD,
            swm::AVP_EAP_REISSUED_PAYLOAD,
            swm::AVP_EAP_MASTER_SESSION_KEY,
            base::AVP_USER_NAME,
        ] {
            assert!(!keys.contains(&AvpKey::ietf(omitted)));
        }
    }
}

#[test]
fn typed_constructor_rejects_mutation_and_a_different_request_envelope() {
    let proxies = vec![proxy_info(PROXY_ONE_HOST, PROXY_ONE_STATE)];
    let first = parsed_request(
        HOP_BY_HOP,
        &[0x02, 0x20, 0x00, 0x08, 0x32, 0x01, 0x02, 0x03],
        &proxies,
    );
    let answer = SwmDiameterEapGenericErrorAnswer::new_agent_delivery_failure_for(
        &first,
        SwmDiameterEapAgentDeliveryFailure::UnableToDeliver,
        "dra.synthetic.example",
        "routing.synthetic.example",
    )
    .expect("bound answer");

    let mut changed_result = answer.clone();
    changed_result.result_code = 3003;
    swm::build_swm_diameter_eap_response_for(
        &first,
        &SwmDiameterEapResponse::GenericError(Box::new(changed_result)),
        EncodeContext::default(),
    )
    .expect_err("unmodeled result cannot inherit agent-delivery provenance");

    let mut changed_session = answer.clone();
    changed_session.session_id = Some("session;synthetic;changed".into());
    swm::build_swm_diameter_eap_response_for(
        &first,
        &SwmDiameterEapResponse::GenericError(Box::new(changed_session)),
        EncodeContext::default(),
    )
    .expect_err("Session-Id must remain copied from the bound request");

    let mut changed_context = answer.clone();
    changed_context.experimental_result = Some(SwmDiameterResult::Experimental {
        vendor_id: VendorId::new(10_415),
        code: 5_001,
    });
    swm::build_swm_diameter_eap_response_for(
        &first,
        &SwmDiameterEapResponse::GenericError(Box::new(changed_context)),
        EncodeContext::default(),
    )
    .expect_err("agent-delivery provenance cannot acquire other result context");

    let changed_payload = parsed_request(
        HOP_BY_HOP,
        &[0x02, 0x20, 0x00, 0x08, 0x32, 0x01, 0x02, 0x04],
        &proxies,
    );
    swm::build_swm_diameter_eap_response_for(
        &changed_payload,
        &SwmDiameterEapResponse::GenericError(Box::new(answer.clone())),
        EncodeContext::default(),
    )
    .expect_err("a conflicting request reusing the transaction must not match");

    let changed_transaction = parsed_request(
        HOP_BY_HOP ^ 1,
        &[0x02, 0x20, 0x00, 0x08, 0x32, 0x01, 0x02, 0x03],
        &proxies,
    );
    swm::build_swm_diameter_eap_response_for(
        &changed_transaction,
        &SwmDiameterEapResponse::GenericError(Box::new(answer)),
        EncodeContext::default(),
    )
    .expect_err("another transaction cannot use the bound response");

    SwmDiameterEapGenericErrorAnswer::new_agent_delivery_failure_for(
        &first,
        SwmDiameterEapAgentDeliveryFailure::TooBusy,
        "",
        "routing.synthetic.example",
    )
    .expect_err("producing DRA Origin-Host is required");
    SwmDiameterEapGenericErrorAnswer::new_agent_delivery_failure_for(
        &first,
        SwmDiameterEapAgentDeliveryFailure::TooBusy,
        "dra.synthetic.example",
        "",
    )
    .expect_err("producing DRA Origin-Realm is required");

    let no_destination_host = parsed_request_without_destination_host(
        HOP_BY_HOP,
        &[0x02, 0x20, 0x00, 0x08, 0x32, 0x01, 0x02, 0x03],
        &proxies,
    );
    SwmDiameterEapGenericErrorAnswer::new_agent_delivery_failure_for(
        &no_destination_host,
        SwmDiameterEapAgentDeliveryFailure::TooBusy,
        "dra.synthetic.example",
        "routing.synthetic.example",
    )
    .expect_err("RFC 6733 permits 3004 only for a specifically requested server");
    SwmDiameterEapGenericErrorAnswer::new_agent_delivery_failure_for(
        &no_destination_host,
        SwmDiameterEapAgentDeliveryFailure::UnableToDeliver,
        "dra.synthetic.example",
        "routing.synthetic.example",
    )
    .expect("3002 does not require Destination-Host");
}

#[test]
fn parsed_generic_agent_errors_cannot_be_reoriginated() {
    let request = parsed_request(
        HOP_BY_HOP,
        &[0x02, 0x21, 0x00, 0x08, 0x32, 0x11, 0x22, 0x33],
        &[],
    );
    for result_code in [
        base::RESULT_CODE_DIAMETER_UNABLE_TO_DELIVER,
        base::RESULT_CODE_DIAMETER_TOO_BUSY,
    ] {
        let wire = agent_error_wire(result_code, HOP_BY_HOP, Some(SESSION_ID), &[], &[]);
        let parsed = swm::parse_swm_diameter_eap_response(
            &decode(&wire),
            typed_context(UnknownIePolicy::Preserve),
        )
        .expect("valid received generic agent error");
        swm::build_swm_diameter_eap_response_for(&request, &parsed, EncodeContext::default())
            .expect_err("parsed evidence must not gain outbound provenance");
    }
}

#[test]
fn agent_delivery_profile_rejects_application_avps_but_retains_bounded_unknowns() {
    let application_avps = [
        mandatory_avp(
            base::AVP_AUTH_APPLICATION_ID,
            &swm::APPLICATION_ID.get().to_be_bytes(),
        ),
        mandatory_avp(
            swm::AVP_AUTH_REQUEST_TYPE,
            &swm::AUTH_REQUEST_TYPE_AUTHORIZE_AUTHENTICATE.to_be_bytes(),
        ),
        mandatory_avp(swm::AVP_EAP_PAYLOAD, &[0x03, 0x01, 0x00, 0x04]),
        mandatory_avp(base::AVP_USER_NAME, b"subscriber-sentinel"),
        mandatory_avp(swm::AVP_MIP6_FEATURE_VECTOR, &1_u64.to_be_bytes()),
        raw_avp(
            swm::AVP_APN_OI_REPLACEMENT,
            AvpFlags::VENDOR | AvpFlags::MANDATORY,
            Some(VENDOR_ID_3GPP),
            b"apn.synthetic.example",
        ),
    ];
    for application_avp in application_avps {
        let wire = agent_error_wire(
            base::RESULT_CODE_DIAMETER_UNABLE_TO_DELIVER,
            HOP_BY_HOP,
            Some(SESSION_ID),
            &[],
            &[application_avp],
        );
        swm::parse_swm_diameter_eap_response(
            &decode(&wire),
            typed_context(UnknownIePolicy::Preserve),
        )
        .expect_err("agent delivery errors must omit application-only AVPs");
    }

    let generic_priority = raw_avp(swm::AVP_DRMP, 0, None, &5_u32.to_be_bytes());
    let generic_base = raw_avp(base::AVP_PRODUCT_NAME, 0, None, b"synthetic-dra-product");
    let generic_priority_wire = agent_error_wire(
        base::RESULT_CODE_DIAMETER_UNABLE_TO_DELIVER,
        HOP_BY_HOP,
        Some(SESSION_ID),
        &[],
        &[generic_priority, generic_base],
    );
    let parsed = swm::parse_swm_diameter_eap_response(
        &decode(&generic_priority_wire),
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect("RFC 7944 DRMP remains a valid generic wildcard AVP");
    let SwmDiameterEapResponse::GenericError(answer) = parsed else {
        panic!("E-bit response must use generic grammar");
    };
    assert_eq!(answer.additional_avp_count(), 2);

    let foreign_collision = raw_avp(
        swm::AVP_EAP_PAYLOAD,
        AvpFlags::VENDOR,
        Some(VendorId::new(42_424)),
        b"foreign-vendor-opaque",
    );
    let foreign_collision_wire = agent_error_wire(
        base::RESULT_CODE_DIAMETER_UNABLE_TO_DELIVER,
        HOP_BY_HOP,
        Some(SESSION_ID),
        &[],
        &[foreign_collision],
    );
    let parsed = swm::parse_swm_diameter_eap_response(
        &decode(&foreign_collision_wire),
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect("full-key foreign-vendor collision remains an unknown optional AVP");
    let SwmDiameterEapResponse::GenericError(answer) = parsed else {
        panic!("E-bit response must use generic grammar");
    };
    assert_eq!(answer.additional_avp_count(), 1);

    let unknown_optional = raw_avp(AvpCode::new(900_464), 0, None, b"opaque-extension");
    let wire = agent_error_wire(
        base::RESULT_CODE_DIAMETER_TOO_BUSY,
        HOP_BY_HOP,
        None,
        &[],
        std::slice::from_ref(&unknown_optional),
    );
    let parsed = swm::parse_swm_diameter_eap_response(
        &decode(&wire),
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect("unknown optional generic wildcard is retained");
    let SwmDiameterEapResponse::GenericError(answer) = parsed else {
        panic!("E-bit response must use generic grammar");
    };
    assert_eq!(answer.additional_avp_count(), 1);
    assert!(answer.session_id.is_none());

    swm::parse_swm_diameter_eap_response(&decode(&wire), typed_context(UnknownIePolicy::Reject))
        .expect_err("unknown optional follows Reject policy");

    let unknown_mandatory = mandatory_avp(AvpCode::new(900_465), b"opaque-extension");
    let mandatory_wire = agent_error_wire(
        base::RESULT_CODE_DIAMETER_TOO_BUSY,
        HOP_BY_HOP,
        None,
        &[],
        &[unknown_mandatory],
    );
    swm::parse_swm_diameter_eap_response(
        &decode(&mandatory_wire),
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect_err("unknown mandatory generic wildcard fails closed");

    let mut bounded = typed_context(UnknownIePolicy::Preserve);
    bounded.max_message_len = unknown_optional.len() - 1;
    swm::parse_swm_diameter_eap_response(&decode(&wire), bounded)
        .expect_err("generic agent-error parsing honors the message-byte bound");
}

#[test]
fn correlated_failure_is_connection_generation_and_request_bound() {
    let proxies = vec![proxy_info(PROXY_ONE_HOST, PROXY_ONE_STATE)];
    let request = bound_request(
        CONNECTION_ONE,
        HOP_BY_HOP,
        &[0x02, 0x22, 0x00, 0x08, 0x32, 0x44, 0x55, 0x66],
        &proxies,
    );
    let wire = encode(&build_agent_error(
        &request,
        SwmDiameterEapAgentDeliveryFailure::TooBusy,
    ));
    let response = swm::parse_swm_diameter_eap_response_envelope_from_connection(
        &decode(&wire),
        CONNECTION_ONE,
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect("connection-bound generic error");
    let correlated = request
        .clone()
        .correlate_response(response)
        .expect("exact request and connection generation correlate");
    assert_eq!(
        correlated.agent_delivery_failure(),
        Some(SwmDiameterEapAgentDeliveryFailure::TooBusy)
    );
    assert!(correlated.redirect().is_none());

    let wrong_connection = swm::parse_swm_diameter_eap_response_envelope_from_connection(
        &decode(&wire),
        CONNECTION_TWO,
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect("well-formed response on another connection generation");
    assert_eq!(
        request
            .clone()
            .correlate_response(wrong_connection)
            .expect_err("dialed DRA generation is binding"),
        SwmDiameterEapCorrelationError::PeerConnectionMismatch,
    );

    let mut failed_over = request.clone();
    failed_over.mark_for_failover_retransmission(
        HOP_BY_HOP ^ 0x0100_0000,
        SwmExpectedAnswerPeer::routed_via(
            CONNECTION_TWO,
            "dra.synthetic.example",
            "routing.synthetic.example",
        ),
    );
    let stale_on_old_generation = swm::parse_swm_diameter_eap_response_envelope_from_connection(
        &decode(&wire),
        CONNECTION_ONE,
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect("stale pre-failover response");
    assert_eq!(
        failed_over
            .clone()
            .correlate_response(stale_on_old_generation)
            .expect_err("pre-failover replay cannot satisfy the new generation"),
        SwmDiameterEapCorrelationError::PeerConnectionMismatch,
    );
    let stale_on_new_generation = swm::parse_swm_diameter_eap_response_envelope_from_connection(
        &decode(&wire),
        CONNECTION_TWO,
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect("old transaction replayed on the new generation");
    assert_eq!(
        failed_over
            .correlate_response(stale_on_new_generation)
            .expect_err("old transaction cannot cross generations"),
        SwmDiameterEapCorrelationError::TransactionMismatch,
    );

    let other_result_wire = agent_error_wire(3003, HOP_BY_HOP, Some(SESSION_ID), &proxies, &[]);
    let other_result = swm::parse_swm_diameter_eap_response_envelope_from_connection(
        &decode(&other_result_wire),
        CONNECTION_ONE,
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect("other generic 3xxx remains receive-capable");
    let other_correlated = request
        .correlate_response(other_result)
        .expect("other generic result still correlates structurally");
    assert_eq!(other_correlated.agent_delivery_failure(), None);
}

#[test]
fn correlated_failure_requires_exact_authenticated_agent_authority() {
    let request_payload = &[0x02, 0x2a, 0x00, 0x08, 0x32, 0x44, 0x55, 0x66];
    let valid_wire = agent_error_wire(
        base::RESULT_CODE_DIAMETER_UNABLE_TO_DELIVER,
        HOP_BY_HOP,
        Some(SESSION_ID),
        &[],
        &[],
    );
    let parsed_response = |wire: &[u8]| {
        swm::parse_swm_diameter_eap_response_envelope_from_connection(
            &decode(wire),
            CONNECTION_ONE,
            typed_context(UnknownIePolicy::Preserve),
        )
        .expect("synthetic authenticated-agent response")
    };

    let no_authority = parsed_request(HOP_BY_HOP, request_payload, &[])
        .with_expected_answer_peer(SwmExpectedAnswerPeer::routed(CONNECTION_ONE));
    assert_eq!(
        no_authority
            .correlate_response(parsed_response(&valid_wire))
            .expect_err("a routed connection alone cannot authorize an agent error"),
        SwmDiameterEapCorrelationError::AgentAuthorityMissing,
    );

    for (origin_host, origin_realm) in [
        (b"other-dra.synthetic.example".as_slice(), DRA_REALM),
        (DRA_HOST, b"other-routing.synthetic.example".as_slice()),
    ] {
        let wrong_origin_wire = agent_error_wire_from_origin(
            base::RESULT_CODE_DIAMETER_UNABLE_TO_DELIVER,
            HOP_BY_HOP,
            origin_host,
            origin_realm,
        );
        assert_eq!(
            bound_request(CONNECTION_ONE, HOP_BY_HOP, request_payload, &[])
                .correlate_response(parsed_response(&wrong_origin_wire))
                .expect_err("the authenticated agent Origin pair is exact"),
            SwmDiameterEapCorrelationError::AgentIdentityMismatch,
        );
    }

    let case_insensitive = parsed_request(HOP_BY_HOP, request_payload, &[])
        .with_expected_answer_peer(SwmExpectedAnswerPeer::routed_via(
            CONNECTION_ONE,
            "DRA.SYNTHETIC.EXAMPLE",
            "ROUTING.SYNTHETIC.EXAMPLE",
        ));
    assert_eq!(
        case_insensitive
            .correlate_response(parsed_response(&valid_wire))
            .expect("Diameter identities compare ASCII case-insensitively")
            .agent_delivery_failure(),
        Some(SwmDiameterEapAgentDeliveryFailure::UnableToDeliver),
    );

    let direct = parsed_request(HOP_BY_HOP, request_payload, &[]).with_expected_answer_peer(
        SwmExpectedAnswerPeer::direct(
            CONNECTION_ONE,
            "DRA.SYNTHETIC.EXAMPLE",
            "ROUTING.SYNTHETIC.EXAMPLE",
        ),
    );
    assert_eq!(
        direct
            .correlate_response(parsed_response(&valid_wire))
            .expect("a direct peer derives agent authority from its exact identity")
            .agent_delivery_failure(),
        Some(SwmDiameterEapAgentDeliveryFailure::UnableToDeliver),
    );

    let direct_with_conflicting_override = parsed_request(HOP_BY_HOP, request_payload, &[])
        .with_expected_answer_peer(
            SwmExpectedAnswerPeer::direct(
                CONNECTION_ONE,
                "dra.synthetic.example",
                "routing.synthetic.example",
            )
            .with_authenticated_agent_origin(
                "other-dra.synthetic.example",
                "other-routing.synthetic.example",
            ),
        );
    assert_eq!(
        direct_with_conflicting_override
            .clone()
            .correlate_response(parsed_response(&valid_wire))
            .expect("a routed-agent override cannot replace direct peer authority")
            .agent_delivery_failure(),
        Some(SwmDiameterEapAgentDeliveryFailure::UnableToDeliver),
    );
    let conflicting_origin_wire = agent_error_wire_from_origin(
        base::RESULT_CODE_DIAMETER_UNABLE_TO_DELIVER,
        HOP_BY_HOP,
        b"other-dra.synthetic.example",
        b"other-routing.synthetic.example",
    );
    assert_eq!(
        direct_with_conflicting_override
            .correlate_response(parsed_response(&conflicting_origin_wire))
            .expect_err("a direct peer's negotiated identity is immutable authority"),
        SwmDiameterEapCorrelationError::AgentIdentityMismatch,
    );

    let separate_terminal_authority = parsed_request(HOP_BY_HOP, request_payload, &[])
        .with_expected_answer_peer(
            SwmExpectedAnswerPeer::routed_in_realm(
                CONNECTION_ONE,
                "terminal-aaa.synthetic.example",
            )
            .with_authenticated_agent_origin("dra.synthetic.example", "routing.synthetic.example"),
        );
    assert_eq!(
        separate_terminal_authority
            .correlate_response(parsed_response(&valid_wire))
            .expect("terminal AAA and authenticated DRA authority remain independent")
            .agent_delivery_failure(),
        Some(SwmDiameterEapAgentDeliveryFailure::UnableToDeliver),
    );
}

#[test]
fn correlated_failure_requires_the_request_session_id() {
    let request = bound_request(
        CONNECTION_ONE,
        HOP_BY_HOP,
        &[0x02, 0x2b, 0x00, 0x08, 0x32, 0x44, 0x55, 0x66],
        &[],
    );
    for result_code in [
        base::RESULT_CODE_DIAMETER_UNABLE_TO_DELIVER,
        base::RESULT_CODE_DIAMETER_TOO_BUSY,
    ] {
        let wire = agent_error_wire(result_code, HOP_BY_HOP, None, &[], &[]);
        let response = swm::parse_swm_diameter_eap_response_envelope_from_connection(
            &decode(&wire),
            CONNECTION_ONE,
            typed_context(UnknownIePolicy::Preserve),
        )
        .expect("generic grammar permits an absent Session-Id before correlation");
        assert_eq!(
            request
                .clone()
                .correlate_response(response)
                .expect_err("RFC 6733 requires copying the DER Session-Id"),
            SwmDiameterEapCorrelationError::SessionMismatch,
        );
    }
}

#[test]
fn transport_pending_consumption_makes_agent_failure_one_shot() {
    let key = (CONNECTION_ONE, HOP_BY_HOP);
    let mut pending = HashMap::from([(
        key,
        bound_request(
            CONNECTION_ONE,
            HOP_BY_HOP,
            &[0x02, 0x2c, 0x00, 0x08, 0x32, 0x44, 0x55, 0x66],
            &[],
        ),
    )]);
    let wire = agent_error_wire(
        base::RESULT_CODE_DIAMETER_UNABLE_TO_DELIVER,
        HOP_BY_HOP,
        Some(SESSION_ID),
        &[],
        &[],
    );
    let response = swm::parse_swm_diameter_eap_response_envelope_from_connection(
        &decode(&wire),
        CONNECTION_ONE,
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect("synthetic agent response");

    let request = pending
        .remove(&key)
        .expect("live transport consumes the pending request first");
    assert_eq!(
        request
            .correlate_response(response)
            .expect("consumed pending response correlates")
            .agent_delivery_failure(),
        Some(SwmDiameterEapAgentDeliveryFailure::UnableToDeliver),
    );
    assert!(
        pending.remove(&key).is_none(),
        "a same-generation duplicate has no live pending request to consume"
    );
}

#[test]
fn failover_retransmission_t_is_bound_but_the_agent_answer_clears_t() {
    let mut request = bound_request(
        CONNECTION_ONE,
        HOP_BY_HOP,
        &[0x02, 0x26, 0x00, 0x08, 0x32, 0x40, 0x50, 0x60],
        &[],
    );
    let replacement_hop = HOP_BY_HOP ^ 0x0200_0000;
    request.mark_for_failover_retransmission(
        replacement_hop,
        SwmExpectedAnswerPeer::routed_via(
            CONNECTION_TWO,
            "dra.synthetic.example",
            "routing.synthetic.example",
        ),
    );
    assert!(request.is_potentially_retransmitted());

    let built = build_agent_error(
        &request,
        SwmDiameterEapAgentDeliveryFailure::UnableToDeliver,
    );
    assert!(!built.header.flags.is_request());
    assert!(built.header.flags.is_proxiable());
    assert!(built.header.flags.is_error());
    assert!(!built.header.flags.is_potentially_retransmitted());
    assert_eq!(built.header.hop_by_hop_identifier, replacement_hop);
    assert_eq!(built.header.end_to_end_identifier, END_TO_END);

    let wire = encode(&built);
    let response = swm::parse_swm_diameter_eap_response_envelope_from_connection(
        &decode(&wire),
        CONNECTION_TWO,
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect("replacement-generation response");
    let correlated = request
        .correlate_response(response)
        .expect("T request receives an R/T-clear correlated answer");
    assert_eq!(
        correlated.agent_delivery_failure(),
        Some(SwmDiameterEapAgentDeliveryFailure::UnableToDeliver),
    );
}

#[test]
fn raw_3004_without_destination_host_is_receive_capable_but_not_actionable() {
    let request = parsed_request_without_destination_host(
        HOP_BY_HOP,
        &[0x02, 0x25, 0x00, 0x08, 0x32, 0x10, 0x20, 0x30],
        &[],
    )
    .with_expected_answer_peer(SwmExpectedAnswerPeer::routed_via(
        CONNECTION_ONE,
        "dra.synthetic.example",
        "routing.synthetic.example",
    ));
    let wire = agent_error_wire(
        base::RESULT_CODE_DIAMETER_TOO_BUSY,
        HOP_BY_HOP,
        Some(SESSION_ID),
        &[],
        &[],
    );
    swm::parse_swm_diameter_eap_response(&decode(&wire), typed_context(UnknownIePolicy::Preserve))
        .expect("raw generic parser remains forward-compatible");
    let response = swm::parse_swm_diameter_eap_response_envelope_from_connection(
        &decode(&wire),
        CONNECTION_ONE,
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect("connection-bound raw 3004");
    assert_eq!(
        request
            .correlate_response(response)
            .expect_err("nonconforming 3004 cannot become actionable"),
        SwmDiameterEapCorrelationError::ApplicationMismatch,
    );
}

#[test]
fn correlation_rejects_session_proxy_and_transaction_mismatches() {
    let proxies = vec![proxy_info(PROXY_ONE_HOST, PROXY_ONE_STATE)];
    let request = bound_request(
        CONNECTION_ONE,
        HOP_BY_HOP,
        &[0x02, 0x23, 0x00, 0x08, 0x32, 0x77, 0x88, 0x99],
        &proxies,
    );
    let wrong_session_wire = agent_error_wire(
        base::RESULT_CODE_DIAMETER_UNABLE_TO_DELIVER,
        HOP_BY_HOP,
        Some(OTHER_SESSION_ID),
        &proxies,
        &[],
    );
    let wrong_session = swm::parse_swm_diameter_eap_response_envelope_from_connection(
        &decode(&wrong_session_wire),
        CONNECTION_ONE,
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect("well-formed mismatched Session-Id");
    assert_eq!(
        request
            .clone()
            .correlate_response(wrong_session)
            .expect_err("present Session-Id is binding"),
        SwmDiameterEapCorrelationError::SessionMismatch,
    );

    let wrong_proxy = vec![proxy_info(PROXY_TWO_HOST, PROXY_TWO_STATE)];
    let wrong_proxy_wire = agent_error_wire(
        base::RESULT_CODE_DIAMETER_UNABLE_TO_DELIVER,
        HOP_BY_HOP,
        Some(SESSION_ID),
        &wrong_proxy,
        &[],
    );
    let wrong_proxy = swm::parse_swm_diameter_eap_response_envelope_from_connection(
        &decode(&wrong_proxy_wire),
        CONNECTION_ONE,
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect("well-formed mismatched Proxy-Info");
    assert_eq!(
        request
            .clone()
            .correlate_response(wrong_proxy)
            .expect_err("ordered Proxy-Info is binding"),
        SwmDiameterEapCorrelationError::ProxyInfoMismatch,
    );

    let wrong_transaction_wire = agent_error_wire(
        base::RESULT_CODE_DIAMETER_UNABLE_TO_DELIVER,
        HOP_BY_HOP ^ 1,
        Some(SESSION_ID),
        &proxies,
        &[],
    );
    let wrong_transaction = swm::parse_swm_diameter_eap_response_envelope_from_connection(
        &decode(&wrong_transaction_wire),
        CONNECTION_ONE,
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect("well-formed mismatched transaction");
    assert_eq!(
        request
            .correlate_response(wrong_transaction)
            .expect_err("both identifiers are binding"),
        SwmDiameterEapCorrelationError::TransactionMismatch,
    );
}

#[test]
fn diagnostics_redact_origin_session_proxy_and_connection_values() {
    let proxies = vec![proxy_info(PROXY_ONE_HOST, PROXY_ONE_STATE)];
    let request = bound_request(
        CONNECTION_ONE,
        HOP_BY_HOP,
        &[0x02, 0x24, 0x00, 0x08, 0x32, 0xaa, 0xbb, 0xcc],
        &proxies,
    );
    let answer = SwmDiameterEapGenericErrorAnswer::new_agent_delivery_failure_for(
        &request,
        SwmDiameterEapAgentDeliveryFailure::UnableToDeliver,
        String::from_utf8(DRA_HOST.to_vec()).expect("ASCII host"),
        String::from_utf8(DRA_REALM.to_vec()).expect("ASCII realm"),
    )
    .expect("bound answer");
    let response = SwmDiameterEapResponse::GenericError(Box::new(answer.clone()));
    let debug = format!("{request:?} {answer:?} {response:?} {CONNECTION_ONE:?}");
    for secret in [
        SESSION_ID,
        DRA_HOST,
        DRA_REALM,
        PROXY_ONE_HOST,
        PROXY_ONE_STATE,
    ] {
        assert!(!debug
            .as_bytes()
            .windows(secret.len())
            .any(|part| part == secret));
    }

    let other = parsed_request(
        HOP_BY_HOP,
        &[0x02, 0x24, 0x00, 0x08, 0x32, 0xaa, 0xbb, 0xcd],
        &proxies,
    );
    let error =
        swm::build_swm_diameter_eap_response_for(&other, &response, EncodeContext::default())
            .expect_err("different request binding");
    let diagnostic = format!("{error:?} {error}");
    for secret in [SESSION_ID, DRA_HOST, DRA_REALM, PROXY_ONE_STATE] {
        assert!(!diagnostic
            .as_bytes()
            .windows(secret.len())
            .any(|part| part == secret));
    }
}

#[test]
fn originated_result_codes_are_exact() {
    assert_eq!(
        SwmDiameterEapAgentDeliveryFailure::UnableToDeliver.result_code(),
        base::RESULT_CODE_DIAMETER_UNABLE_TO_DELIVER,
    );
    assert_eq!(
        SwmDiameterEapAgentDeliveryFailure::TooBusy.result_code(),
        base::RESULT_CODE_DIAMETER_TOO_BUSY,
    );
}
