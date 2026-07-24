//! Independent RFC 6733 authorization-session state evidence for SWm.
//!
//! Input fixtures are hand-authored from RFC 6733 sections 3, 4, and
//! 8.17-8.20 plus the SWm DEA/STR command profiles. No SDK builder produces
//! the bytes fed to the parsers.

#![cfg(feature = "app-swm")]

use bytes::{Bytes, BytesMut};
use opc_proto_diameter::apps::swm::{
    self, SwmAdditionalAvp, SwmClassAvpUpdate, SwmCorrelatedDiameterEapResponse,
    SwmDestinationHostRequirement, SwmDiameterConnectionToken, SwmDiameterTransaction,
    SwmExpectedAnswerPeer, SwmReAuthRequest, SwmReAuthRequestEnvelope, SwmReAuthRequestType,
    SwmSessionBinding, SwmSessionServerFailover, SwmSessionServerFailoverPolicy,
    SwmSessionStateErrorCode, SwmSessionTerminationRequest, SwmSessionTerminationRequestEnvelope,
    SwmTerminationCause,
};
use opc_proto_diameter::avp::dictionary::{Redacted, Sensitive};
use opc_proto_diameter::dictionary::AvpKey;
use opc_proto_diameter::{
    base, AvpCardinality, AvpCode, AvpFlags, AvpHeader, CommandCode, CommandFlags, CommandKind,
    Header, Message, OwnedMessage, VendorId,
};
use opc_protocol::{
    BorrowDecode, DecodeContext, DecodeError, DecodeErrorCode, DuplicateIePolicy, Encode,
    EncodeContext, UnknownIePolicy,
};
use std::num::NonZeroU64;

const HOP_BY_HOP: u32 = 0x3893_9001;
const END_TO_END: u32 = 0x3893_9002;
const AUTH_HOP_BY_HOP: u32 = 0x3893_9011;
const AUTH_END_TO_END: u32 = 0x3893_9012;
const SESSION_ID: &str = "session;private;389-390";
const USER_NAME: &str = "subscriber-private@example.invalid";
const EPDG_HOST: &str = "epdg.private.invalid";
const EPDG_REALM: &str = "visited.private.invalid";
const AAA_HOST: &str = "final-aaa.private.invalid";
const AAA_REALM: &str = "home.private.invalid";
const DRA_HOST: &str = "transport-dra.private.invalid";
const DRA_REALM: &str = "routing.private.invalid";
const CLASS_SENTINEL: &[u8] = b"opaque-class-value-private-sentinel";
const CONNECTION: SwmDiameterConnectionToken = SwmDiameterConnectionToken::new(NonZeroU64::MIN);

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

fn encode(message: &OwnedMessage) -> Vec<u8> {
    let mut wire = BytesMut::new();
    message
        .encode(&mut wire, EncodeContext::default())
        .expect("synthetic Diameter message encodes");
    wire.to_vec()
}

fn message_wire(
    command: CommandCode,
    flags: CommandFlags,
    hop_by_hop: u32,
    end_to_end: u32,
    avps: Vec<Vec<u8>>,
) -> Vec<u8> {
    let raw_avps = avps.into_iter().flatten().collect::<Vec<_>>();
    encode(&OwnedMessage {
        header: Header::new(flags, command, swm::APPLICATION_ID, hop_by_hop, end_to_end),
        raw_avps: Bytes::from(raw_avps),
    })
}

fn wire_with_trailing_avp(wire: &[u8], avp: Vec<u8>) -> Vec<u8> {
    let message = decode(wire);
    let mut raw_avps = message.raw_avps.to_vec();
    raw_avps.extend(avp);
    encode(&OwnedMessage {
        header: message.header,
        raw_avps: Bytes::from(raw_avps),
    })
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

fn typed_context() -> DecodeContext {
    DecodeContext {
        max_ies: 512,
        max_message_len: 256 * 1024,
        duplicate_ie_policy: DuplicateIePolicy::Last,
        unknown_ie_policy: UnknownIePolicy::Preserve,
        ..DecodeContext::conservative()
    }
}

fn decode(wire: &[u8]) -> Message<'_> {
    let (tail, message) = Message::decode(wire, framing_context()).expect("Diameter framing");
    assert!(tail.is_empty());
    message
}

fn class_avp(value: &[u8]) -> Vec<u8> {
    mandatory_avp(base::AVP_CLASS, value)
}

fn request_wire() -> Vec<u8> {
    message_wire(
        swm::COMMAND_DIAMETER_EAP,
        CommandFlags::request(true),
        HOP_BY_HOP,
        END_TO_END,
        vec![
            mandatory_avp(base::AVP_SESSION_ID, SESSION_ID.as_bytes()),
            mandatory_avp(
                base::AVP_AUTH_APPLICATION_ID,
                &swm::APPLICATION_ID.get().to_be_bytes(),
            ),
            mandatory_avp(base::AVP_ORIGIN_HOST, EPDG_HOST.as_bytes()),
            mandatory_avp(base::AVP_ORIGIN_REALM, EPDG_REALM.as_bytes()),
            mandatory_avp(base::AVP_DESTINATION_REALM, AAA_REALM.as_bytes()),
            mandatory_avp(
                swm::AVP_AUTH_REQUEST_TYPE,
                &swm::AUTH_REQUEST_TYPE_AUTHORIZE_AUTHENTICATE.to_be_bytes(),
            ),
            mandatory_avp(
                swm::AVP_EAP_PAYLOAD,
                &[0x02, 0x17, 0x00, 0x08, 0x32, 0x01, 0x02, 0x03],
            ),
        ],
    )
}

fn answer_wire(extras: &[Vec<u8>]) -> Vec<u8> {
    let mut avps = vec![
        mandatory_avp(base::AVP_SESSION_ID, SESSION_ID.as_bytes()),
        mandatory_avp(
            base::AVP_AUTH_APPLICATION_ID,
            &swm::APPLICATION_ID.get().to_be_bytes(),
        ),
        mandatory_avp(
            swm::AVP_AUTH_REQUEST_TYPE,
            &swm::AUTH_REQUEST_TYPE_AUTHORIZE_AUTHENTICATE.to_be_bytes(),
        ),
        mandatory_avp(
            base::AVP_RESULT_CODE,
            &base::RESULT_CODE_DIAMETER_SUCCESS.to_be_bytes(),
        ),
        mandatory_avp(base::AVP_ORIGIN_HOST, AAA_HOST.as_bytes()),
        mandatory_avp(base::AVP_ORIGIN_REALM, AAA_REALM.as_bytes()),
    ];
    avps.extend_from_slice(extras);
    avps.push(mandatory_avp(
        swm::AVP_EAP_PAYLOAD,
        &[0x03, 0x17, 0x00, 0x04],
    ));
    message_wire(
        swm::COMMAND_DIAMETER_EAP,
        CommandFlags::answer(true, false),
        HOP_BY_HOP,
        END_TO_END,
        avps,
    )
}

fn bound_request() -> swm::SwmDiameterEapRequestEnvelope {
    swm::parse_swm_diameter_eap_request_envelope(&decode(&request_wire()), typed_context())
        .expect("independent DER fixture")
        .with_expected_answer_peer(SwmExpectedAnswerPeer::routed_via(
            CONNECTION, DRA_HOST, DRA_REALM,
        ))
}

fn correlated_answer(extras: &[Vec<u8>]) -> SwmCorrelatedDiameterEapResponse {
    let wire = answer_wire(extras);
    let response = swm::parse_swm_diameter_eap_response_envelope_from_connection(
        &decode(&wire),
        CONNECTION,
        typed_context(),
    )
    .expect("independent DEA response envelope");
    bound_request()
        .correlate_response(response)
        .expect("connection, transaction, Session-Id, and application correlate")
}

fn session_termination_request() -> SwmSessionTerminationRequest {
    SwmSessionTerminationRequest {
        session_id: Sensitive::from(SESSION_ID),
        origin_host: Redacted::from(EPDG_HOST),
        origin_realm: Redacted::from(EPDG_REALM),
        destination_realm: Redacted::from(DRA_REALM),
        destination_host: Some(Redacted::from(DRA_HOST)),
        termination_cause: SwmTerminationCause::Administrative,
        user_name: Sensitive::from(USER_NAME),
        drmp: None,
        route_records: Vec::new(),
        additional_avps: Vec::new(),
    }
}

fn encoded_str(request: SwmSessionTerminationRequest) -> Vec<u8> {
    let envelope = SwmSessionTerminationRequestEnvelope::for_outbound(
        request,
        SwmDiameterTransaction::new(HOP_BY_HOP + 1, END_TO_END + 1),
        SwmExpectedAnswerPeer::routed(CONNECTION),
    );
    encode(
        &swm::build_swm_session_termination_request(&envelope, EncodeContext::default())
            .expect("typed STR builds"),
    )
}

fn re_auth_request() -> SwmReAuthRequest {
    SwmReAuthRequest {
        session_id: Redacted::from(SESSION_ID),
        origin_host: Redacted::from(AAA_HOST),
        origin_realm: Redacted::from(AAA_REALM),
        destination_realm: Redacted::from(EPDG_REALM),
        destination_host: Redacted::from(EPDG_HOST),
        re_auth_request_type: SwmReAuthRequestType::AuthorizeOnly,
        user_name: Redacted::from(USER_NAME),
        drmp: None,
        route_records: Vec::new(),
        additional_avps: Vec::new(),
    }
}

fn encoded_rar(request: SwmReAuthRequest) -> Vec<u8> {
    let envelope = SwmReAuthRequestEnvelope::for_outbound(
        request,
        SwmDiameterTransaction::new(HOP_BY_HOP + 2, END_TO_END + 2),
        SwmExpectedAnswerPeer::direct(CONNECTION, EPDG_HOST, EPDG_REALM),
    );
    encode(
        &swm::build_swm_re_auth_request(&envelope, EncodeContext::default())
            .expect("typed RAR builds"),
    )
}

fn class_values(wire: &[u8]) -> Vec<Vec<u8>> {
    decode(wire)
        .avps(framing_context())
        .filter_map(|avp| {
            let avp = avp.expect("framed AVP");
            (avp.header.key() == opc_proto_diameter::dictionary::AvpKey::ietf(base::AVP_CLASS))
                .then(|| {
                    assert_eq!(avp.header.flags, AvpFlags::new(false, true, false));
                    assert_eq!(avp.header.vendor_id, None);
                    avp.value.to_vec()
                })
        })
        .collect()
}

fn ietf_avp_values(wire: &[u8], code: AvpCode) -> Vec<Vec<u8>> {
    decode(wire)
        .avps(framing_context())
        .filter_map(|avp| {
            let avp = avp.expect("framed AVP");
            (avp.header.key() == AvpKey::ietf(code)).then(|| avp.value.to_vec())
        })
        .collect()
}

fn bounded_answer_error(extras: &[Vec<u8>]) -> DecodeError {
    let wire = answer_wire(extras);
    let error = swm::parse_swm_diameter_eap_answer(&decode(&wire), typed_context())
        .expect_err("hostile authorization-session state must fail");
    assert!(error.offset() <= wire.len());
    error
}

#[test]
fn independent_dea_class_fixtures_cover_absent_order_and_empty_values() {
    let fixtures = [
        Vec::<Vec<u8>>::new(),
        vec![b"one".to_vec()],
        vec![b"first".to_vec(), b"second".to_vec()],
        vec![Vec::new()],
    ];
    for values in fixtures {
        let extras = values
            .iter()
            .map(|value| class_avp(value))
            .collect::<Vec<_>>();
        let wire = answer_wire(&extras);
        let answer = swm::parse_swm_diameter_eap_answer(&decode(&wire), typed_context())
            .expect("valid Class fixture parses");
        assert_eq!(answer.class_avp_count(), values.len());
        assert_eq!(
            answer.class_avp_value_bytes(),
            values.iter().map(Vec::len).sum()
        );
        let rebuilt = swm::build_swm_diameter_eap_answer(
            &answer,
            HOP_BY_HOP,
            END_TO_END,
            EncodeContext::default(),
        )
        .expect("parsed DEA remains buildable");
        assert_eq!(class_values(&encode(&rebuilt)), values);
        if extras.is_empty() {
            assert_eq!(encode(&rebuilt), wire, "absent state keeps legacy bytes");
        }
    }
}

#[test]
fn correlated_class_state_clones_and_moves_byte_exactly_into_str_and_rar() {
    let expected = vec![
        b"first-opaque-class".to_vec(),
        Vec::new(),
        b"third-opaque-class".to_vec(),
    ];
    let extras = expected
        .iter()
        .map(|value| class_avp(value))
        .collect::<Vec<_>>();
    let update = correlated_answer(&extras).class_avp_update();
    let replacement = update
        .replacement()
        .expect("present Class values produce replacement");
    assert_eq!(replacement.len(), 3);
    assert_eq!(
        replacement.aggregate_value_bytes(),
        expected.iter().map(Vec::len).sum()
    );

    let mut cloned_str = session_termination_request();
    replacement
        .clone_into_session_termination_request(&mut cloned_str)
        .expect("Class state clones into STR");
    assert_eq!(class_values(&encoded_str(cloned_str)), expected);

    let SwmClassAvpUpdate::Replace(moved) = update.clone() else {
        panic!("Class update must be replacement");
    };
    let mut moved_str = session_termination_request();
    moved
        .move_into_session_termination_request(&mut moved_str)
        .expect("Class state moves into STR");
    assert_eq!(class_values(&encoded_str(moved_str)), expected);

    let SwmClassAvpUpdate::Replace(moved) = update else {
        panic!("Class update must be replacement");
    };
    let mut moved_rar = re_auth_request();
    moved
        .move_into_re_auth_request(&mut moved_rar)
        .expect("Class state moves into RAR");
    assert_eq!(class_values(&encoded_rar(moved_rar)), expected);
}

#[test]
fn class_count_aggregate_headers_and_lengths_fail_closed_at_bounds() {
    let exact = vec![class_avp(&vec![0xa5; swm::MAX_SWM_CLASS_VALUE_BYTES])];
    let parsed = swm::parse_swm_diameter_eap_answer(&decode(&answer_wire(&exact)), typed_context())
        .expect("4096 aggregate Class octets are accepted");
    assert_eq!(
        parsed.class_avp_value_bytes(),
        swm::MAX_SWM_CLASS_VALUE_BYTES
    );

    let excessive = vec![class_avp(&vec![0xa5; swm::MAX_SWM_CLASS_VALUE_BYTES + 1])];
    let error = bounded_answer_error(&excessive);
    assert!(matches!(error.code(), DecodeErrorCode::Structural { .. }));

    let too_many = (0..=swm::MAX_SWM_CLASS_AVPS)
        .map(|_| class_avp(&[]))
        .collect::<Vec<_>>();
    let error = bounded_answer_error(&too_many);
    assert_eq!(error.code(), &DecodeErrorCode::IeCountExceeded);

    for invalid in [
        raw_avp(base::AVP_CLASS, 0, None, b"wrong-m"),
        raw_avp(
            base::AVP_CLASS,
            AvpFlags::MANDATORY | AvpFlags::PROTECTED,
            None,
            b"wrong-p",
        ),
        raw_avp(
            base::AVP_CLASS,
            AvpFlags::VENDOR | AvpFlags::MANDATORY,
            Some(opc_proto_diameter::apps::VENDOR_ID_3GPP),
            b"wrong-vendor",
        ),
    ] {
        bounded_answer_error(&[invalid]);
    }

    let mut invalid_length = class_avp(b"invalid-length");
    invalid_length[5..8].copy_from_slice(&7_u32.to_be_bytes()[1..]);
    let malformed_wire = answer_wire(&[invalid_length]);
    let error = Message::decode(&malformed_wire, typed_context())
        .expect_err("malformed Class header length fails during bounded framing");
    assert!(error.offset() <= malformed_wire.len());
}

#[test]
fn session_binding_and_failover_singletons_validate_flags_width_and_duplicates() {
    let binding = mandatory_avp(base::AVP_SESSION_BINDING, &0_u32.to_be_bytes());
    let failover = mandatory_avp(base::AVP_SESSION_SERVER_FAILOVER, &1_u32.to_be_bytes());

    bounded_answer_error(&[binding.clone(), binding]);
    bounded_answer_error(&[failover.clone(), failover]);
    bounded_answer_error(&[raw_avp(
        base::AVP_SESSION_BINDING,
        0,
        None,
        &0_u32.to_be_bytes(),
    )]);
    bounded_answer_error(&[raw_avp(
        base::AVP_SESSION_SERVER_FAILOVER,
        AvpFlags::VENDOR | AvpFlags::MANDATORY,
        Some(opc_proto_diameter::apps::VENDOR_ID_3GPP),
        &1_u32.to_be_bytes(),
    )]);
    bounded_answer_error(&[mandatory_avp(base::AVP_SESSION_BINDING, &[0, 0, 0])]);
    bounded_answer_error(&[mandatory_avp(
        base::AVP_SESSION_SERVER_FAILOVER,
        &[0, 0, 0, 0, 0],
    )]);
}

#[test]
fn correlated_dra_carried_routing_uses_final_authorizing_origin_for_str() {
    let binding_required = mandatory_avp(base::AVP_SESSION_BINDING, &0_u32.to_be_bytes());
    let correlated = correlated_answer(&[binding_required]);
    let routing = correlated
        .authorization_session_routing()
        .expect("ordinary correlated DEA supplies routing");
    assert_eq!(routing.authorizing_origin_host().as_ref(), AAA_HOST);
    assert_eq!(routing.authorizing_origin_realm().as_ref(), AAA_REALM);
    assert_eq!(
        routing.session_termination_destination_host_requirement(),
        SwmDestinationHostRequirement::Required
    );

    let mut request = session_termination_request();
    routing
        .apply_to_session_termination_request(&mut request)
        .expect("routing applies to exact Session-Id");
    assert_eq!(
        request
            .destination_host
            .as_ref()
            .map(|host| host.as_ref().as_str()),
        Some(AAA_HOST)
    );
    assert_eq!(request.destination_realm.as_ref(), AAA_REALM);
    assert_ne!(
        request
            .destination_host
            .as_ref()
            .map(|host| host.as_ref().as_str()),
        Some(DRA_HOST)
    );
    let required_wire = encoded_str(request);
    assert_eq!(
        ietf_avp_values(&required_wire, base::AVP_DESTINATION_HOST),
        vec![AAA_HOST.as_bytes().to_vec()]
    );
    assert_eq!(
        ietf_avp_values(&required_wire, base::AVP_DESTINATION_REALM),
        vec![AAA_REALM.as_bytes().to_vec()]
    );
    assert!(!required_wire
        .windows(DRA_HOST.len())
        .any(|window| window == DRA_HOST.as_bytes()));

    let prohibited = correlated_answer(&[mandatory_avp(
        base::AVP_SESSION_BINDING,
        &2_u32.to_be_bytes(),
    )])
    .authorization_session_routing()
    .expect("binding projection");
    let mut request = session_termination_request();
    prohibited
        .apply_to_session_termination_request(&mut request)
        .expect("STR bit applies");
    assert_eq!(request.destination_host, None);
    let prohibited_wire = encoded_str(request);
    assert!(
        ietf_avp_values(&prohibited_wire, base::AVP_DESTINATION_HOST).is_empty(),
        "STR binding bit omits Destination-Host on wire"
    );
    assert_eq!(
        ietf_avp_values(&prohibited_wire, base::AVP_DESTINATION_REALM),
        vec![AAA_REALM.as_bytes().to_vec()]
    );
}

#[test]
fn assigned_failover_values_and_absence_gate_host_removal() {
    for (value, policy, removal_allowed) in [
        (0, SwmSessionServerFailoverPolicy::RefuseService, false),
        (1, SwmSessionServerFailoverPolicy::TryAgain, true),
        (2, SwmSessionServerFailoverPolicy::AllowService, false),
        (
            3,
            SwmSessionServerFailoverPolicy::TryAgainAllowService,
            true,
        ),
    ] {
        let extra = mandatory_avp(base::AVP_SESSION_SERVER_FAILOVER, &u32::to_be_bytes(value));
        let routing = correlated_answer(&[extra])
            .authorization_session_routing()
            .expect("ordinary answer routing");
        assert!(routing.explicit_server_failover().is_some());
        assert_eq!(routing.effective_server_failover_policy(), policy);
        let mut request = session_termination_request();
        let result = routing
            .remove_destination_host_after_session_termination_delivery_failure(&mut request);
        assert_eq!(result.is_ok(), removal_allowed);
        if removal_allowed {
            assert_eq!(request.destination_host, None);
            let retry_wire = encoded_str(request);
            assert!(
                ietf_avp_values(&retry_wire, base::AVP_DESTINATION_HOST).is_empty(),
                "authorized failover retry is hostless on wire"
            );
        } else {
            assert!(request.destination_host.is_some());
            assert_eq!(
                result.expect_err("host removal must fail").code(),
                SwmSessionStateErrorCode::DestinationHostRemovalProhibited
            );
        }
    }

    let absent = correlated_answer(&[])
        .authorization_session_routing()
        .expect("ordinary answer routing");
    assert_eq!(absent.explicit_server_failover(), None);
    assert_eq!(
        absent.effective_server_failover_policy(),
        SwmSessionServerFailoverPolicy::RefuseService
    );
    let mut request = session_termination_request();
    absent
        .remove_destination_host_after_session_termination_delivery_failure(&mut request)
        .expect_err("absent failover defaults to REFUSE_SERVICE");
    assert!(request.destination_host.is_some());
}

#[test]
fn unassigned_failover_values_fail_closed_without_value_leakage() {
    const REASON: &str = "Session-Server-Failover contains an unassigned value";

    for value in [99_u32, u32::MAX] {
        let error = bounded_answer_error(&[mandatory_avp(
            base::AVP_SESSION_SERVER_FAILOVER,
            &value.to_be_bytes(),
        )]);
        assert_eq!(
            error.code(),
            &DecodeErrorCode::Structural { reason: REASON }
        );
        let spec = error.spec_ref().expect("RFC failure provenance");
        assert_eq!(spec.body(), "ietf");
        assert_eq!(spec.doc(), "RFC6733");
        assert_eq!(spec.section(), "8.18");

        let decimal = value.to_string();
        assert!(!error.to_string().contains(&decimal));
        assert!(!format!("{error:?}").contains(&decimal));
    }
}

#[test]
fn contradictory_directives_fail_while_valid_unknown_binding_bits_are_retained() {
    let contradictory_binding = 0x8000_0007_u32;
    let error = bounded_answer_error(&[
        mandatory_avp(
            base::AVP_SESSION_BINDING,
            &contradictory_binding.to_be_bytes(),
        ),
        mandatory_avp(base::AVP_SESSION_SERVER_FAILOVER, &3_u32.to_be_bytes()),
    ]);
    assert!(matches!(error.code(), DecodeErrorCode::Structural { .. }));

    let binding = 0x8000_0003_u32;
    let correlated = correlated_answer(&[
        mandatory_avp(base::AVP_SESSION_BINDING, &binding.to_be_bytes()),
        mandatory_avp(base::AVP_SESSION_SERVER_FAILOVER, &3_u32.to_be_bytes()),
    ]);
    let routing = correlated
        .authorization_session_routing()
        .expect("combined directives");
    let binding = routing.session_binding().expect("explicit binding");
    assert!(binding.has_unknown_bits());
    assert_eq!(
        binding.re_auth_destination_host(),
        SwmDestinationHostRequirement::Prohibited
    );
    assert_eq!(
        binding.session_termination_destination_host(),
        SwmDestinationHostRequirement::Prohibited
    );
    assert_eq!(
        binding.accounting_destination_host(),
        SwmDestinationHostRequirement::Required
    );
    assert_eq!(
        routing.effective_server_failover_policy(),
        SwmSessionServerFailoverPolicy::TryAgainAllowService
    );

    let all_prohibited = SwmSessionBinding::new(
        SwmDestinationHostRequirement::Prohibited,
        SwmDestinationHostRequirement::Prohibited,
        SwmDestinationHostRequirement::Prohibited,
    );
    let wire = answer_wire(&[]);
    let mut answer = swm::parse_swm_diameter_eap_answer(&decode(&wire), typed_context())
        .expect("baseline originated answer");
    answer
        .set_session_binding(all_prohibited)
        .expect("binding alone is valid");
    let error = answer
        .set_session_server_failover(SwmSessionServerFailover::TRY_AGAIN_ALLOW_SERVICE)
        .expect_err("setter rejects contradictory failover atomically");
    assert_eq!(
        error.code(),
        SwmSessionStateErrorCode::ContradictoryRoutingDirectives
    );
    assert!(!answer.has_session_server_failover());

    let mut answer = swm::parse_swm_diameter_eap_answer(&decode(&wire), typed_context())
        .expect("second baseline originated answer");
    answer
        .set_session_server_failover(SwmSessionServerFailover::TRY_AGAIN)
        .expect("failover without binding is valid");
    let error = answer
        .set_session_binding(all_prohibited)
        .expect_err("reverse setter order is also atomic");
    assert_eq!(
        error.code(),
        SwmSessionStateErrorCode::ContradictoryRoutingDirectives
    );
    assert!(!answer.has_session_binding());
}

#[test]
fn session_routing_directives_are_dea_only_across_swm_command_roles() {
    for dictionary in [swm::dictionary(), swm::projected_profile_dictionary()] {
        for (command, kind) in [
            (swm::COMMAND_DIAMETER_EAP, CommandKind::Request),
            (swm::COMMAND_RE_AUTH, CommandKind::Request),
            (swm::COMMAND_RE_AUTH, CommandKind::Answer),
            (swm::COMMAND_AA, CommandKind::Request),
            (swm::COMMAND_AA, CommandKind::Answer),
            (swm::COMMAND_ABORT_SESSION, CommandKind::Request),
            (swm::COMMAND_ABORT_SESSION, CommandKind::Answer),
            (swm::COMMAND_SESSION_TERMINATION, CommandKind::Request),
            (swm::COMMAND_SESSION_TERMINATION, CommandKind::Answer),
        ] {
            let definition = dictionary
                .find_command(swm::APPLICATION_ID, command, kind)
                .expect("non-DEA SWm command definition");
            for code in [base::AVP_SESSION_BINDING, base::AVP_SESSION_SERVER_FAILOVER] {
                assert_eq!(
                    definition
                        .find_avp_rule(AvpKey::ietf(code))
                        .map(|rule| rule.cardinality()),
                    Some(AvpCardinality::Forbidden),
                );
            }
        }

        let dea = dictionary
            .find_command(
                swm::APPLICATION_ID,
                swm::COMMAND_DIAMETER_EAP,
                CommandKind::Answer,
            )
            .expect("DEA command definition");
        for code in [base::AVP_SESSION_BINDING, base::AVP_SESSION_SERVER_FAILOVER] {
            assert_eq!(
                dea.find_avp_rule(AvpKey::ietf(code))
                    .map(|rule| rule.cardinality()),
                Some(AvpCardinality::ZeroOrOne),
            );
        }
    }

    for code in [base::AVP_SESSION_BINDING, base::AVP_SESSION_SERVER_FAILOVER] {
        let wire = wire_with_trailing_avp(&request_wire(), mandatory_avp(code, &[0, 0, 0, 0]));
        swm::parse_swm_diameter_eap_request(&decode(&wire), typed_context())
            .expect_err("DER parser rejects answer-only routing directive");

        let mut request = session_termination_request();
        request.additional_avps.push(
            SwmAdditionalAvp::new(
                AvpHeader::ietf(code, true),
                vec![0, 0, 0, 0],
                EncodeContext::default(),
            )
            .expect("well-framed hostile additional AVP"),
        );
        let envelope = SwmSessionTerminationRequestEnvelope::for_outbound(
            request,
            SwmDiameterTransaction::new(HOP_BY_HOP + 3, END_TO_END + 3),
            SwmExpectedAnswerPeer::routed(CONNECTION),
        );
        swm::build_swm_session_termination_request(&envelope, EncodeContext::default())
            .expect_err("STR builder rejects answer-only routing directive");
    }
}

#[test]
fn routing_is_session_bound_and_failures_are_atomic() {
    let routing = correlated_answer(&[])
        .authorization_session_routing()
        .expect("ordinary answer routing");
    let mut request = session_termination_request();
    request.session_id = Sensitive::from("different-private-session");
    let original_realm = request.destination_realm.clone();
    let original_host = request.destination_host.clone();
    let error = routing
        .apply_to_session_termination_request(&mut request)
        .expect_err("routing cannot be transplanted across sessions");
    assert_eq!(error.code(), SwmSessionStateErrorCode::SessionMismatch);
    assert_eq!(request.destination_realm, original_realm);
    assert_eq!(request.destination_host, original_host);
}

fn authorization_request_wire() -> Vec<u8> {
    message_wire(
        swm::COMMAND_AA,
        CommandFlags::request(true),
        AUTH_HOP_BY_HOP,
        AUTH_END_TO_END,
        vec![
            mandatory_avp(base::AVP_SESSION_ID, SESSION_ID.as_bytes()),
            mandatory_avp(
                base::AVP_AUTH_APPLICATION_ID,
                &swm::APPLICATION_ID.get().to_be_bytes(),
            ),
            mandatory_avp(base::AVP_ORIGIN_HOST, EPDG_HOST.as_bytes()),
            mandatory_avp(base::AVP_ORIGIN_REALM, EPDG_REALM.as_bytes()),
            mandatory_avp(base::AVP_DESTINATION_REALM, AAA_REALM.as_bytes()),
            mandatory_avp(
                swm::AVP_AUTH_REQUEST_TYPE,
                &swm::AUTH_REQUEST_TYPE_AUTHORIZE_ONLY.to_be_bytes(),
            ),
            mandatory_avp(base::AVP_USER_NAME, USER_NAME.as_bytes()),
        ],
    )
}

fn authorization_answer_wire(extras: &[Vec<u8>]) -> Vec<u8> {
    let mut avps = vec![
        mandatory_avp(base::AVP_SESSION_ID, SESSION_ID.as_bytes()),
        mandatory_avp(
            base::AVP_AUTH_APPLICATION_ID,
            &swm::APPLICATION_ID.get().to_be_bytes(),
        ),
        mandatory_avp(
            swm::AVP_AUTH_REQUEST_TYPE,
            &swm::AUTH_REQUEST_TYPE_AUTHORIZE_ONLY.to_be_bytes(),
        ),
        mandatory_avp(
            base::AVP_RESULT_CODE,
            &base::RESULT_CODE_DIAMETER_SUCCESS.to_be_bytes(),
        ),
        mandatory_avp(base::AVP_ORIGIN_HOST, AAA_HOST.as_bytes()),
        mandatory_avp(base::AVP_ORIGIN_REALM, AAA_REALM.as_bytes()),
        mandatory_avp(base::AVP_USER_NAME, USER_NAME.as_bytes()),
    ];
    avps.extend_from_slice(extras);
    message_wire(
        swm::COMMAND_AA,
        CommandFlags::answer(true, false),
        AUTH_HOP_BY_HOP,
        AUTH_END_TO_END,
        avps,
    )
}

fn correlated_authorization_answer(extras: &[Vec<u8>]) -> swm::SwmCorrelatedAuthorizationExchange {
    let request = swm::parse_swm_authorization_request_envelope(
        &decode(&authorization_request_wire()),
        typed_context(),
    )
    .expect("independent AAR fixture")
    .with_expected_answer_peer(SwmExpectedAnswerPeer::routed(CONNECTION));
    let wire = authorization_answer_wire(extras);
    let answer = swm::parse_swm_authorization_answer_envelope_from_connection(
        &decode(&wire),
        CONNECTION,
        typed_context(),
    )
    .expect("independent AAA fixture");
    request
        .correlate_answer(answer)
        .expect("AAR and AAA correlate")
}

#[test]
fn later_authorization_answer_replaces_class_while_absence_is_unchanged() {
    let initial = correlated_answer(&[class_avp(b"initial-class")]).class_avp_update();
    let mut retained = None;
    initial.apply_to(&mut retained);
    assert_eq!(retained.as_ref().map(swm::SwmClassAvps::len), Some(1));

    let replacement = correlated_authorization_answer(&[
        class_avp(b"replacement-one"),
        class_avp(b"replacement-two"),
    ])
    .class_avp_update()
    .expect("bounded correlated AAA Class update");
    replacement.apply_to(&mut retained);
    let mut request = session_termination_request();
    retained
        .as_ref()
        .expect("replacement state retained")
        .clone_into_session_termination_request(&mut request)
        .expect("replacement transfers to STR");
    assert_eq!(
        class_values(&encoded_str(request)),
        vec![b"replacement-one".to_vec(), b"replacement-two".to_vec()]
    );

    let unchanged = correlated_authorization_answer(&[])
        .class_avp_update()
        .expect("absent AAA Class update");
    assert!(unchanged.is_unchanged());
    unchanged.apply_to(&mut retained);
    assert_eq!(
        retained.as_ref().map(swm::SwmClassAvps::len),
        Some(2),
        "absence must not erase prior Class state"
    );
}

#[test]
fn diagnostics_redact_class_origin_session_and_routing_values() {
    let correlated = correlated_answer(&[
        class_avp(CLASS_SENTINEL),
        mandatory_avp(base::AVP_SESSION_BINDING, &2_u32.to_be_bytes()),
        mandatory_avp(base::AVP_SESSION_SERVER_FAILOVER, &3_u32.to_be_bytes()),
    ]);
    let update = correlated.class_avp_update();
    let routing = correlated
        .authorization_session_routing()
        .expect("ordinary answer routing");
    let binding = routing.session_binding().expect("binding");
    let failover = routing.explicit_server_failover().expect("failover");
    let mut request = session_termination_request();
    let error = correlated_answer(&[])
        .authorization_session_routing()
        .expect("ordinary answer routing")
        .remove_destination_host_after_session_termination_delivery_failure(&mut request)
        .expect_err("REFUSE_SERVICE is fail closed");

    let diagnostics = [
        format!("{update:?}"),
        format!("{update}"),
        format!("{:?}", update.replacement().expect("replacement")),
        format!("{}", update.replacement().expect("replacement")),
        format!("{routing:?}"),
        format!("{routing}"),
        format!("{binding:?}"),
        format!("{binding}"),
        format!("{failover:?}"),
        format!("{failover}"),
        format!("{error:?}"),
        format!("{error}"),
        format!("{correlated:?}"),
    ]
    .join("\n");
    for secret in [
        std::str::from_utf8(CLASS_SENTINEL).expect("ASCII sentinel"),
        SESSION_ID,
        AAA_HOST,
        AAA_REALM,
        DRA_HOST,
        DRA_REALM,
    ] {
        assert!(
            !diagnostics.contains(secret),
            "diagnostics exposed private authorization-session state"
        );
    }
}
