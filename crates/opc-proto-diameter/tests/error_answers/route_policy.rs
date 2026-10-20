//! Closed route-policy errors preserve the existing request-bound answer contract.

use super::*;
use opc_proto_diameter::error_answer::DiameterRoutePolicyRejection;

const ROUTE_REQUEST: &str =
    include_str!("../fixtures/rfc6733/error_answers/route_policy_request.hex");
const UNABLE_TO_DELIVER_ANSWER: &str =
    include_str!("../fixtures/rfc6733/error_answers/unable_to_deliver_answer.hex");
const REALM_NOT_SERVED_ANSWER: &str =
    include_str!("../fixtures/rfc6733/error_answers/realm_not_served_answer.hex");

const POLICIES: [DiameterRoutePolicyRejection; 2] = [
    DiameterRoutePolicyRejection::UnableToDeliver,
    DiameterRoutePolicyRejection::RealmNotServed,
];

fn route_request(command: CommandCode) -> Vec<u8> {
    let mut request = fixture(ROUTE_REQUEST);
    request[5..8].copy_from_slice(&command.get().to_be_bytes()[1..]);
    if command == swm::COMMAND_ABORT_SESSION {
        // The independent RAR's Authorize-Only (0) becomes State-Maintained
        // (0) for an ASR, with the same remaining mandatory and routing AVPs.
        let message = decode_message(&request);
        let (offset, _) = find_avp_at(&message, base::AVP_RE_AUTH_REQUEST_TYPE);
        request[offset..offset + 4].copy_from_slice(&277_u32.to_be_bytes());
    }
    request
}

#[test]
fn route_policy_rejections_match_independent_wire_answers_for_rar_and_asr() {
    for command in [swm::COMMAND_RE_AUTH, swm::COMMAND_ABORT_SESSION] {
        let request = route_request(command);
        let message = decode_message(&request);
        if command == swm::COMMAND_RE_AUTH {
            swm::parse_swm_re_auth_request_envelope(&message, DecodeContext::conservative())
                .expect("independent RAR has valid typed grammar");
        } else {
            swm::parse_swm_abort_session_request_envelope(&message, DecodeContext::conservative())
                .expect("independent ASR has valid typed grammar");
        }
        let envelope = envelope(&request);
        assert_eq!(envelope.classify(&request, APP_DICTIONARIES), Ok(None));
        for (policy, code, failure_code, expected) in [
            (
                POLICIES[0],
                3002,
                "diameter_unable_to_deliver",
                UNABLE_TO_DELIVER_ANSWER,
            ),
            (
                POLICIES[1],
                3003,
                "diameter_realm_not_served",
                REALM_NOT_SERVED_ANSWER,
            ),
        ] {
            let bound = envelope
                .bind_route_policy_rejection(&request, policy, APP_DICTIONARIES)
                .expect("closed route policy binds to the inspected request");
            assert_eq!(bound.result_code(), code);
            assert_eq!(bound.as_str(), failure_code);
            assert_eq!(
                bound.failure(),
                &DiameterRequestFailure::RoutePolicy(policy)
            );
            assert!(bound.failure().failed_avp().is_none());
            for grammar in [
                DiameterErrorAnswerGrammar::Application,
                DiameterErrorAnswerGrammar::Rfc6733ErrorBitFallback,
            ] {
                let plan = build_diameter_error_answer(
                    &envelope,
                    &bound,
                    &origin(),
                    grammar,
                    EncodeContext::default(),
                )
                .expect("routing errors use the bounded error-answer builder");
                assert_eq!(plan.failure_code(), failure_code);
                assert_eq!(
                    plan.grammar(),
                    DiameterErrorAnswerGrammar::Rfc6733ErrorBitFallback
                );
                let mut encoded = BytesMut::new();
                plan.encode(&mut encoded, EncodeContext::default()).unwrap();
                let mut expected = fixture(expected);
                expected[5..8].copy_from_slice(&command.get().to_be_bytes()[1..]);
                assert_eq!(encoded.as_ref(), expected.as_slice());
                let answer = decode_message(&encoded);
                assert_eq!(result_code(&answer), code);
                assert!(!answer.header.flags.is_request());
                assert!(!answer.header.flags.is_potentially_retransmitted());
                assert!(answer.header.flags.is_error());
                assert_eq!(
                    answer.header.flags.is_proxiable(),
                    message.header.flags.is_proxiable()
                );
                assert_eq!(answer.header.command_code, message.header.command_code);
                assert_eq!(answer.header.application_id, message.header.application_id);
                assert_eq!(
                    answer.header.hop_by_hop_identifier,
                    message.header.hop_by_hop_identifier
                );
                assert_eq!(
                    answer.header.end_to_end_identifier,
                    message.header.end_to_end_identifier
                );
                let reflected = |message: &Message<'_>| {
                    avps(message)
                        .into_iter()
                        .filter(|avp| matches!(avp.header.code, AVP_SESSION_ID | AVP_PROXY_INFO))
                        .map(|avp| (avp.header.code, avp.value.to_vec()))
                        .collect::<Vec<_>>()
                };
                assert_eq!(reflected(&answer), reflected(&message));
                assert_eq!(
                    reflected(&answer).len(),
                    3,
                    "one session and two ordered proxies"
                );
                assert!(avps(&answer).iter().all(|avp| !matches!(
                    avp.header.code,
                    AVP_DESTINATION_HOST
                        | AVP_DESTINATION_REALM
                        | AVP_ROUTE_RECORD
                        | AVP_FAILED_AVP
                        | base::AVP_USER_NAME
                )));
            }
        }
    }
}

#[test]
fn route_policy_rejection_requires_proxiable_request() {
    let mut avps = encode_avp(AvpHeader::ietf(AVP_ORIGIN_HOST, true), b"peer.invalid");
    avps.extend(encode_avp(
        AvpHeader::ietf(AVP_ORIGIN_REALM, true),
        b"invalid",
    ));
    let request = encode_request(
        CommandFlags::request(false),
        COMMAND_DEVICE_WATCHDOG,
        APPLICATION_ID_COMMON_MESSAGES,
        &avps,
    );
    let message = decode_message(&request);
    parse_device_watchdog_request(&message, DecodeContext::conservative())
        .expect("the non-proxiable watchdog has valid command grammar");
    let envelope = envelope(&request);
    assert_eq!(envelope.classify(&request, APP_DICTIONARIES), Ok(None));
    for policy in POLICIES {
        let error = envelope
            .bind_route_policy_rejection(&request, policy, APP_DICTIONARIES)
            .expect_err("a locally processed request cannot acquire route-policy authority");
        assert_eq!(
            error,
            DiameterRequestClassificationError::RoutePolicyRequiresProxiableRequest
        );
        assert_eq!(
            error.as_str(),
            "diameter_request_classification_route_policy_requires_proxiable_request"
        );
    }
}

#[test]
fn route_policy_rejection_keeps_earlier_header_framing_and_dictionary_failures() {
    let mut error_bit = fixture(ROUTE_REQUEST);
    error_bit[4] |= CommandFlags::ERROR;
    let mut reserved_bit = fixture(ROUTE_REQUEST);
    reserved_bit[4] |= 1;
    let mut version = fixture(ROUTE_REQUEST);
    version[0] = 2;
    let mut not_proxiable = fixture(ROUTE_REQUEST);
    not_proxiable[4] &= !CommandFlags::PROXIABLE;
    let wrong_m = encode_request(
        CommandFlags::request(false),
        COMMAND_DEVICE_WATCHDOG,
        APPLICATION_ID_COMMON_MESSAGES,
        &encode_avp(AvpHeader::ietf(AVP_ORIGIN_HOST, false), b"peer.invalid"),
    );
    let malformed = encode_request(
        CommandFlags::request(false),
        COMMAND_DEVICE_WATCHDOG,
        APPLICATION_ID_COMMON_MESSAGES,
        &[0, 0, 1, 8, 0x40, 0, 0, 7],
    );
    for (request, expected_code) in [
        (error_bit, 3008),
        (reserved_bit, 5013),
        (version, 5011),
        (not_proxiable, 3008),
        (wrong_m, 3009),
        (malformed, 5014),
        (fixture(UNKNOWN_COMMAND_REQUEST), 3001),
        (fixture(UNSUPPORTED_APPLICATION_REQUEST), 3007),
        (fixture(UNSUPPORTED_MANDATORY_AVP_REQUEST), 5001),
        (fixture(FORBIDDEN_AVP_REQUEST), 5008),
        (fixture(EXCESS_SINGLETON_REQUEST), 5009),
    ] {
        let envelope = envelope(&request);
        let first = envelope
            .classify(&request, APP_DICTIONARIES)
            .unwrap()
            .unwrap();
        assert_eq!(first.result_code(), expected_code);
        for policy in POLICIES {
            let bound = envelope
                .bind_route_policy_rejection(&request, policy, APP_DICTIONARIES)
                .expect("the existing failure wins before route policy");
            assert_eq!(bound, first);
            let encoded = encode_plan(
                &request,
                &envelope,
                &bound,
                DiameterErrorAnswerGrammar::Application,
            );
            assert_eq!(result_code(&decode_message(&encoded)), expected_code);
        }
    }
}

#[test]
fn route_policy_rejection_fails_closed_on_ambiguous_dictionaries() {
    let request = encode_request(
        CommandFlags::request(false),
        COMMAND_DEVICE_WATCHDOG,
        APPLICATION_ID_COMMON_MESSAGES,
        &encode_avp(AvpHeader::ietf(AVP_ORIGIN_HOST, true), b"peer.invalid"),
    );
    let envelope = envelope(&request);
    for (dictionaries, expected) in [
        (
            AMBIGUOUS_APPLICATION_DICTIONARIES,
            DiameterRequestClassificationError::ApplicationAmbiguous,
        ),
        (
            AMBIGUOUS_COMMAND_DICTIONARIES,
            DiameterRequestClassificationError::CommandAmbiguous,
        ),
        (
            AMBIGUOUS_AVP_DICTIONARIES,
            DiameterRequestClassificationError::AvpDefinitionAmbiguous,
        ),
    ] {
        for policy in POLICIES {
            assert_eq!(
                envelope.bind_route_policy_rejection(&request, policy, dictionaries),
                Err(expected.clone())
            );
        }
    }
}

#[test]
fn route_policy_rejection_rejects_changed_requests_and_cross_request_tokens() {
    let request = fixture(ROUTE_REQUEST);
    let envelope = envelope(&request);
    let message = decode_message(&request);
    let (destination, _) = find_avp_at(&message, AVP_DESTINATION_HOST);
    let (session, _) = find_avp_at(&message, AVP_SESSION_ID);
    for policy in POLICIES {
        let bound = envelope
            .bind_route_policy_rejection(&request, policy, APP_DICTIONARIES)
            .unwrap();
        for offset in [
            12,
            16,
            destination + AVP_HEADER_LEN,
            session + AVP_HEADER_LEN,
        ] {
            let mut different = request.clone();
            different[offset] ^= 1;
            assert_eq!(
                envelope.bind_route_policy_rejection(&different, policy, APP_DICTIONARIES),
                Err(DiameterRequestClassificationError::RequestMismatch)
            );
            let different_envelope = super::envelope(&different);
            assert!(build_diameter_error_answer(
                &different_envelope,
                &bound,
                &origin(),
                DiameterErrorAnswerGrammar::Application,
                EncodeContext::default(),
            )
            .is_err());
        }
        assert_eq!(
            envelope.bind_application_failure(
                &request,
                DiameterRequestFailure::RoutePolicy(policy),
                APP_DICTIONARIES,
            ),
            Err(DiameterRequestClassificationError::FailureProvenanceMismatch),
            "the parser-evidence API cannot manufacture route-policy provenance"
        );
    }
}

#[test]
fn route_policy_rejection_preserves_redaction_and_inspection_and_encoding_bounds() {
    let request = fixture(ROUTE_REQUEST);
    let envelope = envelope(&request);
    for policy in POLICIES {
        let bound = envelope
            .bind_route_policy_rejection(&request, policy, APP_DICTIONARIES)
            .unwrap();
        let origin = origin();
        let plan = build_diameter_error_answer(
            &envelope,
            &bound,
            &origin,
            DiameterErrorAnswerGrammar::Application,
            EncodeContext::default(),
        )
        .unwrap();
        let sizing = plan.amplification_metadata();
        assert_eq!(sizing.request_wire_len, request.len());
        assert_eq!(sizing.planned_response_len, plan.planned_response_len());
        let retained = envelope.session_id().unwrap().retained_wire_len()
            + envelope
                .proxy_infos()
                .iter()
                .map(|avp| avp.retained_wire_len())
                .sum::<usize>();
        assert_eq!(sizing.retained_request_bytes, retained);
        assert!(retained <= request.len());
        let too_small = EncodeContext {
            max_message_len: plan.planned_response_len() - 1,
            ..EncodeContext::default()
        };
        assert!(build_diameter_error_answer(
            &envelope,
            &bound,
            &origin,
            DiameterErrorAnswerGrammar::Application,
            too_small,
        )
        .is_err());
        let mut output = BytesMut::from(&b"unchanged"[..]);
        assert!(plan.encode(&mut output, too_small).is_err());
        assert_eq!(output.as_ref(), b"unchanged");
        assert!(plan.wire_len(too_small).is_err());
        for rendered in [
            format!("{envelope:?}"),
            format!("{bound:?}"),
            format!("{origin:?}"),
            format!("{plan:?}"),
        ] {
            for secret in [
                "sess;route;001",
                "proxy-a",
                "proxy-b",
                "destination.example",
                "destination.realm",
                "user@realm.example",
                "aaa.local",
                "local.test",
            ] {
                assert!(
                    !rendered.contains(secret),
                    "route error diagnostics leaked a request value"
                );
            }
        }
    }
    for (context, expected) in [
        (
            DecodeContext {
                max_message_len: request.len() - 1,
                ..DecodeContext::conservative()
            },
            DiameterUnanswerableReason::MessageLengthExceeded,
        ),
        (
            DecodeContext {
                max_ies: 0,
                ..DecodeContext::conservative()
            },
            DiameterUnanswerableReason::AvpCountExceeded,
        ),
    ] {
        assert!(matches!(inspect_diameter_request(&request, context),
            DiameterRequestInspection::Unanswerable(reason) if reason == expected));
    }
}
