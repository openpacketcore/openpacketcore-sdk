use std::num::NonZeroU32;

use bytes::BytesMut;
use opc_proto_gtpv2c::{
    inspect_gtpv2c_request, CauseValue, Gtpv2cErrorResponseDecision, Gtpv2cErrorResponseKind,
    Gtpv2cErrorResponsePlan, Gtpv2cErrorResponsePlanner, Gtpv2cOffendingIe, Gtpv2cProtocolError,
    Gtpv2cProtocolErrorKind, Gtpv2cProtocolErrorResponseTeid, Gtpv2cReceivedPeerMetadata,
    Gtpv2cReceivedTeid, Gtpv2cRequestFailure, Gtpv2cRequestInspection, Gtpv2cSequenceNumber,
    Gtpv2cUnanswerableReason, Message, MessageType, Recovery, S2bMessage,
    MAX_GTPV2C_ERROR_RESPONSE_WIRE_LEN,
};
use opc_protocol::{
    BorrowDecode, DecodeContext, Encode, EncodeContext, EncodeErrorCode, ValidationLevel,
};

const UNSUPPORTED_VERSION_REQUEST: &str =
    include_str!("fixtures/spec/error_response_plans/unsupported_version_request.hex");
const VERSION_NOT_SUPPORTED_RESPONSE: &str =
    include_str!("fixtures/spec/error_response_plans/version_not_supported_response.hex");
const TOO_SHORT_COMMON_HEADER: &str =
    include_str!("fixtures/spec/error_response_plans/too_short_common_header.hex");
const LENGTH_MISMATCH_CREATE_SESSION_REQUEST: &str =
    include_str!("fixtures/spec/error_response_plans/length_mismatch_create_session_request.hex");
const INVALID_LENGTH_CREATE_SESSION_RESPONSE_REMOTE: &str = include_str!(
    "fixtures/spec/error_response_plans/invalid_length_create_session_response_remote.hex"
);
const INVALID_LENGTH_CREATE_SESSION_RESPONSE_NO_LOOKUP: &str = include_str!(
    "fixtures/spec/error_response_plans/invalid_length_create_session_response_no_lookup.hex"
);
const UNKNOWN_TEID_DELETE_SESSION_REQUEST: &str =
    include_str!("fixtures/spec/error_response_plans/unknown_teid_delete_session_request.hex");
const CONTEXT_NOT_FOUND_DELETE_SESSION_RESPONSE: &str = include_str!(
    "fixtures/spec/error_response_plans/context_not_found_delete_session_response.hex"
);
const MISSING_MANDATORY_CREATE_SESSION_REQUEST: &str =
    include_str!("fixtures/spec/error_response_plans/missing_mandatory_create_session_request.hex");
const MISSING_MANDATORY_CREATE_SESSION_RESPONSE: &str = include_str!(
    "fixtures/spec/error_response_plans/missing_mandatory_create_session_response.hex"
);
const MISSING_CONDITIONAL_CREATE_SESSION_RESPONSE: &str = include_str!(
    "fixtures/spec/error_response_plans/missing_conditional_create_session_response.hex"
);
const INVALID_IE_LENGTH_MODIFY_BEARER_REQUEST: &str =
    include_str!("fixtures/spec/error_response_plans/invalid_ie_length_modify_bearer_request.hex");
const INVALID_IE_LENGTH_MODIFY_BEARER_RESPONSE: &str =
    include_str!("fixtures/spec/error_response_plans/invalid_ie_length_modify_bearer_response.hex");
const INCORRECT_IE_DELETE_SESSION_REQUEST: &str =
    include_str!("fixtures/spec/error_response_plans/incorrect_ie_delete_session_request.hex");
const INCORRECT_IE_DELETE_SESSION_RESPONSE: &str =
    include_str!("fixtures/spec/error_response_plans/incorrect_ie_delete_session_response.hex");
const MALFORMED_ECHO_REQUEST: &str =
    include_str!("fixtures/spec/error_response_plans/malformed_echo_request.hex");
const ECHO_RESPONSE: &str = include_str!("fixtures/spec/error_response_plans/echo_response.hex");
const LENGTH_MISMATCH_RESPONSE: &str =
    include_str!("fixtures/spec/error_response_plans/length_mismatch_response.hex");
const UNKNOWN_MESSAGE: &str =
    include_str!("fixtures/spec/error_response_plans/unknown_message.hex");

fn fixture(source: &str) -> Vec<u8> {
    source
        .split_ascii_whitespace()
        .map(|octet| u8::from_str_radix(octet, 16).expect("fixture octet must be hexadecimal"))
        .collect()
}

fn planner() -> Gtpv2cErrorResponsePlanner {
    Gtpv2cErrorResponsePlanner::new(
        Gtpv2cSequenceNumber::new(0x01_02_03).expect("test sequence must fit 24 bits"),
        Recovery {
            restart_counter: 0x7a,
        },
    )
}

fn remote(value: u32) -> Gtpv2cProtocolErrorResponseTeid {
    Gtpv2cProtocolErrorResponseTeid::Remote(
        NonZeroU32::new(value).expect("test remote TEID must be non-zero"),
    )
}

fn protocol_failure(
    kind: Gtpv2cProtocolErrorKind,
    response_teid: Gtpv2cProtocolErrorResponseTeid,
) -> Gtpv2cRequestFailure {
    Gtpv2cRequestFailure::Protocol(Gtpv2cProtocolError::new(kind, response_teid))
}

fn response_plan(decision: Gtpv2cErrorResponseDecision) -> Gtpv2cErrorResponsePlan {
    match decision {
        Gtpv2cErrorResponseDecision::Respond(plan) => plan,
        Gtpv2cErrorResponseDecision::Unanswerable(reason) => {
            panic!(
                "expected response plan, got unanswerable: {}",
                reason.as_str()
            )
        }
    }
}

fn encode(plan: &Gtpv2cErrorResponsePlan) -> Vec<u8> {
    let mut output = BytesMut::new();
    plan.encode(&mut output, EncodeContext::default())
        .expect("test plan must encode");
    output.to_vec()
}

#[test]
fn unsupported_higher_version_uses_local_sequence_and_header_only_message_three() {
    let request = fixture(UNSUPPORTED_VERSION_REQUEST);
    let Gtpv2cRequestInspection::UnsupportedVersion(envelope) = inspect_gtpv2c_request(&request)
    else {
        panic!("complete higher-version header must be answerable");
    };
    assert_eq!(envelope.version(), 3);
    assert_eq!(envelope.received_teid().value(), Some(0xdead_beef));
    assert_eq!(envelope.actual_len(), 12);
    let envelope_debug = format!("{envelope:?}");
    assert!(!envelope_debug.contains("deadbeef"));
    assert!(envelope_debug.contains("<redacted>"));

    let plan = planner().plan_unsupported_version(envelope);
    assert_eq!(plan.kind(), Gtpv2cErrorResponseKind::VersionNotSupported);
    assert_eq!(
        plan.message_type(),
        MessageType::VersionNotSupportedIndication
    );
    assert_eq!(plan.sequence_number().get(), 0x01_02_03);
    assert_ne!(plan.sequence_number().get(), 0xaa_bb_cc);
    assert_eq!(plan.cause(), None);
    assert_eq!(plan.planned_output_len(), 8);
    assert_eq!(encode(&plan), fixture(VERSION_NOT_SUPPORTED_RESPONSE));

    let encoded = encode(&plan);
    let (_, decoded) = Message::decode(&encoded, DecodeContext::default())
        .expect("message 3 fixture must decode through the generic shell");
    assert_eq!(
        decoded.message_type(),
        MessageType::VersionNotSupportedIndication
    );
    assert!(decoded.raw_ies.is_empty());
}

#[test]
fn too_short_common_header_is_unanswerable_and_produces_no_bytes() {
    let request = fixture(TOO_SHORT_COMMON_HEADER);
    assert_eq!(
        inspect_gtpv2c_request(&request),
        Gtpv2cRequestInspection::Unanswerable(Gtpv2cUnanswerableReason::TooShortForHeader)
    );
    assert_eq!(
        planner().plan(
            &request,
            protocol_failure(
                Gtpv2cProtocolErrorKind::InvalidMessageLength,
                Gtpv2cProtocolErrorResponseTeid::NoLookup,
            ),
        ),
        Gtpv2cErrorResponseDecision::Unanswerable(Gtpv2cUnanswerableReason::TooShortForHeader)
    );
}

#[test]
fn answerable_classes_require_their_exact_complete_fixed_header() {
    let unsupported = fixture(UNSUPPORTED_VERSION_REQUEST);
    for prefix_len in 0..12 {
        assert_eq!(
            inspect_gtpv2c_request(&unsupported[..prefix_len]),
            Gtpv2cRequestInspection::Unanswerable(Gtpv2cUnanswerableReason::TooShortForHeader),
            "unsupported-version T=1 prefix length {prefix_len}"
        );
    }
    assert!(matches!(
        inspect_gtpv2c_request(&unsupported),
        Gtpv2cRequestInspection::UnsupportedVersion(_)
    ));

    let ordinary = fixture(MISSING_MANDATORY_CREATE_SESSION_REQUEST);
    for prefix_len in 0..12 {
        assert_eq!(
            inspect_gtpv2c_request(&ordinary[..prefix_len]),
            Gtpv2cRequestInspection::Unanswerable(Gtpv2cUnanswerableReason::TooShortForHeader),
            "ordinary T=1 prefix length {prefix_len}"
        );
    }
    assert!(matches!(
        inspect_gtpv2c_request(&ordinary),
        Gtpv2cRequestInspection::Request(_)
    ));

    let echo = fixture(MALFORMED_ECHO_REQUEST);
    for prefix_len in 0..8 {
        assert_eq!(
            inspect_gtpv2c_request(&echo[..prefix_len]),
            Gtpv2cRequestInspection::Unanswerable(Gtpv2cUnanswerableReason::TooShortForHeader),
            "Echo T=0 prefix length {prefix_len}"
        );
    }
    assert!(matches!(
        inspect_gtpv2c_request(&echo),
        Gtpv2cRequestInspection::Request(_)
    ));
}

#[test]
fn request_length_mismatch_uses_remote_teid_and_request_sequence() {
    let request = fixture(LENGTH_MISMATCH_CREATE_SESSION_REQUEST);
    let plan = response_plan(planner().plan(
        &request,
        protocol_failure(
            Gtpv2cProtocolErrorKind::InvalidMessageLength,
            remote(0x1122_3344),
        ),
    ));
    assert_eq!(plan.message_type(), MessageType::CreateSessionResponse);
    assert_eq!(plan.sequence_number().get(), 0x0a_0b_0c);
    assert_eq!(plan.cause(), Some(CauseValue::InvalidLength));
    assert!(!plan.uses_zero_teid());
    assert_eq!(
        encode(&plan),
        fixture(INVALID_LENGTH_CREATE_SESSION_RESPONSE_REMOTE)
    );
}

#[test]
fn no_lookup_length_error_uses_zero_without_context_not_found() {
    let request = fixture(LENGTH_MISMATCH_CREATE_SESSION_REQUEST);
    let plan = response_plan(planner().plan(
        &request,
        protocol_failure(
            Gtpv2cProtocolErrorKind::MissingMandatoryIe(
                Gtpv2cOffendingIe::new(71, 0).expect("test IE identity must be valid"),
            ),
            Gtpv2cProtocolErrorResponseTeid::NoLookup,
        ),
    ));
    assert!(plan.uses_zero_teid());
    assert_eq!(plan.cause(), Some(CauseValue::InvalidLength));
    assert_ne!(plan.cause(), Some(CauseValue::ContextNotFound));
    assert_eq!(plan.offending_ie(), None);
    assert_eq!(
        encode(&plan),
        fixture(INVALID_LENGTH_CREATE_SESSION_RESPONSE_NO_LOOKUP)
    );
}

#[test]
fn unknown_session_teid_maps_to_context_not_found_and_zero_teid() {
    let request = fixture(UNKNOWN_TEID_DELETE_SESSION_REQUEST);
    let plan = response_plan(planner().plan(&request, Gtpv2cRequestFailure::UnknownReceivedTeid));
    assert_eq!(plan.message_type(), MessageType::DeleteSessionResponse);
    assert_eq!(plan.sequence_number().get(), 0x01_02_03);
    assert_eq!(plan.cause(), Some(CauseValue::ContextNotFound));
    assert!(plan.uses_zero_teid());
    assert_eq!(
        encode(&plan),
        fixture(CONTEXT_NOT_FOUND_DELETE_SESSION_RESPONSE)
    );
}

#[test]
fn zero_teid_initial_request_cannot_be_classified_as_unknown_received_teid() {
    let request = fixture(MISSING_MANDATORY_CREATE_SESSION_REQUEST);
    let Gtpv2cRequestInspection::Request(envelope) = inspect_gtpv2c_request(&request) else {
        panic!("complete version-2 request must produce an envelope");
    };
    assert_eq!(envelope.received_teid(), Gtpv2cReceivedTeid::Zero);
    let expected = Gtpv2cErrorResponseDecision::Unanswerable(
        Gtpv2cUnanswerableReason::UnknownTeidRequiresNonZeroReceivedTeid,
    );
    assert_eq!(
        planner().plan_request_failure(envelope, Gtpv2cRequestFailure::UnknownReceivedTeid),
        expected
    );
    assert_eq!(
        planner().plan(&request, Gtpv2cRequestFailure::UnknownReceivedTeid),
        expected
    );
    let Gtpv2cErrorResponseDecision::Unanswerable(reason) = expected else {
        panic!("expected typed unanswerable result");
    };
    assert_eq!(
        reason.as_str(),
        "gtpv2c_error_response_unknown_teid_requires_nonzero_received_teid"
    );
}

#[test]
fn missing_mandatory_ie_includes_type_and_instance() {
    let request = fixture(MISSING_MANDATORY_CREATE_SESSION_REQUEST);
    let Gtpv2cRequestInspection::Request(envelope) = inspect_gtpv2c_request(&request) else {
        panic!("complete version-2 request must produce an envelope");
    };
    let offending = Gtpv2cOffendingIe::new(71, 0).expect("APN identity must be valid");
    let plan = response_plan(planner().plan_request_failure(
        envelope,
        protocol_failure(
            Gtpv2cProtocolErrorKind::MissingMandatoryIe(offending),
            remote(0xa1a2_a3a4),
        ),
    ));
    assert_eq!(plan.cause(), Some(CauseValue::MandatoryIeMissing));
    assert_eq!(plan.offending_ie(), Some(offending));
    assert_eq!(plan.planned_output_len(), 22);
    assert_eq!(
        encode(&plan),
        fixture(MISSING_MANDATORY_CREATE_SESSION_RESPONSE)
    );
}

#[test]
fn typed_request_continuation_rejects_conflicting_failure_evidence() {
    let matching = fixture(MISSING_MANDATORY_CREATE_SESSION_REQUEST);
    let Gtpv2cRequestInspection::Request(matching) = inspect_gtpv2c_request(&matching) else {
        panic!("complete version-2 request must produce an envelope");
    };
    assert_eq!(
        planner().plan_request_failure(
            matching,
            protocol_failure(
                Gtpv2cProtocolErrorKind::InvalidMessageLength,
                Gtpv2cProtocolErrorResponseTeid::NoLookup,
            ),
        ),
        Gtpv2cErrorResponseDecision::Unanswerable(Gtpv2cUnanswerableReason::MessageLengthMatches)
    );

    let echo = fixture(MALFORMED_ECHO_REQUEST);
    let Gtpv2cRequestInspection::Request(echo) = inspect_gtpv2c_request(&echo) else {
        panic!("complete Echo request must produce an envelope");
    };
    assert_eq!(
        planner().plan_request_failure(echo, Gtpv2cRequestFailure::UnknownReceivedTeid),
        Gtpv2cErrorResponseDecision::Unanswerable(Gtpv2cUnanswerableReason::UnknownTeidForEcho)
    );

    let mut mismatched = fixture(LENGTH_MISMATCH_CREATE_SESSION_REQUEST);
    mismatched[4..8].copy_from_slice(&0x0102_0304u32.to_be_bytes());
    let Gtpv2cRequestInspection::Request(mismatched) = inspect_gtpv2c_request(&mismatched) else {
        panic!("complete fixed request header must produce an envelope");
    };
    assert_eq!(
        planner().plan_request_failure(mismatched, Gtpv2cRequestFailure::UnknownReceivedTeid,),
        Gtpv2cErrorResponseDecision::Unanswerable(
            Gtpv2cUnanswerableReason::ConflictingLengthAndTeidFailure
        )
    );
}

#[test]
fn missing_verifiable_conditional_ie_uses_conditional_missing_cause() {
    let request = fixture(MISSING_MANDATORY_CREATE_SESSION_REQUEST);
    let offending = Gtpv2cOffendingIe::new(77, 0).expect("Indication identity must be valid");
    let plan = response_plan(planner().plan(
        &request,
        protocol_failure(
            Gtpv2cProtocolErrorKind::MissingConditionalIe(offending),
            remote(0xa1a2_a3a4),
        ),
    ));
    assert_eq!(plan.cause(), Some(CauseValue::ConditionalIeMissing));
    assert_eq!(plan.offending_ie(), Some(offending));
    assert_eq!(
        encode(&plan),
        fixture(MISSING_CONDITIONAL_CREATE_SESSION_RESPONSE)
    );
}

#[test]
fn invalid_mandatory_ie_length_includes_offending_identity() {
    let request = fixture(INVALID_IE_LENGTH_MODIFY_BEARER_REQUEST);
    let offending = Gtpv2cOffendingIe::new(93, 0).expect("Bearer Context identity must be valid");
    let plan = response_plan(planner().plan(
        &request,
        protocol_failure(
            Gtpv2cProtocolErrorKind::InvalidIeLength(offending),
            remote(0x5566_7788),
        ),
    ));
    assert_eq!(plan.message_type(), MessageType::ModifyBearerResponse);
    assert_eq!(plan.cause(), Some(CauseValue::InvalidLength));
    assert_eq!(plan.offending_ie(), Some(offending));
    assert_eq!(
        encode(&plan),
        fixture(INVALID_IE_LENGTH_MODIFY_BEARER_RESPONSE)
    );
}

#[test]
fn semantically_incorrect_ie_maps_to_mandatory_ie_incorrect() {
    let request = fixture(INCORRECT_IE_DELETE_SESSION_REQUEST);
    let offending = Gtpv2cOffendingIe::new(73, 0).expect("EBI identity must be valid");
    let plan = response_plan(planner().plan(
        &request,
        protocol_failure(
            Gtpv2cProtocolErrorKind::IncorrectIe(offending),
            remote(0x1020_3040),
        ),
    ));
    assert_eq!(plan.cause(), Some(CauseValue::MandatoryIeIncorrect));
    assert_eq!(plan.offending_ie(), Some(offending));
    assert_eq!(encode(&plan), fixture(INCORRECT_IE_DELETE_SESSION_RESPONSE));
}

#[test]
fn malformed_echo_ie_produces_echo_response_without_cause() {
    let request = fixture(MALFORMED_ECHO_REQUEST);
    let procedure = DecodeContext {
        validation_level: ValidationLevel::ProcedureAware,
        ..DecodeContext::default()
    };
    assert!(S2bMessage::decode(&request, procedure).is_err());
    let offending = Gtpv2cOffendingIe::new(3, 0).expect("Recovery identity must be valid");
    let plan = response_plan(planner().plan(
        &request,
        protocol_failure(
            Gtpv2cProtocolErrorKind::InvalidIeLength(offending),
            Gtpv2cProtocolErrorResponseTeid::NoLookup,
        ),
    ));
    assert_eq!(plan.kind(), Gtpv2cErrorResponseKind::Echo);
    assert_eq!(plan.message_type(), MessageType::EchoResponse);
    assert_eq!(plan.sequence_number().get(), 0x44_55_66);
    assert_eq!(plan.cause(), None);
    assert_eq!(plan.offending_ie(), None);
    assert_eq!(encode(&plan), fixture(ECHO_RESPONSE));
}

#[test]
fn response_truncation_unknown_message_and_echo_length_mismatch_are_discarded() {
    let failure = protocol_failure(
        Gtpv2cProtocolErrorKind::InvalidMessageLength,
        Gtpv2cProtocolErrorResponseTeid::NoLookup,
    );
    assert_eq!(
        planner().plan(&fixture(LENGTH_MISMATCH_RESPONSE), failure),
        Gtpv2cErrorResponseDecision::Unanswerable(Gtpv2cUnanswerableReason::NotARequest)
    );
    assert_eq!(
        planner().plan(&fixture(UNKNOWN_MESSAGE), failure),
        Gtpv2cErrorResponseDecision::Unanswerable(Gtpv2cUnanswerableReason::UnknownMessageType)
    );

    let mut echo = fixture(MALFORMED_ECHO_REQUEST);
    echo.push(0xff);
    assert_eq!(
        planner().plan(&echo, failure),
        Gtpv2cErrorResponseDecision::Unanswerable(Gtpv2cUnanswerableReason::EchoLengthMismatch)
    );

    let lower_version = [0x28, 32, 0, 8, 0, 0, 0, 0, 1, 2, 3, 0];
    assert_eq!(
        planner().plan(&lower_version, failure),
        Gtpv2cErrorResponseDecision::Unanswerable(
            Gtpv2cUnanswerableReason::UnsupportedLowerVersion
        )
    );
    let piggybacked = [0x58, 32, 0, 8, 0, 0, 0, 0, 1, 2, 3, 0];
    assert_eq!(
        planner().plan(&piggybacked, failure),
        Gtpv2cErrorResponseDecision::Unanswerable(Gtpv2cUnanswerableReason::PiggybackedMessage)
    );
    let echo_with_teid = [0x48, 1, 0, 8, 0, 0, 0, 0, 1, 2, 3, 0];
    assert_eq!(
        planner().plan(&echo_with_teid, failure),
        Gtpv2cErrorResponseDecision::Unanswerable(
            Gtpv2cUnanswerableReason::InvalidRequestHeaderShape
        )
    );
}

#[test]
fn every_declared_s2b_request_maps_to_its_corresponding_response() {
    let mappings = [
        (32, MessageType::CreateSessionResponse),
        (34, MessageType::ModifyBearerResponse),
        (36, MessageType::DeleteSessionResponse),
        (95, MessageType::CreateBearerResponse),
        (97, MessageType::UpdateBearerResponse),
        (99, MessageType::DeleteBearerResponse),
    ];
    for (request_type, response_type) in mappings {
        let request = [0x48, request_type, 0, 8, 0x10, 0x20, 0x30, 0x40, 1, 2, 3, 0];
        let plan = response_plan(planner().plan(
            &request,
            protocol_failure(
                Gtpv2cProtocolErrorKind::MissingMandatoryIe(
                    Gtpv2cOffendingIe::new(1, 0).expect("test IE identity must be valid"),
                ),
                Gtpv2cProtocolErrorResponseTeid::NoLookup,
            ),
        ));
        assert_eq!(plan.message_type(), response_type);
        assert_eq!(plan.sequence_number().get(), 0x01_02_03);
    }
}

#[test]
fn ordinary_error_response_copies_request_message_priority() {
    let request = [0x4c, 32, 0, 8, 0, 0, 0, 0, 1, 2, 3, 0xa0];
    let plan = response_plan(planner().plan(
        &request,
        protocol_failure(
            Gtpv2cProtocolErrorKind::MissingMandatoryIe(
                Gtpv2cOffendingIe::new(71, 0).expect("test IE identity must be valid"),
            ),
            remote(0x1122_3344),
        ),
    ));
    let encoded = encode(&plan);
    assert_eq!(encoded[0], 0x4c);
    assert_eq!(encoded[11], 0xa0);
}

#[test]
fn output_size_is_bounded_and_capacity_failure_writes_nothing() {
    let plan = response_plan(planner().plan(
        &fixture(MISSING_MANDATORY_CREATE_SESSION_REQUEST),
        protocol_failure(
            Gtpv2cProtocolErrorKind::MissingMandatoryIe(
                Gtpv2cOffendingIe::new(71, 0).expect("test IE identity must be valid"),
            ),
            remote(0xa1a2_a3a4),
        ),
    ));
    assert_eq!(
        plan.planned_output_len(),
        MAX_GTPV2C_ERROR_RESPONSE_WIRE_LEN
    );
    assert_eq!(
        plan.amplification_metadata().planned_output_len,
        MAX_GTPV2C_ERROR_RESPONSE_WIRE_LEN
    );
    assert_eq!(plan.amplification_metadata().input_len, 12);

    let limited = EncodeContext {
        max_message_len: MAX_GTPV2C_ERROR_RESPONSE_WIRE_LEN - 1,
        ..EncodeContext::default()
    };
    let mut output = BytesMut::new();
    let error = plan
        .encode(&mut output, limited)
        .expect_err("capacity bound must fail before writing");
    assert!(matches!(
        error.code(),
        EncodeErrorCode::CapacityExceeded {
            required: MAX_GTPV2C_ERROR_RESPONSE_WIRE_LEN,
            available: 21,
        }
    ));
    assert!(output.is_empty());
}

#[test]
fn peer_tuple_and_all_debug_paths_redact_teids_addresses_and_payloads() {
    let request = fixture(UNKNOWN_TEID_DELETE_SESSION_REQUEST);
    let Gtpv2cRequestInspection::Request(envelope) = inspect_gtpv2c_request(&request) else {
        panic!("known request must produce an envelope");
    };
    assert!(matches!(
        envelope.received_teid(),
        Gtpv2cReceivedTeid::NonZero(_)
    ));
    let envelope_debug = format!("{envelope:?}");
    assert!(!envelope_debug.contains("99aabbcc"));
    assert!(envelope_debug.contains("<redacted>"));

    let failure = protocol_failure(
        Gtpv2cProtocolErrorKind::MissingMandatoryIe(
            Gtpv2cOffendingIe::new(71, 0).expect("test IE identity must be valid"),
        ),
        remote(0x1122_3344),
    );
    let failure_debug = format!("{failure:?}");
    assert!(!failure_debug.contains("11223344"));
    assert!(failure_debug.contains("<redacted>"));

    let plan =
        response_plan(planner().plan(&fixture(MISSING_MANDATORY_CREATE_SESSION_REQUEST), failure));
    let send = plan.with_received_peer(Gtpv2cReceivedPeerMetadata::new(
        "peer-secret-address",
        "local-secret-address",
    ));
    assert_eq!(send.send_tuple.source(), &"local-secret-address");
    assert_eq!(send.send_tuple.destination(), &"peer-secret-address");
    let debug = format!("{send:?}");
    assert!(!debug.contains("peer-secret-address"));
    assert!(!debug.contains("local-secret-address"));
    assert!(!debug.contains("11223344"));
    assert!(debug.contains("<redacted>"));
}

#[test]
fn checked_sequence_and_offending_ie_bounds_fail_closed() {
    let sequence_error =
        Gtpv2cSequenceNumber::new(0x0100_0000).expect_err("more than 24 bits must fail");
    assert_eq!(
        sequence_error.as_str(),
        "gtpv2c_sequence_number_out_of_range"
    );
    let instance_error = Gtpv2cOffendingIe::new(71, 16).expect_err("IE instance is four bits");
    assert_eq!(
        instance_error.as_str(),
        "gtpv2c_offending_ie_instance_out_of_range"
    );
}

#[test]
fn no_lookup_protocol_type_cannot_express_context_not_found() {
    let offending = Gtpv2cOffendingIe::new(71, 0).expect("test IE identity must be valid");
    let kinds = [
        Gtpv2cProtocolErrorKind::InvalidMessageLength,
        Gtpv2cProtocolErrorKind::MissingMandatoryIe(offending),
        Gtpv2cProtocolErrorKind::MissingConditionalIe(offending),
        Gtpv2cProtocolErrorKind::InvalidIeLength(offending),
        Gtpv2cProtocolErrorKind::IncorrectIe(offending),
    ];
    for kind in kinds {
        let error = Gtpv2cProtocolError::new(kind, Gtpv2cProtocolErrorResponseTeid::NoLookup);
        assert_ne!(error.kind().cause(), CauseValue::ContextNotFound);
    }
}
