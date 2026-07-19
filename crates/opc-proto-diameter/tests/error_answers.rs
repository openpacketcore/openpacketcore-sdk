//! RFC 6733 request-bound error-answer evidence.

use bytes::{BufMut, BytesMut};
use opc_proto_diameter::apps::swm::{
    parse_swm_diameter_eap_request, parse_swm_diameter_eap_request_with_provenance,
};
use opc_proto_diameter::apps::{swm, APP_DICTIONARIES, VENDOR_ID_3GPP};
use opc_proto_diameter::base::{
    self, APPLICATION_ID_COMMON_MESSAGES, AVP_ACCT_APPLICATION_ID, AVP_AUTH_APPLICATION_ID,
    AVP_DESTINATION_HOST, AVP_DESTINATION_REALM, AVP_DISCONNECT_CAUSE, AVP_FAILED_AVP,
    AVP_HOST_IP_ADDRESS, AVP_ORIGIN_HOST, AVP_ORIGIN_REALM, AVP_PRODUCT_NAME, AVP_PROXY_HOST,
    AVP_PROXY_INFO, AVP_PROXY_STATE, AVP_RESULT_CODE, AVP_ROUTE_RECORD, AVP_SESSION_ID,
    AVP_VENDOR_ID, AVP_VENDOR_SPECIFIC_APPLICATION_ID, COMMAND_CAPABILITIES_EXCHANGE,
    COMMAND_DEVICE_WATCHDOG, COMMAND_DISCONNECT_PEER, RESULT_CODE_DIAMETER_APPLICATION_UNSUPPORTED,
    RESULT_CODE_DIAMETER_AVP_NOT_ALLOWED, RESULT_CODE_DIAMETER_AVP_OCCURS_TOO_MANY_TIMES,
    RESULT_CODE_DIAMETER_AVP_UNSUPPORTED, RESULT_CODE_DIAMETER_COMMAND_UNSUPPORTED,
    RESULT_CODE_DIAMETER_INVALID_AVP_BITS, RESULT_CODE_DIAMETER_INVALID_AVP_LENGTH,
    RESULT_CODE_DIAMETER_INVALID_AVP_VALUE, RESULT_CODE_DIAMETER_INVALID_BIT_IN_HEADER,
    RESULT_CODE_DIAMETER_INVALID_HDR_BITS, RESULT_CODE_DIAMETER_MISSING_AVP,
    RESULT_CODE_DIAMETER_UNSUPPORTED_VERSION,
};
use opc_proto_diameter::dictionary::{
    ApplicationDefinition, AvpDataType, AvpDefinition, AvpFlagRules, AvpKey, CommandAvpRule,
    CommandDefinition, CommandKind, Dictionary, DictionarySet,
};
use opc_proto_diameter::error_answer::{
    build_diameter_error_answer, inspect_diameter_request, DiameterBoundRequestFailure,
    DiameterErrorAnswerGrammar, DiameterErrorOrigin, DiameterFailedAvp,
    DiameterFailureMappingError, DiameterRequestClassificationError, DiameterRequestEnvelope,
    DiameterRequestFailure, DiameterRequestInspection, DiameterUnanswerableReason,
};
use opc_proto_diameter::parser_error::{DiameterGroupedAvpSetFailureKind, DiameterParserError};
use opc_proto_diameter::peer::{
    parse_capabilities_exchange_request, parse_capabilities_exchange_request_with_provenance,
    parse_device_watchdog_answer, parse_device_watchdog_request,
    parse_device_watchdog_request_with_provenance, parse_disconnect_peer_answer,
    parse_disconnect_peer_request, parse_disconnect_peer_request_with_provenance,
};
use opc_proto_diameter::{
    ApplicationId, AvpCode, AvpFlags, AvpHeader, CommandCode, CommandFlags, Header, Message,
    RawAvp, VendorId, AVP_HEADER_LEN, DIAMETER_HEADER_LEN,
};
use opc_protocol::{
    BorrowDecode, DecodeContext, DecodeError, DecodeErrorCode, Encode, EncodeContext,
    EncodeErrorCode, SpecRef, UnknownIePolicy, ValidationLevel,
};

const UNKNOWN_COMMAND_REQUEST: &str =
    include_str!("fixtures/rfc6733/error_answers/unknown_command_request.hex");
const UNKNOWN_COMMAND_ANSWER: &str =
    include_str!("fixtures/rfc6733/error_answers/unknown_command_answer.hex");
const UNSUPPORTED_APPLICATION_REQUEST: &str =
    include_str!("fixtures/rfc6733/error_answers/unsupported_application_request.hex");
const UNSUPPORTED_APPLICATION_ANSWER: &str =
    include_str!("fixtures/rfc6733/error_answers/unsupported_application_answer.hex");
const UNSUPPORTED_MANDATORY_AVP_REQUEST: &str =
    include_str!("fixtures/rfc6733/error_answers/unsupported_mandatory_avp_request.hex");
const UNSUPPORTED_MANDATORY_AVP_ANSWER: &str =
    include_str!("fixtures/rfc6733/error_answers/unsupported_mandatory_avp_answer.hex");
const INVALID_AVP_VALUE_REQUEST: &str =
    include_str!("fixtures/rfc6733/error_answers/invalid_avp_value_request.hex");
const INVALID_AVP_VALUE_ANSWER: &str =
    include_str!("fixtures/rfc6733/error_answers/invalid_avp_value_answer.hex");
const MISSING_MANDATORY_AVP_REQUEST: &str =
    include_str!("fixtures/rfc6733/error_answers/missing_mandatory_avp_request.hex");
const MISSING_MANDATORY_AVP_ANSWER: &str =
    include_str!("fixtures/rfc6733/error_answers/missing_mandatory_avp_answer.hex");
const FORBIDDEN_AVP_REQUEST: &str =
    include_str!("fixtures/rfc6733/error_answers/forbidden_avp_request.hex");
const FORBIDDEN_AVP_ANSWER: &str =
    include_str!("fixtures/rfc6733/error_answers/forbidden_avp_answer.hex");
const EXCESS_SINGLETON_REQUEST: &str =
    include_str!("fixtures/rfc6733/error_answers/excess_singleton_request.hex");
const EXCESS_SINGLETON_ANSWER: &str =
    include_str!("fixtures/rfc6733/error_answers/excess_singleton_answer.hex");

const SYNTHETIC_VENDOR_U32: AvpDefinition = AvpDefinition::new(
    AvpKey::vendor(AvpCode::new(1_401), VendorId::new(10_415)),
    "Synthetic-Vendor-U32",
    AvpDataType::Unsigned32,
    AvpFlagRules::vendor_specific(),
    SpecRef::new("ietf", "RFC6733", "7.5"),
);

const SYNTHETIC_FORBIDDEN_U32: AvpDefinition = AvpDefinition::new(
    AvpKey::vendor(AvpCode::new(1_403), VendorId::new(10_415)),
    "Synthetic-Forbidden-U32",
    AvpDataType::Unsigned32,
    AvpFlagRules::vendor_specific(),
    SpecRef::new("ietf", "RFC6733", "7.5"),
);

static SYNTHETIC_GROUP_RULES: [CommandAvpRule; 2] = [
    CommandAvpRule::new(
        SYNTHETIC_VENDOR_U32.key(),
        opc_proto_diameter::AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        SYNTHETIC_FORBIDDEN_U32.key(),
        opc_proto_diameter::AvpCardinality::Forbidden,
    ),
];

const SYNTHETIC_GROUP: AvpDefinition = AvpDefinition::new(
    AvpKey::vendor(AvpCode::new(1_402), VendorId::new(10_415)),
    "Synthetic-Group",
    AvpDataType::Grouped,
    AvpFlagRules::vendor_specific(),
    SpecRef::new("ietf", "RFC6733", "7.5"),
)
.with_grouped_avp_rules(&SYNTHETIC_GROUP_RULES);

static SYNTHETIC_AVPS: [AvpDefinition; 3] = [
    SYNTHETIC_VENDOR_U32,
    SYNTHETIC_FORBIDDEN_U32,
    SYNTHETIC_GROUP,
];
static SYNTHETIC_AVP_DICTIONARY: Dictionary = Dictionary::new(
    "diameter-error-answer-synthetic-avp-test",
    &[],
    &[],
    &SYNTHETIC_AVPS,
);
static SYNTHETIC_AVP_REFS: [&Dictionary; 2] = [base::dictionary(), &SYNTHETIC_AVP_DICTIONARY];
static SYNTHETIC_AVP_DICTIONARIES: DictionarySet<'static> = DictionarySet::new(&SYNTHETIC_AVP_REFS);

static AMBIGUOUS_COMMANDS: [CommandDefinition; 1] = [CommandDefinition::new(
    COMMAND_DEVICE_WATCHDOG,
    "Conflicting-Device-Watchdog-Request",
    CommandKind::Request,
    APPLICATION_ID_COMMON_MESSAGES,
    true,
    SpecRef::new("ietf", "RFC6733", "5.5.1"),
)];
static AMBIGUOUS_COMMAND_DICTIONARY: Dictionary = Dictionary::new(
    "diameter-error-answer-ambiguous-command-test",
    &[],
    &AMBIGUOUS_COMMANDS,
    &[],
);
static AMBIGUOUS_COMMAND_REFS: [&Dictionary; 2] =
    [base::dictionary(), &AMBIGUOUS_COMMAND_DICTIONARY];
static AMBIGUOUS_COMMAND_DICTIONARIES: DictionarySet<'static> =
    DictionarySet::new(&AMBIGUOUS_COMMAND_REFS);

static CONFLICTING_APPLICATIONS: [ApplicationDefinition; 1] = [ApplicationDefinition::new(
    APPLICATION_ID_COMMON_MESSAGES,
    "Conflicting Common Messages",
    Some(VendorId::new(10_415)),
    SpecRef::new("ietf", "RFC6733", "3"),
)];
static AMBIGUOUS_APPLICATION_DICTIONARY: Dictionary = Dictionary::new(
    "diameter-error-answer-ambiguous-application-test",
    &CONFLICTING_APPLICATIONS,
    &[],
    &[],
);
static AMBIGUOUS_APPLICATION_REFS: [&Dictionary; 2] =
    [base::dictionary(), &AMBIGUOUS_APPLICATION_DICTIONARY];
static AMBIGUOUS_APPLICATION_DICTIONARIES: DictionarySet<'static> =
    DictionarySet::new(&AMBIGUOUS_APPLICATION_REFS);

static DUPLICATE_EQUAL_APPLICATIONS: [ApplicationDefinition; 1] = [ApplicationDefinition::new(
    APPLICATION_ID_COMMON_MESSAGES,
    "Diameter Common Messages",
    None,
    SpecRef::new("ietf", "RFC6733", "3"),
)];
static DUPLICATE_EQUAL_APPLICATION_DICTIONARY: Dictionary = Dictionary::new(
    "diameter-error-answer-duplicate-equal-application-test",
    &DUPLICATE_EQUAL_APPLICATIONS,
    &[],
    &[],
);
static DUPLICATE_EQUAL_APPLICATION_REFS: [&Dictionary; 2] =
    [base::dictionary(), &DUPLICATE_EQUAL_APPLICATION_DICTIONARY];
static DUPLICATE_EQUAL_APPLICATION_DICTIONARIES: DictionarySet<'static> =
    DictionarySet::new(&DUPLICATE_EQUAL_APPLICATION_REFS);

static CONFLICTING_AVPS: [AvpDefinition; 1] = [AvpDefinition::new(
    AvpKey::ietf(AVP_ORIGIN_HOST),
    "Conflicting-Origin-Host",
    AvpDataType::OctetString,
    AvpFlagRules::base_optional(),
    SpecRef::new("ietf", "RFC6733", "6.3"),
)];
static AMBIGUOUS_AVP_DICTIONARY: Dictionary = Dictionary::new(
    "diameter-error-answer-ambiguous-avp-test",
    &[],
    &[],
    &CONFLICTING_AVPS,
);
static AMBIGUOUS_AVP_REFS: [&Dictionary; 2] = [base::dictionary(), &AMBIGUOUS_AVP_DICTIONARY];
static AMBIGUOUS_AVP_DICTIONARIES: DictionarySet<'static> = DictionarySet::new(&AMBIGUOUS_AVP_REFS);

static CONFLICTING_NESTED_VENDOR_ID_AVPS: [AvpDefinition; 1] = [AvpDefinition::new(
    AvpKey::ietf(AVP_VENDOR_ID),
    "Conflicting-Nested-Vendor-Id",
    AvpDataType::OctetString,
    AvpFlagRules::base_optional(),
    SpecRef::new("ietf", "RFC6733", "6.11"),
)];
static AMBIGUOUS_NESTED_VENDOR_ID_DICTIONARY: Dictionary = Dictionary::new(
    "diameter-error-answer-ambiguous-nested-vendor-id-test",
    &[],
    &[],
    &CONFLICTING_NESTED_VENDOR_ID_AVPS,
);
static AMBIGUOUS_NESTED_VENDOR_ID_REFS: [&Dictionary; 2] =
    [base::dictionary(), &AMBIGUOUS_NESTED_VENDOR_ID_DICTIONARY];
static AMBIGUOUS_NESTED_VENDOR_ID_DICTIONARIES: DictionarySet<'static> =
    DictionarySet::new(&AMBIGUOUS_NESTED_VENDOR_ID_REFS);

static MISSING_AVP_APPLICATIONS: [ApplicationDefinition; 1] = [ApplicationDefinition::new(
    APPLICATION_ID_COMMON_MESSAGES,
    "Diameter Common Messages",
    None,
    SpecRef::new("ietf", "RFC6733", "3"),
)];
static MISSING_AVP_COMMANDS: [CommandDefinition; 1] = [CommandDefinition::new(
    COMMAND_DEVICE_WATCHDOG,
    "Device-Watchdog-Request",
    CommandKind::Request,
    APPLICATION_ID_COMMON_MESSAGES,
    false,
    SpecRef::new("ietf", "RFC6733", "5.5.1"),
)];
static MISSING_AVP_DICTIONARY: Dictionary = Dictionary::new(
    "diameter-parser-provenance-no-avp-definition-test",
    &MISSING_AVP_APPLICATIONS,
    &MISSING_AVP_COMMANDS,
    &[],
);
static MISSING_AVP_REFS: [&Dictionary; 1] = [&MISSING_AVP_DICTIONARY];
static MISSING_AVP_DICTIONARIES: DictionarySet<'static> = DictionarySet::new(&MISSING_AVP_REFS);

static SCHEMA_MISMATCH_AVPS: [AvpDefinition; 1] = [AvpDefinition::new(
    AvpKey::ietf(AVP_ORIGIN_HOST),
    "Conflicting-Origin-Host",
    AvpDataType::OctetString,
    AvpFlagRules::base_optional(),
    SpecRef::new("ietf", "RFC6733", "6.3"),
)];
static SCHEMA_MISMATCH_DICTIONARY: Dictionary = Dictionary::new(
    "diameter-parser-provenance-schema-mismatch-test",
    &MISSING_AVP_APPLICATIONS,
    &MISSING_AVP_COMMANDS,
    &SCHEMA_MISMATCH_AVPS,
);
static SCHEMA_MISMATCH_REFS: [&Dictionary; 1] = [&SCHEMA_MISMATCH_DICTIONARY];
static SCHEMA_MISMATCH_DICTIONARIES: DictionarySet<'static> =
    DictionarySet::new(&SCHEMA_MISMATCH_REFS);

fn fixture(source: &str) -> Vec<u8> {
    source
        .lines()
        .flat_map(|line| {
            line.split_once('#')
                .map_or(line, |(bytes, _)| bytes)
                .split_whitespace()
        })
        .map(|octet| u8::from_str_radix(octet, 16).expect("fixture octet must be hexadecimal"))
        .collect()
}

fn origin() -> DiameterErrorOrigin {
    DiameterErrorOrigin::new("aaa.local", "local.test")
        .expect("synthetic local identity must be valid")
}

fn envelope(input: &[u8]) -> DiameterRequestEnvelope {
    match inspect_diameter_request(input, DecodeContext::conservative()) {
        DiameterRequestInspection::Request(envelope) => *envelope,
        DiameterRequestInspection::Unanswerable(reason) => {
            panic!("expected answerable request, got {}", reason.as_str())
        }
    }
}

fn encode_plan(
    request: &[u8],
    envelope: &DiameterRequestEnvelope,
    failure: impl IntoTestBoundFailure,
    grammar: DiameterErrorAnswerGrammar,
) -> Vec<u8> {
    let failure = failure.into_bound(request, envelope);
    let plan = build_diameter_error_answer(
        envelope,
        &failure,
        &origin(),
        grammar,
        EncodeContext::default(),
    )
    .expect("error answer must build");
    let mut encoded = BytesMut::new();
    plan.encode(&mut encoded, EncodeContext::default())
        .expect("error answer plan must encode");
    encoded.to_vec()
}

trait IntoTestBoundFailure {
    fn into_bound(
        self,
        request: &[u8],
        envelope: &DiameterRequestEnvelope,
    ) -> DiameterBoundRequestFailure;
}

impl IntoTestBoundFailure for &DiameterRequestFailure {
    fn into_bound(
        self,
        request: &[u8],
        envelope: &DiameterRequestEnvelope,
    ) -> DiameterBoundRequestFailure {
        envelope
            .bind_application_failure(request, self.clone(), APP_DICTIONARIES)
            .expect("test failure must be bound to its exact request")
    }
}

impl IntoTestBoundFailure for &DiameterBoundRequestFailure {
    fn into_bound(
        self,
        _request: &[u8],
        _envelope: &DiameterRequestEnvelope,
    ) -> DiameterBoundRequestFailure {
        self.clone()
    }
}

fn decode_message(input: &[u8]) -> Message<'_> {
    Message::decode(input, DecodeContext::default())
        .expect("test Diameter message must decode")
        .1
}

fn avps<'a>(message: &'a Message<'a>) -> Vec<RawAvp<'a>> {
    message
        .avps(DecodeContext::default())
        .map(|avp| avp.expect("test AVP must decode"))
        .collect()
}

fn find_avp_at<'a>(message: &'a Message<'a>, code: AvpCode) -> (usize, RawAvp<'a>) {
    let mut remaining = message.raw_avps;
    let mut offset = DIAMETER_HEADER_LEN;
    while !remaining.is_empty() {
        let before = remaining.len();
        let (next, avp) =
            RawAvp::decode(remaining, DecodeContext::default()).expect("fixture AVP must decode");
        if avp.header.code == code {
            return (offset, avp);
        }
        offset += before - next.len();
        remaining = next;
    }
    panic!("fixture AVP {} missing", code.get());
}

fn result_code(message: &Message<'_>) -> u32 {
    let avp = avps(message)
        .into_iter()
        .find(|avp| avp.header.code == AVP_RESULT_CODE)
        .expect("answer must contain Result-Code");
    u32::from_be_bytes(
        avp.value
            .try_into()
            .expect("Result-Code value must be four octets"),
    )
}

fn encode_avp(header: AvpHeader, value: &[u8]) -> Vec<u8> {
    let avp = RawAvp {
        header,
        value,
        padding: &[],
    };
    let mut encoded = BytesMut::new();
    avp.encode(&mut encoded, EncodeContext::default())
        .expect("test AVP must encode");
    encoded.to_vec()
}

fn encode_avp_with_padding(header: AvpHeader, value: &[u8], padding: u8) -> Vec<u8> {
    let unpadded = header.header_len() + value.len();
    let padding_len = (4 - (unpadded % 4)) % 4;
    let padding = vec![padding; padding_len];
    let avp = RawAvp {
        header,
        value,
        padding: &padding,
    };
    let mut encoded = BytesMut::new();
    avp.encode(
        &mut encoded,
        EncodeContext {
            raw_preserving: true,
            ..EncodeContext::default()
        },
    )
    .expect("test AVP with explicit padding must encode");
    encoded.to_vec()
}

fn encode_request(
    flags: CommandFlags,
    command: CommandCode,
    application: ApplicationId,
    raw_avps: &[u8],
) -> Vec<u8> {
    let header = Header::new(flags, command, application, 0x1020_3040, 0x5060_7080)
        .with_length((DIAMETER_HEADER_LEN + raw_avps.len()) as u32);
    let mut encoded = BytesMut::new();
    header
        .encode(&mut encoded, EncodeContext::default())
        .expect("test header must encode");
    encoded.put_slice(raw_avps);
    encoded.to_vec()
}

fn encoded_field(key: AvpKey, mandatory: bool, value: &[u8]) -> (AvpKey, Vec<u8>) {
    let header = match key.vendor_id() {
        Some(vendor_id) => AvpHeader::vendor(key.code(), vendor_id, mandatory),
        None => AvpHeader::ietf(key.code(), mandatory),
    };
    (key, encode_avp(header, value))
}

fn fields_except(fields: &[(AvpKey, Vec<u8>)], missing: AvpKey) -> Vec<u8> {
    fields
        .iter()
        .filter(|(key, _)| *key != missing)
        .flat_map(|(_, wire)| wire.iter().copied())
        .collect()
}

fn cer_request_with_vendor_application(grouped_value: &[u8]) -> Vec<u8> {
    let fields = [
        encode_avp(AvpHeader::ietf(AVP_ORIGIN_HOST, true), b"cer.peer.invalid"),
        encode_avp(AvpHeader::ietf(AVP_ORIGIN_REALM, true), b"invalid"),
        encode_avp(
            AvpHeader::ietf(AVP_HOST_IP_ADDRESS, true),
            &[0, 1, 192, 0, 2, 10],
        ),
        encode_avp(
            AvpHeader::ietf(AVP_VENDOR_ID, true),
            &10_415_u32.to_be_bytes(),
        ),
        encode_avp(AvpHeader::ietf(AVP_PRODUCT_NAME, false), b"opc-test"),
        encode_avp(
            AvpHeader::ietf(AVP_VENDOR_SPECIFIC_APPLICATION_ID, true),
            grouped_value,
        ),
    ];
    let raw: Vec<_> = fields.into_iter().flatten().collect();
    encode_request(
        CommandFlags::request(false),
        COMMAND_CAPABILITIES_EXCHANGE,
        APPLICATION_ID_COMMON_MESSAGES,
        &raw,
    )
}

fn valid_swm_der_fields() -> Vec<Vec<u8>> {
    vec![
        encode_avp(AvpHeader::ietf(AVP_SESSION_ID, true), b"session;redacted"),
        encode_avp(
            AvpHeader::ietf(AVP_AUTH_APPLICATION_ID, true),
            &swm::APPLICATION_ID.get().to_be_bytes(),
        ),
        encode_avp(AvpHeader::ietf(AVP_ORIGIN_HOST, true), b"epdg.invalid"),
        encode_avp(AvpHeader::ietf(AVP_ORIGIN_REALM, true), b"visited.invalid"),
        encode_avp(
            AvpHeader::ietf(AVP_DESTINATION_REALM, true),
            b"home.invalid",
        ),
        encode_avp(
            AvpHeader::ietf(swm::AVP_AUTH_REQUEST_TYPE, true),
            &swm::AUTH_REQUEST_TYPE_AUTHORIZE_AUTHENTICATE.to_be_bytes(),
        ),
        encode_avp(
            AvpHeader::ietf(swm::AVP_EAP_PAYLOAD, true),
            &[2, 7, 0, 8, 1, 2, 3, 4],
        ),
    ]
}

fn failed_avp_inner_wire(answer: &[u8]) -> Vec<u8> {
    let message = decode_message(answer);
    let failed = avps(&message)
        .into_iter()
        .find(|avp| avp.header.code == AVP_FAILED_AVP)
        .expect("answer must contain Failed-AVP");
    failed.value.to_vec()
}

fn assert_typed_missing_maps<T: core::fmt::Debug>(
    request: &[u8],
    expected_key: AvpKey,
    expected_value_len: usize,
    expected_mandatory: bool,
    dictionaries: DictionarySet<'_>,
    parser: impl FnOnce(&Message<'_>) -> Result<T, DiameterParserError>,
) {
    let message = decode_message(request);
    let parser_error = parser(&message).expect_err("the selected mandatory AVP must be absent");
    assert!(matches!(
        parser_error.decode_error().code(),
        DecodeErrorCode::Structural { .. }
    ));
    assert_eq!(parser_error.decode_error().offset(), DIAMETER_HEADER_LEN);
    let provenance = parser_error
        .missing_avp()
        .expect("missing mandatory AVP provenance must be retained");
    assert_eq!(provenance.key(), expected_key);
    assert_eq!(provenance.avp_code(), expected_key.code());
    assert_eq!(provenance.vendor_id(), expected_key.vendor_id());
    let expected_definition = dictionaries
        .find_avp(expected_key)
        .expect("missing AVP must have a dictionary definition");
    assert_eq!(provenance.definition(), expected_definition);
    assert_eq!(provenance.data_type(), expected_definition.data_type());
    assert_eq!(provenance.flag_rules(), expected_definition.flags());
    assert_eq!(provenance.application_id(), message.header.application_id);
    assert_eq!(provenance.command_code(), message.header.command_code);
    assert_eq!(provenance.command_kind(), CommandKind::Request);

    let request_envelope = envelope(request);
    assert!(request_envelope
        .classify(request, dictionaries)
        .expect("test dictionaries must be unambiguous")
        .is_none());
    let bound = DiameterRequestFailure::from_parser_error(
        &request_envelope,
        request,
        &parser_error,
        DecodeContext::conservative(),
        dictionaries,
        EncodeContext::default(),
    )
    .expect("sealed parser provenance must map to a bound 5005 failure");
    assert_eq!(bound.result_code(), RESULT_CODE_DIAMETER_MISSING_AVP);
    let DiameterRequestFailure::MissingMandatoryAvp(failed) = bound.failure() else {
        panic!("typed missing provenance must map to MissingMandatoryAvp");
    };
    assert_eq!(failed.leaf_code(), expected_key.code());
    assert_eq!(failed.leaf_vendor_id(), expected_key.vendor_id());
    assert_eq!(failed.leaf_offset(), None);

    let encoded = encode_plan(
        request,
        &request_envelope,
        &bound,
        DiameterErrorAnswerGrammar::Rfc6733ErrorBitFallback,
    );
    let answer = decode_message(&encoded);
    let failed_group = avps(&answer)
        .into_iter()
        .find(|avp| avp.header.code == AVP_FAILED_AVP)
        .expect("5005 answer must contain Failed-AVP");
    let (remaining, leaf) = RawAvp::decode(failed_group.value, DecodeContext::default())
        .expect("synthesized Failed-AVP leaf must decode");
    assert!(remaining.is_empty());
    assert_eq!(leaf.header.key(), expected_key);
    assert_eq!(leaf.header.flags.is_mandatory(), expected_mandatory);
    assert!(!leaf.header.flags.is_protected());
    assert_eq!(leaf.value.len(), expected_value_len);
    assert!(leaf.value.iter().all(|byte| *byte == 0));
}

#[test]
fn unknown_command_3001_matches_independently_authored_bytes() {
    let request = fixture(UNKNOWN_COMMAND_REQUEST);
    let envelope = envelope(&request);
    let failure = envelope
        .classify(&request, APP_DICTIONARIES)
        .expect("dictionary classification must be unambiguous")
        .expect("unknown command must be classified");
    assert_eq!(failure.failure(), &DiameterRequestFailure::UnknownCommand);
    let encoded = encode_plan(
        &request,
        &envelope,
        &failure,
        DiameterErrorAnswerGrammar::Application,
    );
    assert_eq!(encoded, fixture(UNKNOWN_COMMAND_ANSWER));

    let answer = decode_message(&encoded);
    assert_eq!(answer.header.command_code, envelope.command_code());
    assert_eq!(answer.header.application_id, envelope.application_id());
    assert_eq!(
        answer.header.hop_by_hop_identifier,
        envelope.hop_by_hop_identifier()
    );
    assert_eq!(
        answer.header.end_to_end_identifier,
        envelope.end_to_end_identifier()
    );
    assert!(!answer.header.flags.is_request());
    assert!(answer.header.flags.is_proxiable());
    assert!(answer.header.flags.is_error());
    assert_eq!(result_code(&answer), 3001);
}

#[test]
fn unsupported_application_3007_matches_independently_authored_bytes() {
    let request = fixture(UNSUPPORTED_APPLICATION_REQUEST);
    let envelope = envelope(&request);
    let failure = envelope
        .classify(&request, APP_DICTIONARIES)
        .expect("dictionary classification must be unambiguous")
        .expect("unknown application must be classified");
    assert_eq!(
        failure.failure(),
        &DiameterRequestFailure::UnsupportedApplication
    );
    let encoded = encode_plan(
        &request,
        &envelope,
        &failure,
        DiameterErrorAnswerGrammar::Application,
    );
    assert_eq!(encoded, fixture(UNSUPPORTED_APPLICATION_ANSWER));
    assert_eq!(result_code(&decode_message(&encoded)), 3007);
}

#[test]
fn permanent_failures_match_independently_authored_base_and_swm_bytes() {
    let request = fixture(UNSUPPORTED_MANDATORY_AVP_REQUEST);
    let request_envelope = envelope(&request);
    assert_eq!(request_envelope.command_code(), COMMAND_DEVICE_WATCHDOG);
    let failure = request_envelope
        .classify(&request, APP_DICTIONARIES)
        .expect("classification must be unambiguous")
        .expect("unknown M-bit AVP must classify centrally");
    assert!(matches!(
        failure.failure(),
        DiameterRequestFailure::UnsupportedMandatoryAvp(_)
    ));
    assert_eq!(
        encode_plan(
            &request,
            &request_envelope,
            &failure,
            DiameterErrorAnswerGrammar::Application,
        ),
        fixture(UNSUPPORTED_MANDATORY_AVP_ANSWER)
    );

    let request = fixture(INVALID_AVP_VALUE_REQUEST);
    let request_envelope = envelope(&request);
    assert_eq!(request_envelope.command_code(), COMMAND_DISCONNECT_PEER);
    assert!(request_envelope
        .classify(&request, APP_DICTIONARIES)
        .expect("classification must be unambiguous")
        .is_none());
    let message = decode_message(&request);
    let (offset, offending) = find_avp_at(&message, AVP_DISCONNECT_CAUSE);
    let failure = DiameterRequestFailure::InvalidAvpValue(
        DiameterFailedAvp::copied(&offending, offset, EncodeContext::default())
            .expect("invalid value AVP copy"),
    );
    assert_eq!(
        encode_plan(
            &request,
            &request_envelope,
            &failure,
            DiameterErrorAnswerGrammar::Application,
        ),
        fixture(INVALID_AVP_VALUE_ANSWER)
    );

    let request = fixture(MISSING_MANDATORY_AVP_REQUEST);
    let request_envelope = envelope(&request);
    assert_eq!(request_envelope.command_code(), COMMAND_DEVICE_WATCHDOG);
    assert!(request_envelope
        .classify(&request, APP_DICTIONARIES)
        .expect("classification must be unambiguous")
        .is_none());
    let origin_host = base::dictionary()
        .find_avp(AvpKey::ietf(AVP_ORIGIN_HOST))
        .expect("base Origin-Host definition");
    let failure = DiameterRequestFailure::MissingMandatoryAvp(
        DiameterFailedAvp::missing_for_definition(origin_host, EncodeContext::default())
            .expect("missing Origin-Host shape"),
    );
    assert_eq!(
        encode_plan(
            &request,
            &request_envelope,
            &failure,
            DiameterErrorAnswerGrammar::Application,
        ),
        fixture(MISSING_MANDATORY_AVP_ANSWER)
    );

    let request = fixture(FORBIDDEN_AVP_REQUEST);
    let request_envelope = envelope(&request);
    assert_eq!(request_envelope.command_code(), swm::COMMAND_DIAMETER_EAP);
    let failure = request_envelope
        .classify(&request, APP_DICTIONARIES)
        .expect("classification must be unambiguous")
        .expect("forbidden Result-Code must classify centrally");
    assert!(matches!(
        failure.failure(),
        DiameterRequestFailure::ForbiddenAvp(_)
    ));
    assert_eq!(
        encode_plan(
            &request,
            &request_envelope,
            &failure,
            DiameterErrorAnswerGrammar::Rfc6733ErrorBitFallback,
        ),
        fixture(FORBIDDEN_AVP_ANSWER)
    );

    let request = fixture(EXCESS_SINGLETON_REQUEST);
    let request_envelope = envelope(&request);
    assert_eq!(request_envelope.command_code(), swm::COMMAND_DIAMETER_EAP);
    let failure = request_envelope
        .classify(&request, APP_DICTIONARIES)
        .expect("SWm command dictionary must be unique")
        .expect("duplicate Session-Id failure");
    assert!(matches!(
        failure.failure(),
        DiameterRequestFailure::ExcessSingleton(_)
    ));
    assert_eq!(
        encode_plan(
            &request,
            &request_envelope,
            &failure,
            DiameterErrorAnswerGrammar::Rfc6733ErrorBitFallback,
        ),
        fixture(EXCESS_SINGLETON_ANSWER)
    );
}

#[test]
fn answer_copies_only_required_request_fields_and_ordered_proxy_info() {
    let mut request = fixture(UNKNOWN_COMMAND_REQUEST);
    request.extend_from_slice(&encode_avp(
        AvpHeader::ietf(AVP_ROUTE_RECORD, true),
        b"route-only.example",
    ));
    let request_len = u32::try_from(request.len()).expect("test request length must fit");
    request[1..4].copy_from_slice(&request_len.to_be_bytes()[1..4]);
    let envelope = envelope(&request);
    let encoded = encode_plan(
        &request,
        &envelope,
        &DiameterRequestFailure::UnknownCommand,
        DiameterErrorAnswerGrammar::Application,
    );
    let request_message = decode_message(&request);
    let answer_message = decode_message(&encoded);
    let request_avps = avps(&request_message);
    let answer_avps = avps(&answer_message);

    let request_session = request_avps
        .iter()
        .find(|avp| avp.header.code == AVP_SESSION_ID)
        .expect("request Session-Id");
    let answer_session = answer_avps
        .iter()
        .find(|avp| avp.header.code == AVP_SESSION_ID)
        .expect("answer Session-Id");
    assert_eq!(answer_session, request_session);

    let request_proxies: Vec<_> = request_avps
        .iter()
        .filter(|avp| avp.header.code == AVP_PROXY_INFO)
        .collect();
    let answer_proxies: Vec<_> = answer_avps
        .iter()
        .filter(|avp| avp.header.code == AVP_PROXY_INFO)
        .collect();
    assert_eq!(answer_proxies, request_proxies);
    assert!(answer_avps.iter().all(|avp| !matches!(
        avp.header.code,
        AVP_DESTINATION_HOST | AVP_DESTINATION_REALM | AVP_ROUTE_RECORD
    )));
}

#[test]
fn permanent_failure_uses_application_grammar_without_e() {
    let request = fixture(INVALID_AVP_VALUE_REQUEST);
    let envelope = envelope(&request);
    let message = decode_message(&request);
    let (offset, offending) = find_avp_at(&message, AVP_DISCONNECT_CAUSE);
    let copied = DiameterFailedAvp::copied(&offending, offset, EncodeContext::default())
        .expect("offending AVP copy must fit");
    let failure = DiameterRequestFailure::InvalidAvpValue(copied);
    let encoded = encode_plan(
        &request,
        &envelope,
        &failure,
        DiameterErrorAnswerGrammar::Application,
    );
    let answer = decode_message(&encoded);
    assert_eq!(result_code(&answer), 5004);
    assert!(!answer.header.flags.is_error());
    assert!(avps(&answer)
        .iter()
        .any(|avp| avp.header.code == AVP_FAILED_AVP));
}

#[test]
fn permanent_failure_sets_e_only_for_explicit_rfc_fallback() {
    let request = fixture(INVALID_AVP_VALUE_REQUEST);
    let envelope = envelope(&request);
    let message = decode_message(&request);
    let (offset, offending) = find_avp_at(&message, AVP_DISCONNECT_CAUSE);
    let failed = DiameterFailedAvp::copied(&offending, offset, EncodeContext::default())
        .expect("offending AVP copy must fit");
    let failure = DiameterRequestFailure::InvalidAvpValue(failed);
    let application_bytes = encode_plan(
        &request,
        &envelope,
        &failure,
        DiameterErrorAnswerGrammar::Application,
    );
    let application = decode_message(&application_bytes);
    assert!(!application.header.flags.is_error());
    let fallback_bytes = encode_plan(
        &request,
        &envelope,
        &failure,
        DiameterErrorAnswerGrammar::Rfc6733ErrorBitFallback,
    );
    let fallback = decode_message(&fallback_bytes);
    assert!(fallback.header.flags.is_error());
}

#[test]
fn missing_vendor_avp_uses_dictionary_minimum_and_vendor_id() {
    let request = encode_request(
        CommandFlags::request(false),
        COMMAND_DEVICE_WATCHDOG,
        APPLICATION_ID_COMMON_MESSAGES,
        &[],
    );
    let envelope = envelope(&request);
    let missing =
        DiameterFailedAvp::missing_for_definition(&SYNTHETIC_VENDOR_U32, EncodeContext::default())
            .expect("dictionary missing shape must build");
    assert_eq!(missing.leaf_vendor_id(), Some(VendorId::new(10_415)));
    assert_eq!(missing.retained_wire_len(), 16);
    let bound = envelope
        .bind_application_failure(
            &request,
            DiameterRequestFailure::MissingMandatoryAvp(missing),
            SYNTHETIC_AVP_DICTIONARIES,
        )
        .expect("synthetic dictionary must bind the missing AVP");
    let encoded = encode_plan(
        &request,
        &envelope,
        &bound,
        DiameterErrorAnswerGrammar::Application,
    );
    let answer = decode_message(&encoded);
    let failed_group = avps(&answer)
        .into_iter()
        .find(|avp| avp.header.code == AVP_FAILED_AVP)
        .expect("Failed-AVP must be present");
    let child = RawAvp::decode(failed_group.value, DecodeContext::default())
        .expect("missing shape must decode")
        .1;
    assert_eq!(child.header.code, AvpCode::new(1_401));
    assert_eq!(child.header.vendor_id, Some(VendorId::new(10_415)));
    assert_eq!(child.value, [0, 0, 0, 0]);
}

#[test]
fn duplicate_session_reports_the_first_excess_occurrence() {
    let first = encode_avp(AvpHeader::ietf(AVP_SESSION_ID, true), b"first-session");
    let second = encode_avp(AvpHeader::ietf(AVP_SESSION_ID, true), b"second-session");
    let mut raw = first.clone();
    raw.extend_from_slice(&second);
    let request = encode_request(
        CommandFlags::request(true),
        swm::COMMAND_DIAMETER_EAP,
        swm::APPLICATION_ID,
        &raw,
    );
    let envelope = envelope(&request);
    let failure = envelope
        .classify(&request, APP_DICTIONARIES)
        .expect("SWm command dictionary must be unique")
        .expect("second Session-Id must fail");
    let DiameterRequestFailure::ExcessSingleton(failed) = failure.failure() else {
        panic!("duplicate must map to excess singleton");
    };
    assert_eq!(
        failed.leaf_offset(),
        Some(DIAMETER_HEADER_LEN + first.len())
    );
    let encoded = encode_plan(
        &request,
        &envelope,
        &failure,
        DiameterErrorAnswerGrammar::Application,
    );
    let answer = decode_message(&encoded);
    let failed_group = avps(&answer)
        .into_iter()
        .find(|avp| avp.header.code == AVP_FAILED_AVP)
        .expect("Failed-AVP must be present");
    let child = RawAvp::decode(failed_group.value, DecodeContext::default())
        .expect("copied duplicate must decode")
        .1;
    assert_eq!(child.value, b"second-session");
}

#[test]
fn invalid_short_and_long_avp_lengths_are_answerable_and_bounded() {
    for malformed in [
        vec![0, 0, 3, 0, 0x40, 0, 0, 4],
        vec![0, 0, 3, 1, 0x40, 0, 1, 0],
    ] {
        let request = encode_request(
            CommandFlags::request(true),
            swm::COMMAND_DIAMETER_EAP,
            swm::APPLICATION_ID,
            &malformed,
        );
        let envelope = envelope(&request);
        let failure = envelope
            .classify(&request, APP_DICTIONARIES)
            .expect("SWm dictionary must be unique")
            .expect("invalid AVP length must be selected");
        let DiameterRequestFailure::InvalidAvpLength(failed) = failure.failure() else {
            panic!("malformed AVP must map to invalid length");
        };
        assert!(failed.retained_wire_len() <= 12);
        let answer = encode_plan(
            &request,
            &envelope,
            &failure,
            DiameterErrorAnswerGrammar::Application,
        );
        let answer = decode_message(&answer);
        assert_eq!(result_code(&answer), 5014);
        assert!(!answer.header.flags.is_error());
    }
}

#[test]
fn failed_avp_can_retain_a_nested_grouped_hierarchy() {
    let child_wire = encode_avp(
        AvpHeader::vendor(
            SYNTHETIC_VENDOR_U32.key().code(),
            SYNTHETIC_VENDOR_U32
                .key()
                .vendor_id()
                .expect("synthetic leaf must have a vendor"),
            true,
        ),
        b"nested-secret",
    );
    let child = RawAvp::decode(&child_wire, DecodeContext::default())
        .expect("child must decode")
        .1;
    let group_wire = encode_avp(
        AvpHeader::vendor(
            SYNTHETIC_GROUP.key().code(),
            SYNTHETIC_GROUP
                .key()
                .vendor_id()
                .expect("synthetic group must have a vendor"),
            true,
        ),
        &child_wire,
    );
    let group = RawAvp::decode(&group_wire, DecodeContext::default())
        .expect("group must decode")
        .1;
    let group_offset = DIAMETER_HEADER_LEN;
    let child_offset = group_offset + group.header.header_len();
    let failed = DiameterFailedAvp::copied(&child, child_offset, EncodeContext::default())
        .expect("child copy")
        .within_group(&group, group_offset, EncodeContext::default())
        .expect("group wrapper");
    assert_eq!(failed.hierarchy_depth(), 1);
    let request = encode_request(
        CommandFlags::request(false),
        COMMAND_DEVICE_WATCHDOG,
        APPLICATION_ID_COMMON_MESSAGES,
        &group_wire,
    );
    let request_envelope = envelope(&request);
    let bound = request_envelope
        .bind_application_failure(
            &request,
            DiameterRequestFailure::InvalidAvpValue(failed),
            SYNTHETIC_AVP_DICTIONARIES,
        )
        .expect("nested copied evidence must belong to this request");
    let encoded = encode_plan(
        &request,
        &request_envelope,
        &bound,
        DiameterErrorAnswerGrammar::Application,
    );
    let answer = decode_message(&encoded);
    let failed_group = avps(&answer)
        .into_iter()
        .find(|avp| avp.header.code == AVP_FAILED_AVP)
        .expect("Failed-AVP must be present");
    let outer = RawAvp::decode(failed_group.value, DecodeContext::default())
        .expect("outer group must decode")
        .1;
    assert_eq!(outer.header.code, SYNTHETIC_GROUP.key().code());
    let leaf = RawAvp::decode(outer.value, DecodeContext::default())
        .expect("nested leaf must decode")
        .1;
    assert_eq!(leaf.header.code, SYNTHETIC_VENDOR_U32.key().code());
    assert_eq!(leaf.value, b"nested-secret");
}

#[test]
fn grouped_failed_avp_binding_rejects_fabricated_ancestry() {
    let leaf_wire = encode_avp(
        AvpHeader::vendor(
            SYNTHETIC_VENDOR_U32.key().code(),
            VendorId::new(10_415),
            true,
        ),
        &7_u32.to_be_bytes(),
    );
    let leaf = RawAvp::decode(&leaf_wire, DecodeContext::default())
        .expect("synthetic leaf must decode")
        .1;
    let group_wire = encode_avp(
        AvpHeader::vendor(SYNTHETIC_GROUP.key().code(), VendorId::new(10_415), true),
        &leaf_wire,
    );
    let group = RawAvp::decode(&group_wire, DecodeContext::default())
        .expect("synthetic group must decode")
        .1;

    let unrelated_request = {
        let mut raw = group_wire.clone();
        raw.extend_from_slice(&leaf_wire);
        encode_request(
            CommandFlags::request(false),
            COMMAND_DEVICE_WATCHDOG,
            APPLICATION_ID_COMMON_MESSAGES,
            &raw,
        )
    };
    let unrelated_leaf_offset = DIAMETER_HEADER_LEN + group_wire.len();
    let unrelated =
        DiameterFailedAvp::copied(&leaf, unrelated_leaf_offset, EncodeContext::default())
            .expect("unrelated leaf copy must build")
            .within_group(&group, DIAMETER_HEADER_LEN, EncodeContext::default())
            .expect("unrelated ancestry shape must build before request binding");
    assert_eq!(
        envelope(&unrelated_request).bind_application_failure(
            &unrelated_request,
            DiameterRequestFailure::InvalidAvpValue(unrelated),
            SYNTHETIC_AVP_DICTIONARIES,
        ),
        Err(DiameterRequestClassificationError::FailureProvenanceMismatch)
    );

    let non_group_wire = encode_avp(
        AvpHeader::vendor(
            SYNTHETIC_VENDOR_U32.key().code(),
            VendorId::new(10_415),
            true,
        ),
        &leaf_wire,
    );
    let non_group = RawAvp::decode(&non_group_wire, DecodeContext::default())
        .expect("synthetic non-group wrapper must decode structurally")
        .1;
    let non_group_request = encode_request(
        CommandFlags::request(false),
        COMMAND_DEVICE_WATCHDOG,
        APPLICATION_ID_COMMON_MESSAGES,
        &non_group_wire,
    );
    let non_group_failed = DiameterFailedAvp::copied(
        &leaf,
        DIAMETER_HEADER_LEN + non_group.header.header_len(),
        EncodeContext::default(),
    )
    .expect("non-group leaf copy must build")
    .within_group(&non_group, DIAMETER_HEADER_LEN, EncodeContext::default())
    .expect("non-group ancestry shape must build before dictionary binding");
    assert_eq!(
        envelope(&non_group_request).bind_application_failure(
            &non_group_request,
            DiameterRequestFailure::InvalidAvpValue(non_group_failed),
            SYNTHETIC_AVP_DICTIONARIES,
        ),
        Err(DiameterRequestClassificationError::FailureProvenanceMismatch)
    );

    let grouped_request = encode_request(
        CommandFlags::request(false),
        COMMAND_DEVICE_WATCHDOG,
        APPLICATION_ID_COMMON_MESSAGES,
        &group_wire,
    );
    let out_of_range = DiameterFailedAvp::copied(
        &leaf,
        DIAMETER_HEADER_LEN + group.header.header_len(),
        EncodeContext::default(),
    )
    .expect("in-group leaf copy must build")
    .within_group(&group, DIAMETER_HEADER_LEN + 1, EncodeContext::default())
    .expect("mislocated ancestry shape must build before request binding");
    assert_eq!(
        envelope(&grouped_request).bind_application_failure(
            &grouped_request,
            DiameterRequestFailure::InvalidAvpValue(out_of_range),
            SYNTHETIC_AVP_DICTIONARIES,
        ),
        Err(DiameterRequestClassificationError::FailureProvenanceMismatch)
    );
}

#[test]
fn received_leaf_provenance_distinguishes_top_level_from_embedded_avp_bytes() {
    let leaf_wire = encode_avp(
        AvpHeader::vendor(
            SYNTHETIC_VENDOR_U32.key().code(),
            VendorId::new(10_415),
            true,
        ),
        &9_u32.to_be_bytes(),
    );
    let leaf = RawAvp::decode(&leaf_wire, DecodeContext::default())
        .expect("synthetic leaf must decode")
        .1;
    let octet_container = encode_avp(AvpHeader::ietf(AVP_SESSION_ID, true), &leaf_wire);
    let mut raw = octet_container.clone();
    raw.extend_from_slice(&leaf_wire);
    let request = encode_request(
        CommandFlags::request(false),
        COMMAND_DEVICE_WATCHDOG,
        APPLICATION_ID_COMMON_MESSAGES,
        &raw,
    );
    let request_envelope = envelope(&request);

    let embedded_offset = DIAMETER_HEADER_LEN + AVP_HEADER_LEN;
    let embedded = DiameterFailedAvp::copied(&leaf, embedded_offset, EncodeContext::default())
        .expect("embedded AVP-shaped bytes must copy before binding");
    assert_eq!(
        request_envelope.bind_application_failure(
            &request,
            DiameterRequestFailure::InvalidAvpValue(embedded),
            SYNTHETIC_AVP_DICTIONARIES,
        ),
        Err(DiameterRequestClassificationError::FailureProvenanceMismatch)
    );

    let top_level_offset = DIAMETER_HEADER_LEN + octet_container.len();
    let top_level = DiameterFailedAvp::copied(&leaf, top_level_offset, EncodeContext::default())
        .expect("top-level evidence must copy");
    let bound = request_envelope
        .bind_application_failure(
            &request,
            DiameterRequestFailure::InvalidAvpValue(top_level),
            SYNTHETIC_AVP_DICTIONARIES,
        )
        .expect("an exact top-level iterator entry must bind");
    let DiameterRequestFailure::InvalidAvpValue(failed) = bound.failure() else {
        panic!("top-level evidence must retain its supplied failure kind");
    };
    assert_eq!(failed.leaf_offset(), Some(top_level_offset));
}

#[test]
fn missing_failed_avp_ancestry_requires_a_bounded_trusted_schema_path() {
    const UNKNOWN_GROUP: AvpDefinition = AvpDefinition::new(
        AvpKey::vendor(AvpCode::new(19_999), VendorId::new(10_415)),
        "Unknown-Group",
        AvpDataType::Grouped,
        AvpFlagRules::vendor_specific(),
        SpecRef::new("ietf", "RFC6733", "7.5"),
    );

    let request = encode_request(
        CommandFlags::request(false),
        COMMAND_DEVICE_WATCHDOG,
        APPLICATION_ID_COMMON_MESSAGES,
        &[],
    );
    let unknown_ancestor =
        DiameterFailedAvp::missing_for_definition(&SYNTHETIC_VENDOR_U32, EncodeContext::default())
            .expect("missing leaf must build")
            .within_missing_group(&UNKNOWN_GROUP, EncodeContext::default())
            .expect("unknown group shape must build before dictionary binding");
    assert_eq!(
        envelope(&request).bind_application_failure(
            &request,
            DiameterRequestFailure::MissingMandatoryAvp(unknown_ancestor),
            SYNTHETIC_AVP_DICTIONARIES,
        ),
        Err(DiameterRequestClassificationError::FailureProvenanceMismatch)
    );

    let present_leaf_wire = encode_avp(
        AvpHeader::vendor(
            SYNTHETIC_VENDOR_U32.key().code(),
            VendorId::new(10_415),
            true,
        ),
        &12_u32.to_be_bytes(),
    );
    let present_leaf_request = encode_request(
        CommandFlags::request(false),
        COMMAND_DEVICE_WATCHDOG,
        APPLICATION_ID_COMMON_MESSAGES,
        &present_leaf_wire,
    );
    let false_top_level_missing =
        DiameterFailedAvp::missing_for_definition(&SYNTHETIC_VENDOR_U32, EncodeContext::default())
            .expect("top-level missing shape must build");
    assert_eq!(
        envelope(&present_leaf_request).bind_application_failure(
            &present_leaf_request,
            DiameterRequestFailure::MissingMandatoryAvp(false_top_level_missing),
            SYNTHETIC_AVP_DICTIONARIES,
        ),
        Err(DiameterRequestClassificationError::FailureProvenanceMismatch)
    );

    let present_group_wire = encode_avp(
        AvpHeader::vendor(SYNTHETIC_GROUP.key().code(), VendorId::new(10_415), true),
        &present_leaf_wire,
    );
    let present_group = RawAvp::decode(&present_group_wire, DecodeContext::default())
        .expect("present group must decode")
        .1;
    let present_group_request = encode_request(
        CommandFlags::request(false),
        COMMAND_DEVICE_WATCHDOG,
        APPLICATION_ID_COMMON_MESSAGES,
        &present_group_wire,
    );
    let false_outer_missing =
        DiameterFailedAvp::missing_for_definition(&SYNTHETIC_VENDOR_U32, EncodeContext::default())
            .expect("nested missing leaf must build")
            .within_missing_group(&SYNTHETIC_GROUP, EncodeContext::default())
            .expect("missing outer group shape must build");
    assert_eq!(
        envelope(&present_group_request).bind_application_failure(
            &present_group_request,
            DiameterRequestFailure::MissingMandatoryAvp(false_outer_missing),
            SYNTHETIC_AVP_DICTIONARIES,
        ),
        Err(DiameterRequestClassificationError::FailureProvenanceMismatch)
    );

    let false_child_missing =
        DiameterFailedAvp::missing_for_definition(&SYNTHETIC_VENDOR_U32, EncodeContext::default())
            .expect("missing child shape must build")
            .within_group(
                &present_group,
                DIAMETER_HEADER_LEN,
                EncodeContext::default(),
            )
            .expect("received-parent missing shape must build");
    assert_eq!(
        envelope(&present_group_request).bind_application_failure(
            &present_group_request,
            DiameterRequestFailure::MissingMandatoryAvp(false_child_missing),
            SYNTHETIC_AVP_DICTIONARIES,
        ),
        Err(DiameterRequestClassificationError::FailureProvenanceMismatch)
    );

    let origin_host = base::dictionary()
        .find_avp(AvpKey::ietf(AVP_ORIGIN_HOST))
        .expect("base Origin-Host definition must exist");
    let undeclared_child =
        DiameterFailedAvp::missing_for_definition(origin_host, EncodeContext::default())
            .expect("known missing leaf must build")
            .within_missing_group(&SYNTHETIC_GROUP, EncodeContext::default())
            .expect("undeclared schema shape must build before dictionary binding");
    assert_eq!(
        envelope(&request).bind_application_failure(
            &request,
            DiameterRequestFailure::MissingMandatoryAvp(undeclared_child),
            SYNTHETIC_AVP_DICTIONARIES,
        ),
        Err(DiameterRequestClassificationError::FailureProvenanceMismatch)
    );

    let mut excessive =
        DiameterFailedAvp::missing_for_definition(&SYNTHETIC_VENDOR_U32, EncodeContext::default())
            .expect("missing leaf must build");
    for _ in 0..16 {
        excessive = excessive
            .within_missing_group(&SYNTHETIC_GROUP, EncodeContext::default())
            .expect("hierarchy at the fixed bound must build");
    }
    let error = excessive
        .within_missing_group(&SYNTHETIC_GROUP, EncodeContext::default())
        .expect_err("hierarchy beyond the fixed bound must fail before binding");
    assert!(matches!(error.code(), EncodeErrorCode::Structural { .. }));
}

#[test]
fn header_and_avp_flag_failures_are_typed_when_boundary_is_trustworthy() {
    let header_failure = encode_request(
        CommandFlags::from_bits(CommandFlags::REQUEST | CommandFlags::ERROR),
        COMMAND_DEVICE_WATCHDOG,
        APPLICATION_ID_COMMON_MESSAGES,
        &[],
    );
    let header_envelope = envelope(&header_failure);
    assert!(matches!(
        header_envelope.first_failure(),
        Some(DiameterRequestFailure::InvalidHeaderBits)
    ));
    let header_answer = encode_plan(
        &header_failure,
        &header_envelope,
        header_envelope.first_failure().expect("header failure"),
        DiameterErrorAnswerGrammar::Application,
    );
    let header_answer = decode_message(&header_answer);
    assert_eq!(result_code(&header_answer), 3008);
    assert!(header_answer.header.flags.is_error());

    let mut bad_flags = encode_avp(AvpHeader::ietf(AvpCode::new(777), true), b"x");
    bad_flags[4] = AvpFlags::MANDATORY | 1;
    let request = encode_request(
        CommandFlags::request(true),
        swm::COMMAND_DIAMETER_EAP,
        swm::APPLICATION_ID,
        &bad_flags,
    );
    let avp_envelope = envelope(&request);
    assert!(matches!(
        avp_envelope.first_failure(),
        Some(DiameterRequestFailure::InvalidAvpBits(_))
    ));
    let avp_answer = encode_plan(
        &request,
        &avp_envelope,
        avp_envelope.first_failure().expect("AVP flag failure"),
        DiameterErrorAnswerGrammar::Application,
    );
    let avp_answer = decode_message(&avp_answer);
    assert_eq!(result_code(&avp_answer), 3009);
    assert!(avp_answer.header.flags.is_error());

    let mut unsupported_version = encode_request(
        CommandFlags::request(false),
        COMMAND_DEVICE_WATCHDOG,
        APPLICATION_ID_COMMON_MESSAGES,
        &[],
    );
    unsupported_version[0] = 2;
    let version_envelope = envelope(&unsupported_version);
    assert!(matches!(
        version_envelope.first_failure(),
        Some(DiameterRequestFailure::UnsupportedVersion)
    ));
    let version_answer = encode_plan(
        &unsupported_version,
        &version_envelope,
        version_envelope
            .first_failure()
            .expect("unsupported version failure"),
        DiameterErrorAnswerGrammar::Application,
    );
    let version_answer = decode_message(&version_answer);
    assert_eq!(result_code(&version_answer), 5011);
    assert!(!version_answer.header.flags.is_error());
}

#[test]
fn malformed_base_and_swm_requests_can_receive_correlated_negative_answers() {
    let missing_origin = base::dictionary()
        .find_avp(AvpKey::ietf(AVP_ORIGIN_HOST))
        .expect("base Origin-Host definition");
    for command in [COMMAND_DEVICE_WATCHDOG, COMMAND_DISCONNECT_PEER] {
        let request = encode_request(
            CommandFlags::request(false),
            command,
            APPLICATION_ID_COMMON_MESSAGES,
            &[],
        );
        let envelope = envelope(&request);
        let failure = DiameterRequestFailure::MissingMandatoryAvp(
            DiameterFailedAvp::missing_for_definition(missing_origin, EncodeContext::default())
                .expect("base missing shape"),
        );
        let encoded = encode_plan(
            &request,
            &envelope,
            &failure,
            DiameterErrorAnswerGrammar::Application,
        );
        let answer = decode_message(&encoded);
        assert_eq!(answer.header.command_code, command);
        assert_eq!(result_code(&answer), 5005);
    }

    let session_definition = base::dictionary()
        .find_avp(AvpKey::ietf(AVP_SESSION_ID))
        .expect("base Session-Id definition");
    let swm_request = encode_request(
        CommandFlags::request(true),
        swm::COMMAND_DIAMETER_EAP,
        swm::APPLICATION_ID,
        &[],
    );
    let swm_envelope = envelope(&swm_request);
    let failure = DiameterRequestFailure::MissingMandatoryAvp(
        DiameterFailedAvp::missing_for_definition(session_definition, EncodeContext::default())
            .expect("SWm missing Session-Id shape"),
    );
    let encoded = encode_plan(
        &swm_request,
        &swm_envelope,
        &failure,
        DiameterErrorAnswerGrammar::Rfc6733ErrorBitFallback,
    );
    let answer = decode_message(&encoded);
    assert_eq!(answer.header.command_code, swm::COMMAND_DIAMETER_EAP);
    assert_eq!(answer.header.application_id, swm::APPLICATION_ID);
    assert_eq!(result_code(&answer), 5005);
    assert!(answer.header.flags.is_error());
}

#[test]
fn unsafe_boundaries_and_resource_excess_are_unanswerable() {
    let request = fixture(UNKNOWN_COMMAND_REQUEST);
    for prefix in 0..DIAMETER_HEADER_LEN {
        assert!(matches!(
            inspect_diameter_request(&request[..prefix], DecodeContext::conservative()),
            DiameterRequestInspection::Unanswerable(DiameterUnanswerableReason::TooShortForHeader)
        ));
    }
    let mut answer_header = request[..DIAMETER_HEADER_LEN].to_vec();
    answer_header[4] &= !CommandFlags::REQUEST;
    assert!(matches!(
        inspect_diameter_request(&answer_header, DecodeContext::conservative()),
        DiameterRequestInspection::Unanswerable(DiameterUnanswerableReason::NotARequest)
    ));
    let mut incomplete = request[..DIAMETER_HEADER_LEN].to_vec();
    incomplete[1..4].copy_from_slice(&100_u32.to_be_bytes()[1..4]);
    assert!(matches!(
        inspect_diameter_request(&incomplete, DecodeContext::conservative()),
        DiameterRequestInspection::Unanswerable(
            DiameterUnanswerableReason::UntrustworthyMessageBoundary
        )
    ));
    let tiny_bound = DecodeContext {
        max_message_len: DIAMETER_HEADER_LEN,
        ..DecodeContext::conservative()
    };
    assert!(matches!(
        inspect_diameter_request(&request, tiny_bound),
        DiameterRequestInspection::Unanswerable(DiameterUnanswerableReason::MessageLengthExceeded)
    ));
    let no_avps = DecodeContext {
        max_ies: 0,
        ..DecodeContext::conservative()
    };
    assert!(matches!(
        inspect_diameter_request(&request, no_avps),
        DiameterRequestInspection::Unanswerable(DiameterUnanswerableReason::AvpCountExceeded)
    ));
}

#[test]
fn only_the_first_failure_is_selected() {
    let first = encode_avp(AvpHeader::ietf(AVP_SESSION_ID, true), b"first");
    let second = encode_avp(AvpHeader::ietf(AVP_SESSION_ID, true), b"second");
    let mut raw = first;
    raw.extend_from_slice(&second);
    let request = encode_request(
        CommandFlags::from_bits(CommandFlags::REQUEST | CommandFlags::ERROR),
        swm::COMMAND_DIAMETER_EAP,
        swm::APPLICATION_ID,
        &raw,
    );
    let envelope = envelope(&request);
    assert!(matches!(
        envelope.first_failure(),
        Some(DiameterRequestFailure::InvalidHeaderBits)
    ));
}

#[test]
fn generic_decode_categories_map_without_guessing_structural_semantics() {
    let request = fixture(UNSUPPORTED_MANDATORY_AVP_REQUEST);
    let request_envelope = envelope(&request);
    let message = decode_message(&request);
    let (offset, _) = find_avp_at(&message, AvpCode::new(777));
    let unknown = DecodeError::new(DecodeErrorCode::UnknownCriticalIe, offset);
    assert!(DiameterRequestFailure::from_decode_error(
        &request_envelope,
        &request,
        &unknown,
        DecodeContext::conservative(),
        APP_DICTIONARIES,
        EncodeContext::default(),
    )
    .is_ok_and(|bound| matches!(
        bound.failure(),
        DiameterRequestFailure::UnsupportedMandatoryAvp(_)
    )));

    let first = encode_avp(AvpHeader::ietf(AVP_SESSION_ID, true), b"first");
    let second = encode_avp(AvpHeader::ietf(AVP_SESSION_ID, true), b"second");
    let mut raw = first.clone();
    raw.extend_from_slice(&second);
    let duplicate_request = encode_request(
        CommandFlags::request(true),
        swm::COMMAND_DIAMETER_EAP,
        swm::APPLICATION_ID,
        &raw,
    );
    let duplicate_envelope = envelope(&duplicate_request);
    let duplicate = DecodeError::new(
        DecodeErrorCode::DuplicateIe,
        DIAMETER_HEADER_LEN + first.len(),
    );
    assert!(DiameterRequestFailure::from_decode_error(
        &duplicate_envelope,
        &duplicate_request,
        &duplicate,
        DecodeContext::conservative(),
        APP_DICTIONARIES,
        EncodeContext::default(),
    )
    .is_ok_and(|bound| matches!(bound.failure(), DiameterRequestFailure::ExcessSingleton(_))));

    let mut different_request = request.clone();
    different_request[offset + 8] ^= 1;
    assert_eq!(
        DiameterRequestFailure::from_decode_error(
            &request_envelope,
            &different_request,
            &unknown,
            DecodeContext::conservative(),
            APP_DICTIONARIES,
            EncodeContext::default(),
        ),
        Err(DiameterFailureMappingError::RequestMismatch)
    );
    let structural = DecodeError::new(
        DecodeErrorCode::Structural {
            reason: "synthetic command-specific failure",
        },
        offset,
    );
    assert!(DiameterRequestFailure::from_decode_error(
        &request_envelope,
        &request,
        &structural,
        DecodeContext::conservative(),
        APP_DICTIONARIES,
        EncodeContext::default(),
    )
    .is_ok_and(|bound| matches!(
        bound.failure(),
        DiameterRequestFailure::UnsupportedMandatoryAvp(_)
    )));
}

#[test]
fn triple_singleton_mapping_and_binding_copy_exactly_the_second_occurrence() {
    let first = encode_avp(
        AvpHeader::vendor(swm::AVP_EMERGENCY_SERVICES, VENDOR_ID_3GPP, false),
        &1_u32.to_be_bytes(),
    );
    let second = encode_avp(
        AvpHeader::vendor(swm::AVP_EMERGENCY_SERVICES, VENDOR_ID_3GPP, false),
        &2_u32.to_be_bytes(),
    );
    let third = encode_avp(
        AvpHeader::vendor(swm::AVP_EMERGENCY_SERVICES, VENDOR_ID_3GPP, false),
        &3_u32.to_be_bytes(),
    );
    let mut raw = first.clone();
    raw.extend_from_slice(&second);
    raw.extend_from_slice(&third);
    let request = encode_request(
        CommandFlags::request(true),
        swm::COMMAND_DIAMETER_EAP,
        swm::APPLICATION_ID,
        &raw,
    );
    let request_envelope = envelope(&request);
    let second_offset = DIAMETER_HEADER_LEN + first.len();
    let third_offset = second_offset + second.len();

    let third_error = DecodeError::new(DecodeErrorCode::DuplicateIe, third_offset);
    let mapped = DiameterRequestFailure::from_decode_error(
        &request_envelope,
        &request,
        &third_error,
        DecodeContext::conservative(),
        APP_DICTIONARIES,
        EncodeContext::default(),
    )
    .expect("central cardinality classification must select the first excess occurrence");
    let DiameterRequestFailure::ExcessSingleton(mapped_failed) = mapped.failure() else {
        panic!("triple singleton must map to excess singleton");
    };
    assert_eq!(mapped_failed.leaf_offset(), Some(second_offset));

    let third_raw = RawAvp::decode(&third, DecodeContext::default())
        .expect("third AVP must decode")
        .1;
    let supplied_third = DiameterRequestFailure::ExcessSingleton(
        DiameterFailedAvp::copied(&third_raw, third_offset, EncodeContext::default())
            .expect("third occurrence must copy"),
    );
    let bound = request_envelope
        .bind_application_failure(&request, supplied_third, APP_DICTIONARIES)
        .expect("binding must replace later evidence with the first excess occurrence");
    let DiameterRequestFailure::ExcessSingleton(bound_failed) = bound.failure() else {
        panic!("bound triple singleton must remain excess singleton");
    };
    assert_eq!(bound_failed.leaf_offset(), Some(second_offset));
}

#[test]
fn nested_application_cardinality_uses_only_the_immediate_grouped_grammar() {
    let singleton_children: Vec<_> = [1_u32, 2, 3]
        .into_iter()
        .map(|value| {
            encode_avp(
                AvpHeader::vendor(
                    SYNTHETIC_VENDOR_U32.key().code(),
                    VendorId::new(10_415),
                    true,
                ),
                &value.to_be_bytes(),
            )
        })
        .collect();
    let singleton_value: Vec<_> = singleton_children
        .iter()
        .flat_map(|child| child.iter().copied())
        .collect();
    let singleton_group_wire = encode_avp(
        AvpHeader::vendor(SYNTHETIC_GROUP.key().code(), VendorId::new(10_415), true),
        &singleton_value,
    );
    let singleton_group = RawAvp::decode(&singleton_group_wire, DecodeContext::default())
        .expect("singleton test group must decode")
        .1;
    let singleton_request = encode_request(
        CommandFlags::request(false),
        COMMAND_DEVICE_WATCHDOG,
        APPLICATION_ID_COMMON_MESSAGES,
        &singleton_group_wire,
    );
    let singleton_envelope = envelope(&singleton_request);
    let child_base = DIAMETER_HEADER_LEN + singleton_group.header.header_len();
    let second_offset = child_base + singleton_children[0].len();
    let third_offset = second_offset + singleton_children[1].len();
    let second = RawAvp::decode(&singleton_children[1], DecodeContext::default())
        .expect("second nested singleton must decode")
        .1;
    let third = RawAvp::decode(&singleton_children[2], DecodeContext::default())
        .expect("third nested singleton must decode")
        .1;

    let first_excess = DiameterFailedAvp::copied(&second, second_offset, EncodeContext::default())
        .expect("second nested singleton must copy")
        .within_group(
            &singleton_group,
            DIAMETER_HEADER_LEN,
            EncodeContext::default(),
        )
        .expect("complete nested ancestry must build");
    let bound = singleton_envelope
        .bind_application_failure(
            &singleton_request,
            DiameterRequestFailure::ExcessSingleton(first_excess),
            SYNTHETIC_AVP_DICTIONARIES,
        )
        .expect("the grouped ZeroOrOne rule must bind its second direct child");
    let DiameterRequestFailure::ExcessSingleton(failed) = bound.failure() else {
        panic!("nested duplicate must bind as 5009");
    };
    assert_eq!(failed.leaf_offset(), Some(second_offset));

    let later_excess = DiameterFailedAvp::copied(&third, third_offset, EncodeContext::default())
        .expect("third nested singleton must copy")
        .within_group(
            &singleton_group,
            DIAMETER_HEADER_LEN,
            EncodeContext::default(),
        )
        .expect("complete later nested ancestry must build");
    assert_eq!(
        singleton_envelope.bind_application_failure(
            &singleton_request,
            DiameterRequestFailure::ExcessSingleton(later_excess),
            SYNTHETIC_AVP_DICTIONARIES,
        ),
        Err(DiameterRequestClassificationError::FailureProvenanceMismatch)
    );

    let mut top_level_singletons = singleton_children[0].clone();
    top_level_singletons.extend_from_slice(&singleton_children[1]);
    let top_level_request = encode_request(
        CommandFlags::request(false),
        COMMAND_DEVICE_WATCHDOG,
        APPLICATION_ID_COMMON_MESSAGES,
        &top_level_singletons,
    );
    let top_level_second = DiameterFailedAvp::copied(
        &second,
        DIAMETER_HEADER_LEN + singleton_children[0].len(),
        EncodeContext::default(),
    )
    .expect("top-level second occurrence must copy");
    assert_eq!(
        envelope(&top_level_request).bind_application_failure(
            &top_level_request,
            DiameterRequestFailure::ExcessSingleton(top_level_second),
            SYNTHETIC_AVP_DICTIONARIES,
        ),
        Err(DiameterRequestClassificationError::FailureProvenanceMismatch)
    );

    let forbidden_children: Vec<_> = [10_u32, 11]
        .into_iter()
        .map(|value| {
            encode_avp(
                AvpHeader::vendor(
                    SYNTHETIC_FORBIDDEN_U32.key().code(),
                    VendorId::new(10_415),
                    true,
                ),
                &value.to_be_bytes(),
            )
        })
        .collect();
    let forbidden_value: Vec<_> = forbidden_children
        .iter()
        .flat_map(|child| child.iter().copied())
        .collect();
    let forbidden_group_wire = encode_avp(
        AvpHeader::vendor(SYNTHETIC_GROUP.key().code(), VendorId::new(10_415), true),
        &forbidden_value,
    );
    let forbidden_group = RawAvp::decode(&forbidden_group_wire, DecodeContext::default())
        .expect("forbidden test group must decode")
        .1;
    let forbidden_request = encode_request(
        CommandFlags::request(false),
        COMMAND_DEVICE_WATCHDOG,
        APPLICATION_ID_COMMON_MESSAGES,
        &forbidden_group_wire,
    );
    let forbidden_envelope = envelope(&forbidden_request);
    for (index, child_wire) in forbidden_children.iter().enumerate() {
        let child = RawAvp::decode(child_wire, DecodeContext::default())
            .expect("nested forbidden child must decode")
            .1;
        let offset = DIAMETER_HEADER_LEN
            + forbidden_group.header.header_len()
            + forbidden_children[..index]
                .iter()
                .map(Vec::len)
                .sum::<usize>();
        let failed = DiameterFailedAvp::copied(&child, offset, EncodeContext::default())
            .expect("nested forbidden child must copy")
            .within_group(
                &forbidden_group,
                DIAMETER_HEADER_LEN,
                EncodeContext::default(),
            )
            .expect("nested forbidden ancestry must build");
        let result = forbidden_envelope.bind_application_failure(
            &forbidden_request,
            DiameterRequestFailure::ForbiddenAvp(failed),
            SYNTHETIC_AVP_DICTIONARIES,
        );
        if index == 0 {
            assert!(result.is_ok(), "the first forbidden child must bind");
        } else {
            assert_eq!(
                result,
                Err(DiameterRequestClassificationError::FailureProvenanceMismatch)
            );
        }
    }
}

#[test]
fn new_diagnostic_types_never_expose_sensitive_values() {
    let request = fixture(INVALID_AVP_VALUE_REQUEST);
    let envelope = envelope(&request);
    let message = decode_message(&request);
    let (offset, offending) = find_avp_at(&message, AVP_DISCONNECT_CAUSE);
    let failed = DiameterFailedAvp::copied(&offending, offset, EncodeContext::default())
        .expect("offending AVP copy");
    let origin = origin();
    let bound = envelope
        .bind_application_failure(
            &request,
            DiameterRequestFailure::InvalidAvpValue(failed.clone()),
            APP_DICTIONARIES,
        )
        .expect("copied diagnostic evidence must bind to this request");
    let plan = build_diameter_error_answer(
        &envelope,
        &bound,
        &origin,
        DiameterErrorAnswerGrammar::Application,
        EncodeContext::default(),
    )
    .expect("plan must build");
    for rendered in [
        format!("{envelope:?}"),
        format!("{failed:?}"),
        format!("{failed}"),
        format!("{origin:?}"),
        format!("{origin}"),
        format!("{plan:?}"),
    ] {
        for secret in [
            "sess;fixture;01",
            "proxy-a",
            "proxy-b",
            "destination.example",
            "example",
            "aaa.local",
            "local.test",
        ] {
            assert!(!rendered.contains(secret), "diagnostic leaked {secret}");
        }
    }
    let sizing = plan.amplification_metadata();
    assert_eq!(sizing.request_wire_len, request.len());
    assert_eq!(sizing.planned_response_len, plan.planned_response_len());
    let retained_routing = envelope
        .session_id()
        .map_or(0, |session| session.retained_wire_len())
        + envelope
            .proxy_infos()
            .iter()
            .map(|proxy| proxy.retained_wire_len())
            .sum::<usize>();
    assert_eq!(
        sizing.retained_request_bytes,
        retained_routing + failed.retained_wire_len()
    );
    assert!(sizing.retained_request_bytes <= request.len());
}

#[test]
fn origin_and_encode_limits_fail_closed() {
    assert!(DiameterErrorOrigin::new("", "realm").is_err());
    assert!(DiameterErrorOrigin::new("host", "").is_err());
    let request = fixture(UNKNOWN_COMMAND_REQUEST);
    let envelope = envelope(&request);
    let tiny = EncodeContext {
        max_message_len: DIAMETER_HEADER_LEN,
        ..EncodeContext::default()
    };
    let failure = envelope
        .classify(&request, APP_DICTIONARIES)
        .expect("dictionary classification must be unique")
        .expect("unknown command must be classified");
    assert!(build_diameter_error_answer(
        &envelope,
        &failure,
        &origin(),
        DiameterErrorAnswerGrammar::Application,
        tiny,
    )
    .is_err());
}

#[test]
fn rfc6733_result_codes_include_the_normative_reserved_header_value() {
    let missing =
        DiameterFailedAvp::missing_for_definition(&SYNTHETIC_VENDOR_U32, EncodeContext::default())
            .expect("synthetic Failed-AVP must fit");
    let cases = [
        (
            DiameterRequestFailure::UnknownCommand,
            RESULT_CODE_DIAMETER_COMMAND_UNSUPPORTED,
        ),
        (
            DiameterRequestFailure::UnsupportedApplication,
            RESULT_CODE_DIAMETER_APPLICATION_UNSUPPORTED,
        ),
        (
            DiameterRequestFailure::InvalidHeaderBits,
            RESULT_CODE_DIAMETER_INVALID_HDR_BITS,
        ),
        (
            DiameterRequestFailure::InvalidAvpBits(missing.clone()),
            RESULT_CODE_DIAMETER_INVALID_AVP_BITS,
        ),
        (
            DiameterRequestFailure::UnsupportedMandatoryAvp(missing.clone()),
            RESULT_CODE_DIAMETER_AVP_UNSUPPORTED,
        ),
        (
            DiameterRequestFailure::InvalidAvpValue(missing.clone()),
            RESULT_CODE_DIAMETER_INVALID_AVP_VALUE,
        ),
        (
            DiameterRequestFailure::MissingMandatoryAvp(missing.clone()),
            RESULT_CODE_DIAMETER_MISSING_AVP,
        ),
        (
            DiameterRequestFailure::ForbiddenAvp(missing.clone()),
            RESULT_CODE_DIAMETER_AVP_NOT_ALLOWED,
        ),
        (
            DiameterRequestFailure::ExcessSingleton(missing.clone()),
            RESULT_CODE_DIAMETER_AVP_OCCURS_TOO_MANY_TIMES,
        ),
        (
            DiameterRequestFailure::UnsupportedVersion,
            RESULT_CODE_DIAMETER_UNSUPPORTED_VERSION,
        ),
        (
            DiameterRequestFailure::InvalidBitInHeader,
            RESULT_CODE_DIAMETER_INVALID_BIT_IN_HEADER,
        ),
        (
            DiameterRequestFailure::InvalidAvpLength(missing),
            RESULT_CODE_DIAMETER_INVALID_AVP_LENGTH,
        ),
    ];
    for (failure, expected) in cases {
        assert_eq!(failure.result_code(), expected);
    }
    assert_eq!(RESULT_CODE_DIAMETER_INVALID_BIT_IN_HEADER, 5013);
}

#[test]
fn reserved_header_bits_use_5013_while_command_bit_mismatches_use_3008() {
    let mut reserved = encode_request(
        CommandFlags::request(false),
        COMMAND_DEVICE_WATCHDOG,
        APPLICATION_ID_COMMON_MESSAGES,
        &[],
    );
    reserved[4] |= 1;
    let reserved_envelope = envelope(&reserved);
    assert!(matches!(
        reserved_envelope.first_failure(),
        Some(DiameterRequestFailure::InvalidBitInHeader)
    ));
    let reserved_answer = encode_plan(
        &reserved,
        &reserved_envelope,
        reserved_envelope
            .first_failure()
            .expect("reserved-bit failure"),
        DiameterErrorAnswerGrammar::Application,
    );
    let reserved_answer = decode_message(&reserved_answer);
    assert_eq!(result_code(&reserved_answer), 5013);
    assert!(!reserved_answer.header.flags.is_error());

    let wrong_p = encode_request(
        CommandFlags::request(true),
        COMMAND_DEVICE_WATCHDOG,
        APPLICATION_ID_COMMON_MESSAGES,
        &[],
    );
    let wrong_p_envelope = envelope(&wrong_p);
    assert!(wrong_p_envelope
        .classify(&wrong_p, APP_DICTIONARIES)
        .expect("base command dictionary must be unique")
        .is_some_and(|bound| matches!(bound.failure(), DiameterRequestFailure::InvalidHeaderBits)));

    let missing_p = encode_request(
        CommandFlags::request(false),
        swm::COMMAND_DIAMETER_EAP,
        swm::APPLICATION_ID,
        &[],
    );
    let missing_p_envelope = envelope(&missing_p);
    assert!(missing_p_envelope
        .classify(&missing_p, APP_DICTIONARIES)
        .expect("SWm command dictionary must be unique")
        .is_some_and(|bound| matches!(bound.failure(), DiameterRequestFailure::InvalidHeaderBits)));
}

#[test]
fn protocol_results_report_the_effective_rfc6733_error_bit_grammar() {
    let request = fixture(UNKNOWN_COMMAND_REQUEST);
    let envelope = envelope(&request);
    let failure = envelope
        .classify(&request, APP_DICTIONARIES)
        .expect("dictionary classification must be unique")
        .expect("unknown command must be classified");
    let plan = build_diameter_error_answer(
        &envelope,
        &failure,
        &origin(),
        DiameterErrorAnswerGrammar::Application,
        EncodeContext::default(),
    )
    .expect("protocol error plan must build");
    assert!(plan.has_error_bit());
    assert_eq!(
        plan.grammar(),
        DiameterErrorAnswerGrammar::Rfc6733ErrorBitFallback
    );
}

#[test]
fn dictionary_ambiguity_is_local_and_never_becomes_a_peer_error_plan() {
    let request = encode_request(
        CommandFlags::request(false),
        COMMAND_DEVICE_WATCHDOG,
        APPLICATION_ID_COMMON_MESSAGES,
        &[],
    );
    let request_envelope = envelope(&request);
    assert_eq!(
        request_envelope.classify(&request, AMBIGUOUS_APPLICATION_DICTIONARIES),
        Err(DiameterRequestClassificationError::ApplicationAmbiguous)
    );
    assert_eq!(
        request_envelope.classify(&request, AMBIGUOUS_COMMAND_DICTIONARIES),
        Err(DiameterRequestClassificationError::CommandAmbiguous)
    );

    let origin_host = encode_avp(AvpHeader::ietf(AVP_ORIGIN_HOST, true), b"peer.example");
    let avp_request = encode_request(
        CommandFlags::request(false),
        COMMAND_DEVICE_WATCHDOG,
        APPLICATION_ID_COMMON_MESSAGES,
        &origin_host,
    );
    let avp_envelope = envelope(&avp_request);
    assert_eq!(
        avp_envelope.classify(&avp_request, AMBIGUOUS_AVP_DICTIONARIES),
        Err(DiameterRequestClassificationError::AvpDefinitionAmbiguous)
    );

    let unknown = encode_avp(AvpHeader::ietf(AvpCode::new(900), true), b"x");
    let request = encode_request(
        CommandFlags::request(false),
        COMMAND_DEVICE_WATCHDOG,
        APPLICATION_ID_COMMON_MESSAGES,
        &unknown,
    );
    let envelope = envelope(&request);
    let error = DecodeError::new(DecodeErrorCode::UnknownCriticalIe, DIAMETER_HEADER_LEN);
    assert_eq!(
        DiameterRequestFailure::from_decode_error(
            &envelope,
            &request,
            &error,
            DecodeContext::conservative(),
            AMBIGUOUS_COMMAND_DICTIONARIES,
            EncodeContext::default(),
        ),
        Err(DiameterFailureMappingError::CommandAmbiguous)
    );
}

#[test]
fn dictionary_m_p_and_vendor_zero_rules_fail_with_peer_specific_results() {
    let wrong_m = encode_avp(AvpHeader::ietf(AVP_ORIGIN_HOST, false), b"peer.example");
    let wrong_m_request = encode_request(
        CommandFlags::request(false),
        COMMAND_DEVICE_WATCHDOG,
        APPLICATION_ID_COMMON_MESSAGES,
        &wrong_m,
    );
    let wrong_m_envelope = envelope(&wrong_m_request);
    assert!(wrong_m_envelope
        .classify(&wrong_m_request, APP_DICTIONARIES)
        .expect("classification must be unique")
        .is_some_and(|bound| matches!(bound.failure(), DiameterRequestFailure::InvalidAvpBits(_))));

    let wrong_p_header =
        AvpHeader::ietf(AVP_ORIGIN_HOST, true).with_flags(AvpFlags::new(false, true, true));
    let wrong_p = encode_avp_with_padding(wrong_p_header, b"peer.example", 0);
    let wrong_p_request = encode_request(
        CommandFlags::request(false),
        COMMAND_DEVICE_WATCHDOG,
        APPLICATION_ID_COMMON_MESSAGES,
        &wrong_p,
    );
    let wrong_p_envelope = envelope(&wrong_p_request);
    assert!(wrong_p_envelope
        .classify(&wrong_p_request, APP_DICTIONARIES)
        .expect("classification must be unique")
        .is_some_and(|bound| matches!(bound.failure(), DiameterRequestFailure::InvalidAvpBits(_))));

    let vendor_zero = encode_avp(
        AvpHeader::vendor(AvpCode::new(900), VendorId::new(0), true),
        b"x",
    );
    let vendor_zero_request = encode_request(
        CommandFlags::request(false),
        COMMAND_DEVICE_WATCHDOG,
        APPLICATION_ID_COMMON_MESSAGES,
        &vendor_zero,
    );
    let vendor_zero_envelope = envelope(&vendor_zero_request);
    assert!(vendor_zero_envelope
        .classify(&vendor_zero_request, APP_DICTIONARIES)
        .expect("classification must be unique")
        .is_some_and(|bound| matches!(
            bound.failure(),
            DiameterRequestFailure::InvalidAvpValue(_)
        )));
}

#[test]
fn proxy_info_is_canonically_reencoded_without_exposing_opaque_state() {
    let proxy_state =
        encode_avp_with_padding(AvpHeader::ietf(AVP_PROXY_STATE, true), b"state-x", 0xA5);
    let unknown = encode_avp_with_padding(
        AvpHeader::ietf(AvpCode::new(9_001), false).with_flags(AvpFlags::new(false, false, true)),
        b"opaque-extension",
        0,
    );
    let proxy_host = encode_avp(AvpHeader::ietf(AVP_PROXY_HOST, true), b"proxy.example");
    let mut grouped = proxy_state;
    grouped.extend_from_slice(&unknown);
    grouped.extend_from_slice(&proxy_host);
    let proxy_info = encode_avp(AvpHeader::ietf(AVP_PROXY_INFO, true), &grouped);
    let request = encode_request(
        CommandFlags::request(false),
        COMMAND_DEVICE_WATCHDOG,
        APPLICATION_ID_COMMON_MESSAGES,
        &proxy_info,
    );
    let envelope = envelope(&request);
    assert!(matches!(
        envelope.first_failure(),
        Some(DiameterRequestFailure::InvalidAvpValue(_))
    ));
    let answer = encode_plan(
        &request,
        &envelope,
        envelope.first_failure().expect("proxy padding failure"),
        DiameterErrorAnswerGrammar::Application,
    );
    let strict = DecodeContext {
        unknown_ie_policy: UnknownIePolicy::Preserve,
        ..DecodeContext::conservative()
    };
    let answer_message = Message::decode(&answer, strict)
        .expect("canonical answer must pass strict framing")
        .1;
    let proxy = avps(&answer_message)
        .into_iter()
        .find(|avp| avp.header.code == AVP_PROXY_INFO)
        .expect("answer must copy Proxy-Info");
    assert_eq!(proxy.header.flags.bits(), AvpFlags::MANDATORY);
    assert!(proxy.padding.iter().all(|byte| *byte == 0));
    let children: Vec<_> = proxy
        .grouped_avps(strict)
        .map(|child| child.expect("canonical Proxy-Info child must decode"))
        .collect();
    assert_eq!(
        children
            .iter()
            .map(|child| child.header.code)
            .collect::<Vec<_>>(),
        [AVP_PROXY_STATE, AvpCode::new(9_001), AVP_PROXY_HOST]
    );
    assert_eq!(children[0].value, b"state-x");
    assert!(children[0].padding.iter().all(|byte| *byte == 0));
    assert_eq!(children[1].value, b"opaque-extension");
    assert_eq!(children[1].header.flags.bits(), 0);
    assert_eq!(children[2].value, b"proxy.example");
}

#[test]
fn base_watchdog_and_disconnect_errors_parse_as_dwa_and_dpa() {
    let missing_origin = base::dictionary()
        .find_avp(AvpKey::ietf(AVP_ORIGIN_HOST))
        .expect("base Origin-Host definition");
    for command in [COMMAND_DEVICE_WATCHDOG, COMMAND_DISCONNECT_PEER] {
        let request = encode_request(
            CommandFlags::request(false),
            command,
            APPLICATION_ID_COMMON_MESSAGES,
            &[],
        );
        let envelope = envelope(&request);
        let failure = DiameterRequestFailure::MissingMandatoryAvp(
            DiameterFailedAvp::missing_for_definition(missing_origin, EncodeContext::default())
                .expect("missing AVP must build"),
        );
        let answer = encode_plan(
            &request,
            &envelope,
            &failure,
            DiameterErrorAnswerGrammar::Application,
        );
        let message = decode_message(&answer);
        if command == COMMAND_DEVICE_WATCHDOG {
            let parsed = parse_device_watchdog_answer(&message, DecodeContext::default())
                .expect("DWA error answer must parse");
            assert_eq!(parsed.result_code, RESULT_CODE_DIAMETER_MISSING_AVP);
        } else {
            let parsed = parse_disconnect_peer_answer(&message, DecodeContext::default())
                .expect("DPA error answer must parse");
            assert_eq!(parsed.result_code, RESULT_CODE_DIAMETER_MISSING_AVP);
        }
    }
}

#[test]
fn nested_missing_failed_avp_has_parent_relative_structure_and_no_fake_offset() {
    let failed =
        DiameterFailedAvp::missing_for_definition(&SYNTHETIC_VENDOR_U32, EncodeContext::default())
            .expect("missing leaf must build")
            .within_missing_group(&SYNTHETIC_GROUP, EncodeContext::default())
            .expect("missing grouped hierarchy must build");
    assert_eq!(failed.leaf_offset(), None);
    assert_eq!(failed.hierarchy_depth(), 1);

    let request = encode_request(
        CommandFlags::request(false),
        COMMAND_DEVICE_WATCHDOG,
        APPLICATION_ID_COMMON_MESSAGES,
        &[],
    );
    let envelope = envelope(&request);
    let bound = envelope
        .bind_application_failure(
            &request,
            DiameterRequestFailure::MissingMandatoryAvp(failed),
            SYNTHETIC_AVP_DICTIONARIES,
        )
        .expect("synthetic nested missing evidence must bind");
    let answer = encode_plan(
        &request,
        &envelope,
        &bound,
        DiameterErrorAnswerGrammar::Application,
    );
    let message = decode_message(&answer);
    let failed_group = avps(&message)
        .into_iter()
        .find(|avp| avp.header.code == AVP_FAILED_AVP)
        .expect("Failed-AVP must exist");
    let outer = RawAvp::decode(failed_group.value, DecodeContext::default())
        .expect("synthesized parent must decode")
        .1;
    assert_eq!(outer.header.code, SYNTHETIC_GROUP.key().code());
    let leaf = RawAvp::decode(outer.value, DecodeContext::default())
        .expect("synthesized missing leaf must decode")
        .1;
    assert_eq!(leaf.header.code, SYNTHETIC_VENDOR_U32.key().code());
    assert_eq!(leaf.value, [0, 0, 0, 0]);
}

#[test]
fn decode_error_mapping_rejects_local_policy_header_offsets_and_repeatable_duplicates() {
    let optional = encode_avp(AvpHeader::ietf(AvpCode::new(9_002), false), b"optional");
    let optional_request = encode_request(
        CommandFlags::request(false),
        COMMAND_DEVICE_WATCHDOG,
        APPLICATION_ID_COMMON_MESSAGES,
        &optional,
    );
    let optional_envelope = envelope(&optional_request);
    let optional_message = decode_message(&optional_request);
    let optional_error =
        parse_device_watchdog_request(&optional_message, DecodeContext::conservative())
            .expect_err("local Reject policy must reject the optional unknown AVP");
    assert_eq!(optional_error.code(), &DecodeErrorCode::UnknownCriticalIe);
    assert_eq!(optional_error.offset(), DIAMETER_HEADER_LEN);
    assert_eq!(
        DiameterRequestFailure::from_decode_error(
            &optional_envelope,
            &optional_request,
            &optional_error,
            DecodeContext::conservative(),
            APP_DICTIONARIES,
            EncodeContext::default(),
        ),
        Err(DiameterFailureMappingError::LocalUnknownOptionalRejected)
    );

    let header_error =
        parse_disconnect_peer_request(&optional_message, DecodeContext::conservative())
            .expect_err("the DPR parser must reject a DWR command code at the header");
    assert!(matches!(
        header_error.code(),
        DecodeErrorCode::InvalidEnumValue { .. }
    ));
    assert_eq!(header_error.offset(), 5);
    assert_eq!(
        DiameterRequestFailure::from_decode_error(
            &optional_envelope,
            &optional_request,
            &header_error,
            DecodeContext::conservative(),
            APP_DICTIONARIES,
            EncodeContext::default(),
        ),
        Err(DiameterFailureMappingError::OffsetAmbiguous)
    );

    let host_ip = encode_avp(
        AvpHeader::ietf(AVP_HOST_IP_ADDRESS, true),
        &[0, 1, 192, 0, 2, 1],
    );
    let mut repeated = host_ip.clone();
    repeated.extend_from_slice(&host_ip);
    let cer = encode_request(
        CommandFlags::request(false),
        COMMAND_CAPABILITIES_EXCHANGE,
        APPLICATION_ID_COMMON_MESSAGES,
        &repeated,
    );
    let cer_envelope = envelope(&cer);
    let duplicate = Message::decode(&cer, DecodeContext::conservative())
        .expect_err("blanket raw duplicate policy must reject repeated Host-IP-Address");
    assert_eq!(duplicate.code(), &DecodeErrorCode::DuplicateIe);
    assert_eq!(duplicate.offset(), DIAMETER_HEADER_LEN + host_ip.len());
    assert_eq!(
        DiameterRequestFailure::from_decode_error(
            &cer_envelope,
            &cer,
            &duplicate,
            DecodeContext::conservative(),
            APP_DICTIONARIES,
            EncodeContext::default(),
        ),
        Err(DiameterFailureMappingError::RepeatableDuplicate)
    );

    let one = encode_request(
        CommandFlags::request(false),
        COMMAND_CAPABILITIES_EXCHANGE,
        APPLICATION_ID_COMMON_MESSAGES,
        &host_ip,
    );
    let one_envelope = envelope(&one);
    let false_duplicate = DecodeError::new(DecodeErrorCode::DuplicateIe, DIAMETER_HEADER_LEN);
    assert_eq!(
        DiameterRequestFailure::from_decode_error(
            &one_envelope,
            &one,
            &false_duplicate,
            DecodeContext::conservative(),
            APP_DICTIONARIES,
            EncodeContext::default(),
        ),
        Err(DiameterFailureMappingError::ProvenanceMismatch)
    );
}

#[test]
fn proxy_info_canonicalization_honors_depth_and_nested_ie_limits() {
    let proxy_host = encode_avp(AvpHeader::ietf(AVP_PROXY_HOST, true), b"proxy.example");
    let proxy_state = encode_avp(AvpHeader::ietf(AVP_PROXY_STATE, true), b"state");
    let mut children = proxy_host;
    children.extend_from_slice(&proxy_state);
    let proxy_info = encode_avp(AvpHeader::ietf(AVP_PROXY_INFO, true), &children);
    let request = encode_request(
        CommandFlags::request(false),
        COMMAND_DEVICE_WATCHDOG,
        APPLICATION_ID_COMMON_MESSAGES,
        &proxy_info,
    );

    let no_descent = DecodeContext {
        max_depth: 0,
        ..DecodeContext::conservative()
    };
    assert_eq!(
        inspect_diameter_request(&request, no_descent),
        DiameterRequestInspection::Unanswerable(DiameterUnanswerableReason::NestingDepthExceeded)
    );

    let one_child = DecodeContext {
        max_ies: 1,
        ..DecodeContext::conservative()
    };
    assert_eq!(
        inspect_diameter_request(&request, one_child),
        DiameterRequestInspection::Unanswerable(DiameterUnanswerableReason::AvpCountExceeded)
    );

    let exact_limit = DecodeContext {
        max_depth: 1,
        max_ies: 2,
        ..DecodeContext::conservative()
    };
    assert!(matches!(
        inspect_diameter_request(&request, exact_limit),
        DiameterRequestInspection::Request(_)
    ));

    let mut hostile_children = Vec::new();
    for code in 10_000..10_064 {
        hostile_children
            .extend_from_slice(&encode_avp(AvpHeader::ietf(AvpCode::new(code), false), &[]));
    }
    let hostile_proxy = encode_avp(AvpHeader::ietf(AVP_PROXY_INFO, true), &hostile_children);
    let hostile_request = encode_request(
        CommandFlags::request(false),
        COMMAND_DEVICE_WATCHDOG,
        APPLICATION_ID_COMMON_MESSAGES,
        &hostile_proxy,
    );
    let bounded = DecodeContext {
        max_ies: 8,
        ..DecodeContext::conservative()
    };
    assert_eq!(
        inspect_diameter_request(&hostile_request, bounded),
        DiameterRequestInspection::Unanswerable(DiameterUnanswerableReason::AvpCountExceeded)
    );
}

#[test]
fn duplicate_mapping_requires_explicit_command_cardinality() {
    let origin = encode_avp(AvpHeader::ietf(AVP_ORIGIN_HOST, true), b"peer.example");
    let mut raw = origin.clone();
    raw.extend_from_slice(&origin);
    let request = encode_request(
        CommandFlags::request(false),
        COMMAND_DEVICE_WATCHDOG,
        APPLICATION_ID_COMMON_MESSAGES,
        &raw,
    );
    let base_envelope = envelope(&request);
    let error = DecodeError::new(
        DecodeErrorCode::DuplicateIe,
        DIAMETER_HEADER_LEN + origin.len(),
    );
    assert_eq!(
        DiameterRequestFailure::from_decode_error(
            &base_envelope,
            &request,
            &error,
            DecodeContext::conservative(),
            APP_DICTIONARIES,
            EncodeContext::default(),
        ),
        Err(DiameterFailureMappingError::CommandAvpRuleAbsent)
    );

    let swm_request = fixture(EXCESS_SINGLETON_REQUEST);
    let swm_envelope = envelope(&swm_request);
    let first_session_len =
        encode_avp(AvpHeader::ietf(AVP_SESSION_ID, true), b"sess;swm;001").len();
    let explicit_singleton = DecodeError::new(
        DecodeErrorCode::DuplicateIe,
        DIAMETER_HEADER_LEN + first_session_len,
    );
    assert!(DiameterRequestFailure::from_decode_error(
        &swm_envelope,
        &swm_request,
        &explicit_singleton,
        DecodeContext::conservative(),
        APP_DICTIONARIES,
        EncodeContext::default(),
    )
    .is_ok_and(|bound| matches!(bound.failure(), DiameterRequestFailure::ExcessSingleton(_))));
}

#[test]
fn classification_precedence_and_failure_binding_are_request_exact() {
    let unknown = encode_avp(AvpHeader::ietf(AvpCode::new(9_900), true), b"later");
    let error_offset = DIAMETER_HEADER_LEN;
    let decode_error = DecodeError::new(DecodeErrorCode::UnknownCriticalIe, error_offset);

    let e_request = encode_request(
        CommandFlags::from_bits(CommandFlags::REQUEST | CommandFlags::ERROR),
        COMMAND_DEVICE_WATCHDOG,
        APPLICATION_ID_COMMON_MESSAGES,
        &unknown,
    );
    let e_envelope = envelope(&e_request);
    let e_failure = DiameterRequestFailure::from_decode_error(
        &e_envelope,
        &e_request,
        &decode_error,
        DecodeContext::conservative(),
        APP_DICTIONARIES,
        EncodeContext::default(),
    )
    .expect("the earlier header failure must remain answerable");
    assert!(matches!(
        e_failure.failure(),
        DiameterRequestFailure::InvalidHeaderBits
    ));

    let p_request = encode_request(
        CommandFlags::request(true),
        COMMAND_DEVICE_WATCHDOG,
        APPLICATION_ID_COMMON_MESSAGES,
        &unknown,
    );
    let p_envelope = envelope(&p_request);
    let p_failure = DiameterRequestFailure::from_decode_error(
        &p_envelope,
        &p_request,
        &decode_error,
        DecodeContext::conservative(),
        APP_DICTIONARIES,
        EncodeContext::default(),
    )
    .expect("the earlier command P-bit failure must remain answerable");
    assert!(matches!(
        p_failure.failure(),
        DiameterRequestFailure::InvalidHeaderBits
    ));

    let wrong_m = encode_avp(AvpHeader::ietf(AVP_ORIGIN_HOST, false), b"peer.example");
    let mut avps = wrong_m.clone();
    avps.extend_from_slice(&unknown);
    let dictionary_request = encode_request(
        CommandFlags::request(false),
        COMMAND_DEVICE_WATCHDOG,
        APPLICATION_ID_COMMON_MESSAGES,
        &avps,
    );
    let dictionary_envelope = envelope(&dictionary_request);
    let later_error = DecodeError::new(
        DecodeErrorCode::UnknownCriticalIe,
        DIAMETER_HEADER_LEN + wrong_m.len(),
    );
    let selected = DiameterRequestFailure::from_decode_error(
        &dictionary_envelope,
        &dictionary_request,
        &later_error,
        DecodeContext::conservative(),
        APP_DICTIONARIES,
        EncodeContext::default(),
    )
    .expect("the earlier dictionary flag failure must be selected");
    assert!(matches!(
        selected.failure(),
        DiameterRequestFailure::InvalidAvpBits(_)
    ));

    let mut reverse_avps = unknown.clone();
    reverse_avps.extend_from_slice(&wrong_m);
    let reverse_request = encode_request(
        CommandFlags::request(false),
        COMMAND_DEVICE_WATCHDOG,
        APPLICATION_ID_COMMON_MESSAGES,
        &reverse_avps,
    );
    let reverse_envelope = envelope(&reverse_request);
    let reverse_selected = DiameterRequestFailure::from_decode_error(
        &reverse_envelope,
        &reverse_request,
        &decode_error,
        DecodeContext::conservative(),
        APP_DICTIONARIES,
        EncodeContext::default(),
    )
    .expect("the earlier decoder failure must beat a later dictionary failure");
    assert!(matches!(
        reverse_selected.failure(),
        DiameterRequestFailure::UnsupportedMandatoryAvp(_)
    ));

    let first_avp = encode_avp(
        AvpHeader::ietf(AVP_DISCONNECT_CAUSE, true),
        &0_u32.to_be_bytes(),
    );
    let second_avp = encode_avp(
        AvpHeader::ietf(AVP_DISCONNECT_CAUSE, true),
        &1_u32.to_be_bytes(),
    );
    let first_request = encode_request(
        CommandFlags::request(false),
        COMMAND_DISCONNECT_PEER,
        APPLICATION_ID_COMMON_MESSAGES,
        &first_avp,
    );
    let second_request = encode_request(
        CommandFlags::request(false),
        COMMAND_DISCONNECT_PEER,
        APPLICATION_ID_COMMON_MESSAGES,
        &second_avp,
    );
    let first_message = decode_message(&first_request);
    let (_, first_evidence) = find_avp_at(&first_message, AVP_DISCONNECT_CAUSE);
    let copied = DiameterFailedAvp::copied(
        &first_evidence,
        DIAMETER_HEADER_LEN,
        EncodeContext::default(),
    )
    .expect("source evidence must copy");
    let second_envelope = envelope(&second_request);
    assert_eq!(
        second_envelope.bind_application_failure(
            &second_request,
            DiameterRequestFailure::InvalidAvpValue(copied),
            APP_DICTIONARIES,
        ),
        Err(DiameterRequestClassificationError::FailureProvenanceMismatch)
    );

    let first_unknown = fixture(UNKNOWN_COMMAND_REQUEST);
    let mut second_unknown = first_unknown.clone();
    second_unknown[19] ^= 1;
    let first_envelope = envelope(&first_unknown);
    let second_envelope = envelope(&second_unknown);
    let token = first_envelope
        .classify(&first_unknown, APP_DICTIONARIES)
        .expect("classification must be unique")
        .expect("unknown command must classify");
    assert!(build_diameter_error_answer(
        &second_envelope,
        &token,
        &origin(),
        DiameterErrorAnswerGrammar::Application,
        EncodeContext::default(),
    )
    .is_err());
}

#[test]
fn decode_mapping_rejects_ambiguous_apps_but_accepts_duplicate_equal_metadata() {
    let unknown = encode_avp(AvpHeader::ietf(AvpCode::new(9_901), true), b"unknown");
    let request = encode_request(
        CommandFlags::request(false),
        COMMAND_DEVICE_WATCHDOG,
        APPLICATION_ID_COMMON_MESSAGES,
        &unknown,
    );
    let envelope = envelope(&request);
    let error = DecodeError::new(DecodeErrorCode::UnknownCriticalIe, DIAMETER_HEADER_LEN);
    assert_eq!(
        DiameterRequestFailure::from_decode_error(
            &envelope,
            &request,
            &error,
            DecodeContext::conservative(),
            AMBIGUOUS_APPLICATION_DICTIONARIES,
            EncodeContext::default(),
        ),
        Err(DiameterFailureMappingError::ApplicationAmbiguous)
    );
    assert!(DiameterRequestFailure::from_decode_error(
        &envelope,
        &request,
        &error,
        DecodeContext::conservative(),
        DUPLICATE_EQUAL_APPLICATION_DICTIONARIES,
        EncodeContext::default(),
    )
    .is_ok_and(|bound| matches!(
        bound.failure(),
        DiameterRequestFailure::UnsupportedMandatoryAvp(_)
    )));
}

#[test]
fn known_forbidden_unknown_mandatory_and_local_optional_are_distinct() {
    let request = fixture(FORBIDDEN_AVP_REQUEST);
    let swm_envelope = envelope(&request);
    let message = decode_message(&request);
    let parser_error = parse_swm_diameter_eap_request(&message, DecodeContext::conservative())
        .expect_err("Result-Code is forbidden in a SWm DER");
    let forbidden = DiameterRequestFailure::from_decode_error(
        &swm_envelope,
        &request,
        &parser_error,
        DecodeContext::conservative(),
        APP_DICTIONARIES,
        EncodeContext::default(),
    )
    .expect("the actual SWm parser failure must map");
    assert!(matches!(
        forbidden.failure(),
        DiameterRequestFailure::ForbiddenAvp(_)
    ));

    let known_but_unprofiled = encode_avp(
        AvpHeader::ietf(AVP_DESTINATION_REALM, true),
        b"example.test",
    );
    let dwr = encode_request(
        CommandFlags::request(false),
        COMMAND_DEVICE_WATCHDOG,
        APPLICATION_ID_COMMON_MESSAGES,
        &known_but_unprofiled,
    );
    let dwr_envelope = envelope(&dwr);
    let dwr_message = decode_message(&dwr);
    let dwr_error = parse_device_watchdog_request(&dwr_message, DecodeContext::conservative())
        .expect_err("the DWR parser must reject a non-grammar AVP under local Reject policy");
    assert_eq!(
        DiameterRequestFailure::from_decode_error(
            &dwr_envelope,
            &dwr,
            &dwr_error,
            DecodeContext::conservative(),
            APP_DICTIONARIES,
            EncodeContext::default(),
        ),
        Err(DiameterFailureMappingError::CommandAvpRuleAbsent)
    );
}

#[test]
fn dictionary_decode_and_mapping_reject_the_first_forbidden_occurrence() {
    let forbidden = encode_avp(
        AvpHeader::ietf(AVP_RESULT_CODE, true),
        &2_001_u32.to_be_bytes(),
    );
    for occurrence_count in [1, 2] {
        let mut raw = Vec::new();
        for _ in 0..occurrence_count {
            raw.extend_from_slice(&forbidden);
        }
        let request = encode_request(
            CommandFlags::request(true),
            swm::COMMAND_DIAMETER_EAP,
            swm::APPLICATION_ID,
            &raw,
        );
        let decode_error = Message::decode_with_dictionary(
            &request,
            DecodeContext::conservative(),
            APP_DICTIONARIES,
        )
        .expect_err("a forbidden Result-Code must fail dictionary-aware decode");
        assert_eq!(decode_error.code(), &DecodeErrorCode::UnknownCriticalIe);
        assert_eq!(decode_error.offset(), DIAMETER_HEADER_LEN);

        let request_envelope = envelope(&request);
        let mapped = DiameterRequestFailure::from_decode_error(
            &request_envelope,
            &request,
            &decode_error,
            DecodeContext::conservative(),
            APP_DICTIONARIES,
            EncodeContext::default(),
        )
        .expect("the first forbidden AVP must map to a request-bound failure");
        let DiameterRequestFailure::ForbiddenAvp(failed) = mapped.failure() else {
            panic!("forbidden Result-Code must map to 5008");
        };
        assert_eq!(failed.leaf_offset(), Some(DIAMETER_HEADER_LEN));
    }
}

#[test]
fn central_classification_selects_earlier_unknown_m_bit_but_ignores_optional_unknowns() {
    let unknown_code = AvpCode::new(19_998);
    let unknown_mandatory = encode_avp(AvpHeader::ietf(unknown_code, true), b"opaque");
    let unknown_optional = encode_avp(AvpHeader::ietf(unknown_code, false), b"opaque");
    let forbidden = encode_avp(
        AvpHeader::ietf(AVP_RESULT_CODE, true),
        &2_001_u32.to_be_bytes(),
    );

    let mut mandatory_raw = unknown_mandatory.clone();
    mandatory_raw.extend_from_slice(&forbidden);
    let mandatory_request = encode_request(
        CommandFlags::request(true),
        swm::COMMAND_DIAMETER_EAP,
        swm::APPLICATION_ID,
        &mandatory_raw,
    );
    let mandatory_failure = envelope(&mandatory_request)
        .classify(&mandatory_request, APP_DICTIONARIES)
        .expect("application dictionaries must be unique")
        .expect("unknown M-bit AVP must classify");
    let DiameterRequestFailure::UnsupportedMandatoryAvp(failed) = mandatory_failure.failure()
    else {
        panic!("earlier unknown M-bit AVP must preempt the later forbidden AVP");
    };
    assert_eq!(failed.leaf_code(), unknown_code);
    assert_eq!(failed.leaf_offset(), Some(DIAMETER_HEADER_LEN));

    let mut optional_raw = unknown_optional.clone();
    optional_raw.extend_from_slice(&forbidden);
    let optional_request = encode_request(
        CommandFlags::request(true),
        swm::COMMAND_DIAMETER_EAP,
        swm::APPLICATION_ID,
        &optional_raw,
    );
    let optional_failure = envelope(&optional_request)
        .classify(&optional_request, APP_DICTIONARIES)
        .expect("application dictionaries must be unique")
        .expect("later forbidden AVP must classify");
    let DiameterRequestFailure::ForbiddenAvp(failed) = optional_failure.failure() else {
        panic!("optional unknown AVP must not hide the later forbidden AVP");
    };
    assert_eq!(
        failed.leaf_offset(),
        Some(DIAMETER_HEADER_LEN + unknown_optional.len())
    );
}

#[test]
fn malformed_known_avps_use_unique_dictionary_minimum_shapes() {
    for value in [&[][..], &[0_u8; 8][..]] {
        let avp = encode_avp(AvpHeader::ietf(AVP_DISCONNECT_CAUSE, true), value);
        let request = encode_request(
            CommandFlags::request(false),
            COMMAND_DISCONNECT_PEER,
            APPLICATION_ID_COMMON_MESSAGES,
            &avp,
        );
        let envelope = envelope(&request);
        let message = decode_message(&request);
        let error = parse_disconnect_peer_request(&message, DecodeContext::conservative())
            .expect_err("short or overlong Disconnect-Cause must fail");
        let bound = DiameterRequestFailure::from_decode_error(
            &envelope,
            &request,
            &error,
            DecodeContext::conservative(),
            APP_DICTIONARIES,
            EncodeContext::default(),
        )
        .expect("known base fixed-width failure must map");
        let encoded = encode_plan(
            &request,
            &envelope,
            &bound,
            DiameterErrorAnswerGrammar::Application,
        );
        let answer = decode_message(&encoded);
        let failed_group = avps(&answer)
            .into_iter()
            .find(|avp| avp.header.code == AVP_FAILED_AVP)
            .expect("Failed-AVP must exist");
        let leaf = RawAvp::decode(failed_group.value, DecodeContext::default())
            .expect("base failed leaf must decode")
            .1;
        assert_eq!(leaf.header.code, AVP_DISCONNECT_CAUSE);
        assert_eq!(leaf.value, [0_u8; 4]);
    }

    for value in [&[][..], &[0_u8; 8][..]] {
        let avp = encode_avp(
            AvpHeader::vendor(swm::AVP_EMERGENCY_SERVICES, VENDOR_ID_3GPP, false),
            value,
        );
        let request = encode_request(
            CommandFlags::request(true),
            swm::COMMAND_DIAMETER_EAP,
            swm::APPLICATION_ID,
            &avp,
        );
        let envelope = envelope(&request);
        let message = decode_message(&request);
        let error = parse_swm_diameter_eap_request(&message, DecodeContext::conservative())
            .expect_err("short or overlong Emergency-Services must fail");
        let bound = DiameterRequestFailure::from_decode_error(
            &envelope,
            &request,
            &error,
            DecodeContext::conservative(),
            APP_DICTIONARIES,
            EncodeContext::default(),
        )
        .expect("known vendor fixed-width failure must map");
        let encoded = encode_plan(
            &request,
            &envelope,
            &bound,
            DiameterErrorAnswerGrammar::Application,
        );
        let answer = decode_message(&encoded);
        let failed_group = avps(&answer)
            .into_iter()
            .find(|avp| avp.header.code == AVP_FAILED_AVP)
            .expect("Failed-AVP must exist");
        let leaf = RawAvp::decode(failed_group.value, DecodeContext::default())
            .expect("vendor failed leaf must decode")
            .1;
        assert_eq!(leaf.header.code, swm::AVP_EMERGENCY_SERVICES);
        assert_eq!(leaf.header.vendor_id, Some(VENDOR_ID_3GPP));
        assert_eq!(leaf.value, [0_u8; 4]);
    }

    for (code, known_grouped) in [
        (AVP_VENDOR_SPECIFIC_APPLICATION_ID, true),
        (AvpCode::new(9_902), false),
    ] {
        let avp = encode_avp(AvpHeader::ietf(code, known_grouped), &[1, 2, 3, 4]);
        let request = encode_request(
            CommandFlags::request(false),
            COMMAND_DEVICE_WATCHDOG,
            APPLICATION_ID_COMMON_MESSAGES,
            &avp,
        );
        let envelope = envelope(&request);
        let error = DecodeError::new(
            DecodeErrorCode::InvalidLength {
                reason: "synthetic malformed grouped or unknown AVP",
            },
            DIAMETER_HEADER_LEN + AVP_HEADER_LEN,
        );
        let bound = DiameterRequestFailure::from_decode_error(
            &envelope,
            &request,
            &error,
            DecodeContext::conservative(),
            APP_DICTIONARIES,
            EncodeContext::default(),
        )
        .expect("grouped or unknown invalid-length failure must map");
        let DiameterRequestFailure::InvalidAvpLength(failed) = bound.failure() else {
            panic!("invalid length must remain selected");
        };
        assert_eq!(failed.retained_wire_len(), AVP_HEADER_LEN);
        assert_eq!(known_grouped, code == AVP_VENDOR_SPECIFIC_APPLICATION_ID);
    }

    let ambiguous = encode_avp(AvpHeader::ietf(AVP_ORIGIN_HOST, true), &[]);
    let ambiguous_request = encode_request(
        CommandFlags::request(false),
        COMMAND_DEVICE_WATCHDOG,
        APPLICATION_ID_COMMON_MESSAGES,
        &ambiguous,
    );
    let ambiguous_envelope = envelope(&ambiguous_request);
    let ambiguous_error = DecodeError::new(
        DecodeErrorCode::InvalidLength {
            reason: "synthetic ambiguous definition length",
        },
        DIAMETER_HEADER_LEN + AVP_HEADER_LEN,
    );
    assert_eq!(
        DiameterRequestFailure::from_decode_error(
            &ambiguous_envelope,
            &ambiguous_request,
            &ambiguous_error,
            DecodeContext::conservative(),
            AMBIGUOUS_AVP_DICTIONARIES,
            EncodeContext::default(),
        ),
        Err(DiameterFailureMappingError::AvpDefinitionAmbiguous)
    );
}

#[test]
fn failed_avp_synthesis_rejects_over_u24_lengths_before_allocation() {
    let unbounded = EncodeContext {
        max_message_len: usize::MAX,
        ..EncodeContext::default()
    };
    let missing = DiameterFailedAvp::missing(
        AvpHeader::ietf(AvpCode::new(9_003), true),
        opc_proto_diameter::MAX_U24 as usize,
        unbounded,
    )
    .expect_err("declared AVP length above U24 must fail before allocation");
    assert!(matches!(missing.code(), EncodeErrorCode::LengthOverflow));

    let malformed = DiameterFailedAvp::malformed(
        &[0, 0, 0, 1, AvpFlags::MANDATORY, 0, 0, 8],
        DIAMETER_HEADER_LEN,
        opc_proto_diameter::MAX_U24 as usize,
        unbounded,
    )
    .expect_err("malformed synthesis above U24 must fail before allocation");
    assert!(matches!(malformed.code(), EncodeErrorCode::LengthOverflow));
}

#[test]
fn actual_peer_request_parsers_map_every_required_omission_to_bound_5005() {
    let cer_fields = vec![
        encoded_field(AvpKey::ietf(AVP_ORIGIN_HOST), true, b"cer.peer.invalid"),
        encoded_field(AvpKey::ietf(AVP_ORIGIN_REALM), true, b"invalid"),
        encoded_field(
            AvpKey::ietf(AVP_HOST_IP_ADDRESS),
            true,
            &[0, 1, 192, 0, 2, 10],
        ),
        encoded_field(AvpKey::ietf(AVP_VENDOR_ID), true, &10_415_u32.to_be_bytes()),
        encoded_field(AvpKey::ietf(AVP_PRODUCT_NAME), false, b"opc-test"),
    ];
    for (missing, minimum_value_len, mandatory) in [
        (AvpKey::ietf(AVP_ORIGIN_HOST), 0, true),
        (AvpKey::ietf(AVP_ORIGIN_REALM), 0, true),
        (AvpKey::ietf(AVP_HOST_IP_ADDRESS), 6, true),
        (AvpKey::ietf(AVP_VENDOR_ID), 4, true),
        (AvpKey::ietf(AVP_PRODUCT_NAME), 0, false),
    ] {
        let request = encode_request(
            CommandFlags::request(false),
            COMMAND_CAPABILITIES_EXCHANGE,
            APPLICATION_ID_COMMON_MESSAGES,
            &fields_except(&cer_fields, missing),
        );
        assert_typed_missing_maps(
            &request,
            missing,
            minimum_value_len,
            mandatory,
            APP_DICTIONARIES,
            |message| {
                parse_capabilities_exchange_request_with_provenance(
                    message,
                    DecodeContext::conservative(),
                )
            },
        );
    }

    let dwr_fields = vec![
        encoded_field(AvpKey::ietf(AVP_ORIGIN_HOST), true, b"dwr.peer.invalid"),
        encoded_field(AvpKey::ietf(AVP_ORIGIN_REALM), true, b"invalid"),
    ];
    for missing in [
        AvpKey::ietf(AVP_ORIGIN_HOST),
        AvpKey::ietf(AVP_ORIGIN_REALM),
    ] {
        let request = encode_request(
            CommandFlags::request(false),
            COMMAND_DEVICE_WATCHDOG,
            APPLICATION_ID_COMMON_MESSAGES,
            &fields_except(&dwr_fields, missing),
        );
        assert_typed_missing_maps(&request, missing, 0, true, APP_DICTIONARIES, |message| {
            parse_device_watchdog_request_with_provenance(message, DecodeContext::conservative())
        });
    }

    let dpr_fields = vec![
        encoded_field(AvpKey::ietf(AVP_ORIGIN_HOST), true, b"dpr.peer.invalid"),
        encoded_field(AvpKey::ietf(AVP_ORIGIN_REALM), true, b"invalid"),
        encoded_field(
            AvpKey::ietf(AVP_DISCONNECT_CAUSE),
            true,
            &0_u32.to_be_bytes(),
        ),
    ];
    for (missing, minimum_value_len) in [
        (AvpKey::ietf(AVP_ORIGIN_HOST), 0),
        (AvpKey::ietf(AVP_ORIGIN_REALM), 0),
        (AvpKey::ietf(AVP_DISCONNECT_CAUSE), 4),
    ] {
        let request = encode_request(
            CommandFlags::request(false),
            COMMAND_DISCONNECT_PEER,
            APPLICATION_ID_COMMON_MESSAGES,
            &fields_except(&dpr_fields, missing),
        );
        assert_typed_missing_maps(
            &request,
            missing,
            minimum_value_len,
            true,
            APP_DICTIONARIES,
            |message| {
                parse_disconnect_peer_request_with_provenance(
                    message,
                    DecodeContext::conservative(),
                )
            },
        );
    }
}

#[test]
fn cer_vendor_application_missing_vendor_id_maps_nested_bound_5005() {
    let auth = encode_avp(
        AvpHeader::ietf(AVP_AUTH_APPLICATION_ID, true),
        &swm::APPLICATION_ID.get().to_be_bytes(),
    );
    let request = cer_request_with_vendor_application(&auth);
    let message = decode_message(&request);
    let error = parse_capabilities_exchange_request_with_provenance(
        &message,
        DecodeContext::conservative(),
    )
    .expect_err("VSAI without Vendor-Id must fail");
    let legacy = parse_capabilities_exchange_request(&message, DecodeContext::conservative())
        .expect_err("legacy CER parser must retain the same failure");
    assert_eq!(&legacy, error.decode_error());
    let provenance = error
        .missing_avp()
        .expect("missing nested Vendor-Id provenance must be sealed");
    assert_eq!(provenance.key(), AvpKey::ietf(AVP_VENDOR_ID));
    let parent = provenance.parent().expect("VSAI parent must be retained");
    assert_eq!(
        parent.key(),
        AvpKey::ietf(AVP_VENDOR_SPECIFIC_APPLICATION_ID)
    );
    assert_eq!(
        error.decode_error().offset(),
        parent.offset() + AVP_HEADER_LEN
    );

    let request_envelope = envelope(&request);
    let bound = DiameterRequestFailure::from_parser_error(
        &request_envelope,
        &request,
        &error,
        DecodeContext::conservative(),
        APP_DICTIONARIES,
        EncodeContext::default(),
    )
    .expect("sealed nested omission must bind");
    assert_eq!(bound.result_code(), RESULT_CODE_DIAMETER_MISSING_AVP);
    let answer = encode_plan(
        &request,
        &request_envelope,
        &bound,
        DiameterErrorAnswerGrammar::Application,
    );
    let failed_wire = failed_avp_inner_wire(&answer);
    let (remaining, outer) = RawAvp::decode(&failed_wire, DecodeContext::default())
        .expect("nested Failed-AVP must decode");
    assert!(remaining.is_empty());
    assert_eq!(
        outer.header.key(),
        AvpKey::ietf(AVP_VENDOR_SPECIFIC_APPLICATION_ID)
    );
    let children: Vec<_> = outer
        .grouped_avps(DecodeContext::default())
        .map(|child| child.expect("nested Failed-AVP child must decode"))
        .collect();
    assert_eq!(children.len(), 1);
    assert_eq!(children[0].header.key(), AvpKey::ietf(AVP_VENDOR_ID));
    assert_eq!(children[0].header.flags.bits(), AvpFlags::MANDATORY);
    assert_eq!(children[0].value, [0, 0, 0, 0]);
}

#[test]
fn cer_vendor_application_missing_one_of_reports_both_child_examples() {
    let vendor = encode_avp(
        AvpHeader::ietf(AVP_VENDOR_ID, true),
        &10_415_u32.to_be_bytes(),
    );
    let request = cer_request_with_vendor_application(&vendor);
    let message = decode_message(&request);
    let error = parse_capabilities_exchange_request_with_provenance(
        &message,
        DecodeContext::conservative(),
    )
    .expect_err("VSAI without an application child must fail");
    let grouped = error
        .grouped_avp_set_provenance()
        .expect("one-of failure must retain grouped-set provenance");
    assert_eq!(
        grouped.failure_kind(),
        DiameterGroupedAvpSetFailureKind::MissingOneOf
    );
    assert_eq!(
        grouped
            .definitions()
            .iter()
            .map(|definition| definition.key())
            .collect::<Vec<_>>(),
        [
            AvpKey::ietf(AVP_AUTH_APPLICATION_ID),
            AvpKey::ietf(AVP_ACCT_APPLICATION_ID),
        ]
    );
    let request_envelope = envelope(&request);
    let bounded = DiameterRequestFailure::from_parser_error(
        &request_envelope,
        &request,
        &error,
        DecodeContext::conservative(),
        APP_DICTIONARIES,
        EncodeContext {
            max_message_len: 24,
            ..EncodeContext::default()
        },
    );
    assert!(matches!(
        bounded,
        Err(DiameterFailureMappingError::FailedAvpEncoding(_))
    ));
    let bound = DiameterRequestFailure::from_parser_error(
        &request_envelope,
        &request,
        &error,
        DecodeContext::conservative(),
        APP_DICTIONARIES,
        EncodeContext::default(),
    )
    .expect("sealed one-of omission must bind");
    assert!(matches!(
        bound.failure(),
        DiameterRequestFailure::MissingMandatoryAvp(_)
    ));
    let answer = encode_plan(
        &request,
        &request_envelope,
        &bound,
        DiameterErrorAnswerGrammar::Application,
    );
    let failed_wire = failed_avp_inner_wire(&answer);
    let (remaining, outer) = RawAvp::decode(&failed_wire, DecodeContext::default())
        .expect("one-of Failed-AVP must decode");
    assert!(remaining.is_empty());
    let children: Vec<_> = outer
        .grouped_avps(DecodeContext::default())
        .map(|child| child.expect("one-of Failed-AVP child must decode"))
        .collect();
    assert_eq!(
        children
            .iter()
            .map(|child| child.header.key())
            .collect::<Vec<_>>(),
        [
            AvpKey::ietf(AVP_AUTH_APPLICATION_ID),
            AvpKey::ietf(AVP_ACCT_APPLICATION_ID),
        ]
    );
    assert!(children.iter().all(|child| child.value == [0, 0, 0, 0]));
    assert!(children
        .iter()
        .all(|child| child.header.flags.bits() == AvpFlags::MANDATORY));
}

#[test]
fn cer_vendor_application_conflict_reports_only_received_children_in_wire_order() {
    let unknown = encode_avp(
        AvpHeader::ietf(AvpCode::new(55_510), false),
        b"not-reflected",
    );
    let acct = encode_avp(
        AvpHeader::ietf(AVP_ACCT_APPLICATION_ID, true),
        &0x1122_3344_u32.to_be_bytes(),
    );
    let vendor = encode_avp(
        AvpHeader::ietf(AVP_VENDOR_ID, true),
        &10_415_u32.to_be_bytes(),
    );
    let auth = encode_avp(
        AvpHeader::ietf(AVP_AUTH_APPLICATION_ID, true),
        &0x5566_7788_u32.to_be_bytes(),
    );
    let ctx = DecodeContext {
        unknown_ie_policy: UnknownIePolicy::Preserve,
        ..DecodeContext::conservative()
    };
    let cases = [
        (
            vec![unknown.clone(), acct.clone(), vendor.clone(), auth.clone()],
            [
                (AVP_ACCT_APPLICATION_ID, 0x1122_3344_u32),
                (AVP_AUTH_APPLICATION_ID, 0x5566_7788_u32),
            ],
        ),
        (
            vec![vendor, auth, unknown, acct],
            [
                (AVP_AUTH_APPLICATION_ID, 0x5566_7788_u32),
                (AVP_ACCT_APPLICATION_ID, 0x1122_3344_u32),
            ],
        ),
    ];
    for (ordered_children, expected) in cases {
        let grouped_value: Vec<_> = ordered_children.into_iter().flatten().collect();
        let request = cer_request_with_vendor_application(&grouped_value);
        let message = decode_message(&request);
        let error = parse_capabilities_exchange_request_with_provenance(&message, ctx)
            .expect_err("VSAI carrying Auth and Acct children must fail");
        let legacy = parse_capabilities_exchange_request(&message, ctx)
            .expect_err("legacy CER parser must retain the same conflict failure");
        assert_eq!(&legacy, error.decode_error());
        assert_eq!(
            error
                .grouped_avp_set_provenance()
                .expect("mutual exclusion provenance must be sealed")
                .failure_kind(),
            DiameterGroupedAvpSetFailureKind::MutuallyExclusivePresent
        );
        let request_envelope = envelope(&request);
        let bound = DiameterRequestFailure::from_parser_error(
            &request_envelope,
            &request,
            &error,
            ctx,
            APP_DICTIONARIES,
            EncodeContext::default(),
        )
        .expect("sealed mutual-exclusion failure must bind");
        assert!(matches!(
            bound.failure(),
            DiameterRequestFailure::MutuallyExclusiveAvps(_)
        ));
        assert_eq!(
            bound.result_code(),
            RESULT_CODE_DIAMETER_AVP_OCCURS_TOO_MANY_TIMES
        );
        let answer = encode_plan(
            &request,
            &request_envelope,
            &bound,
            DiameterErrorAnswerGrammar::Application,
        );
        let failed_wire = failed_avp_inner_wire(&answer);
        let (remaining, outer) = RawAvp::decode(&failed_wire, DecodeContext::default())
            .expect("conflict Failed-AVP must decode");
        assert!(remaining.is_empty());
        assert_eq!(
            outer.header.key(),
            AvpKey::ietf(AVP_VENDOR_SPECIFIC_APPLICATION_ID)
        );
        assert_eq!(outer.header.flags.bits(), AvpFlags::MANDATORY);
        let children: Vec<_> = outer
            .grouped_avps(DecodeContext::default())
            .map(|child| child.expect("conflict Failed-AVP child must decode"))
            .collect();
        assert_eq!(children.len(), 2);
        for (child, (expected_code, expected_value)) in children.iter().zip(expected) {
            assert_eq!(child.header.key(), AvpKey::ietf(expected_code));
            assert_eq!(child.header.flags.bits(), AvpFlags::MANDATORY);
            assert_eq!(child.value, expected_value.to_be_bytes());
        }
        let diagnostics = format!("{error:?} {bound:?}");
        assert!(!diagnostics.contains("287454020"));
        assert!(!diagnostics.contains("1432778632"));
        assert!(!diagnostics.contains("not-reflected"));
    }
}

#[test]
fn cer_vendor_application_individual_duplicate_remains_ordinary_5009() {
    let vendor = encode_avp(
        AvpHeader::ietf(AVP_VENDOR_ID, true),
        &10_415_u32.to_be_bytes(),
    );
    for duplicate_code in [AVP_AUTH_APPLICATION_ID, AVP_ACCT_APPLICATION_ID] {
        let application = encode_avp(
            AvpHeader::ietf(duplicate_code, true),
            &swm::APPLICATION_ID.get().to_be_bytes(),
        );
        let grouped_value: Vec<_> = [vendor.clone(), application.clone(), application]
            .into_iter()
            .flatten()
            .collect();
        let request = cer_request_with_vendor_application(&grouped_value);
        let message = decode_message(&request);
        let error = parse_capabilities_exchange_request_with_provenance(
            &message,
            DecodeContext::conservative(),
        )
        .expect_err("duplicate individual application child must fail");
        assert!(error.grouped_avp_set_provenance().is_none());
        assert!(error.missing_avp().is_none());
        let bound = DiameterRequestFailure::from_parser_error(
            &envelope(&request),
            &request,
            &error,
            DecodeContext::conservative(),
            APP_DICTIONARIES,
            EncodeContext::default(),
        )
        .expect("grouped singleton classification must precede generic parser mapping");
        assert!(matches!(
            bound.failure(),
            DiameterRequestFailure::ExcessSingleton(_)
        ));
    }
}

#[test]
fn earlier_nested_vendor_application_failures_precede_cross_field_semantics() {
    let vendor = encode_avp(
        AvpHeader::ietf(AVP_VENDOR_ID, true),
        &10_415_u32.to_be_bytes(),
    );
    let auth = encode_avp(
        AvpHeader::ietf(AVP_AUTH_APPLICATION_ID, true),
        &swm::APPLICATION_ID.get().to_be_bytes(),
    );
    let acct = encode_avp(
        AvpHeader::ietf(AVP_ACCT_APPLICATION_ID, true),
        &3_u32.to_be_bytes(),
    );
    let unknown_m = encode_avp(AvpHeader::ietf(AvpCode::new(55_511), true), b"opaque");
    let invalid_vendor_flags = encode_avp(
        AvpHeader::ietf(AVP_VENDOR_ID, false),
        &10_415_u32.to_be_bytes(),
    );
    let cases = [
        (
            [unknown_m, vendor.clone(), auth.clone(), acct.clone()]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>(),
            RESULT_CODE_DIAMETER_AVP_UNSUPPORTED,
        ),
        (
            [invalid_vendor_flags, auth.clone(), acct.clone()]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>(),
            RESULT_CODE_DIAMETER_INVALID_AVP_BITS,
        ),
        (
            [
                vec![0, 0, 0, 1, AvpFlags::MANDATORY, 0, 0, 7],
                vendor,
                auth,
                acct,
            ]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>(),
            RESULT_CODE_DIAMETER_INVALID_AVP_LENGTH,
        ),
    ];
    for (grouped_value, expected_result) in cases {
        let request = cer_request_with_vendor_application(&grouped_value);
        let message = decode_message(&request);
        let error = parse_capabilities_exchange_request_with_provenance(
            &message,
            DecodeContext::conservative(),
        )
        .expect_err("earlier nested failure must stop VSAI parsing");
        assert!(error.grouped_avp_set_provenance().is_none());
        let bound = DiameterRequestFailure::from_parser_error(
            &envelope(&request),
            &request,
            &error,
            DecodeContext::conservative(),
            APP_DICTIONARIES,
            EncodeContext::default(),
        )
        .expect("earlier nested failure must classify before cross-field semantics");
        assert_eq!(bound.result_code(), expected_result);
    }
}

#[test]
fn cer_vsai_malformed_known_child_uses_dictionary_minimum_and_fails_ambiguity() {
    let malformed_vendor_id = [
        0,
        0,
        1,
        10,
        AvpFlags::MANDATORY,
        0,
        0,
        (AVP_HEADER_LEN - 1) as u8,
    ];
    let request = cer_request_with_vendor_application(&malformed_vendor_id);
    let message = decode_message(&request);
    let error = parse_capabilities_exchange_request_with_provenance(
        &message,
        DecodeContext::conservative(),
    )
    .expect_err("short Vendor-Id child must fail CER parsing");
    assert!(error.missing_avp().is_none());
    assert!(error.grouped_avp_set_provenance().is_none());

    let request_envelope = envelope(&request);
    let bound = DiameterRequestFailure::from_parser_error(
        &request_envelope,
        &request,
        &error,
        DecodeContext::conservative(),
        APP_DICTIONARIES,
        EncodeContext::default(),
    )
    .expect("known malformed grouped child must map using its dictionary definition");
    assert!(matches!(
        bound.failure(),
        DiameterRequestFailure::InvalidAvpLength(_)
    ));
    assert_eq!(bound.result_code(), RESULT_CODE_DIAMETER_INVALID_AVP_LENGTH);

    let answer = encode_plan(
        &request,
        &request_envelope,
        &bound,
        DiameterErrorAnswerGrammar::Application,
    );
    let failed_wire = failed_avp_inner_wire(&answer);
    let (remaining, outer) = RawAvp::decode(&failed_wire, DecodeContext::default())
        .expect("grouped Failed-AVP must decode");
    assert!(remaining.is_empty());
    assert_eq!(
        outer.header.key(),
        AvpKey::ietf(AVP_VENDOR_SPECIFIC_APPLICATION_ID)
    );
    assert_eq!(outer.header.flags.bits(), AvpFlags::MANDATORY);
    let children: Vec<_> = outer
        .grouped_avps(DecodeContext::default())
        .map(|child| child.expect("nested Failed-AVP child must decode"))
        .collect();
    assert_eq!(children.len(), 1);
    assert_eq!(children[0].header.key(), AvpKey::ietf(AVP_VENDOR_ID));
    assert_eq!(children[0].header.flags.bits(), AvpFlags::MANDATORY);
    assert_eq!(children[0].value, [0, 0, 0, 0]);

    assert_eq!(
        DiameterRequestFailure::from_parser_error(
            &request_envelope,
            &request,
            &error,
            DecodeContext::conservative(),
            AMBIGUOUS_NESTED_VENDOR_ID_DICTIONARIES,
            EncodeContext::default(),
        ),
        Err(DiameterFailureMappingError::AvpDefinitionAmbiguous)
    );
}

#[test]
fn actual_swm_der_parser_maps_every_required_omission_to_bound_5005() {
    let fields = vec![
        encoded_field(AvpKey::ietf(AVP_SESSION_ID), true, b"session;redacted"),
        encoded_field(
            AvpKey::ietf(AVP_AUTH_APPLICATION_ID),
            true,
            &swm::APPLICATION_ID.get().to_be_bytes(),
        ),
        encoded_field(AvpKey::ietf(AVP_ORIGIN_HOST), true, b"epdg.invalid"),
        encoded_field(AvpKey::ietf(AVP_ORIGIN_REALM), true, b"visited.invalid"),
        encoded_field(AvpKey::ietf(AVP_DESTINATION_REALM), true, b"home.invalid"),
        encoded_field(
            AvpKey::ietf(swm::AVP_AUTH_REQUEST_TYPE),
            true,
            &swm::AUTH_REQUEST_TYPE_AUTHORIZE_AUTHENTICATE.to_be_bytes(),
        ),
        encoded_field(
            AvpKey::ietf(swm::AVP_EAP_PAYLOAD),
            true,
            &[2, 7, 0, 8, 1, 2, 3, 4],
        ),
    ];
    for (missing, minimum_value_len) in [
        (AvpKey::ietf(AVP_SESSION_ID), 0),
        (AvpKey::ietf(AVP_AUTH_APPLICATION_ID), 4),
        (AvpKey::ietf(AVP_ORIGIN_HOST), 0),
        (AvpKey::ietf(AVP_ORIGIN_REALM), 0),
        (AvpKey::ietf(AVP_DESTINATION_REALM), 0),
        (AvpKey::ietf(swm::AVP_AUTH_REQUEST_TYPE), 4),
        (AvpKey::ietf(swm::AVP_EAP_PAYLOAD), 0),
    ] {
        let request = encode_request(
            CommandFlags::request(true),
            swm::COMMAND_DIAMETER_EAP,
            swm::APPLICATION_ID,
            &fields_except(&fields, missing),
        );
        assert_typed_missing_maps(
            &request,
            missing,
            minimum_value_len,
            true,
            APP_DICTIONARIES,
            |message| {
                parse_swm_diameter_eap_request_with_provenance(
                    message,
                    DecodeContext::conservative(),
                )
            },
        );
    }
}

#[test]
fn swm_terminal_information_missing_imei_maps_nested_bound_5005() {
    let software = encode_avp(
        AvpHeader::vendor(swm::AVP_SOFTWARE_VERSION, VENDOR_ID_3GPP, true),
        b"99",
    );
    let terminal = encode_avp(
        AvpHeader::vendor(swm::AVP_TERMINAL_INFORMATION, VENDOR_ID_3GPP, true),
        &software,
    );
    let mut fields = valid_swm_der_fields();
    fields.push(terminal);
    let raw: Vec<_> = fields.into_iter().flatten().collect();
    let request = encode_request(
        CommandFlags::request(true),
        swm::COMMAND_DIAMETER_EAP,
        swm::APPLICATION_ID,
        &raw,
    );
    let message = decode_message(&request);
    let error =
        parse_swm_diameter_eap_request_with_provenance(&message, DecodeContext::conservative())
            .expect_err("Terminal-Information without IMEI must fail");
    let legacy = parse_swm_diameter_eap_request(&message, DecodeContext::conservative())
        .expect_err("legacy SWm parser must retain the same nested failure");
    assert_eq!(&legacy, error.decode_error());
    let provenance = error
        .missing_avp()
        .expect("missing IMEI provenance must be sealed");
    assert_eq!(
        provenance.key(),
        AvpKey::vendor(swm::AVP_IMEI, VENDOR_ID_3GPP)
    );
    let parent = provenance
        .parent()
        .expect("Terminal-Information parent must be retained");
    assert_eq!(
        parent.key(),
        AvpKey::vendor(swm::AVP_TERMINAL_INFORMATION, VENDOR_ID_3GPP)
    );
    let request_envelope = envelope(&request);
    let bound = DiameterRequestFailure::from_parser_error(
        &request_envelope,
        &request,
        &error,
        DecodeContext::conservative(),
        APP_DICTIONARIES,
        EncodeContext::default(),
    )
    .expect("sealed missing IMEI must bind");
    assert_eq!(bound.result_code(), RESULT_CODE_DIAMETER_MISSING_AVP);
    let answer = encode_plan(
        &request,
        &request_envelope,
        &bound,
        DiameterErrorAnswerGrammar::Application,
    );
    let failed_wire = failed_avp_inner_wire(&answer);
    let (remaining, outer) = RawAvp::decode(&failed_wire, DecodeContext::default())
        .expect("Terminal-Information Failed-AVP must decode");
    assert!(remaining.is_empty());
    assert_eq!(outer.header.key(), parent.key());
    assert_eq!(
        outer.header.flags.bits(),
        AvpFlags::VENDOR | AvpFlags::MANDATORY
    );
    let children: Vec<_> = outer
        .grouped_avps(DecodeContext::default())
        .map(|child| child.expect("Terminal-Information Failed-AVP child must decode"))
        .collect();
    assert_eq!(children.len(), 1);
    assert_eq!(children[0].header.key(), provenance.key());
    assert_eq!(
        children[0].header.flags.bits(),
        AvpFlags::VENDOR | AvpFlags::MANDATORY
    );
    assert!(children[0].value.is_empty());

    let mut different = request.clone();
    let software_position = different
        .windows(2)
        .position(|window| window == b"99")
        .expect("synthetic software version must be present");
    different[software_position] = b'8';
    assert_eq!(
        DiameterRequestFailure::from_parser_error(
            &envelope(&different),
            &different,
            &error,
            DecodeContext::conservative(),
            APP_DICTIONARIES,
            EncodeContext::default(),
        ),
        Err(DiameterFailureMappingError::ParserRequestMismatch)
    );
}

#[test]
fn empty_request_provenance_preserves_existing_required_field_order() {
    let cases = [
        (
            COMMAND_CAPABILITIES_EXCHANGE,
            APPLICATION_ID_COMMON_MESSAGES,
            false,
            AvpKey::ietf(AVP_HOST_IP_ADDRESS),
        ),
        (
            COMMAND_DEVICE_WATCHDOG,
            APPLICATION_ID_COMMON_MESSAGES,
            false,
            AvpKey::ietf(AVP_ORIGIN_HOST),
        ),
        (
            COMMAND_DISCONNECT_PEER,
            APPLICATION_ID_COMMON_MESSAGES,
            false,
            AvpKey::ietf(AVP_DISCONNECT_CAUSE),
        ),
        (
            swm::COMMAND_DIAMETER_EAP,
            swm::APPLICATION_ID,
            true,
            AvpKey::ietf(AVP_AUTH_APPLICATION_ID),
        ),
    ];
    for (command, application, proxiable, expected) in cases {
        let request = encode_request(CommandFlags::request(proxiable), command, application, &[]);
        let message = decode_message(&request);
        let error = if command == COMMAND_CAPABILITIES_EXCHANGE {
            parse_capabilities_exchange_request_with_provenance(
                &message,
                DecodeContext::conservative(),
            )
            .expect_err("empty CER must fail")
        } else if command == COMMAND_DEVICE_WATCHDOG {
            parse_device_watchdog_request_with_provenance(&message, DecodeContext::conservative())
                .expect_err("empty DWR must fail")
        } else if command == COMMAND_DISCONNECT_PEER {
            parse_disconnect_peer_request_with_provenance(&message, DecodeContext::conservative())
                .expect_err("empty DPR must fail")
        } else {
            parse_swm_diameter_eap_request_with_provenance(&message, DecodeContext::conservative())
                .expect_err("empty DER must fail")
        };
        assert_eq!(
            error
                .missing_avp()
                .expect("empty request must retain missing provenance")
                .key(),
            expected
        );
    }
}

#[test]
fn parser_provenance_is_request_bound_and_dictionary_resolution_fails_closed() {
    let request = encode_request(
        CommandFlags::request(false),
        COMMAND_DEVICE_WATCHDOG,
        APPLICATION_ID_COMMON_MESSAGES,
        &[],
    );
    let message = decode_message(&request);
    let parser_error =
        parse_device_watchdog_request_with_provenance(&message, DecodeContext::conservative())
            .expect_err("empty DWR must miss Origin-Host");
    let legacy = parse_device_watchdog_request(&message, DecodeContext::conservative())
        .expect_err("legacy empty DWR parse must fail");
    assert_eq!(&legacy, parser_error.decode_error());

    let mut different_request = request.clone();
    different_request[12] ^= 0x01;
    let different_envelope = envelope(&different_request);
    assert_eq!(
        DiameterRequestFailure::from_parser_error(
            &different_envelope,
            &different_request,
            &parser_error,
            DecodeContext::conservative(),
            APP_DICTIONARIES,
            EncodeContext::default(),
        ),
        Err(DiameterFailureMappingError::ParserRequestMismatch)
    );

    let request_envelope = envelope(&request);
    assert_eq!(
        DiameterRequestFailure::from_parser_error(
            &request_envelope,
            &request,
            &parser_error,
            DecodeContext::conservative(),
            MISSING_AVP_DICTIONARIES,
            EncodeContext::default(),
        ),
        Err(DiameterFailureMappingError::MissingAvpDefinitionMissing)
    );
    assert_eq!(
        DiameterRequestFailure::from_parser_error(
            &request_envelope,
            &request,
            &parser_error,
            DecodeContext::conservative(),
            AMBIGUOUS_AVP_DICTIONARIES,
            EncodeContext::default(),
        ),
        Err(DiameterFailureMappingError::AvpDefinitionAmbiguous)
    );
    assert_eq!(
        DiameterRequestFailure::from_parser_error(
            &request_envelope,
            &request,
            &parser_error,
            DecodeContext::conservative(),
            SCHEMA_MISMATCH_DICTIONARIES,
            EncodeContext::default(),
        ),
        Err(DiameterFailureMappingError::MissingAvpDefinitionMismatch)
    );

    assert_eq!(
        DiameterRequestFailure::from_decode_error(
            &request_envelope,
            &request,
            parser_error.decode_error(),
            DecodeContext::conservative(),
            APP_DICTIONARIES,
            EncodeContext::default(),
        ),
        Err(DiameterFailureMappingError::OffsetAmbiguous)
    );
}

#[test]
fn nonmissing_typed_errors_delegate_and_earlier_request_failures_win() {
    let invalid_cause = encode_avp(
        AvpHeader::ietf(AVP_DISCONNECT_CAUSE, true),
        &99_u32.to_be_bytes(),
    );
    let mut dpr_avps = encode_avp(AvpHeader::ietf(AVP_ORIGIN_HOST, true), b"peer.invalid");
    dpr_avps.extend_from_slice(&encode_avp(
        AvpHeader::ietf(AVP_ORIGIN_REALM, true),
        b"invalid",
    ));
    dpr_avps.extend_from_slice(&invalid_cause);
    let dpr = encode_request(
        CommandFlags::request(false),
        COMMAND_DISCONNECT_PEER,
        APPLICATION_ID_COMMON_MESSAGES,
        &dpr_avps,
    );
    let dpr_message = decode_message(&dpr);
    let dpr_error =
        parse_disconnect_peer_request_with_provenance(&dpr_message, DecodeContext::conservative())
            .expect_err("invalid Disconnect-Cause must fail");
    assert!(dpr_error.missing_avp().is_none());
    let dpr_bound = DiameterRequestFailure::from_parser_error(
        &envelope(&dpr),
        &dpr,
        &dpr_error,
        DecodeContext::conservative(),
        APP_DICTIONARIES,
        EncodeContext::default(),
    )
    .expect("ordinary parser error must delegate to generic mapping");
    assert_eq!(
        dpr_bound.result_code(),
        RESULT_CODE_DIAMETER_INVALID_AVP_VALUE
    );

    let invalid_p_bit = encode_request(
        CommandFlags::request(true),
        COMMAND_DEVICE_WATCHDOG,
        APPLICATION_ID_COMMON_MESSAGES,
        &[],
    );
    let p_message = decode_message(&invalid_p_bit);
    let p_error =
        parse_device_watchdog_request_with_provenance(&p_message, DecodeContext::conservative())
            .expect_err("DWR P-bit mismatch must fail before missing fields");
    let p_bound = DiameterRequestFailure::from_parser_error(
        &envelope(&invalid_p_bit),
        &invalid_p_bit,
        &p_error,
        DecodeContext::conservative(),
        APP_DICTIONARIES,
        EncodeContext::default(),
    )
    .expect("header classification must win");
    assert_eq!(p_bound.result_code(), RESULT_CODE_DIAMETER_INVALID_HDR_BITS);

    let unknown_code = AvpCode::new(55_001);
    let unknown = encode_avp(AvpHeader::ietf(unknown_code, true), b"opaque");
    let unknown_request = encode_request(
        CommandFlags::request(false),
        COMMAND_DEVICE_WATCHDOG,
        APPLICATION_ID_COMMON_MESSAGES,
        &unknown,
    );
    let unknown_message = decode_message(&unknown_request);
    let unknown_error = parse_device_watchdog_request_with_provenance(
        &unknown_message,
        DecodeContext::conservative(),
    )
    .expect_err("unknown M-bit AVP must fail");
    let unknown_bound = DiameterRequestFailure::from_parser_error(
        &envelope(&unknown_request),
        &unknown_request,
        &unknown_error,
        DecodeContext::conservative(),
        APP_DICTIONARIES,
        EncodeContext::default(),
    )
    .expect("unknown mandatory classification must win");
    let DiameterRequestFailure::UnsupportedMandatoryAvp(failed) = unknown_bound.failure() else {
        panic!("unknown mandatory AVP must map to 5001");
    };
    assert_eq!(failed.leaf_code(), unknown_code);

    let forbidden = encode_avp(
        AvpHeader::ietf(AVP_RESULT_CODE, true),
        &2_001_u32.to_be_bytes(),
    );
    let forbidden_request = encode_request(
        CommandFlags::request(true),
        swm::COMMAND_DIAMETER_EAP,
        swm::APPLICATION_ID,
        &forbidden,
    );
    let forbidden_message = decode_message(&forbidden_request);
    let forbidden_error = parse_swm_diameter_eap_request_with_provenance(
        &forbidden_message,
        DecodeContext::conservative(),
    )
    .expect_err("forbidden Result-Code must fail before missing fields");
    let forbidden_bound = DiameterRequestFailure::from_parser_error(
        &envelope(&forbidden_request),
        &forbidden_request,
        &forbidden_error,
        DecodeContext::conservative(),
        APP_DICTIONARIES,
        EncodeContext::default(),
    )
    .expect("forbidden classification must win");
    assert_eq!(
        forbidden_bound.result_code(),
        RESULT_CODE_DIAMETER_AVP_NOT_ALLOWED
    );

    let session = encode_avp(AvpHeader::ietf(AVP_SESSION_ID, true), b"first");
    let mut duplicate_sessions = session.clone();
    duplicate_sessions.extend_from_slice(&session);
    let duplicate_request = encode_request(
        CommandFlags::request(true),
        swm::COMMAND_DIAMETER_EAP,
        swm::APPLICATION_ID,
        &duplicate_sessions,
    );
    let duplicate_message = decode_message(&duplicate_request);
    let duplicate_error = parse_swm_diameter_eap_request_with_provenance(
        &duplicate_message,
        DecodeContext::conservative(),
    )
    .expect_err("duplicate singleton must fail before later missing fields");
    let duplicate_bound = DiameterRequestFailure::from_parser_error(
        &envelope(&duplicate_request),
        &duplicate_request,
        &duplicate_error,
        DecodeContext::conservative(),
        APP_DICTIONARIES,
        EncodeContext::default(),
    )
    .expect("excess singleton classification must win");
    assert_eq!(
        duplicate_bound.result_code(),
        RESULT_CODE_DIAMETER_AVP_OCCURS_TOO_MANY_TIMES
    );

    let malformed_avp = [0, 0, 1, 8, AvpFlags::MANDATORY, 0, 0, 12];
    let malformed_request = encode_request(
        CommandFlags::request(false),
        COMMAND_DEVICE_WATCHDOG,
        APPLICATION_ID_COMMON_MESSAGES,
        &malformed_avp,
    );
    let (_, malformed_message) = Message::decode(
        &malformed_request,
        DecodeContext {
            validation_level: ValidationLevel::HeaderOnly,
            ..DecodeContext::conservative()
        },
    )
    .expect("header-only decode must preserve malformed AVP bytes");
    let malformed_error = parse_device_watchdog_request_with_provenance(
        &malformed_message,
        DecodeContext::conservative(),
    )
    .expect_err("malformed AVP framing must fail");
    let malformed_bound = DiameterRequestFailure::from_parser_error(
        &envelope(&malformed_request),
        &malformed_request,
        &malformed_error,
        DecodeContext::conservative(),
        APP_DICTIONARIES,
        EncodeContext::default(),
    )
    .expect("inspection framing failure must win");
    assert_eq!(
        malformed_bound.result_code(),
        RESULT_CODE_DIAMETER_INVALID_AVP_LENGTH
    );
}

#[test]
fn parser_error_diagnostics_never_expose_request_values() {
    let fields = [
        encoded_field(
            AvpKey::ietf(AVP_AUTH_APPLICATION_ID),
            true,
            &swm::APPLICATION_ID.get().to_be_bytes(),
        ),
        encoded_field(AvpKey::ietf(AVP_SESSION_ID), true, b"SESSION-ID-DO-NOT-LOG"),
        encoded_field(AvpKey::ietf(AVP_ORIGIN_HOST), true, b"IDENTITY-DO-NOT-LOG"),
        encoded_field(AvpKey::ietf(AVP_ORIGIN_REALM), true, b"realm.invalid"),
        encoded_field(
            AvpKey::ietf(AVP_DESTINATION_REALM),
            true,
            b"destination.invalid",
        ),
        encoded_field(
            AvpKey::ietf(swm::AVP_AUTH_REQUEST_TYPE),
            true,
            &swm::AUTH_REQUEST_TYPE_AUTHORIZE_AUTHENTICATE.to_be_bytes(),
        ),
    ];
    let raw: Vec<u8> = fields
        .iter()
        .flat_map(|(_, wire)| wire.iter().copied())
        .collect();
    let request = encode_request(
        CommandFlags::request(true),
        swm::COMMAND_DIAMETER_EAP,
        swm::APPLICATION_ID,
        &raw,
    );
    let message = decode_message(&request);
    let error =
        parse_swm_diameter_eap_request_with_provenance(&message, DecodeContext::conservative())
            .expect_err("request intentionally omits EAP-Payload");
    let diagnostics = format!("{error:?} {error}");
    for sensitive in [
        "SESSION-ID-DO-NOT-LOG",
        "IDENTITY-DO-NOT-LOG",
        "realm.invalid",
        "destination.invalid",
    ] {
        assert!(!diagnostics.contains(sensitive));
    }
    assert!(diagnostics.contains("<redacted>"));
    assert!(!diagnostics.contains("[2, 7"));
}
