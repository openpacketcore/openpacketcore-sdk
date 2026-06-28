use bytes::BytesMut;
use opc_proto_gtpv2c::{
    decode_typed_ie_sequence, s2b, CauseValue, FullyQualifiedTeid, Message, MessageType,
    S2bMessage, TbcdDigits, TypedIe, TypedIeValue, IE_TYPE_APCO, IE_TYPE_BEARER_CONTEXT,
    IE_TYPE_BEARER_QOS, IE_TYPE_CAUSE, IE_TYPE_CHARGING_ID, IE_TYPE_EBI, IE_TYPE_F_TEID,
    IE_TYPE_IMSI, IE_TYPE_INDICATION, IE_TYPE_PCO, IE_TYPE_RECOVERY,
};
use opc_protocol::{
    BorrowDecode, DecodeContext, DecodeErrorCode, DuplicateIePolicy, Encode, EncodeContext,
    EncodeErrorCode, ValidationLevel,
};

fn procedure_context() -> DecodeContext {
    DecodeContext {
        validation_level: ValidationLevel::ProcedureAware,
        ..DecodeContext::default()
    }
}

// Spec-authored fixtures live under tests/fixtures/spec with octet-level
// provenance comments in tests/fixtures/README.md.
const ECHO_REQUEST_FIXTURE: &[u8] = include_bytes!("fixtures/spec/echo_request_recovery.bin");
const ECHO_RESPONSE_FIXTURE: &[u8] = include_bytes!("fixtures/spec/echo_response_recovery.bin");
const CREATE_SESSION_REQUEST_FIXTURE: &[u8] =
    include_bytes!("fixtures/spec/create_session_request_s2b_subset.bin");
const CREATE_SESSION_RESPONSE_FIXTURE: &[u8] =
    include_bytes!("fixtures/spec/create_session_response_s2b_subset.bin");
const MODIFY_BEARER_REQUEST_FIXTURE: &[u8] =
    include_bytes!("fixtures/spec/modify_bearer_request_bearer_context.bin");
const MODIFY_BEARER_RESPONSE_FIXTURE: &[u8] =
    include_bytes!("fixtures/spec/modify_bearer_response_cause.bin");
const DELETE_SESSION_REQUEST_FIXTURE: &[u8] =
    include_bytes!("fixtures/spec/delete_session_request_linked_ebi.bin");
const DELETE_SESSION_RESPONSE_FIXTURE: &[u8] =
    include_bytes!("fixtures/spec/delete_session_response_cause.bin");
const UPDATE_BEARER_REQUEST_FIXTURE: &[u8] =
    include_bytes!("fixtures/spec/update_bearer_request_bearer_context.bin");
const UPDATE_BEARER_RESPONSE_FIXTURE: &[u8] =
    include_bytes!("fixtures/spec/update_bearer_response_cause.bin");

const BEARER_CONTEXT_IE: &[u8] = &[
    0x5d, 0x00, 0x05, 0x00, // Bearer Context grouped IE header.
    0x49, 0x00, 0x01, 0x00, 0x05, // Nested EBI = 5.
];

const CAUSE_IE: &[u8] = &[0x02, 0x00, 0x02, 0x00, 0x10, 0x00];
const EBI_IE: &[u8] = &[0x49, 0x00, 0x01, 0x00, 0x05];

fn decode_s2b(bytes: &[u8]) -> S2bMessage<'_> {
    match S2bMessage::decode(bytes, procedure_context()) {
        Ok((tail, message)) => {
            assert!(tail.is_empty());
            message
        }
        Err(error) => panic!("S2b decode failed: {error:?}"),
    }
}

fn encode_s2b(message: &S2bMessage<'_>, ctx: EncodeContext) -> BytesMut {
    let mut encoded = BytesMut::new();
    match message.encode(&mut encoded, ctx) {
        Ok(()) => encoded,
        Err(error) => panic!("S2b encode failed: {error:?}"),
    }
}

fn procedure_view<'m, 'a>(
    message: &'m S2bMessage<'a>,
) -> &'m opc_proto_gtpv2c::S2bProcedureMessage<'a> {
    match message.as_view() {
        Some(view) => view,
        None => panic!("expected typed S2b view"),
    }
}

fn find_ie<'m, 'a>(ies: &'m [TypedIe<'a>], ie_type: u8) -> &'m TypedIe<'a> {
    for ie in ies {
        if ie.ie_type() == ie_type {
            return ie;
        }
    }
    panic!("missing IE type {ie_type}");
}

#[test]
fn s2b_echo_create_modify_delete_update_fixtures_roundtrip() {
    let cases: &[(&[u8], u8)] = &[
        (ECHO_REQUEST_FIXTURE, s2b::ECHO_REQUEST),
        (ECHO_RESPONSE_FIXTURE, s2b::ECHO_RESPONSE),
        (CREATE_SESSION_REQUEST_FIXTURE, s2b::CREATE_SESSION_REQUEST),
        (
            CREATE_SESSION_RESPONSE_FIXTURE,
            s2b::CREATE_SESSION_RESPONSE,
        ),
        (MODIFY_BEARER_REQUEST_FIXTURE, s2b::MODIFY_BEARER_REQUEST),
        (MODIFY_BEARER_RESPONSE_FIXTURE, s2b::MODIFY_BEARER_RESPONSE),
        (DELETE_SESSION_REQUEST_FIXTURE, s2b::DELETE_SESSION_REQUEST),
        (
            DELETE_SESSION_RESPONSE_FIXTURE,
            s2b::DELETE_SESSION_RESPONSE,
        ),
        (UPDATE_BEARER_REQUEST_FIXTURE, s2b::UPDATE_BEARER_REQUEST),
        (UPDATE_BEARER_RESPONSE_FIXTURE, s2b::UPDATE_BEARER_RESPONSE),
    ];

    for (fixture, message_type) in cases {
        let message = decode_s2b(fixture);
        let view = procedure_view(&message);
        assert_eq!(view.header.message_type, *message_type);

        let canonical = encode_s2b(&message, EncodeContext::default());
        assert_eq!(canonical.as_ref(), *fixture);

        let raw_preserving = encode_s2b(
            &message,
            EncodeContext {
                raw_preserving: true,
                ..EncodeContext::default()
            },
        );
        assert_eq!(raw_preserving.as_ref(), *fixture);
    }

    assert_eq!(&MODIFY_BEARER_REQUEST_FIXTURE[12..], BEARER_CONTEXT_IE);
    assert_eq!(&MODIFY_BEARER_RESPONSE_FIXTURE[12..], CAUSE_IE);
    assert_eq!(&DELETE_SESSION_REQUEST_FIXTURE[12..], EBI_IE);
}

#[test]
fn create_session_request_exposes_mandatory_typed_ies_and_raw_fallback() {
    let message = decode_s2b(CREATE_SESSION_REQUEST_FIXTURE);
    assert!(matches!(message, S2bMessage::CreateSessionRequest(_)));
    let view = procedure_view(&message);

    let imsi = find_ie(&view.ies, opc_proto_gtpv2c::IE_TYPE_IMSI);
    match &imsi.value {
        TypedIeValue::Imsi(value) => assert_eq!(value.digits, "001010123456789"),
        other => panic!("unexpected IMSI value: {other:?}"),
    }

    let apn = find_ie(&view.ies, opc_proto_gtpv2c::IE_TYPE_APN);
    match &apn.value {
        TypedIeValue::AccessPointName(value) => assert_eq!(value.to_dotted_string(), "internet"),
        other => panic!("unexpected APN value: {other:?}"),
    }

    let fteid = find_ie(&view.ies, opc_proto_gtpv2c::IE_TYPE_F_TEID);
    match &fteid.value {
        TypedIeValue::FullyQualifiedTeid(value) => {
            assert_eq!(value.interface_type, 0x0a);
            assert_eq!(value.teid, 0x1122_3344);
            assert_eq!(value.ipv4, Some([192, 0, 2, 10]));
            assert_eq!(
                value.ipv6,
                Some([
                    0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x01,
                ])
            );
        }
        other => panic!("unexpected F-TEID value: {other:?}"),
    }

    let bearer = find_ie(&view.ies, IE_TYPE_BEARER_CONTEXT);
    match &bearer.value {
        TypedIeValue::BearerContext(context) => {
            let ebi = find_ie(&context.members, opc_proto_gtpv2c::IE_TYPE_EBI);
            match &ebi.value {
                TypedIeValue::EpsBearerId(value) => assert_eq!(value.value, 5),
                other => panic!("unexpected EBI value: {other:?}"),
            }
            let bearer_qos = find_ie(&context.members, IE_TYPE_BEARER_QOS);
            match &bearer_qos.value {
                TypedIeValue::BearerQos(value) => {
                    assert_eq!(value.priority_flags, 0x49);
                    assert_eq!(value.qci, 9);
                    assert_eq!(value.maximum_bitrate_uplink, 4096);
                    assert_eq!(value.maximum_bitrate_downlink, 8192);
                    assert_eq!(value.guaranteed_bitrate_uplink, 1024);
                    assert_eq!(value.guaranteed_bitrate_downlink, 2048);
                }
                other => panic!("unexpected Bearer QoS value: {other:?}"),
            }
            let charging_id = find_ie(&context.members, IE_TYPE_CHARGING_ID);
            match &charging_id.value {
                TypedIeValue::ChargingId(value) => assert_eq!(value.value, 0x1234_5678),
                other => panic!("unexpected Charging ID value: {other:?}"),
            }
        }
        other => panic!("unexpected Bearer Context value: {other:?}"),
    }

    let pco = find_ie(&view.ies, IE_TYPE_PCO);
    match &pco.value {
        TypedIeValue::ProtocolConfigurationOptions(value) => {
            assert_eq!(pco.instance, 2);
            assert_eq!(value.value, [0x80, 0x21, 0x00]);
        }
        other => panic!("unexpected PCO value: {other:?}"),
    }
    let indication = find_ie(&view.ies, IE_TYPE_INDICATION);
    match &indication.value {
        TypedIeValue::Indication(value) => assert_eq!(value.flags, [0x40, 0x01]),
        other => panic!("unexpected Indication value: {other:?}"),
    }
    let apco = find_ie(&view.ies, IE_TYPE_APCO);
    match &apco.value {
        TypedIeValue::AdditionalProtocolConfigurationOptions(value) => {
            assert_eq!(apco.instance, 1);
            assert_eq!(value.value, [0x80, 0x21, 0x01]);
        }
        other => panic!("unexpected APCO value: {other:?}"),
    }
    let unsupported = find_ie(&view.ies, 0xfe);
    match &unsupported.value {
        TypedIeValue::Raw(raw) => {
            assert_eq!(raw.ie_type, 0xfe);
            assert_eq!(raw.value, [0xaa]);
        }
        other => panic!("unexpected raw fallback value: {other:?}"),
    }
}

#[test]
fn response_and_update_views_expose_cause_and_procedure() {
    let create_response = decode_s2b(CREATE_SESSION_RESPONSE_FIXTURE);
    let view = procedure_view(&create_response);
    assert_eq!(view.procedure, s2b::Procedure::CreateSession);
    assert_eq!(view.direction, s2b::MessageDirection::Response);
    let cause = find_ie(&view.ies, opc_proto_gtpv2c::IE_TYPE_CAUSE);
    match &cause.value {
        TypedIeValue::Cause(value) => {
            assert_eq!(value.value, CauseValue::RequestAccepted);
            assert_eq!(value.flags_octet, 0);
            assert!(value.offending_ie.is_empty());
        }
        other => panic!("unexpected Cause value: {other:?}"),
    }

    let update_request = decode_s2b(UPDATE_BEARER_REQUEST_FIXTURE);
    let view = procedure_view(&update_request);
    assert_eq!(view.procedure, s2b::Procedure::UpdateSession);
    assert_eq!(view.direction, s2b::MessageDirection::Request);
    assert!(view.has_ie(IE_TYPE_BEARER_CONTEXT));
}

#[test]
fn message_type_unknown_fallback_roundtrips_through_raw_shell() {
    let unknown_fixture = [
        0x40, 0xc8, 0x00, 0x04, // Unknown message type 200, no TEID.
        0x00, 0x20, 0xaa, 0x00,
    ];

    let (_, raw_message) = match Message::decode(&unknown_fixture, DecodeContext::default()) {
        Ok(decoded) => decoded,
        Err(error) => panic!("raw unknown message decode failed: {error:?}"),
    };
    assert_eq!(raw_message.message_type(), MessageType::Unknown(0xc8));

    let (_, s2b_message) = match S2bMessage::decode(&unknown_fixture, DecodeContext::default()) {
        Ok(decoded) => decoded,
        Err(error) => panic!("S2b unknown message decode failed: {error:?}"),
    };
    assert_eq!(s2b_message.message_type(), MessageType::Unknown(0xc8));
    assert!(s2b_message.as_raw().is_some());

    let encoded = encode_s2b(&s2b_message, EncodeContext::default());
    assert_eq!(&encoded[..], unknown_fixture);
}

#[test]
fn procedure_aware_validation_rejects_missing_mandatory_ies() {
    let create_without_mandatory_ies = [
        0x40, 0x20, 0x00, 0x04, // Create Session Request, no TEID, no IE region.
        0x00, 0x20, 0x01, 0x00,
    ];
    let decoded = S2bMessage::decode(&create_without_mandatory_ies, procedure_context());
    assert!(matches!(
        decoded,
        Err(error) if matches!(error.code(), DecodeErrorCode::Structural { .. })
    ));

    let echo_request_without_recovery = [
        0x40, 0x01, 0x00, 0x04, // Echo Request missing mandatory Recovery IE.
        0x00, 0x20, 0x00, 0x00,
    ];
    let decoded = S2bMessage::decode(&echo_request_without_recovery, procedure_context());
    assert!(matches!(
        decoded,
        Err(error) if matches!(error.code(), DecodeErrorCode::Structural { .. })
    ));

    let echo_response_without_recovery = [
        0x40, 0x02, 0x00, 0x04, // Echo Response missing mandatory Recovery IE.
        0x00, 0x20, 0x02, 0x00,
    ];
    let decoded = S2bMessage::decode(&echo_response_without_recovery, procedure_context());
    assert!(matches!(
        decoded,
        Err(error) if matches!(error.code(), DecodeErrorCode::Structural { .. })
    ));
}

fn duplicate_context(policy: DuplicateIePolicy) -> DecodeContext {
    DecodeContext {
        duplicate_ie_policy: policy,
        ..DecodeContext::default()
    }
}

fn assert_duplicate_rejected(result: Result<Vec<TypedIe<'_>>, opc_protocol::DecodeError>) {
    assert!(matches!(
        result,
        Err(error) if matches!(error.code(), DecodeErrorCode::DuplicateIe)
    ));
}

fn ebi_value(ie: &TypedIe<'_>) -> u8 {
    match &ie.value {
        TypedIeValue::EpsBearerId(value) => value.value,
        other => panic!("expected EBI, got {other:?}"),
    }
}

#[test]
fn typed_ie_duplicate_policy_applies_to_top_level_and_grouped_sequences() {
    let duplicate_ebi = [
        0x49, 0x00, 0x01, 0x00, 0x05, // EBI instance 0 = 5.
        0x49, 0x00, 0x01, 0x00, 0x06, // Duplicate EBI instance 0 = 6.
    ];

    assert_duplicate_rejected(decode_typed_ie_sequence(
        &duplicate_ebi,
        duplicate_context(DuplicateIePolicy::Reject),
        0,
    ));

    let first = match decode_typed_ie_sequence(
        &duplicate_ebi,
        duplicate_context(DuplicateIePolicy::First),
        0,
    ) {
        Ok(ies) => ies,
        Err(error) => panic!("first duplicate policy failed: {error:?}"),
    };
    assert_eq!(first.len(), 1);
    assert_eq!(ebi_value(&first[0]), 5);

    let last = match decode_typed_ie_sequence(
        &duplicate_ebi,
        duplicate_context(DuplicateIePolicy::Last),
        0,
    ) {
        Ok(ies) => ies,
        Err(error) => panic!("last duplicate policy failed: {error:?}"),
    };
    assert_eq!(last.len(), 1);
    assert_eq!(ebi_value(&last[0]), 6);

    let duplicate_group_member = [
        IE_TYPE_BEARER_CONTEXT,
        0x00,
        0x0a,
        0x00, // Bearer Context containing two EBI members.
        IE_TYPE_EBI,
        0x00,
        0x01,
        0x00,
        0x05,
        IE_TYPE_EBI,
        0x00,
        0x01,
        0x00,
        0x06,
    ];
    assert_duplicate_rejected(decode_typed_ie_sequence(
        &duplicate_group_member,
        duplicate_context(DuplicateIePolicy::Reject),
        0,
    ));
}

#[test]
fn required_s2b_typed_ie_subset_decodes_and_encodes_byte_exact() {
    let typed_subset = [
        0x4e, 0x00, 0x03, 0x02, 0x80, 0x21, 0x00, // PCO instance 2.
        0xa3, 0x00, 0x03, 0x01, 0x80, 0x21, 0x01, // APCO instance 1.
        0x4d, 0x00, 0x02, 0x00, 0x40, 0x01, // Indication flags.
        0x50, 0x00, 0x16, 0x00, // Bearer QoS.
        0x49, 0x09, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x5e, 0x00, 0x04, 0x00, 0x12, 0x34, 0x56,
        0x78, // Charging ID.
    ];

    let decoded = match decode_typed_ie_sequence(&typed_subset, DecodeContext::default(), 0) {
        Ok(ies) => ies,
        Err(error) => panic!("required typed subset decode failed: {error:?}"),
    };
    assert_eq!(decoded.len(), 5);
    assert!(matches!(
        decoded[0].value,
        TypedIeValue::ProtocolConfigurationOptions(_)
    ));
    assert!(matches!(
        decoded[1].value,
        TypedIeValue::AdditionalProtocolConfigurationOptions(_)
    ));
    assert!(matches!(decoded[2].value, TypedIeValue::Indication(_)));
    assert!(matches!(decoded[3].value, TypedIeValue::BearerQos(_)));
    assert!(matches!(decoded[4].value, TypedIeValue::ChargingId(_)));

    let mut encoded = BytesMut::new();
    for ie in &decoded {
        ie.encode(&mut encoded, EncodeContext::default()).unwrap();
    }
    assert_eq!(&encoded[..], typed_subset);
}

#[test]
fn typed_ie_decode_rejects_noncanonical_trailing_bytes() {
    let fteid_with_trailing = [
        0x57, 0x00, 0x0a, 0x00, // F-TEID value declares one trailing byte.
        0x8a, 0x11, 0x22, 0x33, 0x44, 0xc0, 0x00, 0x02, 0x0a, 0xff,
    ];
    let decoded = decode_typed_ie_sequence(&fteid_with_trailing, DecodeContext::default(), 0);
    assert!(matches!(
        decoded,
        Err(error) if matches!(error.code(), DecodeErrorCode::InvalidLength { .. })
    ));

    let non_ip_paa_with_trailing = [
        0x4f, 0x00, 0x02, 0x00, // PAA value declares a surplus byte.
        0x04, 0xff, // Non-IP PDN type must be one octet only.
    ];
    let decoded = decode_typed_ie_sequence(&non_ip_paa_with_trailing, DecodeContext::default(), 0);
    assert!(matches!(
        decoded,
        Err(error) if matches!(error.code(), DecodeErrorCode::InvalidLength { .. })
    ));

    let fteid_without_address = [
        0x57, 0x00, 0x05, 0x00, // F-TEID with no V4/V6 flag set.
        0x0a, 0x11, 0x22, 0x33, 0x44,
    ];
    let decoded = decode_typed_ie_sequence(&fteid_without_address, DecodeContext::default(), 0);
    assert!(matches!(
        decoded,
        Err(error) if matches!(error.code(), DecodeErrorCode::Structural { .. })
    ));
}

#[test]
fn cause_ie_requires_flags_octet_and_preserves_offending_ie_bytes() {
    let one_octet_cause = [IE_TYPE_CAUSE, 0x00, 0x01, 0x00, 0x10];
    let decoded = decode_typed_ie_sequence(&one_octet_cause, DecodeContext::default(), 0);
    assert!(decoded.is_err());

    let cause_with_offending_ie = [
        IE_TYPE_CAUSE,
        0x00,
        0x06,
        0x00,
        0x46, // Mandatory IE missing.
        0x0d, // Flags/locality octet preserved opaquely.
        0x49,
        0x00,
        0x01,
        0x00,
    ];
    let decoded =
        match decode_typed_ie_sequence(&cause_with_offending_ie, DecodeContext::default(), 0) {
            Ok(ies) => ies,
            Err(error) => panic!("cause with offending IE did not decode: {error:?}"),
        };
    match &decoded[0].value {
        TypedIeValue::Cause(value) => {
            assert_eq!(value.value, CauseValue::MandatoryIeMissing);
            assert_eq!(value.flags_octet, 0x0d);
            assert_eq!(value.offending_ie, [0x49, 0x00, 0x01, 0x00]);
        }
        other => panic!("unexpected Cause value: {other:?}"),
    }

    let mut encoded = BytesMut::new();
    decoded[0]
        .encode(&mut encoded, EncodeContext::default())
        .unwrap();
    assert_eq!(&encoded[..], cause_with_offending_ie);
}

#[test]
fn debug_output_redacts_subscriber_identifiers_and_raw_ie_bytes() {
    let message = decode_s2b(CREATE_SESSION_REQUEST_FIXTURE);
    let debug = format!("{message:?}");
    assert!(!debug.contains("001010123456789"));
    assert!(!debug.contains("raw_ies:"));
    assert!(!debug.contains("[0, 1, 1, 33, 67, 101, 135, 249]"));
    assert!(debug.contains("raw_ies_len"));

    let mei = TypedIe {
        instance: 0,
        value: TypedIeValue::Mei(TbcdDigits::new("490154203237518")),
    };
    let msisdn = TypedIe {
        instance: 0,
        value: TypedIeValue::Msisdn(TbcdDigits::new("15551234567")),
    };
    let mei_debug = format!("{mei:?}");
    let msisdn_debug = format!("{msisdn:?}");
    assert!(!mei_debug.contains("490154203237518"));
    assert!(!msisdn_debug.contains("15551234567"));
    assert!(mei_debug.contains("<redacted>"));
    assert!(msisdn_debug.contains("<redacted>"));
}

/// Build a minimal Create Session Request where the Sender F-TEID IE appears at
/// `fteid_instance`. All other mandatory S2b IEs are present at instance 0.
fn create_session_request_with_fteid_instance(fteid_instance: u8) -> Vec<u8> {
    let mut header = [
        0x40,
        s2b::CREATE_SESSION_REQUEST,
        0x00,
        0x00, // Length placeholder.
        0x00,
        0x20, // Sequence number.
        0x00,
        0x00, // Spare octets.
    ];
    let ies: &[&[u8]] = &[
        &[
            0x01, 0x00, 0x08, 0x00, 0x00, 0x01, 0x01, 0x21, 0x43, 0x65, 0x87, 0xf9,
        ], // IMSI.
        &[0x52, 0x00, 0x01, 0x00, 0x03],             // RAT Type.
        &[0x53, 0x00, 0x03, 0x00, 0x00, 0xf1, 0x10], // Serving Network.
        &[
            IE_TYPE_F_TEID,
            0x00,
            0x09,
            fteid_instance,
            0x8a,
            0x11,
            0x22,
            0x33,
            0x44,
            0xc0,
            0x00,
            0x02,
            0x0a,
        ], // Sender F-TEID.
        &[
            0x47, 0x00, 0x09, 0x00, 0x08, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74,
        ], // APN.
        &[0x80, 0x00, 0x01, 0x00, 0x00],             // Selection Mode.
        &[0x63, 0x00, 0x01, 0x00, 0x01],             // PDN Type.
        &[0x4f, 0x00, 0x05, 0x00, 0x01, 0xc6, 0x33, 0x64, 0x07], // PAA.
        &[0x5d, 0x00, 0x05, 0x00, 0x49, 0x00, 0x01, 0x00, 0x05], // Bearer Context + EBI.
    ];
    let body: Vec<u8> = ies.iter().copied().flatten().copied().collect();
    let length = u16::try_from(header.len() + body.len() - 4).unwrap();
    header[2..4].copy_from_slice(&length.to_be_bytes());
    let mut message = Vec::with_capacity(header.len() + body.len());
    message.extend_from_slice(&header);
    message.extend_from_slice(&body);
    message
}

/// Build a minimal Create Session Response where the Sender F-TEID IE appears at
/// `fteid_instance`. All other mandatory S2b IEs are present at instance 0.
fn create_session_response_with_fteid_instance(fteid_instance: u8) -> Vec<u8> {
    let mut header = [
        0x48,
        s2b::CREATE_SESSION_RESPONSE,
        0x00,
        0x00, // Length placeholder.
        0x01,
        0x02,
        0x03,
        0x04, // TEID.
        0x00,
        0x20, // Sequence number.
        0x00,
        0x00, // Spare octets.
    ];
    let ies: &[&[u8]] = &[
        &[0x02, 0x00, 0x02, 0x00, 0x10, 0x00], // Cause.
        &[
            IE_TYPE_F_TEID,
            0x00,
            0x09,
            fteid_instance,
            0x8b,
            0x55,
            0x66,
            0x77,
            0x88,
            0xc0,
            0x00,
            0x02,
            0x01,
        ], // Sender F-TEID.
        &[0x5d, 0x00, 0x05, 0x00, 0x49, 0x00, 0x01, 0x00, 0x05], // Bearer Context + EBI.
    ];
    let body: Vec<u8> = ies.iter().copied().flatten().copied().collect();
    let length = u16::try_from(header.len() + body.len() - 4).unwrap();
    header[2..4].copy_from_slice(&length.to_be_bytes());
    let mut message = Vec::with_capacity(header.len() + body.len());
    message.extend_from_slice(&header);
    message.extend_from_slice(&body);
    message
}

#[test]
fn procedure_aware_rejects_non_zero_instance_sender_fteid_for_create_session() {
    // Sanity: instance-0 Sender F-TEID is accepted.
    let valid_request = create_session_request_with_fteid_instance(0);
    assert!(S2bMessage::decode(&valid_request, procedure_context()).is_ok());

    let valid_response = create_session_response_with_fteid_instance(0);
    assert!(S2bMessage::decode(&valid_response, procedure_context()).is_ok());

    // Regression: non-zero instance Sender F-TEID must not satisfy the mandatory
    // Sender F-TEID requirement for Create Session Request/Response.
    for instance in [1u8, 2, 15] {
        let bad_request = create_session_request_with_fteid_instance(instance);
        let decoded = S2bMessage::decode(&bad_request, procedure_context());
        assert!(
            matches!(
                decoded,
                Err(error) if matches!(error.code(), DecodeErrorCode::Structural { .. })
            ),
            "Create Session Request with F-TEID instance {instance} should be rejected"
        );

        let bad_response = create_session_response_with_fteid_instance(instance);
        let decoded = S2bMessage::decode(&bad_response, procedure_context());
        assert!(
            matches!(
                decoded,
                Err(error) if matches!(error.code(), DecodeErrorCode::Structural { .. })
            ),
            "Create Session Response with F-TEID instance {instance} should be rejected"
        );
    }
}

#[test]
fn procedure_aware_validation_rejects_missing_mandatory_ies_for_every_claimed_pair() {
    let mut cases: Vec<Vec<u8>> = Vec::new();
    cases.push(vec![
        0x40, 0x01, 0x00, 0x04, // Echo Request missing mandatory Recovery IE.
        0x00, 0x20, 0x00, 0x00,
    ]);
    cases.push(vec![
        0x40, 0x20, 0x00, 0x04, // Create Session Request, no TEID, no IE region.
        0x00, 0x20, 0x01, 0x00,
    ]);
    cases.push(vec![
        0x40, 0x02, 0x00, 0x04, // Echo Response missing mandatory Recovery IE.
        0x00, 0x20, 0x02, 0x00,
    ]);

    for (message_type, seq) in [
        (s2b::CREATE_SESSION_RESPONSE, 0x03),
        (s2b::MODIFY_BEARER_REQUEST, 0x04),
        (s2b::MODIFY_BEARER_RESPONSE, 0x05),
        (s2b::DELETE_SESSION_REQUEST, 0x06),
        (s2b::DELETE_SESSION_RESPONSE, 0x07),
        (s2b::UPDATE_BEARER_REQUEST, 0x08),
        (s2b::UPDATE_BEARER_RESPONSE, 0x09),
    ] {
        cases.push(vec![
            0x48,
            message_type,
            0x00,
            0x08,
            0x01,
            0x02,
            0x03,
            0x04,
            0x00,
            0x20,
            seq,
            0x00,
        ]);
    }

    for bytes in cases {
        let decoded = S2bMessage::decode(&bytes, procedure_context());
        assert!(matches!(
            decoded,
            Err(error) if matches!(error.code(), DecodeErrorCode::Structural { .. })
        ));
    }
}

#[test]
fn fteid_encode_rejects_missing_v4_and_v6() {
    let fteid = FullyQualifiedTeid {
        interface_type: 10,
        teid: 0x1122_3344,
        ipv4: None,
        ipv6: None,
    };
    let ie = TypedIe {
        instance: 0,
        value: TypedIeValue::FullyQualifiedTeid(fteid),
    };
    let mut dst = BytesMut::new();
    let result = ie.encode(&mut dst, EncodeContext::default());
    assert!(matches!(
        result,
        Err(error) if matches!(error.code(), EncodeErrorCode::Structural { .. })
    ));
}

#[test]
fn fteid_encode_rejects_out_of_range_interface_type() {
    let fteid = FullyQualifiedTeid {
        interface_type: 0x40,
        teid: 0,
        ipv4: Some([192, 0, 2, 1]),
        ipv6: None,
    };
    let ie = TypedIe {
        instance: 0,
        value: TypedIeValue::FullyQualifiedTeid(fteid),
    };
    let mut dst = BytesMut::new();
    let result = ie.encode(&mut dst, EncodeContext::default());
    assert!(matches!(
        result,
        Err(error) if matches!(error.code(), EncodeErrorCode::Structural { .. })
    ));
}

#[test]
fn nested_bearer_context_rejects_depth_exceeded() {
    // Outer Bearer Context containing one nested Bearer Context containing EBI.
    let nested = [
        IE_TYPE_BEARER_CONTEXT,
        0x00,
        0x09,
        0x00, // Outer Bearer Context header, length 9.
        IE_TYPE_BEARER_CONTEXT,
        0x00,
        0x05,
        0x00, // Inner Bearer Context header, length 5.
        IE_TYPE_EBI,
        0x00,
        0x01,
        0x00,
        0x05, // EBI = 5.
    ];
    let ctx = DecodeContext {
        max_depth: 1,
        ..DecodeContext::default()
    };
    let result = decode_typed_ie_sequence(&nested, ctx, 0);
    assert!(matches!(
        result,
        Err(error) if matches!(error.code(), DecodeErrorCode::DepthExceeded) && error.offset() == 8
    ));
}

#[test]
fn duplicate_ie_reject_includes_ie_offset() {
    let duplicate_ebi = [
        IE_TYPE_EBI,
        0x00,
        0x01,
        0x00,
        0x05, // EBI instance 0 = 5.
        IE_TYPE_EBI,
        0x00,
        0x01,
        0x00,
        0x06, // Duplicate EBI instance 0 = 6.
    ];
    let ctx = DecodeContext {
        duplicate_ie_policy: DuplicateIePolicy::Reject,
        ..DecodeContext::default()
    };
    let result = decode_typed_ie_sequence(&duplicate_ebi, ctx, 0);
    assert!(matches!(
        result,
        Err(error) if matches!(error.code(), DecodeErrorCode::DuplicateIe) && error.offset() == 5
    ));
}

#[test]
fn nested_bearer_context_duplicate_ie_reject_includes_absolute_offset() {
    // Recovery IE (5 octets) pushes the Bearer Context header to offset 5 and
    // its value start to offset 9. The first nested EBI occupies offsets 9..13,
    // so the duplicate second EBI begins at absolute offset 14.
    let recovery = [IE_TYPE_RECOVERY, 0x00, 0x01, 0x00, 0x2a];
    let bearer_context = [
        IE_TYPE_BEARER_CONTEXT,
        0x00,
        0x0a,
        0x00, // Bearer Context header, value length 10.
        IE_TYPE_EBI,
        0x00,
        0x01,
        0x00,
        0x05, // First nested EBI instance 0 = 5.
        IE_TYPE_EBI,
        0x00,
        0x01,
        0x00,
        0x06, // Duplicate nested EBI instance 0 = 6.
    ];
    let mut input = Vec::with_capacity(recovery.len() + bearer_context.len());
    input.extend_from_slice(&recovery);
    input.extend_from_slice(&bearer_context);

    let ctx = DecodeContext {
        duplicate_ie_policy: DuplicateIePolicy::Reject,
        ..DecodeContext::default()
    };
    let result = decode_typed_ie_sequence(&input, ctx, 0);
    assert!(matches!(
        result,
        Err(error) if matches!(error.code(), DecodeErrorCode::DuplicateIe) && error.offset() == 14
    ));
}

#[test]
fn typed_value_decode_error_includes_ie_value_offset() {
    let invalid_imsi = [
        IE_TYPE_IMSI,
        0x00,
        0x01,
        0x00, // IMSI IE header.
        0x0a, // Invalid TBCD digit in low nibble.
    ];
    let result = decode_typed_ie_sequence(&invalid_imsi, DecodeContext::default(), 0);
    assert!(matches!(
        result,
        Err(error) if matches!(error.code(), DecodeErrorCode::InvalidEnumValue { .. }) && error.offset() == 4
    ));
}

#[test]
fn malformed_nested_bearer_context_member_includes_bearer_value_offset() {
    // Recovery IE (5 octets) pushes the Bearer Context value start to offset 9.
    let recovery = [IE_TYPE_RECOVERY, 0x00, 0x01, 0x00, 0x2a];
    // Bearer Context containing a nested IE header that is truncated mid-header.
    let bearer_context = [
        IE_TYPE_BEARER_CONTEXT,
        0x00,
        0x02,
        0x00, // Bearer Context header, value length 2.
        IE_TYPE_EBI,
        0x00, // Truncated nested EBI header (only 2 of 4 header octets).
    ];
    let mut input = Vec::with_capacity(recovery.len() + bearer_context.len());
    input.extend_from_slice(&recovery);
    input.extend_from_slice(&bearer_context);

    let result = decode_typed_ie_sequence(&input, DecodeContext::default(), 0);
    assert!(matches!(
        result,
        Err(error) if matches!(error.code(), DecodeErrorCode::Truncated) && error.offset() == 9
    ));
}

#[test]
fn strict_nested_bearer_context_member_includes_bearer_value_offset() {
    // Recovery IE (5 octets) pushes the Bearer Context value start to offset 9.
    let recovery = [IE_TYPE_RECOVERY, 0x00, 0x01, 0x00, 0x2a];
    // Bearer Context containing a nested EBI with non-zero spare bits in strict
    // mode. The instance octet is at value offset 3, so absolute offset 12.
    let bearer_context = [
        IE_TYPE_BEARER_CONTEXT,
        0x00,
        0x05,
        0x00, // Bearer Context header, value length 5.
        IE_TYPE_EBI,
        0x00,
        0x01,
        0xf0, // Instance 0 with non-zero spare high nibble.
        0x05,
    ];
    let mut input = Vec::with_capacity(recovery.len() + bearer_context.len());
    input.extend_from_slice(&recovery);
    input.extend_from_slice(&bearer_context);

    let ctx = DecodeContext {
        validation_level: ValidationLevel::Strict,
        ..DecodeContext::default()
    };
    let result = decode_typed_ie_sequence(&input, ctx, 0);
    assert!(matches!(
        result,
        Err(error) if matches!(error.code(), DecodeErrorCode::Structural { .. }) && error.offset() == 12
    ));
}

#[test]
fn value_truncated_ie_reports_start_offset() {
    // Header is complete but the declared value length (5 octets) exceeds the
    // single value octet available. Truncation is reported at the start of the
    // IE, matching the convention used for header-truncated IEs.
    let truncated = [
        IE_TYPE_EBI,
        0x00,
        0x05,
        0x00, // Declares five value octets.
        0x05, // Only one value octet present.
    ];
    let result = decode_typed_ie_sequence(&truncated, DecodeContext::default(), 0);
    assert!(matches!(
        result,
        Err(error) if matches!(error.code(), DecodeErrorCode::Truncated) && error.offset() == 0
    ));
}
