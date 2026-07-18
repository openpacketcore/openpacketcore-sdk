use bytes::BytesMut;
use opc_proto_gtpv2c::{
    decode_typed_ie_sequence, s2b, CauseValue, FullyQualifiedTeid, Message, MessageType,
    S2bMessage, TbcdDigits, TypedIe, TypedIeValue, IE_TYPE_APCO, IE_TYPE_BEARER_CONTEXT,
    IE_TYPE_BEARER_QOS, IE_TYPE_CAUSE, IE_TYPE_EBI, IE_TYPE_F_TEID, IE_TYPE_IMSI,
    IE_TYPE_INDICATION, IE_TYPE_MEI, IE_TYPE_RECOVERY, INTERFACE_TYPE_S2B_EPDG_GTP_C,
    INTERFACE_TYPE_S2B_PGW_GTP_C, INTERFACE_TYPE_S2B_U_EPDG_GTP_U, INTERFACE_TYPE_S2B_U_PGW_GTP_U,
};
use opc_protocol::{
    BorrowDecode, DecodeContext, DecodeErrorCode, DuplicateIePolicy, Encode, EncodeContext,
    EncodeErrorCode, UnknownIePolicy, ValidationLevel,
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

#[test]
fn s2b_interface_type_registry_matches_ts_29_274_table_8_22_1() {
    assert_eq!(INTERFACE_TYPE_S2B_EPDG_GTP_C, 30);
    assert_eq!(INTERFACE_TYPE_S2B_U_EPDG_GTP_U, 31);
    assert_eq!(INTERFACE_TYPE_S2B_PGW_GTP_C, 32);
    assert_eq!(INTERFACE_TYPE_S2B_U_PGW_GTP_U, 33);
}

const BEARER_CONTEXT_IE: &[u8] = &[
    0x5d, 0x00, 0x05, 0x00, // Bearer Context grouped IE header.
    0x49, 0x00, 0x01, 0x00, 0x05, // Nested EBI = 5.
];
const BEARER_CONTEXT_WITH_USER_PLANE_FTEID_IE: &[u8] = &[
    0x5d,
    0x00,
    0x12,
    0x00, // Bearer Context grouped IE header.
    0x49,
    0x00,
    0x01,
    0x00,
    0x05, // Nested EBI = 5.
    IE_TYPE_F_TEID,
    0x00,
    0x09,
    0x00,
    0xa1,
    0x11,
    0x22,
    0x33,
    0x44,
    0xcb,
    0x00,
    0x71,
    0x01, // Nested S2b-U PGW GTP-U F-TEID.
];
const BEARER_CONTEXT_WITH_EPDG_USER_PLANE_FTEID_IE: &[u8] = &[
    IE_TYPE_BEARER_CONTEXT,
    0x00,
    0x12,
    0x00, // Bearer Context grouped IE header.
    IE_TYPE_EBI,
    0x00,
    0x01,
    0x00,
    0x05, // Nested EBI = 5.
    IE_TYPE_F_TEID,
    0x00,
    0x09,
    0x00,
    0x9f,
    0x11,
    0x22,
    0x33,
    0x44,
    0xcb,
    0x00,
    0x71,
    0x0a, // Nested S2b-U ePDG GTP-U F-TEID.
];

const CAUSE_IE: &[u8] = &[0x02, 0x00, 0x02, 0x00, 0x10, 0x00];
const PARTIAL_ACCEPT_CAUSE_IE: &[u8] = &[IE_TYPE_CAUSE, 0x00, 0x02, 0x00, 0x11, 0x00];
const REJECTED_CAUSE_IE: &[u8] = &[IE_TYPE_CAUSE, 0x00, 0x02, 0x00, 0x46, 0x00];
const EBI_IE: &[u8] = &[0x49, 0x00, 0x01, 0x00, 0x05];
const SENDER_F_TEID_IE: &[u8] = &[
    IE_TYPE_F_TEID,
    0x00,
    0x09,
    0x00,
    0x8b,
    0x55,
    0x66,
    0x77,
    0x88,
    0xc0,
    0x00,
    0x02,
    0x01,
];
const EMPTY_BEARER_CONTEXT_IE: &[u8] = &[IE_TYPE_BEARER_CONTEXT, 0x00, 0x00, 0x00];
const IMSI_IE: &[u8] = &[
    IE_TYPE_IMSI,
    0x00,
    0x08,
    0x00,
    0x00,
    0x01,
    0x01,
    0x21,
    0x43,
    0x65,
    0x87,
    0xf9,
];
const MEI_IE: &[u8] = &[
    IE_TYPE_MEI,
    0x00,
    0x08,
    0x00,
    0x94,
    0x10,
    0x45,
    0x02,
    0x23,
    0x73,
    0x15,
    0xf8,
];
const UIMSI_INDICATION_IE: &[u8] = &[IE_TYPE_INDICATION, 0x00, 0x02, 0x00, 0x00, 0x40];
const INDICATION_WITHOUT_UIMSI_IE: &[u8] = &[IE_TYPE_INDICATION, 0x00, 0x01, 0x00, 0x00];

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
            assert_eq!(value.interface_type, INTERFACE_TYPE_S2B_EPDG_GTP_C);
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
            let user_plane_fteid = find_ie(&context.members, IE_TYPE_F_TEID);
            match &user_plane_fteid.value {
                TypedIeValue::FullyQualifiedTeid(value) => {
                    assert_eq!(user_plane_fteid.instance, 5);
                    assert_eq!(value.interface_type, INTERFACE_TYPE_S2B_U_EPDG_GTP_U);
                    assert_eq!(value.teid, 0x1122_3345);
                    assert_eq!(value.ipv4, Some([192, 0, 2, 20]));
                    assert_eq!(value.ipv6, None);
                }
                other => panic!("unexpected S2b-U ePDG F-TEID value: {other:?}"),
            }
            let bearer_qos = find_ie(&context.members, IE_TYPE_BEARER_QOS);
            match &bearer_qos.value {
                TypedIeValue::BearerQos(value) => {
                    assert_eq!(value.priority_flags, 0x49);
                    assert_eq!(value.qci, 1);
                    assert_eq!(value.maximum_bitrate_uplink, 4096);
                    assert_eq!(value.maximum_bitrate_downlink, 8192);
                    assert_eq!(value.guaranteed_bitrate_uplink, 1024);
                    assert_eq!(value.guaranteed_bitrate_downlink, 2048);
                }
                other => panic!("unexpected Bearer QoS value: {other:?}"),
            }
        }
        other => panic!("unexpected Bearer Context value: {other:?}"),
    }

    let indication = find_ie(&view.ies, IE_TYPE_INDICATION);
    match &indication.value {
        TypedIeValue::Indication(value) => assert_eq!(value.flags, [0x40, 0x01]),
        other => panic!("unexpected Indication value: {other:?}"),
    }
    let apco = find_ie(&view.ies, IE_TYPE_APCO);
    match &apco.value {
        TypedIeValue::AdditionalProtocolConfigurationOptions(value) => {
            assert_eq!(apco.instance, 0);
            assert_eq!(value.value, [0x80, 0x21, 0x01]);
        }
        other => panic!("unexpected APCO value: {other:?}"),
    }
    let unsupported = find_ie(&view.ies, 0xfe);
    match &unsupported.value {
        TypedIeValue::Raw(raw) => {
            assert_eq!(raw.ie_type, 0xfe);
            assert_eq!(raw.value, [0x01, 0x00]);
        }
        other => panic!("unexpected raw fallback value: {other:?}"),
    }
}

#[test]
fn unknown_typed_ie_reject_policy_fails_closed() {
    let unknown_ie = [0xfe, 0x00, 0x01, 0x00, 0xaa];
    let ctx = DecodeContext {
        unknown_ie_policy: UnknownIePolicy::Reject,
        ..DecodeContext::default()
    };

    let err = decode_typed_ie_sequence(&unknown_ie, ctx, 0).unwrap_err();

    assert_eq!(err.code(), &DecodeErrorCode::UnknownCriticalIe);
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
        0x49, 0x01, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00,
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
/// `fteid_instance`. All other required S2b IEs are present at instance 0.
fn create_session_request_with_fteid_instance(fteid_instance: u8) -> Vec<u8> {
    create_session_request_with_fteid_instance_and_bearer_context(fteid_instance, BEARER_CONTEXT_IE)
}

fn create_session_request_with_fteid_instance_and_bearer_context(
    fteid_instance: u8,
    bearer_context: &[u8],
) -> Vec<u8> {
    create_session_request_with_identity_ies_and_bearer_context(
        &[IMSI_IE],
        fteid_instance,
        bearer_context,
    )
}

fn create_session_request_with_identity_ies(identity_ies: &[&[u8]]) -> Vec<u8> {
    create_session_request_with_identity_ies_and_bearer_context(identity_ies, 0, BEARER_CONTEXT_IE)
}

fn create_session_request_with_identity_ies_and_bearer_context(
    identity_ies: &[&[u8]],
    fteid_instance: u8,
    bearer_context: &[u8],
) -> Vec<u8> {
    let mut header = [
        0x48,
        s2b::CREATE_SESSION_REQUEST,
        0x00,
        0x00, // Length placeholder.
        0x00,
        0x00,
        0x00,
        0x00, // TEID is present and zero for Create Session Request.
        0x00,
        0x20, // Sequence number.
        0x00,
        0x00, // Spare octets.
    ];
    let remaining_ies: &[&[u8]] = &[
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
        bearer_context,
    ];
    let body: Vec<u8> = identity_ies
        .iter()
        .chain(remaining_ies)
        .flat_map(|ie| ie.iter().copied())
        .collect();
    let length = u16::try_from(header.len() + body.len() - 4).unwrap();
    header[2..4].copy_from_slice(&length.to_be_bytes());
    let mut message = Vec::with_capacity(header.len() + body.len());
    message.extend_from_slice(&header);
    message.extend_from_slice(&body);
    message
}

#[test]
fn procedure_aware_accepts_uicc_less_emergency_create_session_identity() {
    let request = create_session_request_with_identity_ies(&[MEI_IE, UIMSI_INDICATION_IE]);

    let message = decode_s2b(&request);
    assert!(matches!(message, S2bMessage::CreateSessionRequest(_)));
    let view = procedure_view(&message);
    assert!(!view.has_ie(IE_TYPE_IMSI));

    let mei = find_ie(&view.ies, IE_TYPE_MEI);
    assert_eq!(mei.instance, 0);
    match &mei.value {
        TypedIeValue::Mei(value) => assert_eq!(value.digits, "490154203237518"),
        other => panic!("unexpected MEI value: {other:?}"),
    }

    let indication = find_ie(&view.ies, IE_TYPE_INDICATION);
    assert_eq!(indication.instance, 0);
    match &indication.value {
        TypedIeValue::Indication(value) => assert_eq!(value.flags, [0x00, 0x40]),
        other => panic!("unexpected Indication value: {other:?}"),
    }

    let encoded = encode_s2b(&message, EncodeContext::default());
    assert_eq!(encoded.as_ref(), request.as_slice());
}

#[test]
fn procedure_aware_rejects_incomplete_uicc_less_emergency_identity() {
    let cases: &[(&[&[u8]], &str)] = &[
        (&[], "no identity"),
        (&[MEI_IE], "MEI without Indication"),
        (&[UIMSI_INDICATION_IE], "UIMSI without MEI"),
        (
            &[MEI_IE, INDICATION_WITHOUT_UIMSI_IE],
            "MEI with Indication missing UIMSI",
        ),
    ];

    for (identity_ies, label) in cases {
        let request = create_session_request_with_identity_ies(identity_ies);
        let decoded = S2bMessage::decode(&request, procedure_context());
        assert!(
            matches!(
                decoded,
                Err(error) if matches!(error.code(), DecodeErrorCode::Structural { .. })
            ),
            "{label} must not satisfy the conditional Create Session identity"
        );
    }
}

#[test]
fn procedure_aware_imsi_identity_does_not_require_emergency_markers() {
    for identity_ies in [&[IMSI_IE][..], &[IMSI_IE, MEI_IE][..]] {
        let request = create_session_request_with_identity_ies(identity_ies);
        assert!(S2bMessage::decode(&request, procedure_context()).is_ok());
    }
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
        BEARER_CONTEXT_WITH_USER_PLANE_FTEID_IE,
    ];
    let body: Vec<u8> = ies.iter().copied().flatten().copied().collect();
    let length = u16::try_from(header.len() + body.len() - 4).unwrap();
    header[2..4].copy_from_slice(&length.to_be_bytes());
    let mut message = Vec::with_capacity(header.len() + body.len());
    message.extend_from_slice(&header);
    message.extend_from_slice(&body);
    message
}

fn create_session_response_with_projection_ies(
    teid: Option<u32>,
    sequence_number: u32,
    ies: &[&[u8]],
) -> Vec<u8> {
    let mut message = Vec::new();
    message.push(if teid.is_some() { 0x48 } else { 0x40 });
    message.push(s2b::CREATE_SESSION_RESPONSE);
    message.extend_from_slice(&[0x00, 0x00]);
    if let Some(teid) = teid {
        message.extend_from_slice(&teid.to_be_bytes());
    }
    message.push(((sequence_number >> 16) & 0xff) as u8);
    message.push(((sequence_number >> 8) & 0xff) as u8);
    message.push((sequence_number & 0xff) as u8);
    message.push(0x00);
    for ie in ies {
        message.extend_from_slice(ie);
    }

    let length = match u16::try_from(message.len() - 4) {
        Ok(length) => length,
        Err(error) => panic!("projection response fixture too long: {error:?}"),
    };
    message[2..4].copy_from_slice(&length.to_be_bytes());
    message
}

#[test]
fn create_session_rejected_response_summary_allows_cause_only() {
    let response = create_session_response_with_projection_ies(
        Some(0x0102_0304),
        0x0020_00ab,
        &[REJECTED_CAUSE_IE],
    );

    let decoded = decode_s2b(&response);
    let summary = match decoded.create_session_response_summary() {
        Ok(summary) => summary,
        Err(error) => panic!("rejected response summary failed: {error:?}"),
    };
    match &summary {
        s2b::CreateSessionResponseSummary::Rejected(rejected) => {
            assert_eq!(rejected.response_teid, 0x0102_0304);
            assert_eq!(rejected.sequence_number, 0x0020_00ab);
            assert_eq!(rejected.cause, CauseValue::MandatoryIeMissing);
        }
        other => panic!("expected rejected summary, got {other:?}"),
    }

    let direct = match s2b::decode_create_session_response_summary(&response, procedure_context()) {
        Ok(summary) => summary,
        Err(error) => panic!("direct rejected response projection failed: {error:?}"),
    };
    assert_eq!(direct, summary);
}

#[test]
fn create_session_accepted_response_summary_requires_bearer_fields() {
    let accepted = create_session_response_with_fteid_instance(0);
    let summary = match s2b::decode_create_session_response_summary(&accepted, procedure_context())
    {
        Ok(summary) => summary,
        Err(error) => panic!("accepted response summary failed: {error:?}"),
    };
    match summary {
        s2b::CreateSessionResponseSummary::Accepted(accepted) => {
            assert_eq!(accepted.response_teid, 0x0102_0304);
            assert_eq!(accepted.sequence_number, 0x0000_2000);
            assert_eq!(accepted.cause, CauseValue::RequestAccepted);
            assert_eq!(accepted.sender_f_teid.teid, 0x5566_7788);
            assert_eq!(accepted.bearer_ebi.value, 5);
            assert_eq!(
                accepted.bearer_user_plane_f_teid.interface_type,
                INTERFACE_TYPE_S2B_U_PGW_GTP_U
            );
            assert_eq!(accepted.bearer_user_plane_f_teid.teid, 0x1122_3344);
        }
        other => panic!("expected accepted summary, got {other:?}"),
    }

    let missing_sender = create_session_response_with_projection_ies(
        Some(0x0102_0304),
        0x0000_2000,
        &[CAUSE_IE, BEARER_CONTEXT_IE],
    );
    assert!(S2bMessage::decode(&missing_sender, procedure_context()).is_err());
    assert_eq!(
        s2b::decode_create_session_response_summary(&missing_sender, procedure_context()),
        Err(s2b::CreateSessionResponseSummaryError::AcceptedResponseMissingSenderFTeid)
    );

    let missing_bearer = create_session_response_with_projection_ies(
        Some(0x0102_0304),
        0x0000_2000,
        &[CAUSE_IE, SENDER_F_TEID_IE],
    );
    assert!(S2bMessage::decode(&missing_bearer, procedure_context()).is_err());
    assert_eq!(
        s2b::decode_create_session_response_summary(&missing_bearer, procedure_context()),
        Err(s2b::CreateSessionResponseSummaryError::AcceptedResponseMissingBearerContext)
    );

    let missing_ebi = create_session_response_with_projection_ies(
        Some(0x0102_0304),
        0x0000_2000,
        &[CAUSE_IE, SENDER_F_TEID_IE, EMPTY_BEARER_CONTEXT_IE],
    );
    assert!(S2bMessage::decode(&missing_ebi, procedure_context()).is_err());
    assert_eq!(
        s2b::decode_create_session_response_summary(&missing_ebi, procedure_context()),
        Err(s2b::CreateSessionResponseSummaryError::AcceptedResponseMissingBearerEbi)
    );
}

#[test]
fn create_session_partial_accept_response_summary_projects_bearer_fields() {
    let response = create_session_response_with_projection_ies(
        Some(0x0102_0304),
        0x0000_2000,
        &[
            PARTIAL_ACCEPT_CAUSE_IE,
            SENDER_F_TEID_IE,
            BEARER_CONTEXT_WITH_USER_PLANE_FTEID_IE,
        ],
    );

    let decoded = decode_s2b(&response);
    let summary = match decoded.create_session_response_summary() {
        Ok(summary) => summary,
        Err(error) => panic!("partial accept response summary failed: {error:?}"),
    };
    match &summary {
        s2b::CreateSessionResponseSummary::Accepted(accepted) => {
            assert_eq!(accepted.response_teid, 0x0102_0304);
            assert_eq!(accepted.sequence_number, 0x0000_2000);
            assert_eq!(accepted.cause, CauseValue::RequestAcceptedPartially);
            assert_eq!(accepted.sender_f_teid.teid, 0x5566_7788);
            assert_eq!(accepted.bearer_ebi.value, 5);
            assert_eq!(
                accepted.bearer_user_plane_f_teid.interface_type,
                INTERFACE_TYPE_S2B_U_PGW_GTP_U
            );
            assert_eq!(accepted.bearer_user_plane_f_teid.teid, 0x1122_3344);
        }
        other => panic!("expected accepted partial summary, got {other:?}"),
    }

    let direct = match s2b::decode_create_session_response_summary(&response, procedure_context()) {
        Ok(summary) => summary,
        Err(error) => panic!("direct partial accept projection failed: {error:?}"),
    };
    assert_eq!(direct, summary);
}

#[test]
fn create_session_partial_accept_response_requires_accepted_fields() {
    let cause_only = create_session_response_with_projection_ies(
        Some(0x0102_0304),
        0x0000_2000,
        &[PARTIAL_ACCEPT_CAUSE_IE],
    );
    assert!(S2bMessage::decode(&cause_only, procedure_context()).is_err());
    assert_eq!(
        s2b::decode_create_session_response_summary(&cause_only, procedure_context()),
        Err(s2b::CreateSessionResponseSummaryError::AcceptedResponseMissingSenderFTeid)
    );

    let missing_bearer = create_session_response_with_projection_ies(
        Some(0x0102_0304),
        0x0000_2000,
        &[PARTIAL_ACCEPT_CAUSE_IE, SENDER_F_TEID_IE],
    );
    assert!(S2bMessage::decode(&missing_bearer, procedure_context()).is_err());
    assert_eq!(
        s2b::decode_create_session_response_summary(&missing_bearer, procedure_context()),
        Err(s2b::CreateSessionResponseSummaryError::AcceptedResponseMissingBearerContext)
    );
}

#[test]
fn create_session_response_summary_returns_stable_error_codes() {
    let missing_cause =
        create_session_response_with_projection_ies(Some(0x0102_0304), 0x0000_2000, &[]);
    let error =
        match s2b::decode_create_session_response_summary(&missing_cause, procedure_context()) {
            Ok(summary) => panic!("missing Cause unexpectedly projected: {summary:?}"),
            Err(error) => error,
        };
    assert_eq!(error, s2b::CreateSessionResponseSummaryError::MissingCause);
    assert_eq!(error.as_str(), "s2b_create_session_response_missing_cause");
    assert_eq!(error.to_string(), error.as_str());

    let missing_teid =
        create_session_response_with_projection_ies(None, 0x0000_2000, &[REJECTED_CAUSE_IE]);
    let error =
        match s2b::decode_create_session_response_summary(&missing_teid, procedure_context()) {
            Ok(summary) => panic!("missing TEID unexpectedly projected: {summary:?}"),
            Err(error) => error,
        };
    assert_eq!(
        error,
        s2b::CreateSessionResponseSummaryError::MissingResponseTeid
    );
    assert_eq!(error.as_str(), "s2b_create_session_response_missing_teid");
    assert_eq!(error.to_string(), error.as_str());

    let malformed_cause = [IE_TYPE_CAUSE, 0x00, 0x02, 0x00, 0x46];
    let malformed = create_session_response_with_projection_ies(
        Some(0x0102_0304),
        0x0000_2000,
        &[&malformed_cause],
    );
    let error = match s2b::decode_create_session_response_summary(&malformed, procedure_context()) {
        Ok(summary) => panic!("malformed response unexpectedly projected: {summary:?}"),
        Err(error) => error,
    };
    assert_eq!(
        error,
        s2b::CreateSessionResponseSummaryError::MalformedResponse
    );
    assert_eq!(error.as_str(), "s2b_create_session_response_malformed");
    assert_eq!(error.to_string(), error.as_str());
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
fn procedure_aware_accepts_create_session_request_bearer_context_epdg_s2b_u_fteid() {
    let request = create_session_request_with_fteid_instance_and_bearer_context(
        0,
        BEARER_CONTEXT_WITH_EPDG_USER_PLANE_FTEID_IE,
    );

    let message = decode_s2b(&request);
    assert!(matches!(message, S2bMessage::CreateSessionRequest(_)));
    let view = procedure_view(&message);
    let bearer = find_ie(&view.ies, IE_TYPE_BEARER_CONTEXT);
    match &bearer.value {
        TypedIeValue::BearerContext(context) => {
            let ebi = find_ie(&context.members, IE_TYPE_EBI);
            match &ebi.value {
                TypedIeValue::EpsBearerId(value) => assert_eq!(value.value, 5),
                other => panic!("unexpected EBI value: {other:?}"),
            }

            let f_teid = find_ie(&context.members, IE_TYPE_F_TEID);
            match &f_teid.value {
                TypedIeValue::FullyQualifiedTeid(value) => {
                    assert_eq!(value.interface_type, INTERFACE_TYPE_S2B_U_EPDG_GTP_U);
                    assert_eq!(value.teid, 0x1122_3344);
                    assert_eq!(value.ipv4, Some([203, 0, 113, 10]));
                    assert_eq!(value.ipv6, None);
                }
                other => panic!("unexpected bearer F-TEID value: {other:?}"),
            }
        }
        other => panic!("unexpected Bearer Context value: {other:?}"),
    }

    let encoded = encode_s2b(&message, EncodeContext::default());
    assert_eq!(encoded.as_ref(), request.as_slice());
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
