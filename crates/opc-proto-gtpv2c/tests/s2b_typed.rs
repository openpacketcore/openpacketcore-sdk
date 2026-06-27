use bytes::BytesMut;
use opc_proto_gtpv2c::{
    decode_typed_ie_sequence, s2b, CauseValue, S2bMessage, TbcdDigits, TypedIe, TypedIeValue,
    IE_TYPE_BEARER_CONTEXT, IE_TYPE_CAUSE, IE_TYPE_PCO,
};
use opc_protocol::{
    DecodeContext, DecodeErrorCode, DuplicateIePolicy, Encode, EncodeContext, ValidationLevel,
};

fn procedure_context() -> DecodeContext {
    DecodeContext {
        validation_level: ValidationLevel::ProcedureAware,
        ..DecodeContext::default()
    }
}

// TS 29.274 common header, no TEID: flags/type/length/sequence/spare.
const ECHO_REQUEST_FIXTURE: &[u8] = &[
    0x40, // Version 2, no piggybacking, no TEID, spare zero.
    0x01, // Echo Request.
    0x00, 0x04, // Length = sequence/spare only.
    0x00, 0x00, 0x01, // Sequence number 1.
    0x00, // Spare.
];

const ECHO_RESPONSE_FIXTURE: &[u8] = &[
    0x40, // Version 2, no TEID.
    0x02, // Echo Response.
    0x00, 0x09, // Length = sequence/spare + Recovery IE.
    0x00, 0x00, 0x01, 0x00, // Sequence/spare.
    0x03, // IE type 3: Recovery.
    0x00, 0x01, // IE value length.
    0x00, // IE instance 0.
    0x2a, // Restart counter.
];

// Create Session Request, no TEID header: the peer TEID is not assigned yet;
// the sender's control-plane tunnel endpoint is carried by F-TEID IE type 87.
const CREATE_SESSION_REQUEST_FIXTURE: &[u8] = &[
    0x40, // Version 2, no TEID.
    0x20, // Create Session Request (32).
    0x00, 0x69, // Length = sequence/spare (4) + 101 octets of IEs.
    0x00, 0x10, 0x01, 0x00, // Sequence/spare.
    0x01, 0x00, 0x08, 0x00, // IMSI IE header, instance 0.
    0x00, 0x01, 0x01, 0x21, 0x43, 0x65, 0x87, 0xf9, // IMSI 001010123456789.
    0x52, 0x00, 0x01, 0x00, 0x03, // RAT Type = WLAN.
    0x53, 0x00, 0x03, 0x00, 0x00, 0xf1, 0x10, // Serving Network PLMN 001/01.
    0x57, 0x00, 0x19, 0x00, // F-TEID IE header.
    0xca, // V4 and V6 flags + interface type 10.
    0x11, 0x22, 0x33, 0x44, // TEID/GRE key.
    0xc0, 0x00, 0x02, 0x0a, // IPv4 192.0.2.10.
    0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, // IPv6 2001:db8::1.
    0x47, 0x00, 0x09, 0x00, // APN IE header.
    0x08, b'i', b'n', b't', b'e', b'r', b'n', b'e', b't', // APN label "internet".
    0x80, 0x00, 0x01, 0x00, 0x00, // Selection Mode = verified.
    0x63, 0x00, 0x01, 0x00, 0x01, // PDN Type = IPv4.
    0x4f, 0x00, 0x05, 0x00, // PAA IE header.
    0x01, 0xc6, 0x33, 0x64, 0x07, // IPv4 PAA 198.51.100.7.
    0x5d, 0x00, 0x05, 0x00, // Bearer Context grouped IE header.
    0x49, 0x00, 0x01, 0x00, 0x05, // Nested EBI = 5.
    0x4e, 0x00, 0x03, 0x02, // Unsupported PCO IE, instance 2.
    0x80, 0x21, 0x00, // PCO bytes preserved as raw fallback.
];

const CREATE_SESSION_RESPONSE_FIXTURE: &[u8] = &[
    0x48, // Version 2, TEID present.
    0x21, // Create Session Response (33).
    0x00, 0x2d, // Length = TEID/sequence/spare (8) + 37 octets of IEs.
    0x01, 0x02, 0x03, 0x04, // Header TEID.
    0x00, 0x10, 0x02, 0x00, // Sequence/spare.
    0x02, 0x00, 0x02, 0x00, 0x10, 0x00, // Cause = Request accepted, flags zero.
    0x57, 0x00, 0x09, 0x00, // Sender F-TEID IE.
    0x8b, 0x55, 0x66, 0x77, 0x88, 0xc0, 0x00, 0x02, 0x01, 0x4f, 0x00, 0x05, 0x00, 0x01, 0xc6, 0x33,
    0x64, 0x07, // PAA.
    0x5d, 0x00, 0x05, 0x00, 0x49, 0x00, 0x01, 0x00, 0x05, // Bearer Context/EBI.
];

const BEARER_CONTEXT_IE: &[u8] = &[
    0x5d, 0x00, 0x05, 0x00, // Bearer Context grouped IE header.
    0x49, 0x00, 0x01, 0x00, 0x05, // Nested EBI = 5.
];

const CAUSE_IE: &[u8] = &[0x02, 0x00, 0x02, 0x00, 0x10, 0x00];
const EBI_IE: &[u8] = &[0x49, 0x00, 0x01, 0x00, 0x05];

const MODIFY_BEARER_REQUEST_FIXTURE: &[u8] = &[
    0x48, 0x22, 0x00, 0x11, 0x01, 0x02, 0x03, 0x04, 0x00, 0x10, 0x03, 0x00, 0x5d, 0x00, 0x05, 0x00,
    0x49, 0x00, 0x01, 0x00, 0x05,
];
const MODIFY_BEARER_RESPONSE_FIXTURE: &[u8] = &[
    0x48, 0x23, 0x00, 0x0e, 0x01, 0x02, 0x03, 0x04, 0x00, 0x10, 0x04, 0x00, 0x02, 0x00, 0x02, 0x00,
    0x10, 0x00,
];
const DELETE_SESSION_REQUEST_FIXTURE: &[u8] = &[
    0x48, 0x24, 0x00, 0x0d, 0x01, 0x02, 0x03, 0x04, 0x00, 0x10, 0x05, 0x00, 0x49, 0x00, 0x01, 0x00,
    0x05,
];
const DELETE_SESSION_RESPONSE_FIXTURE: &[u8] = &[
    0x48, 0x25, 0x00, 0x0e, 0x01, 0x02, 0x03, 0x04, 0x00, 0x10, 0x06, 0x00, 0x02, 0x00, 0x02, 0x00,
    0x10, 0x00,
];
const UPDATE_BEARER_REQUEST_FIXTURE: &[u8] = &[
    0x48, 0x61, 0x00, 0x11, 0x01, 0x02, 0x03, 0x04, 0x00, 0x10, 0x07, 0x00, 0x5d, 0x00, 0x05, 0x00,
    0x49, 0x00, 0x01, 0x00, 0x05,
];
const UPDATE_BEARER_RESPONSE_FIXTURE: &[u8] = &[
    0x48, 0x62, 0x00, 0x0e, 0x01, 0x02, 0x03, 0x04, 0x00, 0x10, 0x08, 0x00, 0x02, 0x00, 0x02, 0x00,
    0x10, 0x00,
];

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
        }
        other => panic!("unexpected Bearer Context value: {other:?}"),
    }

    let pco = find_ie(&view.ies, IE_TYPE_PCO);
    match &pco.value {
        TypedIeValue::Raw(raw) => {
            assert_eq!(raw.ie_type, IE_TYPE_PCO);
            assert_eq!(raw.instance, 2);
            assert_eq!(raw.value, [0x80, 0x21, 0x00]);
        }
        other => panic!("unexpected PCO fallback value: {other:?}"),
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
        0x5d, 0x00, 0x0a, 0x00, // Bearer Context containing two EBI members.
        0x49, 0x00, 0x01, 0x00, 0x05, 0x49, 0x00, 0x01, 0x00, 0x06,
    ];
    assert_duplicate_rejected(decode_typed_ie_sequence(
        &duplicate_group_member,
        duplicate_context(DuplicateIePolicy::Reject),
        0,
    ));
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

#[test]
fn procedure_aware_validation_rejects_missing_mandatory_ies_for_every_claimed_pair() {
    let mut cases: Vec<Vec<u8>> = Vec::new();
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
