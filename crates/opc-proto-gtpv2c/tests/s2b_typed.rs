use bytes::BytesMut;
use opc_proto_gtpv2c::{
    s2b, CauseValue, S2bMessage, TypedIe, TypedIeValue, IE_TYPE_BEARER_CONTEXT, IE_TYPE_PCO,
};
use opc_protocol::{DecodeContext, DecodeErrorCode, Encode, EncodeContext, ValidationLevel};

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
    0x00, 0x59, // Length = sequence/spare (4) + 85 octets of IEs.
    0x00, 0x10, 0x01, 0x00, // Sequence/spare.
    0x01, 0x00, 0x08, 0x00, // IMSI IE header, instance 0.
    0x00, 0x01, 0x01, 0x21, 0x43, 0x65, 0x87, 0xf9, // IMSI 001010123456789.
    0x52, 0x00, 0x01, 0x00, 0x03, // RAT Type = WLAN.
    0x53, 0x00, 0x03, 0x00, 0x00, 0xf1, 0x10, // Serving Network PLMN 001/01.
    0x57, 0x00, 0x09, 0x00, // F-TEID IE header.
    0x4a, // V4 flag + interface type 10.
    0x11, 0x22, 0x33, 0x44, // TEID/GRE key.
    0xc0, 0x00, 0x02, 0x0a, // IPv4 192.0.2.10.
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
    0x00, 0x2c, // Length = TEID/sequence/spare (8) + 36 octets of IEs.
    0x01, 0x02, 0x03, 0x04, // Header TEID.
    0x00, 0x10, 0x02, 0x00, // Sequence/spare.
    0x02, 0x00, 0x01, 0x00, 0x10, // Cause = Request accepted.
    0x57, 0x00, 0x09, 0x00, // Sender F-TEID IE.
    0x4b, 0x55, 0x66, 0x77, 0x88, 0xc0, 0x00, 0x02, 0x01, 0x4f, 0x00, 0x05, 0x00, 0x01, 0xc6, 0x33,
    0x64, 0x07, // PAA.
    0x5d, 0x00, 0x05, 0x00, 0x49, 0x00, 0x01, 0x00, 0x05, // Bearer Context/EBI.
];

const BEARER_CONTEXT_IE: &[u8] = &[
    0x5d, 0x00, 0x05, 0x00, // Bearer Context grouped IE header.
    0x49, 0x00, 0x01, 0x00, 0x05, // Nested EBI = 5.
];

const CAUSE_IE: &[u8] = &[0x02, 0x00, 0x01, 0x00, 0x10];
const EBI_IE: &[u8] = &[0x49, 0x00, 0x01, 0x00, 0x05];

const MODIFY_BEARER_REQUEST_FIXTURE: &[u8] = &[
    0x48, 0x22, 0x00, 0x11, 0x01, 0x02, 0x03, 0x04, 0x00, 0x10, 0x03, 0x00, 0x5d, 0x00, 0x05, 0x00,
    0x49, 0x00, 0x01, 0x00, 0x05,
];
const MODIFY_BEARER_RESPONSE_FIXTURE: &[u8] = &[
    0x48, 0x23, 0x00, 0x0d, 0x01, 0x02, 0x03, 0x04, 0x00, 0x10, 0x04, 0x00, 0x02, 0x00, 0x01, 0x00,
    0x10,
];
const DELETE_SESSION_REQUEST_FIXTURE: &[u8] = &[
    0x48, 0x24, 0x00, 0x0d, 0x01, 0x02, 0x03, 0x04, 0x00, 0x10, 0x05, 0x00, 0x49, 0x00, 0x01, 0x00,
    0x05,
];
const DELETE_SESSION_RESPONSE_FIXTURE: &[u8] = &[
    0x48, 0x25, 0x00, 0x0d, 0x01, 0x02, 0x03, 0x04, 0x00, 0x10, 0x06, 0x00, 0x02, 0x00, 0x01, 0x00,
    0x10,
];
const UPDATE_BEARER_REQUEST_FIXTURE: &[u8] = &[
    0x48, 0x61, 0x00, 0x11, 0x01, 0x02, 0x03, 0x04, 0x00, 0x10, 0x07, 0x00, 0x5d, 0x00, 0x05, 0x00,
    0x49, 0x00, 0x01, 0x00, 0x05,
];
const UPDATE_BEARER_RESPONSE_FIXTURE: &[u8] = &[
    0x48, 0x62, 0x00, 0x0d, 0x01, 0x02, 0x03, 0x04, 0x00, 0x10, 0x08, 0x00, 0x02, 0x00, 0x01, 0x00,
    0x10,
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
            assert_eq!(value.ipv6, None);
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
        TypedIeValue::Cause(value) => assert_eq!(value.value, CauseValue::RequestAccepted),
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
