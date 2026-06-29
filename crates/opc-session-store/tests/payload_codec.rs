use opc_session_store::{
    decode_json_payload, encode_json_payload, encode_session_payload_envelope,
    validate_session_payload_size, validate_session_payload_size_for_backend, BackendCapabilities,
    EncryptedSessionPayload, SessionPayloadCodecError, SessionPayloadEnvelope,
    SessionPayloadFormat, SessionPayloadVersion,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ProductCheckpoint {
    state: String,
    generation: u64,
}

fn test_format() -> SessionPayloadFormat {
    SessionPayloadFormat::from_static("test/checkpoint")
}

#[test]
fn json_payload_round_trips_through_sdk_envelope() {
    let dto = ProductCheckpoint {
        state: "attached".to_string(),
        generation: 7,
    };

    let payload = encode_json_payload(&test_format(), SessionPayloadVersion::new(1), &dto, None)
        .expect("encode payload");
    let decoded: ProductCheckpoint = decode_json_payload(
        &payload,
        &test_format(),
        SessionPayloadVersion::new(1),
        None,
    )
    .expect("decode payload");

    assert_eq!(decoded, dto);
}

#[test]
fn wrong_format_fails_closed_without_echoing_format() {
    let dto = ProductCheckpoint {
        state: "attached".to_string(),
        generation: 7,
    };
    let payload = encode_json_payload(
        &SessionPayloadFormat::from_static("other/checkpoint"),
        SessionPayloadVersion::new(1),
        &dto,
        None,
    )
    .expect("encode payload");

    let err = decode_json_payload::<ProductCheckpoint>(
        &payload,
        &test_format(),
        SessionPayloadVersion::new(1),
        None,
    )
    .expect_err("wrong format must fail");

    assert_eq!(err, SessionPayloadCodecError::FormatMismatch);
    assert_eq!(err.code(), "format_mismatch");
    assert!(!format!("{err:?}").contains("other/checkpoint"));
    assert!(!err.to_string().contains("other/checkpoint"));
}

#[test]
fn unsupported_version_reports_stable_numeric_metadata() {
    let dto = ProductCheckpoint {
        state: "attached".to_string(),
        generation: 7,
    };
    let payload = encode_json_payload(&test_format(), SessionPayloadVersion::new(2), &dto, None)
        .expect("encode payload");

    let err = decode_json_payload::<ProductCheckpoint>(
        &payload,
        &test_format(),
        SessionPayloadVersion::new(1),
        None,
    )
    .expect_err("unsupported version must fail");

    assert_eq!(
        err,
        SessionPayloadCodecError::UnsupportedVersion {
            expected: 1,
            actual: 2
        }
    );
    assert_eq!(err.code(), "unsupported_version");
}

#[test]
fn malformed_envelope_fails_closed_without_payload_leakage() {
    let payload = EncryptedSessionPayload::new(br#"{"format":"test/checkpoint","body":"imsi-001"#);

    let err = decode_json_payload::<ProductCheckpoint>(
        &payload,
        &test_format(),
        SessionPayloadVersion::new(1),
        None,
    )
    .expect_err("malformed envelope must fail");

    assert_eq!(err, SessionPayloadCodecError::MalformedEnvelope);
    assert_eq!(err.code(), "malformed_envelope");
    assert!(!format!("{err:?}").contains("imsi-001"));
    assert!(!err.to_string().contains("imsi-001"));
}

#[test]
fn malformed_product_body_fails_closed_without_payload_leakage() {
    let envelope = SessionPayloadEnvelope::new(
        test_format(),
        SessionPayloadVersion::new(1),
        br#"{"state":"imsi-001""#.to_vec(),
    );
    let payload = encode_session_payload_envelope(&envelope, None).expect("encode envelope");

    let err = decode_json_payload::<ProductCheckpoint>(
        &payload,
        &test_format(),
        SessionPayloadVersion::new(1),
        None,
    )
    .expect_err("malformed product body must fail");

    assert_eq!(err, SessionPayloadCodecError::MalformedBody);
    assert_eq!(err.code(), "malformed_body");
    assert!(!format!("{err:?}").contains("imsi-001"));
    assert!(!err.to_string().contains("imsi-001"));
}

#[test]
fn unsupported_content_type_fails_closed() {
    let envelope = SessionPayloadEnvelope::new(
        test_format(),
        SessionPayloadVersion::new(1),
        br#"{"state":"attached","generation":7}"#.to_vec(),
    )
    .with_content_type("application/octet-stream")
    .expect("valid content type");
    let payload = encode_session_payload_envelope(&envelope, None).expect("encode envelope");

    let err = decode_json_payload::<ProductCheckpoint>(
        &payload,
        &test_format(),
        SessionPayloadVersion::new(1),
        None,
    )
    .expect_err("unsupported content type must fail");

    assert_eq!(err, SessionPayloadCodecError::UnsupportedContentType);
    assert_eq!(err.code(), "unsupported_content_type");
}

#[test]
fn max_size_is_enforced_for_encode_decode_and_backend_validation() {
    let dto = ProductCheckpoint {
        state: "attached".repeat(16),
        generation: 7,
    };
    let payload = encode_json_payload(&test_format(), SessionPayloadVersion::new(1), &dto, None)
        .expect("encode payload");
    let too_small = payload.len() - 1;

    let encode_err = encode_json_payload(
        &test_format(),
        SessionPayloadVersion::new(1),
        &dto,
        Some(too_small),
    )
    .expect_err("encode must enforce max size");
    assert_eq!(
        encode_err,
        SessionPayloadCodecError::PayloadTooLarge {
            max: too_small,
            actual: payload.len()
        }
    );

    let decode_err = decode_json_payload::<ProductCheckpoint>(
        &payload,
        &test_format(),
        SessionPayloadVersion::new(1),
        Some(too_small),
    )
    .expect_err("decode must enforce max size before parsing");
    assert_eq!(
        decode_err,
        SessionPayloadCodecError::PayloadTooLarge {
            max: too_small,
            actual: payload.len()
        }
    );

    let validate_err =
        validate_session_payload_size(&payload, too_small).expect_err("size validation");
    assert_eq!(validate_err.code(), "payload_too_large");

    let mut capabilities = BackendCapabilities::all_enabled();
    capabilities.max_value_bytes = too_small;
    let backend_err = validate_session_payload_size_for_backend(&payload, &capabilities)
        .expect_err("backend size validation");
    assert_eq!(backend_err.code(), "payload_too_large");
}

#[test]
fn envelope_debug_reports_body_length_not_body_bytes() {
    let envelope = SessionPayloadEnvelope::new(
        test_format(),
        SessionPayloadVersion::new(1),
        b"subscriber-secret-body".to_vec(),
    );

    let debug = format!("{envelope:?}");
    assert!(debug.contains("body_len"));
    assert!(!debug.contains("subscriber-secret-body"));
}
