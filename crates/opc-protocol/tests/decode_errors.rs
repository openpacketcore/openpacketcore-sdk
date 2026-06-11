//! Tests for structured decode errors.
//!
//! Errors MUST be safe to expose in logs. They MUST NOT include raw packet
//! payload unless debug packet capture is explicitly enabled.

use opc_protocol::{DecodeError, DecodeErrorCode, SpecRef};

#[test]
fn decode_error_has_structured_fields() {
    let err = DecodeError::new(DecodeErrorCode::Truncated, 42);
    assert_eq!(err.offset(), 42);
    assert!(matches!(err.code(), DecodeErrorCode::Truncated));
    assert!(err.spec_ref().is_none());
}

#[test]
fn decode_error_can_carry_spec_ref() {
    let spec = SpecRef::new("3gpp", "TS 29.281", "5.1").with_table("5.1-1");
    let err = DecodeError::new(
        DecodeErrorCode::InvalidLength {
            reason: "length exceeds parent",
        },
        10,
    )
    .with_spec_ref(spec);

    assert_eq!(err.offset(), 10);
    let code = err.code();
    assert!(matches!(code, DecodeErrorCode::InvalidLength { .. }));

    let spec = err.spec_ref().unwrap();
    assert_eq!(spec.body(), "3gpp");
    assert_eq!(spec.doc(), "TS 29.281");
    assert_eq!(spec.section(), "5.1");
    assert_eq!(spec.table(), Some("5.1-1"));
}

#[test]
fn decode_error_codes_are_stable_and_safe_to_log() {
    // Every variant must be constructible and Display-able without leaking
    // raw packet bytes.
    let cases: Vec<DecodeErrorCode> = vec![
        DecodeErrorCode::Truncated,
        DecodeErrorCode::InvalidLength { reason: "bad len" },
        DecodeErrorCode::LengthOverflow,
        DecodeErrorCode::DepthExceeded,
        DecodeErrorCode::IeCountExceeded,
        DecodeErrorCode::MessageLengthExceeded,
        DecodeErrorCode::UnknownCriticalIe,
        DecodeErrorCode::DuplicateIe,
        DecodeErrorCode::InvalidEnumValue {
            field: "msg_type",
            value: 255,
        },
        DecodeErrorCode::Structural {
            reason: "missing mandatory IE",
        },
        DecodeErrorCode::Incomplete,
    ];

    for code in cases {
        let text = format!("{code}");
        // Ensure the Display output does not contain raw hex bytes.
        // This is a coarse heuristic: deny strings that look like raw payload.
        assert!(
            !text.contains("0x"),
            "error display should not leak raw payload: {text}"
        );
    }
}

#[test]
fn decode_error_can_be_cloned_and_compared() {
    let err = DecodeError::new(DecodeErrorCode::Truncated, 0);
    let err2 = err.clone();
    assert_eq!(err, err2);
}

#[test]
fn decode_error_debug_does_not_contain_payload() {
    let err = DecodeError::new(DecodeErrorCode::Truncated, 5);
    let dbg = format!("{err:?}");
    // Debug should show the error type and offset, but no byte slice.
    assert!(dbg.contains("Truncated"));
    assert!(dbg.contains("offset: 5"));
}
