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

/// A `DecodeError` carries no offending element until one is attached, and
/// `with_offending_ie` attaches the identity it is given.
#[test]
fn decode_error_offending_ie_is_absent_until_attached() {
    let err = DecodeError::new(DecodeErrorCode::Truncated, 42);
    assert_eq!(err.offending_ie(), None);

    let annotated = err.with_offending_ie(73, 2);
    assert_eq!(annotated.offending_ie(), Some((73, 2)));
}

/// `with_offending_ie` is set-if-absent: a later call does not overwrite an
/// identity already attached.
///
/// This is the guarantee the accessor's documentation rests on. A decode error
/// propagates outward through whatever nesting raised it, and each enclosing
/// container gets a chance to annotate it on the way out. Keeping the first
/// attachment is what makes the innermost element -- the one that actually
/// failed to decode -- the one named, instead of whichever container annotated
/// last. 3GPP TS 29.274 requires an "Invalid length" response to carry "the
/// type and instance of the offending IE"; naming the container would put an
/// identity in the Cause IE that is not the element at fault.
///
/// Red-first proof: replacing the `is_none()` guard in `with_offending_ie`
/// with an unconditional assignment turns the `container` assertion below red
/// (`Some((93, 1))` observed where `Some((73, 2))` is required). Before this
/// test this crate had no test that so much as mentioned `offending_ie`, so
/// the guard could be deleted here without anything in `opc-protocol`
/// noticing.
#[test]
fn decode_error_offending_ie_keeps_the_first_identity_attached() {
    // Inner element: EBI (type 73) at instance 2 fails its value decode.
    let inner = DecodeError::new(
        DecodeErrorCode::InvalidLength {
            reason: "EBI IE must be one octet",
        },
        12,
    )
    .with_offending_ie(73, 2);
    assert_eq!(inner.offending_ie(), Some((73, 2)));

    // Enclosing element: Bearer Context (type 93) at instance 1 annotates the
    // same error as it propagates. The inner identity must survive.
    let container = inner.clone().with_offending_ie(93, 1);
    assert_eq!(
        container.offending_ie(),
        Some((73, 2)),
        "an enclosing element must not overwrite the innermost offending identity"
    );

    // Repeated annotation with the same identity is likewise a no-op, and no
    // other field is disturbed by the attempt.
    let twice = container.clone().with_offending_ie(93, 1);
    assert_eq!(twice, container);
    assert_eq!(twice.offset(), 12);
    assert!(matches!(
        twice.code(),
        DecodeErrorCode::InvalidLength { .. }
    ));
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

/// `DecodeError` is returned by every protocol crate in this workspace, so its
/// size is a cross-crate contract: growing it pushes callers' error enums past
/// `clippy::result_large_err` and breaks unrelated crates. Adding
/// `offending_ie` did exactly that until `offset` was narrowed to `u32` to pay
/// for it. Pin the size so the next field addition fails here, in the crate
/// that owns the type, rather than as a lint in a crate that merely uses it.
#[test]
fn decode_error_size_is_pinned() {
    assert_eq!(
        core::mem::size_of::<DecodeError>(),
        104,
        "DecodeError changed size; see the `offset` field comment before \
         adjusting this number -- growing it breaks opc-proto-pfcp and others"
    );
}

/// `offset` is stored as `u32`. The protocols this type serves bound offsets
/// by 16- and 32-bit length fields, so the range is unreachable in practice,
/// but a saturating conversion means a pathological value reports the maximum
/// rather than silently wrapping to a small, wrong offset.
#[test]
#[cfg(target_pointer_width = "64")]
fn decode_error_offset_saturates_instead_of_wrapping() {
    let huge = u32::MAX as usize + 1;
    let err = DecodeError::new(DecodeErrorCode::Truncated, huge);
    assert_eq!(err.offset(), u32::MAX as usize);

    let representable = DecodeError::new(DecodeErrorCode::Truncated, 4_294_967_294);
    assert_eq!(representable.offset(), 4_294_967_294);
}
