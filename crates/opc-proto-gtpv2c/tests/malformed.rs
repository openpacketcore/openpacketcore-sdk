use bytes::{Bytes, BytesMut};
use opc_proto_gtpv2c::{
    decode_header, validate_ie_region, Header, Message, OwnedMessage, RawIeIterator,
};
use opc_protocol::{
    BorrowDecode, DecodeContext, DecodeErrorCode, Encode, EncodeContext, EncodeErrorCode,
    OwnedDecode, ValidationLevel,
};

fn assert_decode_does_not_panic(input: &[u8]) {
    let structural = std::panic::catch_unwind(|| {
        let _ = Message::decode(input, DecodeContext::default());
    });
    assert!(
        structural.is_ok(),
        "structural message decode panicked for {input:?}"
    );

    let strict = std::panic::catch_unwind(|| {
        let ctx = DecodeContext {
            validation_level: ValidationLevel::Strict,
            ..DecodeContext::default()
        };
        let _ = Message::decode(input, ctx);
    });
    assert!(
        strict.is_ok(),
        "strict message decode panicked for {input:?}"
    );

    let owned = std::panic::catch_unwind(|| {
        let _ = OwnedMessage::decode_owned(Bytes::copy_from_slice(input), DecodeContext::default());
    });
    assert!(owned.is_ok(), "owned message decode panicked for {input:?}");

    let ies = std::panic::catch_unwind(|| {
        for item in RawIeIterator::new(input, DecodeContext::default()) {
            if item.is_err() {
                break;
            }
        }
    });
    assert!(ies.is_ok(), "raw IE iteration panicked for {input:?}");
}

#[test]
fn malformed_prefixes_and_structural_inputs_do_not_panic() {
    let valid = [
        0x48, 0x20, 0x00, 0x0d, 0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x02, 0x00, 0xff, 0x00, 0x01,
        0x00, 0xaa,
    ];
    for len in 0..valid.len() {
        assert_decode_does_not_panic(&valid[..len]);
    }

    let malformed_cases: &[&[u8]] = &[
        &[0x00, 0x01, 0xff, 0xff],
        &[0x48, 0x20, 0x00, 0x07, 0x01, 0x02, 0x03, 0x04],
        &[0x40, 0x01, 0xff, 0xff, 0x00, 0x00, 0x01, 0x00],
        &[0xff, 0xff, 0xff, 0xff, 0xff],
        &[
            0x48, 0x20, 0x00, 0x0c, 0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x02, 0x00, 0xff, 0x00,
        ],
    ];
    for input in malformed_cases {
        assert_decode_does_not_panic(input);
    }
}

#[test]
fn malformed_header_rejects_short_or_inconsistent_lengths() {
    let truncated_no_teid = [0x40, 0x01, 0x00, 0x04, 0x00, 0x00, 0x01];
    let decoded = decode_header(&truncated_no_teid, DecodeContext::default());
    assert!(matches!(
        decoded,
        Err(error) if matches!(error.code(), DecodeErrorCode::Truncated)
    ));

    let declared_shorter_than_no_teid_header = [0x40, 0x01, 0x00, 0x03, 0x00, 0x00, 0x01, 0x00];
    let decoded = decode_header(
        &declared_shorter_than_no_teid_header,
        DecodeContext::default(),
    );
    assert!(matches!(
        decoded,
        Err(error) if matches!(error.code(), DecodeErrorCode::InvalidLength { .. })
    ));

    let declared_shorter_than_teid_header = [
        0x48, 0x20, 0x00, 0x07, 0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x02, 0x00,
    ];
    let decoded = decode_header(&declared_shorter_than_teid_header, DecodeContext::default());
    assert!(matches!(
        decoded,
        Err(error) if matches!(error.code(), DecodeErrorCode::InvalidLength { .. })
    ));
}

#[test]
fn malformed_message_rejects_declared_boundary_and_limit_errors() {
    let incomplete = [
        0x48, 0x20, 0x00, 0x0d, 0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x02, 0x00, 0xff, 0x00, 0x01,
        0x00,
    ];
    let decoded = Message::decode(&incomplete, DecodeContext::default());
    assert!(matches!(
        decoded,
        Err(error) if matches!(error.code(), DecodeErrorCode::Truncated)
    ));

    let too_long = [0x40, 0x01, 0x00, 0x04, 0x00, 0x00, 0x01, 0x00];
    let ctx = DecodeContext {
        max_message_len: 7,
        ..DecodeContext::default()
    };
    let decoded = Message::decode(&too_long, ctx);
    assert!(matches!(
        decoded,
        Err(error) if matches!(error.code(), DecodeErrorCode::MessageLengthExceeded)
    ));

    let ie_count_limited = [
        0x48, 0x20, 0x00, 0x10, 0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x02, 0x00, 0xff, 0x00, 0x00,
        0x00, 0xfe, 0x00, 0x00, 0x00,
    ];
    let ctx = DecodeContext {
        max_ies: 1,
        ..DecodeContext::default()
    };
    let decoded = Message::decode(&ie_count_limited, ctx);
    assert!(matches!(
        decoded,
        Err(error) if matches!(error.code(), DecodeErrorCode::IeCountExceeded)
    ));
}

#[test]
fn malformed_ie_region_rejects_truncation_and_count_limit() {
    let truncated_value = [0xff, 0x00, 0x02, 0x00, 0xaa];
    let validated = validate_ie_region(&truncated_value, DecodeContext::default());
    assert!(matches!(
        validated,
        Err(error) if matches!(error.code(), DecodeErrorCode::Truncated)
    ));

    let ctx = DecodeContext {
        max_ies: 0,
        ..DecodeContext::default()
    };
    let validated = validate_ie_region(&[0xff, 0x00, 0x00, 0x00], ctx);
    assert!(matches!(
        validated,
        Err(error) if matches!(error.code(), DecodeErrorCode::IeCountExceeded)
    ));
}

#[test]
fn malformed_encode_fails_capacity_and_length_before_writing_message_body() {
    let message = Message {
        header: Header::with_teid(32, 0x0102_0304, 2),
        raw_ies: &[0xff, 0x00, 0x01, 0x00, 0xaa],
        tail: &[],
    };
    let mut dst = BytesMut::new();
    let ctx = EncodeContext {
        max_message_len: 16,
        ..EncodeContext::default()
    };
    let encoded = message.encode(&mut dst, ctx);
    assert!(matches!(
        encoded,
        Err(error) if matches!(error.code(), EncodeErrorCode::CapacityExceeded { .. })
    ));
    assert!(dst.is_empty());
}
