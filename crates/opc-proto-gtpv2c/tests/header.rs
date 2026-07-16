use bytes::BytesMut;
use opc_proto_gtpv2c::header::{
    decode_header, encode_header, Header, MessagePriority, HEADER_LEN_WITHOUT_TEID,
    HEADER_LEN_WITH_TEID, MAX_MESSAGE_PRIORITY, MAX_SEQUENCE_NUMBER,
};
use opc_proto_gtpv2c::{Message, GTPV2C_VERSION};
use opc_protocol::{
    BorrowDecode, DecodeContext, DecodeErrorCode, Encode, EncodeContext, EncodeErrorCode,
    ValidationLevel,
};

fn strict_context() -> DecodeContext {
    DecodeContext {
        validation_level: ValidationLevel::Strict,
        ..DecodeContext::default()
    }
}

fn parse_hex_fixture(source: &str) -> Vec<u8> {
    match source
        .split_ascii_whitespace()
        .map(|octet| u8::from_str_radix(octet, 16))
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(bytes) => bytes,
        Err(error) => panic!("invalid hexadecimal fixture: {error}"),
    }
}

#[test]
fn header_decodes_no_teid_and_teid_layouts() {
    let echo_request = [0x40, 0x01, 0x00, 0x04, 0x00, 0x00, 0x01, 0x00];
    let (tail, header) = match decode_header(&echo_request, DecodeContext::default()) {
        Ok(value) => value,
        Err(error) => panic!("no-TEID header decode failed: {error:?}"),
    };
    assert!(tail.is_empty());
    assert_eq!(header.version, GTPV2C_VERSION);
    assert!(!header.teid_flag);
    assert_eq!(header.length, 4);
    assert_eq!(header.teid, None);
    assert_eq!(header.sequence_number, 1);
    assert!(!header.message_priority_flag);
    assert_eq!(header.message_priority, None);
    assert_eq!(header.wire_len(), HEADER_LEN_WITHOUT_TEID);

    let create_session = [
        0x48, 0x20, 0x00, 0x08, 0x01, 0x02, 0x03, 0x04, 0x00, 0xab, 0xcd, 0x00,
    ];
    let (tail, header) = match decode_header(&create_session, DecodeContext::default()) {
        Ok(value) => value,
        Err(error) => panic!("TEID header decode failed: {error:?}"),
    };
    assert!(tail.is_empty());
    assert!(header.teid_flag);
    assert_eq!(header.length, 8);
    assert_eq!(header.teid, Some(0x0102_0304));
    assert_eq!(header.sequence_number, 0x0000_abcd);
    assert!(!header.message_priority_flag);
    assert_eq!(header.message_priority, None);
    assert_eq!(header.wire_len(), HEADER_LEN_WITH_TEID);
}

#[test]
fn header_raw_preserving_roundtrip_keeps_spare_bits_and_tail_boundary() {
    let bytes = [
        0x4f, 0x20, 0x00, 0x0d, 0x0a, 0x0b, 0x0c, 0x0d, 0x00, 0x00, 0x02, 0xee, 0xfe, 0x00, 0x01,
        0xa5, 0x99, 0xde, 0xad,
    ];
    let (tail, message) = match Message::decode(&bytes, DecodeContext::default()) {
        Ok(value) => value,
        Err(error) => panic!("message decode failed: {error:?}"),
    };
    assert_eq!(tail, [0xde, 0xad]);
    assert_eq!(message.tail, [0xde, 0xad]);
    assert!(message.header.message_priority_flag);
    assert_eq!(
        message.header.message_priority.map(MessagePriority::get),
        Some(14)
    );
    assert_eq!(message.header.spare, 0x03);
    assert_eq!(message.header.spare_octet, 0xee);

    let mut encoded = BytesMut::new();
    let result = message.encode(
        &mut encoded,
        EncodeContext {
            raw_preserving: true,
            ..EncodeContext::default()
        },
    );
    assert!(result.is_ok());
    assert_eq!(encoded.as_ref(), &bytes[..17]);
}

#[test]
fn header_canonical_message_encode_zeroes_spares_but_preserves_raw_ie_region() {
    let bytes = [
        0x4f, 0x20, 0x00, 0x0d, 0x0a, 0x0b, 0x0c, 0x0d, 0x00, 0x00, 0x02, 0xee, 0xfe, 0x00, 0x01,
        0xa5, 0x99,
    ];
    let (_, message) = match Message::decode(&bytes, DecodeContext::default()) {
        Ok(value) => value,
        Err(error) => panic!("message decode failed: {error:?}"),
    };

    let mut encoded = BytesMut::new();
    let result = message.encode(&mut encoded, EncodeContext::default());
    assert!(result.is_ok());
    assert_eq!(encoded[0], 0x4c);
    assert_eq!(encoded[11], 0xe0);
    assert_eq!(&encoded[12..], &bytes[12..]);
}

#[test]
fn raw_mode_preserves_ignored_priority_nibble_when_mp_is_clear() {
    let bytes = [
        0x48, 0x20, 0x00, 0x08, 0x01, 0x02, 0x03, 0x04, 0x00, 0xab, 0xcd, 0x7a,
    ];
    let (tail, header) = match decode_header(&bytes, DecodeContext::default()) {
        Ok(value) => value,
        Err(error) => panic!("non-strict ignored-priority decode failed: {error:?}"),
    };
    assert!(tail.is_empty());
    assert!(!header.message_priority_flag);
    assert_eq!(header.message_priority(), None);
    assert_eq!(header.spare_octet, 0x7a);

    let mut raw = BytesMut::new();
    assert!(encode_header(
        &header,
        &mut raw,
        EncodeContext {
            raw_preserving: true,
            ..EncodeContext::default()
        },
    )
    .is_ok());
    assert_eq!(raw.as_ref(), bytes.as_slice());

    let mut canonical = BytesMut::new();
    assert!(encode_header(&header, &mut canonical, EncodeContext::default()).is_ok());
    assert_eq!(canonical[11], 0);
}

#[test]
fn strict_header_accepts_full_message_priority_range() {
    for (wire_priority, expected) in [(0x00, 0), (0x70, 7), (0xf0, 15)] {
        let bytes = [
            0x4c,
            0x20,
            0x00,
            0x08,
            0x01,
            0x02,
            0x03,
            0x04,
            0x00,
            0xab,
            0xcd,
            wire_priority,
        ];
        let (tail, header) = match decode_header(&bytes, strict_context()) {
            Ok(value) => value,
            Err(error) => panic!("valid Message Priority header failed: {error:?}"),
        };
        assert!(tail.is_empty());
        assert!(header.message_priority_flag);
        assert_eq!(
            header.message_priority.map(MessagePriority::get),
            Some(expected)
        );

        let mut canonical = BytesMut::new();
        assert!(encode_header(&header, &mut canonical, EncodeContext::default()).is_ok());
        assert_eq!(canonical.as_ref(), bytes.as_slice());
    }
}

#[test]
fn spec_message_priority_fixtures_decode_strictly() {
    let fixtures = [
        (
            include_str!("fixtures/spec/message_priority_highest_header.hex"),
            MessagePriority::HIGHEST,
        ),
        (
            include_str!("fixtures/spec/message_priority_lowest_header.hex"),
            MessagePriority::LOWEST,
        ),
    ];

    for (source, expected) in fixtures {
        let bytes = parse_hex_fixture(source);
        let (tail, header) = match decode_header(&bytes, strict_context()) {
            Ok(value) => value,
            Err(error) => panic!("spec Message Priority fixture failed: {error:?}"),
        };
        assert!(tail.is_empty());
        assert!(header.message_priority_flag);
        assert_eq!(header.message_priority, Some(expected));
    }
}

#[test]
fn message_priority_type_and_builder_are_bounded_and_canonical() {
    let highest = match MessagePriority::new(0) {
        Ok(value) => value,
        Err(error) => panic!("priority zero was rejected: {error}"),
    };
    let lowest = match MessagePriority::new(MAX_MESSAGE_PRIORITY) {
        Ok(value) => value,
        Err(error) => panic!("priority 15 was rejected: {error}"),
    };
    assert_eq!(highest, MessagePriority::HIGHEST);
    assert_eq!(lowest, MessagePriority::LOWEST);
    assert_eq!(u8::from(lowest), MAX_MESSAGE_PRIORITY);
    let error = match MessagePriority::new(MAX_MESSAGE_PRIORITY + 1) {
        Ok(value) => panic!("out-of-range priority was accepted: {value:?}"),
        Err(error) => error,
    };
    assert_eq!(error.value(), 16);
    assert_eq!(
        error.to_string(),
        "GTPv2-C message priority must be between 0 and 15 inclusive"
    );

    let mut header = Header::with_teid(32, 0x0102_0304, 0x0000_abcd)
        .with_message_priority(MessagePriority::HIGHEST);
    header.length = 8;
    assert!(header.message_priority_flag);
    assert_eq!(header.message_priority, Some(MessagePriority::HIGHEST));

    let mut encoded = BytesMut::new();
    assert!(encode_header(&header, &mut encoded, EncodeContext::default()).is_ok());
    assert_eq!(encoded[0], 0x4c);
    assert_eq!(encoded[11], 0x00);

    header.set_message_priority(Some(MessagePriority::LOWEST));
    encoded.clear();
    assert!(encode_header(&header, &mut encoded, EncodeContext::default()).is_ok());
    assert_eq!(encoded[11], 0xf0);

    header.set_message_priority(None);
    encoded.clear();
    assert!(encode_header(&header, &mut encoded, EncodeContext::default()).is_ok());
    assert_eq!(encoded[0], 0x48);
    assert_eq!(encoded[11], 0x00);

    let copied = Header::with_teid(34, 0x0506_0708, 0x000102)
        .with_optional_message_priority(header.message_priority());
    assert_eq!(copied.message_priority(), None);
    let copied = copied.with_optional_message_priority(Some(MessagePriority::LOWEST));
    assert!(copied.message_priority_flag);
    assert_eq!(copied.message_priority(), Some(MessagePriority::LOWEST));
}

#[test]
fn header_debug_redacts_tunnel_identifier() {
    let header = Header::with_teid(32, 0x0102_0304, 0x0000_abcd)
        .with_message_priority(MessagePriority::LOWEST);
    let debug = format!("{header:?}");

    assert!(debug.contains("teid_flag: true"));
    assert!(debug.contains("teid_present: true"));
    assert!(debug.contains("message_priority: Some(MessagePriority(15))"));
    assert!(!debug.contains("16909060"));
    assert!(!debug.contains("teid: "));
}

#[test]
fn missing_teid_encode_is_structured_and_does_not_write() {
    let mut header = Header::with_teid(32, 0x0102_0304, 1);
    header.teid = None;
    let mut encoded = BytesMut::new();
    let error = match encode_header(&header, &mut encoded, EncodeContext::default()) {
        Ok(()) => panic!("inconsistent TEID header unexpectedly encoded"),
        Err(error) => error,
    };

    assert!(encoded.is_empty());
    assert!(matches!(
        error.code(),
        EncodeErrorCode::Structural {
            reason: "TEID flag set without TEID value"
        }
    ));
    let spec = match error.spec_ref() {
        Some(spec) => spec,
        None => panic!("TEID encode error omitted its specification reference"),
    };
    assert_eq!(spec.doc(), "TS29274");
    assert_eq!(spec.section(), "5.1");
}

#[test]
fn header_strict_decode_rejects_spares_and_encode_rejects_bad_shape() {
    let spare_flags = [0x41, 0x01, 0x00, 0x04, 0x00, 0x00, 0x01, 0x00];
    let decoded = decode_header(&spare_flags, strict_context());
    assert!(matches!(
        decoded,
        Err(error) if matches!(error.code(), DecodeErrorCode::Structural { .. })
    ));

    let spare_octet = [0x40, 0x01, 0x00, 0x04, 0x00, 0x00, 0x01, 0x01];
    let decoded = decode_header(&spare_octet, strict_context());
    assert!(matches!(
        decoded,
        Err(error) if matches!(error.code(), DecodeErrorCode::Structural { .. })
    ));

    let mp_clear_with_value = [
        0x48, 0x20, 0x00, 0x08, 0x01, 0x02, 0x03, 0x04, 0x00, 0xab, 0xcd, 0x70,
    ];
    let decoded = decode_header(&mp_clear_with_value, strict_context());
    assert!(matches!(
        decoded,
        Err(error) if matches!(error.code(), DecodeErrorCode::Structural { .. })
    ));

    let mp_with_spare_nibble = [
        0x4c, 0x20, 0x00, 0x08, 0x01, 0x02, 0x03, 0x04, 0x00, 0xab, 0xcd, 0x71,
    ];
    let decoded = decode_header(&mp_with_spare_nibble, strict_context());
    assert!(matches!(
        decoded,
        Err(error) if matches!(error.code(), DecodeErrorCode::Structural { .. })
    ));

    let mut no_teid = Header::without_teid(1, MAX_SEQUENCE_NUMBER + 1);
    no_teid.length = 4;
    let mut dst = BytesMut::new();
    let encoded = encode_header(&no_teid, &mut dst, EncodeContext::default());
    assert!(matches!(
        encoded,
        Err(error) if matches!(error.code(), EncodeErrorCode::Structural { .. })
    ));

    let mut inconsistent = Header::with_teid(32, 0x0102_0304, 1);
    inconsistent.teid = None;
    let encoded = encode_header(&inconsistent, &mut dst, EncodeContext::default());
    assert!(matches!(
        encoded,
        Err(error) if matches!(error.code(), EncodeErrorCode::Structural { .. })
    ));

    let mut value_without_flag = Header::without_teid(32, 1);
    value_without_flag.teid = Some(0x0102_0304);
    let encoded = encode_header(&value_without_flag, &mut dst, EncodeContext::default());
    assert!(matches!(
        encoded,
        Err(error) if matches!(error.code(), EncodeErrorCode::Structural { .. })
    ));

    let mut bad_version = Header::without_teid(1, 1);
    bad_version.version = 1;
    let ctx = EncodeContext {
        raw_preserving: true,
        ..EncodeContext::default()
    };
    let encoded = encode_header(&bad_version, &mut dst, ctx);
    assert!(matches!(
        encoded,
        Err(error) if matches!(error.code(), EncodeErrorCode::Structural { .. })
    ));

    let mut missing_priority = Header::with_teid(32, 0x0102_0304, 1);
    missing_priority.message_priority_flag = true;
    let encoded = encode_header(&missing_priority, &mut dst, EncodeContext::default());
    assert!(matches!(
        encoded,
        Err(error) if matches!(error.code(), EncodeErrorCode::Structural { .. })
    ));

    let priority = match MessagePriority::new(7) {
        Ok(value) => value,
        Err(error) => panic!("priority seven was rejected: {error}"),
    };
    let mut missing_flag = Header::with_teid(32, 0x0102_0304, 1);
    missing_flag.message_priority = Some(priority);
    let encoded = encode_header(&missing_flag, &mut dst, EncodeContext::default());
    assert!(matches!(
        encoded,
        Err(error) if matches!(error.code(), EncodeErrorCode::Structural { .. })
    ));

    let no_teid_priority = Header::without_teid(1, 1).with_message_priority(priority);
    let encoded = encode_header(&no_teid_priority, &mut dst, EncodeContext::default());
    assert!(matches!(
        encoded,
        Err(error) if matches!(error.code(), EncodeErrorCode::Structural { .. })
    ));
}

#[test]
fn header_canonical_encode_zeroes_spare_bits_and_spare_octet() {
    let header = Header {
        version: GTPV2C_VERSION,
        piggybacking: false,
        teid_flag: true,
        message_priority_flag: false,
        spare: 0x07,
        message_type: 0x20,
        length: 8,
        teid: Some(0x0102_0304),
        sequence_number: 0x0000_abcd,
        message_priority: None,
        spare_octet: 0xee,
    };
    let mut dst = BytesMut::new();
    let encoded = encode_header(&header, &mut dst, EncodeContext::default());
    assert!(encoded.is_ok());
    assert_eq!(dst[0], 0x48);
    assert_eq!(dst[11], 0x00);
}

#[test]
fn header_decode_rejects_truncated_and_under_length_inputs() {
    let truncated_no_teid = [0x40, 0x01, 0x00, 0x04, 0x00, 0x00, 0x01];
    let decoded = decode_header(&truncated_no_teid, DecodeContext::default());
    assert!(matches!(
        decoded,
        Err(error) if matches!(error.code(), DecodeErrorCode::Truncated)
    ));

    let declared_shorter_than_header = [0x40, 0x01, 0x00, 0x03, 0x00, 0x00, 0x01, 0x00];
    let decoded = decode_header(&declared_shorter_than_header, DecodeContext::default());
    assert!(matches!(
        decoded,
        Err(error) if matches!(error.code(), DecodeErrorCode::InvalidLength { .. })
    ));

    let truncated_teid = [
        0x48, 0x20, 0x00, 0x08, 0x01, 0x02, 0x03, 0x04, 0x00, 0xab, 0xcd,
    ];
    let decoded = decode_header(&truncated_teid, DecodeContext::default());
    assert!(matches!(
        decoded,
        Err(error) if matches!(error.code(), DecodeErrorCode::Truncated)
    ));
}

#[test]
fn header_decode_rejects_non_v2_version() {
    // Version 7 in the top three bits of the flags octet (0xe0).
    let bytes = [0xe0, 0x01, 0x00, 0x04, 0x00, 0x00, 0x01, 0x00];
    let decoded = decode_header(&bytes, DecodeContext::default());
    assert!(matches!(
        decoded,
        Err(error) if matches!(
            error.code(),
            DecodeErrorCode::InvalidEnumValue { field: "version", value: 7 }
        )
    ));
}

#[test]
fn header_decodes_and_preserves_piggybacking_flag() {
    // Piggybacking bit (0x10) set together with TEID flag (0x08) -> flags 0x58.
    let bytes = [
        0x58, 0x20, 0x00, 0x08, 0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x02, 0x00,
    ];
    let (tail, header) = match decode_header(&bytes, DecodeContext::default()) {
        Ok(value) => value,
        Err(error) => panic!("piggybacking header decode failed: {error:?}"),
    };
    assert!(tail.is_empty());
    assert!(header.piggybacking);
    assert!(header.teid_flag);
    assert_eq!(header.teid, Some(0x0102_0304));

    let mut dst = BytesMut::new();
    let encoded = encode_header(
        &header,
        &mut dst,
        EncodeContext {
            raw_preserving: true,
            ..EncodeContext::default()
        },
    );
    assert!(encoded.is_ok());
    assert_eq!(dst.as_ref(), bytes.as_slice());
}
