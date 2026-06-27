use bytes::BytesMut;
use opc_proto_gtpv2c::header::{
    decode_header, encode_header, Header, HEADER_LEN_WITHOUT_TEID, HEADER_LEN_WITH_TEID,
    MAX_SEQUENCE_NUMBER,
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
    assert_eq!(message.header.spare, 0x07);
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
    assert_eq!(encoded[0], 0x48);
    assert_eq!(encoded[11], 0x00);
    assert_eq!(&encoded[12..], &bytes[12..]);
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
}

#[test]
fn header_canonical_encode_zeroes_spare_bits_and_spare_octet() {
    let header = Header {
        version: GTPV2C_VERSION,
        piggybacking: false,
        teid_flag: true,
        spare: 0x07,
        message_type: 0x20,
        length: 8,
        teid: Some(0x0102_0304),
        sequence_number: 0x0000_abcd,
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

    let truncated_teid = [0x48, 0x20, 0x00, 0x08, 0x01, 0x02, 0x03, 0x04, 0x00, 0xab, 0xcd];
    let decoded = decode_header(&truncated_teid, DecodeContext::default());
    assert!(matches!(
        decoded,
        Err(error) if matches!(error.code(), DecodeErrorCode::Truncated)
    ));
}
