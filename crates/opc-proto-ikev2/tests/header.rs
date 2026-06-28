use bytes::BytesMut;
use opc_proto_ikev2::{
    decode_header, encode_header, Header, HeaderFlags, PayloadType, EXCHANGE_TYPE_IKE_SA_INIT,
    HEADER_LEN, IKEV2_MAJOR_VERSION, IKEV2_MINOR_VERSION,
};
use opc_protocol::{DecodeContext, DecodeErrorCode, EncodeContext, ValidationLevel};

fn strict_context() -> DecodeContext {
    DecodeContext {
        validation_level: ValidationLevel::Strict,
        ..DecodeContext::default()
    }
}

#[test]
fn decodes_and_roundtrips_fixed_header() {
    let bytes = [
        0x01,
        0x02,
        0x03,
        0x04,
        0x05,
        0x06,
        0x07,
        0x08, // initiator SPI
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00, // responder SPI
        0x00, // no next payload
        0x20, // version 2.0
        EXCHANGE_TYPE_IKE_SA_INIT,
        0x08, // initiator flag
        0x00,
        0x00,
        0x00,
        0x00, // message id
        0x00,
        0x00,
        0x00,
        0x1c, // length 28
    ];

    let (tail, header) = match decode_header(&bytes, DecodeContext::default()) {
        Ok(value) => value,
        Err(error) => panic!("header decode failed: {error:?}"),
    };
    assert!(tail.is_empty());
    assert_eq!(header.initiator_spi, 0x0102_0304_0506_0708);
    assert_eq!(header.responder_spi, 0);
    assert_eq!(header.next_payload, PayloadType::NoNext.as_u8());
    assert_eq!(header.major_version, IKEV2_MAJOR_VERSION);
    assert_eq!(header.minor_version, IKEV2_MINOR_VERSION);
    assert!(header.flags.initiator());
    assert!(!header.flags.response());
    assert_eq!(header.length as usize, HEADER_LEN);

    let mut encoded = BytesMut::new();
    let result = encode_header(
        &header,
        &mut encoded,
        EncodeContext {
            raw_preserving: true,
            ..EncodeContext::default()
        },
    );
    assert!(result.is_ok());
    assert_eq!(encoded.as_ref(), bytes.as_slice());
}

#[test]
fn canonical_encode_clears_reserved_header_flag_bits() {
    let mut header = Header::new(
        0x0102_0304_0506_0708,
        0,
        PayloadType::NoNext.as_u8(),
        EXCHANGE_TYPE_IKE_SA_INIT,
        HeaderFlags::new(0x8f),
        0,
    );
    header.length = HEADER_LEN as u32;

    let mut encoded = BytesMut::new();
    let result = encode_header(&header, &mut encoded, EncodeContext::default());
    assert!(result.is_ok());
    assert_eq!(encoded[19], 0x08);
}

#[test]
fn strict_decode_rejects_reserved_header_flags() {
    let bytes = [
        0x01,
        0x02,
        0x03,
        0x04,
        0x05,
        0x06,
        0x07,
        0x08,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0x00,
        0x20,
        EXCHANGE_TYPE_IKE_SA_INIT,
        0x01,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0x1c,
    ];
    let decoded = decode_header(&bytes, strict_context());
    assert!(matches!(
        decoded,
        Err(error) if matches!(error.code(), DecodeErrorCode::Structural { .. })
    ));
}

#[test]
fn header_rejects_truncated_invalid_version_and_short_length() {
    let truncated = [0u8; HEADER_LEN - 1];
    let decoded = decode_header(&truncated, DecodeContext::default());
    assert!(matches!(
        decoded,
        Err(error) if matches!(error.code(), DecodeErrorCode::Truncated)
    ));

    let mut wrong_version = [0u8; HEADER_LEN];
    wrong_version[17] = 0x10;
    wrong_version[24..28].copy_from_slice(&(HEADER_LEN as u32).to_be_bytes());
    let decoded = decode_header(&wrong_version, DecodeContext::default());
    assert!(matches!(
        decoded,
        Err(error) if matches!(
            error.code(),
            DecodeErrorCode::InvalidEnumValue { field: "major_version", value: 1 }
        )
    ));

    let mut short_length = [0u8; HEADER_LEN];
    short_length[17] = 0x20;
    short_length[24..28].copy_from_slice(&27u32.to_be_bytes());
    let decoded = decode_header(&short_length, DecodeContext::default());
    assert!(matches!(
        decoded,
        Err(error) if matches!(error.code(), DecodeErrorCode::InvalidLength { .. })
    ));
}
