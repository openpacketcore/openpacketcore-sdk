use bytes::BytesMut;
use opc_proto_ikev2::{
    decode_header, encode_header, Header, HeaderFlags, PayloadType, EXCHANGE_TYPE_IKE_SA_INIT,
    HEADER_LEN, IKEV2_MAJOR_VERSION, IKEV2_MINOR_VERSION,
};
use opc_protocol::{
    DecodeContext, DecodeErrorCode, EncodeContext, EncodeErrorCode, ValidationLevel,
};

fn strict_context() -> DecodeContext {
    DecodeContext {
        validation_level: ValidationLevel::Strict,
        ..DecodeContext::default()
    }
}

#[test]
fn decodes_and_roundtrips_fixed_header() {
    let bytes = [
        0x01,                      // RFC 7296 §3.1 octet 0: Initiator SPI byte 0.
        0x02,                      // RFC 7296 §3.1 octet 1: Initiator SPI byte 1.
        0x03,                      // RFC 7296 §3.1 octet 2: Initiator SPI byte 2.
        0x04,                      // RFC 7296 §3.1 octet 3: Initiator SPI byte 3.
        0x05,                      // RFC 7296 §3.1 octet 4: Initiator SPI byte 4.
        0x06,                      // RFC 7296 §3.1 octet 5: Initiator SPI byte 5.
        0x07,                      // RFC 7296 §3.1 octet 6: Initiator SPI byte 6.
        0x08,                      // RFC 7296 §3.1 octet 7: Initiator SPI byte 7.
        0x00,                      // RFC 7296 §3.1 octet 8: Responder SPI byte 0.
        0x00,                      // RFC 7296 §3.1 octet 9: Responder SPI byte 1.
        0x00,                      // RFC 7296 §3.1 octet 10: Responder SPI byte 2.
        0x00,                      // RFC 7296 §3.1 octet 11: Responder SPI byte 3.
        0x00,                      // RFC 7296 §3.1 octet 12: Responder SPI byte 4.
        0x00,                      // RFC 7296 §3.1 octet 13: Responder SPI byte 5.
        0x00,                      // RFC 7296 §3.1 octet 14: Responder SPI byte 6.
        0x00,                      // RFC 7296 §3.1 octet 15: Responder SPI byte 7.
        0x00,                      // RFC 7296 §3.1 octet 16: No Next Payload (IANA value 0).
        0x20,                      // RFC 7296 §3.1 octet 17: version 2.0.
        EXCHANGE_TYPE_IKE_SA_INIT, // RFC 7296 §3.1 octet 18: IKE_SA_INIT (34).
        0x08,                      // RFC 7296 §3.1 octet 19: Initiator flag set, V bit clear.
        0x00,                      // RFC 7296 §3.1 octet 20: Message ID byte 0.
        0x00,                      // RFC 7296 §3.1 octet 21: Message ID byte 1.
        0x00,                      // RFC 7296 §3.1 octet 22: Message ID byte 2.
        0x00,                      // RFC 7296 §3.1 octet 23: Message ID byte 3.
        0x00,                      // RFC 7296 §3.1 octet 24: Length byte 0.
        0x00,                      // RFC 7296 §3.1 octet 25: Length byte 1.
        0x00,                      // RFC 7296 §3.1 octet 26: Length byte 2.
        0x1c,                      // RFC 7296 §3.1 octet 27: Length byte 3 (28 octets).
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
fn canonical_encode_clears_version_and_reserved_header_flag_bits() {
    let mut header = Header::new(
        0x0102_0304_0506_0708,
        0,
        PayloadType::NoNext,
        EXCHANGE_TYPE_IKE_SA_INIT,
        HeaderFlags::new(0xbf),
        0,
    );
    header.length = HEADER_LEN as u32;

    let mut encoded = BytesMut::new();
    let result = encode_header(&header, &mut encoded, EncodeContext::default());
    assert!(result.is_ok());
    assert_eq!(encoded[19], 0x28);
}

#[test]
fn encode_header_capacity_counts_only_fixed_header_bytes() {
    let mut header = Header::new(
        0x0102_0304_0506_0708,
        0,
        PayloadType::NoNext,
        EXCHANGE_TYPE_IKE_SA_INIT,
        HeaderFlags::from_bits(true, false, false),
        0,
    );
    header.length = 4096;

    let mut encoded = BytesMut::new();
    let result = encode_header(
        &header,
        &mut encoded,
        EncodeContext {
            max_message_len: HEADER_LEN,
            ..EncodeContext::default()
        },
    );
    assert!(result.is_ok());
    assert_eq!(encoded.len(), HEADER_LEN);
    assert_eq!(&encoded[24..28], &4096u32.to_be_bytes());
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
fn strict_decode_ignores_rfc7296_version_flag_bit() {
    let mut bytes = [
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
        0x08,
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
    assert!(decoded.is_ok());

    bytes[19] = 0x18;
    let decoded = decode_header(&bytes, strict_context());
    assert!(matches!(decoded, Ok((_tail, header)) if header.flags.version()));
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

#[test]
fn header_rejects_declared_length_above_context_limit() {
    let mut bytes = [0u8; HEADER_LEN];
    bytes[17] = 0x20;
    bytes[18] = EXCHANGE_TYPE_IKE_SA_INIT;
    bytes[24..28].copy_from_slice(&((HEADER_LEN + 1) as u32).to_be_bytes());
    let decoded = decode_header(
        &bytes,
        DecodeContext {
            max_message_len: HEADER_LEN,
            ..DecodeContext::default()
        },
    );
    assert!(matches!(
        decoded,
        Err(error) if matches!(error.code(), DecodeErrorCode::MessageLengthExceeded)
    ));
}

#[test]
fn encode_header_rejects_capacity_below_fixed_header_len() {
    let header = Header::new(
        0x0102_0304_0506_0708,
        0,
        PayloadType::NoNext,
        EXCHANGE_TYPE_IKE_SA_INIT,
        HeaderFlags::from_bits(true, false, false),
        0,
    );
    let mut encoded = BytesMut::new();
    let result = encode_header(
        &header,
        &mut encoded,
        EncodeContext {
            max_message_len: HEADER_LEN - 1,
            ..EncodeContext::default()
        },
    );
    assert!(matches!(
        result,
        Err(error) if matches!(error.code(), EncodeErrorCode::CapacityExceeded { .. })
    ));
    assert!(encoded.is_empty());
}
