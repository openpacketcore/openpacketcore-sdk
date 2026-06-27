use bytes::BytesMut;
use opc_proto_gtpv2c::{validate_ie_region, Message, OwnedRawIe, RawIe, RawIeIterator};
use opc_protocol::{
    BorrowDecode, DecodeContext, DecodeErrorCode, Encode, EncodeContext, ValidationLevel,
};

fn strict_context() -> DecodeContext {
    DecodeContext {
        validation_level: ValidationLevel::Strict,
        ..DecodeContext::default()
    }
}

#[test]
fn ie_raw_unknown_ie_region_roundtrips_byte_exact() {
    let bytes = [
        0x48, 0x20, 0x00, 0x14, 0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x02, 0x00, 0xff, 0x00, 0x01,
        0x03, 0xaa, 0xfe, 0x00, 0x03, 0x25, 0xde, 0xad, 0xbe,
    ];
    let (_, message) = match Message::decode(&bytes, DecodeContext::default()) {
        Ok(value) => value,
        Err(error) => panic!("message decode failed: {error:?}"),
    };
    assert_eq!(
        message.raw_ies,
        &[0xff, 0x00, 0x01, 0x03, 0xaa, 0xfe, 0x00, 0x03, 0x25, 0xde, 0xad, 0xbe]
    );

    let mut seen = Vec::new();
    for item in message.ies() {
        let ie = match item {
            Ok(ie) => ie,
            Err(error) => panic!("raw IE decode failed: {error:?}"),
        };
        seen.push((
            ie.ie_type,
            ie.len() as u16,
            ie.instance,
            ie.spare,
            ie.value.to_vec(),
        ));
    }
    assert_eq!(
        seen,
        vec![
            (0xff, 1, 3, 0, vec![0xaa]),
            (0xfe, 3, 5, 2, vec![0xde, 0xad, 0xbe]),
        ]
    );

    let mut encoded = BytesMut::new();
    let result = message.encode(
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
fn ie_raw_borrowed_and_owned_encoding_preserve_tliv_fields() {
    let ie = RawIe {
        ie_type: 0xfe,
        instance: 0x05,
        spare: 0x0a,
        value: &[0xde, 0xad, 0xbe],
    };
    let mut encoded = BytesMut::new();
    let result = ie.encode(&mut encoded);
    assert!(result.is_ok());
    assert_eq!(
        encoded.as_ref(),
        &[0xfe, 0x00, 0x03, 0xa5, 0xde, 0xad, 0xbe]
    );

    let owned: OwnedRawIe = ie.to_owned_ie();
    let borrowed = owned.as_borrowed();
    assert_eq!(borrowed, ie);

    let mut encoded_owned = BytesMut::new();
    let result = owned.encode(&mut encoded_owned);
    assert!(result.is_ok());
    assert_eq!(encoded_owned, encoded);
}

#[test]
fn ie_raw_strict_decode_rejects_spare_bits_without_losing_structural_mode() {
    let region = [0xfe, 0x00, 0x03, 0xa5, 0xde, 0xad, 0xbe];
    let structural = validate_ie_region(&region, DecodeContext::default());
    assert!(structural.is_ok());

    let strict = validate_ie_region(&region, strict_context());
    assert!(matches!(
        strict,
        Err(error) if matches!(error.code(), DecodeErrorCode::Structural { .. })
    ));
}

#[test]
fn ie_raw_iterator_stops_after_first_malformed_element() {
    let region = [
        0xff, 0x00, 0x01, 0x00, 0xaa, // valid first IE
        0xfe, 0x00, 0x04, 0x00, 0xde, 0xad, // declared value is truncated
    ];
    let mut iter = RawIeIterator::new(&region, DecodeContext::default());
    let first = match iter.next() {
        Some(Ok(ie)) => ie,
        Some(Err(error)) => panic!("first IE decode failed: {error:?}"),
        None => panic!("first IE missing"),
    };
    assert_eq!(first.ie_type, 0xff);
    assert_eq!(first.value, [0xaa]);

    let second = iter.next();
    assert!(matches!(
        second,
        Some(Err(error)) if matches!(error.code(), DecodeErrorCode::Truncated)
    ));
    assert!(iter.next().is_none());
}
