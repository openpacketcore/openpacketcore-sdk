use bytes::{BufMut, BytesMut};
use opc_proto_diameter::dictionary::{AvpDataType, AvpDefinition, AvpFlagRules, AvpKey};
use opc_proto_diameter::{
    validate_avp_region, validate_avp_region_with_dictionary, ApplicationId, AvpCode, AvpFlags,
    AvpHeader, CommandCode, CommandFlags, Dictionary, DictionarySet, Header, Message, RawAvp,
    AVP_HEADER_LEN, DIAMETER_HEADER_LEN,
};
use opc_protocol::{
    BorrowDecode, DecodeContext, DecodeErrorCode, DuplicateIePolicy, Encode, EncodeContext,
};
use opc_protocol::{SpecRef, ValidationLevel};

static TEST_AVPS: [AvpDefinition; 1] = [AvpDefinition::new(
    AvpKey::ietf(AvpCode::new(279)),
    "Failed-AVP",
    AvpDataType::Grouped,
    AvpFlagRules::base_mandatory(),
    SpecRef::new("ietf", "RFC6733", "7.5"),
)];

static TEST_DICTIONARY: Dictionary =
    Dictionary::new("diameter-codec-core-test", &[], &[], &TEST_AVPS);

fn dictionary_set() -> DictionarySet<'static> {
    static DICTIONARIES: [&Dictionary; 1] = [&TEST_DICTIONARY];
    DictionarySet::new(&DICTIONARIES)
}

fn encode_raw_avp(header: AvpHeader, value: &[u8]) -> BytesMut {
    let avp = RawAvp {
        header,
        value,
        padding: &[],
    };
    let mut encoded = BytesMut::new();
    if let Err(error) = avp.encode(&mut encoded, EncodeContext::default()) {
        panic!("raw AVP encode failed: {error}");
    }
    encoded
}

fn encode_message(raw_avps: &[u8]) -> BytesMut {
    let header = Header::new(
        CommandFlags::request(false),
        CommandCode::new(257),
        ApplicationId::new(0),
        0x0102_0304,
        0xA0B0_C0D0,
    )
    .with_length((DIAMETER_HEADER_LEN + raw_avps.len()) as u32);
    let mut encoded = BytesMut::new();
    if let Err(error) = header.encode(&mut encoded, EncodeContext::default()) {
        panic!("message header encode failed: {error}");
    }
    encoded.put_slice(raw_avps);
    encoded
}

#[test]
fn standard_vendor_and_padded_avps_round_trip() {
    let standard = encode_raw_avp(AvpHeader::ietf(AvpCode::new(264), true), b"host.example1");
    let vendor = encode_raw_avp(
        AvpHeader::vendor(
            AvpCode::new(7000),
            opc_proto_diameter::VendorId::new(10415),
            true,
        ),
        b"abc",
    );
    let mut region = BytesMut::new();
    region.put_slice(&standard);
    region.put_slice(&vendor);

    assert!(validate_avp_region(&region, DecodeContext::default()).is_ok());
    let mut iterator = opc_proto_diameter::RawAvpIterator::new(&region, DecodeContext::default());

    match iterator.next() {
        Some(Ok(decoded)) => {
            assert_eq!(decoded.header.code, AvpCode::new(264));
            assert_eq!(decoded.value, b"host.example1");
            assert_eq!(decoded.padding, b"\0\0\0");
        }
        other => panic!("unexpected first AVP decode result: {other:?}"),
    }

    match iterator.next() {
        Some(Ok(decoded)) => {
            assert_eq!(
                decoded.header.vendor_id,
                Some(opc_proto_diameter::VendorId::new(10415))
            );
            assert_eq!(decoded.value, b"abc");
            assert_eq!(decoded.padding, b"\0");
        }
        other => panic!("unexpected vendor AVP decode result: {other:?}"),
    }
    assert!(iterator.next().is_none());
}

#[test]
fn message_decode_and_grouped_dictionary_validation_accept_nested_avps() {
    let child = encode_raw_avp(AvpHeader::ietf(AvpCode::new(264), true), b"host.example");
    let grouped = encode_raw_avp(AvpHeader::ietf(AvpCode::new(279), true), &child);
    let encoded = encode_message(&grouped);

    let (_, message) = match Message::decode(&encoded, DecodeContext::default()) {
        Ok(decoded) => decoded,
        Err(error) => panic!("message decode failed: {error}"),
    };
    assert!(message
        .validate_avps_with_dictionary(DecodeContext::default(), dictionary_set())
        .is_ok());

    let mut avps = message.avps(DecodeContext::default());
    let grouped_avp = match avps.next() {
        Some(Ok(avp)) => avp,
        other => panic!("unexpected grouped AVP decode result: {other:?}"),
    };
    assert!(grouped_avp
        .validate_grouped_value_with_dictionary(DecodeContext::default(), dictionary_set())
        .is_ok());
    let mut children = grouped_avp.grouped_avps(DecodeContext::default());
    match children.next() {
        Some(Ok(child_avp)) => assert_eq!(child_avp.header.code, AvpCode::new(264)),
        other => panic!("unexpected grouped child decode result: {other:?}"),
    }
    assert!(children.next().is_none());
}

#[test]
fn duplicate_avp_policy_is_enforced_per_region() {
    let origin_host = encode_raw_avp(AvpHeader::ietf(AvpCode::new(264), true), b"host.example");
    let mut region = BytesMut::new();
    region.put_slice(&origin_host);
    region.put_slice(&origin_host);

    let reject_duplicates = DecodeContext {
        duplicate_ie_policy: DuplicateIePolicy::Reject,
        ..DecodeContext::default()
    };
    let result = validate_avp_region(&region, reject_duplicates);
    assert!(matches!(
        result,
        Err(error) if matches!(error.code(), DecodeErrorCode::DuplicateIe)
            && error.offset() == origin_host.len()
    ));

    let first_wins = DecodeContext {
        duplicate_ie_policy: DuplicateIePolicy::First,
        ..DecodeContext::default()
    };
    assert!(validate_avp_region(&region, first_wins).is_ok());

    let last_wins = DecodeContext {
        duplicate_ie_policy: DuplicateIePolicy::Last,
        ..DecodeContext::default()
    };
    assert!(validate_avp_region(&region, last_wins).is_ok());
}

#[test]
fn malformed_avp_region_rejects_short_lengths_and_reserved_bits() {
    let too_short = [0, 0, 1, 8, 0x40, 0, 0, (AVP_HEADER_LEN - 1) as u8];
    let result = validate_avp_region(&too_short, DecodeContext::default());
    assert!(matches!(
        result,
        Err(error) if matches!(error.code(), DecodeErrorCode::InvalidLength { .. })
            && error.offset() == 5
    ));

    let reserved_flags = [0, 0, 1, 8, 0x41, 0, 0, AVP_HEADER_LEN as u8];
    let result = validate_avp_region(&reserved_flags, DecodeContext::conservative());
    assert!(matches!(
        result,
        Err(error) if matches!(
            error.code(),
            DecodeErrorCode::Structural {
                reason: "diameter AVP reserved flag bits must be zero"
            }
        )
    ));
}

#[test]
fn grouped_dictionary_validation_is_bounded_by_depth_limit() {
    let child = encode_raw_avp(AvpHeader::ietf(AvpCode::new(264), true), b"host.example");
    let inner_grouped = encode_raw_avp(AvpHeader::ietf(AvpCode::new(279), true), &child);
    let outer_grouped = encode_raw_avp(AvpHeader::ietf(AvpCode::new(279), true), &inner_grouped);

    let shallow = DecodeContext {
        max_depth: 1,
        validation_level: ValidationLevel::Strict,
        ..DecodeContext::default()
    };
    let result = validate_avp_region_with_dictionary(&outer_grouped, shallow, dictionary_set());
    assert!(matches!(
        result,
        Err(error) if matches!(error.code(), DecodeErrorCode::DepthExceeded)
            && error.offset() == AVP_HEADER_LEN
    ));

    let deep_enough = DecodeContext {
        max_depth: 2,
        validation_level: ValidationLevel::Strict,
        ..DecodeContext::default()
    };
    assert!(
        validate_avp_region_with_dictionary(&outer_grouped, deep_enough, dictionary_set()).is_ok()
    );
}

#[test]
fn strict_message_validation_reports_absolute_avp_offsets() {
    let mut region = encode_raw_avp(AvpHeader::ietf(AvpCode::new(264), true), b"host.example");
    region.put_slice(&[
        0,
        0,
        1,
        8,
        AvpFlags::MANDATORY,
        0,
        0,
        (AVP_HEADER_LEN - 1) as u8,
    ]);
    let encoded = encode_message(&region);

    let result = Message::decode(&encoded, DecodeContext::default());
    assert!(matches!(
        result,
        Err(error) if matches!(error.code(), DecodeErrorCode::InvalidLength { .. })
            // The malformed AVP's header starts at
            // `DIAMETER_HEADER_LEN + region.len() - AVP_HEADER_LEN`; the invalid length is
            // reported at byte 5 of that header, hence the `+ 5`.
            && error.offset() == DIAMETER_HEADER_LEN + region.len() - AVP_HEADER_LEN + 5
    ));
}

#[test]
fn grouped_value_validation_respects_max_depth_at_entry() {
    let child = encode_raw_avp(AvpHeader::ietf(AvpCode::new(264), true), b"host.example");
    let grouped = encode_raw_avp(AvpHeader::ietf(AvpCode::new(279), true), &child);

    let grouped_avp = match RawAvp::decode(&grouped, DecodeContext::default()) {
        Ok((_, avp)) => avp,
        Err(error) => panic!("grouped AVP decode failed: {error}"),
    };

    let max_depth_zero = DecodeContext {
        max_depth: 0,
        validation_level: ValidationLevel::Strict,
        ..DecodeContext::default()
    };
    let result =
        grouped_avp.validate_grouped_value_with_dictionary(max_depth_zero, dictionary_set());
    assert!(matches!(
        result,
        Err(error) if matches!(error.code(), DecodeErrorCode::DepthExceeded)
            && error.offset() == 0
    ));
}

#[test]
fn per_region_avp_count_limit_is_enforced() {
    let first = encode_raw_avp(AvpHeader::ietf(AvpCode::new(264), true), b"host.example");
    let second = encode_raw_avp(AvpHeader::ietf(AvpCode::new(296), true), b"realm.example");
    let mut region = BytesMut::new();
    region.put_slice(&first);
    region.put_slice(&second);

    let limited = DecodeContext {
        max_ies: 1,
        ..DecodeContext::default()
    };
    let result = validate_avp_region(&region, limited);
    assert!(matches!(
        result,
        Err(error) if matches!(error.code(), DecodeErrorCode::IeCountExceeded)
            && error.offset() == first.len()
    ));
}

#[test]
fn strict_mode_rejects_non_zero_padding() {
    let avp_with_bad_padding = [
        0,
        0,
        1,
        8,
        AvpFlags::MANDATORY,
        0,
        0,
        (AVP_HEADER_LEN + 1) as u8,
        b'x',
        0xFF,
        0xFF,
        0xFF,
    ];
    let strict = DecodeContext {
        validation_level: ValidationLevel::Strict,
        ..DecodeContext::default()
    };
    let result = validate_avp_region(&avp_with_bad_padding, strict);
    assert!(matches!(
        result,
        Err(error) if matches!(
            error.code(),
            DecodeErrorCode::Structural {
                reason: "diameter AVP padding must be zero"
            }
        ) && error.offset() == AVP_HEADER_LEN + 1
    ));
}
