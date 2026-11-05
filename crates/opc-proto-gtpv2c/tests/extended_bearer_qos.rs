//! TS 29.274 clauses 7.7.7 and 8.15: the 22-octet prefix and unknown extensions.

use bytes::BytesMut;
use opc_proto_gtpv2c::{
    BearerQos, BearerQosValidationError, S2bMessage, TypedIe, TypedIeValue,
    MAX_BEARER_QOS_BITRATE_KBPS,
};
use opc_protocol::{DecodeContext, DecodeErrorCode, Encode, EncodeContext, ValidationLevel};

// ARP level 1, QCI 1, then four big-endian 40-bit rates in integer kbps.
const PREFIX: [u8; 22] = [
    0x04, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, // MBR UL = 16,777,216
    0x00, 0x02, 0x00, 0x00, 0x00, // MBR DL = 33,554,432
    0x00, 0x00, 0x01, 0x00, 0x00, // GBR UL = 65,536
    0x00, 0x00, 0x02, 0x00, 0x00, // GBR DL = 131,072
];

fn qos_ie(value: &[u8]) -> Vec<u8> {
    let mut wire = vec![80];
    wire.extend_from_slice(
        &u16::try_from(value.len())
            .expect("test value length")
            .to_be_bytes(),
    );
    wire.push(0);
    wire.extend_from_slice(value);
    wire
}

#[test]
fn extended_bearer_qos_decodes_known_rates_and_canonicalizes_only_the_prefix() {
    for suffix in [&[][..], &[0xff][..], &[0x80, 0xff, 0x01, 0x00][..]] {
        let wire = qos_ie(&[PREFIX.as_slice(), suffix].concat());
        let decoded = TypedIe::decode_sequence(&wire, DecodeContext::default())
            .expect("an unknown extension must not reject the known QoS prefix");
        let TypedIeValue::BearerQos(qos) = &decoded[0].value else {
            panic!("expected Bearer QoS");
        };
        assert_eq!(qos.priority_flags, 0x04);
        assert_eq!(qos.qci, 1);
        assert_eq!(qos.maximum_bitrate_uplink, 16_777_216);
        assert_eq!(qos.maximum_bitrate_downlink, 33_554_432);
        assert_eq!(qos.guaranteed_bitrate_uplink, 65_536);
        assert_eq!(qos.guaranteed_bitrate_downlink, 131_072);
        let mut canonical = BytesMut::new();
        decoded[0]
            .encode(&mut canonical, EncodeContext::default())
            .expect("known QoS fields encode");
        assert_eq!(canonical.as_ref(), qos_ie(&PREFIX));
    }
}

fn update_request(qos: &[u8]) -> Vec<u8> {
    let mut wire =
        include_bytes!("fixtures/spec/update_bearer_request_bearer_context.bin").to_vec();
    // This spec fixture ends in a Bearer Context containing only its EBI.
    assert_eq!(&wire[24..28], &[93, 0, 5, 0]);
    let group_len = u16::try_from(5 + qos.len()).expect("test group length");
    wire[25..27].copy_from_slice(&group_len.to_be_bytes());
    wire.extend_from_slice(qos);
    let message_len = u16::try_from(wire.len() - 4).expect("test message length");
    wire[2..4].copy_from_slice(&message_len.to_be_bytes());
    wire
}

#[test]
fn extended_bearer_qos_survives_s2b_projection_and_raw_preserving_encoding() {
    let canonical_wire = update_request(&qos_ie(&PREFIX));
    let extended_wire = update_request(&qos_ie(&[PREFIX.as_slice(), &[0xaa, 0xbb]].concat()));
    let context = DecodeContext {
        validation_level: ValidationLevel::ProcedureAware,
        ..DecodeContext::default()
    };
    let (_, expected) =
        S2bMessage::decode(&canonical_wire, context).expect("baseline Update Bearer request");
    let (tail, decoded) = S2bMessage::decode(&extended_wire, context)
        .expect("nested QoS extension must be ignored on S2b receive");
    assert!(tail.is_empty());
    assert_eq!(
        decoded.as_view().expect("procedure view").ies,
        expected.as_view().expect("baseline view").ies
    );
    let mut canonical = BytesMut::new();
    decoded
        .encode(&mut canonical, EncodeContext::default())
        .expect("canonical message encoding");
    assert_eq!(canonical.as_ref(), canonical_wire);
    let mut preserved = BytesMut::new();
    decoded
        .encode(
            &mut preserved,
            EncodeContext {
                raw_preserving: true,
                ..EncodeContext::default()
            },
        )
        .expect("raw-preserving message encoding");
    assert_eq!(preserved.as_ref(), extended_wire);
}

#[test]
fn extended_bearer_qos_still_requires_the_whole_prefix_and_valid_tliv_framing() {
    for length in 0..PREFIX.len() {
        let wire = qos_ie(&PREFIX[..length]);
        let error = TypedIe::decode_sequence(&wire, DecodeContext::default())
            .expect_err("a complete but undersized QoS value violates its required prefix length");
        assert!(
            matches!(error.code(), DecodeErrorCode::InvalidLength { .. }),
            "complete value of length {length}: {error:?}"
        );
    }
    let mut truncated = qos_ie(&PREFIX);
    truncated[2] = 23;
    let error = TypedIe::decode_sequence(&truncated, DecodeContext::default())
        .expect_err("an extension declared outside the IE boundary is truncated");
    assert_eq!(error.code(), &DecodeErrorCode::Truncated);
}

#[test]
fn extended_bearer_qos_still_checks_arp_qci_and_rate_relationships() {
    for (offset, byte) in [(0, 0), (1, 11), (1, 9), (12, 0x01), (17, 0x01)] {
        let mut value = PREFIX.to_vec();
        value[offset] = byte;
        value.extend_from_slice(&[0xaa, 0xbb]);
        let wire = qos_ie(&value);
        let error = TypedIe::decode_sequence(&wire, DecodeContext::default())
            .expect_err("a suffix cannot hide invalid prefix semantics");
        assert!(matches!(error.code(), DecodeErrorCode::Structural { .. }));
    }
}

#[test]
fn bearer_qos_wire_rates_use_all_forty_bits_and_reject_overflow_in_each_field() {
    // An operator-specific QCI permits wire representation without inferring
    // the operator's resource type or policy limits.
    let mut value = [0xff; 22];
    value[0] = 0x04;
    value[1] = 200;
    let wire = qos_ie(&value);
    let decoded = TypedIe::decode_sequence(&wire, DecodeContext::default())
        .expect("the largest representable u40 rate decodes");
    let TypedIeValue::BearerQos(qos) = &decoded[0].value else {
        panic!("expected Bearer QoS");
    };
    assert_eq!(qos.maximum_bitrate_uplink, MAX_BEARER_QOS_BITRATE_KBPS);
    assert_eq!(qos.maximum_bitrate_downlink, MAX_BEARER_QOS_BITRATE_KBPS);
    assert_eq!(qos.guaranteed_bitrate_uplink, MAX_BEARER_QOS_BITRATE_KBPS);
    assert_eq!(qos.guaranteed_bitrate_downlink, MAX_BEARER_QOS_BITRATE_KBPS);
    let mut encoded = BytesMut::new();
    decoded[0]
        .encode(&mut encoded, EncodeContext::default())
        .expect("the largest representable u40 rate encodes");
    assert_eq!(encoded.as_ref(), wire);
    for field in 0..4 {
        let mut overflow: BearerQos = qos.clone();
        let rates = [
            &mut overflow.maximum_bitrate_uplink,
            &mut overflow.maximum_bitrate_downlink,
            &mut overflow.guaranteed_bitrate_uplink,
            &mut overflow.guaranteed_bitrate_downlink,
        ];
        *rates[field] = MAX_BEARER_QOS_BITRATE_KBPS + 1;
        assert_eq!(
            overflow.validate(),
            Err(BearerQosValidationError::BitrateExceedsU40)
        );
        let ie = TypedIe {
            instance: 0,
            value: TypedIeValue::BearerQos(overflow),
        };
        assert!(ie
            .encode(&mut BytesMut::new(), EncodeContext::default())
            .is_err());
    }
}

#[test]
fn review_arp_spares_do_not_reject_create_or_update_bearer() {
    let update = update_request(&qos_ie(&PREFIX));
    let create = include_bytes!("fixtures/spec/create_bearer_request_s2b.bin").to_vec();
    for original in [create, update] {
        let marker = original
            .windows(4)
            .position(|w| w == [80, 0, 22, 0])
            .unwrap()
            + 4;
        for spare in [0x02, 0x80, 0x82] {
            let mut received = original.clone();
            received[marker] |= spare;
            for level in [
                ValidationLevel::Structural,
                ValidationLevel::Strict,
                ValidationLevel::ProcedureAware,
            ] {
                let context = DecodeContext {
                    validation_level: level,
                    ..DecodeContext::default()
                };
                let (_, expected) = S2bMessage::decode(&original, context).unwrap();
                let (_, decoded) = S2bMessage::decode(&received, context)
                    .expect("TS 29.274 7.7.8: ARP spare bits must not reject a bearer request");
                assert_eq!(
                    decoded.as_view().unwrap().ies,
                    expected.as_view().unwrap().ies
                );
                let mut canonical = BytesMut::new();
                decoded
                    .encode(&mut canonical, EncodeContext::default())
                    .unwrap();
                assert_eq!(canonical.as_ref(), original);
                let mut raw = BytesMut::new();
                decoded
                    .encode(
                        &mut raw,
                        EncodeContext {
                            raw_preserving: true,
                            ..EncodeContext::default()
                        },
                    )
                    .unwrap();
                assert_eq!(raw.as_ref(), received);
            }
        }
    }
}
