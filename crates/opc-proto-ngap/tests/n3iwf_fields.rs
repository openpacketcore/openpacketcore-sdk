//! Independent Release 18 field encodings; synthetic values only.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use opc_proto_ngap::n3iwf::{
    AmfUeId, EncodedValue, N3iwfLocation, NasPdu, RanUeId, SecurityKey, TrackingArea,
};
use opc_protocol::{DecodeContext, EncodeContext};
use opc_types::PlmnId;
use serde_json::Value;
use sha2::{Digest, Sha256};

fn decode_context() -> DecodeContext {
    DecodeContext {
        max_message_len: 200_000,
        ..DecodeContext::conservative()
    }
}

fn encode_context() -> EncodeContext {
    EncodeContext {
        max_message_len: 200_000,
        ..EncodeContext::default()
    }
}

fn octets(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn matches_reference(wire: &EncodedValue, row: &Value) {
    assert_eq!(
        wire.as_bytes().len(),
        row["wire_len"].as_u64().unwrap() as usize
    );
    let digest = Sha256::digest(wire.as_bytes());
    assert!(
        digest.as_slice() == octets(row["wire_sha256"].as_str().unwrap()),
        "field type {} differs from independent reference",
        row["type"].as_str().unwrap()
    );
    if let Some(hex) = row["wire_hex"].as_str() {
        assert!(
            wire.as_bytes() == octets(hex),
            "field differs from independent reference"
        );
    }
}

#[test]
fn all_independent_fields_construct_and_decode() {
    let oracle: Value = serde_json::from_str(include_str!("fixtures/n3iwf-fields.json")).unwrap();
    let cases = oracle["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 51);
    for row in cases {
        let recipe = &row["recipe"];
        let wire = match row["type"].as_str().unwrap() {
            "RAN_UE_NGAP_ID" => {
                let value = RanUeId::new(recipe["integer"].as_u64().unwrap() as u32);
                let wire = value.encode(encode_context()).unwrap();
                let received =
                    RanUeId::decode(&octets(row["wire_hex"].as_str().unwrap()), decode_context())
                        .unwrap();
                assert!(value == received);
                wire
            }
            "AMF_UE_NGAP_ID" => {
                let value = AmfUeId::new(recipe["integer"].as_u64().unwrap()).unwrap();
                let wire = value.encode(encode_context()).unwrap();
                let received =
                    AmfUeId::decode(&octets(row["wire_hex"].as_str().unwrap()), decode_context())
                        .unwrap();
                assert!(value == received);
                wire
            }
            "NAS_PDU" => {
                let size = recipe["length"].as_u64().unwrap() as usize;
                let nas: Vec<_> = (0..size).map(|i| (i * 17 + 3) as u8).collect();
                let wire = NasPdu::new(&nas).encode(encode_context()).unwrap();
                // Digest comparison below supplies independent evidence for
                // large values; decode consumes the same exact matched bytes.
                let received = NasPdu::decode(wire.as_bytes(), decode_context()).unwrap();
                assert!(received.as_bytes() == nas);
                wire
            }
            "SecurityKey" => {
                let key: [u8; 32] = std::array::from_fn(|i| i as u8);
                let wire = SecurityKey::new(&key).encode(encode_context()).unwrap();
                let bytes = octets(row["wire_hex"].as_str().unwrap());
                let received = SecurityKey::decode(&bytes, decode_context()).unwrap();
                assert!(received.expose_bytes() == &key);
                // Borrowed decode never makes an owned copy of key material.
                assert!(std::ptr::eq(
                    received.expose_bytes().as_ptr(),
                    bytes.as_ptr()
                ));
                wire
            }
            "TAI" => {
                let value = TrackingArea::new(
                    PlmnId::new("001", recipe["mnc"].as_str().unwrap()).unwrap(),
                    [0, 0, 1],
                );
                let received = TrackingArea::decode(
                    &octets(row["wire_hex"].as_str().unwrap()),
                    decode_context(),
                )
                .unwrap();
                assert!(value == received);
                value.encode(encode_context()).unwrap()
            }
            "UserLocationInformation" => {
                let tai = recipe["tai"].as_bool().unwrap().then(|| {
                    TrackingArea::new(
                        PlmnId::new("001", recipe["mnc"].as_str().unwrap()).unwrap(),
                        [0, 0, 1],
                    )
                });
                let value = N3iwfLocation::new(
                    recipe["address"].as_str().unwrap().parse().unwrap(),
                    recipe["port"].as_u64().map(|v| v as u16),
                    tai,
                );
                let received = N3iwfLocation::decode(
                    &octets(row["wire_hex"].as_str().unwrap()),
                    decode_context(),
                )
                .unwrap();
                assert!(value == received);
                value.encode(encode_context()).unwrap()
            }
            _ => panic!("unrecognized reference field type"),
        };
        matches_reference(&wire, row);
        let limited = EncodeContext {
            max_message_len: wire.as_bytes().len() - 1,
            ..encode_context()
        };
        if row["type"] == "NAS_PDU" {
            let size = recipe["length"].as_u64().unwrap() as usize;
            assert!(NasPdu::new(&vec![0; size]).encode(limited).is_err());
        }
    }
}

#[test]
fn malformed_fields_and_advertised_extensions_are_bounded() {
    assert!(AmfUeId::new(1 << 40).is_err());
    let ctx = decode_context();
    let location = octets("90f8c00002011194000000d540070000f110000001");
    for end in 0..location.len() {
        assert!(N3iwfLocation::decode(&location[..end], ctx).is_err());
    }
    for input in [
        &[0xc0][..],
        &[0xc5][..],
        &[0xff][..],
        &[0x80][..],
        &[0xc1, 0][..],
        &[0x00, 0][..],
    ] {
        assert!(NasPdu::decode(input, ctx).is_err());
    }
    let mut excessive = location.clone();
    excessive[8..10].copy_from_slice(&[0xff, 0xfe]);
    let error = N3iwfLocation::decode(&excessive, ctx).unwrap_err();
    assert!(matches!(
        error.code(),
        opc_protocol::DecodeErrorCode::IeCountExceeded
    ));
    let mut extension = location.clone();
    extension[11] = 212;
    assert!(N3iwfLocation::decode(&extension, ctx).is_err());
    let mut criticality = location.clone();
    criticality[12] = 0;
    assert!(N3iwfLocation::decode(&criticality, ctx).is_err());
    let mut sequence_extension = location.clone();
    sequence_extension[0] |= 0x20;
    assert!(N3iwfLocation::decode(&sequence_extension, ctx).is_err());
    let mut trailing = location.clone();
    trailing.push(0);
    assert!(N3iwfLocation::decode(&trailing, ctx).is_err());
    for len in [0, 31, 33, 65] {
        assert!(SecurityKey::decode(&vec![0; len], ctx).is_err());
    }
    assert!(SecurityKey::new(&[0; 32])
        .encode(EncodeContext {
            max_message_len: 31,
            ..encode_context()
        })
        .is_err());
    for value in [
        &[0, 0xfa, 0x10, 0, 0, 0, 0][..],
        &[0x40, 0, 0xf1, 0x10, 0, 0, 1][..],
        &[0x80, 0, 0xf1, 0x10, 0, 0, 1][..],
    ] {
        assert!(TrackingArea::decode(value, ctx).is_err());
    }
    assert!(N3iwfLocation::decode(
        &location,
        DecodeContext {
            max_message_len: location.len() - 1,
            ..ctx
        }
    )
    .is_err());
    assert!(N3iwfLocation::decode(
        &location,
        DecodeContext {
            max_depth: 2,
            ..ctx
        }
    )
    .is_err());
    assert!(N3iwfLocation::decode(&location, DecodeContext { max_ies: 0, ..ctx }).is_err());
}

#[test]
fn field_diagnostics_never_format_values() {
    let key = [0x53; 32];
    let nas = b"private-nas-marker";
    let tai = TrackingArea::new(PlmnId::new("001", "01").unwrap(), [0xab, 0xcd, 0xef]);
    let location = N3iwfLocation::new("192.0.2.1".parse().unwrap(), Some(4500), Some(tai.clone()));
    let key = SecurityKey::new(&key);
    let encoded = key.encode(encode_context()).unwrap();
    for text in [
        format!("{:?}", RanUeId::new(123456)),
        format!("{:?}", AmfUeId::new(123456789).unwrap()),
        format!("{:?}", NasPdu::new(nas)),
        format!("{key:?}"),
        format!("{tai:?}"),
        format!("{location:?}"),
        format!("{encoded:?}"),
    ] {
        for forbidden in [
            "private-nas-marker",
            "83, 83",
            "192.0.2.1",
            "001-01",
            "4500",
            "123456",
            "171, 205, 239",
        ] {
            assert!(!text.contains(forbidden));
        }
    }
}

#[test]
fn published_uplink_message_constructs_from_typed_values() {
    use opc_proto_ngap::{encode, Criticality, MessageType, Pdu, ProtocolIe};
    // Unchanged complete UL NAS message from the published Release 18 oracle.
    // The fields below come from its synthetic recipe, never an SDK decode.
    let oracle: Value = serde_json::from_str(include_str!(
        "../../opc-n3iwf-fixtures/oracles/ngap-rel18-messages.json"
    ))
    .unwrap();
    for (name, address, port) in [
        ("complete-uplink-nas-transport", "192.0.2.1", Some(4500)),
        ("complete-n3iwf-ipv6-without-port", "2001:db8::1", None),
    ] {
        let row = oracle["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["name"] == name)
            .unwrap();
        let amf = AmfUeId::new(0x0102030405)
            .unwrap()
            .encode(encode_context())
            .unwrap();
        let ran = RanUeId::new(0x10203040).encode(encode_context()).unwrap();
        let nas = NasPdu::new(&[0x7e, 0, 0x64, 0x14])
            .encode(encode_context())
            .unwrap();
        let tai = TrackingArea::new(PlmnId::new("001", "01").unwrap(), [0, 0, 1]);
        let location = N3iwfLocation::new(address.parse().unwrap(), port, Some(tai))
            .encode(encode_context())
            .unwrap();
        let pdu = Pdu::from_protocol_ies(
            MessageType::UplinkNasTransport,
            &[
                ProtocolIe::new(10, Criticality::reject, amf.as_bytes()),
                ProtocolIe::new(85, Criticality::reject, ran.as_bytes()),
                ProtocolIe::new(38, Criticality::reject, nas.as_bytes()),
                ProtocolIe::new(121, Criticality::ignore, location.as_bytes()),
            ],
            decode_context(),
        )
        .unwrap();
        assert!(pdu.raw.is_empty());
        let expected = octets(row["wire_hex"].as_str().unwrap());
        assert!(encode(&pdu, encode_context()).unwrap() == expected);
    }
}

#[test]
fn every_small_reference_truncation_and_octet_mutation_is_safe() {
    let oracle: Value = serde_json::from_str(include_str!("fixtures/n3iwf-fields.json")).unwrap();
    for row in oracle["cases"].as_array().unwrap() {
        let Some(hex) = row["wire_hex"].as_str() else {
            continue;
        };
        let bytes = octets(hex);
        let check = |input: &[u8]| {
            let ctx = decode_context();
            let _ = AmfUeId::decode(input, ctx);
            let _ = RanUeId::decode(input, ctx);
            let _ = SecurityKey::decode(input, ctx);
            let _ = NasPdu::decode(input, ctx);
            let _ = TrackingArea::decode(input, ctx);
            if let Ok(location) = N3iwfLocation::decode(input, ctx) {
                let wire = location.encode(encode_context()).unwrap();
                assert!(N3iwfLocation::decode(wire.as_bytes(), ctx).unwrap() == location);
            }
        };
        for end in 0..=bytes.len() {
            check(&bytes[..end]);
        }
        for i in 0..bytes.len() {
            for mask in [1, 0x40, 0x80, 0xff] {
                let mut mutation = bytes.clone();
                mutation[i] ^= mask;
                check(&mutation);
            }
        }
    }
}
