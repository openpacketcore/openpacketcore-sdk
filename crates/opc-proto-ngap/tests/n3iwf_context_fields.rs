#![allow(clippy::unwrap_used)]
use opc_proto_ngap::n3iwf::context_fields::{AllowedNssai, Guami, SecurityAlgorithmMasks};
use opc_protocol::{DecodeContext, EncodeContext};
use opc_types::Snssai;
use serde_json::Value;

fn oracle() -> Value {
    serde_json::from_str(include_str!("fixtures/n3iwf-context-fields.json")).unwrap()
}
fn bytes(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|v| u8::from_str_radix(std::str::from_utf8(v).unwrap(), 16).unwrap())
        .collect()
}
fn guami(v: &Value) -> Guami {
    Guami::new(
        v["plmn"].as_str().unwrap().parse().unwrap(),
        v["region"].as_u64().unwrap() as u8,
        v["set"].as_u64().unwrap() as u16,
        v["pointer"].as_u64().unwrap() as u8,
    )
    .unwrap()
}
fn slices(v: &Value) -> AllowedNssai {
    AllowedNssai::new(
        v.as_array()
            .unwrap()
            .iter()
            .map(|s| match s["sd"].as_str() {
                Some(sd) => Snssai::with_sd(s["sst"].as_u64().unwrap() as u8, sd).unwrap(),
                None => Snssai::without_sd(s["sst"].as_u64().unwrap() as u8),
            })
            .collect(),
    )
    .unwrap()
}
#[test]
fn independent_context_fields_cover_all_mask_bits_and_slice_alignments() {
    let reference = oracle();
    for row in reference["fields"].as_array().unwrap() {
        let wire = bytes(row["wire_hex"].as_str().unwrap());
        let m = &row["model"];
        let output = match row["type"].as_str().unwrap() {
            "GUAMI" => {
                let expected = guami(m);
                assert!(Guami::decode(&wire, DecodeContext::default()).unwrap() == expected);
                expected.encode(EncodeContext::default()).unwrap()
            }
            "AllowedNSSAI" => {
                let expected = slices(m);
                assert!(AllowedNssai::decode(&wire, DecodeContext::default()).unwrap() == expected);
                expected.encode(EncodeContext::default()).unwrap()
            }
            "UESecurityCapabilities" => {
                let masks: Vec<_> = m
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| v.as_u64().unwrap() as u16)
                    .collect();
                let value = SecurityAlgorithmMasks::new(masks[0], masks[1], masks[2], masks[3]);
                assert_eq!(
                    [
                        value.nr_encryption(),
                        value.nr_integrity(),
                        value.eutra_encryption(),
                        value.eutra_integrity()
                    ],
                    masks.as_slice()
                );
                value.encode(EncodeContext::default()).unwrap()
            }
            _ => panic!("reference field"),
        };
        assert!(
            output.as_bytes() == wire,
            "independent {} wire differs",
            row["type"]
        );
    }
    assert_eq!(reference["fields"].as_array().unwrap().len(), 98);
}
#[test]
fn field_bounds_extensions_trailing_data_and_redaction_are_explicit() {
    let reference = oracle();
    assert!(AllowedNssai::new(vec![]).is_err());
    assert!(AllowedNssai::new(vec![Snssai::without_sd(1); 9]).is_err());
    for row in reference["fields"].as_array().unwrap() {
        let wire = bytes(row["wire_hex"].as_str().unwrap());
        let short = EncodeContext {
            max_message_len: wire.len() - 1,
            ..EncodeContext::default()
        };
        let exact = EncodeContext {
            max_message_len: wire.len(),
            ..EncodeContext::default()
        };
        let bound = DecodeContext {
            max_message_len: wire.len() - 1,
            ..DecodeContext::default()
        };
        let mut trailing = wire.clone();
        trailing.push(0);
        let debug = match row["type"].as_str().unwrap() {
            "GUAMI" => {
                let value = guami(&row["model"]);
                assert!(value.encode(short).is_err());
                assert!(value.encode(exact).is_ok());
                assert!(Guami::decode(&wire, bound).is_err());
                assert!(Guami::decode(&trailing, DecodeContext::default()).is_err());
                assert!(Guami::decode(
                    &wire,
                    DecodeContext {
                        max_depth: 1,
                        ..DecodeContext::default()
                    }
                )
                .is_err());
                for mask in [0x80, 0x40] {
                    let mut changed = wire.clone();
                    changed[0] |= mask;
                    assert!(Guami::decode(&changed, DecodeContext::default()).is_err());
                }
                format!("{value:?}")
            }
            "AllowedNSSAI" => {
                let value = slices(&row["model"]);
                assert!(value.encode(short).is_err());
                assert!(value.encode(exact).is_ok());
                assert!(AllowedNssai::decode(&wire, bound).is_err());
                assert!(AllowedNssai::decode(&trailing, DecodeContext::default()).is_err());
                assert!(AllowedNssai::decode(
                    &wire,
                    DecodeContext {
                        max_depth: 3,
                        ..DecodeContext::default()
                    }
                )
                .is_err());
                assert!(AllowedNssai::decode(
                    &wire,
                    DecodeContext {
                        max_ies: value.values().len() - 1,
                        ..DecodeContext::default()
                    }
                )
                .is_err());
                assert!(AllowedNssai::decode(
                    &wire,
                    DecodeContext {
                        max_ies: value.values().len(),
                        ..DecodeContext::default()
                    }
                )
                .is_ok());
                for mask in [0x10, 0x08, 0x04, 0x01] {
                    let mut changed = wire.clone();
                    changed[0] |= mask;
                    assert!(AllowedNssai::decode(&changed, DecodeContext::default()).is_err());
                }
                format!("{value:?}")
            }
            _ => {
                let value = SecurityAlgorithmMasks::new(1, 2, 4, 8);
                assert!(value.encode(short).is_err());
                assert!(value.encode(exact).is_ok());
                format!("{value:?}")
            }
        };
        assert!(debug.contains("REDACTED"));
        assert!(!debug.chars().any(|c| c.is_ascii_digit()));
    }
}
fn exercise(data: &[u8]) {
    if let Ok(value) = Guami::decode(data, DecodeContext::default()) {
        let encoded = value.encode(EncodeContext::default()).unwrap();
        assert!(Guami::decode(encoded.as_bytes(), DecodeContext::default()).unwrap() == value);
    }
    if let Ok(value) = AllowedNssai::decode(data, DecodeContext::default()) {
        let encoded = value.encode(EncodeContext::default()).unwrap();
        assert!(
            AllowedNssai::decode(encoded.as_bytes(), DecodeContext::default()).unwrap() == value
        );
    }
}
#[test]
fn every_independent_field_truncation_and_byte_mutation_is_safe() {
    let reference = oracle();
    for row in reference["fields"].as_array().unwrap() {
        let wire = bytes(row["wire_hex"].as_str().unwrap());
        for end in 0..=wire.len() {
            exercise(&wire[..end]);
        }
        for index in 0..wire.len() {
            for mask in [1, 0x80, 0xff] {
                let mut changed = wire.clone();
                changed[index] ^= mask;
                exercise(&changed);
            }
        }
    }
}
