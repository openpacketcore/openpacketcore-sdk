//! Specification-authored TS 29.274 8.62 value vectors and bounded decoding.

use bytes::BytesMut;
use opc_proto_gtpv2c::{
    CauseValue, FqCsid, FqCsidBuildError, FqCsidDecodeError, FqCsidMccMncNodeId, FqCsidNodeId,
    RawIe, RawIeIterator, IE_TYPE_FQ_CSID, MAX_FQ_CSID_COUNT,
};
use opc_protocol::{DecodeContext, ValidationLevel};

// Four-bit type, four-bit count, network-order Node-ID, then u16 CSIDs.
const IPV4: &[u8] = &[132, 0, 7, 2, 0x01, 192, 0, 2, 1, 0x12, 0x34];
const IPV6: &[u8] = &[
    132, 0, 21, 7, 0x12, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0xff,
    0xff,
];
// Binary 310 * 1000 + 260 = 0x4bbf4; operator ID = 0xabc.
const MCC_MNC: &[u8] = &[132, 0, 7, 15, 0x21, 0x4b, 0xbf, 0x4a, 0xbc, 0x12, 0x34];

fn raw(wire: &[u8]) -> RawIe<'_> {
    let (tail, ie) = RawIe::decode(wire).expect("valid generic IE framing");
    assert!(tail.is_empty());
    ie
}

fn typed(wire: &[u8]) -> FqCsid {
    FqCsid::decode_from_raw(&raw(wire))
        .expect("valid FQ-CSID value")
        .expect("matching IE type")
}

fn encode(value: &FqCsid, instance: u8) -> Vec<u8> {
    let ie = value.to_raw_ie(instance).expect("four-bit instance");
    let mut bytes = BytesMut::new();
    ie.encode(&mut bytes).expect("generic IE encoder");
    bytes.to_vec()
}

#[test]
fn empty_and_reserved_values_have_named_value_free_errors_and_request_causes() {
    for (wire, error, cause) in [
        (
            &[132, 0, 0, 2][..],
            FqCsidDecodeError::MissingTypeAndCount,
            CauseValue::InvalidLength,
        ),
        (
            &[132, 0, 7, 2, 0x31, 192, 0, 2, 1, 0, 1][..],
            FqCsidDecodeError::ReservedNodeIdType,
            CauseValue::MandatoryIeIncorrect,
        ),
    ] {
        let ie = raw(wire); // Framing accepts both: semantic validation is separate.
        let actual = FqCsid::decode_from_raw(&ie).expect_err("invalid typed value");
        assert_eq!(actual, error);
        assert_eq!(actual.mandatory_request_cause(), cause);
        assert!(!format!("{actual:?} {actual}").contains("192"));
    }
}

#[test]
fn all_node_id_types_match_independent_octets() {
    let ipv4 = FqCsid::new(FqCsidNodeId::Ipv4([192, 0, 2, 1]), &[0x1234]).unwrap();
    assert_eq!(typed(IPV4), ipv4);
    assert_eq!(encode(&ipv4, 2), IPV4);
    let ipv6_addr = [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let ipv6 = FqCsid::new(FqCsidNodeId::Ipv6(ipv6_addr), &[0, u16::MAX]).unwrap();
    assert_eq!(typed(IPV6), ipv6);
    assert_eq!(encode(&ipv6, 7), IPV6);
    let id = FqCsidMccMncNodeId::new(310, 260, 0xabc).unwrap();
    assert_eq!((id.mcc(), id.mnc(), id.operator_id()), (310, 260, 0xabc));
    let plmn = FqCsid::new(FqCsidNodeId::MccMnc(id), &[0x1234]).unwrap();
    assert_eq!(typed(MCC_MNC), plmn);
    assert_eq!(encode(&plmn, 15), MCC_MNC);
}

#[test]
fn unrelated_ies_are_not_interpreted_even_with_empty_or_arbitrary_values() {
    for ie_type in 0..=u8::MAX {
        if ie_type == IE_TYPE_FQ_CSID {
            continue;
        }
        for value in [&[][..], &[0x31, 0xff, 0xff][..]] {
            let ie = RawIe {
                ie_type,
                instance: 2,
                spare: 15,
                value,
            };
            assert_eq!(FqCsid::decode_from_raw(&ie), Ok(None));
        }
    }
}

#[test]
fn count_boundaries_preserve_all_unsigned_csids() {
    assert_eq!(MAX_FQ_CSID_COUNT, 15);
    for count in [0, 1, 15] {
        let csids: Vec<_> = (0..count)
            .map(|i| if i == 0 { 0 } else { u16::MAX })
            .collect();
        let value = FqCsid::new(FqCsidNodeId::Ipv4([192, 0, 2, 1]), &csids).unwrap();
        let wire = encode(&value, 0);
        assert_eq!(wire[4] & 15, u8::try_from(count).unwrap());
        assert_eq!(wire.len(), 9 + 2 * count);
        assert_eq!(typed(&wire).csids(), csids);
    }
    assert_eq!(
        FqCsid::new(FqCsidNodeId::Ipv4([192, 0, 2, 1]), &[1; 16]),
        Err(FqCsidBuildError::TooManyCsids)
    );
}

#[test]
fn decimal_node_id_and_instance_boundaries_are_validated_without_value_echo() {
    for (mcc, mnc, id, error) in [
        (1000, 0, 0, FqCsidBuildError::InvalidMcc),
        (0, 1000, 0, FqCsidBuildError::InvalidMnc),
        (999, 999, 4096, FqCsidBuildError::InvalidOperatorId),
    ] {
        assert_eq!(FqCsidMccMncNodeId::new(mcc, mnc, id), Err(error));
    }
    for (mcc, mnc, id) in [(0, 0, 0), (999, 999, 4095), (1, 1, 1)] {
        let node = FqCsidMccMncNodeId::new(mcc, mnc, id).unwrap();
        let value = FqCsid::new(FqCsidNodeId::MccMnc(node), &[u16::MAX]).unwrap();
        assert_eq!(typed(&encode(&value, 0)), value);
    }
    let invalid_decimal = RawIe {
        ie_type: 132,
        instance: 0,
        spare: 0,
        value: &[0x21, 0xf4, 0x24, 0x00, 0x00, 0, 1],
    }; // 1,000,000 << 12.
    let error = FqCsid::decode_from_raw(&invalid_decimal).unwrap_err();
    assert_eq!(error, FqCsidDecodeError::InvalidMccMnc);
    assert_eq!(
        error.mandatory_request_cause(),
        CauseValue::MandatoryIeIncorrect
    );
    assert_eq!(
        typed(IPV4).to_raw_ie(16),
        Err(FqCsidBuildError::InvalidInstance)
    );
}

#[test]
fn every_known_prefix_truncation_is_an_invalid_length() {
    for wire in [IPV4, IPV6, MCC_MNC] {
        let full = raw(wire);
        let node_len = if full.value[0] >> 4 == 1 { 16 } else { 4 };
        for len in 0..full.value.len() {
            let ie = RawIe {
                value: &full.value[..len],
                ..full.clone()
            };
            let error = FqCsid::decode_from_raw(&ie).unwrap_err();
            let expected = if len == 0 {
                FqCsidDecodeError::MissingTypeAndCount
            } else if len < 1 + node_len {
                FqCsidDecodeError::TruncatedNodeId
            } else {
                FqCsidDecodeError::TruncatedCsids
            };
            assert_eq!(error, expected, "prefix length {len}");
            assert_eq!(error.mandatory_request_cause(), CauseValue::InvalidLength);
        }
    }
}

#[test]
fn all_reserved_node_id_types_are_semantic_errors_not_spare_bits() {
    for node_type in 3..=15 {
        let mut value = raw(IPV4).value.to_vec();
        value[0] = (node_type << 4) | 1;
        let ie = RawIe {
            ie_type: 132,
            instance: 2,
            spare: 15,
            value: &value,
        };
        assert_eq!(
            FqCsid::decode_from_raw(&ie),
            Err(FqCsidDecodeError::ReservedNodeIdType)
        );
    }
}

#[test]
fn receive_header_spares_are_ignored_and_send_spares_are_canonical() {
    let expected = typed(IPV4);
    for instance in 0..=15 {
        for spare in 0..=15 {
            let mut wire = IPV4.to_vec();
            wire[3] = (spare << 4) | instance;
            let context = DecodeContext {
                validation_level: ValidationLevel::Structural,
                ..DecodeContext::default()
            };
            let ie = RawIeIterator::new(&wire, context).next().unwrap().unwrap();
            let value = FqCsid::decode_from_raw(&ie).unwrap().unwrap();
            assert_eq!(value, expected);
            let canonical = encode(&value, instance);
            assert_eq!(canonical[3], instance);
            assert_eq!(&canonical[4..], &IPV4[4..]);
        }
    }
}

#[test]
fn extendable_suffix_is_ignored_without_becoming_csids_or_crossing_ie_boundaries() {
    let mut wire = IPV4.to_vec();
    wire[2] += 3;
    wire.extend_from_slice(&[0xab, 0xcd, 0xef]);
    wire.extend_from_slice(&[3, 0, 1, 0, 9]);
    let mut ies = RawIeIterator::new(&wire, DecodeContext::default());
    let first = ies.next().unwrap().unwrap();
    let second = ies.next().unwrap().unwrap();
    assert!(ies.next().is_none());
    assert_eq!(FqCsid::decode_from_raw(&second), Ok(None));
    let typed = FqCsid::decode_from_raw(&first).unwrap().unwrap();
    assert_eq!(typed.csids(), &[0x1234]);
    assert_eq!(encode(&typed, 2), IPV4);
    let mut raw_wire = BytesMut::new();
    first.encode(&mut raw_wire).unwrap();
    assert_eq!(raw_wire.as_ref(), &wire[..14]);
    assert!(RawIe::decode(&IPV4[..IPV4.len() - 1]).is_err());
}

fn next(seed: &mut u64) -> u64 {
    *seed ^= *seed << 13;
    *seed ^= *seed >> 7;
    *seed ^= *seed << 17;
    *seed
}

#[test]
fn deterministic_randomized_round_trips_match_an_independent_value_layout() {
    let mut seed = 0x37d4_91ae_a850_214bu64;
    for _ in 0..2048 {
        let word = next(&mut seed);
        let count = usize::try_from(word & 15).unwrap();
        let csids: Vec<_> = (0..count).map(|_| next(&mut seed) as u16).collect();
        let (node, kind, address) = match word % 3 {
            0 => {
                let b = (next(&mut seed) as u32).to_be_bytes();
                (FqCsidNodeId::Ipv4(b), 0, b.to_vec())
            }
            1 => {
                let mut b = [0; 16];
                b[..8].copy_from_slice(&next(&mut seed).to_be_bytes());
                b[8..].copy_from_slice(&next(&mut seed).to_be_bytes());
                (FqCsidNodeId::Ipv6(b), 1, b.to_vec())
            }
            _ => {
                let mcc = (next(&mut seed) % 1000) as u16;
                let mnc = (next(&mut seed) % 1000) as u16;
                let id = (next(&mut seed) & 4095) as u16;
                let packed = (((u32::from(mcc) * 1000 + u32::from(mnc)) << 12) | u32::from(id))
                    .to_be_bytes();
                (
                    FqCsidNodeId::MccMnc(FqCsidMccMncNodeId::new(mcc, mnc, id).unwrap()),
                    2,
                    packed.to_vec(),
                )
            }
        };
        let value = FqCsid::new(node, &csids).unwrap();
        let instance = (word & 15) as u8;
        let wire = encode(&value, instance);
        let mut reference = vec![(kind << 4) | count as u8];
        reference.extend_from_slice(&address);
        for csid in &csids {
            reference.extend_from_slice(&csid.to_be_bytes());
        }
        assert_eq!(&wire[4..], reference);
        assert_eq!(typed(&wire), value);
        assert_eq!(value.node_id(), typed(&wire).node_id());
    }
}

#[test]
fn arbitrary_bounded_values_never_panic_and_errors_contain_no_received_values() {
    let mut seed = 0xab19_7a88_51e0_c2d3u64;
    for len in 0..=256 {
        let bytes: Vec<_> = (0..len).map(|_| next(&mut seed) as u8).collect();
        let ie = RawIe {
            ie_type: 132,
            instance: 0,
            spare: 15,
            value: &bytes,
        };
        match FqCsid::decode_from_raw(&ie) {
            Ok(Some(value)) => {
                let encoded = encode(&value, 0);
                assert!(encoded.len() <= 51);
                assert_eq!(typed(&encoded), value);
            }
            Ok(None) => panic!("FQ-CSID type cannot be unrelated"),
            Err(error) => {
                assert!(error.to_string().starts_with("gtpv2c_fq_csid_"));
            }
        }
    }
    let value = typed(IPV4);
    let debug = format!("{value:?} {:?}", value.node_id());
    assert!(!debug.contains("192"));
    assert!(!debug.contains("4660"));
}

#[test]
fn a_large_construction_count_is_rejected_before_copying() {
    assert_eq!(
        FqCsid::new(FqCsidNodeId::Ipv4([192, 0, 2, 1]), &[0; 256]),
        Err(FqCsidBuildError::TooManyCsids),
    );
}

#[test]
fn maximum_tlv_extension_keeps_typed_storage_bounded() {
    let mut wire = vec![0; 4 + usize::from(u16::MAX)];
    wire[..IPV4.len()].copy_from_slice(IPV4);
    wire[1..3].copy_from_slice(&u16::MAX.to_be_bytes());
    let value = FqCsid::decode_from_raw(&raw(&wire)).unwrap().unwrap();
    assert_eq!(value, typed(IPV4));
    assert_eq!(encode(&value, 2), IPV4);
    assert_eq!(value.csids(), &[0x1234]);
    assert_eq!(raw(&wire).value.len(), usize::from(u16::MAX));
}

#[test]
fn ipv6_and_decimal_node_debug_redact_every_identity_and_csid() {
    let decimal = FqCsidMccMncNodeId::new(310, 260, 0xabc).unwrap();
    assert_eq!(format!("{decimal:?}"), "FqCsidMccMncNodeId(<redacted>)");
    for (wire, kind) in [(IPV6, 1), (MCC_MNC, 2)] {
        let value = typed(wire);
        assert_eq!(
            format!("{:?}", value.node_id()),
            format!("FqCsidNodeId {{ type: {kind}, .. }}")
        );
        assert_eq!(
            format!("{value:?}"),
            format!(
                "FqCsid {{ node_id: FqCsidNodeId {{ type: {kind}, .. }}, csid_count: {}, .. }}",
                value.csids().len()
            )
        );
    }
}

#[test]
fn decode_and_build_errors_keep_exact_distinct_value_free_labels() {
    let decode = [
        (
            FqCsidDecodeError::MissingTypeAndCount,
            "gtpv2c_fq_csid_missing_type_and_count",
        ),
        (
            FqCsidDecodeError::TruncatedNodeId,
            "gtpv2c_fq_csid_truncated_node_id",
        ),
        (
            FqCsidDecodeError::TruncatedCsids,
            "gtpv2c_fq_csid_truncated_csids",
        ),
        (
            FqCsidDecodeError::ReservedNodeIdType,
            "gtpv2c_fq_csid_reserved_node_id_type",
        ),
        (
            FqCsidDecodeError::InvalidMccMnc,
            "gtpv2c_fq_csid_invalid_mcc_mnc",
        ),
    ];
    let build = [
        (
            FqCsidBuildError::TooManyCsids,
            "gtpv2c_fq_csid_too_many_csids",
        ),
        (FqCsidBuildError::InvalidMcc, "gtpv2c_fq_csid_invalid_mcc"),
        (FqCsidBuildError::InvalidMnc, "gtpv2c_fq_csid_invalid_mnc"),
        (
            FqCsidBuildError::InvalidOperatorId,
            "gtpv2c_fq_csid_invalid_operator_id",
        ),
        (
            FqCsidBuildError::InvalidInstance,
            "gtpv2c_fq_csid_invalid_instance",
        ),
    ];
    let mut labels = std::collections::BTreeSet::new();
    for (error, label) in decode {
        assert_eq!(error.as_str(), label);
        assert_eq!(error.to_string(), label);
        assert!(
            labels.insert(label),
            "each decode error has a distinct label"
        );
    }
    for (error, label) in build {
        assert_eq!(error.as_str(), label);
        assert_eq!(error.to_string(), label);
        assert!(
            labels.insert(label),
            "each build error has a distinct label"
        );
    }
    assert_eq!(labels.len(), 10);
}
