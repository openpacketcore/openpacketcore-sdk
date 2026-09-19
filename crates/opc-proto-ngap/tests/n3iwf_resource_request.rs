#![allow(clippy::unwrap_used)]
use opc_proto_ngap::n3iwf::resource_fields::{
    DownlinkTransport, NonGbrFlow, QosFlowId, QosFlowSetupList, SessionAggregateBitRate,
    SessionType, UplinkTransport,
};
use opc_protocol::{DecodeContext, EncodeContext};
use serde_json::Value;

fn oracle() -> Value {
    serde_json::from_str(include_str!("fixtures/n3iwf-resource-request.json")).unwrap()
}
fn bytes(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|v| u8::from_str_radix(std::str::from_utf8(v).unwrap(), 16).unwrap())
        .collect()
}
fn session_type(m: &Value) -> SessionType {
    match m.as_str().unwrap() {
        "ipv4" => SessionType::Ipv4,
        "ipv6" => SessionType::Ipv6,
        "ipv4v6" => SessionType::Ipv4v6,
        "ethernet" => SessionType::Ethernet,
        "unstructured" => SessionType::Unstructured,
        _ => panic!("reference session kind"),
    }
}
fn flows(m: &Value) -> QosFlowSetupList {
    QosFlowSetupList::new(
        m.as_array()
            .unwrap()
            .iter()
            .map(|f| {
                NonGbrFlow::new(
                    QosFlowId::new(f["qfi"].as_u64().unwrap() as u8).unwrap(),
                    f["priority"].as_u64().unwrap() as u8,
                    f["may_preempt"].as_bool().unwrap(),
                    f["preemptable"].as_bool().unwrap(),
                )
                .unwrap()
            })
            .collect(),
    )
    .unwrap()
}
#[test]
fn independent_resource_fields_match_values_and_constructed_bytes() {
    let reference = oracle();
    for row in reference["fields"].as_array().unwrap() {
        let wire = bytes(row["wire_hex"].as_str().unwrap());
        let model = &row["model"];
        let result = match row["type"].as_str().unwrap() {
            "UPTransportLayerInformation" => {
                let address = model["address"].as_str().unwrap().parse().unwrap();
                let teid = model["teid"].as_u64().unwrap() as u32;
                let up = UplinkTransport::new(address, teid);
                let down = DownlinkTransport::new(address, teid);
                assert!(UplinkTransport::decode(&wire, DecodeContext::default()).unwrap() == up);
                assert!(
                    DownlinkTransport::decode(&wire, DecodeContext::default()).unwrap() == down
                );
                assert!(down.encode(EncodeContext::default()).unwrap().as_bytes() == wire);
                assert!(up.address() == address && up.teid() == teid);
                assert!(down.address() == address && down.teid() == teid);
                up.encode(EncodeContext::default()).unwrap()
            }
            "PDUSessionAggregateMaximumBitRate" => {
                let expected = SessionAggregateBitRate::new(
                    model["downlink"].as_u64().unwrap(),
                    model["uplink"].as_u64().unwrap(),
                )
                .unwrap();
                assert!(
                    SessionAggregateBitRate::decode(&wire, DecodeContext::default()).unwrap()
                        == expected
                );
                assert_eq!(expected.downlink(), model["downlink"].as_u64().unwrap());
                assert_eq!(expected.uplink(), model["uplink"].as_u64().unwrap());
                expected.encode(EncodeContext::default()).unwrap()
            }
            "PDUSessionType" => {
                let expected = session_type(model);
                assert!(SessionType::decode(&wire, DecodeContext::default()).unwrap() == expected);
                expected.encode(EncodeContext::default()).unwrap()
            }
            "QosFlowSetupRequestList" => {
                let expected = flows(model);
                let decoded = QosFlowSetupList::decode(&wire, DecodeContext::default()).unwrap();
                assert!(decoded == expected, "independent QoS fields differ");
                for (got, wanted) in decoded.values().iter().zip(model.as_array().unwrap()) {
                    assert_eq!(got.qfi().value(), wanted["qfi"].as_u64().unwrap() as u8);
                    assert_eq!(got.priority(), wanted["priority"].as_u64().unwrap() as u8);
                    assert_eq!(got.may_preempt(), wanted["may_preempt"].as_bool().unwrap());
                    assert_eq!(got.preemptable(), wanted["preemptable"].as_bool().unwrap());
                }
                expected.encode(EncodeContext::default()).unwrap()
            }
            _ => panic!("reference kind"),
        };
        assert!(
            result.as_bytes() == wire,
            "independent field bytes differ for {}",
            row["type"]
        );
    }
    assert_eq!(reference["fields"].as_array().unwrap().len(), 225);
}

use opc_proto_ngap::n3iwf::resource_request::SetupRequestTransfer;
use opc_protocol::{DuplicateIePolicy, UnknownIePolicy, ValidationLevel};
fn context() -> DecodeContext {
    DecodeContext {
        max_message_len: 200_000,
        validation_level: ValidationLevel::Strict,
        duplicate_ie_policy: DuplicateIePolicy::Reject,
        ..DecodeContext::default()
    }
}
fn transfer(model: &Value) -> SetupRequestTransfer {
    SetupRequestTransfer {
        security: None,
        network_instance: None,
        common_network_instance: None,
        uplink: UplinkTransport::new(
            model["uplink"]["address"]
                .as_str()
                .unwrap()
                .parse()
                .unwrap(),
            model["uplink"]["teid"].as_u64().unwrap() as u32,
        ),
        aggregate_bit_rate: SessionAggregateBitRate::new(
            model["ambr"]["downlink"].as_u64().unwrap(),
            model["ambr"]["uplink"].as_u64().unwrap(),
        )
        .unwrap(),
        session_type: session_type(&model["session_type"]),
        flows: flows(&model["flows"]),
    }
}
#[test]
fn independent_transfers_cover_required_conditional_and_policy_cases() {
    let reference = oracle();
    let mut admitted = 0;
    for row in reference["transfers"].as_array().unwrap() {
        let wire = bytes(row["wire_hex"].as_str().unwrap());
        let mode = row["mode"].as_str().unwrap();
        let result = SetupRequestTransfer::decode(&wire, context());
        if mode == "construct"
            || mode.starts_with("unknown-ignore")
            || mode.starts_with("unknown-notify")
        {
            let decoded = result.unwrap();
            let expected = transfer(&row["model"]);
            assert!(
                decoded.transfer == expected,
                "independent transfer fields differ"
            );
            assert_eq!(
                decoded.ignored_ie_count,
                usize::from(mode.starts_with("unknown-ignore"))
            );
            assert_eq!(
                decoded.notify_ie_ids,
                if mode.starts_with("unknown-notify") {
                    vec![65535]
                } else {
                    vec![]
                }
            );
            let encoded = expected.encode(EncodeContext::default()).unwrap();
            assert!(encoded.as_bytes() == bytes(row["canonical_wire_hex"].as_str().unwrap()));
            for unknown_ie_policy in [UnknownIePolicy::Drop, UnknownIePolicy::Reject] {
                let selected = SetupRequestTransfer::decode(
                    &wire,
                    DecodeContext {
                        unknown_ie_policy,
                        ..context()
                    },
                );
                if mode == "construct" || unknown_ie_policy == UnknownIePolicy::Drop {
                    let selected = selected.unwrap();
                    assert!(selected.transfer == expected);
                    assert_eq!(selected.ignored_ie_count, 0);
                    assert!(selected.notify_ie_ids.is_empty());
                } else {
                    assert!(selected.is_err());
                }
            }
            admitted += 1;
        } else {
            assert!(
                result.is_err(),
                "negative independent mode {mode} was admitted"
            );
            if mode == "duplicate" {
                for duplicate_ie_policy in [DuplicateIePolicy::First, DuplicateIePolicy::Last] {
                    assert!(SetupRequestTransfer::decode(
                        &wire,
                        DecodeContext {
                            duplicate_ie_policy,
                            ..context()
                        }
                    )
                    .is_ok());
                }
            }
        }
    }
    assert_eq!(reference["transfers"].as_array().unwrap().len(), 49);
    assert_eq!(admitted, 34);
}
fn append_ie(input: &[u8], id: u16, criticality: u8, value: &[u8]) -> Vec<u8> {
    assert!(value.len() < 128);
    let mut wire = input.to_vec();
    let count = u16::from_be_bytes([wire[1], wire[2]]) + 1;
    wire[1..3].copy_from_slice(&count.to_be_bytes());
    wire.extend_from_slice(&id.to_be_bytes());
    wire.push(criticality << 6);
    wire.push(value.len() as u8);
    wire.extend_from_slice(value);
    wire
}
#[test]
fn selection_precedes_field_admission_and_unqualified_optional_fields_fail() {
    let reference = oracle();
    let base = &reference["transfers"][0];
    let wire = bytes(base["wire_hex"].as_str().unwrap());
    let changed = append_ie(&wire, 134, 0, &[0x10]); // independently qualified IPv6 enumeration
    let first = SetupRequestTransfer::decode(
        &changed,
        DecodeContext {
            duplicate_ie_policy: DuplicateIePolicy::First,
            ..context()
        },
    )
    .unwrap();
    let last = SetupRequestTransfer::decode(
        &changed,
        DecodeContext {
            duplicate_ie_policy: DuplicateIePolicy::Last,
            ..context()
        },
    )
    .unwrap();
    assert!(first.transfer.session_type == SessionType::Ipv4);
    assert!(last.transfer.session_type == SessionType::Ipv6);
    assert!(SetupRequestTransfer::decode(&changed, context()).is_err());
    let malformed = append_ie(&wire, 134, 0, &[0xff]);
    assert!(SetupRequestTransfer::decode(
        &malformed,
        DecodeContext {
            duplicate_ie_policy: DuplicateIePolicy::First,
            ..context()
        }
    )
    .is_ok());
    assert!(SetupRequestTransfer::decode(
        &malformed,
        DecodeContext {
            duplicate_ie_policy: DuplicateIePolicy::Last,
            ..context()
        }
    )
    .is_err());
    for row in reference["request_ie_metadata"].as_array().unwrap() {
        let id = row["id"].as_u64().unwrap() as u16;
        if [130, 139, 134, 136, 127].contains(&id) {
            continue;
        }
        let crit = if row["criticality"] == "reject" { 0 } else { 1 };
        let changed = append_ie(&wire, id, crit, &[0xff]);
        for unknown_ie_policy in [UnknownIePolicy::Preserve, UnknownIePolicy::Drop] {
            assert!(
                SetupRequestTransfer::decode(
                    &changed,
                    DecodeContext {
                        unknown_ie_policy,
                        ..context()
                    }
                )
                .is_err(),
                "known optional IE was silently admitted"
            );
        }
    }
    let critical = append_ie(&wire, 65535, 0, &[]);
    assert!(SetupRequestTransfer::decode(&critical, DecodeContext::default()).is_err());
    for unknown_ie_policy in [UnknownIePolicy::Preserve, UnknownIePolicy::Drop] {
        assert!(SetupRequestTransfer::decode(
            &critical,
            DecodeContext {
                unknown_ie_policy,
                ..context()
            }
        )
        .is_err());
    }
    let discarded = SetupRequestTransfer::decode(
        &critical,
        DecodeContext {
            unknown_ie_policy: UnknownIePolicy::Drop,
            ..DecodeContext::default()
        },
    )
    .unwrap();
    assert_eq!(discarded.ignored_ie_count, 0); // preserves the generic Structural/Drop policy
    assert!(discarded.notify_ie_ids.is_empty());
}

#[test]
fn resource_limits_extensions_and_redaction_are_explicit() {
    assert!(QosFlowId::new(64).is_err());
    assert!(NonGbrFlow::new(QosFlowId::new(1).unwrap(), 0, false, false).is_err());
    assert!(NonGbrFlow::new(QosFlowId::new(1).unwrap(), 16, false, false).is_err());
    assert!(SessionAggregateBitRate::new(4_000_000_000_001, 0).is_err());
    assert!(SessionAggregateBitRate::new(0, 4_000_000_000_001).is_err());
    let flow = NonGbrFlow::new(QosFlowId::new(1).unwrap(), 1, false, false).unwrap();
    assert!(QosFlowSetupList::new(vec![]).is_err());
    assert!(QosFlowSetupList::new(vec![flow; 65]).is_err());
    assert!(QosFlowSetupList::new(vec![flow; 2]).is_err());
    assert!(QosFlowSetupList::decode(&[0xfc], context()).is_err()); // impossible physical count
    let reference = oracle();
    for row in reference["fields"].as_array().unwrap() {
        let wire = bytes(row["wire_hex"].as_str().unwrap());
        let short = DecodeContext {
            max_message_len: wire.len() - 1,
            ..context()
        };
        let output = EncodeContext {
            max_message_len: wire.len() - 1,
            ..EncodeContext::default()
        };
        let exact = EncodeContext {
            max_message_len: wire.len(),
            ..EncodeContext::default()
        };
        let mut trailing = wire.clone();
        trailing.push(0);
        let debug = match row["type"].as_str().unwrap() {
            "UPTransportLayerInformation" => {
                let field = UplinkTransport::decode(&wire, context()).unwrap();
                assert!(field.encode(output).is_err());
                assert!(field.encode(exact).is_ok());
                assert!(UplinkTransport::decode(&wire, short).is_err());
                assert!(UplinkTransport::decode(
                    &wire,
                    DecodeContext {
                        max_depth: 2,
                        ..context()
                    }
                )
                .is_err());
                assert!(UplinkTransport::decode(&trailing, context()).is_err());
                for mask in [0x80, 0x40, 0x20, 0x10] {
                    let mut changed = wire.clone();
                    changed[0] |= mask;
                    assert!(UplinkTransport::decode(&changed, context()).is_err());
                }
                format!("{field:?}")
            }
            "PDUSessionAggregateMaximumBitRate" => {
                let field = SessionAggregateBitRate::decode(&wire, context()).unwrap();
                assert!(field.encode(output).is_err());
                assert!(field.encode(exact).is_ok());
                assert!(SessionAggregateBitRate::decode(&wire, short).is_err());
                assert!(SessionAggregateBitRate::decode(
                    &wire,
                    DecodeContext {
                        max_depth: 1,
                        ..context()
                    }
                )
                .is_err());
                assert!(SessionAggregateBitRate::decode(&trailing, context()).is_err());
                for mask in [0x80, 0x40] {
                    let mut changed = wire.clone();
                    changed[0] |= mask;
                    assert!(SessionAggregateBitRate::decode(&changed, context()).is_err());
                }
                format!("{field:?}")
            }
            "PDUSessionType" => {
                let field = SessionType::decode(&wire, context()).unwrap();
                assert!(field.encode(output).is_err());
                assert!(field.encode(exact).is_ok());
                assert!(SessionType::decode(&wire, short).is_err());
                assert!(SessionType::decode(
                    &wire,
                    DecodeContext {
                        max_depth: 0,
                        ..context()
                    }
                )
                .is_err());
                assert!(SessionType::decode(&trailing, context()).is_err());
                let mut changed = wire.clone();
                changed[0] |= 0x80;
                assert!(SessionType::decode(&changed, context()).is_err());
                format!("{field:?}")
            }
            _ => {
                let field = QosFlowSetupList::decode(&wire, context()).unwrap();
                assert!(field.encode(output).is_err());
                assert!(field.encode(exact).is_ok());
                assert!(QosFlowSetupList::decode(&wire, short).is_err());
                assert!(QosFlowSetupList::decode(
                    &wire,
                    DecodeContext {
                        max_depth: 5,
                        ..context()
                    }
                )
                .is_err());
                assert!(QosFlowSetupList::decode(
                    &wire,
                    DecodeContext {
                        max_ies: field.values().len() - 1,
                        ..context()
                    }
                )
                .is_err());
                assert!(QosFlowSetupList::decode(
                    &wire,
                    DecodeContext {
                        max_ies: field.values().len(),
                        ..context()
                    }
                )
                .is_ok());
                assert!(QosFlowSetupList::decode(&trailing, context()).is_err());
                // Count occupies six bits; item flags straddle the first two bytes.
                for bit in [
                    6usize, 7, 8, 9, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28,
                ] {
                    let mut changed = wire.clone();
                    changed[bit / 8] |= 1 << (7 - bit % 8);
                    assert!(
                        QosFlowSetupList::decode(&changed, context()).is_err(),
                        "unsupported QoS flag admitted"
                    );
                }
                format!("{field:?}")
            }
        };
        assert!(debug.contains("REDACTED"));
        assert!(!debug.chars().any(|c| c.is_ascii_digit()));
    }
    for row in reference["transfers"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["mode"] == "construct")
    {
        let wire = bytes(row["wire_hex"].as_str().unwrap());
        let expected = transfer(&row["model"]);
        assert!(expected
            .encode(EncodeContext {
                max_message_len: wire.len() - 1,
                ..EncodeContext::default()
            })
            .is_err());
        assert!(expected
            .encode(EncodeContext {
                max_message_len: wire.len(),
                ..EncodeContext::default()
            })
            .is_ok());
        assert!(SetupRequestTransfer::decode(
            &wire,
            DecodeContext {
                max_message_len: wire.len() - 1,
                ..context()
            }
        )
        .is_err());
        assert!(SetupRequestTransfer::decode(
            &wire,
            DecodeContext {
                max_depth: 9,
                ..context()
            }
        )
        .is_err());
        assert!(SetupRequestTransfer::decode(
            &wire,
            DecodeContext {
                max_ies: 3,
                ..context()
            }
        )
        .is_err());
        assert!(SetupRequestTransfer::decode(
            &wire,
            DecodeContext {
                max_depth: 10,
                max_ies: expected.flows.values().len().max(4),
                ..context()
            }
        )
        .is_ok());
        let mut changed = wire.clone();
        changed[0] |= 0x80;
        assert!(SetupRequestTransfer::decode(&changed, context()).is_err());
        let mut changed = wire.clone();
        changed[0] |= 1;
        assert!(SetupRequestTransfer::decode(&changed, context()).is_err());
        let mut changed = wire.clone();
        changed[1..3].copy_from_slice(&65535u16.to_be_bytes());
        assert!(SetupRequestTransfer::decode(&changed, context()).is_err());
        let mut changed = wire.clone();
        changed[5] |= 1;
        assert!(SetupRequestTransfer::decode(&changed, context()).is_err());
        let mut changed = wire.clone();
        changed[5] = 0xc0;
        assert!(SetupRequestTransfer::decode(&changed, context()).is_err());
        let mut changed = wire.clone();
        changed.push(0);
        assert!(SetupRequestTransfer::decode(&changed, context()).is_err());
        let debug = format!(
            "{:?}",
            SetupRequestTransfer::decode(&wire, context()).unwrap()
        );
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains(row["model"]["uplink"]["address"].as_str().unwrap()));
    }
}
fn exercise(data: &[u8]) {
    let output = EncodeContext {
        max_message_len: 200_000,
        ..EncodeContext::default()
    };
    macro_rules! field {
        ($kind:ty) => {
            if let Ok(value) = <$kind>::decode(data, context()) {
                let encoded = value.encode(output).unwrap();
                assert!(<$kind>::decode(encoded.as_bytes(), context()).unwrap() == value);
            }
        };
    }
    field!(UplinkTransport);
    field!(DownlinkTransport);
    field!(SessionAggregateBitRate);
    field!(SessionType);
    field!(QosFlowSetupList);
    if let Ok(value) = SetupRequestTransfer::decode(data, context()) {
        let encoded = value.transfer.encode(output).unwrap();
        let decoded = SetupRequestTransfer::decode(encoded.as_bytes(), context()).unwrap();
        assert!(decoded.transfer == value.transfer);
        assert_eq!(decoded.ignored_ie_count, 0);
        assert!(decoded.notify_ie_ids.is_empty());
    }
}
#[test]
fn all_independent_truncations_and_bounded_byte_mutations_are_safe() {
    let reference = oracle();
    for row in reference["fields"]
        .as_array()
        .unwrap()
        .iter()
        .chain(reference["transfers"].as_array().unwrap())
    {
        let wire = bytes(row["wire_hex"].as_str().unwrap());
        for end in 0..=wire.len() {
            exercise(&wire[..end]);
        }
        for index in (0..wire.len()).step_by((wire.len() / 128).max(1)) {
            for mask in [1, 0x80, 0xff] {
                let mut changed = wire.clone();
                changed[index] ^= mask;
                exercise(&changed);
            }
        }
    }
}
