use opc_proto_ngap::n3iwf::modify_fields::{
    ModifiedQosFlows, QosFlowCause, QosFlowCauses, QosFlowModification, QosFlowModifications,
    UplinkModification, UplinkModifications,
};
use opc_proto_ngap::n3iwf::release::{Cause, CauseClass};
use opc_proto_ngap::n3iwf::resource_fields::{
    DownlinkTransport, NonGbrFlow, QosFlowId, UplinkTransport,
};
use opc_protocol::{DecodeContext, EncodeContext};
use serde_json::Value;

fn oracle() -> Value {
    serde_json::from_str(include_str!("fixtures/n3iwf-modify-fields.json")).unwrap()
}
fn context() -> DecodeContext {
    DecodeContext {
        max_message_len: 4096,
        max_ies: 64,
        max_depth: 8,
        ..DecodeContext::default()
    }
}
fn output() -> EncodeContext {
    EncodeContext {
        max_message_len: 4096,
        ..EncodeContext::default()
    }
}
fn bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}
fn qfi(v: &Value) -> QosFlowId {
    QosFlowId::new(v["qfi"].as_u64().unwrap() as u8).unwrap()
}
fn cause(v: &Value) -> Cause {
    Cause::new(
        match v["group"].as_str().unwrap() {
            "radioNetwork" => CauseClass::RadioNetwork,
            "transport" => CauseClass::Transport,
            "nas" => CauseClass::Nas,
            "protocol" => CauseClass::Protocol,
            _ => CauseClass::Misc,
        },
        v["code"].as_u64().unwrap() as u8,
    )
    .unwrap()
}
fn requests(model: &Value) -> Result<QosFlowModifications, opc_protocol::DecodeError> {
    QosFlowModifications::new(
        model
            .as_array()
            .unwrap()
            .iter()
            .map(|v| {
                let p = &v["parameters"];
                if p.is_null() {
                    QosFlowModification::Identifier(qfi(v))
                } else {
                    QosFlowModification::NonGbr(
                        NonGbrFlow::new(
                            qfi(v),
                            p["priority"].as_u64().unwrap() as u8,
                            p["may_preempt"].as_bool().unwrap(),
                            p["preemptable"].as_bool().unwrap(),
                        )
                        .unwrap(),
                    )
                }
            })
            .collect(),
    )
}
fn responses(model: &Value) -> Result<ModifiedQosFlows, opc_protocol::DecodeError> {
    ModifiedQosFlows::new(model.as_array().unwrap().iter().map(qfi).collect())
}
fn causes(model: &Value) -> Result<QosFlowCauses, opc_protocol::DecodeError> {
    QosFlowCauses::new(
        model
            .as_array()
            .unwrap()
            .iter()
            .map(|v| QosFlowCause {
                qfi: qfi(v),
                cause: cause(&v["cause"]),
            })
            .collect(),
    )
}
fn tunnels(model: &Value) -> UplinkModifications {
    UplinkModifications::new(
        model
            .as_array()
            .unwrap()
            .iter()
            .map(|v| UplinkModification {
                uplink: UplinkTransport::new(
                    v["uplink"]["address"].as_str().unwrap().parse().unwrap(),
                    v["uplink"]["teid"].as_u64().unwrap() as u32,
                ),
                downlink: DownlinkTransport::new(
                    v["downlink"]["address"].as_str().unwrap().parse().unwrap(),
                    v["downlink"]["teid"].as_u64().unwrap() as u32,
                ),
            })
            .collect(),
    )
    .unwrap()
}
fn rejects(kind: &str, wire: &[u8]) -> bool {
    match kind {
        "QosFlowAddOrModifyRequestList" => QosFlowModifications::decode(wire, context()).is_err(),
        "QosFlowAddOrModifyResponseList" => ModifiedQosFlows::decode(wire, context()).is_err(),
        "QosFlowListWithCause" => QosFlowCauses::decode(wire, context()).is_err(),
        "UL_NGU_UP_TNLModifyList" => UplinkModifications::decode(wire, context()).is_err(),
        _ => unreachable!(),
    }
}

#[test]
fn independent_root_values_encoding_and_exact_limits() {
    let corpus = oracle();
    assert_eq!(corpus["cases"].as_array().unwrap().len(), 687);
    let mut admitted = 0;
    for row in corpus["cases"].as_array().unwrap() {
        let name = row["name"].as_str().unwrap();
        let kind = row["type"].as_str().unwrap();
        let model = &row["model"];
        let wire = bytes(row["wire_hex"].as_str().unwrap());
        if row["admitted"] == false {
            assert!(rejects(kind, &wire), "{name} receive");
            if row["mode"] == "duplicate" {
                assert!(match kind {
                    "QosFlowAddOrModifyRequestList" => requests(model).is_err(),
                    "QosFlowAddOrModifyResponseList" => responses(model).is_err(),
                    "QosFlowListWithCause" => causes(model).is_err(),
                    _ => false,
                });
            }
            continue;
        }
        macro_rules! check {
            ($ty:ty, $expected:expr, $depth:expr) => {{
                let expected = $expected;
                let ctx = DecodeContext {
                    max_depth: $depth,
                    max_message_len: wire.len(),
                    max_ies: model.as_array().unwrap().len(),
                    ..context()
                };
                assert!(
                    <$ty>::decode(&wire, ctx).unwrap() == expected,
                    "{name} values"
                );
                assert!(
                    expected
                        .encode(EncodeContext {
                            max_message_len: wire.len(),
                            ..output()
                        })
                        .unwrap()
                        .as_bytes()
                        == wire,
                    "{name} encode"
                );
                assert!(
                    expected
                        .encode(EncodeContext {
                            max_message_len: wire.len() - 1,
                            ..output()
                        })
                        .is_err(),
                    "{name} capacity"
                );
                for short in [
                    DecodeContext {
                        max_depth: ctx.max_depth - 1,
                        ..ctx
                    },
                    DecodeContext {
                        max_ies: ctx.max_ies - 1,
                        ..ctx
                    },
                    DecodeContext {
                        max_message_len: ctx.max_message_len - 1,
                        ..ctx
                    },
                ] {
                    assert!(<$ty>::decode(&wire, short).is_err(), "{name} limits");
                }
                assert!(format!("{expected:?}").contains("REDACTED"));
            }};
        }
        match kind {
            "QosFlowAddOrModifyRequestList" => {
                let depth = if model
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|v| !v["parameters"].is_null())
                {
                    6
                } else {
                    3
                };
                check!(QosFlowModifications, requests(model).unwrap(), depth);
            }
            "QosFlowAddOrModifyResponseList" => {
                check!(ModifiedQosFlows, responses(model).unwrap(), 3)
            }
            "QosFlowListWithCause" => check!(QosFlowCauses, causes(model).unwrap(), 4),
            "UL_NGU_UP_TNLModifyList" => check!(UplinkModifications, tunnels(model), 5),
            _ => unreachable!(),
        }
        admitted += 1;
    }
    assert_eq!(admitted, 682);
}

#[test]
fn constructors_preserve_absence_order_direction_and_reject_bad_counts() {
    let qfi = QosFlowId::new(7).unwrap();
    let identifier = QosFlowModification::Identifier(qfi);
    let parameters = QosFlowModification::NonGbr(NonGbrFlow::new(qfi, 1, false, false).unwrap());
    assert!(identifier != parameters);
    assert!(identifier.qfi() == parameters.qfi());
    assert!(QosFlowModifications::new(vec![identifier, parameters]).is_err());
    assert!(QosFlowModifications::new(vec![]).is_err());
    assert!(QosFlowModifications::new(vec![identifier; 65]).is_err());
    assert!(ModifiedQosFlows::new(vec![]).is_err());
    assert!(ModifiedQosFlows::new(vec![qfi; 65]).is_err());
    let failed = QosFlowCause {
        qfi,
        cause: Cause::new(CauseClass::Transport, 0).unwrap(),
    };
    assert!(QosFlowCauses::new(vec![]).is_err());
    assert!(QosFlowCauses::new(vec![failed; 65]).is_err());
    let pair = UplinkModification {
        uplink: UplinkTransport::new("192.0.2.1".parse().unwrap(), 1),
        downlink: DownlinkTransport::new("198.51.100.2".parse().unwrap(), 2),
    };
    assert!(UplinkModifications::new(vec![]).is_err());
    assert!(UplinkModifications::new(vec![pair; 5]).is_err());
    let repeated = UplinkModifications::new(vec![pair, pair]).unwrap();
    let wire = repeated.encode(output()).unwrap();
    assert!(
        UplinkModifications::decode(wire.as_bytes(), context())
            .unwrap()
            .values()
            == [pair, pair]
    );
    let ordered = ModifiedQosFlows::new(vec![
        QosFlowId::new(63).unwrap(),
        QosFlowId::new(0).unwrap(),
    ])
    .unwrap();
    assert_eq!(ordered.values()[0].value(), 63);
    assert_eq!(ordered.values()[1].value(), 0);
}

#[test]
fn explicit_padding_and_extension_mutations_are_rejected() {
    let corpus = oracle();
    let cases = corpus["cases"].as_array().unwrap();
    for name in ["request-identifiers-1", "response-count-1", "cause-root-46"] {
        let row = cases.iter().find(|v| v["name"] == name).unwrap();
        let mut wire = bytes(row["wire_hex"].as_str().unwrap());
        assert_eq!(wire.last().unwrap() & 1, 0);
        *wire.last_mut().unwrap() |= 1;
        assert!(
            rejects(row["type"].as_str().unwrap(), &wire),
            "{name} padding"
        );
    }
    for (name, offsets) in [
        (
            "request-identifiers-1",
            vec![(0, 2), (1, 128), (1, 64), (1, 32)],
        ),
        ("request-parameters-1", vec![(2, 64), (3, 4), (3, 1)]),
        ("response-count-1", vec![(0, 2), (0, 1), (1, 128)]),
        (
            "tunnels-1-0",
            vec![(0, 32), (0, 16), (0, 8), (0, 4), (0, 2), (0, 1), (11, 1)],
        ),
    ] {
        let row = cases.iter().find(|v| v["name"] == name).unwrap();
        let original = bytes(row["wire_hex"].as_str().unwrap());
        for (offset, mask) in offsets {
            let mut wire = original.clone();
            assert_eq!(wire[offset] & mask, 0);
            wire[offset] |= mask;
            assert!(
                rejects(row["type"].as_str().unwrap(), &wire),
                "{name} flags/padding"
            );
        }
    }
}

#[test]
fn independent_truncations_trailing_bytes_and_hostile_counts_are_bounded() {
    let corpus = oracle();
    for row in corpus["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|v| v["admitted"] == true)
    {
        let wire = bytes(row["wire_hex"].as_str().unwrap());
        let kind = row["type"].as_str().unwrap();
        for cut in [0, 1, wire.len() / 2, wire.len() - 1] {
            assert!(rejects(kind, &wire[..cut]), "{} truncation", row["name"]);
        }
        let mut extra = wire.clone();
        extra.push(0);
        assert!(rejects(kind, &extra), "{} trailing", row["name"]);
        for pos in [0, wire.len() / 2, wire.len() - 1] {
            for bit in 0..8 {
                let mut mutated = wire.clone();
                mutated[pos] ^= 1 << bit;
                let _ = rejects(kind, &mutated);
            }
        }
    }
    for kind in [
        "QosFlowAddOrModifyRequestList",
        "QosFlowAddOrModifyResponseList",
        "QosFlowListWithCause",
        "UL_NGU_UP_TNLModifyList",
    ] {
        for wire in [&[0xff][..], &[0xfc, 0, 0][..]] {
            assert!(rejects(kind, wire));
        }
    }
}
