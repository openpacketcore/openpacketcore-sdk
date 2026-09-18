use opc_proto_ngap::n3iwf::reset_fields::{
    Connection, Connections, CriticalityDiagnostics, DiagnosticCriticality, DiagnosticError,
    DiagnosticItem, DiagnosticItems, ResetType, TriggeringOutcome,
};
use opc_proto_ngap::n3iwf::{AmfUeId, RanUeId};
use opc_proto_ngap::Criticality;
use opc_protocol::{DecodeContext, EncodeContext};
use serde_json::Value;

fn oracle() -> Value {
    serde_json::from_str(include_str!("fixtures/n3iwf-reset-fields.json")).unwrap()
}
fn context() -> DecodeContext {
    DecodeContext {
        max_message_len: 2_000_000,
        max_ies: 65536,
        max_depth: 16,
        ..DecodeContext::default()
    }
}
fn output() -> EncodeContext {
    EncodeContext {
        max_message_len: 2_000_000,
        ..EncodeContext::default()
    }
}
fn bytes(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).unwrap())
        .collect()
}
fn expanded(model: &Value) -> Vec<Value> {
    if let Some(values) = model.as_array() {
        return values.clone();
    }
    let cycle = model["cycle"].as_array().unwrap();
    (0..model["count"].as_u64().unwrap() as usize)
        .map(|i| cycle[i % cycle.len()].clone())
        .collect()
}
fn connections(model: &Value) -> Connections {
    Connections::new(
        expanded(model)
            .iter()
            .map(|v| Connection {
                amf: v["amf"].as_u64().map(|v| AmfUeId::new(v).unwrap()),
                ran: v["ran"].as_u64().map(|v| RanUeId::new(v as u32)),
            })
            .collect(),
    )
    .unwrap()
}
fn criticality(value: &str) -> Criticality {
    match value {
        "reject" => Criticality::reject,
        "ignore" => Criticality::ignore,
        _ => Criticality::notify,
    }
}
fn diagnostics(model: &Value) -> Option<CriticalityDiagnostics> {
    let ies = if let Some(items) = model["items"].as_array() {
        let mut values = Vec::new();
        for item in items {
            let criticality = match item["criticality"].as_str().unwrap() {
                "reject" => DiagnosticCriticality::Reject,
                "notify" => DiagnosticCriticality::Notify,
                _ => return None,
            };
            values.push(DiagnosticItem {
                criticality,
                id: item["id"].as_u64().unwrap() as u16,
                error: if item["error"] == "missing" {
                    DiagnosticError::Missing
                } else {
                    DiagnosticError::NotUnderstood
                },
            });
        }
        Some(DiagnosticItems::new(values).unwrap())
    } else {
        None
    };
    Some(CriticalityDiagnostics {
        procedure_code: model["procedure_code"].as_u64().map(|v| v as u8),
        triggering_outcome: model["trigger"].as_str().map(|v| match v {
            "initiating-message" => TriggeringOutcome::Initiating,
            "successful-outcome" => TriggeringOutcome::Successful,
            _ => TriggeringOutcome::Unsuccessful,
        }),
        procedure_criticality: model["criticality"].as_str().map(criticality),
        ies,
    })
}

#[test]
fn independent_values_construction_and_exact_limits() {
    let reference = oracle();
    assert_eq!(reference["cases"].as_array().unwrap().len(), 1093);
    let mut admitted = 0;
    for row in reference["cases"].as_array().unwrap() {
        let wire = bytes(row["wire_hex"].as_str().unwrap());
        let model = &row["model"];
        let name = row["name"].as_str().unwrap();
        if row["admitted"] == false {
            assert!(diagnostics(model).is_none());
            assert!(CriticalityDiagnostics::decode(&wire, context()).is_err());
            continue;
        }
        macro_rules! check {
            ($type:ty, $expected:expr, $depth:expr, $count:expr) => {{
                let expected = $expected;
                let count = $count;
                let ctx = DecodeContext {
                    max_depth: $depth,
                    max_ies: count,
                    max_message_len: wire.len(),
                    ..context()
                };
                let out = EncodeContext {
                    max_message_len: wire.len(),
                    ..output()
                };
                assert!(
                    <$type>::decode(&wire, ctx).unwrap() == expected,
                    "{name} decode"
                );
                assert!(
                    expected.encode(out).unwrap().as_bytes() == wire,
                    "{name} encode"
                );
                assert!(expected
                    .encode(EncodeContext {
                        max_message_len: wire.len() - 1,
                        ..out
                    })
                    .is_err());
                for short in [
                    DecodeContext {
                        max_depth: $depth - 1,
                        ..ctx
                    },
                    DecodeContext {
                        max_message_len: wire.len() - 1,
                        ..ctx
                    },
                ] {
                    assert!(<$type>::decode(&wire, short).is_err(), "{name} limit");
                }
                if count > 0 {
                    assert!(
                        <$type>::decode(
                            &wire,
                            DecodeContext {
                                max_ies: count - 1,
                                ..ctx
                            }
                        )
                        .is_err(),
                        "{name} count"
                    );
                }
                assert!(format!("{expected:?}").contains("REDACTED"));
            }};
        }
        match row["type"].as_str().unwrap() {
            "UE_associatedLogicalNG_connectionList" => {
                let expected = connections(model);
                let count = expected.values().len();
                check!(Connections, expected, 3, count);
            }
            "ResetType" if model["all"] == true => check!(ResetType, ResetType::All, 2, 0),
            "ResetType" => {
                let values = connections(&model["connections"]);
                let count = values.values().len();
                check!(ResetType, ResetType::Part(values), 4, count);
            }
            "CriticalityDiagnostics" => {
                let expected = diagnostics(model).unwrap();
                let count = expected.ies.as_ref().map_or(0, |v| v.values().len());
                check!(
                    CriticalityDiagnostics,
                    expected,
                    if count == 0 { 2 } else { 4 },
                    count
                );
            }
            _ => unreachable!(),
        }
        admitted += 1;
    }
    assert_eq!(admitted, 1079);
}

#[test]
fn empty_items_are_ignored_without_losing_order_or_repeated_ids() {
    let empty = Connection {
        amf: None,
        ran: None,
    };
    let pair = Connection {
        amf: Some(AmfUeId::new(7).unwrap()),
        ran: Some(RanUeId::new(3)),
    };
    let only_ran = Connection {
        amf: None,
        ran: pair.ran,
    };
    let list = Connections::new(vec![empty, pair, empty, only_ran, pair]).unwrap();
    assert_eq!(list.ignored_empty_count(), 2);
    assert!(list.nonempty().copied().collect::<Vec<_>>() == [pair, only_ran, pair]);
    let wire = list.encode(output()).unwrap();
    assert!(Connections::decode(wire.as_bytes(), context()).unwrap() == list);
    let empty_list = Connections::new(vec![empty, empty]).unwrap();
    assert_eq!(empty_list.nonempty().count(), 0);
    let part = ResetType::Part(empty_list);
    let wire = part.encode(output()).unwrap();
    assert!(matches!(
        ResetType::decode(wire.as_bytes(), context()).unwrap(),
        ResetType::Part(_)
    ));
    assert!(Connections::new(vec![]).is_err());
    assert!(Connections::new(vec![empty; 65537]).is_err());
    assert!(DiagnosticItems::new(vec![]).is_err());
    assert!(DiagnosticItems::new(vec![
        DiagnosticItem {
            criticality: DiagnosticCriticality::Reject,
            id: 7,
            error: DiagnosticError::Missing
        };
        257
    ])
    .is_err());
}

fn rejected(kind: &str, wire: &[u8]) -> bool {
    match kind {
        "UE_associatedLogicalNG_connectionList" => Connections::decode(wire, context()).is_err(),
        "ResetType" => ResetType::decode(wire, context()).is_err(),
        "CriticalityDiagnostics" => CriticalityDiagnostics::decode(wire, context()).is_err(),
        _ => unreachable!(),
    }
}

#[test]
fn nonzero_alignment_and_final_padding_are_rejected() {
    let reference = oracle();
    // A single empty connection has four flags and four final padding bits.
    // An empty Diagnostics has six flags and two final padding bits. Partial
    // Reset also aligns its two-bit choice before the element-count determinant.
    for (name, final_bits, choice_bits) in [
        ("list-widths-None-None", 4, 0),
        ("partial-widths-None-None", 4, 6),
        ("presence-0", 2, 0),
    ] {
        let row = reference["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["name"] == name)
            .unwrap();
        let wire = bytes(row["wire_hex"].as_str().unwrap());
        let kind = row["type"].as_str().unwrap();
        assert!(!rejected(kind, &wire), "{name} baseline");
        for (index, bits) in [(wire.len() - 1, final_bits), (0, choice_bits)] {
            for bit in 0..bits {
                assert_eq!(wire[index] & (1 << bit), 0);
                let mut changed = wire.clone();
                changed[index] |= 1 << bit;
                assert!(rejected(kind, &changed), "{name} byte {index} bit {bit}");
            }
        }
    }
}

#[test]
fn extensions_truncations_trailing_data_and_hostile_counts_are_rejected() {
    let reference = oracle();
    for row in reference["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|v| v["admitted"] == true)
    {
        let wire = bytes(row["wire_hex"].as_str().unwrap());
        let kind = row["type"].as_str().unwrap();
        let name = row["name"].as_str().unwrap();
        let stride = (wire.len() / 16).max(1);
        for end in (0..wire.len()).step_by(stride).chain([wire.len() - 1]) {
            assert!(rejected(kind, &wire[..end]), "{name} truncation");
        }
        let mut trailing = wire.clone();
        trailing.push(0);
        assert!(rejected(kind, &trailing), "{name} trailing");
        if kind == "CriticalityDiagnostics" {
            for mask in [0x80, 4] {
                let mut changed = wire.clone();
                changed[0] |= mask;
                assert!(rejected(kind, &changed), "{name} extension");
            }
        } else if row["model"]["all"] == true {
            for bit in 0..8 {
                let mut changed = wire.clone();
                changed[0] |= 1 << bit;
                assert!(rejected(kind, &changed), "{name} all framing");
            }
        } else {
            let start = usize::from(kind == "ResetType");
            let item = start
                + if wire[start] >= 128 && wire[start] < 192 {
                    2
                } else {
                    1
                };
            for mask in [0x80, 0x10] {
                let mut changed = wire.clone();
                changed[item] |= mask;
                assert!(rejected(kind, &changed), "{name} item extension");
            }
        }
    }
    for wire in [
        vec![],
        vec![0],
        vec![0xc0],
        vec![0xc4],
        vec![0xc5, 0],
        vec![0x80, 1, 0],
        vec![0xff; 16],
    ] {
        assert!(Connections::decode(&wire, context()).is_err());
    }
}
