use opc_proto_ngap::n3iwf::notify_fields::{
    NotificationCause, NotifiedQosFlow, NotifiedSession, NotifiedSessions, NotifyReleasedTransfer,
    NotifyTransfer, ReleasedQosFlow, ReleasedSession, ReleasedSessions,
};
use opc_proto_ngap::n3iwf::release::{Cause, CauseClass};
use opc_proto_ngap::n3iwf::resource_fields::QosFlowId;
use opc_proto_ngap::n3iwf::session_lists::SessionId;
use opc_protocol::{DecodeContext, EncodeContext};
use serde_json::Value;

fn oracle() -> Value {
    serde_json::from_str(include_str!("fixtures/n3iwf-notify-fields.json")).unwrap()
}
fn context() -> DecodeContext {
    DecodeContext {
        max_message_len: 200_000,
        max_ies: 256,
        max_depth: 16,
        ..DecodeContext::default()
    }
}
fn output() -> EncodeContext {
    EncodeContext {
        max_message_len: 200_000,
        ..EncodeContext::default()
    }
}
fn bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
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
fn notify(model: &Value) -> Result<NotifyTransfer, opc_protocol::DecodeError> {
    NotifyTransfer::new(
        model["notified"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| NotifiedQosFlow {
                qfi: QosFlowId::new(v["qfi"].as_u64().unwrap() as u8).unwrap(),
                cause: if v["fulfilled"] == true {
                    NotificationCause::Fulfilled
                } else {
                    NotificationCause::NotFulfilled
                },
            })
            .collect(),
        model["released"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| ReleasedQosFlow {
                qfi: QosFlowId::new(v["qfi"].as_u64().unwrap() as u8).unwrap(),
                cause: cause(&v["cause"]),
            })
            .collect(),
    )
}
fn notified(model: &Value) -> Result<NotifiedSessions, opc_protocol::DecodeError> {
    NotifiedSessions::new(
        model
            .as_array()
            .unwrap()
            .iter()
            .map(|v| {
                Ok(NotifiedSession {
                    id: SessionId::new(v["id"].as_u64().unwrap() as u8),
                    transfer: notify(&v["transfer"])?,
                })
            })
            .collect::<Result<_, opc_protocol::DecodeError>>()?,
    )
}
fn released(model: &Value) -> Result<ReleasedSessions, opc_protocol::DecodeError> {
    ReleasedSessions::new(
        model
            .as_array()
            .unwrap()
            .iter()
            .map(|v| ReleasedSession {
                id: SessionId::new(v["id"].as_u64().unwrap() as u8),
                transfer: NotifyReleasedTransfer {
                    cause: cause(&v["cause"]),
                },
            })
            .collect(),
    )
}
fn transfer_limits(model: &Value) -> (usize, usize) {
    let n = model["notified"].as_array().unwrap().len();
    let r = model["released"].as_array().unwrap().len();
    (if r == 0 { 4 } else { 5 }, n + r)
}
fn rejects(kind: &str, wire: &[u8]) -> bool {
    match kind {
        "PDUSessionResourceNotifyTransfer" => NotifyTransfer::decode(wire, context()).is_err(),
        "PDUSessionResourceNotifyReleasedTransfer" => {
            NotifyReleasedTransfer::decode(wire, context()).is_err()
        }
        "PDUSessionResourceNotifyList" => NotifiedSessions::decode(wire, context()).is_err(),
        "PDUSessionResourceReleasedListNot" => ReleasedSessions::decode(wire, context()).is_err(),
        _ => unreachable!(),
    }
}

#[test]
fn independent_fields_values_construction_and_exact_limits() {
    let corpus = oracle();
    assert_eq!(corpus["cases"].as_array().unwrap().len(), 971);
    let mut admitted = 0;
    for row in corpus["cases"].as_array().unwrap() {
        let wire = bytes(row["wire_hex"].as_str().unwrap());
        let kind = row["type"].as_str().unwrap();
        let model = &row["model"];
        let name = row["name"].as_str().unwrap();
        if row["admitted"] == false {
            assert!(rejects(kind, &wire), "{name} receive");
            assert!(
                match kind {
                    "PDUSessionResourceNotifyTransfer" => notify(model).is_err(),
                    "PDUSessionResourceNotifyList" => notified(model).is_err(),
                    "PDUSessionResourceReleasedListNot" => released(model).is_err(),
                    _ => false,
                },
                "{name} constructor"
            );
            continue;
        }
        macro_rules! check {
            ($ty:ty,$expected:expr,$depth:expr,$count:expr) => {{
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
                    <$ty>::decode(&wire, ctx).unwrap() == expected,
                    "{name} values"
                );
                assert!(
                    expected.encode(out).unwrap().as_bytes() == wire,
                    "{name} encode"
                );
                assert!(
                    expected
                        .encode(EncodeContext {
                            max_message_len: wire.len() - 1,
                            ..out
                        })
                        .is_err(),
                    "{name} capacity"
                );
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
                    assert!(<$ty>::decode(&wire, short).is_err(), "{name} limit");
                }
                if count > 0 {
                    assert!(
                        <$ty>::decode(
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
        match kind {
            "PDUSessionResourceNotifyTransfer" => {
                let (depth, count) = transfer_limits(model);
                check!(NotifyTransfer, notify(model).unwrap(), depth, count);
            }
            "PDUSessionResourceNotifyReleasedTransfer" => check!(
                NotifyReleasedTransfer,
                NotifyReleasedTransfer {
                    cause: cause(model)
                },
                3,
                0
            ),
            "PDUSessionResourceNotifyList" => {
                let models = model.as_array().unwrap();
                let limits: Vec<_> = models
                    .iter()
                    .map(|v| transfer_limits(&v["transfer"]))
                    .collect();
                let depth = 3 + limits.iter().map(|v| v.0).max().unwrap();
                let count = models.len().max(limits.iter().map(|v| v.1).max().unwrap());
                check!(NotifiedSessions, notified(model).unwrap(), depth, count);
            }
            "PDUSessionResourceReleasedListNot" => check!(
                ReleasedSessions,
                released(model).unwrap(),
                6,
                model.as_array().unwrap().len()
            ),
            _ => unreachable!(),
        }
        admitted += 1;
    }
    assert_eq!(admitted, 964);
}

#[test]
fn constructor_bounds_and_conflicting_flow_reports_are_rejected() {
    let qfi = QosFlowId::new(7).unwrap();
    let cause = Cause::new(CauseClass::Nas, 0).unwrap();
    let item = NotifiedQosFlow {
        qfi,
        cause: NotificationCause::Fulfilled,
    };
    let release = ReleasedQosFlow { qfi, cause };
    assert!(NotifyTransfer::new(vec![], vec![]).is_err());
    assert!(NotifyTransfer::new(vec![item; 65], vec![]).is_err());
    assert!(NotifyTransfer::new(vec![], vec![release; 65]).is_err());
    assert!(NotifyTransfer::new(vec![item, item], vec![]).is_err());
    assert!(NotifyTransfer::new(vec![item], vec![release]).is_err());
    assert!(NotifyTransfer::new(vec![], vec![release, release]).is_err());
    assert!(NotifiedSessions::new(vec![]).is_err());
    assert!(ReleasedSessions::new(vec![]).is_err());
    let item = ReleasedSession {
        id: SessionId::new(7),
        transfer: NotifyReleasedTransfer { cause },
    };
    assert!(ReleasedSessions::new(vec![item; 257]).is_err());
}

#[test]
fn exact_padding_extension_flags_and_nonminimal_lengths_are_rejected() {
    let corpus = oracle();
    let rows = corpus["cases"].as_array().unwrap();
    let one = rows
        .iter()
        .find(|v| v["name"] == "notified-count-1")
        .unwrap();
    let wire = bytes(one["wire_hex"].as_str().unwrap());
    // Four root flags, six count bits, then 11 bits for the single item.
    for bit in [0, 3, 10, 11, 12, 19, 21, 22, 23] {
        let mut changed = wire.clone();
        changed[bit / 8] |= 1 << (7 - bit % 8);
        assert!(
            NotifyTransfer::decode(&changed, context()).is_err(),
            "bit {bit}"
        );
    }
    let one = rows
        .iter()
        .find(|v| {
            v["type"] == "PDUSessionResourceNotifyReleasedTransfer"
                && v["model"]["group"] == "transport"
                && v["model"]["code"] == 0
        })
        .unwrap();
    let wire = bytes(one["wire_hex"].as_str().unwrap());
    for mask in [0x80, 0x40, 1] {
        let mut changed = wire.clone();
        changed[0] |= mask;
        assert!(NotifyReleasedTransfer::decode(&changed, context()).is_err());
    }
    for name in ["notified-sessions-1", "released-sessions-1"] {
        let row = rows.iter().find(|v| v["name"] == name).unwrap();
        let wire = bytes(row["wire_hex"].as_str().unwrap());
        for bit in 0..8 {
            let mut changed = wire.clone();
            changed[1] |= 1 << bit;
            assert!(
                rejects(row["type"].as_str().unwrap(), &changed),
                "{name} item bit {bit}"
            );
        }
        let mut changed = wire.clone();
        changed.splice(3..4, [0x80, wire[3]]);
        assert!(
            rejects(row["type"].as_str().unwrap(), &changed),
            "{name} determinant"
        );
    }
}

#[test]
fn complete_field_truncations_trailing_data_and_hostile_counts_reject() {
    for row in oracle()["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|v| v["admitted"] == true)
    {
        let wire = bytes(row["wire_hex"].as_str().unwrap());
        let kind = row["type"].as_str().unwrap();
        let name = row["name"].as_str().unwrap();
        for end in (0..wire.len())
            .step_by((wire.len() / 12).max(1))
            .chain([wire.len() - 1])
        {
            assert!(rejects(kind, &wire[..end]), "{name} truncation");
        }
        let mut changed = wire.clone();
        changed.push(0);
        assert!(rejects(kind, &changed), "{name} trailing");
    }
    for wire in [
        &[][..],
        &[0xff][..],
        &[0xff, 0, 0][..],
        &[0, 0, 0, 0xc4][..],
    ] {
        assert!(NotifiedSessions::decode(wire, context()).is_err());
        assert!(ReleasedSessions::decode(wire, context()).is_err());
    }
}
