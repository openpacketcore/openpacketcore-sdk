use opc_proto_ngap::n3iwf::modify_fields::{ModifiedQosFlows, QosFlowCause, QosFlowCauses};
use opc_proto_ngap::n3iwf::modify_results::{ModifyFailureTransfer, ModifyResponseTransfer};
use opc_proto_ngap::n3iwf::release::{Cause, CauseClass};
use opc_proto_ngap::n3iwf::reset_fields::{
    CriticalityDiagnostics, DiagnosticCriticality, DiagnosticError, DiagnosticItem,
    DiagnosticItems, TriggeringOutcome,
};
use opc_proto_ngap::n3iwf::resource_fields::{DownlinkTransport, QosFlowId, UplinkTransport};
use opc_proto_ngap::Criticality;
use opc_protocol::{DecodeContext, DecodeError, EncodeContext};
use serde_json::Value;

#[path = "support/modify_results.rs"]
mod support;
fn oracle() -> Value {
    serde_json::from_str(include_str!("fixtures/n3iwf-modify-results.json")).unwrap()
}
fn context() -> DecodeContext {
    DecodeContext {
        max_message_len: 4096,
        max_ies: 256,
        max_depth: 5,
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
fn qfi(v: &Value) -> QosFlowId {
    QosFlowId::new(v.as_u64().unwrap() as u8).unwrap()
}
fn response(v: &Value) -> Result<ModifyResponseTransfer, DecodeError> {
    let tunnel = |v: &Value| {
        (
            v["address"].as_str().unwrap().parse().unwrap(),
            v["teid"].as_u64().unwrap() as u32,
        )
    };
    Ok(ModifyResponseTransfer {
        downlink: if v["downlink"].is_null() {
            None
        } else {
            let (ip, teid) = tunnel(&v["downlink"]);
            Some(DownlinkTransport::new(ip, teid))
        },
        uplink: if v["uplink"].is_null() {
            None
        } else {
            let (ip, teid) = tunnel(&v["uplink"]);
            Some(UplinkTransport::new(ip, teid))
        },
        accepted: v["accepted"]
            .as_array()
            .map(|v| ModifiedQosFlows::new(v.iter().map(qfi).collect()))
            .transpose()?,
        failed: v["failed"]
            .as_array()
            .map(|v| {
                QosFlowCauses::new(
                    v.iter()
                        .map(|v| QosFlowCause {
                            qfi: qfi(&v["qfi"]),
                            cause: cause(&v["cause"]),
                        })
                        .collect(),
                )
            })
            .transpose()?,
    })
}
fn failure(v: &Value) -> ModifyFailureTransfer {
    let d = &v["diagnostics"];
    ModifyFailureTransfer {
        cause: cause(&v["cause"]),
        diagnostics: if d.is_null() {
            None
        } else {
            Some(CriticalityDiagnostics {
                procedure_code: d["procedure_code"].as_u64().map(|v| v as u8),
                triggering_outcome: d["trigger"].as_str().map(|v| match v {
                    "initiating-message" => TriggeringOutcome::Initiating,
                    "successful-outcome" => TriggeringOutcome::Successful,
                    _ => TriggeringOutcome::Unsuccessful,
                }),
                procedure_criticality: d["criticality"].as_str().map(|v| match v {
                    "reject" => Criticality::reject,
                    "ignore" => Criticality::ignore,
                    _ => Criticality::notify,
                }),
                ies: d["items"].as_array().map(|v| {
                    DiagnosticItems::new(
                        v.iter()
                            .map(|v| DiagnosticItem {
                                id: v["id"].as_u64().unwrap() as u16,
                                criticality: match v["criticality"].as_str().unwrap() {
                                    "reject" => DiagnosticCriticality::Reject,
                                    "notify" => DiagnosticCriticality::Notify,
                                    _ => panic!("inapplicable diagnostic criticality"),
                                },
                                error: if v["error"] == "missing" {
                                    DiagnosticError::Missing
                                } else {
                                    DiagnosticError::NotUnderstood
                                },
                            })
                            .collect(),
                    )
                    .unwrap()
                }),
            })
        },
    }
}

#[test]
fn independent_values_encodings_and_exact_limits() {
    let corpus = oracle();
    assert_eq!(corpus["cases"].as_array().unwrap().len(), 1436);
    let mut admitted = 0;
    for row in corpus["cases"].as_array().unwrap() {
        let name = row["name"].as_str().unwrap();
        let wire = bytes(row["wire_hex"].as_str().unwrap());
        let is_failure = row["type"] == "PDUSessionResourceModifyUnsuccessfulTransfer";
        if row["admitted"] == false {
            if is_failure {
                assert!(
                    ModifyFailureTransfer::decode(&wire, context()).is_err(),
                    "{name}"
                );
                if name.starts_with("inapplicable-procedure_code")
                    || name.starts_with("inapplicable-trigger")
                {
                    assert!(
                        failure(&row["model"]).encode(output()).is_err(),
                        "{name} encode"
                    );
                }
            } else {
                assert!(
                    ModifyResponseTransfer::decode(&wire, context()).is_err(),
                    "{name}"
                );
                if name.starts_with("duplicate-") {
                    assert!(response(&row["model"]).is_err());
                }
                if name == "overlap" {
                    assert!(response(&row["model"]).unwrap().encode(output()).is_err());
                }
            }
            continue;
        }
        admitted += 1;
        macro_rules! check {
            ($ty:ty, $expected:expr, $depth:expr, $count:expr) => {{
                let value = $expected;
                assert!(
                    <$ty>::decode(&wire, context()).unwrap() == value,
                    "{name} independent values"
                );
                assert!(
                    value.encode(output()).unwrap().as_bytes() == wire,
                    "{name} independent encoding"
                );
                assert!(
                    <$ty>::decode(
                        &wire,
                        DecodeContext {
                            max_depth: $depth,
                            max_ies: $count,
                            max_message_len: wire.len(),
                            ..context()
                        }
                    )
                    .is_ok(),
                    "{name} exact limits"
                );
                assert!(
                    <$ty>::decode(
                        &wire,
                        DecodeContext {
                            max_depth: $depth - 1,
                            ..context()
                        }
                    )
                    .is_err(),
                    "{name} depth"
                );
                if $count > 0 {
                    assert!(
                        <$ty>::decode(
                            &wire,
                            DecodeContext {
                                max_ies: $count - 1,
                                ..context()
                            }
                        )
                        .is_err(),
                        "{name} count"
                    );
                }
                assert!(
                    <$ty>::decode(
                        &wire,
                        DecodeContext {
                            max_message_len: wire.len() - 1,
                            ..context()
                        }
                    )
                    .is_err(),
                    "{name} input length"
                );
                assert!(
                    value
                        .encode(EncodeContext {
                            max_message_len: wire.len(),
                            ..output()
                        })
                        .is_ok(),
                    "{name} exact output"
                );
                assert!(
                    value
                        .encode(EncodeContext {
                            max_message_len: wire.len() - 1,
                            ..output()
                        })
                        .is_err(),
                    "{name} output length"
                );
                let debug = format!("{value:?}");
                assert!(debug.ends_with("([REDACTED])"));
                assert!(!debug.chars().any(|v| v.is_ascii_digit()));
            }};
        }
        if is_failure {
            let value = failure(&row["model"]);
            let count = value
                .diagnostics
                .as_ref()
                .and_then(|v| v.ies.as_ref())
                .map_or(0, |v| v.values().len());
            check!(
                ModifyFailureTransfer,
                value,
                if count == 0 { 3 } else { 5 },
                count
            );
        } else {
            let value = response(&row["model"]).unwrap();
            let count = value.accepted.as_ref().map_or(0, |v| v.values().len())
                + value.failed.as_ref().map_or(0, |v| v.values().len());
            let depth = if value.failed.is_some() {
                5
            } else if value.accepted.is_some() || value.downlink.is_some() || value.uplink.is_some()
            {
                4
            } else {
                1
            };
            check!(ModifyResponseTransfer, value, depth, count);
        }
    }
    assert_eq!(admitted, 1423);
}

#[test]
fn empty_roots_absent_and_empty_diagnostics_remain_distinct() {
    let corpus = oracle();
    let rows = corpus["cases"].as_array().unwrap();
    for name in ["presence-0", "failed-count-64"] {
        let row = rows.iter().find(|v| v["name"] == name).unwrap();
        let wire = bytes(row["wire_hex"].as_str().unwrap());
        let value = ModifyResponseTransfer::decode(&wire, context()).unwrap();
        assert!(value.downlink.is_none() && value.uplink.is_none() && value.accepted.is_none());
        assert!(value.encode(output()).unwrap().as_bytes() == wire);
    }
    let absent = failure(
        &rows
            .iter()
            .find(|v| v["name"] == "failure-radioNetwork-0")
            .unwrap()["model"],
    );
    let empty = failure(
        &rows
            .iter()
            .find(|v| v["name"] == "diagnostic-cause-radioNetwork-0-0")
            .unwrap()["model"],
    );
    assert!(absent != empty);
    assert!(absent.diagnostics.is_none());
    assert!(empty.diagnostics.is_some());
    assert!(
        absent.encode(output()).unwrap().as_bytes() != empty.encode(output()).unwrap().as_bytes()
    );
    let row = rows
        .iter()
        .find(|v| v["name"] == "diagnostic-count-256")
        .unwrap();
    let wire = bytes(row["wire_hex"].as_str().unwrap());
    let value = ModifyFailureTransfer::decode(&wire, context()).unwrap();
    let items = value.diagnostics.unwrap().ies.unwrap();
    assert_eq!(items.values().len(), 256);
    assert_eq!(items.values()[0].id, items.values()[3].id);
}

fn set_bit(wire: &mut [u8], bit: usize) {
    wire[bit / 8] |= 1 << (7 - bit % 8);
}
#[test]
fn unsupported_flags_padding_and_trailing_bytes_are_rejected() {
    let corpus = oracle();
    for row in corpus["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|v| v["admitted"] == true)
    {
        let name = row["name"].as_str().unwrap();
        let wire = bytes(row["wire_hex"].as_str().unwrap());
        let failure = row["type"] == "PDUSessionResourceModifyUnsuccessfulTransfer";
        let rejects = |v: &[u8]| {
            if failure {
                ModifyFailureTransfer::decode(v, context()).is_err()
            } else {
                ModifyResponseTransfer::decode(v, context()).is_err()
            }
        };
        let mut changed = wire.clone();
        changed.push(0);
        assert!(rejects(&changed), "{name} trailing");
        let flags: &[usize] = if failure { &[0, 2] } else { &[0, 4, 6] };
        for &bit in flags {
            let mut changed = wire.clone();
            set_bit(&mut changed, bit);
            assert!(rejects(&changed), "{name} extension flags");
        }
        if name == "presence-0" {
            let mut changed = wire.clone();
            *changed.last_mut().unwrap() |= 1;
            assert!(rejects(&changed), "empty padding");
        }
        if name.starts_with("downlink-") || name.starts_with("uplink-") {
            // Seven parent flags, four nested transport flags and eight address
            // length bits put five required zero alignment bits before the IP.
            for bit in 7..11 {
                let mut changed = wire.clone();
                set_bit(&mut changed, bit);
                assert!(rejects(&changed), "{name} transport flags");
            }
            for bit in 19..24 {
                let mut changed = wire.clone();
                set_bit(&mut changed, bit);
                assert!(rejects(&changed), "{name} transport padding");
            }
        }
        if name.starts_with("failure-") || name.starts_with("diagnostic-") {
            let width = match row["model"]["cause"]["group"].as_str().unwrap() {
                "radioNetwork" => 6,
                "transport" => 1,
                "nas" => 2,
                _ => 3,
            };
            let mut changed = wire.clone();
            set_bit(&mut changed, 6);
            assert!(rejects(&changed), "{name} cause extension");
            if name.starts_with("failure-") {
                for bit in (7 + width)..(wire.len() * 8) {
                    let mut changed = wire.clone();
                    set_bit(&mut changed, bit);
                    assert!(rejects(&changed), "{name} cause padding");
                }
            } else {
                for bit in [7 + width, 12 + width] {
                    let mut changed = wire.clone();
                    set_bit(&mut changed, bit);
                    assert!(rejects(&changed), "{name} diagnostic extension");
                }
                // Diagnostic entries end with two bits; final six bits are pad.
                if row["model"]["diagnostics"]["items"].is_array() {
                    let mut changed = wire.clone();
                    *changed.last_mut().unwrap() |= 1;
                    assert!(rejects(&changed), "{name} diagnostic padding");
                }
            }
        }
    }
    for wire in [&[0x10, 0xfc][..], &[0x04, 0xfc][..], &[0x80][..]] {
        assert!(ModifyResponseTransfer::decode(wire, context()).is_err());
    }
}

#[test]
fn all_independent_truncations_and_bounded_mutations_replay_safely() {
    let corpus = oracle();
    for row in corpus["cases"].as_array().unwrap() {
        let wire = bytes(row["wire_hex"].as_str().unwrap());
        for end in 0..=wire.len() {
            support::exercise(&wire[..end], context(), output());
        }
        for index in (0..wire.len()).step_by((wire.len() / 128).max(1)) {
            for mask in [1, 0x80, 0xff] {
                let mut changed = wire.clone();
                changed[index] ^= mask;
                support::exercise(&changed, context(), output());
            }
        }
    }
}
