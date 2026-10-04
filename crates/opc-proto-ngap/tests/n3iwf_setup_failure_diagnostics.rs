#![allow(clippy::unwrap_used)]
use bytes::Bytes;
use opc_proto_ngap::n3iwf::release::{Cause, CauseClass};
use opc_proto_ngap::n3iwf::reset_fields::{
    CriticalityDiagnostics, DiagnosticCriticality, DiagnosticError, DiagnosticItem, DiagnosticItems,
};
use opc_proto_ngap::n3iwf::resource_results::SetupFailureTransfer;
use opc_proto_ngap::n3iwf::resource_setup::{
    InitialContextFailure, InitialContextResponse, ResourceSetupMessage, SessionResourceResponse,
};
use opc_proto_ngap::n3iwf::session_lists::{
    FailedSession, FailedSessions, SessionId, SessionResults,
};
use opc_proto_ngap::n3iwf::{AmfUeId, RanUeId};
use opc_proto_ngap::{encode, Criticality, Pdu};
use opc_protocol::{DecodeContext, EncodeContext, OwnedDecode};
use serde_json::Value;

#[path = "support/setup_failure_diagnostics.rs"]
mod support;

fn bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}
fn oracle() -> Value {
    serde_json::from_str(include_str!(
        "fixtures/n3iwf-setup-failure-diagnostics.json"
    ))
    .unwrap()
}
fn context(depth: usize) -> DecodeContext {
    DecodeContext {
        max_depth: depth,
        max_ies: 256,
        max_message_len: 4096,
        ..DecodeContext::default()
    }
}
fn output() -> EncodeContext {
    EncodeContext {
        max_message_len: 4096,
        ..EncodeContext::default()
    }
}
fn expected(model: &Value) -> SetupFailureTransfer {
    let cause = &model["cause"];
    let group = match cause["group"].as_str().unwrap() {
        "radioNetwork" => CauseClass::RadioNetwork,
        "transport" => CauseClass::Transport,
        "nas" => CauseClass::Nas,
        "protocol" => CauseClass::Protocol,
        "misc" => CauseClass::Misc,
        _ => panic!("reference cause"),
    };
    let diagnostic = &model["diagnostics"];
    SetupFailureTransfer {
        cause: Cause::new(group, cause["code"].as_u64().unwrap() as u8).unwrap(),
        diagnostics: if diagnostic.is_null() {
            None
        } else {
            Some(CriticalityDiagnostics {
                procedure_code: None,
                triggering_outcome: None,
                procedure_criticality: diagnostic["criticality"].as_str().map(|v| match v {
                    "reject" => Criticality::reject,
                    "ignore" => Criticality::ignore,
                    "notify" => Criticality::notify,
                    _ => panic!("reference criticality"),
                }),
                ies: diagnostic["items"].as_array().map(|items| {
                    DiagnosticItems::new(
                        items
                            .iter()
                            .map(|v| DiagnosticItem {
                                criticality: if v["criticality"] == "reject" {
                                    DiagnosticCriticality::Reject
                                } else {
                                    DiagnosticCriticality::Notify
                                },
                                id: v["id"].as_u64().unwrap() as u16,
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
fn independent_setup_failure_values_construction_and_exact_limits() {
    let corpus = oracle();
    let cases = corpus["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 584);
    let mut admitted = 0;
    let mut maximum = 0;
    for row in cases {
        let name = row["name"].as_str().unwrap();
        let wire = bytes(row["wire_hex"].as_str().unwrap());
        if row["admitted"] == false {
            assert!(
                SetupFailureTransfer::decode(&wire, context(5)).is_err(),
                "{name}"
            );
            continue;
        }
        admitted += 1;
        maximum = maximum.max(wire.len());
        let expected = expected(&row["model"]);
        let count = expected
            .diagnostics
            .as_ref()
            .and_then(|v| v.ies.as_ref())
            .map_or(0, |v| v.values().len());
        let depth = if count == 0 { 3 } else { 5 };
        let exact = DecodeContext {
            max_depth: depth,
            max_message_len: wire.len(),
            max_ies: count,
            ..context(5)
        };
        assert!(
            SetupFailureTransfer::decode(&wire, exact).unwrap() == expected,
            "{name}"
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
            "{name}"
        );
        assert!(
            expected
                .encode(EncodeContext {
                    max_message_len: wire.len() - 1,
                    ..output()
                })
                .is_err(),
            "{name}"
        );
        assert!(
            SetupFailureTransfer::decode(
                &wire,
                DecodeContext {
                    max_depth: depth - 1,
                    ..exact
                }
            )
            .is_err(),
            "{name}"
        );
        assert!(
            SetupFailureTransfer::decode(
                &wire,
                DecodeContext {
                    max_message_len: wire.len() - 1,
                    ..exact
                }
            )
            .is_err(),
            "{name}"
        );
        if count != 0 {
            assert!(
                SetupFailureTransfer::decode(
                    &wire,
                    DecodeContext {
                        max_ies: count - 1,
                        ..exact
                    }
                )
                .is_err(),
                "{name}"
            );
        }
        assert_eq!(format!("{expected:?}"), "SetupFailureTransfer([REDACTED])");
    }
    assert_eq!(admitted, 576);
    assert_eq!(maximum, 773);
}

fn construct(
    kind: &str,
    transfer: SetupFailureTransfer,
    ctx: DecodeContext,
) -> Result<Pdu, opc_protocol::DecodeError> {
    let failed = FailedSessions::new(vec![FailedSession {
        id: SessionId::new(255),
        transfer,
    }])
    .unwrap();
    let amf = AmfUeId::new(1).unwrap();
    let ran = RanUeId::new(2);
    match kind {
        "InitialContextSetupResponse" => InitialContextResponse {
            amf,
            ran,
            sessions: SessionResults::new(None, Some(failed)).unwrap(),
            diagnostics: None,
        }
        .construct(ctx),
        "InitialContextSetupFailure" => InitialContextFailure {
            amf,
            ran,
            cause: Cause::new(CauseClass::RadioNetwork, 0).unwrap(),
            failed: Some(failed),
            diagnostics: None,
        }
        .construct(ctx),
        "PDUSessionResourceSetupResponse" => SessionResourceResponse {
            amf,
            ran,
            sessions: SessionResults::new(None, Some(failed)).unwrap(),
            location: None,
            diagnostics: None,
        }
        .construct(ctx),
        _ => panic!("reference message"),
    }
}

#[test]
fn all_three_complete_setup_outcomes_preserve_nested_diagnostics_and_bounds() {
    let corpus = oracle();
    let cases = corpus["cases"].as_array().unwrap();
    let messages = corpus["messages"].as_array().unwrap();
    assert_eq!(messages.len(), 102);
    let mut admitted_count = 0;
    for row in messages {
        let source = cases.iter().find(|v| v["name"] == row["transfer"]).unwrap();
        let wire = bytes(row["wire_hex"].as_str().unwrap());
        let pdu = Pdu::decode_owned(Bytes::copy_from_slice(&wire), context(12)).unwrap();
        let admitted = ResourceSetupMessage::from_pdu(&pdu, context(12));
        if row["admitted"] == false {
            assert!(admitted.is_err(), "{} {}", row["kind"], row["transfer"]);
            continue;
        }
        admitted_count += 1;
        let expected = expected(&source["model"]);
        let count = expected
            .diagnostics
            .as_ref()
            .and_then(|v| v.ies.as_ref())
            .map_or(0, |v| v.values().len());
        let depth = if count == 0 { 10 } else { 12 };
        let ctx = DecodeContext {
            max_depth: depth,
            max_message_len: wire.len(),
            ..context(12)
        };
        let admitted = admitted.unwrap();
        let failed = match &admitted.message {
            ResourceSetupMessage::InitialResponse(v) => v.sessions.failed().unwrap(),
            ResourceSetupMessage::InitialFailure(v) => v.failed.as_ref().unwrap(),
            ResourceSetupMessage::SessionResponse(v) => v.sessions.failed().unwrap(),
            _ => panic!("unexpected outcome"),
        };
        assert_eq!(failed.values()[0].id.value(), 255);
        assert!(failed.values()[0].transfer == expected);
        let kind = row["kind"].as_str().unwrap();
        let constructed = construct(kind, expected.clone(), ctx).unwrap();
        assert!(
            encode(&constructed, output()).unwrap() == wire,
            "{kind} {}",
            row["transfer"]
        );
        assert!(ResourceSetupMessage::from_pdu(&pdu, ctx).is_ok());
        let short = DecodeContext {
            max_depth: depth - 1,
            ..ctx
        };
        assert!(ResourceSetupMessage::from_pdu(&pdu, short).is_err());
        assert!(construct(kind, expected.clone(), short).is_err());
        if count > 4 {
            let short = DecodeContext {
                max_ies: count - 1,
                ..ctx
            };
            assert!(ResourceSetupMessage::from_pdu(&pdu, short).is_err());
            assert!(construct(kind, expected, short).is_err());
        }
    }
    assert_eq!(admitted_count, 78);
}

#[test]
fn constructor_applicability_and_bounded_adversarial_replay() {
    use opc_proto_ngap::n3iwf::reset_fields::TriggeringOutcome;
    let corpus = oracle();
    let cases = corpus["cases"].as_array().unwrap();
    let row = cases
        .iter()
        .find(|v| v["name"] == "diagnostic-count-256")
        .unwrap();
    let baseline = expected(&row["model"]);
    for trigger in [
        TriggeringOutcome::Initiating,
        TriggeringOutcome::Successful,
        TriggeringOutcome::Unsuccessful,
    ] {
        let mut changed = baseline.clone();
        changed.diagnostics.as_mut().unwrap().triggering_outcome = Some(trigger);
        assert!(changed.encode(output()).is_err());
    }
    for code in [0, 14, 29, 255] {
        let mut changed = baseline.clone();
        changed.diagnostics.as_mut().unwrap().procedure_code = Some(code);
        assert!(changed.encode(output()).is_err());
    }
    let mut mutations = 0;
    for row in cases.iter().step_by(17).chain(std::iter::once(row)) {
        let wire = bytes(row["wire_hex"].as_str().unwrap());
        for end in 0..wire.len() {
            assert!(SetupFailureTransfer::decode(&wire[..end], context(5)).is_err());
        }
        let mut trailing = wire.clone();
        trailing.push(0);
        assert!(SetupFailureTransfer::decode(&trailing, context(5)).is_err());
        for pos in 0..wire.len() {
            for mask in [1, 128, 255] {
                let mut changed = wire.clone();
                changed[pos] ^= mask;
                for depth in [3, 5] {
                    support::exercise(&changed, context(depth), output());
                }
                mutations += 1;
            }
        }
    }
    assert!(mutations > 10_000);
}

#[test]
fn independent_empty_setup_failure_diagnostics_are_admitted() {
    let corpus: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/n3iwf-resource-results.json")).unwrap();
    let row = corpus["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["name"] == "unsupported-diagnostics")
        .unwrap();
    let wire: Vec<_> = row["wire_hex"]
        .as_str()
        .unwrap()
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|v| u8::from_str_radix(std::str::from_utf8(v).unwrap(), 16).unwrap())
        .collect();
    assert!(SetupFailureTransfer::decode(&wire, DecodeContext::default()).is_ok());
}
