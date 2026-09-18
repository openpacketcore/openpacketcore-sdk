#[path = "support/response_diagnostics.rs"]
mod shared;
use bytes::Bytes;
use opc_proto_ngap::n3iwf::reset_fields::{
    CriticalityDiagnostics, DiagnosticCriticality, DiagnosticError, DiagnosticItem,
    DiagnosticItems, TriggeringOutcome,
};
use opc_proto_ngap::{encode, Criticality, MessageType, Pdu, PduKind, ProtocolIe};
use opc_protocol::{
    DecodeContext, DecodeError, DuplicateIePolicy, EncodeContext, OwnedDecode, UnknownIePolicy,
    ValidationLevel,
};
use serde_json::Value;
use shared::{admit, Response};
use std::sync::OnceLock;

fn oracle() -> &'static Value {
    static DATA: OnceLock<Value> = OnceLock::new();
    DATA.get_or_init(|| {
        serde_json::from_str(include_str!("fixtures/n3iwf-response-diagnostics.json")).unwrap()
    })
}
fn rows() -> &'static [Value] {
    oracle()["cases"].as_array().unwrap()
}
fn bytes(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
fn context() -> DecodeContext {
    DecodeContext {
        max_message_len: 200_000,
        max_ies: 256,
        max_depth: 24,
        duplicate_ie_policy: DuplicateIePolicy::Reject,
        validation_level: ValidationLevel::Strict,
        ..DecodeContext::default()
    }
}
fn output() -> EncodeContext {
    EncodeContext {
        max_message_len: 200_000,
        ..EncodeContext::default()
    }
}
fn read(row: &Value, ctx: DecodeContext) -> Result<Pdu, DecodeError> {
    Pdu::decode_owned(Bytes::from(bytes(row["wire_hex"].as_str().unwrap())), ctx)
}
fn criticality(s: &str) -> Criticality {
    match s {
        "reject" => Criticality::reject,
        "ignore" => Criticality::ignore,
        "notify" => Criticality::notify,
        _ => panic!("reference criticality"),
    }
}
fn kind(row: &Value) -> MessageType {
    match row["kind"].as_str().unwrap() {
        "NGSetupResponse" => MessageType::NgSetupResponse,
        "NGSetupFailure" => MessageType::NgSetupFailure,
        "InitialContextSetupResponse" => MessageType::InitialContextSetupResponse,
        "InitialContextSetupFailure" => MessageType::InitialContextSetupFailure,
        "PDUSessionResourceSetupResponse" => MessageType::PduSessionResourceSetupResponse,
        "PDUSessionResourceReleaseResponse" => MessageType::PduSessionResourceReleaseResponse,
        "UEContextReleaseComplete" => MessageType::UeContextReleaseComplete,
        _ => panic!("reference outcome"),
    }
}
type Fields = Vec<(u16, Criticality, Vec<u8>)>;
fn fields(row: &Value) -> Fields {
    row["fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            (
                f["id"].as_u64().unwrap() as u16,
                criticality(f["criticality"].as_str().unwrap()),
                bytes(f["wire_hex"].as_str().unwrap()),
            )
        })
        .collect()
}
fn from_fields(row: &Value, fs: &Fields, ctx: DecodeContext) -> Result<Pdu, DecodeError> {
    Pdu::from_protocol_ies(
        kind(row),
        &fs.iter()
            .map(|(id, crit, v)| ProtocolIe::new(*id, *crit, v))
            .collect::<Vec<_>>(),
        ctx,
    )
}
fn diagnostic_model(m: &Value) -> Option<CriticalityDiagnostics> {
    let ies = if let Some(items) = m["items"].as_array() {
        let mut values = Vec::new();
        for item in items {
            let criticality = match item["criticality"].as_str().unwrap() {
                "reject" => DiagnosticCriticality::Reject,
                "notify" => DiagnosticCriticality::Notify,
                "ignore" => return None,
                _ => panic!("reference item criticality"),
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
        procedure_code: m["procedure_code"].as_u64().map(|v| v as u8),
        triggering_outcome: m["trigger"].as_str().map(|v| match v {
            "initiating-message" => TriggeringOutcome::Initiating,
            "successful-outcome" => TriggeringOutcome::Successful,
            "unsuccessful-outcome" => TriggeringOutcome::Unsuccessful,
            _ => panic!("reference trigger"),
        }),
        procedure_criticality: m["criticality"].as_str().map(criticality),
        ies,
    })
}
fn expected(row: &Value) -> Option<CriticalityDiagnostics> {
    row["diagnostics"]
        .as_str()
        .map(|name| diagnostic_model(&oracle()["diagnostics"][name]["model"]).unwrap())
}
fn base(row: &Value) -> Response {
    let mut fs = fields(row);
    fs.retain(|v| v.0 != 19);
    admit(&from_fields(row, &fs, context()).unwrap(), context())
        .unwrap()
        .0
}
fn depth(row: &Value, diagnostic: &Option<CriticalityDiagnostics>) -> usize {
    let has = |id| {
        row["fields"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["id"] == id)
    };
    let base = match kind(row) {
        MessageType::NgSetupResponse => 10,
        MessageType::NgSetupFailure => 6,
        MessageType::InitialContextSetupResponse => {
            if has(72) {
                13
            } else if has(55) {
                10
            } else {
                5
            }
        }
        MessageType::InitialContextSetupFailure => {
            if has(132) {
                10
            } else {
                6
            }
        }
        MessageType::PduSessionResourceSetupResponse => {
            if has(75) {
                13
            } else {
                10
            }
        }
        MessageType::PduSessionResourceReleaseResponse => 8,
        MessageType::UeContextReleaseComplete => {
            if has(121) {
                8
            } else {
                5
            }
        }
        _ => unreachable!(),
    };
    base.max(
        diagnostic
            .as_ref()
            .map_or(0, |v| if v.ies.is_some() { 8 } else { 6 }),
    )
}

#[test]
fn independent_seven_outcomes_construction_and_exact_limits() {
    assert_eq!(rows().len(), 4349);
    let mut admitted = 0;
    let mut counts = std::collections::BTreeMap::<String, std::collections::BTreeSet<usize>>::new();
    for row in rows() {
        let name = row["name"].as_str().unwrap();
        let pdu = read(row, context());
        if row["admitted"] == false {
            assert!(
                pdu.as_ref()
                    .ok()
                    .and_then(|p| admit(p, context()).ok())
                    .is_none(),
                "{name}"
            );
            continue;
        }
        admitted += 1;
        let pdu = pdu.unwrap();
        let (typed, ignored, notify) =
            admit(&pdu, context()).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        let diagnostic = expected(row);
        assert!(
            typed.diagnostics() == &diagnostic,
            "{name}: diagnostic model"
        );
        assert!(
            ignored == 0 && notify.is_empty(),
            "{name}: admitted diagnostic must not be ignored"
        );
        let items = diagnostic
            .as_ref()
            .and_then(|v| v.ies.as_ref())
            .map_or(0, |v| v.values().len());
        if row["diagnostics"]
            .as_str()
            .is_some_and(|s| s.starts_with("response-items-"))
        {
            counts
                .entry(row["kind"].as_str().unwrap().into())
                .or_default()
                .insert(items);
        }
        let wire = bytes(row["wire_hex"].as_str().unwrap());
        let count = row["fields"].as_array().unwrap().len().max(items);
        let exact = DecodeContext {
            max_depth: depth(row, &diagnostic),
            max_ies: count,
            max_message_len: wire.len(),
            ..context()
        };
        let mut constructed = base(row);
        constructed.set_diagnostics(diagnostic);
        for value in [&typed, &constructed] {
            let p = value
                .construct(exact)
                .unwrap_or_else(|e| panic!("{name}: exact construction {e:?}"));
            assert!(
                encode(
                    &p,
                    EncodeContext {
                        max_message_len: wire.len(),
                        ..output()
                    }
                )
                .unwrap()
                    == wire,
                "{name}: reference wire"
            );
            assert!(
                encode(
                    &p,
                    EncodeContext {
                        max_message_len: wire.len() - 1,
                        ..output()
                    }
                )
                .is_err(),
                "{name}: output bound"
            );
            for short in [
                DecodeContext {
                    max_depth: exact.max_depth - 1,
                    ..exact
                },
                DecodeContext {
                    max_ies: count - 1,
                    ..exact
                },
                DecodeContext {
                    max_message_len: wire.len() - 1,
                    ..exact
                },
            ] {
                assert!(value.construct(short).is_err(), "{name}: constructor bound");
                assert!(admit(&pdu, short).is_err(), "{name}: admission bound");
            }
        }
        assert!(
            admit(&read(row, exact).unwrap(), exact).is_ok(),
            "{name}: receive exact"
        );
        assert!(read(
            row,
            DecodeContext {
                max_message_len: wire.len() - 1,
                ..exact
            }
        )
        .is_err());
        let debug = format!("{pdu:?}");
        assert!(!debug.contains("01020304") && !debug.contains("203.0.113"));
        if let Some(diagnostic) = typed.diagnostics() {
            assert!(format!("{diagnostic:?}").contains("REDACTED"));
        }
    }
    assert_eq!(admitted, 2046);
    assert_eq!(counts.len(), 7);
    for values in counts.values() {
        assert!(values.iter().copied().eq(1..=256));
    }
}

#[test]
fn response_header_applicability_constructor_and_duplicate_policies() {
    let mut constructor_negatives = 0;
    for row in rows().iter().filter(|v| v["admitted"] == false) {
        let name = row["name"].as_str().unwrap();
        if name.ends_with("duplicate-last-inapplicable") {
            for policy in [
                DuplicateIePolicy::First,
                DuplicateIePolicy::Last,
                DuplicateIePolicy::Reject,
            ] {
                let ctx = DecodeContext {
                    duplicate_ie_policy: policy,
                    ..context()
                };
                let got = read(row, ctx).and_then(|pdu| admit(&pdu, ctx));
                if matches!(policy, DuplicateIePolicy::First) {
                    assert!(got
                        .unwrap()
                        .0
                        .diagnostics()
                        .as_ref()
                        .is_some_and(|v| v.procedure_code.is_none() && v.ies.is_none()));
                } else {
                    assert!(got.is_err(), "{name}");
                }
            }
        } else if let Some(key) = row["diagnostics"].as_str() {
            if let Some(diagnostic) = diagnostic_model(&oracle()["diagnostics"][key]["model"]) {
                if diagnostic.procedure_code.is_some() || diagnostic.triggering_outcome.is_some() {
                    let mut value = base(row);
                    value.set_diagnostics(Some(diagnostic));
                    assert!(
                        value.construct(context()).is_err(),
                        "{name}: constructor applicability"
                    );
                    constructor_negatives += 1;
                }
            }
        }
    }
    assert_eq!(constructor_negatives, 2191);
}

#[test]
fn metadata_unknown_policy_and_malformed_diagnostics() {
    for row in rows().iter().filter(|v| {
        v["name"].as_str().unwrap().ends_with("-presence-0")
            && !v["name"].as_str().unwrap().contains("minimal")
    }) {
        let pdu = read(row, context()).unwrap();
        for change in 0..3 {
            let mut bad = pdu.clone();
            match &mut bad.kind {
                PduKind::Successful {
                    procedure_code,
                    criticality,
                    ..
                }
                | PduKind::Unsuccessful {
                    procedure_code,
                    criticality,
                    ..
                } => {
                    if change == 0 {
                        *procedure_code = 255
                    } else if change == 1 {
                        *criticality = Criticality::notify
                    }
                }
                _ => unreachable!(),
            }
            if change == 2 {
                bad.kind = match bad.kind {
                    PduKind::Successful {
                        procedure_code,
                        criticality,
                        message,
                    } => PduKind::Unsuccessful {
                        procedure_code,
                        criticality,
                        message,
                    },
                    PduKind::Unsuccessful {
                        procedure_code,
                        criticality,
                        message,
                    } => PduKind::Successful {
                        procedure_code,
                        criticality,
                        message,
                    },
                    _ => unreachable!(),
                };
            }
            assert!(admit(&bad, context()).is_err());
        }
        for malformed in [
            vec![],
            vec![0x80],
            vec![0x04],
            vec![0x01],
            vec![0, 0],
            vec![0x08],
            vec![0x08, 0xff],
        ] {
            let mut fs = fields(row);
            fs.iter_mut().find(|v| v.0 == 19).unwrap().2 = malformed;
            let bad = from_fields(row, &fs, context()).unwrap();
            assert!(
                admit(&bad, context()).is_err(),
                "diagnostic framing/extension/padding"
            );
        }
        for crit in [
            Criticality::reject,
            Criticality::ignore,
            Criticality::notify,
        ] {
            let mut fs = fields(row);
            fs.push((65530, Criticality::ignore, vec![0xde, 0xad, 0xbe, 0xef]));
            let structural = DecodeContext {
                validation_level: ValidationLevel::Structural,
                ..context()
            };
            let mut wire = encode(&from_fields(row, &fs, structural).unwrap(), output()).unwrap();
            // Construction correctly refuses unknown reject-criticality IEs.
            // Mutate the final synthetic IE's criticality to test peer input.
            let criticality_offset = wire.len() - 6;
            assert_eq!(
                &wire[criticality_offset - 2..criticality_offset],
                &[0xff, 0xfa]
            );
            wire[criticality_offset] = (crit as u8) << 6;
            for policy in [
                UnknownIePolicy::Preserve,
                UnknownIePolicy::Drop,
                UnknownIePolicy::Reject,
            ] {
                let ctx = DecodeContext {
                    unknown_ie_policy: policy,
                    ..context()
                };
                let got =
                    Pdu::decode_owned(Bytes::from(wire.clone()), ctx).and_then(|v| admit(&v, ctx));
                if crit == Criticality::reject || matches!(policy, UnknownIePolicy::Reject) {
                    assert!(got.is_err());
                } else {
                    let (value, ignored, notify) = got.unwrap();
                    assert!(value.diagnostics().is_some());
                    let preserve = matches!(policy, UnknownIePolicy::Preserve);
                    assert_eq!(
                        ignored,
                        usize::from(preserve && crit == Criticality::ignore)
                    );
                    assert_eq!(
                        notify,
                        if preserve && crit == Criticality::notify {
                            vec![65530]
                        } else {
                            vec![]
                        }
                    );
                }
            }
        }
    }
}

#[test]
fn bounded_shared_fuzz_replay_and_physical_trailing_data() {
    for row in rows() {
        let wire = bytes(row["wire_hex"].as_str().unwrap());
        shared::exercise(&wire, context(), output());
        if row["name"].as_str().unwrap().ends_with("-presence-0") {
            let mut trailing = wire.clone();
            trailing.push(0);
            assert!(Pdu::decode_owned(Bytes::from(trailing), context()).is_err());
            for length in 0..wire.len() {
                shared::exercise(&wire[..length], context(), output());
            }
            for index in 0..wire.len().min(64) {
                for bit in [1, 0x20, 0x80] {
                    let mut changed = wire.clone();
                    changed[index] ^= bit;
                    shared::exercise(&changed, context(), output());
                }
            }
        }
    }
}
