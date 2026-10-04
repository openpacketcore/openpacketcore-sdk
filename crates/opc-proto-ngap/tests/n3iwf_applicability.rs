use bytes::Bytes;
use opc_proto_ngap::n3iwf::applicability::{
    inspect, ApplicableMessage, Association, Direction, Endpoint, ReceiveDisposition, TriggerGate,
    UnsupportedAction, APPLICABLE_MESSAGES,
};
use opc_proto_ngap::n3iwf::nas::NasMessage;
use opc_proto_ngap::n3iwf::reset_fields::CriticalityDiagnostics;
use opc_proto_ngap::{encode, Criticality, Outcome, Pdu};
use opc_protocol::{
    DecodeContext, DuplicateIePolicy, EncodeContext, OwnedDecode, UnknownIePolicy, ValidationLevel,
};
use serde_json::Value;

#[path = "support/applicability.rs"]
mod replay;

fn oracle() -> Value {
    serde_json::from_str(include_str!("fixtures/n3iwf-applicability.json")).unwrap()
}
fn bytes(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).unwrap())
        .collect()
}
fn context() -> DecodeContext {
    DecodeContext {
        max_message_len: 200_000,
        max_depth: 20,
        max_ies: 256,
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
fn outcome(value: &Value) -> Outcome {
    match value.as_str().unwrap() {
        "initiatingMessage" => Outcome::Initiating,
        "successfulOutcome" => Outcome::Successful,
        "unsuccessfulOutcome" => Outcome::Unsuccessful,
        _ => panic!("reference outcome"),
    }
}
fn criticality(value: &Value) -> Criticality {
    match value.as_str().unwrap() {
        "reject" => Criticality::reject,
        "ignore" => Criticality::ignore,
        "notify" => Criticality::notify,
        _ => panic!("reference criticality"),
    }
}

#[test]
fn complete_applicability_metadata_directions_and_trigger_gates() {
    let f = oracle();
    assert_eq!(APPLICABLE_MESSAGES.len(), 40);
    assert_eq!(f["procedures"].as_array().unwrap().len(), 131);
    let mut qualified = 0;
    for row in f["applicable"].as_array().unwrap() {
        let message = *APPLICABLE_MESSAGES
            .iter()
            .find(|m| m.rule().name == row["name"].as_str().unwrap())
            .unwrap();
        let rule = message.rule();
        assert_eq!(u64::from(rule.procedure_code), row["procedure_code"]);
        assert_eq!(rule.outcome, outcome(&row["outcome"]));
        assert_eq!(rule.criticality, criticality(&row["criticality"]));
        assert_eq!(rule.clause, row["clause"].as_str().unwrap());
        assert_eq!(
            rule.association,
            match row["association"].as_str().unwrap() {
                "ue" => Association::Ue,
                "non-ue" => Association::NonUe,
                _ => Association::Either,
            }
        );
        assert_eq!(
            rule.direction,
            match row["receiver"].as_str().unwrap() {
                "amf" => Direction::ToAmf,
                "n3iwf" => Direction::ToN3iwf,
                _ => Direction::Either,
            }
        );
        let supported = row["support"] == "qualified";
        assert_eq!(rule.codec.is_some(), supported);
        qualified += usize::from(supported);
        for (receiver, sender) in [("amf", Endpoint::N3iwf), ("n3iwf", Endpoint::Amf)] {
            let gate = message.local_trigger(sender);
            if row["receiver"] != receiver && row["receiver"] != "either" {
                assert_eq!(gate, TriggerGate::WrongDirection);
            } else if let Some(codec) = rule.codec {
                assert_eq!(gate, TriggerGate::CodecAvailable(codec));
                // Empty IE containers qualify the structural envelope only.
                let pdu = Pdu::from_protocol_ies(codec, &[], context()).unwrap();
                let wire = encode(&pdu, output()).unwrap();
                let expected = f["cases"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|v| {
                        v["outcome"] == row["outcome"]
                            && v["procedure_code"] == row["procedure_code"]
                            && v["criticality"] == row["criticality"]
                    })
                    .unwrap();
                assert!(wire == bytes(expected["wire_hex"].as_str().unwrap()));
            } else {
                assert_eq!(gate, TriggerGate::DisabledPendingHandler);
            }
        }
    }
    assert_eq!(qualified, 23);
}

#[test]
fn all_codes_outcomes_criticalities_and_independent_error_diagnostics() {
    let f = oracle();
    assert_eq!(f["cases"].as_array().unwrap().len(), 2321);
    for row in f["cases"].as_array().unwrap() {
        let wire = bytes(row["wire_hex"].as_str().unwrap());
        for (key, receiver) in [("n3iwf", Endpoint::N3iwf), ("amf", Endpoint::Amf)] {
            let actual = inspect(&wire, receiver, context());
            match row["route"][key].as_str().unwrap() {
                "metadata-error" | "direction-error" => assert!(actual.is_err()),
                "qualified" | "handler" => {
                    let route = actual.unwrap();
                    let message = match route {
                        ReceiveDisposition::Qualified(m) => {
                            assert_eq!(row["route"][key], "qualified");
                            m
                        }
                        ReceiveDisposition::HandlerRequired(m) => {
                            assert_eq!(row["route"][key], "handler");
                            m
                        }
                        _ => panic!("applicable message reached unsupported fallback"),
                    };
                    assert_eq!(
                        message.rule().name,
                        row["applicable_name"].as_str().unwrap()
                    );
                }
                action => {
                    let ReceiveDisposition::Unsupported(value) = actual.unwrap() else {
                        panic!("non-applicable procedure reached handler");
                    };
                    assert_eq!(value.reference_known(), row["reference_known"]);
                    assert_eq!(
                        value.action(),
                        match action {
                            "unsupported-reject" => UnsupportedAction::RejectAndReport,
                            "unsupported-ignore" => UnsupportedAction::Ignore,
                            "unsupported-notify" => UnsupportedAction::IgnoreAndReport,
                            _ => panic!("reference action"),
                        }
                    );
                    let diagnostic = value.diagnostics();
                    if let Some(expected) = row["diagnostics_wire_hex"].as_str() {
                        let d = diagnostic.unwrap();
                        let wire = d.encode(output()).unwrap();
                        assert!(wire.as_bytes() == bytes(expected));
                        assert!(
                            CriticalityDiagnostics::decode(wire.as_bytes(), context()).unwrap()
                                == d
                        );
                    } else {
                        assert!(diagnostic.is_none());
                    }
                }
            }
        }
    }
}

#[test]
fn routing_preserves_field_policy_boundary_and_exact_resource_limits() {
    let f = oracle();
    for row in f["cases"].as_array().unwrap() {
        let wire = bytes(row["wire_hex"].as_str().unwrap());
        for receiver in [Endpoint::N3iwf, Endpoint::Amf] {
            let original = inspect(&wire, receiver, context());
            for unknown in [
                UnknownIePolicy::Drop,
                UnknownIePolicy::Preserve,
                UnknownIePolicy::Reject,
            ] {
                for validation in [
                    ValidationLevel::HeaderOnly,
                    ValidationLevel::Structural,
                    ValidationLevel::Strict,
                    ValidationLevel::ProcedureAware,
                ] {
                    for duplicate in [
                        DuplicateIePolicy::First,
                        DuplicateIePolicy::Last,
                        DuplicateIePolicy::Reject,
                    ] {
                        let ctx = DecodeContext {
                            max_message_len: wire.len(),
                            max_depth: 3,
                            max_ies: 0,
                            unknown_ie_policy: unknown,
                            duplicate_ie_policy: duplicate,
                            validation_level: validation,
                            ..context()
                        };
                        let next = inspect(&wire, receiver, ctx);
                        assert_eq!(next.as_ref().ok(), original.as_ref().ok());
                        assert!(inspect(
                            &wire,
                            receiver,
                            DecodeContext {
                                max_message_len: wire.len() - 1,
                                ..ctx
                            }
                        )
                        .is_err());
                        assert!(inspect(
                            &wire,
                            receiver,
                            DecodeContext {
                                max_depth: 2,
                                ..ctx
                            }
                        )
                        .is_err());
                    }
                }
            }
        }
    }
    let row = f["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["applicable_name"] == "InitialUEMessage" && r["route"]["amf"] == "qualified")
        .unwrap();
    let wire = bytes(row["wire_hex"].as_str().unwrap());
    let pdu = Pdu::decode_owned(Bytes::from(wire.clone()), context()).unwrap();
    assert!(matches!(
        inspect(&wire, Endpoint::Amf, context()),
        Ok(ReceiveDisposition::Qualified(
            ApplicableMessage::InitialUeMessage
        ))
    ));
    assert!(NasMessage::from_pdu(&pdu, context()).is_err()); // mandatory fields absent
    let paging = [0, 24, 64, 3, 0, 0, 0];
    assert!(matches!(
        inspect(&paging, Endpoint::N3iwf, context()).unwrap(),
        ReceiveDisposition::Unsupported(_)
    ));
}

#[test]
fn physical_framing_adversarial_replay_and_redaction() {
    let f = oracle();
    for row in f["cases"].as_array().unwrap() {
        let wire = bytes(row["wire_hex"].as_str().unwrap());
        replay::exercise(&wire, context(), output());
        let cuts: Vec<_> = if wire.len() < 16 {
            (0..wire.len()).collect()
        } else {
            vec![
                0,
                1,
                2,
                3,
                4,
                127.min(wire.len() - 1),
                wire.len() / 2,
                wire.len() - 1,
            ]
        };
        for cut in cuts {
            assert!(inspect(&wire[..cut], Endpoint::N3iwf, context()).is_err());
        }
        let mut trailing = wire.clone();
        trailing.push(0);
        assert!(inspect(&trailing, Endpoint::N3iwf, context()).is_err());
        for position in [0, 1, 2, 3, wire.len() / 2, wire.len() - 1] {
            for bit in [1, 32, 128] {
                let mut changed = wire.clone();
                changed[position] ^= bit;
                replay::exercise(&changed, context(), output());
            }
        }
    }
    for bad in [
        vec![0, 250, 0, 0x80, 0],
        vec![0, 250, 0, 0xc0],
        vec![0, 250, 0, 0xc5],
        vec![0, 250, 0, 0xc1, 0],
        vec![0x80, 250, 0, 0],
        vec![0x60, 250, 0, 0],
        vec![1, 250, 0, 0],
        vec![0, 250, 1, 0],
        vec![0, 250, 0xc0, 0],
    ] {
        assert!(inspect(&bad, Endpoint::N3iwf, context()).is_err());
    }
    let secret = b"synthetic-nas-key-peer-value";
    let mut wire = vec![0, 250, 128, secret.len() as u8];
    wire.extend_from_slice(secret);
    let value = inspect(&wire, Endpoint::N3iwf, context()).unwrap();
    let debug = format!("{value:?}");
    assert!(!debug.contains(std::str::from_utf8(secret).unwrap()));
    wire[2] |= 1;
    let error = inspect(&wire, Endpoint::N3iwf, context()).unwrap_err();
    assert!(!format!("{error:?} {error}").contains(std::str::from_utf8(secret).unwrap()));
}
