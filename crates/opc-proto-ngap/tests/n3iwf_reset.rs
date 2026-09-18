use bytes::Bytes;
use opc_proto_ngap::n3iwf::release::Cause;
use opc_proto_ngap::n3iwf::reset::{
    ErrorIndication, ResetAcknowledge, ResetMessage, ResetRequest, Signalling,
};
use opc_proto_ngap::n3iwf::reset_fields::{Connections, CriticalityDiagnostics, ResetType};
use opc_proto_ngap::n3iwf::{AmfUeId, RanUeId};
use opc_proto_ngap::{encode, Criticality, MessageType, Pdu, PduKind, ProtocolIe};
use opc_protocol::{
    DecodeContext, DuplicateIePolicy, EncodeContext, OwnedDecode, UnknownIePolicy, ValidationLevel,
};
use serde_json::Value;

fn oracle() -> Value {
    serde_json::from_str(include_str!("fixtures/n3iwf-reset.json")).unwrap()
}
fn context() -> DecodeContext {
    DecodeContext {
        max_message_len: 2_000_000,
        max_ies: 65536,
        max_depth: 16,
        validation_level: ValidationLevel::Strict,
        duplicate_ie_policy: DuplicateIePolicy::Reject,
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
fn signalling(row: &Value) -> Signalling {
    if row["signalling"] == "ue" {
        Signalling::UeAssociated
    } else {
        Signalling::NonUe
    }
}
fn kind(row: &Value) -> MessageType {
    match row["kind"].as_str().unwrap() {
        "NGReset" => MessageType::NgReset,
        "NGResetAcknowledge" => MessageType::NgResetAcknowledge,
        _ => MessageType::ErrorIndication,
    }
}
fn fields(row: &Value, key: &str) -> Vec<(u16, Criticality, Vec<u8>)> {
    row[key]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| {
            let crit = match v["criticality"].as_str().unwrap() {
                "reject" => Criticality::reject,
                "ignore" => Criticality::ignore,
                _ => Criticality::notify,
            };
            (
                v["id"].as_u64().unwrap() as u16,
                crit,
                bytes(v["wire_hex"].as_str().unwrap()),
            )
        })
        .collect()
}
fn value(row: &Value) -> ResetMessage {
    let values = fields(row, "canonical_fields");
    let get = |id| values.iter().find(|v| v.0 == id).map(|v| v.2.as_slice());
    let diagnostics = get(19).map(|v| CriticalityDiagnostics::decode(v, context()).unwrap());
    match kind(row) {
        MessageType::NgReset => ResetMessage::Request(ResetRequest {
            cause: Cause::decode(get(15).unwrap(), context()).unwrap(),
            reset: ResetType::decode(get(88).unwrap(), context()).unwrap(),
        }),
        MessageType::NgResetAcknowledge => ResetMessage::Acknowledge(ResetAcknowledge {
            diagnostics,
            connections: get(111).map(|v| Connections::decode(v, context()).unwrap()),
        }),
        _ => ResetMessage::Error(ErrorIndication {
            amf: get(10).map(|v| AmfUeId::decode(v, context()).unwrap()),
            ran: get(85).map(|v| RanUeId::decode(v, context()).unwrap()),
            cause: get(15).map(|v| Cause::decode(v, context()).unwrap()),
            diagnostics,
        }),
    }
}
fn read(row: &Value, ctx: DecodeContext) -> Result<Pdu, opc_protocol::DecodeError> {
    Pdu::decode_owned(Bytes::from(bytes(row["wire_hex"].as_str().unwrap())), ctx)
}
fn depth(value: &ResetMessage) -> usize {
    let diagnostic = |v: &Option<CriticalityDiagnostics>| {
        v.as_ref()
            .map_or(5, |v| if v.ies.is_some() { 8 } else { 6 })
    };
    match value {
        ResetMessage::Request(v) => {
            if matches!(v.reset, ResetType::All) {
                6
            } else {
                8
            }
        }
        ResetMessage::Acknowledge(v) => {
            diagnostic(&v.diagnostics).max(if v.connections.is_some() { 7 } else { 5 })
        }
        ResetMessage::Error(v) => {
            diagnostic(&v.diagnostics).max(if v.cause.is_some() { 6 } else { 5 })
        }
    }
}

#[test]
fn complete_messages_match_independent_values_presence_and_signalling_rules() {
    let reference = oracle();
    let mut count = 0;
    for row in reference["cases"].as_array().unwrap() {
        let name = row["name"].as_str().unwrap();
        let pdu = read(row, context());
        if row["admitted"] == false {
            if let Ok(pdu) = pdu {
                assert!(
                    ResetMessage::from_pdu(&pdu, signalling(row), context()).is_err(),
                    "{name}"
                );
            }
            continue;
        }
        let pdu = pdu.unwrap();
        let admitted = ResetMessage::from_pdu(&pdu, signalling(row), context()).unwrap();
        let expected = value(row);
        assert!(admitted.message == expected, "{name} fields");
        let wire = bytes(row["canonical_wire_hex"].as_str().unwrap());
        assert!(
            encode(
                &expected.construct(signalling(row), context()).unwrap(),
                output()
            )
            .unwrap()
                == wire,
            "{name} construction"
        );
        assert!(
            encode(
                &admitted
                    .message
                    .construct(signalling(row), context())
                    .unwrap(),
                output()
            )
            .unwrap()
                == wire,
            "{name} admission"
        );
        assert_eq!(
            admitted.ignored_empty_connection_count,
            row["empty_connections"].as_u64().unwrap() as usize
        );
        assert_eq!(
            admitted.ignored_ie_count,
            usize::from(row["criticality"] == "ignore")
        );
        assert_eq!(
            admitted.notify_ie_ids,
            if row["criticality"] == "notify" {
                vec![65530]
            } else {
                vec![]
            }
        );
        assert!(format!("{admitted:?}").contains("REDACTED"));
        let ctx = DecodeContext {
            max_depth: depth(&expected),
            max_message_len: wire.len(),
            ..context()
        };
        let constructed = expected.construct(signalling(row), ctx).unwrap();
        assert!(ResetMessage::from_pdu(&constructed, signalling(row), ctx).is_ok());
        for short in [
            DecodeContext {
                max_depth: ctx.max_depth - 1,
                ..ctx
            },
            DecodeContext {
                max_message_len: wire.len() - 1,
                ..ctx
            },
        ] {
            assert!(
                expected.construct(signalling(row), short).is_err(),
                "{name} construction limit"
            );
            assert!(
                ResetMessage::from_pdu(&constructed, signalling(row), short).is_err(),
                "{name} receive limit"
            );
        }
        let fields = row["canonical_fields"].as_array().unwrap().len();
        if fields > 0 {
            let short = DecodeContext {
                max_ies: fields - 1,
                ..ctx
            };
            assert!(expected.construct(signalling(row), short).is_err());
            assert!(ResetMessage::from_pdu(&constructed, signalling(row), short).is_err());
        }
        let connections = row["connection_count"].as_u64().unwrap() as usize;
        if connections > fields {
            let short = DecodeContext {
                max_ies: connections - 1,
                ..ctx
            };
            assert!(expected.construct(signalling(row), short).is_err());
            assert!(ResetMessage::from_pdu(&constructed, signalling(row), short).is_err());
        }
        count += 1;
    }
    assert_eq!(count, 165);
    assert_eq!(reference["cases"].as_array().unwrap().len(), 189);
}

#[test]
fn constructors_require_error_basis_ue_ids_and_response_diagnostic_applicability() {
    let reference = oracle();
    for row in reference["cases"].as_array().unwrap() {
        if matches!(
            row["mode"].as_str(),
            Some("basis" | "signalling" | "header")
        ) {
            assert_eq!(
                value(row).construct(signalling(row), context()).is_ok(),
                row["admitted"].as_bool().unwrap(),
                "{}",
                row["name"].as_str().unwrap()
            );
        }
    }
    let base = reference["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"] == "error-identifiers-ue-3")
        .unwrap();
    let ResetMessage::Error(error) = value(base) else {
        panic!()
    };
    for changed in [
        ErrorIndication {
            amf: None,
            ..error.clone()
        },
        ErrorIndication { ran: None, ..error },
    ] {
        assert!(ResetMessage::Error(changed.clone())
            .construct(Signalling::UeAssociated, context())
            .is_err());
        assert!(ResetMessage::Error(changed)
            .construct(Signalling::NonUe, context())
            .is_ok());
    }
}

#[test]
fn generic_unknown_duplicate_and_mutable_container_policies_remain_authoritative() {
    let reference = oracle();
    for row in reference["cases"].as_array().unwrap() {
        if row["mode"] == "duplicate" {
            let original = fields(row, "fields");
            let id = if kind(row) == MessageType::NgResetAcknowledge {
                19
            } else {
                15
            };
            for policy in [DuplicateIePolicy::First, DuplicateIePolicy::Last] {
                let ctx = DecodeContext {
                    duplicate_ie_policy: policy,
                    ..context()
                };
                let pdu = read(row, ctx).unwrap();
                let admitted = ResetMessage::from_pdu(&pdu, Signalling::NonUe, ctx).unwrap();
                let candidates: Vec<_> = original.iter().filter(|v| v.0 == id).collect();
                let expected = if policy == DuplicateIePolicy::First {
                    candidates[0]
                } else {
                    candidates[candidates.len() - 1]
                };
                let encoded = match admitted.message {
                    ResetMessage::Request(v) => v.cause.encode(output()).unwrap(),
                    ResetMessage::Error(v) => v.cause.unwrap().encode(output()).unwrap(),
                    ResetMessage::Acknowledge(v) => {
                        v.diagnostics.unwrap().encode(output()).unwrap()
                    }
                };
                assert!(encoded.as_bytes() == expected.2);
            }
        }
        if row["mode"] == "unknown" {
            let ctx = DecodeContext {
                unknown_ie_policy: UnknownIePolicy::Drop,
                ..context()
            };
            if row["criticality"] == "reject" {
                assert!(read(row, ctx).is_err());
                let ctx = DecodeContext {
                    validation_level: ValidationLevel::Structural,
                    ..ctx
                };
                let pdu = read(row, ctx).unwrap();
                assert!(ResetMessage::from_pdu(&pdu, Signalling::NonUe, ctx).is_ok());
            } else {
                let pdu = read(row, ctx).unwrap();
                let admitted = ResetMessage::from_pdu(&pdu, Signalling::NonUe, ctx).unwrap();
                assert_eq!(admitted.ignored_ie_count, 0);
                assert!(admitted.notify_ie_ids.is_empty());
                assert!(read(
                    row,
                    DecodeContext {
                        unknown_ie_policy: UnknownIePolicy::Reject,
                        ..context()
                    }
                )
                .is_err());
            }
        }
        if row["name"].as_str().unwrap().starts_with("base-") {
            let mut pdu = read(row, context()).unwrap();
            match &mut pdu.kind {
                PduKind::Initiating { procedure_code, .. }
                | PduKind::Successful { procedure_code, .. }
                | PduKind::Unsuccessful { procedure_code, .. } => *procedure_code = 255,
            }
            assert!(ResetMessage::from_pdu(&pdu, Signalling::NonUe, context()).is_err());
            let mut pdu = read(row, context()).unwrap();
            let (procedure_code, criticality, message) = match pdu.kind {
                PduKind::Initiating {
                    procedure_code,
                    criticality,
                    message,
                }
                | PduKind::Successful {
                    procedure_code,
                    criticality,
                    message,
                }
                | PduKind::Unsuccessful {
                    procedure_code,
                    criticality,
                    message,
                } => (procedure_code, criticality, message),
            };
            pdu.kind = PduKind::Unsuccessful {
                procedure_code,
                criticality,
                message,
            };
            assert!(ResetMessage::from_pdu(&pdu, Signalling::NonUe, context()).is_err());
            let mut values = fields(row, "fields");
            if let Some(v) = values.first_mut() {
                v.1 = Criticality::notify;
                let ies: Vec<_> = values
                    .iter()
                    .map(|(id, crit, value)| ProtocolIe::new(*id, *crit, value))
                    .collect();
                assert!(Pdu::from_protocol_ies(kind(row), &ies, context()).is_err());
            }
        }
    }
}

#[test]
fn complete_message_truncations_and_bounded_mutations_never_panic() {
    let reference = oracle();
    for row in reference["cases"].as_array().unwrap() {
        let wire = bytes(row["wire_hex"].as_str().unwrap());
        let stride = (wire.len() / 24).max(1);
        for end in (0..wire.len()).step_by(stride).chain([wire.len() - 1]) {
            assert!(Pdu::decode_owned(Bytes::copy_from_slice(&wire[..end]), context()).is_err());
        }
        for index in (0..wire.len()).step_by(stride) {
            for mask in [1, 0x80, 0xff] {
                let mut changed = wire.clone();
                changed[index] ^= mask;
                if let Ok(pdu) = Pdu::decode_owned(Bytes::from(changed), context()) {
                    let _ = ResetMessage::from_pdu(&pdu, signalling(row), context());
                }
            }
        }
    }
}
