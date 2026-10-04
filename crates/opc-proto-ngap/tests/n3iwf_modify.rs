use bytes::Bytes;
use opc_proto_ngap::n3iwf::modify::{ModifyMessage, ModifyRequest, ModifyResponse};
use opc_proto_ngap::n3iwf::modify_lists::{
    FailedModifications, ModifiedSessions, SessionModifications,
};
use opc_proto_ngap::n3iwf::reset_fields::CriticalityDiagnostics;
use opc_proto_ngap::n3iwf::{AmfUeId, N3iwfLocation, RanUeId};
use opc_proto_ngap::{encode, Criticality, MessageType, Pdu, PduKind, ProtocolIe};
use opc_protocol::{
    DecodeContext, DuplicateIePolicy, EncodeContext, OwnedDecode, UnknownIePolicy, ValidationLevel,
};
use serde_json::Value;
fn oracle() -> Value {
    serde_json::from_str(include_str!("fixtures/n3iwf-modify.json")).unwrap()
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
        max_depth: 20,
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
fn read(row: &Value, ctx: DecodeContext) -> Result<Pdu, opc_protocol::DecodeError> {
    Pdu::decode_owned(Bytes::from(bytes(row["wire_hex"].as_str().unwrap())), ctx)
}
fn fields(row: &Value, key: &str) -> Vec<(u16, Criticality, Vec<u8>)> {
    row[key]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            (
                f["id"].as_u64().unwrap() as u16,
                match f["criticality"].as_str().unwrap() {
                    "reject" => Criticality::reject,
                    "ignore" => Criticality::ignore,
                    _ => Criticality::notify,
                },
                bytes(f["wire_hex"].as_str().unwrap()),
            )
        })
        .collect()
}
fn construct(
    value: &ModifyMessage<'_>,
    ctx: DecodeContext,
) -> Result<Pdu, opc_protocol::DecodeError> {
    match value {
        ModifyMessage::Request(v) => v.construct(ctx),
        ModifyMessage::Response(v) => v.construct(ctx),
    }
}
#[test]
fn independent_complete_messages_and_constructed_fields() {
    let f = oracle();
    assert_eq!(f["cases"].as_array().unwrap().len(), 63);
    let mut admitted = 0;
    for row in f["cases"].as_array().unwrap() {
        let name = row["name"].as_str().unwrap();
        let pdu = read(row, context());
        if row["admitted"] == false {
            assert!(
                pdu.as_ref()
                    .ok()
                    .and_then(|p| ModifyMessage::from_pdu(p, context()).ok())
                    .is_none(),
                "{name}"
            );
            continue;
        }
        admitted += 1;
        let pdu = pdu.unwrap();
        let typed = ModifyMessage::from_pdu(&pdu, context()).unwrap();
        let wire = encode(&construct(&typed.message, context()).unwrap(), output()).unwrap();
        assert!(
            wire == bytes(row["canonical_wire_hex"].as_str().unwrap()),
            "{name} canonical"
        );
        let fs = fields(row, "canonical_fields");
        let get = |id| fs.iter().find(|v| v.0 == id).map(|v| v.2.as_slice());
        let amf = AmfUeId::decode(get(10).unwrap(), context()).unwrap();
        let ran = RanUeId::decode(get(85).unwrap(), context()).unwrap();
        let expected = if row["kind"] == "PDUSessionResourceModifyRequest" {
            let sessions = SessionModifications::decode(get(64).unwrap(), context()).unwrap();
            ModifyMessage::Request(ModifyRequest {
                amf,
                ran,
                sessions: sessions.requests,
            })
        } else {
            ModifyMessage::Response(ModifyResponse {
                amf,
                ran,
                modified: get(65).map(|v| ModifiedSessions::decode(v, context()).unwrap()),
                failed: get(54).map(|v| FailedModifications::decode(v, context()).unwrap()),
                location: get(121).map(|v| N3iwfLocation::decode(v, context()).unwrap()),
                diagnostics: get(19).map(|v| CriticalityDiagnostics::decode(v, context()).unwrap()),
            })
        };
        assert!(
            encode(&construct(&expected, context()).unwrap(), output()).unwrap() == wire,
            "{name} independent fields"
        );
        let request = row["kind"] == "PDUSessionResourceModifyRequest";
        assert!(matches!(
            (&pdu.kind, request),
            (
                PduKind::Initiating {
                    procedure_code: 26,
                    criticality: Criticality::reject,
                    ..
                },
                true
            ) | (
                PduKind::Successful {
                    procedure_code: 26,
                    criticality: Criticality::reject,
                    ..
                },
                false
            )
        ));
        let length = bytes(row["wire_hex"].as_str().unwrap()).len();
        let exact = DecodeContext {
            max_message_len: length,
            ..context()
        };
        assert!(ModifyMessage::from_pdu(&pdu, exact).is_ok());
        assert!(read(
            row,
            DecodeContext {
                max_message_len: length - 1,
                ..context()
            }
        )
        .is_err());
        assert_eq!(
            typed.ignored_ie_count,
            usize::from(name.ends_with("unknown-ignore") || name.ends_with("paging-ignored"))
        );
        assert_eq!(
            typed.notify_ie_ids.len(),
            usize::from(name.ends_with("unknown-notify"))
        );
        if name.ends_with("request-request-notify") {
            assert_eq!(typed.transfer_diagnostics.len(), 2);
            assert!(typed
                .transfer_diagnostics
                .iter()
                .all(|v| v.notify_ie_ids == [65530]));
        }
        for d in [format!("{pdu:?}"), format!("{typed:?}")] {
            assert!(
                !d.contains("01020304") && !d.contains("modify-nas-") && !d.contains("198.51.100"),
                "{name} redaction"
            );
        }
    }
    assert_eq!(admitted, 35);
}
#[test]
fn shared_policies_metadata_and_invalid_response_construction() {
    let f = oracle();
    for row in f["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["mode"] == "duplicate")
    {
        for policy in [DuplicateIePolicy::First, DuplicateIePolicy::Last] {
            let ctx = DecodeContext {
                duplicate_ie_policy: policy,
                ..context()
            };
            let pdu = read(row, ctx).unwrap();
            let got = ModifyMessage::from_pdu(&pdu, ctx).unwrap();
            let name = row["name"].as_str().unwrap();
            let (amf, ran, sessions) = match &got.message {
                ModifyMessage::Request(v) => {
                    (v.amf.value(), v.ran.value(), v.sessions.values().len())
                }
                ModifyMessage::Response(v) => (
                    v.amf.value(),
                    v.ran.value(),
                    v.modified.as_ref().unwrap().values().len(),
                ),
            };
            let last = matches!(policy, DuplicateIePolicy::Last);
            assert_eq!(
                amf,
                if last && name.ends_with("duplicate-10") {
                    1
                } else {
                    0x0102030405
                }
            );
            assert_eq!(
                ran,
                if last && name.ends_with("duplicate-85") {
                    1
                } else {
                    0x01020304
                }
            );
            assert_eq!(
                sessions,
                if last && (name.ends_with("duplicate-64") || name.ends_with("duplicate-65")) {
                    2
                } else {
                    1
                }
            );
        }
    }
    for row in f["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["mode"] == "unknown")
    {
        let strict_drop = DecodeContext {
            unknown_ie_policy: UnknownIePolicy::Drop,
            ..context()
        };
        let bad = row["name"].as_str().unwrap().ends_with("reject");
        assert_eq!(read(row, strict_drop).is_err(), bad);
        let drop = DecodeContext {
            validation_level: ValidationLevel::Structural,
            ..strict_drop
        };
        let pdu = read(row, drop).unwrap();
        let got = ModifyMessage::from_pdu(&pdu, drop).unwrap();
        assert_eq!(got.ignored_ie_count, 0);
        assert!(got.notify_ie_ids.is_empty());
        let reject = DecodeContext {
            unknown_ie_policy: UnknownIePolicy::Reject,
            ..context()
        };
        assert!(read(row, reject).is_err());
    }
    let row = f["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == "PDUSessionResourceModifyResponse-partial")
        .unwrap();
    let pdu = read(row, context()).unwrap();
    let ModifyMessage::Response(mut response) =
        ModifyMessage::from_pdu(&pdu, context()).unwrap().message
    else {
        panic!("response")
    };
    let mut bad = pdu.clone();
    if let PduKind::Successful { procedure_code, .. } = &mut bad.kind {
        *procedure_code = 29;
    }
    assert!(ModifyMessage::from_pdu(&bad, context()).is_err());
    response.modified = None;
    response.failed = None;
    assert!(response.construct(context()).is_err());
    let unsuccessful = Pdu::decode_owned(
        Bytes::from_static(&[0x40, 26, 0, 3, 0, 0, 0]),
        DecodeContext {
            validation_level: ValidationLevel::Structural,
            ..context()
        },
    )
    .unwrap();
    assert!(ModifyMessage::from_pdu(&unsuccessful, context()).is_err());
    let fs = fields(row, "fields");
    let ies: Vec<_> = fs
        .iter()
        .map(|(id, c, v)| ProtocolIe::new(*id, *c, v))
        .collect();
    assert!(Pdu::from_protocol_ies(
        MessageType::PduSessionResourceModifyResponse,
        &ies,
        DecodeContext {
            max_ies: ies.len() - 1,
            ..context()
        }
    )
    .is_err());
}

#[path = "support/modify.rs"]
mod replay;
#[test]
fn exact_message_depth_count_and_output_limits_with_adversarial_replay() {
    let f = oracle();
    for (name, depth, count) in [
        ("PDUSessionResourceModifyRequest-sessions-1", 17, 4),
        (
            "PDUSessionResourceModifyRequest-request-request-empty",
            11,
            3,
        ),
        (
            "PDUSessionResourceModifyResponse-response-response-empty",
            8,
            3,
        ),
        ("PDUSessionResourceModifyResponse-sessions-1", 12, 3),
        ("PDUSessionResourceModifyResponse-failure-count-1", 10, 3),
        (
            "PDUSessionResourceModifyResponse-failure-failure-diagnostics",
            12,
            256,
        ),
    ] {
        let row = f["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["name"] == name)
            .unwrap();
        let pdu = read(row, context()).unwrap();
        let exact = DecodeContext {
            max_depth: depth,
            max_ies: count,
            ..context()
        };
        let value = ModifyMessage::from_pdu(&pdu, exact).unwrap();
        let built = construct(&value.message, exact).unwrap();
        let wire = encode(&built, output()).unwrap();
        assert!(encode(
            &built,
            EncodeContext {
                max_message_len: wire.len(),
                ..output()
            }
        )
        .is_ok());
        assert!(encode(
            &built,
            EncodeContext {
                max_message_len: wire.len() - 1,
                ..output()
            }
        )
        .is_err());
        for ctx in [
            DecodeContext {
                max_depth: depth - 1,
                ..exact
            },
            DecodeContext {
                max_ies: count - 1,
                ..exact
            },
        ] {
            assert!(
                ModifyMessage::from_pdu(&pdu, ctx).is_err(),
                "{name} admit bound"
            );
            assert!(
                construct(&value.message, ctx).is_err(),
                "{name} construct bound"
            );
        }
    }
    for row in f["cases"].as_array().unwrap() {
        let wire = bytes(row["wire_hex"].as_str().unwrap());
        replay::exercise(&wire, context(), output());
        if row["admitted"] == true {
            for i in (0..wire.len()).step_by((wire.len() / 16).max(1)) {
                for mask in [1, 0x40, 0x80] {
                    let mut mutated = wire.clone();
                    mutated[i] ^= mask;
                    replay::exercise(&mutated, context(), output());
                }
            }
        }
    }
}
