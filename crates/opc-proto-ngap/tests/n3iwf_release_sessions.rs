#[path = "support/release_sessions.rs"]
mod shared;
use bytes::Bytes;
use opc_proto_ngap::n3iwf::release::ReleaseMessage;
use opc_proto_ngap::n3iwf::release_sessions::{ContextReleasedSession, ContextReleasedSessions};
use opc_proto_ngap::n3iwf::reset_fields::CriticalityDiagnostics;
use opc_proto_ngap::n3iwf::resource_release::ReleaseResponseTransfer;
use opc_proto_ngap::n3iwf::session_lists::SessionId;
use opc_proto_ngap::n3iwf::{AmfUeId, N3iwfLocation, RanUeId};
use opc_proto_ngap::{encode, Criticality, MessageType, Pdu, PduKind, ProtocolIe};
use opc_protocol::{
    DecodeContext, DecodeError, DuplicateIePolicy, EncodeContext, OwnedDecode, ValidationLevel,
};
use serde_json::Value;
use std::sync::OnceLock;
fn oracle() -> &'static Value {
    static DATA: OnceLock<Value> = OnceLock::new();
    DATA.get_or_init(|| {
        serde_json::from_str(include_str!("fixtures/n3iwf-release-sessions.json")).unwrap()
    })
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
        max_depth: 16,
        max_ies: 256,
        validation_level: ValidationLevel::Strict,
        duplicate_ie_policy: DuplicateIePolicy::Reject,
        ..DecodeContext::default()
    }
}
fn output() -> EncodeContext {
    EncodeContext {
        max_message_len: 200_000,
        ..EncodeContext::default()
    }
}
fn model(row: &Value) -> Result<ContextReleasedSessions, DecodeError> {
    ContextReleasedSessions::new(
        row["model"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| ContextReleasedSession {
                id: SessionId::new(v["id"].as_u64().unwrap() as u8),
                transfer: v["transfer"]
                    .as_bool()
                    .unwrap()
                    .then_some(ReleaseResponseTransfer),
            })
            .collect(),
    )
}
fn field_depth(value: &ContextReleasedSessions) -> usize {
    if value.values().iter().any(|v| v.transfer.is_some()) {
        6
    } else {
        3
    }
}
type Fields = Vec<(u16, Criticality, Vec<u8>)>;
fn fields(row: &Value) -> Fields {
    row["fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| {
            (
                v["id"].as_u64().unwrap() as u16,
                match v["criticality"].as_str().unwrap() {
                    "reject" => Criticality::reject,
                    "ignore" => Criticality::ignore,
                    _ => Criticality::notify,
                },
                bytes(v["wire_hex"].as_str().unwrap()),
            )
        })
        .collect()
}
fn read(row: &Value, ctx: DecodeContext) -> Result<Pdu, DecodeError> {
    Pdu::decode_owned(Bytes::from(bytes(row["wire_hex"].as_str().unwrap())), ctx)
}
fn construct_row(row: &Value) -> ReleaseMessage {
    let fs = fields(row);
    let get = |id| fs.iter().find(|v| v.0 == id).map(|v| v.2.as_slice());
    ReleaseMessage::Complete {
        amf: AmfUeId::decode(get(10).unwrap(), context()).unwrap(),
        ran: RanUeId::decode(get(85).unwrap(), context()).unwrap(),
        location: get(121).map(|v| N3iwfLocation::decode(v, context()).unwrap()),
        diagnostics: get(19).map(|v| CriticalityDiagnostics::decode(v, context()).unwrap()),
        sessions: row["sessions"]
            .as_str()
            .map(|s| model(&oracle()["fields"][s]).unwrap()),
    }
}
fn sessions(value: &ReleaseMessage) -> &Option<ContextReleasedSessions> {
    let ReleaseMessage::Complete { sessions, .. } = value else {
        panic!("response expected")
    };
    sessions
}
fn message_depth(value: &ReleaseMessage) -> usize {
    let ReleaseMessage::Complete {
        sessions,
        location,
        diagnostics,
        ..
    } = value
    else {
        panic!("response expected")
    };
    let mut depth = 5;
    if location.is_some() {
        depth = 8;
    }
    if let Some(v) = diagnostics {
        depth = depth.max(if v.ies.is_some() { 8 } else { 6 });
    }
    if let Some(v) = sessions {
        depth = depth.max(4 + field_depth(v));
    }
    depth
}
#[test]
fn independent_lists_values_generated_paths_and_exact_bounds() {
    let rows = oracle()["fields"].as_object().unwrap();
    assert_eq!(rows.len(), 1287);
    let mut admitted = 0;
    for (name, row) in rows {
        let wire = bytes(row["wire_hex"].as_str().unwrap());
        if row["admitted"] == false {
            assert!(
                ContextReleasedSessions::decode(&wire, context()).is_err(),
                "{name}"
            );
            if name == "duplicate-session" {
                assert!(model(row).is_err());
            }
            continue;
        }
        admitted += 1;
        let value = model(row).unwrap();
        let exact = DecodeContext {
            max_message_len: wire.len(),
            max_depth: field_depth(&value),
            max_ies: value.values().len(),
            ..context()
        };
        assert!(
            ContextReleasedSessions::decode(&wire, exact).unwrap() == value,
            "{name}: model"
        );
        assert!(
            value
                .encode(EncodeContext {
                    max_message_len: wire.len(),
                    ..output()
                })
                .unwrap()
                .as_bytes()
                == wire,
            "{name}: independent bytes"
        );
        assert!(value
            .encode(EncodeContext {
                max_message_len: wire.len() - 1,
                ..output()
            })
            .is_err());
        for short in [
            DecodeContext {
                max_depth: exact.max_depth - 1,
                ..exact
            },
            DecodeContext {
                max_ies: exact.max_ies - 1,
                ..exact
            },
            DecodeContext {
                max_message_len: wire.len() - 1,
                ..exact
            },
        ] {
            assert!(
                ContextReleasedSessions::decode(&wire, short).is_err(),
                "{name}: limit"
            );
        }
        assert!(format!("{value:?}").contains("REDACTED"));
    }
    assert_eq!(admitted, 1280);
    assert!(ContextReleasedSessions::new(vec![]).is_err());
    assert!(ContextReleasedSessions::new(vec![
        ContextReleasedSession {
            id: SessionId::new(1),
            transfer: None
        };
        257
    ])
    .is_err());
}
#[test]
fn complete_messages_preserve_optional_reports_and_existing_fields() {
    let rows = oracle()["messages"].as_array().unwrap();
    assert_eq!(rows.len(), 1308);
    let mut admitted = 0;
    for row in rows {
        let name = row["name"].as_str().unwrap();
        let pdu = read(row, context());
        if row["admitted"] == false {
            assert!(
                pdu.as_ref()
                    .ok()
                    .and_then(|v| ReleaseMessage::from_pdu(v, context()).ok())
                    .is_none(),
                "{name}"
            );
            continue;
        }
        admitted += 1;
        let pdu = pdu.unwrap();
        let value = ReleaseMessage::from_pdu(&pdu, context()).unwrap();
        let expected = construct_row(row);
        assert!(
            sessions(&value.message) == sessions(&expected),
            "{name}: presence/value"
        );
        assert!(value.ignored_ie_count == 0 && value.notify_ie_ids.is_empty());
        let wire = bytes(row["wire_hex"].as_str().unwrap());
        let count = fields(row)
            .len()
            .max(sessions(&expected).as_ref().map_or(0, |v| v.values().len()));
        let exact = DecodeContext {
            max_message_len: wire.len(),
            max_depth: message_depth(&expected),
            max_ies: count,
            ..context()
        };
        for message in [&value.message, &expected] {
            let p = message
                .construct(exact)
                .unwrap_or_else(|e| panic!("{name}: construct {e:?}"));
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
                "{name}: canonical reference"
            );
            assert!(encode(
                &p,
                EncodeContext {
                    max_message_len: wire.len() - 1,
                    ..output()
                }
            )
            .is_err());
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
                assert!(
                    message.construct(short).is_err(),
                    "{name}: construction bound"
                );
                assert!(
                    ReleaseMessage::from_pdu(&pdu, short).is_err(),
                    "{name}: admission bound"
                );
            }
        }
        assert!(ReleaseMessage::from_pdu(&read(row, exact).unwrap(), exact).is_ok());
        assert!(read(
            row,
            DecodeContext {
                max_message_len: wire.len() - 1,
                ..exact
            }
        )
        .is_err());
        assert!(format!("{:?}", value.message).contains("REDACTED"));
    }
    assert_eq!(admitted, 1298);
}
#[test]
fn singleton_policy_wrapper_metadata_and_nested_framing() {
    let row = oracle()["messages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"] == "duplicate-session-list")
        .unwrap();
    for policy in [
        DuplicateIePolicy::First,
        DuplicateIePolicy::Last,
        DuplicateIePolicy::Reject,
    ] {
        let ctx = DecodeContext {
            duplicate_ie_policy: policy,
            ..context()
        };
        let pdu = read(row, ctx);
        if matches!(policy, DuplicateIePolicy::Reject) {
            assert!(pdu.is_err());
            continue;
        }
        let pdu = pdu.unwrap();
        let value = ReleaseMessage::from_pdu(&pdu, ctx).unwrap();
        let key = if matches!(policy, DuplicateIePolicy::First) {
            "single-7-0"
        } else {
            "single-9-1"
        };
        assert!(
            sessions(&value.message).as_ref().unwrap() == &model(&oracle()["fields"][key]).unwrap()
        );
    }
    let row = oracle()["messages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"] == "single-7-1")
        .unwrap();
    let pdu = read(row, context()).unwrap();
    for change in 0..3 {
        let mut bad = pdu.clone();
        if let PduKind::Successful {
            procedure_code,
            criticality,
            ..
        } = &mut bad.kind
        {
            if change == 0 {
                *procedure_code = 255;
            } else if change == 1 {
                *criticality = Criticality::ignore;
            }
        }
        if change == 2 {
            if let PduKind::Successful {
                procedure_code,
                criticality,
                message,
            } = bad.kind
            {
                bad.kind = PduKind::Unsuccessful {
                    procedure_code,
                    criticality,
                    message,
                };
            }
        }
        assert!(ReleaseMessage::from_pdu(&bad, context()).is_err());
    }
    let original = bytes(
        oracle()["fields"]["single-7-1"]["wire_hex"]
            .as_str()
            .unwrap(),
    );
    assert_eq!(original.len(), 11);
    let mut malformed = vec![];
    for (offset, mask) in [(1, 0x80), (1, 1), (7, 1), (10, 1), (10, 0x80)] {
        let mut v = original.clone();
        v[offset] ^= mask;
        malformed.push(v);
    }
    let mut outer = original.clone();
    outer.splice(8..9, [0x80, 2]);
    malformed.push(outer);
    let mut inner = original.clone();
    inner.splice(9..10, [0x80, 1]);
    inner[8] = 3;
    malformed.push(inner);
    let mut truncated = original.clone();
    truncated[8] = 0xc1;
    malformed.push(truncated);
    let mut trailing = original.clone();
    trailing.push(0);
    malformed.push(trailing);
    for wire in malformed {
        assert!(ContextReleasedSessions::decode(&wire, context()).is_err());
        let mut fs = fields(row);
        fs.iter_mut().find(|v| v.0 == 60).unwrap().2 = wire;
        let ies: Vec<_> = fs
            .iter()
            .map(|(id, crit, v)| ProtocolIe::new(*id, *crit, v))
            .collect();
        let pdu =
            Pdu::from_protocol_ies(MessageType::UeContextReleaseComplete, &ies, context()).unwrap();
        assert!(ReleaseMessage::from_pdu(&pdu, context()).is_err());
    }
}
#[test]
fn bounded_complete_and_field_replay_mutations_and_truncations() {
    for row in oracle()["fields"]
        .as_object()
        .unwrap()
        .values()
        .chain(oracle()["messages"].as_array().unwrap())
    {
        let wire = bytes(row["wire_hex"].as_str().unwrap());
        shared::exercise(&wire, context(), output());
        for length in [0, 1, wire.len() / 2, wire.len() - 1] {
            shared::exercise(&wire[..length], context(), output());
        }
        for offset in [0, 1, wire.len() / 2, wire.len() - 1] {
            let mut v = wire.clone();
            v[offset] ^= 0x80;
            shared::exercise(&v, context(), output());
        }
    }
}
