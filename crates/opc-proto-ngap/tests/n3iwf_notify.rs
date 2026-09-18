use bytes::Bytes;
use opc_proto_ngap::n3iwf::notify::ResourceNotify;
use opc_proto_ngap::n3iwf::notify_fields::{NotifiedSessions, ReleasedSessions};
use opc_proto_ngap::n3iwf::{AmfUeId, N3iwfLocation, RanUeId};
use opc_proto_ngap::{encode, Criticality, MessageType, Pdu, PduKind, ProtocolIe};
use opc_protocol::{
    DecodeContext, DuplicateIePolicy, EncodeContext, OwnedDecode, UnknownIePolicy, ValidationLevel,
};
use serde_json::Value;

fn oracle() -> Value {
    serde_json::from_str(include_str!("fixtures/n3iwf-notify.json")).unwrap()
}
fn context() -> DecodeContext {
    DecodeContext {
        max_message_len: 200_000,
        max_ies: 256,
        max_depth: 16,
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
fn bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}
fn fields(row: &Value, key: &str) -> Vec<(u16, Criticality, Vec<u8>)> {
    row[key]
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
fn expected(row: &Value) -> ResourceNotify {
    let fields = fields(row, "canonical_fields");
    let get = |id| fields.iter().find(|v| v.0 == id).map(|v| v.2.as_slice());
    ResourceNotify {
        amf: AmfUeId::decode(get(10).unwrap(), context()).unwrap(),
        ran: RanUeId::decode(get(85).unwrap(), context()).unwrap(),
        notified: get(66).map(|v| NotifiedSessions::decode(v, context()).unwrap()),
        released: get(67).map(|v| ReleasedSessions::decode(v, context()).unwrap()),
        location: get(121).map(|v| N3iwfLocation::decode(v, context()).unwrap()),
    }
}
fn read(row: &Value, ctx: DecodeContext) -> Result<Pdu, opc_protocol::DecodeError> {
    Pdu::decode_owned(Bytes::from(bytes(row["wire_hex"].as_str().unwrap())), ctx)
}
fn limits(v: &ResourceNotify) -> (usize, usize) {
    let mut depth = 10;
    let mut count = 0;
    if let Some(values) = &v.notified {
        count = count.max(values.values().len());
        for value in values.values() {
            depth = depth.max(if value.transfer.released().is_empty() {
                11
            } else {
                12
            });
            count = count.max(value.transfer.notified().len() + value.transfer.released().len());
        }
    }
    if let Some(values) = &v.released {
        count = count.max(values.values().len());
    }
    (depth, count)
}

#[test]
fn complete_messages_match_independent_fields_presence_and_limits() {
    let corpus = oracle();
    assert_eq!(corpus["cases"].as_array().unwrap().len(), 43);
    let mut admitted = 0;
    for row in corpus["cases"].as_array().unwrap() {
        let name = row["name"].as_str().unwrap();
        let pdu = read(row, context());
        if row["admitted"] == false {
            assert!(
                pdu.and_then(|p| ResourceNotify::from_pdu(&p, context()))
                    .is_err(),
                "{name}"
            );
            continue;
        }
        let pdu = pdu.unwrap();
        let wanted = expected(row);
        let value = ResourceNotify::from_pdu(&pdu, context()).unwrap();
        assert!(value.message == wanted, "{name} fields");
        assert_eq!(
            value.ignored_ie_count,
            usize::from(name == "unknown-ignore")
        );
        assert_eq!(
            value.notify_ie_ids.len(),
            usize::from(name == "unknown-notify")
        );
        if name == "unknown-notify" {
            assert_eq!(value.notify_ie_ids, [65530]);
        }
        assert!(format!("{value:?}").contains("REDACTED"));
        let canonical = bytes(row["canonical_wire_hex"].as_str().unwrap());
        let wire = bytes(row["wire_hex"].as_str().unwrap());
        let (depth, nested_count) = limits(&wanted);
        let count = nested_count.max(row["fields"].as_array().unwrap().len());
        let ctx = DecodeContext {
            max_depth: depth,
            max_ies: count,
            max_message_len: wire.len(),
            ..context()
        };
        let decoded = read(row, ctx).unwrap();
        assert!(ResourceNotify::from_pdu(&decoded, ctx).unwrap().message == wanted);
        let constructed = wanted
            .construct(DecodeContext {
                max_message_len: canonical.len(),
                ..ctx
            })
            .unwrap();
        assert!(
            encode(&constructed, output()).unwrap() == canonical,
            "{name} encode"
        );
        assert!(wanted
            .construct(DecodeContext {
                max_message_len: canonical.len() - 1,
                ..ctx
            })
            .is_err());
        for short in [
            DecodeContext {
                max_depth: depth - 1,
                ..ctx
            },
            DecodeContext {
                max_ies: count - 1,
                ..ctx
            },
            DecodeContext {
                max_message_len: wire.len() - 1,
                ..ctx
            },
        ] {
            assert!(
                read(row, short)
                    .and_then(|p| ResourceNotify::from_pdu(&p, short))
                    .is_err(),
                "{name} limit"
            );
        }
        assert!(wanted
            .construct(DecodeContext {
                max_depth: depth - 1,
                ..ctx
            })
            .is_err());
        let fields = fields(row, "canonical_fields");
        let ies: Vec<_> = fields
            .iter()
            .map(|(id, c, v)| ProtocolIe::new(*id, *c, v))
            .collect();
        assert!(
            encode(
                &Pdu::from_protocol_ies(MessageType::PduSessionResourceNotify, &ies, ctx).unwrap(),
                output()
            )
            .unwrap()
                == canonical
        );
        admitted += 1;
    }
    assert_eq!(admitted, 27);
}

#[test]
fn constructors_reject_missing_and_conflicting_session_reports() {
    let corpus = oracle();
    let rows = corpus["cases"].as_array().unwrap();
    let mut value = expected(rows.iter().find(|v| v["name"] == "mixed-sessions").unwrap());
    value.notified = None;
    value.released = None;
    assert!(value.construct(context()).is_err());
    let conflict = expected(
        rows.iter()
            .find(|v| v["name"] == "overlap-sessions")
            .unwrap(),
    );
    assert!(conflict.construct(context()).is_err());
}

#[test]
fn selected_duplicate_unknown_and_mutable_container_policies_remain_authoritative() {
    let corpus = oracle();
    for row in corpus["cases"].as_array().unwrap() {
        let name = row["name"].as_str().unwrap();
        if row["mode"] == "duplicate" {
            assert!(read(row, context()).is_err());
            let id = name
                .strip_prefix("duplicate-")
                .unwrap()
                .parse::<u16>()
                .unwrap();
            let original = fields(row, "fields");
            let values: Vec<_> = original.iter().filter(|v| v.0 == id).collect();
            assert!(values[0].2 != values[1].2);
            for policy in [DuplicateIePolicy::First, DuplicateIePolicy::Last] {
                let ctx = DecodeContext {
                    duplicate_ie_policy: policy,
                    ..context()
                };
                let pdu = read(row, ctx).unwrap();
                let value = ResourceNotify::from_pdu(&pdu, ctx).unwrap().message;
                let wire = match id {
                    10 => value.amf.encode(output()).unwrap(),
                    85 => value.ran.encode(output()).unwrap(),
                    _ => value.notified.unwrap().encode(output()).unwrap(),
                };
                let selected = if policy == DuplicateIePolicy::First {
                    values[0]
                } else {
                    values[1]
                };
                assert!(wire.as_bytes() == selected.2);
            }
        }
        if row["mode"] == "unknown" {
            let ctx = DecodeContext {
                unknown_ie_policy: UnknownIePolicy::Drop,
                ..context()
            };
            if name == "unknown-reject" {
                assert!(read(row, ctx).is_err());
                let ctx = DecodeContext {
                    validation_level: ValidationLevel::Structural,
                    ..ctx
                };
                let pdu = read(row, ctx).unwrap();
                assert!(ResourceNotify::from_pdu(&pdu, ctx).is_ok());
                let ctx = DecodeContext {
                    validation_level: ValidationLevel::Structural,
                    ..context()
                };
                let pdu = read(row, ctx).unwrap();
                assert!(ResourceNotify::from_pdu(&pdu, ctx).is_err());
            } else {
                let pdu = read(row, ctx).unwrap();
                let value = ResourceNotify::from_pdu(&pdu, ctx).unwrap();
                assert_eq!(value.ignored_ie_count, 0);
                assert!(value.notify_ie_ids.is_empty());
            }
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
    let row = corpus["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"] == "notified-1")
        .unwrap();
    let mut pdu = read(row, context()).unwrap();
    if let PduKind::Initiating { procedure_code, .. } = &mut pdu.kind {
        *procedure_code = 255;
    }
    assert!(ResourceNotify::from_pdu(&pdu, context()).is_err());
    let mut pdu = read(row, context()).unwrap();
    if let PduKind::Initiating { criticality, .. } = &mut pdu.kind {
        *criticality = Criticality::reject;
    }
    assert!(ResourceNotify::from_pdu(&pdu, context()).is_err());
    let mut pdu = read(row, context()).unwrap();
    if let PduKind::Initiating {
        procedure_code,
        criticality,
        message,
    } = pdu.kind
    {
        pdu.kind = PduKind::Successful {
            procedure_code,
            criticality,
            message,
        };
    }
    assert!(ResourceNotify::from_pdu(&pdu, context()).is_err());
    let mut values = fields(row, "fields");
    values[0].1 = Criticality::notify;
    let ies: Vec<_> = values
        .iter()
        .map(|(id, c, v)| ProtocolIe::new(*id, *c, v))
        .collect();
    assert!(
        Pdu::from_protocol_ies(MessageType::PduSessionResourceNotify, &ies, context()).is_err()
    );
}

#[test]
fn full_message_truncations_and_bounded_mutations_never_panic() {
    for row in oracle()["cases"].as_array().unwrap() {
        let wire = bytes(row["wire_hex"].as_str().unwrap());
        let stride = (wire.len() / 16).max(1);
        for end in (0..wire.len()).step_by(stride).chain([wire.len() - 1]) {
            assert!(Pdu::decode_owned(Bytes::copy_from_slice(&wire[..end]), context()).is_err());
        }
        for index in (0..wire.len()).step_by(stride) {
            for mask in [1, 0x80, 0xff] {
                let mut changed = wire.clone();
                changed[index] ^= mask;
                if let Ok(pdu) = Pdu::decode_owned(Bytes::from(changed), context()) {
                    let _ = ResourceNotify::from_pdu(&pdu, context());
                }
            }
        }
    }
}
