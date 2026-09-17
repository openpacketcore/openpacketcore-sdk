use bytes::Bytes;
use opc_proto_ngap::n3iwf::release::{Cause, CauseClass};
use opc_proto_ngap::n3iwf::resource_release::{
    ReleaseCommandTransfer, ReleaseResponseTransfer, ReleasedSessions, RequestedSessionRelease,
    ResourceReleaseMessage, SessionReleaseCommand, SessionReleaseRequests, SessionReleaseResponse,
};
use opc_proto_ngap::n3iwf::session_lists::SessionId;
use opc_proto_ngap::n3iwf::{AmfUeId, N3iwfLocation, NasPdu, RanUeId};
use opc_proto_ngap::{encode, Criticality, MessageType, Pdu, PduKind, ProtocolIe};
use opc_protocol::{
    DecodeContext, DuplicateIePolicy, EncodeContext, OwnedDecode, UnknownIePolicy, ValidationLevel,
};
use serde_json::Value;

fn oracle() -> Value {
    serde_json::from_str(include_str!("fixtures/n3iwf-resource-release.json")).unwrap()
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
fn bytes(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).unwrap())
        .collect()
}
fn cause(model: &Value) -> Cause {
    let class = match model["class"].as_str().unwrap() {
        "radioNetwork" => CauseClass::RadioNetwork,
        "transport" => CauseClass::Transport,
        "nas" => CauseClass::Nas,
        "protocol" => CauseClass::Protocol,
        "misc" => CauseClass::Misc,
        _ => unreachable!(),
    };
    Cause::new(class, model["code"].as_u64().unwrap() as u8).unwrap()
}
fn requested(model: &Value) -> Result<SessionReleaseRequests, opc_protocol::DecodeError> {
    SessionReleaseRequests::new(
        model
            .as_array()
            .unwrap()
            .iter()
            .map(|v| RequestedSessionRelease {
                id: SessionId::new(v["id"].as_u64().unwrap() as u8),
                transfer: ReleaseCommandTransfer {
                    cause: cause(&v["cause"]),
                },
            })
            .collect(),
    )
}
fn released(model: &Value) -> Result<ReleasedSessions, opc_protocol::DecodeError> {
    ReleasedSessions::new(
        model
            .as_array()
            .unwrap()
            .iter()
            .map(|v| SessionId::new(v["id"].as_u64().unwrap() as u8))
            .collect(),
    )
}

#[test]
fn independent_transfers_and_all_list_lengths_match_values_and_construction() {
    let reference = oracle();
    let mut admitted = 0;
    for row in reference["cases"].as_array().unwrap() {
        let wire = bytes(row["wire_hex"].as_str().unwrap());
        let model = &row["model"];
        let name = row["name"].as_str().unwrap();
        if row["admitted"] == false {
            if row["type"] == "PDUSessionResourceToReleaseListRelCmd" {
                assert!(requested(model).is_err());
                assert!(SessionReleaseRequests::decode(&wire, context()).is_err());
            } else {
                assert!(released(model).is_err());
                assert!(ReleasedSessions::decode(&wire, context()).is_err());
            }
            continue;
        }
        macro_rules! check {
            ($type:ty, $expected:expr, $depth:expr) => {{
                let expected = $expected;
                let ctx = DecodeContext {
                    max_depth: $depth,
                    max_message_len: wire.len(),
                    ..context()
                };
                let out = EncodeContext {
                    max_message_len: wire.len(),
                    ..output()
                };
                assert!(<$type>::decode(&wire, ctx).unwrap() == expected, "{name}");
                assert!(expected.encode(out).unwrap().as_bytes() == wire, "{name}");
                assert!(expected
                    .encode(EncodeContext {
                        max_message_len: wire.len() - 1,
                        ..out
                    })
                    .is_err());
                assert!(<$type>::decode(
                    &wire,
                    DecodeContext {
                        max_depth: $depth - 1,
                        ..ctx
                    }
                )
                .is_err());
                assert!(<$type>::decode(
                    &wire,
                    DecodeContext {
                        max_message_len: wire.len() - 1,
                        ..ctx
                    }
                )
                .is_err());
                assert!(format!("{expected:?}").contains("REDACTED"));
            }};
        }
        match row["type"].as_str().unwrap() {
            "PDUSessionResourceReleaseCommandTransfer" => check!(
                ReleaseCommandTransfer,
                ReleaseCommandTransfer {
                    cause: cause(model)
                },
                3
            ),
            "PDUSessionResourceReleaseResponseTransfer" => {
                check!(ReleaseResponseTransfer, ReleaseResponseTransfer, 1)
            }
            "PDUSessionResourceToReleaseListRelCmd" => {
                check!(SessionReleaseRequests, requested(model).unwrap(), 6)
            }
            "PDUSessionResourceReleasedListRelRes" => {
                check!(ReleasedSessions, released(model).unwrap(), 4)
            }
            _ => unreachable!(),
        }
        admitted += 1;
    }
    assert_eq!(admitted, 577);
    assert_eq!(reference["cases"].as_array().unwrap().len(), 579);
}

fn leaf_rejected(kind: &str, wire: &[u8], ctx: DecodeContext) -> bool {
    match kind {
        "PDUSessionResourceReleaseCommandTransfer" => {
            ReleaseCommandTransfer::decode(wire, ctx).is_err()
        }
        "PDUSessionResourceReleaseResponseTransfer" => {
            ReleaseResponseTransfer::decode(wire, ctx).is_err()
        }
        "PDUSessionResourceToReleaseListRelCmd" => {
            SessionReleaseRequests::decode(wire, ctx).is_err()
        }
        "PDUSessionResourceReleasedListRelRes" => ReleasedSessions::decode(wire, ctx).is_err(),
        _ => unreachable!(),
    }
}

#[test]
fn list_capacity_and_nested_flags_lengths_and_padding_are_rejected() {
    assert!(SessionReleaseRequests::new(vec![]).is_err());
    assert!(ReleasedSessions::new(vec![]).is_err());
    assert!(ReleasedSessions::new(vec![SessionId::new(0); 257]).is_err());
    let reference = oracle();
    for row in reference["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["admitted"] == true)
    {
        let wire = bytes(row["wire_hex"].as_str().unwrap());
        let kind = row["type"].as_str().unwrap();
        if kind.ends_with("Transfer") {
            for mask in [0x80, 0x40] {
                let mut changed = wire.clone();
                changed[0] |= mask;
                assert!(leaf_rejected(kind, &changed, context()));
            }
            // For every root Cause, determine padding from the reference
            // class width and corrupt each final unused bit independently.
            let used = if kind.contains("Command") {
                6 + match row["model"]["class"].as_str().unwrap() {
                    "radioNetwork" => 6,
                    "transport" => 1,
                    "nas" => 2,
                    _ => 3,
                }
            } else {
                2
            };
            for bit in 0..wire.len() * 8 - used {
                let mut changed = wire.clone();
                *changed.last_mut().unwrap() |= 1 << bit;
                assert!(leaf_rejected(kind, &changed, context()));
            }
        } else {
            let count = row["model"].as_array().unwrap().len();
            assert!(leaf_rejected(
                kind,
                &wire,
                DecodeContext {
                    max_ies: count - 1,
                    ..context()
                }
            ));
            for (index, mask) in [(1, 0x80), (1, 0x40), (1, 1), (4, 0x80), (4, 0x40)] {
                let mut changed = wire.clone();
                changed[index] |= mask;
                assert!(leaf_rejected(kind, &changed, context()));
            }
            for length in [0, 3, 0xc1] {
                let mut changed = wire.clone();
                changed[3] = length;
                assert!(leaf_rejected(kind, &changed, context()));
            }
        }
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
fn kind(row: &Value) -> MessageType {
    if row["kind"] == "PDUSessionResourceReleaseCommand" {
        MessageType::PduSessionResourceReleaseCommand
    } else {
        MessageType::PduSessionResourceReleaseResponse
    }
}
fn construct_row(row: &Value, ctx: DecodeContext) -> Result<Pdu, opc_protocol::DecodeError> {
    let values = fields(row, "canonical_fields");
    let get = |id| values.iter().find(|v| v.0 == id).map(|v| v.2.as_slice());
    let amf = AmfUeId::decode(get(10).unwrap(), context())?;
    let ran = RanUeId::decode(get(85).unwrap(), context())?;
    let value = if kind(row) == MessageType::PduSessionResourceReleaseCommand {
        ResourceReleaseMessage::Command(SessionReleaseCommand {
            amf,
            ran,
            sessions: SessionReleaseRequests::decode(get(79).unwrap(), context())?,
            nas: get(38).map(|v| NasPdu::decode(v, context())).transpose()?,
        })
    } else {
        ResourceReleaseMessage::Response(SessionReleaseResponse {
            amf,
            ran,
            sessions: ReleasedSessions::decode(get(70).unwrap(), context())?,
            location: get(121)
                .map(|v| N3iwfLocation::decode(v, context()))
                .transpose()?,
        })
    };
    value.construct(ctx)
}
fn read(row: &Value, ctx: DecodeContext) -> Result<Pdu, opc_protocol::DecodeError> {
    Pdu::decode_owned(Bytes::from(bytes(row["wire_hex"].as_str().unwrap())), ctx)
}
fn pdu_fields(
    row: &Value,
    values: &[(u16, Criticality, Vec<u8>)],
    ctx: DecodeContext,
) -> Result<Pdu, opc_protocol::DecodeError> {
    let ies: Vec<_> = values
        .iter()
        .map(|(id, crit, value)| ProtocolIe::new(*id, *crit, value))
        .collect();
    Pdu::from_protocol_ies(kind(row), &ies, ctx)
}

#[test]
fn complete_messages_match_independent_construction_and_presence_rules() {
    let reference = oracle();
    let mut count = 0;
    for row in reference["messages"].as_array().unwrap() {
        let name = row["name"].as_str().unwrap();
        let pdu = read(row, context());
        if row["admitted"] == false {
            if let Ok(pdu) = pdu {
                assert!(
                    ResourceReleaseMessage::from_pdu(&pdu, context()).is_err(),
                    "{name}"
                );
            }
            continue;
        }
        let pdu = pdu.unwrap();
        let admitted = ResourceReleaseMessage::from_pdu(&pdu, context()).unwrap();
        let expected = bytes(row["canonical_wire_hex"].as_str().unwrap());
        assert!(
            encode(&construct_row(row, context()).unwrap(), output()).unwrap() == expected,
            "{name}"
        );
        assert!(
            encode(&admitted.message.construct(context()).unwrap(), output()).unwrap() == expected,
            "{name}"
        );
        assert_eq!(
            admitted.ignored_ie_count,
            usize::from(row["criticality"] == "ignore" || row["mode"] == "ignored")
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
        let depth = if kind(row) == MessageType::PduSessionResourceReleaseCommand {
            10
        } else {
            8
        };
        let ctx = DecodeContext {
            max_depth: depth,
            max_message_len: expected.len(),
            ..context()
        };
        let constructed = construct_row(row, ctx).unwrap();
        assert!(ResourceReleaseMessage::from_pdu(&constructed, ctx).is_ok());
        for ctx in [
            DecodeContext {
                max_depth: depth - 1,
                ..ctx
            },
            DecodeContext {
                max_message_len: expected.len() - 1,
                ..ctx
            },
            DecodeContext { max_ies: 2, ..ctx },
        ] {
            assert!(construct_row(row, ctx).is_err(), "{name}");
            assert!(
                ResourceReleaseMessage::from_pdu(&constructed, ctx).is_err(),
                "{name}"
            );
        }
        count += 1;
    }
    assert_eq!(count, 15);
    assert_eq!(reference["messages"].as_array().unwrap().len(), 28);
}

fn amf(message: &ResourceReleaseMessage<'_>) -> u64 {
    match message {
        ResourceReleaseMessage::Command(v) => v.amf.value(),
        ResourceReleaseMessage::Response(v) => v.amf.value(),
    }
}

#[test]
fn shared_policies_and_mutated_message_boundaries_remain_authoritative() {
    let reference = oracle();
    for row in reference["messages"].as_array().unwrap() {
        if row["mode"] == "duplicate" {
            let values = fields(row, "fields");
            let expected = AmfUeId::decode(
                &values.iter().rev().find(|v| v.0 == 10).unwrap().2,
                context(),
            )
            .unwrap()
            .value();
            for (policy, want) in [
                (DuplicateIePolicy::First, 7),
                (DuplicateIePolicy::Last, expected),
            ] {
                let ctx = DecodeContext {
                    duplicate_ie_policy: policy,
                    ..context()
                };
                let pdu = read(row, ctx).unwrap();
                assert_eq!(
                    amf(&ResourceReleaseMessage::from_pdu(&pdu, ctx).unwrap().message),
                    want
                );
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
                assert!(ResourceReleaseMessage::from_pdu(&pdu, ctx).is_ok());
            } else {
                let pdu = read(row, ctx).unwrap();
                let admitted = ResourceReleaseMessage::from_pdu(&pdu, ctx).unwrap();
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
            let mut values = fields(row, "fields");
            let list = values.iter_mut().find(|v| v.0 == 79 || v.0 == 70).unwrap();
            list.2[4] |= 0x80;
            let pdu = pdu_fields(row, &values, context()).unwrap();
            assert!(ResourceReleaseMessage::from_pdu(&pdu, context()).is_err());
            let mut values = fields(row, "fields");
            values[0].1 = Criticality::notify;
            assert!(pdu_fields(row, &values, context()).is_err());
            let mut pdu = read(row, context()).unwrap();
            match &mut pdu.kind {
                PduKind::Initiating { procedure_code, .. }
                | PduKind::Successful { procedure_code, .. }
                | PduKind::Unsuccessful { procedure_code, .. } => *procedure_code = 255,
            };
            assert!(ResourceReleaseMessage::from_pdu(&pdu, context()).is_err());
        }
    }
}

#[test]
fn truncations_and_bounded_mutations_never_panic() {
    let reference = oracle();
    for row in reference["cases"].as_array().unwrap() {
        let wire = bytes(row["wire_hex"].as_str().unwrap());
        let kind = row["type"].as_str().unwrap();
        let stride = (wire.len() / 64).max(1);
        for end in (0..wire.len()).step_by(stride).chain([wire.len() - 1]) {
            assert!(leaf_rejected(kind, &wire[..end], context()));
        }
        let mut trailing = wire.clone();
        trailing.push(0);
        assert!(leaf_rejected(kind, &trailing, context()));
        for index in (0..wire.len()).step_by(stride) {
            for mask in [1, 0x80, 0xff] {
                let mut changed = wire.clone();
                changed[index] ^= mask;
                let _ = leaf_rejected(kind, &changed, context());
            }
        }
    }
    for row in reference["messages"].as_array().unwrap() {
        let wire = bytes(row["wire_hex"].as_str().unwrap());
        let stride = (wire.len() / 128).max(1);
        for end in (0..wire.len()).step_by(stride).chain([wire.len() - 1]) {
            assert!(Pdu::decode_owned(Bytes::copy_from_slice(&wire[..end]), context()).is_err());
        }
        for index in (0..wire.len()).step_by(stride) {
            for mask in [1, 0x80, 0xff] {
                let mut changed = wire.clone();
                changed[index] ^= mask;
                if let Ok(pdu) = Pdu::decode_owned(Bytes::from(changed), context()) {
                    let _ = ResourceReleaseMessage::from_pdu(&pdu, context());
                }
            }
        }
    }
}
