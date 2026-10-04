use bytes::Bytes;
use opc_proto_ngap::n3iwf::release::Cause;
use opc_proto_ngap::n3iwf::session_lists::SessionId;
use opc_proto_ngap::n3iwf::ue_requests::{
    ContextReleaseSessions, NasNonDelivery, UeReleaseRequest, UeRequestMessage,
};
use opc_proto_ngap::n3iwf::{AmfUeId, NasPdu, RanUeId};
use opc_proto_ngap::{encode, Criticality, Message, MessageType, Pdu, PduKind, ProtocolIe};
use opc_protocol::{
    DecodeContext, DuplicateIePolicy, EncodeContext, OwnedDecode, UnknownIePolicy, ValidationLevel,
};
use serde_json::Value;

fn oracle() -> Value {
    serde_json::from_str(include_str!("fixtures/n3iwf-ue-requests.json")).unwrap()
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
fn sessions(row: &Value) -> Result<ContextReleaseSessions, opc_protocol::DecodeError> {
    ContextReleaseSessions::new(
        row["model"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| SessionId::new(v.as_u64().unwrap() as u8))
            .collect(),
    )
}

#[test]
fn independent_session_values_all_lengths_and_exact_limits() {
    let reference = oracle();
    assert_eq!(reference["cases"].as_array().unwrap().len(), 257);
    for row in reference["cases"].as_array().unwrap() {
        let wire = bytes(row["wire_hex"].as_str().unwrap());
        if row["admitted"] == false {
            assert!(sessions(row).is_err());
            assert!(ContextReleaseSessions::decode(&wire, context()).is_err());
            continue;
        }
        let expected = sessions(row).unwrap();
        let ctx = DecodeContext {
            max_depth: 3,
            max_message_len: wire.len(),
            max_ies: expected.values().len(),
            ..context()
        };
        let out = EncodeContext {
            max_message_len: wire.len(),
            ..output()
        };
        assert!(ContextReleaseSessions::decode(&wire, ctx).unwrap() == expected);
        assert!(expected.encode(out).unwrap().as_bytes() == wire);
        assert!(expected
            .encode(EncodeContext {
                max_message_len: wire.len() - 1,
                ..out
            })
            .is_err());
        for short in [
            DecodeContext {
                max_depth: 2,
                ..ctx
            },
            DecodeContext {
                max_message_len: wire.len() - 1,
                ..ctx
            },
            DecodeContext {
                max_ies: ctx.max_ies - 1,
                ..ctx
            },
        ] {
            assert!(ContextReleaseSessions::decode(&wire, short).is_err());
        }
        assert!(format!("{expected:?}").contains("REDACTED"));
    }
    assert!(ContextReleaseSessions::new(vec![]).is_err());
    assert!(ContextReleaseSessions::new(vec![SessionId::new(0); 257]).is_err());
}

#[test]
fn session_preflight_rejects_flags_padding_duplicates_and_truncation() {
    let reference = oracle();
    for row in reference["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["admitted"] == true)
    {
        let wire = bytes(row["wire_hex"].as_str().unwrap());
        // Every item's extension/optional flags and every alignment padding bit.
        for index in (1..wire.len()).step_by(2) {
            for bit in 0..8 {
                let mut changed = wire.clone();
                changed[index] |= 1 << bit;
                assert!(ContextReleaseSessions::decode(&changed, context()).is_err());
            }
        }
        if wire[0] > 0 {
            let mut changed = wire.clone();
            changed[4] = changed[2];
            assert!(ContextReleaseSessions::decode(&changed, context()).is_err());
        }
        let stride = (wire.len() / 32).max(1);
        for end in (0..wire.len()).step_by(stride).chain([wire.len() - 1]) {
            assert!(ContextReleaseSessions::decode(&wire[..end], context()).is_err());
        }
        let mut trailing = wire.clone();
        trailing.push(0);
        assert!(ContextReleaseSessions::decode(&trailing, context()).is_err());
        for count in [0, 255] {
            if count == wire[0] {
                continue;
            }
            let mut changed = wire.clone();
            changed[0] = count;
            assert!(ContextReleaseSessions::decode(&changed, context()).is_err());
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
    if row["kind"] == "NASNonDeliveryIndication" {
        MessageType::NasNonDeliveryIndication
    } else {
        MessageType::UeContextReleaseRequest
    }
}
fn construct_row(row: &Value, ctx: DecodeContext) -> Result<Pdu, opc_protocol::DecodeError> {
    let values = fields(row, "canonical_fields");
    let get = |id| values.iter().find(|v| v.0 == id).map(|v| v.2.as_slice());
    let amf = AmfUeId::decode(get(10).unwrap(), context())?;
    let ran = RanUeId::decode(get(85).unwrap(), context())?;
    let cause = Cause::decode(get(15).unwrap(), context())?;
    let message = if kind(row) == MessageType::NasNonDeliveryIndication {
        UeRequestMessage::NasNonDelivery(NasNonDelivery {
            amf,
            ran,
            cause,
            nas: NasPdu::decode(get(38).unwrap(), context())?,
        })
    } else {
        UeRequestMessage::ContextRelease(UeReleaseRequest {
            amf,
            ran,
            cause,
            sessions: get(133)
                .map(|v| ContextReleaseSessions::decode(v, context()))
                .transpose()?,
        })
    };
    message.construct(ctx)
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
fn complete_messages_match_reference_presence_cause_padding_and_limits() {
    let reference = oracle();
    let mut count = 0;
    for row in reference["messages"].as_array().unwrap() {
        let name = row["name"].as_str().unwrap();
        let pdu = read(row, context());
        if row["admitted"] == false {
            if let Ok(pdu) = pdu {
                assert!(
                    UeRequestMessage::from_pdu(&pdu, context()).is_err(),
                    "{name}"
                );
            }
            continue;
        }
        let pdu = pdu.unwrap();
        let admitted = UeRequestMessage::from_pdu(&pdu, context()).unwrap();
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
        let depth = if fields(row, "canonical_fields").iter().any(|v| v.0 == 133) {
            7
        } else {
            6
        };
        let ctx = DecodeContext {
            max_depth: depth,
            max_message_len: expected.len(),
            ..context()
        };
        let constructed = construct_row(row, ctx).unwrap();
        assert!(UeRequestMessage::from_pdu(&constructed, ctx).is_ok());
        for short in [
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
            assert!(construct_row(row, short).is_err(), "{name}");
            assert!(
                UeRequestMessage::from_pdu(&constructed, short).is_err(),
                "{name}"
            );
        }
        count += 1;
    }
    assert_eq!(count, 144);
    assert_eq!(reference["messages"].as_array().unwrap().len(), 291);
}

fn amf(message: &UeRequestMessage<'_>) -> u64 {
    match message {
        UeRequestMessage::NasNonDelivery(v) => v.amf.value(),
        UeRequestMessage::ContextRelease(v) => v.amf.value(),
    }
}

#[test]
fn generic_policies_and_mutable_metadata_remain_authoritative() {
    let reference = oracle();
    for row in reference["messages"].as_array().unwrap() {
        if row["mode"] == "duplicate" {
            for (policy, expected) in [
                (DuplicateIePolicy::First, 7),
                (DuplicateIePolicy::Last, 0x8123456789),
            ] {
                let ctx = DecodeContext {
                    duplicate_ie_policy: policy,
                    ..context()
                };
                let pdu = read(row, ctx).unwrap();
                assert_eq!(
                    amf(&UeRequestMessage::from_pdu(&pdu, ctx).unwrap().message),
                    expected
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
                assert!(UeRequestMessage::from_pdu(&pdu, ctx).is_ok());
            } else {
                let pdu = read(row, ctx).unwrap();
                let admitted = UeRequestMessage::from_pdu(&pdu, ctx).unwrap();
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
            values[0].1 = Criticality::notify;
            assert!(pdu_fields(row, &values, context()).is_err());
            let mut pdu = read(row, context()).unwrap();
            let PduKind::Initiating { procedure_code, .. } = &mut pdu.kind else {
                panic!()
            };
            *procedure_code = 255;
            assert!(UeRequestMessage::from_pdu(&pdu, context()).is_err());
            let mut pdu = read(row, context()).unwrap();
            let PduKind::Initiating { criticality, .. } = &mut pdu.kind else {
                panic!()
            };
            *criticality = Criticality::reject;
            assert!(UeRequestMessage::from_pdu(&pdu, context()).is_err());
            let mut pdu = read(row, context()).unwrap();
            let PduKind::Initiating {
                procedure_code,
                criticality,
                message,
            } = pdu.kind
            else {
                panic!()
            };
            pdu.kind = PduKind::Successful {
                procedure_code,
                criticality,
                message,
            };
            assert!(UeRequestMessage::from_pdu(&pdu, context()).is_err());
        }
    }
}

#[test]
fn nas_borrows_contiguous_values_and_preserves_distinct_fragment_payloads() {
    let reference = oracle();
    for row in reference["messages"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["name"].as_str().unwrap().starts_with("nas-length-"))
    {
        let pdu = read(row, context()).unwrap();
        let admitted = UeRequestMessage::from_pdu(&pdu, context()).unwrap();
        let UeRequestMessage::NasNonDelivery(value) = admitted.message else {
            panic!()
        };
        let length: usize = row["name"]
            .as_str()
            .unwrap()
            .trim_start_matches("nas-length-")
            .parse()
            .unwrap();
        assert_eq!(value.nas.as_bytes().len(), length);
        // Reproduce the independent synthetic payload, including distinct
        // contents at each fragment boundary, without using the SDK encoder.
        use sha2::{Digest, Sha256};
        let expected: Vec<_> = (0..length.div_ceil(32))
            .flat_map(|i| Sha256::digest(format!("non-delivery-nas-{i}")))
            .take(length)
            .collect();
        assert!(value.nas.as_bytes() == expected);
        if length < 16384 {
            let PduKind::Initiating {
                message: Message::NasNonDeliveryIndication(raw),
                ..
            } = &pdu.kind
            else {
                panic!()
            };
            let field = raw
                .protocol_ies
                .0
                .iter()
                .find(|v| v.id == 38)
                .unwrap()
                .value
                .as_bytes();
            assert_eq!(
                value.nas.as_bytes().as_ptr(),
                field[field.len() - length..].as_ptr()
            );
        }
    }
}

#[test]
fn complete_message_truncations_and_bounded_mutations_never_panic() {
    let reference = oracle();
    for row in reference["messages"].as_array().unwrap() {
        let wire = bytes(row["wire_hex"].as_str().unwrap());
        let stride = (wire.len() / 64).max(1);
        for end in (0..wire.len()).step_by(stride).chain([wire.len() - 1]) {
            assert!(Pdu::decode_owned(Bytes::copy_from_slice(&wire[..end]), context()).is_err());
        }
        for index in (0..wire.len()).step_by(stride) {
            for mask in [1, 0x80, 0xff] {
                let mut changed = wire.clone();
                changed[index] ^= mask;
                if let Ok(pdu) = Pdu::decode_owned(Bytes::from(changed), context()) {
                    let _ = UeRequestMessage::from_pdu(&pdu, context());
                }
            }
        }
    }
}
