//! Independent Release 18 root causes, identifier choices and release messages.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use opc_proto_ngap::n3iwf::release::{Cause, CauseClass, ReleaseMessage, UeIdentifiers};
use opc_proto_ngap::n3iwf::{AmfUeId, N3iwfLocation, RanUeId, TrackingArea};
use opc_proto_ngap::{decode, encode, Criticality, Message, MessageType, Pdu, PduKind, ProtocolIe};
use opc_protocol::{
    DecodeContext, DuplicateIePolicy, EncodeContext, UnknownIePolicy, ValidationLevel,
};
use opc_types::PlmnId;
use serde_json::Value;

fn context() -> DecodeContext {
    DecodeContext {
        validation_level: ValidationLevel::Strict,
        duplicate_ie_policy: DuplicateIePolicy::Reject,
        ..DecodeContext::default()
    }
}
fn oracle() -> Value {
    serde_json::from_str(include_str!("fixtures/n3iwf-release.json")).unwrap()
}
fn octets(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}
fn class(name: &str) -> CauseClass {
    match name {
        "radioNetwork" => CauseClass::RadioNetwork,
        "transport" => CauseClass::Transport,
        "nas" => CauseClass::Nas,
        "protocol" => CauseClass::Protocol,
        "misc" => CauseClass::Misc,
        _ => panic!("reference cause class"),
    }
}
fn identifiers(row: &Value) -> UeIdentifiers {
    let amf = AmfUeId::new(row["amf"].as_u64().unwrap_or(0x0102030405)).unwrap();
    if row.get("ran").is_some_and(Value::is_null) {
        UeIdentifiers::AmfOnly(amf)
    } else {
        UeIdentifiers::Pair {
            amf,
            ran: RanUeId::new(row["ran"].as_u64().unwrap_or(0x10203040) as u32),
        }
    }
}
fn construct(row: &Value) -> ReleaseMessage {
    match row["message"].as_str().unwrap() {
        "UEContextReleaseCommand" => ReleaseMessage::Command {
            identifiers: identifiers(row),
            cause: Cause::new(
                class(row["group"].as_str().unwrap_or("misc")),
                row["code"].as_u64().unwrap_or(5) as u8,
            )
            .unwrap(),
        },
        "UEContextReleaseComplete" => ReleaseMessage::Complete {
            diagnostics: None,
            amf: AmfUeId::new(0x0102030405).unwrap(),
            ran: RanUeId::new(0x10203040),
            location: (row["location"] != false).then(|| {
                N3iwfLocation::new(
                    "192.0.2.1".parse().unwrap(),
                    Some(4500),
                    Some(TrackingArea::new(
                        PlmnId::new("001", "01").unwrap(),
                        [0, 0, 1],
                    )),
                )
            }),
        },
        _ => panic!("reference message type"),
    }
}
fn same_fields(left: &ReleaseMessage, right: &ReleaseMessage) {
    match (left, right) {
        (
            ReleaseMessage::Command {
                identifiers: a,
                cause: x,
            },
            ReleaseMessage::Command {
                identifiers: b,
                cause: y,
            },
        ) => {
            assert!(a == b);
            assert!(x == y);
        }
        (
            ReleaseMessage::Complete {
                amf: a,
                ran: b,
                location: c,
                diagnostics: d,
            },
            ReleaseMessage::Complete {
                amf: x,
                ran: y,
                location: z,
                diagnostics: w,
            },
        ) => {
            assert!(a == x);
            assert!(b == y);
            assert!(c == z);
            assert!(d == w);
        }
        _ => panic!("release outcome differs"),
    }
}

#[test]
fn all_root_causes_and_identifier_boundaries_match_independent_fields() {
    let oracle = oracle();
    let mut count = 0;
    for row in oracle["fields"].as_array().unwrap() {
        count += 1;
        let wire = octets(row["wire_hex"].as_str().unwrap());
        if row["type"] == "Cause" {
            let expected = Cause::new(
                class(row["group"].as_str().unwrap()),
                row["code"].as_u64().unwrap() as u8,
            )
            .unwrap();
            assert!(
                expected
                    .encode(EncodeContext::default())
                    .unwrap()
                    .as_bytes()
                    == wire
            );
            let received = Cause::decode(&wire, context()).unwrap();
            assert!(received == expected);
            assert_eq!(received.class(), expected.class());
            assert!(received.code() == expected.code());
        } else {
            let expected = identifiers(row);
            assert!(
                expected
                    .encode(EncodeContext::default())
                    .unwrap()
                    .as_bytes()
                    == wire
            );
            assert!(UeIdentifiers::decode(&wire, context()).unwrap() == expected);
        }
    }
    assert_eq!(count, 94);
}

#[test]
fn complete_release_construction_and_receive_match_reference() {
    let oracle = oracle();
    let mut count = 0;
    for row in oracle["messages"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["construct"] == true)
    {
        count += 1;
        let wire = octets(row["wire_hex"].as_str().unwrap());
        let expected = construct(row);
        let constructed = expected.construct(context()).unwrap();
        assert!(constructed.raw.is_empty());
        assert!(encode(&constructed, EncodeContext::default()).unwrap() == wire);
        let received = decode(&wire, context()).unwrap();
        let admitted = ReleaseMessage::from_pdu(&received, context()).unwrap();
        same_fields(&expected, &admitted.message);
        assert_eq!(admitted.ignored_ie_count, 0);
        assert!(admitted.notify_ie_ids.is_empty());
    }
    assert_eq!(count, 97);
}

#[test]
fn independent_missing_fields_duplicates_and_unknown_criticality_obey_policy() {
    let oracle = oracle();
    let mut missing = 0;
    for row in oracle["messages"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["construct"] != true)
    {
        let wire = octets(row["wire_hex"].as_str().unwrap());
        if row.get("missing_id").is_some() {
            missing += 1;
            let pdu = decode(&wire, context()).unwrap();
            assert!(ReleaseMessage::from_pdu(&pdu, context()).is_err());
        } else if row["duplicate"] == true {
            assert!(decode(&wire, context()).is_err());
            for selection in [DuplicateIePolicy::First, DuplicateIePolicy::Last] {
                let ctx = DecodeContext {
                    duplicate_ie_policy: selection,
                    ..context()
                };
                let pdu = decode(&wire, ctx).unwrap();
                assert!(pdu.raw.as_ref() == wire);
                let admitted = ReleaseMessage::from_pdu(&pdu, ctx).unwrap();
                same_fields(&construct(row), &admitted.message);
            }
        } else if row["unknown_criticality"] == "reject" {
            assert!(decode(&wire, context()).is_err());
            let pdu = decode(
                &wire,
                DecodeContext {
                    validation_level: ValidationLevel::Structural,
                    ..context()
                },
            )
            .unwrap();
            assert!(ReleaseMessage::from_pdu(&pdu, context()).is_err());
        } else {
            let pdu = decode(&wire, context()).unwrap();
            let admitted = ReleaseMessage::from_pdu(&pdu, context()).unwrap();
            assert_eq!(
                admitted.ignored_ie_count,
                usize::from(row["unknown_criticality"] == "ignore")
            );
            assert_eq!(
                admitted.notify_ie_ids,
                if row["unknown_criticality"] == "notify" {
                    vec![65530]
                } else {
                    vec![]
                }
            );
            let dropped = decode(
                &wire,
                DecodeContext {
                    unknown_ie_policy: UnknownIePolicy::Drop,
                    ..context()
                },
            )
            .unwrap();
            assert!(dropped.raw.as_ref() == wire);
            let filtered = ReleaseMessage::from_pdu(&dropped, context()).unwrap();
            assert_eq!(filtered.ignored_ie_count, 0);
            assert!(filtered.notify_ie_ids.is_empty());
        }
    }
    assert_eq!(missing, 4);
}

fn with_extra(pdu: &Pdu, id: u16, criticality: Criticality, value: &[u8]) -> Pdu {
    let (kind, mut fields): (_, Vec<_>) = match &pdu.kind {
        PduKind::Initiating {
            message: Message::UeContextReleaseCommand(v),
            ..
        } => (
            MessageType::UeContextReleaseCommand,
            v.protocol_ies
                .0
                .iter()
                .map(|ie| {
                    ProtocolIe::new(ie.id.0, crit_of(ie.criticality as u8), ie.value.as_bytes())
                })
                .collect(),
        ),
        PduKind::Successful {
            message: Message::UeContextReleaseComplete(v),
            ..
        } => (
            MessageType::UeContextReleaseComplete,
            v.protocol_ies
                .0
                .iter()
                .map(|ie| {
                    ProtocolIe::new(ie.id.0, crit_of(ie.criticality as u8), ie.value.as_bytes())
                })
                .collect(),
        ),
        _ => panic!("release message"),
    };
    fields.push(ProtocolIe::new(id, criticality, value));
    Pdu::from_protocol_ies(kind, &fields, context()).unwrap()
}
fn crit_of(value: u8) -> Criticality {
    match value {
        0 => Criticality::reject,
        1 => Criticality::ignore,
        2 => Criticality::notify,
        _ => panic!("criticality"),
    }
}

#[test]
fn ignored_fields_and_unimplemented_applicable_fields_stay_distinct() {
    let message = construct(&serde_json::json!({"message":"UEContextReleaseComplete"}));
    let base = message.construct(context()).unwrap();
    for id in [32, 207] {
        let pdu = with_extra(&base, id, Criticality::ignore, &[0xff, 0xfe]);
        let admitted = ReleaseMessage::from_pdu(&pdu, context()).unwrap();
        assert_eq!(admitted.ignored_ie_count, 1);
        same_fields(&message, &admitted.message);
    }
    let pdu = with_extra(&base, 60, Criticality::reject, &[0]);
    assert!(ReleaseMessage::from_pdu(&pdu, context()).is_err());
}

#[test]
fn extensions_bounds_wrapper_mutation_and_redaction_are_enforced() {
    let message = construct(&serde_json::json!({"message":"UEContextReleaseCommand"}));
    let mut pdu = message.construct(context()).unwrap();
    let wire = encode(&pdu, EncodeContext::default()).unwrap();
    for ctx in [
        DecodeContext {
            max_message_len: wire.len() - 1,
            ..context()
        },
        DecodeContext {
            max_depth: 6,
            ..context()
        },
        DecodeContext {
            max_ies: 1,
            ..context()
        },
    ] {
        assert!(ReleaseMessage::from_pdu(&pdu, ctx).is_err());
        assert!(message.construct(ctx).is_err());
    }
    for class in [
        CauseClass::RadioNetwork,
        CauseClass::Nas,
        CauseClass::Transport,
        CauseClass::Protocol,
        CauseClass::Misc,
    ] {
        assert!(Cause::new(class, 255).is_err());
    }
    for wire in [&[0x10, 0][..], &[0xa0, 0, 0, 0, 0], &[0xff]] {
        assert!(Cause::decode(wire, context()).is_err());
    }
    for wire in [
        &[0x20, 0, 0][..],
        &[0x10, 0, 0],
        &[0x80, 0, 0, 0, 0],
        &[0xff],
    ] {
        assert!(UeIdentifiers::decode(wire, context()).is_err());
    }
    let text = format!("{:?}", ReleaseMessage::from_pdu(&pdu, context()).unwrap());
    for forbidden in ["270544960", "4328719365", "192.0.2.1", "4500"] {
        assert!(!text.contains(forbidden));
    }
    if let PduKind::Initiating { procedure_code, .. } = &mut pdu.kind {
        *procedure_code = 4;
    }
    assert!(ReleaseMessage::from_pdu(&pdu, context()).is_err());
}

fn exercise(data: &[u8]) {
    if let Ok(value) = Cause::decode(data, context()) {
        let wire = value.encode(EncodeContext::default()).unwrap();
        assert!(Cause::decode(wire.as_bytes(), context()).unwrap() == value);
    }
    if let Ok(value) = UeIdentifiers::decode(data, context()) {
        let wire = value.encode(EncodeContext::default()).unwrap();
        assert!(UeIdentifiers::decode(wire.as_bytes(), context()).unwrap() == value);
    }
    if let Ok(pdu) = decode(data, context()) {
        if let Ok(admitted) = ReleaseMessage::from_pdu(&pdu, context()) {
            let canonical = admitted.message.construct(context()).unwrap();
            let wire = encode(&canonical, EncodeContext::default()).unwrap();
            let pdu = decode(&wire, context()).unwrap();
            let readmitted = ReleaseMessage::from_pdu(&pdu, context()).unwrap();
            same_fields(&admitted.message, &readmitted.message);
        }
    }
}

#[test]
fn independent_field_and_message_truncations_and_mutations_never_panic() {
    let oracle = oracle();
    for row in oracle["fields"]
        .as_array()
        .unwrap()
        .iter()
        .chain(oracle["messages"].as_array().unwrap())
    {
        let wire = octets(row["wire_hex"].as_str().unwrap());
        for end in 0..=wire.len() {
            exercise(&wire[..end]);
        }
        for index in 0..wire.len() {
            for mask in [1, 0x80, 0xff] {
                let mut mutated = wire.clone();
                mutated[index] ^= mask;
                exercise(&mutated);
            }
        }
    }
}
