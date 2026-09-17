#![allow(clippy::unwrap_used)]
use opc_proto_ngap::n3iwf::setup_fields::*;
use opc_protocol::{DecodeContext, EncodeContext};
use opc_types::{PlmnId, Snssai};
use serde_json::Value;

fn oracle() -> Value {
    serde_json::from_str(include_str!("fixtures/n3iwf-setup.json")).unwrap()
}
fn octets(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|part| u8::from_str_radix(std::str::from_utf8(part).unwrap(), 16).unwrap())
        .collect()
}
fn context() -> DecodeContext {
    DecodeContext {
        max_ies: 20_000,
        validation_level: opc_protocol::ValidationLevel::Strict,
        max_message_len: 131_072,
        ..DecodeContext::default()
    }
}
fn plmn(value: &Value) -> PlmnId {
    value.as_str().unwrap().parse().unwrap()
}
fn plmns(model: &Value) -> Vec<PlmnSlices> {
    model
        .as_array()
        .unwrap()
        .iter()
        .map(|row| {
            PlmnSlices::new(
                plmn(&row["plmn"]),
                row["slices"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|s| match s["sd"].as_str() {
                        Some(sd) => Snssai::with_sd(s["sst"].as_u64().unwrap() as u8, sd).unwrap(),
                        None => Snssai::without_sd(s["sst"].as_u64().unwrap() as u8),
                    })
                    .collect(),
            )
            .unwrap()
        })
        .collect()
}
fn global(model: &Value) -> GlobalN3iwfId {
    GlobalN3iwfId::new(plmn(&model["plmn"]), model["id"].as_u64().unwrap() as u16)
}
fn guamis(model: &Value) -> ServedGuamiList {
    ServedGuamiList::new(
        model
            .as_array()
            .unwrap()
            .iter()
            .map(|r| {
                Guami::new(
                    plmn(&r["plmn"]),
                    r["region"].as_u64().unwrap() as u8,
                    r["set"].as_u64().unwrap() as u16,
                    r["pointer"].as_u64().unwrap() as u8,
                )
                .unwrap()
            })
            .collect(),
    )
    .unwrap()
}
fn tas(model: &Value) -> SupportedTaList {
    SupportedTaList::new(
        model
            .as_array()
            .unwrap()
            .iter()
            .map(|r| {
                SupportedTa::new(
                    octets(r["tac"].as_str().unwrap()).try_into().unwrap(),
                    plmns(&r["plmns"]),
                )
                .unwrap()
            })
            .collect(),
    )
    .unwrap()
}

#[test]
fn nested_fields_match_independent_values_and_generated_output() {
    let reference = oracle();
    let mut checked = 0;
    for row in reference["fields"].as_array().unwrap() {
        let wire = octets(row["wire_hex"].as_str().unwrap());
        let model = &row["model"];
        let name = row["name"].as_str().unwrap();
        macro_rules! check {
            ($ty:ty, $expected:expr) => {{
                let expected = $expected;
                let output = expected
                    .encode(EncodeContext::default())
                    .unwrap_or_else(|e| panic!("{name}: encode {e:?}"));
                assert!(
                    output.as_bytes() == wire,
                    "{name}: independent wire differs"
                );
                let received = <$ty>::decode(&wire, context())
                    .unwrap_or_else(|e| panic!("{name}: decode {e:?}"));
                assert!(received == expected, "{name}: independent value differs");
                assert!(expected
                    .encode(EncodeContext {
                        max_message_len: wire.len() - 1,
                        ..EncodeContext::default()
                    })
                    .is_err());
                assert!(expected
                    .encode(EncodeContext {
                        max_message_len: wire.len(),
                        ..EncodeContext::default()
                    })
                    .is_ok());
                assert!(<$ty>::decode(
                    &wire,
                    DecodeContext {
                        max_message_len: wire.len() - 1,
                        ..context()
                    }
                )
                .is_err());
                let mut trailing = wire.clone();
                trailing.push(0);
                assert!(<$ty>::decode(&trailing, context()).is_err());
                checked += 1;
            }};
        }
        match row["type"].as_str().unwrap() {
            "GlobalRANNodeID" => check!(GlobalN3iwfId, global(model)),
            "ServedGUAMIList" => check!(ServedGuamiList, guamis(model)),
            "PLMNSupportList" => {
                check!(PlmnSupportList, PlmnSupportList::new(plmns(model)).unwrap())
            }
            "SupportedTAList" => check!(SupportedTaList, tas(model)),
            "AMFName" => check!(AmfName, AmfName::new(model.as_str().unwrap()).unwrap()),
            _ => (),
        }
    }
    assert_eq!(checked, 47);
}

use opc_proto_ngap::n3iwf::{
    release::{Cause, CauseClass},
    setup::*,
};
use opc_proto_ngap::{decode, encode, Criticality, Message, MessageType, Pdu, PduKind, ProtocolIe};
use opc_protocol::{DuplicateIePolicy, UnknownIePolicy};

fn paging(value: &str) -> PagingDrx {
    match value {
        "v32" => PagingDrx::v32,
        "v64" => PagingDrx::v64,
        "v128" => PagingDrx::v128,
        "v256" => PagingDrx::v256,
        _ => panic!("reference paging"),
    }
}
fn wait(value: &str) -> TimeToWait {
    match value {
        "v1s" => TimeToWait::v1s,
        "v2s" => TimeToWait::v2s,
        "v5s" => TimeToWait::v5s,
        "v10s" => TimeToWait::v10s,
        "v20s" => TimeToWait::v20s,
        "v60s" => TimeToWait::v60s,
        _ => panic!("reference wait"),
    }
}
fn base_request() -> NgSetupRequest {
    NgSetupRequest {
        global: GlobalN3iwfId::new("001-01".parse().unwrap(), 1),
        tracking_areas: SupportedTaList::new(vec![SupportedTa::new(
            [0, 0, 1],
            vec![PlmnSlices::new("001-01".parse().unwrap(), vec![Snssai::without_sd(1)]).unwrap()],
        )
        .unwrap()])
        .unwrap(),
    }
}
fn base_response() -> NgSetupResponse {
    NgSetupResponse {
        name: AmfName::new("synthetic-amf.example").unwrap(),
        served: ServedGuamiList::new(vec![Guami::new("001-01".parse().unwrap(), 1, 1, 1).unwrap()])
            .unwrap(),
        relative_capacity: 128,
        plmns: PlmnSupportList::new(vec![PlmnSlices::new(
            "001-01".parse().unwrap(),
            vec![Snssai::without_sd(1)],
        )
        .unwrap()])
        .unwrap(),
    }
}
fn expected(row: &Value, oracle: &Value) -> (SetupMessage, PagingDrx) {
    let mut message = match row["message"].as_str().unwrap() {
        "NGSetupRequest" => SetupMessage::Request(base_request()),
        "NGSetupResponse" => SetupMessage::Response(base_response()),
        "NGSetupFailure" => SetupMessage::Failure(NgSetupFailure {
            cause: Cause::new(CauseClass::Misc, 5).unwrap(),
            time_to_wait: if row["no_wait"] == true {
                None
            } else {
                Some(TimeToWait::v10s)
            },
        }),
        _ => panic!("reference message"),
    };
    let mut drx = PagingDrx::v128;
    if let Some(index) = row["field_index"].as_u64() {
        let field = &oracle["fields"][index as usize];
        let model = &field["model"];
        match (&mut message, field["type"].as_str().unwrap()) {
            (SetupMessage::Request(r), "GlobalRANNodeID") => r.global = global(model),
            (SetupMessage::Request(r), "SupportedTAList") => r.tracking_areas = tas(model),
            (SetupMessage::Request(_), "PagingDRX") => drx = paging(model.as_str().unwrap()),
            (SetupMessage::Response(r), "AMFName") => {
                r.name = AmfName::new(model.as_str().unwrap()).unwrap()
            }
            (SetupMessage::Response(r), "ServedGUAMIList") => r.served = guamis(model),
            (SetupMessage::Response(r), "PLMNSupportList") => {
                r.plmns = PlmnSupportList::new(plmns(model)).unwrap()
            }
            (SetupMessage::Response(r), "RelativeAMFCapacity") => {
                r.relative_capacity = model.as_u64().unwrap() as u8
            }
            (SetupMessage::Failure(r), "TimeToWait") => {
                r.time_to_wait = Some(wait(model.as_str().unwrap()))
            }
            _ => panic!("reference field"),
        }
    }
    (message, drx)
}
fn construct(
    message: &SetupMessage,
    drx: PagingDrx,
    ctx: DecodeContext,
) -> Result<Pdu, opc_protocol::DecodeError> {
    match message {
        SetupMessage::Request(r) => r.construct(drx, ctx),
        SetupMessage::Response(r) => r.construct(ctx),
        SetupMessage::Failure(r) => r.construct(ctx),
    }
}
fn ignores(message: &SetupMessage) -> usize {
    usize::from(matches!(message, SetupMessage::Request(_)))
}

#[test]
fn complete_setup_construction_and_receive_match_independent_messages() {
    let reference = oracle();
    let mut count = 0;
    for row in reference["messages"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["construct"] == true)
    {
        let wire = octets(row["wire_hex"].as_str().unwrap());
        let (expected, drx) = expected(row, &reference);
        let name = row["name"].as_str().unwrap();
        let pdu = construct(&expected, drx, context()).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert!(pdu.raw.is_empty());
        assert!(
            encode(&pdu, EncodeContext::default()).unwrap() == wire,
            "{name}: independent message differs"
        );
        let received = decode(&wire, context()).unwrap();
        let admitted = SetupMessage::from_pdu(&received, context())
            .unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert!(
            admitted.message == expected,
            "{name}: independent fields differ"
        );
        assert_eq!(admitted.ignored_ie_count, ignores(&expected));
        assert!(admitted.notify_ie_ids.is_empty());
        if let Some(index) = row["field_index"].as_u64() {
            let field = &reference["fields"][index as usize];
            let field_wire = octets(field["wire_hex"].as_str().unwrap());
            let id = match field["type"].as_str().unwrap() {
                "GlobalRANNodeID" => 27,
                "SupportedTAList" => 102,
                "PagingDRX" => 21,
                "AMFName" => 1,
                "ServedGUAMIList" => 96,
                "PLMNSupportList" => 80,
                "RelativeAMFCapacity" => 86,
                "TimeToWait" => 107,
                _ => panic!("reference field"),
            };
            assert!(
                owned_fields(&pdu)
                    .iter()
                    .find(|(i, _, _)| *i == id)
                    .unwrap()
                    .2
                    == field_wire
            );
        }
        count += 1;
    }
    assert_eq!(count, 67);
}

#[test]
fn independent_missing_fields_duplicates_and_unknown_policies() {
    let reference = oracle();
    let mut counts = [0; 3];
    for row in reference["messages"].as_array().unwrap() {
        let wire = octets(row["wire_hex"].as_str().unwrap());
        if row.get("missing_id").is_some() {
            let pdu = decode(&wire, context()).unwrap();
            assert!(
                SetupMessage::from_pdu(&pdu, context()).is_err(),
                "{}",
                row["name"]
            );
            counts[0] += 1;
        } else if row["duplicate"] == true {
            assert!(decode(
                &wire,
                DecodeContext {
                    duplicate_ie_policy: DuplicateIePolicy::Reject,
                    ..context()
                }
            )
            .is_err());
            for policy in [DuplicateIePolicy::First, DuplicateIePolicy::Last] {
                let pdu = decode(
                    &wire,
                    DecodeContext {
                        duplicate_ie_policy: policy,
                        ..context()
                    },
                )
                .unwrap();
                assert!(SetupMessage::from_pdu(&pdu, context()).is_ok());
            }
            counts[1] += 1;
        } else if let Some(criticality) = row["unknown_criticality"].as_str() {
            counts[2] += 1;
            if criticality == "reject" {
                assert!(decode(&wire, context()).is_err());
                continue;
            }
            let pdu = decode(&wire, context()).unwrap();
            let raw = pdu.raw.clone();
            let admitted = SetupMessage::from_pdu(&pdu, context()).unwrap();
            assert_eq!(
                admitted.ignored_ie_count,
                ignores(&admitted.message) + usize::from(criticality == "ignore")
            );
            assert_eq!(
                admitted.notify_ie_ids,
                if criticality == "notify" {
                    vec![65530]
                } else {
                    vec![]
                }
            );
            assert!(pdu.raw == raw);
            assert!(decode(
                &wire,
                DecodeContext {
                    unknown_ie_policy: UnknownIePolicy::Reject,
                    ..context()
                }
            )
            .is_err());
            let dropped = decode(
                &wire,
                DecodeContext {
                    unknown_ie_policy: UnknownIePolicy::Drop,
                    ..context()
                },
            )
            .unwrap();
            let admitted = SetupMessage::from_pdu(&dropped, context()).unwrap();
            assert!(admitted.notify_ie_ids.is_empty());
            assert_eq!(admitted.ignored_ie_count, ignores(&admitted.message));
        }
    }
    assert_eq!(counts, [8, 3, 9]);
}

fn owned_fields(pdu: &Pdu) -> Vec<(u16, Criticality, Vec<u8>)> {
    fn crit(v: u8) -> Criticality {
        match v {
            0 => Criticality::reject,
            1 => Criticality::ignore,
            2 => Criticality::notify,
            _ => panic!("criticality"),
        }
    }
    match &pdu.kind {
        PduKind::Initiating {
            message: Message::NgSetupRequest(v),
            ..
        } => v
            .protocol_ies
            .0
            .iter()
            .map(|ie| {
                (
                    ie.id,
                    crit(ie.criticality as u8),
                    ie.value.as_bytes().to_vec(),
                )
            })
            .collect(),
        PduKind::Successful {
            message: Message::NgSetupResponse(v),
            ..
        } => v
            .protocol_ies
            .0
            .iter()
            .map(|ie| {
                (
                    ie.id,
                    crit(ie.criticality as u8),
                    ie.value.as_bytes().to_vec(),
                )
            })
            .collect(),
        PduKind::Unsuccessful {
            message: Message::NgSetupFailure(v),
            ..
        } => v
            .protocol_ies
            .0
            .iter()
            .map(|ie| {
                (
                    ie.id,
                    crit(ie.criticality as u8),
                    ie.value.as_bytes().to_vec(),
                )
            })
            .collect(),
        _ => panic!("setup message"),
    }
}
fn from_fields(kind: MessageType, fields: &[(u16, Criticality, Vec<u8>)]) -> Pdu {
    let borrowed: Vec<_> = fields
        .iter()
        .map(|(id, c, v)| ProtocolIe::new(*id, *c, v))
        .collect();
    Pdu::from_protocol_ies(kind, &borrowed, context()).unwrap()
}

#[test]
fn receiver_ignore_rules_preserve_mandatory_presence_and_other_fields_fail_explicitly() {
    let reference = oracle();
    for (label, kind, ignored, unsupported) in [
        (
            "base-NGSetupRequest",
            MessageType::NgSetupRequest,
            &[21, 204][..],
            &[82, 147, 273][..],
        ),
        (
            "base-NGSetupResponse",
            MessageType::NgSetupResponse,
            &[200, 404][..],
            &[19, 147, 274][..],
        ),
        (
            "base-NGSetupFailure",
            MessageType::NgSetupFailure,
            &[][..],
            &[19][..],
        ),
    ] {
        let row = reference["messages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["name"] == label)
            .unwrap();
        let pdu = decode(&octets(row["wire_hex"].as_str().unwrap()), context()).unwrap();
        let original = SetupMessage::from_pdu(&pdu, context()).unwrap();
        let base = owned_fields(&pdu);
        for id in ignored {
            let mut fields = base.clone();
            fields.retain(|(i, _, _)| i != id);
            fields.push((*id, Criticality::ignore, vec![0xff; 3]));
            let changed = from_fields(kind, &fields);
            let admitted = SetupMessage::from_pdu(&changed, context()).unwrap();
            assert!(admitted.message == original.message);
            assert_eq!(
                admitted.ignored_ie_count,
                original.ignored_ie_count + usize::from(*id != 21)
            );
        }
        for id in unsupported {
            let mut fields = base.clone();
            fields.push((*id, Criticality::ignore, vec![0xff]));
            assert!(SetupMessage::from_pdu(&from_fields(kind, &fields), context()).is_err());
        }
    }
}

#[test]
fn bounds_extensions_redaction_and_mutable_container_are_enforced() {
    assert!(PlmnSupportList::new(vec![]).is_err());
    assert!(ServedGuamiList::new(vec![]).is_err());
    assert!(SupportedTaList::new(vec![]).is_err());
    let p: PlmnId = "001-01".parse().unwrap();
    assert!(PlmnSlices::new(p.clone(), vec![]).is_err());
    assert!(PlmnSlices::new(p.clone(), vec![Snssai::without_sd(1); 1025]).is_err());
    assert!(SupportedTa::new([0; 3], vec![]).is_err());
    assert!(Guami::new(p.clone(), 0, 1024, 0).is_err());
    assert!(Guami::new(p, 0, 0, 64).is_err());
    for name in ["", "bad@name", "é", "\0", &"x".repeat(151)] {
        assert!(AmfName::new(name).is_err());
    }
    let reference = oracle();
    for (label, depth) in [
        ("base-NGSetupRequest", 12),
        ("base-NGSetupResponse", 10),
        ("base-NGSetupFailure", 6),
    ] {
        let row = reference["messages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["name"] == label)
            .unwrap();
        let wire = octets(row["wire_hex"].as_str().unwrap());
        let (message, drx) = expected(row, &reference);
        let mut pdu = construct(&message, drx, context()).unwrap();
        for ctx in [
            DecodeContext {
                max_depth: depth - 1,
                ..context()
            },
            DecodeContext {
                max_ies: 0,
                ..context()
            },
            DecodeContext {
                max_message_len: wire.len() - 1,
                ..context()
            },
        ] {
            assert!(construct(&message, drx, ctx).is_err());
            assert!(SetupMessage::from_pdu(&pdu, ctx).is_err());
        }
        assert!(construct(
            &message,
            drx,
            DecodeContext {
                max_depth: depth,
                ..context()
            }
        )
        .is_ok());
        let debug = format!("{:?}", SetupMessage::from_pdu(&pdu, context()).unwrap());
        for forbidden in ["synthetic", "001-01", "128", "010203"] {
            assert!(!debug.contains(forbidden));
        }
        match &mut pdu.kind {
            PduKind::Initiating { procedure_code, .. }
            | PduKind::Successful { procedure_code, .. }
            | PduKind::Unsuccessful { procedure_code, .. } => *procedure_code = 4,
        }
        assert!(SetupMessage::from_pdu(&pdu, context()).is_err());
    }
    for (kind, depth, count, index, masks) in [
        ("GlobalRANNodeID", 4, 0, 0, &[0x40, 0x20, 0x10][..]),
        (
            "ServedGUAMIList",
            4,
            1,
            1,
            &[0x80, 0x40, 0x20, 0x10, 0x08][..],
        ),
        ("PLMNSupportList", 6, 2, 0, &[0x08, 0x04][..]),
        ("SupportedTAList", 8, 3, 1, &[0x80, 0x40][..]),
        ("AMFName", 1, 0, 0, &[0x80][..]),
    ] {
        let row = reference["fields"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["type"] == kind)
            .unwrap();
        let wire = octets(row["wire_hex"].as_str().unwrap());
        for mask in masks {
            let mut changed = wire.clone();
            changed[index] |= mask;
            assert!(!field_admitted(kind, &changed, context()));
        }
        assert!(!field_admitted(
            kind,
            &wire,
            DecodeContext {
                max_depth: depth - 1,
                ..context()
            }
        ));
        if count != 0 {
            assert!(!field_admitted(
                kind,
                &wire,
                DecodeContext {
                    max_ies: count - 1,
                    ..context()
                }
            ));
            assert!(field_admitted(
                kind,
                &wire,
                DecodeContext {
                    max_ies: count,
                    ..context()
                }
            ));
        }
    }
    // Bad nested counts and flags, with otherwise independent valid prefixes.
    let root = reference["fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["type"] == "PLMNSupportList")
        .unwrap();
    let wire = octets(root["wire_hex"].as_str().unwrap());
    for (index, mask) in [
        (0, 0xf0),
        (4, 0xff),
        (6, 0x80),
        (6, 0x40),
        (6, 0x20),
        (6, 0x08),
    ] {
        let mut changed = wire.clone();
        changed[index] |= mask;
        assert!(PlmnSupportList::decode(&changed, context()).is_err());
    }
}
fn field_admitted(kind: &str, input: &[u8], ctx: DecodeContext) -> bool {
    match kind {
        "GlobalRANNodeID" => GlobalN3iwfId::decode(input, ctx).is_ok(),
        "ServedGUAMIList" => ServedGuamiList::decode(input, ctx).is_ok(),
        "PLMNSupportList" => PlmnSupportList::decode(input, ctx).is_ok(),
        "SupportedTAList" => SupportedTaList::decode(input, ctx).is_ok(),
        "AMFName" => AmfName::decode(input, ctx).is_ok(),
        _ => false,
    }
}
fn exercise(data: &[u8]) {
    macro_rules! field {
        ($ty:ty) => {
            if let Ok(value) = <$ty>::decode(data, context()) {
                let output = value.encode(EncodeContext::default()).unwrap();
                assert!(<$ty>::decode(output.as_bytes(), context()).unwrap() == value);
            }
        };
    }
    field!(GlobalN3iwfId);
    field!(ServedGuamiList);
    field!(PlmnSupportList);
    field!(SupportedTaList);
    field!(AmfName);
    if let Ok(pdu) = decode(data, context()) {
        if let Ok(admitted) = SetupMessage::from_pdu(&pdu, context()) {
            let constructed = construct(&admitted.message, PagingDrx::v128, context()).unwrap();
            let wire = encode(&constructed, EncodeContext::default()).unwrap();
            let readmitted =
                SetupMessage::from_pdu(&decode(&wire, context()).unwrap(), context()).unwrap();
            assert!(readmitted.message == admitted.message);
        }
    }
}
#[test]
fn independent_field_and_message_truncations_and_mutations_are_safe() {
    let reference = oracle();
    for row in reference["fields"]
        .as_array()
        .unwrap()
        .iter()
        .chain(reference["messages"].as_array().unwrap())
    {
        let wire = octets(row["wire_hex"].as_str().unwrap());
        // Every truncation, and deterministic mutations sampled across large
        // maximum-list vectors to keep the ordinary CI workload bounded.
        for end in 0..=wire.len() {
            exercise(&wire[..end]);
        }
        let stride = (wire.len() / 128).max(1);
        for index in (0..wire.len()).step_by(stride) {
            for mask in [1, 0x80, 0xff] {
                let mut changed = wire.clone();
                changed[index] ^= mask;
                exercise(&changed);
            }
        }
    }
}
