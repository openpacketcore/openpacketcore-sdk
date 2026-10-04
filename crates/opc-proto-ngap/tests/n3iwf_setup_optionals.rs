#[path = "support/setup_optionals.rs"]
mod setup_optionals;
use opc_proto_ngap::n3iwf::setup::*;
use opc_proto_ngap::{decode, encode, Message, Pdu, PduKind};
use opc_protocol::{DecodeContext, DuplicateIePolicy, EncodeContext, ValidationLevel};
use opc_types::Snssai;
use serde_json::Value;

fn reference() -> Value {
    serde_json::from_str(include_str!("fixtures/n3iwf-setup-optionals.json")).unwrap()
}
fn bytes(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).unwrap())
        .collect()
}
fn context() -> DecodeContext {
    DecodeContext {
        max_depth: 12,
        max_ies: 1024,
        max_message_len: 131072,
        validation_level: ValidationLevel::Strict,
        duplicate_ie_policy: DuplicateIePolicy::Reject,
        ..DecodeContext::default()
    }
}

fn expected(row: &Value) -> SetupMessage {
    let model = &row["model"];
    let plmns =
        || vec![PlmnSlices::new("001-01".parse().unwrap(), vec![Snssai::without_sd(1)]).unwrap()];
    let retention = (model["retention"] == true).then_some(UeRetentionInformation::UesRetained);
    let extended = &model["extended"];
    if row["message"] == "NGSetupRequest" {
        SetupMessage::Request(NgSetupRequest {
            global: GlobalN3iwfId::new("001-01".parse().unwrap(), 1),
            tracking_areas: SupportedTaList::new(vec![
                SupportedTa::new([0, 0, 1], plmns()).unwrap()
            ])
            .unwrap(),
            node_name: model["name"].as_str().map(|v| RanNodeName::new(v).unwrap()),
            retention,
            extended_node_name: model.get("extended").map(|_| {
                ExtendedRanNodeName::new(extended["visible"].as_str(), extended["utf8"].as_str())
                    .unwrap()
            }),
        })
    } else {
        let names = model["backups"]
            .as_array()
            .cloned()
            .unwrap_or_else(|| vec![Value::Null]);
        SetupMessage::Response(NgSetupResponse {
            name: AmfName::new("synthetic-amf.example").unwrap(),
            served: ServedGuamiList::with_backups(
                names
                    .iter()
                    .map(|name| {
                        (
                            Guami::new("001-01".parse().unwrap(), 1, 1, 1).unwrap(),
                            name.as_str().map(|v| AmfName::new(v).unwrap()),
                        )
                    })
                    .collect(),
            )
            .unwrap(),
            relative_capacity: 128,
            plmns: PlmnSupportList::new(plmns()).unwrap(),
            diagnostics: None,
            retention,
            extended_name: model.get("extended").map(|_| {
                ExtendedAmfName::new(extended["visible"].as_str(), extended["utf8"].as_str())
                    .unwrap()
            }),
        })
    }
}
fn construct(value: &SetupMessage, ctx: DecodeContext) -> Result<Pdu, opc_protocol::DecodeError> {
    match value {
        SetupMessage::Request(v) => v.construct(PagingDrx::v128, ctx),
        SetupMessage::Response(v) => v.construct(ctx),
        SetupMessage::Failure(v) => v.construct(ctx),
    }
}

#[test]
fn independent_semantics_construction_and_negative_outcomes_match() {
    let reference = reference();
    let rows = reference["cases"].as_array().unwrap();
    assert_eq!(rows.len(), 162);
    let (mut positive, mut constructed) = (0, 0);
    for row in rows {
        let wire = bytes(row["wire_hex"].as_str().unwrap());
        let result =
            decode(&wire, context()).and_then(|pdu| SetupMessage::from_pdu(&pdu, context()));
        if row["admit"] != true {
            assert!(result.is_err(), "negative admitted: {}", row["name"]);
            continue;
        }
        let admitted = result.unwrap();
        let expected = expected(row);
        assert!(
            admitted.message == expected,
            "independent values differ: {}",
            row["name"]
        );
        assert_eq!(
            admitted.ignored_ie_count,
            usize::from(row["message"] == "NGSetupRequest")
                + usize::from(row["unknown"] == "ignore")
        );
        assert_eq!(
            admitted.notify_ie_ids,
            if row["unknown"] == "notify" {
                vec![65530]
            } else {
                vec![]
            }
        );
        assert!(format!("{admitted:?}").contains("REDACTED"));
        positive += 1;
        if row["construct"] == true {
            let pdu = construct(&expected, context()).unwrap();
            assert!(
                encode(
                    &pdu,
                    EncodeContext {
                        max_message_len: wire.len(),
                        ..EncodeContext::default()
                    }
                )
                .unwrap()
                    == wire,
                "independent construction differs: {}",
                row["name"]
            );
            assert!(construct(
                &expected,
                DecodeContext {
                    max_message_len: wire.len() - 1,
                    ..context()
                }
            )
            .is_err());
            assert!(construct(
                &expected,
                DecodeContext {
                    max_depth: if row["message"] == "NGSetupRequest" {
                        11
                    } else {
                        9
                    },
                    ..context()
                }
            )
            .is_err());
            constructed += 1;
        }
        let mut rebuilt = admitted.message.clone();
        setup_optionals::reconstruct(&mut rebuilt);
        assert!(rebuilt == expected);
    }
    assert_eq!(positive, 118);
    assert_eq!(constructed, 112);
}

#[test]
fn duplicates_select_values_and_mutable_criticality_is_rechecked() {
    for row in reference()["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r.get("duplicate").is_some())
    {
        let wire = bytes(row["wire_hex"].as_str().unwrap());
        let id = row["duplicate"].as_u64().unwrap() as u16;
        assert!(decode(
            &wire,
            DecodeContext {
                duplicate_ie_policy: DuplicateIePolicy::Reject,
                ..context()
            }
        )
        .is_err());
        for policy in [DuplicateIePolicy::First, DuplicateIePolicy::Last] {
            let ctx = DecodeContext {
                duplicate_ie_policy: policy,
                ..context()
            };
            let mut pdu = decode(&wire, ctx).unwrap();
            let actual = SetupMessage::from_pdu(&pdu, ctx).unwrap().message;
            let mut wanted = expected(row);
            if policy == DuplicateIePolicy::Last {
                match &mut wanted {
                    SetupMessage::Request(v) if id == 82 => {
                        v.node_name = Some(RanNodeName::new("last").unwrap())
                    }
                    SetupMessage::Request(v) if id == 273 => {
                        v.extended_node_name =
                            Some(ExtendedRanNodeName::new(None, Some("last")).unwrap())
                    }
                    SetupMessage::Response(v) if id == 274 => {
                        v.extended_name = Some(ExtendedAmfName::new(None, Some("last")).unwrap())
                    }
                    _ => (),
                }
            }
            assert!(actual == wanted);
            match &mut pdu.kind {
                PduKind::Initiating {
                    message: Message::NgSetupRequest(v),
                    ..
                } => {
                    v.protocol_ies
                        .0
                        .iter_mut()
                        .find(|v| v.id == id)
                        .unwrap()
                        .criticality = rasn::aper::decode(&[0]).unwrap();
                }
                PduKind::Successful {
                    message: Message::NgSetupResponse(v),
                    ..
                } => {
                    v.protocol_ies
                        .0
                        .iter_mut()
                        .find(|v| v.id == id)
                        .unwrap()
                        .criticality = rasn::aper::decode(&[0]).unwrap();
                }
                _ => panic!(),
            }
            assert!(SetupMessage::from_pdu(&pdu, ctx).is_err());
        }
    }
}

#[test]
fn backup_name_and_optional_leaf_bounds_are_enforced() {
    for value in ["", "bad_name", "é", &"n".repeat(151)] {
        assert!(RanNodeName::new(value).is_err());
    }
    assert!(ExtendedRanNodeName::new(Some("\n"), None).is_err());
    assert!(ExtendedRanNodeName::new(None, Some(&"🙂".repeat(151))).is_err());
    assert!(ServedGuamiList::with_backups(vec![]).is_err());
    assert!(ServedGuamiList::with_backups(vec![
        (
            Guami::new("001-01".parse().unwrap(), 1, 1, 1).unwrap(),
            None
        );
        257
    ])
    .is_err());
    assert_eq!(
        format!("{:?}", RanNodeName::new("SECRET").unwrap()),
        "RanNodeName([REDACTED])"
    );
    assert_eq!(
        format!(
            "{:?}",
            ExtendedRanNodeName::new(Some("SECRET"), None).unwrap()
        ),
        "ExtendedRanNodeName([REDACTED])"
    );
    assert_eq!(
        format!("{:?}", UeRetentionInformation::UesRetained),
        "UeRetentionInformation([REDACTED])"
    );
    for row in reference()["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["model"].get("backups").is_some())
    {
        let SetupMessage::Response(value) = expected(row) else {
            panic!()
        };
        let leaf = value.served.encode(EncodeContext::default()).unwrap();
        assert!(ServedGuamiList::decode(
            leaf.as_bytes(),
            DecodeContext {
                max_ies: value.served.values().len() - 1,
                ..context()
            }
        )
        .is_err());
        assert!(ServedGuamiList::decode(
            leaf.as_bytes(),
            DecodeContext {
                max_depth: 3,
                ..context()
            }
        )
        .is_err());
        assert!(value
            .served
            .encode(EncodeContext {
                max_message_len: leaf.as_bytes().len() - 1,
                ..EncodeContext::default()
            })
            .is_err());
        let mut trailing = leaf.as_bytes().to_vec();
        trailing.push(0);
        assert!(ServedGuamiList::decode(&trailing, context()).is_err());
    }
    for raw in [vec![], vec![1], vec![0x80], vec![0, 0]] {
        assert!(UeRetentionInformation::decode(&raw, context()).is_err());
    }
    assert!(UeRetentionInformation::decode(
        &[0],
        DecodeContext {
            max_depth: 0,
            ..context()
        }
    )
    .is_err());
    assert!(UeRetentionInformation::UesRetained
        .encode(EncodeContext {
            max_message_len: 0,
            ..EncodeContext::default()
        })
        .is_err());
}

#[test]
fn independent_wires_and_bounded_mutations_reconstruct_without_panics() {
    let output = EncodeContext {
        max_message_len: 131072,
        ..EncodeContext::default()
    };
    let mut mutations = 0;
    for row in reference()["cases"].as_array().unwrap() {
        let wire = bytes(row["wire_hex"].as_str().unwrap());
        for ctx in [
            context(),
            DecodeContext {
                max_depth: 8,
                max_ies: 8,
                ..context()
            },
        ] {
            setup_optionals::exercise(&wire, ctx, output);
            let stride = (wire.len() / 96).max(1);
            for offset in (0..wire.len()).step_by(stride) {
                setup_optionals::exercise(&wire[..offset], ctx, output);
                for mask in [1, 0x80, 0xff] {
                    let mut changed = wire.clone();
                    changed[offset] ^= mask;
                    setup_optionals::exercise(&changed, ctx, output);
                    mutations += 1;
                }
            }
        }
    }
    assert!(mutations > 50_000);
    eprintln!("NG Setup optional-field bounded byte mutations: {mutations}");
}

#[test]
fn independent_setup_optional_fields_are_admitted() {
    for row in reference()["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["admit"] == true)
    {
        let wire = bytes(row["wire_hex"].as_str().unwrap());
        let pdu = decode(&wire, context()).unwrap();
        assert!(
            SetupMessage::from_pdu(&pdu, context()).is_ok(),
            "applicable NG Setup optional field remains unsupported: {}",
            row["name"]
        );
    }
}
