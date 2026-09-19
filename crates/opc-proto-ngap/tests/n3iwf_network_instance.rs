use opc_proto_ngap::n3iwf::modify_request::ModifyRequestTransfer;
use opc_proto_ngap::n3iwf::resource_request::SetupRequestTransfer;
use opc_protocol::{
    DecodeContext, DuplicateIePolicy, EncodeContext, UnknownIePolicy, ValidationLevel,
};
use serde_json::Value;

fn reference() -> Value {
    serde_json::from_str(include_str!("fixtures/n3iwf-network-instance.json")).unwrap()
}
fn bytes(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|v| u8::from_str_radix(std::str::from_utf8(v).unwrap(), 16).unwrap())
        .collect()
}
fn context() -> DecodeContext {
    DecodeContext {
        max_message_len: 200_000,
        max_depth: 24,
        max_ies: 256,
        duplicate_ie_policy: DuplicateIePolicy::Reject,
        validation_level: ValidationLevel::Strict,
        ..DecodeContext::default()
    }
}
fn expected_transfers(setup: bool) {
    let oracle = reference();
    for row in oracle["transfers"].as_array().unwrap() {
        if row["kind"].as_str().unwrap().contains("Setup") != setup {
            continue;
        }
        let wire = bytes(row["wire_hex"].as_str().unwrap());
        let admitted = if setup {
            SetupRequestTransfer::decode(&wire, context()).is_ok()
        } else {
            ModifyRequestTransfer::decode(&wire, context()).is_ok()
        };
        assert_eq!(admitted, row["admit"].as_bool().unwrap(), "{}", row["name"]);
    }
}

#[test]
fn independent_setup_network_instances_match_reference() {
    expected_transfers(true);
}

#[test]
fn independent_modify_network_instances_match_reference() {
    expected_transfers(false);
}

use opc_proto_ngap::n3iwf::context_fields::SecurityAlgorithmMasks;
use opc_proto_ngap::n3iwf::modify::ModifyMessage;
use opc_proto_ngap::n3iwf::network_fields::{CommonNetworkInstance, TransportNetworkInstance};
use opc_proto_ngap::n3iwf::resource_fields::{
    NonGbrFlow, QosFlowId, QosFlowSetupList, SessionAggregateBitRate, SessionType, UplinkTransport,
};
use opc_proto_ngap::n3iwf::resource_setup::ResourceSetupMessage;
use opc_proto_ngap::n3iwf::security_fields::NetworkInstance;
use opc_proto_ngap::{decode, encode};

fn output() -> EncodeContext {
    EncodeContext {
        max_message_len: 200_000,
        ..EncodeContext::default()
    }
}
fn octets(model: &Value) -> Vec<u8> {
    let length = model["length"].as_u64().unwrap() as usize;
    let seed = model["seed"].as_u64().unwrap() as usize;
    (0..length).map(|i| ((seed + 17 * i) % 256) as u8).collect()
}
fn common(model: &Value) -> Option<CommonNetworkInstance> {
    model
        .get("common")
        .map(|v| CommonNetworkInstance::new(octets(v)))
}
fn numeric(model: &Value) -> Option<NetworkInstance> {
    model["network"]
        .as_u64()
        .map(|v| NetworkInstance::new(v as u16).unwrap())
}
fn setup(model: &Value) -> SetupRequestTransfer {
    SetupRequestTransfer {
        uplink: UplinkTransport::new("198.51.100.17".parse().unwrap(), 0x11223344),
        aggregate_bit_rate: SessionAggregateBitRate::new(1_000_000, 2_000_000).unwrap(),
        session_type: SessionType::Ipv4,
        flows: QosFlowSetupList::new(vec![NonGbrFlow::new(
            QosFlowId::new(9).unwrap(),
            8,
            false,
            false,
        )
        .unwrap()])
        .unwrap(),
        security: None,
        network_instance: numeric(model),
        common_network_instance: common(model),
    }
}
fn modify(model: &Value) -> ModifyRequestTransfer {
    ModifyRequestTransfer {
        network_instance: numeric(model),
        common_network_instance: common(model),
        ..Default::default()
    }
}
fn preference(value: Option<TransportNetworkInstance<'_>>, model: &Value) {
    if let Some(expected) = common(model) {
        assert!(matches!(value, Some(TransportNetworkInstance::Common(v)) if *v == expected));
    } else if let Some(expected) = numeric(model) {
        assert!(matches!(value, Some(TransportNetworkInstance::Network(v)) if v == expected));
    } else {
        assert!(value.is_none());
    }
    if let Some(value) = value {
        assert_eq!(format!("{value:?}"), "TransportNetworkInstance([REDACTED])");
    }
}

#[test]
fn common_octets_fragment_boundaries_and_resource_limits_match_reference() {
    let oracle = reference();
    assert_eq!(oracle["fields"].as_array().unwrap().len(), 271);
    for row in oracle["fields"].as_array().unwrap() {
        let raw = bytes(row["wire_hex"].as_str().unwrap());
        let expected = CommonNetworkInstance::new(octets(&row["model"]));
        let ctx = DecodeContext {
            max_message_len: raw.len(),
            max_depth: 1,
            max_ies: 0,
            ..context()
        };
        let out = EncodeContext {
            max_message_len: raw.len(),
            ..output()
        };
        let received = CommonNetworkInstance::decode(&raw, ctx).unwrap();
        assert!(received == expected);
        assert!(received.as_bytes() == octets(&row["model"]));
        assert!(expected.encode(out).unwrap().as_bytes() == raw);
        assert_eq!(format!("{received:?}"), "CommonNetworkInstance([REDACTED])");
        assert!(expected
            .encode(EncodeContext {
                max_message_len: raw.len() - 1,
                ..out
            })
            .is_err());
        assert!(CommonNetworkInstance::decode(
            &raw,
            DecodeContext {
                max_message_len: raw.len() - 1,
                ..ctx
            }
        )
        .is_err());
        assert!(CommonNetworkInstance::decode(
            &raw,
            DecodeContext {
                max_depth: 0,
                ..ctx
            }
        )
        .is_err());
        let mut trailing = raw.clone();
        trailing.push(0);
        assert!(CommonNetworkInstance::decode(&trailing, context()).is_err());
        let cuts: Vec<usize> = if raw.len() <= 260 {
            (0..raw.len()).collect()
        } else {
            [
                0,
                1,
                2,
                127,
                128,
                16383,
                16384,
                16385,
                raw.len() - 2,
                raw.len() - 1,
            ]
            .into_iter()
            .filter(|i| *i < raw.len())
            .collect()
        };
        for cut in cuts {
            assert!(CommonNetworkInstance::decode(&raw[..cut], ctx).is_err());
        }
    }
    for raw in [
        vec![0xc0],
        vec![0xc5],
        vec![0x80, 0],
        vec![0x80, 1, 17],
        vec![0xc1; 2],
    ] {
        assert!(CommonNetworkInstance::decode(&raw, context()).is_err());
    }
}

fn transfer_wire(
    setup_kind: bool,
    model: &Value,
    ctx: EncodeContext,
) -> Result<Vec<u8>, opc_protocol::EncodeError> {
    let encoded = if setup_kind {
        setup(model).encode(ctx)
    } else {
        modify(model).encode(ctx)
    }?;
    Ok(encoded.as_bytes().to_vec())
}
fn received_transfer(
    setup_kind: bool,
    raw: &[u8],
    model: &Value,
    ctx: DecodeContext,
) -> Result<(Vec<u8>, usize, Vec<u16>), opc_protocol::DecodeError> {
    if setup_kind {
        let value = SetupRequestTransfer::decode(raw, ctx)?;
        assert!(value.transfer == setup(model));
        preference(value.transfer.transport_network_instance(), model);
        Ok((
            value.transfer.encode(output()).unwrap().as_bytes().to_vec(),
            value.ignored_ie_count,
            value.notify_ie_ids,
        ))
    } else {
        let value = ModifyRequestTransfer::decode(raw, ctx)?;
        assert!(value.transfer == modify(model));
        preference(value.transfer.transport_network_instance(), model);
        Ok((
            value.transfer.encode(output()).unwrap().as_bytes().to_vec(),
            value.ignored_ie_count,
            value.notify_ie_ids,
        ))
    }
}

#[test]
fn transfer_construction_precedence_selection_and_limits_match_reference() {
    let oracle = reference();
    assert_eq!(oracle["transfers"].as_array().unwrap().len(), 365);
    for row in oracle["transfers"].as_array().unwrap() {
        let raw = bytes(row["wire_hex"].as_str().unwrap());
        let setup_kind = row["kind"].as_str().unwrap().contains("Setup");
        let model = &row["model"];
        let count = u16::from_be_bytes([raw[1], raw[2]]) as usize;
        let depth = if setup_kind {
            10
        } else if count == 0 {
            4
        } else {
            5
        };
        let ctx = DecodeContext {
            max_message_len: raw.len(),
            max_depth: depth,
            max_ies: count,
            ..context()
        };
        if row["admit"] == true {
            let (canonical, ignored, notify) =
                received_transfer(setup_kind, &raw, model, ctx).unwrap();
            assert!(
                canonical == bytes(row["canonical_wire_hex"].as_str().unwrap()),
                "{}",
                row["name"]
            );
            assert_eq!(ignored, usize::from(row["unknown"] == "ignore"));
            assert_eq!(
                notify,
                if row["unknown"] == "notify" {
                    vec![65530]
                } else {
                    vec![]
                }
            );
            let out = EncodeContext {
                max_message_len: canonical.len(),
                ..output()
            };
            assert!(transfer_wire(setup_kind, model, out).unwrap() == canonical);
            assert!(transfer_wire(
                setup_kind,
                model,
                EncodeContext {
                    max_message_len: canonical.len() - 1,
                    ..out
                }
            )
            .is_err());
            for short in [
                DecodeContext {
                    max_message_len: raw.len() - 1,
                    ..ctx
                },
                DecodeContext {
                    max_depth: depth - 1,
                    ..ctx
                },
            ] {
                assert!(received_transfer(setup_kind, &raw, model, short).is_err());
            }
            if count != 0 {
                assert!(received_transfer(
                    setup_kind,
                    &raw,
                    model,
                    DecodeContext {
                        max_ies: count - 1,
                        ..ctx
                    }
                )
                .is_err());
            }
        }
        if row.get("duplicate").is_some() {
            for policy in [DuplicateIePolicy::First, DuplicateIePolicy::Last] {
                let selected = if policy == DuplicateIePolicy::First {
                    model
                } else {
                    &row["last_model"]
                };
                let duplicate_ctx = DecodeContext {
                    duplicate_ie_policy: policy,
                    ..context()
                };
                if policy == DuplicateIePolicy::Last && row["last_reject"] == true {
                    // Avoid constructing a model for a malformed selected value.
                    assert!(if setup_kind {
                        SetupRequestTransfer::decode(&raw, duplicate_ctx).is_err()
                    } else {
                        ModifyRequestTransfer::decode(&raw, duplicate_ctx).is_err()
                    });
                } else {
                    let (wire, ignored, notify) =
                        received_transfer(setup_kind, &raw, selected, duplicate_ctx).unwrap();
                    let expected_key = if policy == DuplicateIePolicy::First {
                        "first_wire_hex"
                    } else {
                        "last_wire_hex"
                    };
                    assert!(wire == bytes(row[expected_key].as_str().unwrap()));
                    assert_eq!(ignored, 0);
                    assert!(notify.is_empty());
                }
            }
        }
        if row.get("unknown").is_some() {
            let reject = DecodeContext {
                unknown_ie_policy: UnknownIePolicy::Reject,
                ..context()
            };
            assert!(received_transfer(setup_kind, &raw, model, reject).is_err());
            if row["unknown"] != "reject" {
                let drop = DecodeContext {
                    unknown_ie_policy: UnknownIePolicy::Drop,
                    ..context()
                };
                let (_, ignored, notify) =
                    received_transfer(setup_kind, &raw, model, drop).unwrap();
                assert_eq!(ignored, 0);
                assert!(notify.is_empty());
            }
        }
    }
}

#[test]
fn complete_messages_construct_independent_network_instance_bytes() {
    let oracle = reference();
    assert_eq!(oracle["messages"].as_array().unwrap().len(), 15);
    for row in oracle["messages"].as_array().unwrap() {
        let raw = bytes(row["wire_hex"].as_str().unwrap());
        let model = &row["model"];
        let pdu = decode(&raw, context()).unwrap();
        resource_setup::exercise(&raw, context(), output());
        let constructed = if row["kind"] == "PDUSessionResourceModifyRequest" {
            let received = ModifyMessage::from_pdu(&pdu, context()).unwrap();
            let ModifyMessage::Request(value) = received.message else {
                panic!("reference message kind")
            };
            assert!(value.sessions.values()[0].transfer == modify(model));
            preference(
                value.sessions.values()[0]
                    .transfer
                    .transport_network_instance(),
                model,
            );
            assert!(
                transfer_wire(false, model, output()).unwrap()
                    == bytes(row["transfer_wire_hex"].as_str().unwrap())
            );
            value.construct(context())
        } else {
            let received = ResourceSetupMessage::from_pdu(&pdu, context()).unwrap();
            let expected = setup(model);
            assert!(
                expected.encode(output()).unwrap().as_bytes()
                    == bytes(row["transfer_wire_hex"].as_str().unwrap())
            );
            match received.message {
                ResourceSetupMessage::InitialRequest(value) => {
                    assert!(value.sessions.as_ref().unwrap().values()[0].transfer == expected);
                    value.construct(SecurityAlgorithmMasks::new(0, 0, 0, 0), context())
                }
                ResourceSetupMessage::SessionRequest(value) => {
                    assert!(value.sessions.values()[0].transfer == expected);
                    value.construct(context())
                }
                _ => panic!("reference message kind"),
            }
        }
        .unwrap();
        assert!(
            encode(&constructed, output()).unwrap() == raw,
            "{} {}",
            row["kind"],
            row["name"]
        );
    }
}

#[path = "support/modify.rs"]
mod modify_messages;
#[path = "support/network_instance.rs"]
mod network_instance;
#[path = "support/resource_setup.rs"]
mod resource_setup;

#[test]
fn hostile_leaf_transfer_and_message_mutations_remain_bounded() {
    let oracle = reference();
    let mut mutations = 0;
    for category in ["fields", "transfers", "messages"] {
        for row in oracle[category].as_array().unwrap() {
            let raw = bytes(row["wire_hex"].as_str().unwrap());
            let positions: Vec<usize> = if raw.len() <= 300 {
                (0..raw.len()).collect()
            } else {
                [
                    0,
                    1,
                    2,
                    3,
                    4,
                    127,
                    128,
                    16383,
                    16384,
                    16385,
                    raw.len() - 2,
                    raw.len() - 1,
                ]
                .into_iter()
                .filter(|i| *i < raw.len())
                .collect()
            };
            for ctx in [
                context(),
                DecodeContext {
                    max_depth: 5,
                    max_ies: 2,
                    ..context()
                },
            ] {
                let exercise = |wire: &[u8]| {
                    network_instance::exercise(wire, ctx, output());
                    if category == "messages" {
                        resource_setup::exercise_bounded(wire, ctx, output());
                        modify_messages::exercise(wire, ctx, output());
                    }
                };
                exercise(&raw);
                for position in &positions {
                    exercise(&raw[..*position]);
                    mutations += 1;
                    for bit in 0..8 {
                        let mut changed = raw.clone();
                        changed[*position] ^= 1 << bit;
                        exercise(&changed);
                        mutations += 1;
                    }
                }
            }
        }
    }
    assert!(mutations > 90_000);
    eprintln!("Exercised {mutations} bounded reference mutations");
}
