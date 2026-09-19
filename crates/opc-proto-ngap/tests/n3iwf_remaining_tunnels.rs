#![allow(clippy::unwrap_used)]
use bytes::Bytes;
use opc_proto_ngap::n3iwf::modify::ModifyMessage;
use opc_proto_ngap::n3iwf::modify_fields::{ModifiedQosFlows, QosFlowCause, QosFlowCauses};
use opc_proto_ngap::n3iwf::modify_request::ModifyRequestTransfer;
use opc_proto_ngap::n3iwf::modify_results::ModifyResponseTransfer;
use opc_proto_ngap::n3iwf::release::{Cause, CauseClass};
use opc_proto_ngap::n3iwf::resource_fields::{
    DownlinkTransport, NonGbrFlow, QosFlowId, QosFlowSetupList, SessionAggregateBitRate,
    SessionType, UplinkTransport, UplinkTransportList,
};
use opc_proto_ngap::n3iwf::resource_request::SetupRequestTransfer;
use opc_proto_ngap::n3iwf::resource_results::{
    AssociatedQosFlow, DownlinkQosTunnel, QosFlowMapping,
};
use opc_proto_ngap::n3iwf::resource_setup::ResourceSetupMessage;
use opc_proto_ngap::{encode, Pdu};
use opc_protocol::{
    DecodeContext, DecodeError, DuplicateIePolicy, EncodeContext, OwnedDecode, UnknownIePolicy,
};
use serde_json::Value;

#[path = "support/remaining_tunnels.rs"]
mod support;

fn oracle() -> Value {
    serde_json::from_str(include_str!("fixtures/n3iwf-remaining-tunnels.json")).unwrap()
}
fn bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}
fn context() -> DecodeContext {
    DecodeContext {
        max_depth: 32,
        max_ies: 320,
        max_message_len: 4096,
        ..DecodeContext::default()
    }
}
fn first(kind: &str) -> Vec<u8> {
    let data = oracle();
    let row = data["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["kind"] == kind)
        .unwrap();
    bytes(row["wire_hex"].as_str().unwrap())
}

#[test]
fn independent_additional_uplink_setup_is_admitted() {
    assert!(SetupRequestTransfer::decode(
        &first("PDUSessionResourceSetupRequestTransfer"),
        context()
    )
    .is_ok());
}
#[test]
fn independent_additional_uplink_modify_is_admitted() {
    assert!(ModifyRequestTransfer::decode(
        &first("PDUSessionResourceModifyRequestTransfer"),
        context()
    )
    .is_ok());
}
#[test]
fn independent_additional_downlink_modify_is_admitted() {
    assert!(ModifyResponseTransfer::decode(
        &first("PDUSessionResourceModifyResponseTransfer"),
        context()
    )
    .is_ok());
}

#[test]
fn additional_uplink_selection_validates_only_selected_duplicate_values() {
    let data = oracle();
    let requests: Vec<_> = data["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["kind"] == "PDUSessionResourceModifyRequestTransfer")
        .take(2)
        .collect();
    let first = bytes(requests[0]["wire_hex"].as_str().unwrap());
    let last = bytes(requests[1]["wire_hex"].as_str().unwrap());
    let mut duplicates = first.clone();
    duplicates[2] = 2;
    duplicates.extend_from_slice(&last[3..]);
    for unknown_ie_policy in [UnknownIePolicy::Preserve, UnknownIePolicy::Drop] {
        let ctx = DecodeContext {
            unknown_ie_policy,
            ..context()
        };
        assert!(ModifyRequestTransfer::decode(
            &duplicates,
            DecodeContext {
                duplicate_ie_policy: DuplicateIePolicy::Reject,
                ..ctx
            }
        )
        .is_err());
        for (policy, row) in [
            (DuplicateIePolicy::First, requests[0]),
            (DuplicateIePolicy::Last, requests[1]),
        ] {
            let value = ModifyRequestTransfer::decode(
                &duplicates,
                DecodeContext {
                    duplicate_ie_policy: policy,
                    ..ctx
                },
            )
            .unwrap();
            assert!(value.transfer.additional_uplink.unwrap() == uplinks(&row["model"]));
        }
        let mut malformed = first.clone();
        malformed[2] = 2;
        malformed.extend_from_slice(&[0, 126, 0, 1, 0]);
        assert!(ModifyRequestTransfer::decode(
            &malformed,
            DecodeContext {
                duplicate_ie_policy: DuplicateIePolicy::First,
                ..ctx
            }
        )
        .is_ok());
        assert!(ModifyRequestTransfer::decode(
            &malformed,
            DecodeContext {
                duplicate_ie_policy: DuplicateIePolicy::Last,
                ..ctx
            }
        )
        .is_err());
        let setup = bytes(data["cases"][0]["wire_hex"].as_str().unwrap());
        let mut duplicates = setup.clone();
        duplicates[2] += 1;
        duplicates.extend_from_slice(&last[3..]);
        for (policy, row) in [
            (DuplicateIePolicy::First, requests[0]),
            (DuplicateIePolicy::Last, requests[1]),
        ] {
            let value = SetupRequestTransfer::decode(
                &duplicates,
                DecodeContext {
                    duplicate_ie_policy: policy,
                    ..ctx
                },
            )
            .unwrap();
            assert!(value.transfer.additional_uplink.unwrap() == uplinks(&row["model"]));
        }
    }
}

fn output() -> EncodeContext {
    EncodeContext {
        max_message_len: 4096,
        ..EncodeContext::default()
    }
}
fn endpoint(model: &Value) -> (std::net::IpAddr, u32) {
    (
        model["address"].as_str().unwrap().parse().unwrap(),
        model["teid"].as_u64().unwrap() as u32,
    )
}
fn uplinks(model: &Value) -> UplinkTransportList {
    UplinkTransportList::new(
        model
            .as_array()
            .unwrap()
            .iter()
            .map(|v| {
                let (ip, teid) = endpoint(v);
                UplinkTransport::new(ip, teid)
            })
            .collect(),
    )
    .unwrap()
}
fn setup(model: &Value) -> SetupRequestTransfer {
    SetupRequestTransfer {
        uplink: UplinkTransport::new("198.51.100.17".parse().unwrap(), 0x11223344),
        additional_uplink: Some(uplinks(model)),
        aggregate_bit_rate: Some(SessionAggregateBitRate::new(1_000_000, 2_000_000).unwrap()),
        session_type: SessionType::Ipv4,
        flows: QosFlowSetupList::new(vec![NonGbrFlow::new(
            QosFlowId::new(0).unwrap(),
            1,
            false,
            false,
        )
        .unwrap()])
        .unwrap(),
        security: None,
        network_instance: None,
        common_network_instance: None,
    }
}
fn qfi(value: &Value) -> QosFlowId {
    QosFlowId::new(value.as_u64().unwrap() as u8).unwrap()
}
fn response(model: &Value) -> Result<ModifyResponseTransfer, DecodeError> {
    Ok(ModifyResponseTransfer {
        downlink: model["downlink"].as_object().map(|_| {
            let (ip, teid) = endpoint(&model["downlink"]);
            DownlinkTransport::new(ip, teid)
        }),
        uplink: model["uplink"].as_object().map(|_| {
            let (ip, teid) = endpoint(&model["uplink"]);
            UplinkTransport::new(ip, teid)
        }),
        accepted: if model["accepted"].as_array().unwrap().is_empty() {
            None
        } else {
            Some(ModifiedQosFlows::new(
                model["accepted"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(qfi)
                    .collect(),
            )?)
        },
        additional: model["additional"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| {
                let (ip, teid) = endpoint(v);
                DownlinkQosTunnel::new(
                    DownlinkTransport::new(ip, teid),
                    v["flows"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|f| AssociatedQosFlow {
                            qfi: qfi(&f["qfi"]),
                            mapping: match f["mapping"].as_str() {
                                None => None,
                                Some("ul") => Some(QosFlowMapping::Uplink),
                                Some("dl") => Some(QosFlowMapping::Downlink),
                                _ => panic!("reference mapping"),
                            },
                        })
                        .collect(),
                )
            })
            .collect::<Result<_, _>>()?,
        failed: if model["failed"].as_array().unwrap().is_empty() {
            None
        } else {
            Some(QosFlowCauses::new(
                model["failed"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|f| QosFlowCause {
                        qfi: qfi(&f["qfi"]),
                        cause: Cause::new(
                            match f["cause"]["kind"].as_str().unwrap() {
                                "radioNetwork" => CauseClass::RadioNetwork,
                                "transport" => CauseClass::Transport,
                                "nas" => CauseClass::Nas,
                                "protocol" => CauseClass::Protocol,
                                "misc" => CauseClass::Misc,
                                _ => panic!("reference cause"),
                            },
                            f["cause"]["code"].as_u64().unwrap() as u8,
                        )
                        .unwrap(),
                    })
                    .collect(),
            )?)
        },
    })
}

#[test]
fn independent_remaining_tunnels_match_values_encodings_and_exact_limits() {
    let data = oracle();
    let cases = data["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 631);
    let mut admitted = 0;
    for row in cases {
        let name = row["name"].as_str().unwrap();
        let wire = bytes(row["wire_hex"].as_str().unwrap());
        let ctx = DecodeContext {
            max_depth: row["depth"].as_u64().unwrap() as usize,
            max_ies: row["count"].as_u64().unwrap() as usize,
            max_message_len: wire.len(),
            ..context()
        };
        if row["admitted"] == false {
            assert!(
                ModifyResponseTransfer::decode(&wire, ctx).is_err(),
                "{name}"
            );
            assert!(
                response(&row["model"]).map_or(true, |v| v.encode(output()).is_err()),
                "{name}"
            );
            continue;
        }
        admitted += 1;
        macro_rules! check {
            ($value:expr, $decode:expr) => {{
                let value = $value;
                assert!(($decode)(&wire, ctx).unwrap() == value, "{name} values");
                assert_eq!(
                    value
                        .encode(EncodeContext {
                            max_message_len: wire.len(),
                            ..output()
                        })
                        .unwrap()
                        .as_bytes(),
                    wire,
                    "{name} encoding"
                );
                assert!(
                    value
                        .encode(EncodeContext {
                            max_message_len: wire.len() - 1,
                            ..output()
                        })
                        .is_err(),
                    "{name} output limit"
                );
                for short in [
                    DecodeContext {
                        max_depth: ctx.max_depth - 1,
                        ..ctx
                    },
                    DecodeContext {
                        max_ies: ctx.max_ies - 1,
                        ..ctx
                    },
                    DecodeContext {
                        max_message_len: wire.len() - 1,
                        ..ctx
                    },
                ] {
                    assert!(($decode)(&wire, short).is_err(), "{name} short limit");
                }
            }};
        }
        match row["kind"].as_str().unwrap() {
            "PDUSessionResourceSetupRequestTransfer" => {
                check!(setup(&row["model"]), |v: &[u8], c| {
                    SetupRequestTransfer::decode(v, c).map(|v| v.transfer)
                })
            }
            "PDUSessionResourceModifyRequestTransfer" => check!(
                ModifyRequestTransfer {
                    additional_uplink: Some(uplinks(&row["model"])),
                    ..Default::default()
                },
                |v: &[u8], c| ModifyRequestTransfer::decode(v, c).map(|v| v.transfer)
            ),
            "PDUSessionResourceModifyResponseTransfer" => check!(
                response(&row["model"]).unwrap(),
                ModifyResponseTransfer::decode
            ),
            _ => panic!("reference kind"),
        }
        if let Some(hex) = row["leaf_hex"].as_str() {
            let leaf = bytes(hex);
            let value = uplinks(&row["model"]);
            let ctx = DecodeContext {
                max_depth: 5,
                max_ies: value.values().len(),
                max_message_len: leaf.len(),
                ..context()
            };
            assert!(UplinkTransportList::decode(&leaf, ctx).unwrap() == value);
            assert_eq!(
                value
                    .encode(EncodeContext {
                        max_message_len: leaf.len(),
                        ..output()
                    })
                    .unwrap()
                    .as_bytes(),
                leaf
            );
            assert!(value
                .encode(EncodeContext {
                    max_message_len: leaf.len() - 1,
                    ..output()
                })
                .is_err());
            for short in [
                DecodeContext {
                    max_depth: 4,
                    ..ctx
                },
                DecodeContext {
                    max_ies: ctx.max_ies - 1,
                    ..ctx
                },
                DecodeContext {
                    max_message_len: leaf.len() - 1,
                    ..ctx
                },
            ] {
                assert!(UplinkTransportList::decode(&leaf, short).is_err());
            }
            assert_eq!(format!("{value:?}"), "UplinkTransportList([REDACTED])");
            support::exercise(&leaf, context(), output());
        }
        support::exercise(&wire, context(), output());
    }
    assert_eq!(admitted, 625);
}

#[test]
fn complete_requests_and_modify_responses_preserve_additional_tunnels() {
    let data = oracle();
    let messages = data["messages"].as_array().unwrap();
    assert_eq!(messages.len(), 35);
    let mut admitted = 0;
    for row in messages {
        let name = row["kind"].as_str().unwrap();
        let wire = bytes(row["wire_hex"].as_str().unwrap());
        let pdu = Pdu::decode_owned(Bytes::from(wire.clone()), context()).unwrap();
        let ctx = DecodeContext {
            max_depth: row["depth"].as_u64().unwrap() as usize,
            max_message_len: wire.len(),
            ..context()
        };
        let short = DecodeContext {
            max_depth: ctx.max_depth - 1,
            ..ctx
        };
        if name.contains("Modify") {
            let value = ModifyMessage::from_pdu(&pdu, ctx);
            if row["admitted"] == false {
                assert!(value.is_err());
                continue;
            }
            let value = value.unwrap();
            let constructed = match value.message {
                ModifyMessage::Request(v) => {
                    assert!(v.sessions.values()[0].transfer.additional_uplink.is_some());
                    assert!(v.construct(short).is_err());
                    v.construct(ctx).unwrap()
                }
                ModifyMessage::Response(v) => {
                    assert!(!v.modified.as_ref().unwrap().values()[0]
                        .transfer
                        .additional
                        .is_empty());
                    assert!(v.construct(short).is_err());
                    v.construct(ctx).unwrap()
                }
            };
            assert_eq!(encode(&constructed, output()).unwrap(), wire, "{name}");
            assert!(ModifyMessage::from_pdu(&pdu, short).is_err());
        } else {
            let value = ResourceSetupMessage::from_pdu(&pdu, ctx).unwrap();
            let constructed = match value.message {
                ResourceSetupMessage::InitialRequest(v) => {
                    assert!(v.sessions.as_ref().unwrap().values()[0]
                        .transfer
                        .additional_uplink
                        .is_some());
                    let capabilities =
                        opc_proto_ngap::n3iwf::context_fields::SecurityAlgorithmMasks::new(
                            0, 0, 0, 0,
                        );
                    assert!(v.construct(capabilities, short).is_err());
                    v.construct(capabilities, ctx).unwrap()
                }
                ResourceSetupMessage::SessionRequest(v) => {
                    assert!(v.sessions.values()[0].transfer.additional_uplink.is_some());
                    assert!(v.construct(short).is_err());
                    v.construct(ctx).unwrap()
                }
                _ => panic!("reference kind"),
            };
            assert_eq!(encode(&constructed, output()).unwrap(), wire, "{name}");
            assert!(ResourceSetupMessage::from_pdu(&pdu, short).is_err());
        }
        admitted += 1;
    }
    assert_eq!(admitted, 29);
}

#[test]
fn additional_tunnel_bounds_and_adversarial_replay() {
    let endpoint = UplinkTransport::new("198.51.100.1".parse().unwrap(), 1);
    assert!(UplinkTransportList::new(vec![]).is_err());
    assert!(UplinkTransportList::new(vec![endpoint; 4]).is_err());
    let data = oracle();
    let mut mutations = 0;
    for row in data["cases"].as_array().unwrap().iter().step_by(11) {
        let wire = bytes(row["wire_hex"].as_str().unwrap());
        let mut trailing = wire.clone();
        trailing.push(0);
        match row["kind"].as_str().unwrap() {
            "PDUSessionResourceSetupRequestTransfer" => {
                assert!(SetupRequestTransfer::decode(&trailing, context()).is_err())
            }
            "PDUSessionResourceModifyRequestTransfer" => {
                assert!(ModifyRequestTransfer::decode(&trailing, context()).is_err())
            }
            _ => assert!(ModifyResponseTransfer::decode(&trailing, context()).is_err()),
        }
        if let Some(hex) = row["leaf_hex"].as_str() {
            let leaf = bytes(hex);
            for mask in [0x20, 0x10, 0x08, 0x04, 0x02, 0x01] {
                let mut changed = leaf.clone();
                changed[0] |= mask;
                assert!(UplinkTransportList::decode(&changed, context()).is_err());
            }
            let mut changed = leaf.clone();
            changed[0] |= 0xc0;
            assert!(UplinkTransportList::decode(&changed, context()).is_err());
            changed = leaf;
            changed[1] = 159;
            assert!(UplinkTransportList::decode(&changed, context()).is_err());
        }
        for length in 0..wire.len() {
            match row["kind"].as_str().unwrap() {
                "PDUSessionResourceSetupRequestTransfer" => {
                    assert!(SetupRequestTransfer::decode(&wire[..length], context()).is_err())
                }
                "PDUSessionResourceModifyRequestTransfer" => {
                    assert!(ModifyRequestTransfer::decode(&wire[..length], context()).is_err())
                }
                _ => assert!(ModifyResponseTransfer::decode(&wire[..length], context()).is_err()),
            }
        }
        for index in 0..wire.len() {
            for mask in [1, 0x80, 0xff] {
                let mut changed = wire.clone();
                changed[index] ^= mask;
                support::exercise(&changed, context(), output());
                mutations += 1;
            }
        }
    }
    assert!(mutations > 10000);
    println!("{mutations} deterministic tunnel mutations");
    let case = data["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["name"] == "mapping-0-None")
        .unwrap();
    let mut value = response(&case["model"]).unwrap();
    value.additional = vec![value.additional[0].clone(); 4];
    assert!(value.encode(output()).is_err());
}
