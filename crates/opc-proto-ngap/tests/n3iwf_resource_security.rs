#![allow(clippy::unwrap_used)]
use opc_proto_ngap::n3iwf::resource_request::SetupRequestTransfer;
use opc_proto_ngap::n3iwf::resource_results::SetupResponseTransfer;
use opc_protocol::{
    DecodeContext, DuplicateIePolicy, EncodeContext, UnknownIePolicy, ValidationLevel,
};
use serde_json::Value;

fn reference() -> Value {
    serde_json::from_str(include_str!("fixtures/n3iwf-resource-security.json")).unwrap()
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
        max_depth: 24,
        max_ies: 256,
        duplicate_ie_policy: DuplicateIePolicy::Reject,
        validation_level: ValidationLevel::Strict,
        ..DecodeContext::default()
    }
}

#[test]
fn independent_security_requests_have_expected_admission() {
    let oracle = reference();
    for row in oracle["requests"].as_array().unwrap() {
        let wire = bytes(row["wire_hex"].as_str().unwrap());
        assert_eq!(
            SetupRequestTransfer::decode(&wire, context()).is_ok(),
            row["admit"].as_bool().unwrap(),
            "{}",
            row["name"]
        );
    }
}

use opc_proto_ngap::n3iwf::context_fields::SecurityAlgorithmMasks;
use opc_proto_ngap::n3iwf::release::{Cause, CauseClass};
use opc_proto_ngap::n3iwf::resource_fields::{
    DownlinkTransport, NonGbrFlow, QosFlowId, QosFlowSetupList, SessionAggregateBitRate,
    SessionType, UplinkTransport,
};
use opc_proto_ngap::n3iwf::resource_results::FailedQosFlow;
use opc_proto_ngap::n3iwf::resource_setup::ResourceSetupMessage;
use opc_proto_ngap::n3iwf::security_fields::{
    MaximumIntegrityRate, NetworkInstance, ProtectionRequirement, SecurityIndication,
    SecurityResult,
};
use opc_proto_ngap::{decode, encode};
use std::collections::BTreeSet;

#[path = "support/resource_setup.rs"]
mod resource_setup;
use resource_setup::resource_security;

fn indication(model: &Value) -> Result<SecurityIndication, opc_protocol::DecodeError> {
    let rate = model["rate"].as_u64().unwrap() as u8;
    SecurityIndication::new(
        ProtectionRequirement::new(model["integrity"].as_u64().unwrap() as u8)?,
        ProtectionRequirement::new(model["confidentiality"].as_u64().unwrap() as u8)?,
        if rate == 0 {
            None
        } else {
            Some(MaximumIntegrityRate::new(rate - 1)?)
        },
    )
}
fn result(model: &Value) -> SecurityResult {
    SecurityResult::new(model["integrity"] == 0, model["confidentiality"] == 0)
}
fn request(model: &Value) -> Result<SetupRequestTransfer, opc_protocol::DecodeError> {
    Ok(SetupRequestTransfer {
        additional_uplink: None,
        uplink: UplinkTransport::new("198.51.100.17".parse().unwrap(), 0x11223344),
        aggregate_bit_rate: Some(SessionAggregateBitRate::new(1_000_000, 2_000_000)?),
        session_type: SessionType::Ipv4,
        flows: QosFlowSetupList::new(vec![NonGbrFlow::new(QosFlowId::new(9)?, 8, false, false)?])?,
        security: model.get("security").map(indication).transpose()?,
        network_instance: model["network"]
            .as_u64()
            .map(|v| NetworkInstance::new(v as u16))
            .transpose()?,
        common_network_instance: None,
    })
}
fn response(model: &Value) -> SetupResponseTransfer {
    SetupResponseTransfer::new(
        DownlinkTransport::new(
            model["address"]
                .as_str()
                .unwrap_or("198.51.100.17")
                .parse()
                .unwrap(),
            0x11223344,
        ),
        model["accepted"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| QosFlowId::new(v.as_u64().unwrap() as u8).unwrap())
            .collect(),
        model["failed"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| FailedQosFlow {
                qfi: QosFlowId::new(v["qfi"].as_u64().unwrap() as u8).unwrap(),
                cause: Cause::new(
                    match v["cause"]["class_"].as_str().unwrap() {
                        "radioNetwork" => CauseClass::RadioNetwork,
                        "transport" => CauseClass::Transport,
                        "nas" => CauseClass::Nas,
                        "protocol" => CauseClass::Protocol,
                        "misc" => CauseClass::Misc,
                        _ => panic!("reference cause class"),
                    },
                    v["cause"]["code"].as_u64().unwrap() as u8,
                )
                .unwrap(),
            })
            .collect(),
    )
    .unwrap()
    .with_security_result(Some(result(&model["security"])))
}

#[test]
fn independent_leaf_values_and_every_fixed_root_pattern_match() {
    let oracle = reference();
    let fields = oracle["fields"].as_array().unwrap();
    assert_eq!(fields.len(), 287);
    let mut indication_roots = BTreeSet::new();
    let mut network_roots = BTreeSet::new();
    let mut result_roots = BTreeSet::new();
    for row in fields {
        let raw = bytes(row["wire_hex"].as_str().unwrap());
        let admit = row["admit"].as_bool().unwrap();
        let model = &row["model"];
        let kind = row["kind"].as_str().unwrap();
        let ctx = DecodeContext {
            max_message_len: raw.len(),
            max_depth: if kind == "NetworkInstance" { 1 } else { 2 },
            ..context()
        };
        let output = EncodeContext {
            max_message_len: raw.len(),
            ..EncodeContext::default()
        };
        let short = EncodeContext {
            max_message_len: raw.len() - 1,
            ..output
        };
        let encoded = match kind {
            "SecurityIndication" => {
                let expected = indication(model);
                let received = SecurityIndication::decode(&raw, ctx);
                assert_eq!(expected.is_ok(), admit);
                assert_eq!(received.is_ok(), admit);
                if !admit {
                    continue;
                }
                let expected = expected.unwrap();
                assert!(received.unwrap() == expected);
                assert_eq!(
                    expected.integrity().value(),
                    model["integrity"].as_u64().unwrap() as u8
                );
                assert_eq!(
                    expected.confidentiality().value(),
                    model["confidentiality"].as_u64().unwrap() as u8
                );
                assert_eq!(
                    expected.uplink_rate().map_or(0, |r| r.value() + 1),
                    model["rate"].as_u64().unwrap() as u8
                );
                assert!(expected.encode(short).is_err());
                assert!(SecurityIndication::decode(
                    &raw,
                    DecodeContext {
                        max_depth: 1,
                        ..ctx
                    }
                )
                .is_err());
                indication_roots.insert(raw.clone());
                expected.encode(output).unwrap()
            }
            "SecurityResult" => {
                let expected = result(model);
                assert!(SecurityResult::decode(&raw, ctx).unwrap() == expected);
                assert_eq!(expected.integrity_performed(), model["integrity"] == 0);
                assert_eq!(
                    expected.confidentiality_performed(),
                    model["confidentiality"] == 0
                );
                assert!(expected.encode(short).is_err());
                assert!(SecurityResult::decode(
                    &raw,
                    DecodeContext {
                        max_depth: 1,
                        ..ctx
                    }
                )
                .is_err());
                result_roots.insert(raw.clone());
                expected.encode(output).unwrap()
            }
            "NetworkInstance" => {
                let expected = NetworkInstance::new(model.as_u64().unwrap() as u16).unwrap();
                assert!(NetworkInstance::decode(&raw, ctx).unwrap() == expected);
                assert_eq!(expected.value(), model.as_u64().unwrap() as u16);
                assert!(expected.encode(short).is_err());
                assert!(NetworkInstance::decode(
                    &raw,
                    DecodeContext {
                        max_depth: 0,
                        ..ctx
                    }
                )
                .is_err());
                network_roots.insert(raw.clone());
                expected.encode(output).unwrap()
            }
            _ => panic!("reference leaf kind"),
        };
        assert!(encoded.as_bytes() == raw);
        let too_short = DecodeContext {
            max_message_len: raw.len() - 1,
            ..ctx
        };
        assert!(match kind {
            "SecurityIndication" => SecurityIndication::decode(&raw, too_short).is_err(),
            "SecurityResult" => SecurityResult::decode(&raw, too_short).is_err(),
            "NetworkInstance" => NetworkInstance::decode(&raw, too_short).is_err(),
            _ => unreachable!(),
        });
        for length in 0..raw.len() {
            resource_security::exercise(&raw[..length], context(), EncodeContext::default());
        }
    }
    assert_eq!(
        (
            indication_roots.len(),
            network_roots.len(),
            result_roots.len()
        ),
        (21, 256, 4)
    );
    for value in 0..=u16::MAX {
        let raw = value.to_be_bytes();
        assert_eq!(
            SecurityIndication::decode(&raw, context()).is_ok(),
            indication_roots.contains(raw.as_slice())
        );
        assert_eq!(
            NetworkInstance::decode(&raw, context()).is_ok(),
            network_roots.contains(raw.as_slice())
        );
    }
    for value in 0..=u8::MAX {
        assert_eq!(
            SecurityResult::decode(&[value], context()).is_ok(),
            result_roots.contains([value].as_slice())
        );
    }
    for bad in [0, 257, u16::MAX] {
        assert!(NetworkInstance::new(bad).is_err());
    }
    for bad in 3..=u8::MAX {
        assert!(ProtectionRequirement::new(bad).is_err());
    }
    for bad in 2..=u8::MAX {
        assert!(MaximumIntegrityRate::new(bad).is_err());
    }
    for raw in [vec![], vec![0, 0, 0], vec![0, 0, 0, 0]] {
        assert!(SecurityIndication::decode(&raw, context()).is_err());
        assert!(NetworkInstance::decode(&raw, context()).is_err());
        assert!(SecurityResult::decode(&raw, context()).is_err());
    }
    assert_eq!(
        format!(
            "{:?}",
            result(&serde_json::json!({"integrity":0,"confidentiality":1}))
        ),
        "SecurityResult([REDACTED])"
    );
    assert_eq!(
        format!("{:?}", NetworkInstance::new(256).unwrap()),
        "NetworkInstance([REDACTED])"
    );
}

#[test]
fn request_selection_receiver_ignore_and_construction_preserve_semantics() {
    let oracle = reference();
    assert_eq!(oracle["requests"].as_array().unwrap().len(), 375);
    for row in oracle["requests"].as_array().unwrap() {
        let raw = bytes(row["wire_hex"].as_str().unwrap());
        let received = SetupRequestTransfer::decode(&raw, context());
        if row["admit"] == true {
            let expected = request(&row["model"]).unwrap();
            let received = received.unwrap();
            assert!(received.transfer == expected, "{}", row["name"]);
            assert_eq!(
                received.ignored_ie_count,
                row["receiver_ignored"].as_u64().unwrap() as usize
                    + usize::from(row["unknown"] == "ignore")
            );
            assert_eq!(
                received.notify_ie_ids,
                if row["unknown"] == "notify" {
                    vec![65530]
                } else {
                    vec![]
                }
            );
            let canonical = bytes(row["canonical_wire_hex"].as_str().unwrap());
            assert!(
                expected
                    .encode(EncodeContext::default())
                    .unwrap()
                    .as_bytes()
                    == canonical,
                "{}",
                row["name"]
            );
            assert!(expected
                .encode(EncodeContext {
                    max_message_len: canonical.len() - 1,
                    ..EncodeContext::default()
                })
                .is_err());
            for ctx in [
                DecodeContext {
                    max_depth: 9,
                    ..context()
                },
                DecodeContext {
                    max_ies: usize::from(u16::from_be_bytes([raw[1], raw[2]])) - 1,
                    ..context()
                },
                DecodeContext {
                    max_message_len: raw.len() - 1,
                    ..context()
                },
            ] {
                assert!(SetupRequestTransfer::decode(&raw, ctx).is_err());
            }
        } else {
            assert!(received.is_err());
        }
        if row.get("duplicate").is_some() {
            for duplicate_ie_policy in [DuplicateIePolicy::First, DuplicateIePolicy::Last] {
                let received = SetupRequestTransfer::decode(
                    &raw,
                    DecodeContext {
                        duplicate_ie_policy,
                        ..context()
                    },
                );
                if duplicate_ie_policy == DuplicateIePolicy::Last && row["last_reject"] == true {
                    assert!(received.is_err());
                } else {
                    let model = if duplicate_ie_policy == DuplicateIePolicy::First {
                        &row["model"]
                    } else {
                        &row["last_model"]
                    };
                    let received = received.unwrap();
                    assert!(received.transfer == request(model).unwrap());
                    assert_eq!(received.ignored_ie_count, 1);
                }
            }
        }
        if row.get("unknown").is_some() {
            assert!(SetupRequestTransfer::decode(
                &raw,
                DecodeContext {
                    unknown_ie_policy: UnknownIePolicy::Reject,
                    ..context()
                }
            )
            .is_err());
            if row["unknown"] != "reject" {
                let discarded = SetupRequestTransfer::decode(
                    &raw,
                    DecodeContext {
                        unknown_ie_policy: UnknownIePolicy::Drop,
                        ..context()
                    },
                )
                .unwrap();
                assert!(discarded.transfer == request(&row["model"]).unwrap());
                assert_eq!(discarded.ignored_ie_count, 1); // Known receiver-ignore survives unknown Drop.
                assert!(discarded.notify_ie_ids.is_empty());
            }
        }
    }
}

#[test]
fn response_results_match_independent_bytes_at_every_list_count_and_bit_offset() {
    let oracle = reference();
    assert_eq!(oracle["responses"].as_array().unwrap().len(), 1536);
    for row in oracle["responses"].as_array().unwrap() {
        let raw = bytes(row["wire_hex"].as_str().unwrap());
        let expected = response(&row["model"]);
        let count = expected.accepted().len() + expected.failed().len();
        let ctx = DecodeContext {
            max_depth: 6,
            max_ies: count,
            max_message_len: raw.len(),
            ..context()
        };
        assert!(
            SetupResponseTransfer::decode(&raw, ctx).unwrap() == expected,
            "{}",
            row["name"]
        );
        assert!(
            expected
                .encode(EncodeContext {
                    max_message_len: raw.len(),
                    ..EncodeContext::default()
                })
                .unwrap()
                .as_bytes()
                == raw,
            "{}",
            row["name"]
        );
        assert!(expected
            .encode(EncodeContext {
                max_message_len: raw.len() - 1,
                ..EncodeContext::default()
            })
            .is_err());
        for ctx in [
            DecodeContext {
                max_ies: count - 1,
                ..ctx
            },
            DecodeContext {
                max_depth: 5,
                ..ctx
            },
            DecodeContext {
                max_message_len: raw.len() - 1,
                ..ctx
            },
        ] {
            assert!(SetupResponseTransfer::decode(&raw, ctx).is_err());
        }
        let without_report = expected.clone().with_security_result(None);
        assert!(without_report.security_result().is_none());
        for mask in [0x80, 0x40, 0x08] {
            let mut changed = raw.clone();
            changed[0] |= mask;
            assert!(SetupResponseTransfer::decode(&changed, context()).is_err());
        }
    }
}

#[test]
fn nested_initial_context_and_session_setup_preserve_security_fields() {
    let oracle = reference();
    assert_eq!(oracle["messages"].as_array().unwrap().len(), 108);
    for row in oracle["messages"].as_array().unwrap() {
        let raw = bytes(row["wire_hex"].as_str().unwrap());
        let pdu = decode(&raw, context()).unwrap();
        let received = ResourceSetupMessage::from_pdu(&pdu, context());
        if row["admit"] == false {
            assert!(received.is_err(), "{}", row["name"]);
            continue;
        }
        let received = received.unwrap();
        let constructed = match &received.message {
            ResourceSetupMessage::InitialRequest(v) => {
                assert!(
                    v.sessions.as_ref().unwrap().values()[0].transfer
                        == request(&row["model"]).unwrap()
                );
                v.construct(SecurityAlgorithmMasks::new(0, 0, 0, 0), context())
            }
            ResourceSetupMessage::SessionRequest(v) => {
                assert!(v.sessions.values()[0].transfer == request(&row["model"]).unwrap());
                v.construct(context())
            }
            ResourceSetupMessage::InitialResponse(v) => {
                assert!(
                    v.sessions.successful().unwrap().values()[0].transfer
                        == response(&row["model"])
                );
                v.construct(context())
            }
            ResourceSetupMessage::SessionResponse(v) => {
                assert!(
                    v.sessions.successful().unwrap().values()[0].transfer
                        == response(&row["model"])
                );
                v.construct(context())
            }
            _ => panic!("reference setup message kind"),
        }
        .unwrap();
        assert!(
            encode(&constructed, EncodeContext::default()).unwrap()
                == bytes(row["canonical_wire_hex"].as_str().unwrap()),
            "{}",
            row["name"]
        );
        resource_setup::exercise(&raw, context(), EncodeContext::default());
    }
}

#[test]
fn leaf_transfer_and_nested_mutations_remain_bounded() {
    let oracle = reference();
    let output = EncodeContext {
        max_message_len: 131072,
        ..EncodeContext::default()
    };
    let mut mutations = 0;
    for category in ["fields", "requests", "responses", "messages"] {
        for (index, row) in oracle[category].as_array().unwrap().iter().enumerate() {
            let raw = bytes(row["wire_hex"].as_str().unwrap());
            for ctx in [
                context(),
                DecodeContext {
                    max_depth: 6,
                    max_ies: 4,
                    ..context()
                },
            ] {
                resource_setup::exercise_bounded(&raw, ctx, output);
                // Every corpus case is replayed. Large response count/cause
                // grids share a shape; select every sixteenth for mutations.
                if category == "responses" && index % 16 != 0 {
                    continue;
                }
                let stride = (raw.len() / 48).max(1);
                for offset in (0..raw.len()).step_by(stride) {
                    resource_setup::exercise_bounded(&raw[..offset], ctx, output);
                    mutations += 1;
                    for mask in [1, 0x80, 0xff] {
                        let mut changed = raw.clone();
                        changed[offset] ^= mask;
                        resource_setup::exercise_bounded(&changed, ctx, output);
                        mutations += 1;
                    }
                }
            }
        }
    }
    eprintln!("Replayed {mutations} deterministic mutations across two bounded contexts");
}

#[test]
fn independent_security_responses_have_expected_admission() {
    let oracle = reference();
    for row in oracle["responses"].as_array().unwrap() {
        let wire = bytes(row["wire_hex"].as_str().unwrap());
        assert_eq!(
            SetupResponseTransfer::decode(&wire, context()).is_ok(),
            row["admit"].as_bool().unwrap(),
            "{}",
            row["name"]
        );
    }
}
