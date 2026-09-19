use opc_proto_ngap::n3iwf::modify_fields::{QosFlowModification, QosFlowModifications};
use opc_proto_ngap::n3iwf::qos_fields::*;
use opc_proto_ngap::n3iwf::resource_fields::QosFlowId;
use opc_proto_ngap::n3iwf::resource_fields::QosFlowSetupList;
use opc_protocol::{DecodeContext, EncodeContext};
use serde_json::Value;

fn corpus() -> Value {
    serde_json::from_str(include_str!("fixtures/n3iwf-qos-profiles.json")).unwrap()
}

#[path = "support/qos_models.rs"]
mod models;
use models::{flow, parameters};

fn modifications(model: &Value) -> Result<QosFlowModifications, opc_protocol::DecodeError> {
    QosFlowModifications::new(
        model
            .as_array()
            .unwrap()
            .iter()
            .map(|v| {
                if v.get("parameters").is_some() {
                    QosFlowModification::Profile(flow(v))
                } else {
                    let qfi = QosFlowId::new(v["qfi"].as_u64().unwrap() as u8).unwrap();
                    match v["erab"].as_u64() {
                        Some(erab) => QosFlowModification::IdentifierWithErab {
                            qfi,
                            erab: erab as u8,
                        },
                        None => QosFlowModification::Identifier(qfi),
                    }
                }
            })
            .collect(),
    )
}

#[test]
fn independently_encoded_qos_profiles_are_admitted() {
    let corpus = corpus();
    for row in corpus["cases"].as_array().unwrap() {
        if row["type"] != "QosFlowSetupRequestList" || row["accept"] != true {
            continue;
        }
        let wire = unhex(row["wire_hex"].as_str().unwrap());
        assert!(
            QosFlowSetupList::decode(&wire, DecodeContext::default()).is_ok(),
            "independent root QoS profile was not admitted: {}",
            row["name"]
        );
    }
}

#[test]
fn independent_values_construction_and_exact_bounds() {
    let corpus = corpus();
    assert_eq!(corpus["cases"].as_array().unwrap().len(), 5060);
    for row in corpus["cases"].as_array().unwrap() {
        let wire = unhex(row["wire_hex"].as_str().unwrap());
        let model = &row["model"];
        let kind = row["type"].as_str().unwrap();
        let field = kind == "QosFlowLevelQosParameters";
        let count = if field {
            1
        } else {
            model.as_array().unwrap().len()
        };
        let dynamic = if field {
            model["descriptor"]["kind"] == "dynamic"
        } else {
            model
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v["parameters"]["descriptor"]["kind"] == "dynamic")
        };
        let identifiers_only = !field
            && model
                .as_array()
                .unwrap()
                .iter()
                .all(|v| v.get("parameters").is_none());
        let depth = if field {
            4
        } else if identifiers_only {
            3
        } else {
            6
        } + usize::from(dynamic);
        let ctx = DecodeContext {
            max_depth: depth,
            max_ies: count,
            max_message_len: wire.len(),
            ..DecodeContext::default()
        };
        macro_rules! check {
            ($ty:ty,$expected:expr) => {{
                let expected = $expected;
                if row["accept"] == false {
                    assert!(expected.is_err());
                    assert!(<$ty>::decode(&wire, ctx).is_err());
                    continue;
                }
                let expected = expected.unwrap();
                let decoded = <$ty>::decode(&wire, ctx)
                    .unwrap_or_else(|_| panic!("independent decode failed: {}", row["name"]));
                assert!(
                    decoded == expected,
                    "independent values differ: {}",
                    row["name"]
                );
                let output = expected
                    .encode(EncodeContext {
                        max_message_len: wire.len(),
                        ..EncodeContext::default()
                    })
                    .unwrap();
                assert!(
                    output.as_bytes() == wire,
                    "independent bytes differ: {}",
                    row["name"]
                );
                assert!(expected
                    .encode(EncodeContext {
                        max_message_len: wire.len() - 1,
                        ..EncodeContext::default()
                    })
                    .is_err());
                assert!(<$ty>::decode(
                    &wire,
                    DecodeContext {
                        max_message_len: wire.len() - 1,
                        ..ctx
                    }
                )
                .is_err());
                assert!(<$ty>::decode(
                    &wire,
                    DecodeContext {
                        max_depth: depth - 1,
                        ..ctx
                    }
                )
                .is_err());
                if !field {
                    assert!(<$ty>::decode(
                        &wire,
                        DecodeContext {
                            max_ies: count - 1,
                            ..ctx
                        }
                    )
                    .is_err());
                }
                let mut tail = wire.clone();
                tail.push(0);
                assert!(<$ty>::decode(
                    &tail,
                    DecodeContext {
                        max_message_len: tail.len(),
                        ..ctx
                    }
                )
                .is_err());
                assert!(format!("{decoded:?}").contains("REDACTED"));
            }};
        }
        match kind {
            "QosFlowLevelQosParameters" => check!(
                QosParameters,
                Ok::<_, opc_protocol::DecodeError>(parameters(model))
            ),
            "QosFlowSetupRequestList" => check!(
                QosFlowSetupList,
                QosFlowSetupList::with_profiles(
                    model.as_array().unwrap().iter().map(flow).collect()
                )
            ),
            "QosFlowAddOrModifyRequestList" => check!(QosFlowModifications, modifications(model)),
            _ => panic!("unknown corpus field"),
        }
    }
}

#[test]
fn independent_conditional_failures_preserve_ignored_request_fields() {
    let corpus = corpus();
    for row in corpus["cases"].as_array().unwrap() {
        if row["type"] != "QosFlowLevelQosParameters" {
            continue;
        }
        let raw = QosParameters::decode(
            &unhex(row["wire_hex"].as_str().unwrap()),
            DecodeContext::default(),
        )
        .unwrap();
        for (name, resource_type) in [
            ("non_gbr", QosResourceType::NonGbr),
            ("gbr", QosResourceType::Gbr),
        ] {
            let result = raw.applicable(resource_type);
            let outcome = match result {
                Ok(value) => {
                    assert!(value.requested() == raw);
                    if resource_type == QosResourceType::NonGbr {
                        assert!(value.gbr().is_none());
                        assert_eq!(value.reflective(), raw.reflective());
                        assert_eq!(value.additional(), raw.additional());
                    } else {
                        assert!(!value.reflective() && !value.additional());
                        assert!(!value.gbr().unwrap().notification_control);
                    }
                    "admitted"
                }
                Err(QosConditionFailure::MissingGbrInformation) => "missing-gbr",
                Err(QosConditionFailure::MissingDelayCritical) => "missing-delay-critical",
                Err(QosConditionFailure::MissingAveragingWindow) => "missing-window",
                Err(QosConditionFailure::MissingMaximumDataBurst) => "missing-burst",
            };
            assert_eq!(
                outcome, row["resource_conditions"][name],
                "independent condition differs: {}",
                row["name"]
            );
        }
    }
}

#[test]
fn public_constructor_bounds_and_redaction_do_not_depend_on_wire_validation() {
    let arp = AllocationRetentionPriority::new(8, true, false).unwrap();
    for priority in [0, 16, u8::MAX] {
        assert!(AllocationRetentionPriority::new(priority, false, false).is_err());
    }
    let root = NonDynamicQos {
        five_qi: 9,
        priority: None,
        averaging_window: None,
        maximum_data_burst: None,
    };
    for bad in [
        NonDynamicQos {
            priority: Some(0),
            ..root
        },
        NonDynamicQos {
            priority: Some(128),
            ..root
        },
        NonDynamicQos {
            averaging_window: Some(4096),
            ..root
        },
        NonDynamicQos {
            maximum_data_burst: Some(4096),
            ..root
        },
    ] {
        assert!(QosParameters::new(QosCharacteristics::NonDynamic(bad), arp).is_err());
    }
    let dynamic = DynamicQos {
        priority: 1,
        packet_delay_budget: 0,
        error_scalar: 0,
        error_exponent: 0,
        five_qi: None,
        delay_critical: None,
        averaging_window: None,
        maximum_data_burst: None,
    };
    for bad in [
        DynamicQos {
            priority: 0,
            ..dynamic
        },
        DynamicQos {
            priority: 128,
            ..dynamic
        },
        DynamicQos {
            packet_delay_budget: 1024,
            ..dynamic
        },
        DynamicQos {
            error_scalar: 10,
            ..dynamic
        },
        DynamicQos {
            error_exponent: 10,
            ..dynamic
        },
        DynamicQos {
            averaging_window: Some(4096),
            ..dynamic
        },
        DynamicQos {
            maximum_data_burst: Some(4096),
            ..dynamic
        },
    ] {
        assert!(QosParameters::new(QosCharacteristics::Dynamic(bad), arp).is_err());
    }
    let p = QosParameters::new(QosCharacteristics::NonDynamic(root), arp).unwrap();
    let gbr = GbrQosInformation {
        maximum_downlink: 0,
        maximum_uplink: 0,
        guaranteed_downlink: 0,
        guaranteed_uplink: 0,
        notification_control: false,
        maximum_packet_loss_downlink: None,
        maximum_packet_loss_uplink: None,
    };
    for bad in [
        GbrQosInformation {
            maximum_downlink: 4_000_000_000_001,
            ..gbr
        },
        GbrQosInformation {
            maximum_uplink: 4_000_000_000_001,
            ..gbr
        },
        GbrQosInformation {
            guaranteed_downlink: 4_000_000_000_001,
            ..gbr
        },
        GbrQosInformation {
            guaranteed_uplink: 4_000_000_000_001,
            ..gbr
        },
        GbrQosInformation {
            maximum_packet_loss_downlink: Some(1001),
            ..gbr
        },
        GbrQosInformation {
            maximum_packet_loss_uplink: Some(1001),
            ..gbr
        },
    ] {
        assert!(p.with_gbr(Some(bad)).is_err());
    }
    let qfi = QosFlowId::new(63).unwrap();
    let f = QosFlow::new(qfi, p);
    assert!(f.with_erab(Some(16)).is_err());
    assert!(
        QosFlowModifications::new(vec![QosFlowModification::IdentifierWithErab {
            qfi,
            erab: 16
        }])
        .is_err()
    );
    assert!(QosFlowSetupList::with_profiles(vec![f, f]).is_err());
    assert!(QosFlowSetupList::with_profiles(vec![]).is_err());
    assert!(QosFlowSetupList::with_profiles(vec![f; 65]).is_err());
    for value in [
        format!("{root:?}"),
        format!("{dynamic:#?}"),
        format!("{gbr:?}"),
        format!("{p:?}"),
        format!("{f:#?}"),
        format!("{arp:?}"),
        format!("{:?}", p.applicable(QosResourceType::NonGbr).unwrap()),
    ] {
        assert!(value.contains("REDACTED"));
        assert!(!value.chars().any(|c| c.is_ascii_digit()));
    }
}

#[path = "support/qos_profiles.rs"]
mod shared;

#[test]
fn bounded_mutations_and_truncations_preserve_validated_values() {
    let corpus = corpus();
    let mut mutations = 0;
    for row in corpus["cases"].as_array().unwrap() {
        let wire = unhex(row["wire_hex"].as_str().unwrap());
        shared::exercise(&wire, DecodeContext::default(), EncodeContext::default());
        // Complete root fields and three-item mixed lists exercise every bit offset.
        if row["type"] != "QosFlowLevelQosParameters"
            && !row["name"].as_str().unwrap().ends_with("-3")
        {
            continue;
        }
        for len in 0..wire.len() {
            shared::exercise(
                &wire[..len],
                DecodeContext::default(),
                EncodeContext::default(),
            );
        }
        for index in 0..wire.len() {
            for mask in [1, 0x80, 0xff] {
                let mut changed = wire.clone();
                changed[index] ^= mask;
                shared::exercise(&changed, DecodeContext::default(), EncodeContext::default());
                mutations += 1;
            }
        }
    }
    assert!(mutations > 200_000);
}

fn unhex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}
