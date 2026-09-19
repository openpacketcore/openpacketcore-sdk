use opc_proto_ngap::n3iwf::context_fields::SecurityAlgorithmMasks;
use opc_proto_ngap::n3iwf::qos_fields::{QosConditionFailure, QosResourceType, QosResourceTypes};
use opc_proto_ngap::n3iwf::resource_fields::{
    QosFlowId, QosFlowSetupList, SessionAggregateBitRate, SessionType, UplinkTransport,
};
use opc_proto_ngap::n3iwf::resource_request::SetupRequestTransfer;
use opc_proto_ngap::n3iwf::resource_setup::ResourceSetupMessage;
use opc_proto_ngap::n3iwf::session_lists::{SessionId, SessionResourceTypes};
use opc_proto_ngap::{decode, encode};
use opc_protocol::{DecodeContext, DuplicateIePolicy, EncodeContext, ValidationLevel};
use serde_json::Value;

#[path = "support/qos_models.rs"]
mod models;

fn reference() -> Value {
    serde_json::from_str(include_str!("fixtures/n3iwf-qos-admission.json")).unwrap()
}
fn bytes(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}
fn context() -> DecodeContext {
    DecodeContext {
        max_depth: 18,
        max_ies: 256,
        max_message_len: 200_000,
        duplicate_ie_policy: DuplicateIePolicy::Reject,
        validation_level: ValidationLevel::Strict,
        ..DecodeContext::default()
    }
}
fn output() -> EncodeContext {
    EncodeContext {
        max_message_len: 200_000,
        ..EncodeContext::default()
    }
}
fn resource_type(value: &Value) -> QosResourceType {
    match value.as_str().unwrap() {
        "gbr" => QosResourceType::Gbr,
        "non_gbr" => QosResourceType::NonGbr,
        _ => panic!("independent classification"),
    }
}
fn types(row: &Value) -> QosResourceTypes {
    QosResourceTypes::new(row["flows"].as_array().unwrap().iter().map(|flow| {
        (
            QosFlowId::new(flow["qfi"].as_u64().unwrap() as u8).unwrap(),
            resource_type(&flow["resource_type"]),
        )
    }))
    .unwrap()
}
fn session_types(row: &Value) -> SessionResourceTypes {
    SessionResourceTypes::new(vec![
        (SessionId::new(1), types(row)),
        (
            SessionId::new(255),
            QosResourceTypes::new([(QosFlowId::new(0).unwrap(), QosResourceType::NonGbr)]).unwrap(),
        ),
    ])
    .unwrap()
}
fn transfer(row: &Value) -> SetupRequestTransfer {
    SetupRequestTransfer {
        uplink: UplinkTransport::new("198.51.100.17".parse().unwrap(), 0x11223344),
        aggregate_bit_rate: row["ambr"]
            .as_bool()
            .unwrap()
            .then(|| SessionAggregateBitRate::new(1_000_000, 2_000_000).unwrap()),
        session_type: SessionType::Ipv4,
        flows: QosFlowSetupList::with_profiles(
            row["flows"]
                .as_array()
                .unwrap()
                .iter()
                .map(models::flow)
                .collect(),
        )
        .unwrap(),
        security: None,
        network_instance: None,
        common_network_instance: None,
    }
}

#[test]
fn independently_encoded_session_ambr_conditions_and_flow_failures() {
    let corpus = reference();
    assert_eq!(corpus["transfers"].as_array().unwrap().len(), 224);
    for row in corpus["transfers"].as_array().unwrap() {
        let raw = bytes(row["wire_hex"].as_str().unwrap());
        let expected = transfer(row);
        let types = types(row);
        let admitted = row["admit"].as_bool().unwrap();
        let ambr = row["ambr"].as_bool().unwrap();
        let decoded = SetupRequestTransfer::decode_classified(&raw, &types, context());
        assert_eq!(decoded.is_ok(), admitted, "{}", row["name"]);
        assert_eq!(
            expected.encode_classified(&types, output()).is_ok(),
            admitted
        );
        assert_eq!(SetupRequestTransfer::decode(&raw, context()).is_ok(), ambr);
        assert_eq!(expected.encode(output()).is_ok(), ambr);
        // A per-flow conditional failure remains distinguishable from the
        // session-level missing-AMBR failure, so other flows can succeed.
        for (flow, condition) in expected
            .flows
            .values()
            .iter()
            .zip(row["flow_conditions"].as_array().unwrap())
        {
            let result = flow.parameters().applicable(types.get(flow.qfi()).unwrap());
            let actual = match result {
                Ok(_) => "admitted",
                Err(QosConditionFailure::MissingGbrInformation) => "missing-gbr",
                Err(QosConditionFailure::MissingDelayCritical) => "missing-delay-critical",
                Err(QosConditionFailure::MissingAveragingWindow) => "missing-window",
                Err(QosConditionFailure::MissingMaximumDataBurst) => "missing-burst",
            };
            assert_eq!(actual, condition.as_str().unwrap());
        }
        if !admitted {
            continue;
        }
        let decoded = decoded.unwrap();
        assert!(decoded.transfer == expected);
        assert_eq!(decoded.ignored_ie_count, 0);
        assert!(decoded.notify_ie_ids.is_empty());
        assert_eq!(
            expected
                .encode_classified(&types, output())
                .unwrap()
                .as_bytes(),
            raw
        );
        let dynamic = row["flows"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["parameters"]["descriptor"]["kind"] == "dynamic");
        let exact = DecodeContext {
            max_depth: 10 + usize::from(dynamic),
            max_ies: expected.flows.values().len().max(if ambr { 4 } else { 3 }),
            max_message_len: raw.len(),
            ..context()
        };
        assert!(SetupRequestTransfer::decode_classified(&raw, &types, exact).is_ok());
        for too_small in [
            DecodeContext {
                max_depth: exact.max_depth - 1,
                ..exact
            },
            DecodeContext {
                max_ies: exact.max_ies - 1,
                ..exact
            },
            DecodeContext {
                max_message_len: raw.len() - 1,
                ..exact
            },
        ] {
            assert!(SetupRequestTransfer::decode_classified(&raw, &types, too_small).is_err());
        }
        assert!(expected
            .encode_classified(
                &types,
                EncodeContext {
                    max_message_len: raw.len() - 1,
                    ..output()
                }
            )
            .is_err());
        assert_eq!(format!("{types:?}"), "QosResourceTypes([REDACTED])");
    }
}

#[test]
fn complete_context_and_session_requests_preserve_conditional_admission() {
    let corpus = reference();
    assert_eq!(corpus["messages"].as_array().unwrap().len(), 224);
    for row in corpus["messages"].as_array().unwrap() {
        let source = corpus["transfers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["name"] == row["transfer"])
            .unwrap();
        let types = session_types(source);
        let raw = bytes(row["wire_hex"].as_str().unwrap());
        let pdu = decode(&raw, context()).unwrap();
        let admitted = ResourceSetupMessage::from_pdu_classified(&pdu, &types, context());
        assert_eq!(
            admitted.is_ok(),
            row["admit"].as_bool().unwrap(),
            "{} {}",
            row["kind"],
            row["transfer"]
        );
        assert_eq!(
            ResourceSetupMessage::from_pdu(&pdu, context()).is_ok(),
            source["ambr"].as_bool().unwrap()
        );
        let Ok(admitted) = admitted else { continue };
        let expected = transfer(source);
        let constructed = match admitted.message {
            ResourceSetupMessage::InitialRequest(value) => {
                let sessions = value.sessions.as_ref().unwrap();
                assert_eq!(sessions.values().len(), 2);
                assert_eq!(sessions.values()[0].id.value(), 1);
                assert_eq!(sessions.values()[1].id.value(), 255);
                assert!(sessions.values()[0].transfer == expected);
                assert!(sessions.values()[1].transfer.aggregate_bit_rate.is_some());
                assert!(value.aggregate_bit_rate.is_some());
                value.construct_classified(
                    SecurityAlgorithmMasks::new(0, 0, 0, 0),
                    &types,
                    context(),
                )
            }
            ResourceSetupMessage::SessionRequest(value) => {
                assert_eq!(value.sessions.values().len(), 2);
                assert!(value.sessions.values()[0].transfer == expected);
                assert_eq!(value.sessions.values()[1].id.value(), 255);
                value.construct_classified(&types, context())
            }
            _ => panic!("independent request kind"),
        }
        .unwrap();
        assert_eq!(encode(&constructed, output()).unwrap(), raw);
        let dynamic = source["flows"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["parameters"]["descriptor"]["kind"] == "dynamic");
        let exact = DecodeContext {
            max_depth: 17 + usize::from(dynamic),
            max_message_len: raw.len(),
            ..context()
        };
        assert!(ResourceSetupMessage::from_pdu_classified(&pdu, &types, exact).is_ok());
        assert!(ResourceSetupMessage::from_pdu_classified(
            &pdu,
            &types,
            DecodeContext {
                max_depth: exact.max_depth - 1,
                ..exact
            }
        )
        .is_err());
        assert_eq!(format!("{types:?}"), "SessionResourceTypes([REDACTED])");
    }
}

#[test]
fn missing_extra_and_duplicate_classifications_cannot_admit_requests() {
    let corpus = reference();
    let row = corpus["transfers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"] == "gbr-1-0-0")
        .unwrap();
    let value = transfer(row);
    let raw = bytes(row["wire_hex"].as_str().unwrap());
    let qfi = QosFlowId::new(0).unwrap();
    assert!(QosResourceTypes::new([]).is_err());
    assert!(
        QosResourceTypes::new([(qfi, QosResourceType::Gbr), (qfi, QosResourceType::NonGbr)])
            .is_err()
    );
    for wrong in [
        vec![(QosFlowId::new(1).unwrap(), QosResourceType::Gbr)],
        vec![
            (qfi, QosResourceType::Gbr),
            (QosFlowId::new(1).unwrap(), QosResourceType::Gbr),
        ],
        vec![(qfi, QosResourceType::NonGbr)],
    ] {
        let types = QosResourceTypes::new(wrong).unwrap();
        assert!(SetupRequestTransfer::decode_classified(&raw, &types, context()).is_err());
        assert!(value.encode_classified(&types, output()).is_err());
    }
    let types = types(row);
    assert!(SessionResourceTypes::new(vec![]).is_err());
    assert!(SessionResourceTypes::new(vec![(SessionId::new(1), types); 2]).is_err());
    for message in corpus["messages"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|v| v["transfer"] == row["name"])
    {
        let raw = bytes(message["wire_hex"].as_str().unwrap());
        let pdu = decode(&raw, context()).unwrap();
        for roster in [
            vec![(SessionId::new(1), types)],
            vec![(SessionId::new(1), types), (SessionId::new(2), types)],
            vec![
                (SessionId::new(1), types),
                (SessionId::new(255), types),
                (SessionId::new(254), types),
            ],
        ] {
            let wrong = SessionResourceTypes::new(roster).unwrap();
            assert!(ResourceSetupMessage::from_pdu_classified(&pdu, &wrong, context()).is_err());
        }
    }
}

#[path = "support/qos_admission.rs"]
mod shared;

#[test]
fn classified_transfer_and_message_truncations_and_mutations_are_bounded() {
    let corpus = reference();
    let mut mutations = 0;
    for category in ["transfers", "messages"] {
        for row in corpus[category].as_array().unwrap() {
            let raw = bytes(row["wire_hex"].as_str().unwrap());
            shared::exercise(&raw, context(), output());
            let name = row
                .get("name")
                .unwrap_or(&row["transfer"])
                .as_str()
                .unwrap();
            // Cover every field and bit offset in both enclosing outcomes,
            // including longest lists, without mirroring the runtime parser.
            if !name.starts_with("all-optionals-") && !name.starts_with("gbr-1-") {
                continue;
            }
            for length in 0..raw.len() {
                shared::exercise(&raw[..length], context(), output());
            }
            for index in 0..raw.len() {
                for mask in [1, 0x80, 0xff] {
                    let mut changed = raw.clone();
                    changed[index] ^= mask;
                    shared::exercise(&changed, context(), output());
                    mutations += 1;
                }
            }
        }
    }
    assert!(mutations > 20_000);
}
