#![allow(clippy::unwrap_used)]
use opc_proto_ngap::n3iwf::release::{Cause, CauseClass};
use opc_proto_ngap::n3iwf::resource_fields::{
    DownlinkTransport, NonGbrFlow, QosFlowId, QosFlowSetupList, SessionAggregateBitRate,
    SessionType, UplinkTransport,
};
use opc_proto_ngap::n3iwf::resource_request::SetupRequestTransfer;
use opc_proto_ngap::n3iwf::resource_results::{
    FailedQosFlow, SetupFailureTransfer, SetupResponseTransfer,
};
use opc_proto_ngap::n3iwf::session_lists::{
    FailedSession, FailedSessions, SessionId, SessionResults, SessionSetupRequest,
    SessionSetupRequests, SuccessfulSession, SuccessfulSessions,
};
use opc_proto_ngap::n3iwf::NasPdu;
use opc_protocol::{
    DecodeContext, DuplicateIePolicy, EncodeContext, UnknownIePolicy, ValidationLevel,
};
use opc_types::Snssai;
use serde_json::Value;

fn oracle() -> Value {
    serde_json::from_str(include_str!("fixtures/n3iwf-session-lists.json")).unwrap()
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
fn cause(m: &Value) -> Cause {
    let class = match m["class"].as_str().unwrap() {
        "radioNetwork" => CauseClass::RadioNetwork,
        "transport" => CauseClass::Transport,
        "nas" => CauseClass::Nas,
        "protocol" => CauseClass::Protocol,
        "misc" => CauseClass::Misc,
        _ => panic!("reference class"),
    };
    Cause::new(class, m["code"].as_u64().unwrap() as u8).unwrap()
}
fn request_transfer(m: &Value) -> SetupRequestTransfer {
    SetupRequestTransfer {
        additional_uplink: None,
        security: None,
        network_instance: None,
        common_network_instance: None,
        uplink: UplinkTransport::new(
            m["uplink"]["address"].as_str().unwrap().parse().unwrap(),
            m["uplink"]["teid"].as_u64().unwrap() as u32,
        ),
        aggregate_bit_rate: Some(
            SessionAggregateBitRate::new(
                m["ambr"]["downlink"].as_u64().unwrap(),
                m["ambr"]["uplink"].as_u64().unwrap(),
            )
            .unwrap(),
        ),
        session_type: match m["session_type"].as_str().unwrap() {
            "ipv4" => SessionType::Ipv4,
            "ipv6" => SessionType::Ipv6,
            "ipv4v6" => SessionType::Ipv4v6,
            "ethernet" => SessionType::Ethernet,
            "unstructured" => SessionType::Unstructured,
            _ => panic!("reference kind"),
        },
        flows: QosFlowSetupList::new(
            m["flows"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| {
                    NonGbrFlow::new(
                        QosFlowId::new(v["qfi"].as_u64().unwrap() as u8).unwrap(),
                        v["priority"].as_u64().unwrap() as u8,
                        v["may_preempt"].as_bool().unwrap(),
                        v["preemptable"].as_bool().unwrap(),
                    )
                    .unwrap()
                })
                .collect(),
        )
        .unwrap(),
    }
}
fn response_transfer(m: &Value) -> SetupResponseTransfer {
    SetupResponseTransfer::new(
        DownlinkTransport::new(
            m["downlink"]["address"].as_str().unwrap().parse().unwrap(),
            m["downlink"]["teid"].as_u64().unwrap() as u32,
        ),
        m["accepted"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| QosFlowId::new(v.as_u64().unwrap() as u8).unwrap())
            .collect(),
        m["failed"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| FailedQosFlow {
                qfi: QosFlowId::new(v["qfi"].as_u64().unwrap() as u8).unwrap(),
                cause: cause(&v["cause"]),
            })
            .collect(),
    )
    .unwrap()
}
fn ids(row: &Value) -> Vec<SessionId> {
    row["model"]["ids"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| SessionId::new(v.as_u64().unwrap() as u8))
        .collect()
}
fn model<'a>(reference: &'a Value, row: &Value) -> &'a Value {
    &reference["base_transfers"][row["model"]["transfer"].as_str().unwrap()]["model"]
}
fn requests<'a>(
    reference: &Value,
    row: &Value,
    nas: Option<&'a [u8]>,
) -> Result<SessionSetupRequests<'a>, opc_protocol::DecodeError> {
    SessionSetupRequests::new(
        ids(row)
            .into_iter()
            .map(|id| SessionSetupRequest {
                id,
                slice: match row["model"]["sd"].as_str() {
                    Some(sd) => Snssai::with_sd(id.value(), sd).unwrap(),
                    None => Snssai::without_sd(id.value()),
                },
                nas: nas.map(NasPdu::new),
                transfer: request_transfer(model(reference, row)),
            })
            .collect(),
    )
}
fn successes(
    reference: &Value,
    row: &Value,
) -> Result<SuccessfulSessions, opc_protocol::DecodeError> {
    SuccessfulSessions::new(
        ids(row)
            .into_iter()
            .map(|id| SuccessfulSession {
                id,
                transfer: response_transfer(model(reference, row)),
            })
            .collect(),
    )
}
fn failures(reference: &Value, row: &Value) -> Result<FailedSessions, opc_protocol::DecodeError> {
    FailedSessions::new(
        ids(row)
            .into_iter()
            .map(|id| FailedSession {
                id,
                transfer: SetupFailureTransfer {
                    cause: cause(model(reference, row)),
                    diagnostics: None,
                },
            })
            .collect(),
    )
}
#[test]
fn independent_lists_match_values_canonical_construction_and_diagnostics() {
    let reference = oracle();
    let mut admitted = 0;
    for row in reference["cases"].as_array().unwrap() {
        let wire = bytes(row["wire_hex"].as_str().unwrap());
        let canonical = bytes(row["canonical_wire_hex"].as_str().unwrap());
        let valid = row["admitted"].as_bool().unwrap();
        let nas = row["model"]["nas_hex"].as_str().map(bytes);
        match row["category"].as_str().unwrap() {
            "request" => {
                let received = SessionSetupRequests::decode(&wire, context());
                let expected = requests(&reference, row, nas.as_deref());
                if !valid {
                    assert!(received.is_err(), "{}", row["name"]);
                    if row["name"].as_str().unwrap().starts_with("duplicate-") {
                        assert!(expected.is_err());
                    }
                    continue;
                }
                let received = received.unwrap();
                let expected = expected.unwrap();
                for (got, wanted) in received.requests.values().iter().zip(expected.values()) {
                    assert_eq!(got.id.value(), wanted.id.value());
                    assert!(got.slice == wanted.slice);
                    assert!(got.transfer == wanted.transfer);
                    assert!(
                        got.nas.as_ref().map(|v| v.as_bytes())
                            == wanted.nas.as_ref().map(|v| v.as_bytes())
                    );
                    if let Some(value) = &got.nas {
                        if !value.as_bytes().is_empty() && value.as_bytes().len() < 16384 {
                            let address = value.as_bytes().as_ptr() as usize;
                            assert!(
                                (wire.as_ptr() as usize..wire.as_ptr() as usize + wire.len())
                                    .contains(&address)
                            );
                        }
                    }
                }
                assert_eq!(received.requests.values().len(), expected.values().len());
                assert!(
                    received.requests.encode(output()).unwrap().as_bytes() == canonical,
                    "{}",
                    row["name"]
                );
                assert!(
                    expected.encode(output()).unwrap().as_bytes() == canonical,
                    "{}",
                    row["name"]
                );
                match row["model"]["transfer"].as_str().unwrap() {
                    "request-notify" => {
                        assert_eq!(received.diagnostics.len(), 1);
                        assert_eq!(received.diagnostics[0].session.value(), 2);
                        assert_eq!(received.diagnostics[0].notify_ie_ids, vec![65535]);
                        assert_eq!(received.diagnostics[0].ignored_ie_count, 0);
                    }
                    "request-ignore" => {
                        assert_eq!(received.diagnostics.len(), 1);
                        assert_eq!(received.diagnostics[0].ignored_ie_count, 1);
                        assert!(received.diagnostics[0].notify_ie_ids.is_empty());
                    }
                    _ => assert!(received.diagnostics.is_empty()),
                }
            }
            "response" => {
                let received = SuccessfulSessions::decode(&wire, context());
                let expected = successes(&reference, row);
                if !valid {
                    assert!(received.is_err());
                    assert!(expected.is_err());
                    continue;
                }
                let expected = expected.unwrap();
                assert!(received.unwrap() == expected, "{}", row["name"]);
                assert!(
                    expected.encode(output()).unwrap().as_bytes() == canonical,
                    "{}",
                    row["name"]
                );
            }
            "failure" => {
                let received = FailedSessions::decode(&wire, context());
                let expected = failures(&reference, row);
                if !valid {
                    assert!(received.is_err());
                    assert!(expected.is_err());
                    continue;
                }
                let expected = expected.unwrap();
                assert!(received.unwrap() == expected, "{}", row["name"]);
                assert!(
                    expected.encode(output()).unwrap().as_bytes() == canonical,
                    "{}",
                    row["name"]
                );
            }
            _ => panic!("reference category"),
        }
        admitted += 1;
    }
    assert_eq!(reference["cases"].as_array().unwrap().len(), 102);
    assert_eq!(admitted, 93);
}
fn find_row<'a>(reference: &'a Value, prefix: &str, category: &str) -> &'a Value {
    reference["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"].as_str().unwrap().starts_with(prefix) && v["category"] == category)
        .unwrap()
}
fn decodes(category: &str, wire: &[u8], ctx: DecodeContext) -> bool {
    match category {
        "request" => SessionSetupRequests::decode(wire, ctx).is_ok(),
        "response" => SuccessfulSessions::decode(wire, ctx).is_ok(),
        "failure" => FailedSessions::decode(wire, ctx).is_ok(),
        _ => panic!("reference category"),
    }
}
#[test]
fn list_limits_flags_and_malformed_nested_entries_fail_before_admission() {
    let reference = oracle();
    for (category, depth) in [("request", 13), ("response", 9), ("failure", 6)] {
        let row = find_row(&reference, "count-256-", category);
        let wire = bytes(row["wire_hex"].as_str().unwrap());
        for ctx in [
            DecodeContext {
                max_ies: 255,
                ..context()
            },
            DecodeContext {
                max_depth: depth - 1,
                ..context()
            },
            DecodeContext {
                max_message_len: wire.len() - 1,
                ..context()
            },
        ] {
            assert!(!decodes(category, &wire, ctx));
        }
        assert!(decodes(
            category,
            &wire,
            DecodeContext {
                max_ies: 256,
                max_depth: depth,
                ..context()
            }
        ));
        let short = bytes(
            find_row(&reference, "count-1-", category)["wire_hex"]
                .as_str()
                .unwrap(),
        );
        let mut count_bomb = short.clone();
        count_bomb[0] = 255;
        assert!(!decodes(category, &count_bomb, context()));
        for mask in [0x80, if category == "request" { 0x20 } else { 0x40 }, 1] {
            let mut changed = short.clone();
            changed[1] |= mask;
            assert!(!decodes(category, &changed, context()));
        }
        let row = find_row(&reference, "count-2-", category);
        let mut changed = bytes(row["wire_hex"].as_str().unwrap());
        let leaf = bytes(
            reference["base_transfers"][category]["wire_hex"]
                .as_str()
                .unwrap(),
        );
        let index = changed
            .windows(leaf.len())
            .rposition(|v| v == leaf)
            .unwrap();
        changed[index] |= 0x80;
        assert!(!decodes(category, &changed, context()));
        let encoded = match category {
            "request" => requests(&reference, row, None)
                .unwrap()
                .encode(output())
                .unwrap(),
            "response" => successes(&reference, row)
                .unwrap()
                .encode(output())
                .unwrap(),
            _ => failures(&reference, row).unwrap().encode(output()).unwrap(),
        };
        let too_small = EncodeContext {
            max_message_len: encoded.as_bytes().len() - 1,
            ..output()
        };
        let rejected = match category {
            "request" => requests(&reference, row, None)
                .unwrap()
                .encode(too_small)
                .is_err(),
            "response" => successes(&reference, row)
                .unwrap()
                .encode(too_small)
                .is_err(),
            _ => failures(&reference, row)
                .unwrap()
                .encode(too_small)
                .is_err(),
        };
        assert!(rejected);
    }
    assert!(SessionSetupRequests::new(vec![]).is_err());
    assert!(SuccessfulSessions::new(vec![]).is_err());
    assert!(FailedSessions::new(vec![]).is_err());
}
#[test]
fn partial_session_results_are_disjoint_and_redacted() {
    let reference = oracle();
    let yes = successes(&reference, find_row(&reference, "count-1-", "response")).unwrap();
    let no = failures(&reference, find_row(&reference, "count-1-", "failure")).unwrap();
    assert!(FailedSessions::new(vec![no.values()[0].clone(); 257]).is_err());
    assert!(SessionResults::new(Some(yes.clone()), Some(no.clone())).is_err());
    let different = FailedSessions::new(vec![FailedSession {
        id: SessionId::new(255),
        transfer: no.values()[0].transfer.clone(),
    }])
    .unwrap();
    let results = SessionResults::new(Some(yes), Some(different)).unwrap();
    assert!(!results.is_empty());
    assert_eq!(results.successful().unwrap().values()[0].id.value(), 0);
    assert_eq!(results.failed().unwrap().values()[0].id.value(), 255);
    assert!(SessionResults::new(None, None).unwrap().is_empty());
    assert!(SessionResults::new(None, Some(no)).is_ok());
    let row = find_row(&reference, "nas-length-127-", "request");
    let wire = bytes(row["wire_hex"].as_str().unwrap());
    let got = SessionSetupRequests::decode(&wire, context()).unwrap();
    for value in [
        format!("{results:?}"),
        format!("{:?}", got.requests),
        format!("{:?}", got.requests.values()[0]),
        format!("{:?}", results.successful().unwrap().values()[0]),
        format!("{:?}", results.failed().unwrap().values()[0]),
    ] {
        assert!(value.contains("REDACTED"));
        assert!(!value.contains("198.51.100"));
        assert!(!value.contains("abcdef"));
    }
}
#[test]
fn contained_transfers_preserve_policy_and_field_local_count_limits() {
    let reference = oracle();
    let reject = bytes(
        find_row(&reference, "request-reject-", "request")["wire_hex"]
            .as_str()
            .unwrap(),
    );
    let drop = DecodeContext {
        unknown_ie_policy: UnknownIePolicy::Drop,
        ..context()
    };
    assert!(SessionSetupRequests::decode(&reject, drop).is_err());
    // Preserve the shared codec's existing structural/drop policy: strict
    // criticality rejection must not be bypassed by the enclosing list.
    assert!(SessionSetupRequests::decode(
        &reject,
        DecodeContext {
            validation_level: ValidationLevel::Structural,
            ..drop
        }
    )
    .is_ok());
    let notify = bytes(
        find_row(&reference, "request-notify-", "request")["wire_hex"]
            .as_str()
            .unwrap(),
    );
    assert!(SessionSetupRequests::decode(&notify, drop)
        .unwrap()
        .diagnostics
        .is_empty());
    assert!(SessionSetupRequests::decode(
        &notify,
        DecodeContext {
            unknown_ie_policy: UnknownIePolicy::Reject,
            ..context()
        }
    )
    .is_err());
    let maximum = bytes(
        find_row(&reference, "request-max-", "request")["wire_hex"]
            .as_str()
            .unwrap(),
    );
    for (max_ies, accepted) in [(63, false), (64, true)] {
        assert_eq!(
            SessionSetupRequests::decode(
                &maximum,
                DecodeContext {
                    max_ies,
                    ..context()
                }
            )
            .is_ok(),
            accepted
        );
    }
}
#[test]
fn truncations_and_bounded_mutations_cover_nested_list_inputs() {
    let reference = oracle();
    for row in reference["cases"].as_array().unwrap() {
        let wire = bytes(row["wire_hex"].as_str().unwrap());
        let category = row["category"].as_str().unwrap();
        let stride = (wire.len() / 256).max(1);
        for end in (0..wire.len()).step_by(stride).chain([wire.len() - 1]) {
            assert!(!decodes(category, &wire[..end], context()));
        }
        let mut trailing = wire.clone();
        trailing.push(0);
        assert!(!decodes(category, &trailing, context()));
        for index in (0..wire.len()).step_by(stride) {
            for mask in [1, 0x80, 0xff] {
                let mut changed = wire.clone();
                changed[index] ^= mask;
                let _ = decodes(category, &changed, context());
            }
        }
    }
}
