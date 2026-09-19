#![allow(clippy::unwrap_used)]
use opc_proto_ngap::n3iwf::release::{Cause, CauseClass};
use opc_proto_ngap::n3iwf::resource_fields::{DownlinkTransport, QosFlowId};
use opc_proto_ngap::n3iwf::resource_results::{
    FailedQosFlow, SetupFailureTransfer, SetupResponseTransfer,
};
use opc_protocol::{DecodeContext, EncodeContext};
use serde_json::Value;

fn oracle() -> Value {
    serde_json::from_str(include_str!("fixtures/n3iwf-resource-results.json")).unwrap()
}
fn bytes(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|v| u8::from_str_radix(std::str::from_utf8(v).unwrap(), 16).unwrap())
        .collect()
}
fn cause(model: &Value) -> Cause {
    let class = match model["class"].as_str().unwrap() {
        "radioNetwork" => CauseClass::RadioNetwork,
        "transport" => CauseClass::Transport,
        "nas" => CauseClass::Nas,
        "protocol" => CauseClass::Protocol,
        "misc" => CauseClass::Misc,
        _ => panic!("reference cause class"),
    };
    Cause::new(class, model["code"].as_u64().unwrap() as u8).unwrap()
}
fn response(model: &Value) -> Result<SetupResponseTransfer, opc_protocol::DecodeError> {
    SetupResponseTransfer::new(
        DownlinkTransport::new(
            model["downlink"]["address"]
                .as_str()
                .unwrap()
                .parse()
                .unwrap(),
            model["downlink"]["teid"].as_u64().unwrap() as u32,
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
                cause: cause(&v["cause"]),
            })
            .collect(),
    )
}
fn row_named<'a>(oracle: &'a Value, name: &str) -> &'a Value {
    oracle["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"] == name)
        .unwrap()
}
#[test]
fn independent_results_match_values_and_constructor_bytes() {
    let reference = oracle();
    let mut admitted = 0;
    for row in reference["cases"].as_array().unwrap() {
        let wire = bytes(row["wire_hex"].as_str().unwrap());
        let admit = row["admitted"].as_bool().unwrap();
        if row["type"] == "PDUSessionResourceSetupResponseTransfer" {
            let received = SetupResponseTransfer::decode(&wire, DecodeContext::default());
            // Preserve the original corpus bytes and its historical label;
            // this formerly unsupported root is now independently qualified.
            if row["name"] == "unsupported-security-result" {
                let model = response(&row_named(&reference, "accepted-count-1")["model"])
                    .unwrap()
                    .with_security_result(Some(
                        opc_proto_ngap::n3iwf::security_fields::SecurityResult::new(true, false),
                    ));
                assert!(received.unwrap() == model);
                assert!(model.encode(EncodeContext::default()).unwrap().as_bytes() == wire);
                admitted += 1;
                continue;
            }
            if !admit {
                assert!(received.is_err(), "{}", row["name"]);
                if !row["model"].is_null() {
                    assert!(response(&row["model"]).is_err());
                }
                continue;
            }
            let expected = response(&row["model"]).unwrap();
            let received = received.unwrap();
            assert!(received == expected, "{}", row["name"]);
            assert!(
                expected
                    .encode(EncodeContext::default())
                    .unwrap()
                    .as_bytes()
                    == wire,
                "{}",
                row["name"]
            );
            assert!(received.downlink() == expected.downlink());
            assert!(received.accepted() == expected.accepted());
            assert!(received.failed() == expected.failed());
        } else {
            let received = SetupFailureTransfer::decode(&wire, DecodeContext::default());
            if row["name"] == "unsupported-diagnostics" {
                let expected = SetupFailureTransfer {
                    cause: Cause::new(CauseClass::RadioNetwork, 0).unwrap(),
                    diagnostics: Some(
                        opc_proto_ngap::n3iwf::reset_fields::CriticalityDiagnostics {
                            procedure_code: None,
                            triggering_outcome: None,
                            procedure_criticality: None,
                            ies: None,
                        },
                    ),
                };
                assert!(received.unwrap() == expected);
                assert_eq!(
                    expected
                        .encode(EncodeContext::default())
                        .unwrap()
                        .as_bytes(),
                    wire
                );
                continue;
            }
            if !admit {
                assert!(received.is_err(), "{}", row["name"]);
                continue;
            }
            let expected = SetupFailureTransfer {
                cause: cause(&row["model"]),
                diagnostics: None,
            };
            assert!(received.unwrap() == expected, "{}", row["name"]);
            assert!(
                expected
                    .encode(EncodeContext::default())
                    .unwrap()
                    .as_bytes()
                    == wire,
                "{}",
                row["name"]
            );
        }
        admitted += 1;
    }
    assert_eq!(reference["cases"].as_array().unwrap().len(), 547);
    assert_eq!(admitted, 540);
}
#[test]
fn result_limits_are_checked_on_receive_and_construction() {
    let reference = oracle();
    for name in ["accepted-count-64", "partial-count-63", "partial-count-1"] {
        let row = row_named(&reference, name);
        let wire = bytes(row["wire_hex"].as_str().unwrap());
        for ctx in [
            DecodeContext {
                max_ies: 63,
                ..DecodeContext::default()
            },
            DecodeContext {
                max_depth: 5,
                ..DecodeContext::default()
            },
            DecodeContext {
                max_message_len: wire.len() - 1,
                ..DecodeContext::default()
            },
        ] {
            assert!(SetupResponseTransfer::decode(&wire, ctx).is_err());
        }
        assert!(SetupResponseTransfer::decode(
            &wire,
            DecodeContext {
                max_ies: 64,
                max_depth: 6,
                ..DecodeContext::default()
            }
        )
        .is_ok());
        let model = response(&row["model"]).unwrap();
        assert!(model
            .encode(EncodeContext {
                max_message_len: wire.len() - 1,
                ..EncodeContext::default()
            })
            .is_err());
        assert_eq!(
            model
                .encode(EncodeContext {
                    max_message_len: wire.len(),
                    ..EncodeContext::default()
                })
                .unwrap()
                .as_bytes(),
            wire
        );
    }
    let endpoint = DownlinkTransport::new("198.51.100.17".parse().unwrap(), 0x11223344);
    let qfi = QosFlowId::new(1).unwrap();
    assert!(SetupResponseTransfer::new(endpoint, vec![], vec![]).is_err());
    assert!(SetupResponseTransfer::new(endpoint, vec![qfi; 65], vec![]).is_err());
    assert!(SetupResponseTransfer::new(endpoint, vec![qfi, qfi], vec![]).is_err());
    let failure = SetupFailureTransfer {
        cause: Cause::new(CauseClass::RadioNetwork, 44).unwrap(),
        diagnostics: None,
    };
    let wire = failure.encode(EncodeContext::default()).unwrap();
    for ctx in [
        DecodeContext {
            max_depth: 2,
            ..DecodeContext::default()
        },
        DecodeContext {
            max_message_len: wire.as_bytes().len() - 1,
            ..DecodeContext::default()
        },
    ] {
        assert!(SetupFailureTransfer::decode(wire.as_bytes(), ctx).is_err());
    }
    assert!(SetupFailureTransfer::decode(
        wire.as_bytes(),
        DecodeContext {
            max_depth: 3,
            ..DecodeContext::default()
        }
    )
    .is_ok());
    assert!(failure
        .encode(EncodeContext {
            max_message_len: 1,
            ..EncodeContext::default()
        })
        .is_err());
}
fn set_bit(wire: &mut [u8], bit: usize) {
    wire[bit / 8] |= 1 << (7 - bit % 8);
}
#[test]
fn nested_flags_padding_and_invalid_causes_fail_explicitly() {
    let reference = oracle();
    let wire = bytes(
        row_named(&reference, "accepted-count-1")["wire_hex"]
            .as_str()
            .unwrap(),
    );
    // Transfer, TNL, tunnel, address and flow extension/optional bits;
    // address alignment padding follows bit 18.
    for bit in [
        0, 1, 2, 4, 5, 6, 7, 8, 9, 10, 19, 20, 21, 22, 23, 94, 95, 96, 97,
    ] {
        let mut changed = wire.clone();
        set_bit(&mut changed, bit);
        assert!(
            SetupResponseTransfer::decode(&changed, DecodeContext::default()).is_err(),
            "bit {bit}"
        );
    }
    let mut count_bomb = wire.clone();
    for bit in 88..94 {
        set_bit(&mut count_bomb, bit);
    }
    assert!(SetupResponseTransfer::decode(&count_bomb, DecodeContext::default()).is_err());
    let partial = bytes(
        row_named(&reference, "partial-cause-1-radioNetwork-0")["wire_hex"]
            .as_str()
            .unwrap(),
    );
    for bit in [110, 111, 112, 122] {
        let mut changed = partial.clone();
        set_bit(&mut changed, bit);
        assert!(
            SetupResponseTransfer::decode(&changed, DecodeContext::default()).is_err(),
            "bit {bit}"
        );
    }
    let mut bad_cause = partial.clone();
    for bit in 119..122 {
        set_bit(&mut bad_cause, bit);
    }
    assert!(SetupResponseTransfer::decode(&bad_cause, DecodeContext::default()).is_err());
    let mut bad_enum = partial;
    for bit in 123..129 {
        set_bit(&mut bad_enum, bit);
    }
    assert!(SetupResponseTransfer::decode(&bad_enum, DecodeContext::default()).is_err());
    let failure = bytes(
        row_named(&reference, "failure-radioNetwork-0")["wire_hex"]
            .as_str()
            .unwrap(),
    );
    for bit in [0, 1, 2, 6, 13, 14, 15] {
        let mut changed = failure.clone();
        set_bit(&mut changed, bit);
        assert!(
            SetupFailureTransfer::decode(&changed, DecodeContext::default()).is_err(),
            "bit {bit}"
        );
    }
    for invalid in [vec![0x14, 0], vec![0x1c, 0], vec![0x01, 0xf8]] {
        assert!(SetupFailureTransfer::decode(&invalid, DecodeContext::default()).is_err());
    }
    let accepted = response(&row_named(&reference, "partial-count-1")["model"]).unwrap();
    for redacted in [
        format!("{accepted:?}"),
        format!("{:?}", accepted.failed()[0]),
        format!(
            "{:?}",
            SetupFailureTransfer {
                cause: accepted.failed()[0].cause,
                diagnostics: None,
            }
        ),
    ] {
        assert!(redacted.contains("REDACTED"));
        assert!(!redacted.contains("198.51.100"));
        assert!(!redacted.contains("11223344"));
    }
}
#[test]
fn all_reference_truncations_and_mutations_remain_bounded() {
    let reference = oracle();
    for row in reference["cases"].as_array().unwrap() {
        let wire = bytes(row["wire_hex"].as_str().unwrap());
        let response = row["type"] == "PDUSessionResourceSetupResponseTransfer";
        for end in 0..wire.len() {
            if response {
                assert!(
                    SetupResponseTransfer::decode(&wire[..end], DecodeContext::default()).is_err()
                );
            } else {
                assert!(
                    SetupFailureTransfer::decode(&wire[..end], DecodeContext::default()).is_err()
                );
            }
        }
        let mut trailing = wire.clone();
        trailing.push(0);
        if response {
            assert!(SetupResponseTransfer::decode(&trailing, DecodeContext::default()).is_err());
        } else {
            assert!(SetupFailureTransfer::decode(&trailing, DecodeContext::default()).is_err());
        }
        for index in 0..wire.len() {
            for mask in [1, 0x80, 0xff] {
                let mut changed = wire.clone();
                changed[index] ^= mask;
                if response {
                    if let Ok(value) =
                        SetupResponseTransfer::decode(&changed, DecodeContext::default())
                    {
                        assert!(
                            value.encode(EncodeContext::default()).unwrap().as_bytes() == changed
                        );
                    }
                } else if let Ok(value) =
                    SetupFailureTransfer::decode(&changed, DecodeContext::default())
                {
                    assert!(value.encode(EncodeContext::default()).unwrap().as_bytes() == changed);
                }
            }
        }
    }
}
