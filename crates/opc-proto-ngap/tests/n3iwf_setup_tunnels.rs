#![allow(clippy::unwrap_used)]
use bytes::Bytes;
use opc_proto_ngap::n3iwf::release::{Cause, CauseClass};
use opc_proto_ngap::n3iwf::resource_fields::{DownlinkTransport, QosFlowId};
use opc_proto_ngap::n3iwf::resource_results::{
    AssociatedQosFlow, DownlinkQosTunnel, FailedQosFlow, QosFlowMapping, SetupResponseTransfer,
};
use opc_proto_ngap::n3iwf::resource_setup::{
    InitialContextResponse, ResourceSetupMessage, SessionResourceResponse,
};
use opc_proto_ngap::n3iwf::security_fields::SecurityResult;
use opc_proto_ngap::n3iwf::session_lists::{
    SessionId, SessionResults, SuccessfulSession, SuccessfulSessions,
};
use opc_proto_ngap::n3iwf::{AmfUeId, RanUeId};
use opc_proto_ngap::{encode, Criticality, Pdu, PduKind};
use opc_protocol::{DecodeContext, EncodeContext, OwnedDecode};
use serde_json::Value;

#[path = "support/setup_tunnels.rs"]
mod support;

fn bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn independent_setup_mapping_and_additional_tunnel_are_admitted() {
    let original: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/n3iwf-resource-results.json")).unwrap();
    for name in [
        "unsupported-mapping-ul",
        "unsupported-mapping-dl",
        "unsupported-additional-tunnel",
    ] {
        let row = original["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["name"] == name)
            .unwrap();
        let wire = bytes(row["wire_hex"].as_str().unwrap());
        assert!(
            SetupResponseTransfer::decode(
                &wire,
                DecodeContext {
                    max_depth: 8,
                    max_ies: 320,
                    ..DecodeContext::default()
                }
            )
            .is_ok(),
            "{name}"
        );
    }
}

fn oracle() -> Value {
    serde_json::from_str(include_str!("fixtures/n3iwf-setup-tunnels.json")).unwrap()
}

fn context() -> DecodeContext {
    DecodeContext {
        max_depth: 15,
        max_ies: 320,
        max_message_len: 4096,
        ..DecodeContext::default()
    }
}

fn output() -> EncodeContext {
    EncodeContext {
        max_message_len: 4096,
        ..EncodeContext::default()
    }
}

fn tunnel(model: &Value) -> Result<DownlinkQosTunnel, opc_protocol::DecodeError> {
    DownlinkQosTunnel::new(
        DownlinkTransport::new(
            model["address"].as_str().unwrap().parse().unwrap(),
            model["teid"].as_u64().unwrap() as u32,
        ),
        model["flows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|flow| AssociatedQosFlow {
                qfi: QosFlowId::new(flow["qfi"].as_u64().unwrap() as u8).unwrap(),
                mapping: match flow["mapping"].as_str() {
                    None => None,
                    Some("ul") => Some(QosFlowMapping::Uplink),
                    Some("dl") => Some(QosFlowMapping::Downlink),
                    _ => panic!("reference mapping"),
                },
            })
            .collect(),
    )
}

fn expected(model: &Value) -> Result<SetupResponseTransfer, opc_protocol::DecodeError> {
    Ok(SetupResponseTransfer::with_tunnels(
        tunnel(&model["primary"])?,
        model["additional"]
            .as_array()
            .unwrap()
            .iter()
            .map(tunnel)
            .collect::<Result<Vec<_>, _>>()?,
        model["failed"]
            .as_array()
            .unwrap()
            .iter()
            .map(|flow| FailedQosFlow {
                qfi: QosFlowId::new(flow["qfi"].as_u64().unwrap() as u8).unwrap(),
                cause: Cause::new(
                    match flow["cause"]["kind"].as_str().unwrap() {
                        "radioNetwork" => CauseClass::RadioNetwork,
                        "transport" => CauseClass::Transport,
                        "nas" => CauseClass::Nas,
                        "protocol" => CauseClass::Protocol,
                        "misc" => CauseClass::Misc,
                        _ => panic!("reference cause"),
                    },
                    flow["cause"]["code"].as_u64().unwrap() as u8,
                )
                .unwrap(),
            })
            .collect(),
    )?
    .with_security_result(
        model["security"]
            .as_array()
            .map(|value| SecurityResult::new(value[0] == "performed", value[1] == "performed")),
    ))
}

#[test]
fn independent_tunnels_preserve_associations_and_exact_resource_limits() {
    let oracle = oracle();
    let cases = oracle["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 925);
    let mut admitted = 0;
    let mut maximum = 0;
    for row in cases {
        let name = row["name"].as_str().unwrap();
        let wire = bytes(row["wire_hex"].as_str().unwrap());
        let ctx = DecodeContext {
            max_depth: row["depth"].as_u64().unwrap() as usize,
            max_ies: row["count"].as_u64().unwrap() as usize,
            max_message_len: wire.len(),
            ..context()
        };
        let constructed = expected(&row["model"]);
        let decoded = SetupResponseTransfer::decode(&wire, ctx);
        if !row["admitted"].as_bool().unwrap() {
            assert!(constructed.is_err(), "{name}");
            assert!(decoded.is_err(), "{name}");
            continue;
        }
        admitted += 1;
        maximum = maximum.max(wire.len());
        let constructed = constructed.unwrap();
        assert!(decoded.unwrap() == constructed, "{name}");
        assert!(
            constructed
                .encode(EncodeContext {
                    max_message_len: wire.len(),
                    ..output()
                })
                .unwrap()
                .as_bytes()
                == wire,
            "{name}"
        );
        assert!(
            constructed
                .encode(EncodeContext {
                    max_message_len: wire.len() - 1,
                    ..output()
                })
                .is_err(),
            "{name}"
        );
        assert!(
            SetupResponseTransfer::decode(
                &wire,
                DecodeContext {
                    max_message_len: wire.len() - 1,
                    ..ctx
                }
            )
            .is_err(),
            "{name}"
        );
        assert!(
            SetupResponseTransfer::decode(
                &wire,
                DecodeContext {
                    max_depth: ctx.max_depth - 1,
                    ..ctx
                }
            )
            .is_err(),
            "{name}"
        );
        assert!(
            SetupResponseTransfer::decode(
                &wire,
                DecodeContext {
                    max_ies: ctx.max_ies - 1,
                    ..ctx
                }
            )
            .is_err(),
            "{name}"
        );
        assert_eq!(
            format!("{constructed:?}"),
            "SetupResponseTransfer([REDACTED])"
        );
        assert_eq!(
            format!("{:?}", constructed.primary()),
            "DownlinkQosTunnel([REDACTED])"
        );
        for flow in constructed.primary().flows() {
            assert_eq!(format!("{flow:?}"), "AssociatedQosFlow([REDACTED])");
        }
        support::exercise(&wire, ctx, output());
    }
    assert_eq!(admitted, 916);
    assert_eq!(maximum, 478);
}

fn construct(
    name: &str,
    transfer: SetupResponseTransfer,
    ctx: DecodeContext,
) -> Result<Pdu, opc_protocol::DecodeError> {
    let sessions = SessionResults::new(
        Some(
            SuccessfulSessions::new(vec![SuccessfulSession {
                id: SessionId::new(255),
                transfer,
            }])
            .unwrap(),
        ),
        None,
    )
    .unwrap();
    let amf = AmfUeId::new(1).unwrap();
    let ran = RanUeId::new(2);
    match name {
        "InitialContextSetupResponse" => InitialContextResponse {
            amf,
            ran,
            sessions,
            diagnostics: None,
        }
        .construct(ctx),
        "PDUSessionResourceSetupResponse" => SessionResourceResponse {
            amf,
            ran,
            sessions,
            location: None,
            diagnostics: None,
        }
        .construct(ctx),
        _ => panic!("reference outcome"),
    }
}

#[test]
fn complete_setup_responses_construct_and_admit_additional_tunnels() {
    let oracle = oracle();
    let cases = oracle["cases"].as_array().unwrap();
    let messages = oracle["messages"].as_array().unwrap();
    assert_eq!(messages.len(), 32);
    let mut admitted = 0;
    for row in messages {
        let source = cases
            .iter()
            .find(|case| case["name"] == row["transfer"])
            .unwrap();
        let wire = bytes(row["wire_hex"].as_str().unwrap());
        let pdu = Pdu::decode_owned(Bytes::from(wire.clone()), context()).unwrap();
        let received = ResourceSetupMessage::from_pdu(&pdu, context());
        if !row["admitted"].as_bool().unwrap() {
            assert!(received.is_err());
            continue;
        }
        admitted += 1;
        let value = expected(&source["model"]).unwrap();
        let received = received.unwrap();
        let results = match &received.message {
            ResourceSetupMessage::InitialResponse(value) => &value.sessions,
            ResourceSetupMessage::SessionResponse(value) => &value.sessions,
            _ => panic!("unexpected response"),
        };
        assert!(results.successful().unwrap().values()[0].transfer == value);
        let ctx = DecodeContext {
            max_depth: source["depth"].as_u64().unwrap() as usize + 7,
            max_message_len: wire.len(),
            ..context()
        };
        let name = row["name"].as_str().unwrap();
        let constructed = construct(name, value.clone(), ctx).unwrap();
        assert!(encode(&constructed, output()).unwrap() == wire);
        assert!(ResourceSetupMessage::from_pdu(&pdu, ctx).is_ok());
        let short = DecodeContext {
            max_depth: ctx.max_depth - 1,
            ..ctx
        };
        assert!(ResourceSetupMessage::from_pdu(&pdu, short).is_err());
        assert!(construct(name, value.clone(), short).is_err());
        if source["count"].as_u64().unwrap() > 3 {
            let short = DecodeContext {
                max_ies: source["count"].as_u64().unwrap() as usize - 1,
                ..ctx
            };
            assert!(ResourceSetupMessage::from_pdu(&pdu, short).is_err());
            assert!(construct(name, value.clone(), short).is_err());
        }
        let mut malformed = pdu.clone();
        let PduKind::Successful { criticality, .. } = &mut malformed.kind else {
            panic!("outcome");
        };
        *criticality = Criticality::ignore;
        assert!(ResourceSetupMessage::from_pdu(&malformed, ctx).is_err());
    }
    assert_eq!(admitted, 14);
}

#[test]
fn constructor_bounds_and_adversarial_tunnel_replay() {
    let oracle = oracle();
    let cases = oracle["cases"].as_array().unwrap();
    let tunnel = tunnel(&cases[0]["model"]["primary"]).unwrap();
    assert!(
        SetupResponseTransfer::with_tunnels(tunnel.clone(), vec![tunnel.clone(); 4], vec![])
            .is_err()
    );
    assert!(DownlinkQosTunnel::new(tunnel.downlink(), vec![]).is_err());
    assert!(
        DownlinkQosTunnel::new(tunnel.downlink(), vec![tunnel.flows().next().unwrap(); 65])
            .is_err()
    );
    let mut mutations = 0;
    for row in cases.iter().step_by(37) {
        let wire = bytes(row["wire_hex"].as_str().unwrap());
        for length in 0..wire.len() {
            assert!(SetupResponseTransfer::decode(&wire[..length], context()).is_err());
        }
        let mut trailing = wire.clone();
        trailing.push(0);
        assert!(SetupResponseTransfer::decode(&trailing, context()).is_err());
        for index in 0..wire.len() {
            for mask in [1, 0x80, 0xff] {
                let mut changed = wire.clone();
                changed[index] ^= mask;
                for depth in [6, 8] {
                    support::exercise(
                        &changed,
                        DecodeContext {
                            max_depth: depth,
                            ..context()
                        },
                        output(),
                    );
                    mutations += 1;
                }
            }
        }
    }
    assert!(mutations > 10000);
}
