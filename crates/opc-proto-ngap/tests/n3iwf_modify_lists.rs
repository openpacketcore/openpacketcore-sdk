use opc_proto_ngap::n3iwf::modify_fields::QosFlowModification;
use opc_proto_ngap::n3iwf::modify_lists::*;
use opc_proto_ngap::n3iwf::modify_request::ModifyRequestTransfer;
use opc_proto_ngap::n3iwf::modify_results::{ModifyFailureTransfer, ModifyResponseTransfer};
use opc_proto_ngap::n3iwf::session_lists::SessionId;
use opc_proto_ngap::n3iwf::NasPdu;
use opc_protocol::{
    DecodeContext, DuplicateIePolicy, EncodeContext, UnknownIePolicy, ValidationLevel,
};
use opc_types::Snssai;
use serde_json::Value;
use sha2::{Digest, Sha256};
fn oracle() -> Value {
    serde_json::from_str(include_str!("fixtures/n3iwf-modify-lists.json")).unwrap()
}
fn bytes(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
fn context() -> DecodeContext {
    DecodeContext {
        max_message_len: 200_000,
        max_ies: 256,
        max_depth: 20,
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
fn nas(length: usize) -> Vec<u8> {
    (0..length.div_ceil(32))
        .flat_map(|i| Sha256::digest(format!("modify-nas-{i}")).to_vec())
        .take(length)
        .collect()
}
fn request_budget(t: &ModifyRequestTransfer, fields: usize) -> (usize, usize) {
    let mut d = 4;
    let mut c = fields;
    if t.aggregate_bit_rate.is_some() {
        d = 6;
    }
    if let Some(v) = &t.uplink_modifications {
        d = 9;
        c = c.max(v.values().len());
    }
    if let Some(v) = &t.add_or_modify {
        d = d.max(
            if v.values()
                .iter()
                .any(|v| matches!(v, QosFlowModification::NonGbr(_)))
            {
                10
            } else {
                7
            },
        );
        c = c.max(v.values().len());
    }
    if let Some(v) = &t.release {
        d = d.max(8);
        c = c.max(v.values().len());
    }
    (d + 3, c)
}
#[test]
fn independent_lists_preserve_values_fragments_diagnostics_and_limits() {
    let f = oracle();
    assert_eq!(f["cases"].as_array().unwrap().len(), 1062);
    let mut admitted = 0;
    for row in f["cases"].as_array().unwrap() {
        let name = row["name"].as_str().unwrap();
        let kind = row["category"].as_str().unwrap();
        let wire = bytes(row["wire_hex"].as_str().unwrap());
        let m = &row["model"];
        let read = |ctx| match kind {
            "request" => SessionModifications::decode(&wire, ctx).map(|_| ()),
            "response" => ModifiedSessions::decode(&wire, ctx).map(|_| ()),
            _ => FailedModifications::decode(&wire, ctx).map(|_| ()),
        };
        if row["admitted"] == false {
            assert!(read(context()).is_err(), "{name}");
            continue;
        }
        admitted += 1;
        let base = &f["base_transfers"][m["transfer"].as_str().unwrap()];
        let leaf = bytes(base["wire_hex"].as_str().unwrap());
        let ids: Vec<_> = m["ids"]
            .as_array()
            .unwrap()
            .iter()
            .map(|id| SessionId::new(id.as_u64().unwrap() as u8))
            .collect();
        let (canonical, depth, count) = match kind {
            "request" => {
                let expected = ModifyRequestTransfer::decode(&leaf, context()).unwrap();
                let got = SessionModifications::decode(&wire, context()).unwrap();
                let n = m["nas_length"].as_u64().map(|v| nas(v as usize));
                let slice = if m["slice"].is_null() {
                    None
                } else {
                    let s = &m["slice"];
                    Some(if let Some(sd) = s["sd"].as_str() {
                        Snssai::with_sd(s["sst"].as_u64().unwrap() as u8, sd).unwrap()
                    } else {
                        Snssai::without_sd(s["sst"].as_u64().unwrap() as u8)
                    })
                };
                assert!(
                    got.requests
                        .values()
                        .iter()
                        .map(|v| v.id)
                        .eq(ids.iter().copied()),
                    "{name} ids"
                );
                for v in got.requests.values() {
                    assert!(
                        v.transfer == expected.transfer && v.slice == slice,
                        "{name} fields"
                    );
                    assert!(
                        v.nas.as_ref().map(NasPdu::as_bytes) == n.as_deref(),
                        "{name} nas"
                    );
                    if let Some(value) = &v.nas {
                        if value.as_bytes().len() < 16384 {
                            let p = value.as_bytes().as_ptr() as usize;
                            assert!(
                                p >= wire.as_ptr() as usize
                                    && p <= wire.as_ptr() as usize + wire.len(),
                                "{name} borrow"
                            );
                        }
                    }
                }
                if expected.ignored_ie_count > 0 || !expected.notify_ie_ids.is_empty() {
                    assert_eq!(got.diagnostics.len(), ids.len());
                    for (d, id) in got.diagnostics.iter().zip(&ids) {
                        assert!(d.session == *id);
                        assert_eq!(d.ignored_ie_count, expected.ignored_ie_count);
                        assert_eq!(d.notify_ie_ids, expected.notify_ie_ids);
                    }
                } else {
                    assert!(got.diagnostics.is_empty());
                }
                let constructed = SessionModifications::new(
                    ids.iter()
                        .map(|id| SessionModification {
                            id: *id,
                            nas: n.as_deref().map(NasPdu::new),
                            slice: slice.clone(),
                            transfer: expected.transfer.clone(),
                        })
                        .collect(),
                )
                .unwrap();
                let a = checked_encode(|ctx| constructed.encode(ctx));
                assert!(a.as_bytes() == got.requests.encode(output()).unwrap().as_bytes());
                let (d, c) =
                    request_budget(&expected.transfer, base["fields"].as_array().unwrap().len());
                (a, d, c.max(ids.len()))
            }
            "response" => {
                let transfer = ModifyResponseTransfer::decode(&leaf, context()).unwrap();
                let expected = ModifiedSessions::new(
                    ids.iter()
                        .map(|id| ModifiedSession {
                            id: *id,
                            transfer: transfer.clone(),
                        })
                        .collect(),
                )
                .unwrap();
                assert!(
                    ModifiedSessions::decode(&wire, context()).unwrap() == expected,
                    "{name} fields"
                );
                let count = transfer.accepted.as_ref().map_or(0, |v| v.values().len())
                    + transfer.failed.as_ref().map_or(0, |v| v.values().len());
                let d = if transfer.failed.is_some() {
                    8
                } else if transfer.accepted.is_some()
                    || transfer.downlink.is_some()
                    || transfer.uplink.is_some()
                {
                    7
                } else {
                    4
                };
                (
                    checked_encode(|ctx| expected.encode(ctx)),
                    d,
                    count.max(ids.len()),
                )
            }
            _ => {
                let transfer = ModifyFailureTransfer::decode(&leaf, context()).unwrap();
                let expected = FailedModifications::new(
                    ids.iter()
                        .map(|id| FailedModification {
                            id: *id,
                            transfer: transfer.clone(),
                        })
                        .collect(),
                )
                .unwrap();
                assert!(
                    FailedModifications::decode(&wire, context()).unwrap() == expected,
                    "{name} fields"
                );
                let c = transfer
                    .diagnostics
                    .as_ref()
                    .and_then(|v| v.ies.as_ref())
                    .map_or(0, |v| v.values().len());
                (
                    checked_encode(|ctx| expected.encode(ctx)),
                    if c == 0 { 6 } else { 8 },
                    c.max(ids.len()),
                )
            }
        };
        assert!(
            canonical.as_bytes() == bytes(row["canonical_wire_hex"].as_str().unwrap()),
            "{name} independent bytes"
        );
        let exact = DecodeContext {
            max_message_len: wire.len(),
            max_depth: depth,
            max_ies: count,
            ..context()
        };
        assert!(read(exact).is_ok(), "{name} exact {depth}/{count}");
        for ctx in [
            DecodeContext {
                max_message_len: wire.len() - 1,
                ..exact
            },
            DecodeContext {
                max_depth: depth - 1,
                ..exact
            },
            DecodeContext {
                max_ies: count - 1,
                ..exact
            },
        ] {
            assert!(read(ctx).is_err(), "{name} one short");
        }
    }
    assert_eq!(admitted, 1051);
}
#[test]
fn nested_selection_remains_authoritative_and_extensions_do_not_disappear() {
    let f = oracle();
    for name in [
        "request-request-ignore",
        "request-request-notify",
        "request-request-reject",
        "request-request-duplicate",
    ] {
        let row = f["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["name"] == name)
            .unwrap();
        let wire = bytes(row["wire_hex"].as_str().unwrap());
        let dropped = DecodeContext {
            unknown_ie_policy: UnknownIePolicy::Drop,
            validation_level: ValidationLevel::Structural,
            duplicate_ie_policy: DuplicateIePolicy::First,
            ..context()
        };
        let got = SessionModifications::decode(&wire, dropped).unwrap();
        assert!(got.diagnostics.is_empty());
        let strict = DecodeContext {
            validation_level: ValidationLevel::Strict,
            ..dropped
        };
        assert_eq!(
            SessionModifications::decode(&wire, strict).is_err(),
            name.ends_with("reject")
        );
    }
    for row in f["cases"].as_array().unwrap().iter().filter(|v| {
        v["name"].as_str().unwrap().contains("extension")
            || v["name"] == "request-slice-wrong-criticality"
    }) {
        let wire = bytes(row["wire_hex"].as_str().unwrap());
        let ctx = DecodeContext {
            unknown_ie_policy: UnknownIePolicy::Drop,
            validation_level: ValidationLevel::Structural,
            ..context()
        };
        let bad = match row["category"].as_str().unwrap() {
            "request" => SessionModifications::decode(&wire, ctx).is_err(),
            "response" => ModifiedSessions::decode(&wire, ctx).is_err(),
            _ => FailedModifications::decode(&wire, ctx).is_err(),
        };
        assert!(bad);
    }
}

#[path = "support/modify.rs"]
mod replay;
#[test]
fn bounded_mutations_complete_replay_and_physical_rejections() {
    let f = oracle();
    for row in f["cases"].as_array().unwrap() {
        replay::exercise(
            &bytes(row["wire_hex"].as_str().unwrap()),
            context(),
            output(),
        );
    }
    for name in [
        "request-count-1",
        "request-nas-65537",
        "response-count-1",
        "failure-failure-diagnostics",
    ] {
        let row = f["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["name"] == name)
            .unwrap();
        let wire = bytes(row["wire_hex"].as_str().unwrap());
        let reject = |data: &[u8]| match row["category"].as_str().unwrap() {
            "request" => SessionModifications::decode(data, context()).is_err(),
            "response" => ModifiedSessions::decode(data, context()).is_err(),
            _ => FailedModifications::decode(data, context()).is_err(),
        };
        for end in (0..wire.len()).step_by(if wire.len() < 512 {
            1
        } else {
            (wire.len() / 128).max(1)
        }) {
            assert!(reject(&wire[..end]), "{name} truncated {end}");
        }
        for mask in [0x80, 1] {
            let mut bad = wire.clone();
            bad[1] |= mask;
            assert!(reject(&bad), "{name} flag/pad");
        }
        let mut trailing = wire.clone();
        trailing.push(0);
        assert!(reject(&trailing));
        for i in (0..wire.len()).step_by((wire.len() / 32).max(1)) {
            for mask in [1, 0x40, 0x80] {
                let mut bad = wire.clone();
                bad[i] ^= mask;
                replay::exercise(&bad, context(), output());
            }
        }
    }
    let row = f["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"] == "request-count-1")
        .unwrap();
    let mut wire = bytes(row["wire_hex"].as_str().unwrap());
    wire.insert(3, 0x80);
    assert!(SessionModifications::decode(&wire, context()).is_err());
    assert!(SessionModifications::new(Vec::new()).is_err());
    assert!(ModifiedSessions::new(Vec::new()).is_err());
    assert!(FailedModifications::new(Vec::new()).is_err());
    let t = ModifyResponseTransfer::default();
    assert!(ModifiedSessions::new(vec![
        ModifiedSession {
            id: SessionId::new(1),
            transfer: t.clone()
        };
        2
    ])
    .is_err());
    assert!(ModifiedSessions::new(
        (0..257)
            .map(|i| ModifiedSession {
                id: SessionId::new(i as u8),
                transfer: t.clone()
            })
            .collect()
    )
    .is_err());
}

fn checked_encode(
    encode: impl Fn(
        EncodeContext,
    ) -> Result<opc_proto_ngap::n3iwf::EncodedValue, opc_protocol::EncodeError>,
) -> opc_proto_ngap::n3iwf::EncodedValue {
    let value = encode(output()).unwrap();
    let len = value.as_bytes().len();
    assert!(encode(EncodeContext {
        max_message_len: len,
        ..output()
    })
    .is_ok());
    assert!(encode(EncodeContext {
        max_message_len: len - 1,
        ..output()
    })
    .is_err());
    value
}
