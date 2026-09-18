use opc_proto_ngap::n3iwf::modify_fields::{
    QosFlowCauses, QosFlowModification, QosFlowModifications, UplinkModifications,
};
use opc_proto_ngap::n3iwf::modify_request::ModifyRequestTransfer;
use opc_proto_ngap::n3iwf::resource_fields::SessionAggregateBitRate;
use opc_protocol::{
    DecodeContext, DuplicateIePolicy, EncodeContext, UnknownIePolicy, ValidationLevel,
};
use serde_json::Value;

#[path = "support/modify_request.rs"]
mod support;

fn oracle() -> Value {
    serde_json::from_str(include_str!("fixtures/n3iwf-modify-request.json")).unwrap()
}
fn context() -> DecodeContext {
    DecodeContext {
        max_message_len: 131072,
        max_ies: 64,
        max_depth: 10,
        validation_level: ValidationLevel::Strict,
        duplicate_ie_policy: DuplicateIePolicy::Reject,
        ..DecodeContext::default()
    }
}
fn output() -> EncodeContext {
    EncodeContext {
        max_message_len: 131072,
        ..EncodeContext::default()
    }
}
fn bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}
// The enclosing oracle independently serializes every nested field. Their
// semantic codecs were qualified against the separate Modify-fields corpus;
// compare their selected values here, without deriving expectations from the
// enclosing transfer decoder or encoder under test.
fn expected(fields: &[Value], last: bool) -> ModifyRequestTransfer {
    let mut result = ModifyRequestTransfer::default();
    for field in fields {
        let wire = bytes(field["wire_hex"].as_str().unwrap());
        match field["id"].as_u64().unwrap() {
            130 if last || result.aggregate_bit_rate.is_none() => {
                result.aggregate_bit_rate =
                    Some(SessionAggregateBitRate::decode(&wire, context()).unwrap())
            }
            140 if last || result.uplink_modifications.is_none() => {
                result.uplink_modifications =
                    Some(UplinkModifications::decode(&wire, context()).unwrap())
            }
            135 if last || result.add_or_modify.is_none() => {
                result.add_or_modify = Some(QosFlowModifications::decode(&wire, context()).unwrap())
            }
            137 if last || result.release.is_none() => {
                result.release = Some(QosFlowCauses::decode(&wire, context()).unwrap())
            }
            _ => {}
        }
    }
    result
}
fn budgets(value: &ModifyRequestTransfer, container_count: usize) -> (usize, usize) {
    let mut depth = 4;
    let mut count = container_count;
    if value.aggregate_bit_rate.is_some() {
        depth = 6;
    }
    if let Some(v) = &value.uplink_modifications {
        depth = 9;
        count = count.max(v.values().len());
    }
    if let Some(v) = &value.add_or_modify {
        depth = depth.max(
            if v.values()
                .iter()
                .any(|v| matches!(v, QosFlowModification::NonGbr(_)))
            {
                10
            } else {
                7
            },
        );
        count = count.max(v.values().len());
    }
    if let Some(v) = &value.release {
        depth = depth.max(8);
        count = count.max(v.values().len());
    }
    (depth, count)
}

#[test]
fn independent_transfers_preserve_optional_values_and_canonical_bytes() {
    let corpus = oracle();
    let rows = corpus["cases"].as_array().unwrap();
    assert_eq!(rows.len(), 380);
    let mut admitted = 0;
    for row in rows {
        let name = row["name"].as_str().unwrap();
        let wire = bytes(row["wire_hex"].as_str().unwrap());
        let decoded = ModifyRequestTransfer::decode(&wire, context());
        if row["admitted"] == false {
            assert!(decoded.is_err(), "{name} negative admitted");
            if name == "overlap" {
                assert!(expected(row["fields"].as_array().unwrap(), false)
                    .encode(output())
                    .is_err());
            }
            continue;
        }
        admitted += 1;
        let decoded = decoded.unwrap_or_else(|e| panic!("{name}: {e:?}"));
        let value = expected(row["fields"].as_array().unwrap(), false);
        assert!(decoded.transfer == value, "{name} fields");
        let mode = row["mode"].as_str().unwrap();
        assert_eq!(
            decoded.ignored_ie_count,
            usize::from(mode == "unknown-ignore")
        );
        assert_eq!(
            decoded.notify_ie_ids,
            if mode == "unknown-notify" {
                vec![65530]
            } else {
                vec![]
            }
        );
        let canonical = bytes(row["canonical_wire_hex"].as_str().unwrap());
        assert!(
            value.encode(output()).unwrap().as_bytes() == canonical,
            "{name} encoding"
        );
        let (depth, count) = budgets(&value, row["fields"].as_array().unwrap().len());
        assert!(
            ModifyRequestTransfer::decode(
                &wire,
                DecodeContext {
                    max_depth: depth,
                    max_ies: count,
                    max_message_len: wire.len(),
                    allocation_budget: opc_protocol::AllocationBudget {
                        decode_heap_allocations_fast_path: 0,
                        decode_max_temporary_bytes: 0,
                        encode_max_temporary_bytes: 0
                    },
                    ..context()
                }
            )
            .is_ok(),
            "{name} exact receive limits"
        );
        assert!(
            ModifyRequestTransfer::decode(
                &wire,
                DecodeContext {
                    max_depth: depth - 1,
                    ..context()
                }
            )
            .is_err(),
            "{name} depth"
        );
        if count > 0 {
            assert!(
                ModifyRequestTransfer::decode(
                    &wire,
                    DecodeContext {
                        max_ies: count - 1,
                        ..context()
                    }
                )
                .is_err(),
                "{name} count"
            );
        }
        assert!(
            ModifyRequestTransfer::decode(
                &wire,
                DecodeContext {
                    max_message_len: wire.len() - 1,
                    ..context()
                }
            )
            .is_err(),
            "{name} input length"
        );
        assert!(
            value
                .encode(EncodeContext {
                    max_message_len: canonical.len(),
                    ..output()
                })
                .is_ok(),
            "{name} exact output length"
        );
        assert!(
            value
                .encode(EncodeContext {
                    max_message_len: canonical.len() - 1,
                    ..output()
                })
                .is_err(),
            "{name} output length"
        );
        assert_eq!(format!("{value:?}"), "ModifyRequestTransfer([REDACTED])");
    }
    assert_eq!(admitted, 363);
}

fn append(input: &[u8], id: u16, criticality: u8, value: &[u8]) -> Vec<u8> {
    assert!(value.len() < 128);
    let mut wire = input.to_vec();
    let count = u16::from_be_bytes([wire[1], wire[2]]) + 1;
    wire[1..3].copy_from_slice(&count.to_be_bytes());
    wire.extend_from_slice(&id.to_be_bytes());
    wire.push(criticality << 6);
    wire.push(value.len() as u8);
    wire.extend_from_slice(value);
    wire
}

#[test]
fn selection_matches_shared_policies_and_distinct_duplicate_values() {
    let corpus = oracle();
    for row in corpus["cases"].as_array().unwrap() {
        let wire = bytes(row["wire_hex"].as_str().unwrap());
        if row["mode"] == "duplicate" {
            let fields = row["fields"].as_array().unwrap();
            let first = expected(fields, false);
            let last = expected(fields, true);
            assert!(first != last);
            for (duplicate_ie_policy, expected) in [
                (DuplicateIePolicy::First, first),
                (DuplicateIePolicy::Last, last),
            ] {
                let decoded = ModifyRequestTransfer::decode(
                    &wire,
                    DecodeContext {
                        duplicate_ie_policy,
                        ..context()
                    },
                )
                .unwrap();
                assert!(decoded.transfer == expected);
            }
            // Selection discards a malformed duplicate value, but never a bad
            // criticality header or broken physical framing.
            let id = fields[0]["id"].as_u64().unwrap() as u16;
            let changed = append(&wire, id, 0, &[0xff]);
            assert!(ModifyRequestTransfer::decode(
                &changed,
                DecodeContext {
                    duplicate_ie_policy: DuplicateIePolicy::First,
                    ..context()
                }
            )
            .is_ok());
            assert!(ModifyRequestTransfer::decode(
                &changed,
                DecodeContext {
                    duplicate_ie_policy: DuplicateIePolicy::Last,
                    ..context()
                }
            )
            .is_err());
            let changed = append(&wire, id, 1, &[0xff]);
            assert!(ModifyRequestTransfer::decode(
                &changed,
                DecodeContext {
                    duplicate_ie_policy: DuplicateIePolicy::First,
                    ..context()
                }
            )
            .is_err());
        }
        let mode = row["mode"].as_str().unwrap();
        if !mode.starts_with("unknown-") {
            continue;
        }
        for validation_level in [
            ValidationLevel::Structural,
            ValidationLevel::Strict,
            ValidationLevel::ProcedureAware,
        ] {
            for unknown_ie_policy in [
                UnknownIePolicy::Preserve,
                UnknownIePolicy::Drop,
                UnknownIePolicy::Reject,
            ] {
                let result = ModifyRequestTransfer::decode(
                    &wire,
                    DecodeContext {
                        validation_level,
                        unknown_ie_policy,
                        ..context()
                    },
                );
                let reject = unknown_ie_policy == UnknownIePolicy::Reject
                    || mode == "unknown-reject"
                        && !(validation_level == ValidationLevel::Structural
                            && unknown_ie_policy == UnknownIePolicy::Drop);
                if reject {
                    assert!(result.is_err());
                } else {
                    let selected = result.unwrap();
                    assert!(
                        selected.transfer
                            == expected(row["canonical_fields"].as_array().unwrap(), false)
                    );
                    assert_eq!(
                        selected.ignored_ie_count,
                        usize::from(
                            mode == "unknown-ignore"
                                && unknown_ie_policy == UnknownIePolicy::Preserve
                        )
                    );
                    assert_eq!(
                        selected.notify_ie_ids,
                        if mode == "unknown-notify"
                            && unknown_ie_policy == UnknownIePolicy::Preserve
                        {
                            vec![65530]
                        } else {
                            vec![]
                        }
                    );
                }
            }
        }
    }
}

#[test]
fn known_metadata_is_not_dropped_and_optional_ambr_stays_absent() {
    let corpus = oracle();
    let rows = corpus["cases"].as_array().unwrap();
    let all = rows.iter().find(|v| v["name"] == "presence-15").unwrap();
    for row in corpus["request_ie_metadata"].as_array().unwrap() {
        assert_eq!(row["presence"], "optional");
        let id = row["id"].as_u64().unwrap() as u16;
        let criticality = if row["criticality"] == "reject" { 0 } else { 1 };
        let supported = [130, 140, 135, 137].contains(&id);
        let value = if supported {
            bytes(
                all["fields"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|v| v["id"] == id)
                    .unwrap()["wire_hex"]
                    .as_str()
                    .unwrap(),
            )
        } else {
            vec![0]
        };
        for unknown_ie_policy in [UnknownIePolicy::Preserve, UnknownIePolicy::Drop] {
            let ctx = DecodeContext {
                unknown_ie_policy,
                ..context()
            };
            let result =
                ModifyRequestTransfer::decode(&append(&[0, 0, 0], id, criticality, &value), ctx);
            assert_eq!(result.is_ok(), supported, "known id {id}");
            if !supported {
                assert!(format!("{:?}", result.unwrap_err()).contains("unsupported n3iwf"));
            }
            assert!(
                ModifyRequestTransfer::decode(
                    &append(&[0, 0, 0], id, criticality ^ 1, &value),
                    ctx
                )
                .is_err(),
                "criticality {id}"
            );
        }
    }
    for name in [
        "presence-0",
        "request-identifiers-64",
        "request-parameters-64",
    ] {
        let row = rows.iter().find(|v| v["name"] == name).unwrap();
        let wire = bytes(row["wire_hex"].as_str().unwrap());
        let value = ModifyRequestTransfer::decode(&wire, context())
            .unwrap()
            .transfer;
        assert!(value.aggregate_bit_rate.is_none());
        assert!(value.encode(output()).unwrap().as_bytes() == wire);
        if name == "request-identifiers-64" {
            assert!(value
                .add_or_modify
                .unwrap()
                .values()
                .iter()
                .all(|v| matches!(v, QosFlowModification::Identifier(_))));
        }
    }
}

#[test]
fn malformed_container_framing_and_nonminimal_lengths_are_rejected() {
    let corpus = oracle();
    for row in corpus["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|v| v["admitted"] == true)
    {
        let wire = bytes(row["wire_hex"].as_str().unwrap());
        let mut mutations = Vec::new();
        for mask in [1, 0x40, 0x80] {
            let mut changed = wire.clone();
            changed[0] |= mask;
            mutations.push(changed);
        }
        let mut changed = wire.clone();
        changed.push(0);
        mutations.push(changed);
        let mut changed = wire.clone();
        changed[1..3].copy_from_slice(&65535u16.to_be_bytes());
        mutations.push(changed);
        if wire.len() > 3 {
            for criticality in [1, 0x40, 0xc0] {
                let mut changed = wire.clone();
                changed[5] = criticality;
                mutations.push(changed);
            }
            if wire[6] < 128 {
                let mut changed = wire.clone();
                changed.insert(6, 0x80);
                mutations.push(changed);
            }
            for determinant in [0xc0, 0xc5, 0xff] {
                let mut changed = wire.clone();
                changed[6] = determinant;
                mutations.push(changed);
            }
        }
        for changed in mutations {
            assert!(
                ModifyRequestTransfer::decode(&changed, context()).is_err(),
                "{} framing",
                row["name"]
            );
        }
    }
    // The unknown fragmented value is still physically validated when Drop
    // would remove it, including the required terminal length determinant.
    for row in corpus["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|v| v["name"].as_str().unwrap().ends_with("fragment"))
    {
        let wire = bytes(row["wire_hex"].as_str().unwrap());
        assert!(ModifyRequestTransfer::decode(
            &wire[..wire.len() - 1],
            DecodeContext {
                unknown_ie_policy: UnknownIePolicy::Drop,
                ..context()
            }
        )
        .is_err());
        let mut changed = wire.clone();
        changed.insert(changed.len() - 1, 0x80);
        assert!(ModifyRequestTransfer::decode(&changed, context()).is_err());
    }
}

#[test]
fn independent_truncations_and_bounded_mutations_replay_safely() {
    let corpus = oracle();
    for row in corpus["cases"].as_array().unwrap() {
        let wire = bytes(row["wire_hex"].as_str().unwrap());
        for end in 0..=wire.len() {
            support::exercise(&wire[..end], context(), output());
        }
        for index in (0..wire.len()).step_by((wire.len() / 128).max(1)) {
            for mask in [1, 0x80, 0xff] {
                let mut changed = wire.clone();
                changed[index] ^= mask;
                support::exercise(&changed, context(), output());
            }
        }
    }
}
