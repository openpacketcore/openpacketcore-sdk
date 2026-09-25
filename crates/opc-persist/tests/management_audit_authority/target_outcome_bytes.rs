//! RFC 019 target outcomes are disjoint from the frozen running outcomes.
//! Decoding a fixture is not proof of an authenticated or applied operation.

use opc_persist::audit_authority::AuditOperationState;
use serde_json::{json, Value};

fn authority() -> Value {
    json!({
        "cluster_id": [0x31; 32].as_slice(),
        "configuration_id": [0x32; 32].as_slice(),
        "configuration_epoch": 1,
    })
}

fn scoped_number(value: u64) -> Value {
    json!({"authority": authority(), "value": value})
}

fn scoped_token(byte: u8) -> Value {
    json!({"authority": authority(), "value": [byte; 16].as_slice()})
}

fn body(outcome: Value) -> Value {
    json!({"target-v1": {
        "authority": authority(),
        "profile_incarnation": [0x41; 16].as_slice(),
        "state_digest": [0x42; 32].as_slice(),
        "outcome": outcome,
    }})
}

fn authority_bytes() -> Vec<u8> {
    // Frozen postcard fields: fixed cluster/configuration arrays and epoch 1.
    // Do not ask the SDK encoder to generate the expected representation.
    let mut bytes = vec![0x31; 32];
    bytes.extend_from_slice(&[0x32; 32]);
    bytes.push(1);
    bytes
}

fn scoped_bytes(value: &[u8]) -> Vec<u8> {
    let mut bytes = authority_bytes();
    bytes.extend_from_slice(value);
    bytes
}

fn fixtures() -> Vec<(Value, Vec<u8>)> {
    let variants = [
        (
            json!({"candidate": {"generation": scoped_number(1)}}),
            scoped_bytes(&[1]),
        ),
        (
            json!({"startup": {"revision": scoped_number(2)}}),
            scoped_bytes(&[2]),
        ),
        (json!({"copied-running": {"running_version": 3}}), vec![3]),
        (
            json!({"promoted": {"running_version": 4, "retired_generation": scoped_number(5)}}),
            [vec![4], scoped_bytes(&[5])].concat(),
        ),
        (
            json!({"tentative": {"running_version": 6, "retired_generation": scoped_number(7), "pending": scoped_token(0x43)}}),
            [vec![6], scoped_bytes(&[7]), scoped_bytes(&[0x43; 16])].concat(),
        ),
        (
            json!({"confirmed": {"pending": scoped_token(0x43)}}),
            scoped_bytes(&[0x43; 16]),
        ),
        (
            json!({"rolled-back": {"running_version": 8, "pending": scoped_token(0x43)}}),
            [vec![8], scoped_bytes(&[0x43; 16])].concat(),
        ),
        (
            json!({"lifecycle": {"incarnation": scoped_token(0x44)}}),
            scoped_bytes(&[0x44; 16]),
        ),
    ];
    variants
        .into_iter()
        .enumerate()
        .map(|(tag, (outcome, encoded))| {
            let mut bytes = vec![4]; // Existing outcome tags 0..3 stay unchanged.
            bytes.extend_from_slice(&authority_bytes());
            bytes.extend_from_slice(&[0x41; 16]);
            bytes.extend_from_slice(&[0x42; 32]);
            bytes.push(tag as u8);
            bytes.extend_from_slice(&encoded);
            (body(outcome), bytes)
        })
        .collect()
}

#[test]
fn target_outcomes_have_versioned_disjoint_json_and_binary_fixtures() {
    for (value, bytes) in fixtures() {
        let decoded: AuditOperationState = serde_json::from_value(value.clone())
            .expect("the reviewed target-v1 outcome must decode independently of running commits");
        assert!(!matches!(decoded, AuditOperationState::Committed { .. }));
        assert_eq!(serde_json::to_value(decoded).unwrap(), value);
        assert_eq!(opc_consensus::encode_bounded(&decoded).unwrap(), bytes);
        assert_eq!(
            opc_consensus::decode_bounded::<AuditOperationState>(&bytes).unwrap(),
            decoded
        );
    }
}

#[test]
fn target_outcomes_reject_unknown_fields_tags_and_invalid_scope() {
    for (value, _) in fixtures() {
        let mut unknown = value.clone();
        unknown["target-v1"]["unrecognized"] = json!(1);
        assert!(serde_json::from_value::<AuditOperationState>(unknown).is_err());
        let mut wrong_scope = value.clone();
        let outcome = wrong_scope["target-v1"]["outcome"].as_object_mut().unwrap();
        let fields = outcome
            .values_mut()
            .next()
            .unwrap()
            .as_object_mut()
            .unwrap();
        fields.insert("unrecognized".into(), json!(1));
        assert!(serde_json::from_value::<AuditOperationState>(wrong_scope).is_err());
        let mut no_profile = value.clone();
        no_profile["target-v1"]["profile_incarnation"] = json!([0; 16].as_slice());
        assert!(serde_json::from_value::<AuditOperationState>(no_profile).is_err());
        let mut version = value["target-v1"].clone();
        version["outcome"] = json!({"unrecognized": {}});
        assert!(
            serde_json::from_value::<AuditOperationState>(json!({"target-v1":version})).is_err()
        );
        assert!(serde_json::from_value::<AuditOperationState>(
            json!({"target-v2":value["target-v1"]})
        )
        .is_err());
    }
    for name in ["candidate", "startup", "promoted", "tentative"] {
        let (mut value, _) = fixtures()
            .into_iter()
            .find(|(v, _)| v["target-v1"]["outcome"].get(name).is_some())
            .unwrap();
        let counter = match name {
            "candidate" => "generation",
            "startup" => "revision",
            _ => "retired_generation",
        };
        value["target-v1"]["outcome"][name][counter]["authority"]["configuration_epoch"] = json!(2);
        assert!(
            serde_json::from_value::<AuditOperationState>(value).is_err(),
            "foreign counter scope"
        );
    }
    for (mut value, _) in fixtures() {
        let kind = value["target-v1"]["outcome"]
            .as_object()
            .unwrap()
            .keys()
            .next()
            .unwrap()
            .clone();
        for field in [
            "generation",
            "revision",
            "retired_generation",
            "pending",
            "incarnation",
            "running_version",
        ] {
            if value["target-v1"]["outcome"][&kind].get(field).is_none() {
                continue;
            }
            let mut zero = value.clone();
            if field == "running_version" {
                zero["target-v1"]["outcome"][&kind][field] = json!(0);
            } else if matches!(field, "pending" | "incarnation") {
                zero["target-v1"]["outcome"][&kind][field]["value"] = json!([0; 16].as_slice());
            } else {
                zero["target-v1"]["outcome"][&kind][field]["value"] = json!(0);
            }
            assert!(
                serde_json::from_value::<AuditOperationState>(zero).is_err(),
                "zero applied result"
            );
        }
        value["target-v1"]
            .as_object_mut()
            .unwrap()
            .remove("state_digest");
        assert!(serde_json::from_value::<AuditOperationState>(value).is_err());
    }
}

#[test]
fn target_outcome_binary_refuses_truncation_trailing_data_and_unknown_tag() {
    for (_, bytes) in fixtures() {
        assert!(opc_consensus::decode_bounded::<AuditOperationState>(&bytes).is_ok());
        for end in 0..bytes.len() {
            assert!(opc_consensus::decode_bounded::<AuditOperationState>(&bytes[..end]).is_err());
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(opc_consensus::decode_bounded::<AuditOperationState>(&trailing).is_err());
        let mut unknown = bytes;
        // Outer tag, authority (32 + 32 + 1), profile (16), digest (32).
        unknown[114] = 8;
        assert!(opc_consensus::decode_bounded::<AuditOperationState>(&unknown).is_err());
    }
}

#[test]
fn target_outcome_diagnostics_hide_scope_and_state() {
    for (value, _) in fixtures() {
        let decoded: AuditOperationState = serde_json::from_value(value).unwrap();
        assert_eq!(
            format!("{decoded:?}"),
            "TargetV1(NetconfTargetResult(<redacted>))"
        );
    }
}
