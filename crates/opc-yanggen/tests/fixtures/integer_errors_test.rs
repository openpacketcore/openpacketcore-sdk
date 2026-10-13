use generated_test::{gnmi_set, patch, types::*};
use opc_config_model::{OpcConfig, YangPath};
use opc_gnmi_server::{Encoding, GnmiError, GnmiPatchApplicator, NormalizedSet, NormalizedValue};
use serde_json::{json, Value};

fn invalid_integer_bodies() -> Vec<Value> {
    let mut bodies = Vec::new();
    for (ty, below, above) in [
        ("uint8", "-1", "256"),
        ("uint16", "-1", "65536"),
        ("uint32", "-1", "4294967296"),
        ("uint64", "-1", "18446744073709551616"),
        ("int8", "-129", "128"),
        ("int16", "-32769", "32768"),
        ("int32", "-2147483649", "2147483648"),
        ("int64", "-9223372036854775809", "9223372036854775808"),
    ] {
        let wrong_shape = if ty.ends_with("64") { json!(987654321) } else { json!("synthetic-secret-marker") };
        let wrong_values = [wrong_shape, json!(["synthetic-secret-marker"]), json!({"synthetic-secret-marker": 987654321})];
        for value in wrong_values.into_iter().chain([below, above].map(|value| {
            if ty.ends_with("64") { json!(value) } else { serde_json::from_str(value).unwrap() }
        })) {
            bodies.extend([
                json!({format!("example:secret-{ty}"): value.clone()}),
                json!({format!("example:bounded-{ty}"): value.clone()}),
                json!({format!("example:secret-{ty}-values"): [value.clone()]}),
                json!({format!("example:by-{ty}"): [{"secret-id": value, "value": 1}]}),
            ]);
        }
    }
    bodies.push(json!({"example:child": {"secret-value": 987654321}}));
    bodies.push(json!({"example:state": {"counter": "synthetic-secret-marker"}}));
    bodies
}

#[test]
fn integer_json_refusals_have_exact_value_free_reasons() {
    for body in invalid_integer_bodies() {
        let error = serde_json::from_value::<Root>(body).unwrap_err();
        assert_eq!(error.to_string(), "invalid integer value");
    }
}

#[test]
fn malformed_subtree_patches_are_atomic_and_value_free() {
    let baseline: Root = serde_json::from_value(json!({"example:secret-uint8": 1})).unwrap();
    for body in invalid_integer_bodies() {
        for operation in [patch::ConfigOp::Update, patch::ConfigOp::Merge, patch::ConfigOp::Replace] {
            let mut candidate = baseline.clone();
            let segments = patch::parse_path("").unwrap();
            let error = candidate.apply_patch_segments(&operation, &segments, Some(&body.to_string())).unwrap_err();
            assert_eq!(error.kind(), "invalid-value");
            assert_eq!(error.message(), "invalid integer value");
            assert_eq!(candidate, baseline);
        }
        let mut candidate = baseline.clone();
        let error = patch::apply_patch(&mut candidate, &[
            patch::ConfigDelta::Update(YangPath::new("/ex:root/ex:secret-uint8").unwrap(), "2".into()),
            patch::ConfigDelta::Replace(YangPath::new("/ex:root").unwrap(), body.to_string()),
        ]).unwrap_err();
        assert_eq!(error.kind(), "invalid-value");
        assert_eq!(error.message(), "invalid integer value");
        assert_eq!(candidate, baseline);
    }
    assert_eq!(baseline.validate_syntax(), Ok(()));
}

#[test]
fn malformed_integer_wrappers_never_forward_serde_values() {
    for value in [json!(987654321), json!("synthetic-secret-marker"), json!(["synthetic-secret-marker"])] {
        assert_eq!(serde_json::from_value::<YangUint64>(value.clone()).unwrap_err().to_string(),
                   "invalid integer value");
        assert_eq!(serde_json::from_value::<YangInt64>(value).unwrap_err().to_string(),
                   "invalid integer value");
    }
}

#[test]
fn gnmi_subtree_integer_refusals_do_not_depend_on_string_constraints() {
    let baseline: Root = serde_json::from_value(json!({"example:secret-uint8": 1})).unwrap();
    for body in invalid_integer_bodies() {
        let mut request = NormalizedSet::default();
        request.updates.push((
            YangPath::new("/ex:root").unwrap(),
            NormalizedValue::new(Encoding::JsonIetf, body.to_string(), &Default::default()).unwrap(),
        ));
        assert_eq!(gnmi_set::patcher().apply_set(&baseline, &request).unwrap_err(),
                   GnmiError::invalid("gNMI Set patch application failed"));
        assert_eq!(serde_json::to_value(&baseline).unwrap(), json!({"example:secret-uint8": 1}));
    }
}

#[test]
fn malformed_structures_never_echo_values_from_integer_models() {
    for body in [
        json!(987654321), json!("synthetic-secret-marker"),
        json!({"example:child": "synthetic-secret-marker"}),
        json!({"example:by-uint8": "synthetic-secret-marker"}),
    ] {
        assert_eq!(serde_json::from_value::<Root>(body.clone()).unwrap_err().to_string(),
                   "invalid JSON configuration");
        let mut candidate = Root::default();
        let error = patch::apply_patch(&mut candidate, &[patch::ConfigDelta::Replace(
            YangPath::new("/ex:root").unwrap(), body.to_string()
        )]).unwrap_err();
        assert_eq!(error.kind(), "invalid-value");
        assert_eq!(error.message(), "invalid JSON configuration");
        assert_eq!(candidate, Root::default());
    }
}

#[test]
fn integer_key_integrity_keeps_its_exact_value_free_reasons() {
    for ty in ["uint8", "uint16", "uint32", "uint64", "int8", "int16", "int32", "int64"] {
        let id = if ty.ends_with("64") { json!("1") } else { json!(1) };
        let row = json!({"secret-id": id, "value": 1});
        let field = format!("example:by-{ty}");
        let baseline: Root = serde_json::from_value(json!({&field: [row.clone()]})).unwrap();
        for (rows, reason) in [
            (json!([{"value": 1}]), "keyed-list entry is missing a required key leaf"),
            (json!([row.clone(), row]), "keyed-list contains a duplicate key"),
        ] {
            let body = json!({&field: rows});
            assert_eq!(serde_json::from_value::<Root>(body.clone()).unwrap_err().to_string(), reason);
            let mut candidate = baseline.clone();
            let error = patch::apply_patch(&mut candidate, &[patch::ConfigDelta::Replace(
                YangPath::new("/ex:root").unwrap(), body.to_string()
            )]).unwrap_err();
            assert_eq!(error.kind(), "invalid-value");
            assert_eq!(error.message(), reason);
            assert_eq!(candidate, baseline);
        }
    }
}

fn invalid_direct_scalar_values() -> [Value; 4] {
    [json!(987654321), json!("synthetic-secret-marker"),
     json!(["synthetic-secret-marker"]), json!({"synthetic-secret-marker": 1})]
}

#[test]
fn direct_sensitive_keys_never_forward_scalar_values() {
    for value in invalid_direct_scalar_values() {
        assert_eq!(serde_json::from_value::<SensitiveKey<u8>>(value).unwrap_err().to_string(), "invalid JSON configuration");
    }
}

#[test]
fn direct_secret_wrappers_never_forward_scalar_values() {
    for value in invalid_direct_scalar_values() {
        assert_eq!(serde_json::from_value::<SecretLeaf<u8>>(value).unwrap_err().to_string(), "invalid JSON configuration");
    }
}

#[test]
fn direct_presence_wrappers_never_forward_scalar_values() {
    for value in invalid_direct_scalar_values() {
        assert_eq!(serde_json::from_value::<LeafPresence<u8>>(value).unwrap_err().to_string(), "invalid JSON configuration");
    }
}

#[test]
fn direct_composite_keys_never_forward_scalar_values() {
    for value in invalid_direct_scalar_values() {
        assert_eq!(serde_json::from_value::<PairKey>(json!({"secret_id": value, "slot": "1"})).unwrap_err().to_string(), "invalid JSON configuration");
        assert_eq!(serde_json::from_value::<PairKey>(json!({"secret_id": 1, "slot": value})).unwrap_err().to_string(), "invalid integer value");
    }
}
