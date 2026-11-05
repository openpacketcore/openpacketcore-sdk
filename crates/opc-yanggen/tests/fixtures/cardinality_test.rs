use generated_test::types::Root;
use opc_config_model::OpcConfig;
use serde_json::{json, Value};

fn valid() -> Value {
    json!({"required": false, "plain": {"inside": "present"},
        "server": [{"name": "a", "port": 0, "details": {"online": false}}],
        "codes": ["a"], "api-token": ["sensitive-value-marker"]})
}

fn check(value: Value) -> Result<(), opc_config_model::ValidationError> {
    serde_json::from_value::<Root>(value).unwrap().validate_syntax()
}

#[test]
fn mandatory_boolean_distinguishes_false_from_absent_and_invalid_lexical_values() {
    check(valid()).unwrap();
    let mut missing = valid();
    missing.as_object_mut().unwrap().remove("required");
    assert!(check(missing).is_err());
    for value in [Value::Null, json!("false"), json!(0)] {
        let mut config = valid();
        config["required"] = value;
        let parsed = serde_json::from_value::<Root>(config);
        assert!(parsed.is_err() || parsed.unwrap().validate_syntax().is_err());
    }
}

#[test]
fn absent_nonpresence_containers_do_not_hide_required_descendants() {
    let mut missing = valid();
    missing.as_object_mut().unwrap().remove("plain");
    assert!(check(missing).is_err());
    let mut missing = valid();
    missing["server"][0].as_object_mut().unwrap().remove("details");
    assert!(check(missing).is_err());
    check(valid()).unwrap();
    let mut enabled = valid();
    enabled["enabled"] = json!({});
    assert!(check(enabled.clone()).is_err());
    enabled["enabled"] = json!({"token": "present", "labels": ["a", "b"]});
    check(enabled.clone()).unwrap();
    enabled["enabled"]["labels"] = json!(["a"]);
    assert!(check(enabled).is_err());
}

#[test]
fn list_bounds_and_entry_requirements_are_enforced() {
    let entry = valid()["server"][0].clone();
    for size in [0, 3] {
        let mut config = valid();
        config["server"] = (0..size).map(|index| {
            let mut entry = entry.clone(); entry["name"] = json!(format!("server-{index}")); entry
        }).collect::<Vec<_>>().into();
        assert!(check(config).is_err());
    }
    let mut missing = valid();
    missing["server"][0].as_object_mut().unwrap().remove("port");
    assert!(check(missing).is_err());
    let mut two = valid();
    let mut other = entry;
    other["name"] = json!("b");
    two["server"].as_array_mut().unwrap().push(other);
    check(two).unwrap();
}

#[test]
fn leaf_list_bounds_apply_to_user_ordered_and_sensitive_values() {
    for leaf in ["codes", "api-token"] {
        for values in [json!([]), json!(["a", "b", "sensitive-value-marker"])] {
            let mut config = valid(); config[leaf] = values;
            let error = check(config).unwrap_err();
            assert!(!format!("{error:?}").contains("sensitive-value-marker"));
        }
        let mut config = valid(); config[leaf] = json!(["a", "b"]);
        check(config).unwrap();
    }
}
