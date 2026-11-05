use generated_test::types::Root;
use opc_config_model::OpcConfig;
use serde_json::{json, Value};

fn valid() -> Value { json!({"protected":{"amount":7}, "entries":[{"name":"private-marker","amount":2}]}) }
fn check(value: Value) -> bool {
    serde_json::from_value::<Root>(value).is_ok_and(|root| root.validate_syntax().is_ok())
}

#[test]
fn sensitive_leaves_preserve_required_fields_and_cardinality() {
    assert!(check(valid()));
    let mut missing = valid(); missing.as_object_mut().unwrap().remove("protected"); assert!(!check(missing));
    let mut missing = valid(); missing["entries"][0].as_object_mut().unwrap().remove("amount"); assert!(!check(missing));
    for entries in [json!([]), json!([{"name":"a","amount":1},{"name":"b","amount":2},{"name":"c","amount":3}])] {
        let mut value = valid(); value["entries"] = entries; assert!(!check(value));
    }
    let mut active = valid(); active["enabled"] = json!({}); assert!(!check(active.clone()));
    active["enabled"]["token"] = json!("present"); assert!(check(active));
}

#[test]
fn sensitive_leaf_scalar_failures_remain_value_free() {
    for field in ["protected", "entries"] {
        let mut value = valid();
        if field == "entries" { value[field][0]["amount"] = json!(11); } else { value[field]["amount"] = json!(11); }
        assert!(!check(value));
    }
    let root: Root = serde_json::from_value(valid()).unwrap();
    assert!(!format!("{root:?}").contains("private-marker"));
}
