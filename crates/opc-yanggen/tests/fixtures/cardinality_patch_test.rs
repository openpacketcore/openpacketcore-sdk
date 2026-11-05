use generated_test::{patch::{self, ConfigDelta}, types::Root};
use opc_config_model::{OpcConfig, YangPath};
use serde_json::json;

fn update(name: &str, value: &str) -> ConfigDelta {
    ConfigDelta::Update(YangPath::new(format!("/p:root/p:{name}")).unwrap(), value.into())
}

#[test]
fn partial_patches_defer_whole_configuration_cardinality() {
    let mut root = Root::default();
    patch::apply_patch(&mut root, &[update("first", "7")]).unwrap();
    assert!(root.validate_syntax().is_err());
    patch::apply_patch(&mut root, &[update("second", "ready")]).unwrap();
    assert!(root.validate_syntax().is_err());
    patch::apply_patch(&mut root, &[update("codes", r#"["a"]"#)]).unwrap();
    root.validate_syntax().unwrap();
    for invalid in [r#"[]"#, r#"["a","b","c"]"#] {
        let mut candidate = root.clone();
        patch::apply_patch(&mut candidate, &[update("codes", invalid)]).unwrap();
        assert!(candidate.validate_syntax().is_err(), "final candidate still enforces cardinality");
    }
}

#[test]
fn individual_delta_replay_reconstructs_a_complete_candidate() {
    let desired: Root = serde_json::from_value(json!({"first":7,"second":"ready","codes":["a"]})).unwrap();
    let mut replay = Root::default();
    let deltas = desired.diff(&replay).unwrap();
    assert!(deltas.len() > 1);
    for delta in deltas { replay.apply_delta(delta).unwrap(); }
    assert_eq!(replay, desired);
    replay.validate_syntax().unwrap();
}

#[test]
fn partial_patch_scalar_and_uniqueness_checks_remain_atomic() {
    let initial: Root = serde_json::from_value(json!({"first":7,"second":"ready","codes":["a"]})).unwrap();
    for delta in [update("first", "11"), update("second", "too-long-value"), update("codes", r#"["a","a"]"#)] {
        let mut candidate = initial.clone();
        assert!(patch::apply_patch(&mut candidate, &[delta]).is_err());
        assert_eq!(candidate, initial);
    }
}
