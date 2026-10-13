use generated_config_false_test::{keys, minimal, mixed, nested};
use opc_config_model::{OpcConfig, YangPath};
use opc_gnmi_server::{GnmiJsonRenderer, ReadSelection, ReadSelectionEntry};
use opc_mgmt_limits::MgmtLimits;
use opc_mgmt_schema::{DefaultReport, NetconfEditError, NetconfXmlRenderer};
use opc_netconf_server::{parse_edit_config_xml_with_limits, EditDefaultOperation};
use serde_json::json;

fn sample() -> minimal::types::State {
    serde_json::from_value(json!({
        "error": [{"reason": "temporary", "count": 7}]
    }))
    .unwrap()
}

#[test]
fn state_single_key_retains_its_optional_leaf_and_map_key_type() {
    let state = sample();
    let entry = state.error.get("temporary").unwrap();
    let reason: &Option<String> = &entry.reason;
    assert_eq!(reason.as_deref(), Some("temporary"));
    assert_eq!(entry.count, Some(7));
    assert_eq!(
        minimal::serde::ExtractKey::extract_key(entry),
        Some("temporary".to_owned())
    );
    let encoded = serde_json::to_value(&state).unwrap();
    assert_eq!(
        encoded,
        json!({"minimal-state:error": [{"reason": "temporary", "count": 7}]})
    );
    let decoded: minimal::types::State = serde_json::from_value(encoded).unwrap();
    assert_eq!(decoded, state);
}

#[test]
fn state_composite_key_retains_each_scalar_type() {
    let state: keys::types::State = serde_json::from_value(json!({
        "endpoint": [{"region": 7, "name": "edge", "active": true}]
    }))
    .unwrap();
    let key = keys::types::EndpointKey {
        region: 7,
        name: "edge".to_owned(),
    };
    let entry = state.endpoint.get(&key).unwrap();
    assert_eq!(entry.region, Some(7));
    assert_eq!(entry.name.as_deref(), Some("edge"));
    assert_eq!(keys::serde::ExtractKey::extract_key(entry), Some(key));
}

#[test]
fn state_sensitive_single_and_composite_keys_extract_and_redact() {
    let state: keys::types::State = serde_json::from_value(json!({
        "account": [{"token": "single-secret", "count": 1}],
        "session": [{"token": "composite-secret", "region": 2, "active": true}]
    }))
    .unwrap();
    let account = state.account.get("single-secret").unwrap();
    let key: keys::types::SensitiveKey<String> =
        keys::serde::ExtractKey::extract_key(account).unwrap();
    assert_eq!(key.get(), "single-secret");
    assert_eq!(account.token.get().as_deref(), Some("single-secret"));
    let session_key = keys::types::SessionKey {
        token: "composite-secret".to_owned(),
        region: 2,
    };
    let session = state.session.get(&session_key).unwrap();
    assert_eq!(
        keys::serde::ExtractKey::extract_key(session),
        Some(session_key)
    );
    let debug = format!("{state:?}");
    assert!(debug.contains("<REDACTED>"));
    assert!(!debug.contains("single-secret"));
    assert!(!debug.contains("composite-secret"));
}

#[test]
fn state_list_missing_and_duplicate_keys_are_rejected() {
    let missing = serde_json::from_value::<minimal::types::State>(json!({
        "error": [{"count": 7}]
    }))
    .unwrap_err();
    assert_eq!(missing.to_string(), minimal::serde::MISSING_LIST_KEY_ERROR);
    let duplicate = serde_json::from_value::<minimal::types::State>(json!({
        "error": [{"reason": "temporary"}, {"reason": "temporary"}]
    }))
    .unwrap_err();
    assert_eq!(
        duplicate.to_string(),
        minimal::serde::DUPLICATE_LIST_KEY_ERROR
    );
}

#[test]
fn state_list_gnmi_read_emits_the_selected_entry() {
    let state = sample();
    let schema_path = "/ms:state/ms:error/ms:count";
    let path = YangPath::new("/ms:state/ms:error[ms:reason='temporary']/ms:count").unwrap();
    let selection = [ReadSelectionEntry::new(schema_path, path.clone())];
    let updates = minimal::gnmi_json::renderer()
        .render_running_json(
            &state,
            ReadSelection::with_entries(&[schema_path], &selection),
        )
        .unwrap();
    assert_eq!(updates.len(), 1);
    assert_eq!(updates[0].path(), &path);
    assert_eq!(updates[0].value_json(), "7");
}

#[test]
fn state_list_netconf_read_includes_the_key_and_counter() {
    let xml = minimal::netconf_xml::renderer()
        .render_running_config(
            &sample(),
            &[
                "/ms:state/ms:error/ms:reason",
                "/ms:state/ms:error/ms:count",
            ],
            DefaultReport::Trim,
        )
        .unwrap();
    assert!(xml.contains("<ms:reason>temporary</ms:reason>"));
    assert!(xml.contains("<ms:count>7</ms:count>"));
}

#[test]
fn state_counter_changes_do_not_create_configuration_deltas() {
    let previous = sample();
    let mut current = previous.clone();
    current.error.get_mut("temporary").unwrap().count = Some(8);
    assert!(current.diff(&previous).unwrap().is_empty());
}

#[test]
fn nested_state_counter_changes_do_not_create_configuration_deltas() {
    let previous: nested::types::State = serde_json::from_value(json!({
        "sample": [{"name": "edge", "detail": {"count": 7}}]
    }))
    .unwrap();
    let mut current = previous.clone();
    let entry = current.sample.get_mut("edge").unwrap();
    assert_eq!(entry.name.as_deref(), Some("edge"));
    let detail = entry.detail.as_mut().unwrap();
    assert_eq!(detail.count, Some(7));
    detail.count = Some(8);
    assert!(current.diff(&previous).unwrap().is_empty());
}

#[test]
fn state_list_patch_is_refused_without_mutation() {
    let mut state = sample();
    let previous = state.clone();
    let path = YangPath::new("/ms:state/ms:error[reason='temporary']/ms:count").unwrap();
    let error = minimal::patch::apply_patch(
        &mut state,
        &[minimal::patch::ConfigDelta::Update(path, "8".to_owned())],
    )
    .unwrap_err();
    assert_eq!(error.kind(), "read-only");
    assert_eq!(
        error.message(),
        "cannot modify read-only path: /ms:state/ms:error[reason='temporary']/ms:count"
    );
    assert_eq!(state, previous);
}

#[test]
fn state_list_netconf_edit_is_refused() {
    let error = parse_edit_config_xml_with_limits(
        r#"<config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><state xmlns="urn:example:minimal-state"><error><reason>temporary</reason><count>8</count></error></state></config>"#,
        minimal::schema_registry::registry(),
        EditDefaultOperation::Merge,
        &MgmtLimits::default(),
    )
    .unwrap_err();
    assert_eq!(error, NetconfEditError::ReadOnly { path: "/ms:state" });
}

#[test]
fn configuration_sibling_keeps_its_writable_leaf_type() {
    let mut root: mixed::types::Root = serde_json::from_value(json!({
        "hostname": "old",
        "state": {"error": [{"reason": "temporary", "count": 7}]}
    }))
    .unwrap();
    let previous_state = root.state.clone();
    let path = YangPath::new("/mx:root/mx:hostname").unwrap();
    mixed::patch::apply_patch(
        &mut root,
        &[mixed::patch::ConfigDelta::Update(path, "new".to_owned())],
    )
    .unwrap();
    assert_eq!(
        root.hostname,
        mixed::types::LeafPresence::Explicit("new".to_owned())
    );
    assert_eq!(root.state, previous_state);
}
