use generated_config_false_test::{keyless, keys, minimal, mixed, nested};
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
fn removing_state_row_does_not_create_configuration_deltas() {
    let previous = sample();
    let mut current = previous.clone();
    current.error.clear();
    assert!(current.diff(&previous).unwrap().is_empty());
}

#[test]
fn removing_state_container_does_not_create_configuration_deltas() {
    let previous: mixed::types::Root = serde_json::from_value(json!({
        "hostname": "router",
        "state": {"error": [{"reason": "temporary", "count": 7}]}
    }))
    .unwrap();
    let mut current = previous.clone();
    current.state = None;
    assert!(current.diff(&previous).unwrap().is_empty());
}

#[test]
fn removing_nested_state_container_does_not_create_configuration_deltas() {
    let previous: nested::types::State = serde_json::from_value(json!({
        "sample": [{"name": "edge", "detail": {"count": 7}}]
    }))
    .unwrap();
    let mut current = previous.clone();
    current.sample.get_mut("edge").unwrap().detail = None;
    assert!(current.diff(&previous).unwrap().is_empty());
}

#[test]
fn state_leaf_list_changes_do_not_create_configuration_deltas() {
    let previous: nested::types::State = serde_json::from_value(json!({
        "label": ["ready", "active"]
    }))
    .unwrap();
    let mut current = previous.clone();
    current.label.clear();
    assert!(current.diff(&previous).unwrap().is_empty());
    current.label.push("available".to_owned());
    assert!(current.diff(&previous).unwrap().is_empty());
}

#[test]
fn state_keyless_list_changes_do_not_create_configuration_deltas() {
    let previous: nested::types::State = serde_json::from_value(json!({
        "observation": [{"value": 7}]
    }))
    .unwrap();
    let mut current = previous.clone();
    current.observation[0].value = Some(8);
    assert!(current.diff(&previous).unwrap().is_empty());
    current.observation.clear();
    assert!(current.diff(&previous).unwrap().is_empty());
}

#[test]
fn state_removal_preserves_writable_sibling_delta() {
    let previous: mixed::types::Root = serde_json::from_value(json!({
        "hostname": "old",
        "state": {"error": [{"reason": "temporary", "count": 7}]}
    }))
    .unwrap();
    let mut current = previous.clone();
    current.state = None;
    current.hostname = mixed::types::LeafPresence::Explicit("new".to_owned());
    assert_eq!(
        current.diff(&previous).unwrap(),
        vec![mixed::patch::ConfigDelta::Update(
            YangPath::new("/mx:root/mx:hostname").unwrap(),
            "new".to_owned()
        )]
    );
}

fn assert_safe_patch_error(error: &opc_config_model::ConfigError, kind: &str, message: &str) {
    assert_eq!(error.kind(), kind);
    assert_eq!(error.message(), message);
    for text in [error.message().to_owned(), error.to_string(), format!("{error:?}")] {
        assert!(!text.contains("synthetic-secret"));
        assert!(!text.contains("token="));
    }
}

#[test]
fn state_sensitive_key_patch_errors_do_not_disclose_values() {
    let previous: keys::types::State = serde_json::from_value(json!({
        "account": [{"token": "synthetic-secret", "count": 7}],
        "session": [{"token": "synthetic-secret", "region": 2, "active": true}]
    }))
    .unwrap();
    for text in [
        "/sk:state/sk:account[token='synthetic-secret']",
        "/sk:state/sk:account[token='synthetic-secret']/sk:count",
        "/sk:state/sk:session[token='synthetic-secret'][region='2']/sk:active",
    ] {
        let path = YangPath::new(text).unwrap();
        for delta in [
            keys::patch::ConfigDelta::Update(path.clone(), "8".to_owned()),
            keys::patch::ConfigDelta::Replace(path.clone(), "8".to_owned()),
            keys::patch::ConfigDelta::Merge(path.clone(), "8".to_owned()),
            keys::patch::ConfigDelta::Delete(path.clone()),
            keys::patch::ConfigDelta::Remove(path.clone()),
        ] {
            let mut state = previous.clone();
            let error = keys::patch::apply_patch(&mut state, &[delta]).unwrap_err();
            assert_eq!(state, previous);
            assert_safe_patch_error(&error, "read-only", "cannot modify read-only path");
        }
    }
}

#[test]
fn invalid_patch_paths_do_not_disclose_sensitive_keys() {
    let previous: keys::types::State = serde_json::from_value(json!({
        "account": [{"token": "synthetic-secret", "count": 7}]
    }))
    .unwrap();
    for text in [
        "/sk:state/sk:account[token='synthetic-secret']/sk:unknown",
        "/sk:unknown[token='synthetic-secret']",
    ] {
        let mut state = previous.clone();
        let path = YangPath::new(text).unwrap();
        let error = keys::patch::apply_patch(
            &mut state,
            &[keys::patch::ConfigDelta::Delete(path)],
        )
        .unwrap_err();
        assert_eq!(state, previous);
        assert_safe_patch_error(&error, "invalid-path", "invalid path");
    }
}

#[test]
fn patch_json_errors_do_not_disclose_values_or_unknown_fields() {
    use mixed::patch::ConfigDelta;
    let previous: mixed::types::Root = serde_json::from_value(json!({"hostname": "old"})).unwrap();
    for (path, value, replace, kind, message) in [
        ("/mx:root", json!({"synthetic-secret": "value"}), false, "unsupported-path", "unsupported field"),
        ("/mx:root", json!({"count": "synthetic-secret"}), false, "invalid-value", "invalid numeric value"),
        ("/mx:root", json!({"count": "synthetic-secret"}), true, "invalid-value", "invalid JSON value"),
        ("/mx:root/mx:counters", json!(["synthetic-secret"]), false, "invalid-value", "invalid JSON value"),
        ("/mx:root/mx:counters", json!(["synthetic-secret"]), true, "invalid-value", "invalid JSON value"),
        ("/mx:root/mx:account[token='synthetic-secret']", json!({"count": "synthetic-secret"}), false, "invalid-value", "invalid JSON value"),
        ("/mx:root/mx:account[token='synthetic-secret']", json!({"count": "synthetic-secret"}), true, "invalid-value", "invalid JSON value"),
    ] {
        let mut candidate = previous.clone();
        let path = YangPath::new(path).unwrap();
        let delta = if replace { ConfigDelta::Replace(path, value.to_string()) } else { ConfigDelta::Merge(path, value.to_string()) };
        let error = mixed::patch::apply_patch(&mut candidate, &[delta]).unwrap_err();
        assert_safe_patch_error(&error, kind, message);
        assert_eq!(candidate, previous);
    }
}

#[test]
fn leafref_leaf_list_errors_never_disclose_referenced_values() {
    use opc_config_model::{CommitMode, ConfigOperation, RequestId, RequestSource, TransportType, TrustedPrincipal, ValidationContext, ValidationError, WorkloadIdentity};
    let context = ValidationContext {
        request_id: RequestId::new(),
        principal: TrustedPrincipal::new(WorkloadIdentity::Internal("test".into()), opc_types::TenantId::new("example").unwrap()),
        transport: TransportType::Internal,
        source: RequestSource::Northbound,
        operation: ConfigOperation::Replace,
        mode: CommitMode::Commit,
        base_version: opc_types::ConfigVersion::INITIAL,
        previous: None,
    };
    for name in ["references", "api-token"] {
        let mut candidate: mixed::types::Root = serde_json::from_value(json!({"hostname": "present"})).unwrap();
        let path = YangPath::new(format!("/mx:root/mx:{name}")).unwrap();
        mixed::patch::apply_patch(&mut candidate, &[mixed::patch::ConfigDelta::Update(path.clone(), json!(["present"]).to_string())]).unwrap();
        candidate.validate_semantics(&context).unwrap();
        mixed::patch::apply_patch(&mut candidate, &[mixed::patch::ConfigDelta::Update(path, json!(["present", "synthetic-secret"]).to_string())]).unwrap();
        let error = candidate.validate_semantics(&context).unwrap_err();
        assert_eq!(error, ValidationError::semantics("Leaf-list value at index 1 not found in target path /mx:root/mx:hostname"));
        for text in [error.message.clone(), error.to_string(), format!("{error:?}")] {
            assert!(!text.contains("synthetic-secret"));
            assert!(!text.contains("present"));
        }
    }
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
        "cannot modify read-only path"
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

#[test]
fn nested_keyless_state_content_round_trips_without_configuration_deltas() {
    let state: keyless::types::State = serde_json::from_value(json!({
        "keyed": [{
            "name": "first",
            "observation": [{"detail": {"count": 7}, "label": ["a", "b"]}]
        }]
    })).unwrap();
    let row = state.keyed.get("first").unwrap();
    assert_eq!(row.observation.len(), 1);
    assert_eq!(row.observation[0].detail.as_ref().unwrap().count, Some(7));
    assert_eq!(row.observation[0].label, ["a", "b"]);
    let encoded = serde_json::to_value(&state).unwrap();
    let restored: keyless::types::State = serde_json::from_value(encoded).unwrap();
    assert_eq!(restored, state);
    let absent = keyless::types::State::default();
    assert!(state.changed_paths(&absent).is_empty());
    assert!(keyless::patch::diff_root(&state, &absent).unwrap().is_empty());
}

#[test]
fn nested_keyless_state_edit_keeps_its_rejection_stub() {
    use opc_mgmt_schema::{EditConfigNode, EditOperation, NetconfXmlEditApplicator, NodeKind};

    let state: keyless::types::State = serde_json::from_value(json!({
        "keyed": [{"name": "first", "observation": [{"label": ["retained"]}]}]
    })).unwrap();
    let original = state.clone();
    let edit = EditConfigNode {
        schema_path: "/nk:state",
        operation: EditOperation::Merge,
        value: None,
        list_keys: Default::default(),
        children: vec![EditConfigNode {
            schema_path: "/nk:state/nk:keyed",
            operation: EditOperation::Merge,
            value: None,
            list_keys: [("name".into(), "first".into())].into(),
            children: vec![EditConfigNode {
                schema_path: "/nk:state/nk:keyed/nk:observation",
                operation: EditOperation::Merge,
                value: None,
                list_keys: Default::default(),
                children: Vec::new(),
            }],
        }],
    };
    let error = keyless::netconf_xml_edit::applicator().apply_edit_config(&state, &edit).unwrap_err();
    assert_eq!(error, NetconfEditError::UnsupportedShape {
        path: "/nk:state/nk:keyed/nk:observation",
        kind: NodeKind::List,
    });
    assert_eq!(state, original);
}
