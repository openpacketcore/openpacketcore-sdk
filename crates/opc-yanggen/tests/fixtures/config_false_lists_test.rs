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
fn state_sensitive_numeric_key_retains_copy_and_redaction() {
    let state: keys::types::State = serde_json::from_value(json!({
        "grant": [{"token-id": 918273, "count": 7}]
    })).unwrap();
    let row = state.grant.get(&918273).unwrap();
    let key: keys::types::SensitiveKey<u32> = keys::serde::ExtractKey::extract_key(row).unwrap();
    let copied = key;
    assert_eq!(*key.get(), 918273);
    assert_eq!(copied, key);
    assert_eq!(*row.token_id.get(), Some(918273));
    assert_eq!(format!("{key:?}"), "<REDACTED>");
    assert!(!format!("{state:?}").contains("918273"));
}

#[test]
fn state_defaults_keep_optional_presence_without_inventing_observations() {
    let default = keys::types::Grant::default();
    let count: &Option<u32> = &default.count;
    assert_eq!(*count, None);
    assert_eq!(*default.secret_counter.get(), None);
    let absent: keys::types::Grant = serde_json::from_value(json!({"token-id": 17})).unwrap();
    assert_eq!(absent.count, None);
    assert_eq!(*absent.secret_counter.get(), None);
    let present: keys::types::Grant = serde_json::from_value(json!({
        "token-id": 17, "count": 0, "secret-counter": 0
    })).unwrap();
    assert_eq!(present.count, Some(0));
    assert_eq!(*present.secret_counter.get(), Some(0));
    let encoded = serde_json::to_value(&present).unwrap();
    assert_eq!(encoded["count"], 0);
    assert_eq!(encoded["secret-counter"], 0);
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
    let deltas = keyless::patch::diff_root(&state, &absent).unwrap();
    assert!(deltas.is_empty());
    assert!(state.changed_paths(&absent, &deltas).unwrap().is_empty());
}

#[test]
fn nested_keyless_state_edit_is_read_only() {
    use opc_mgmt_schema::{EditConfigNode, EditOperation, NetconfXmlEditApplicator};

    let state: keyless::types::State = serde_json::from_value(json!({
        "keyed": [{"name": "first", "observation": [{"label": ["retained"]}]}]
    })).unwrap();
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
    assert_eq!(error, NetconfEditError::ReadOnly { path: "/nk:state" });
}

fn state_write_bodies() -> Vec<(&'static str, serde_json::Value)> {
    vec![
        ("/mx:root", json!({"hostname": "new", "state": {"error": [{"reason": "synthetic-secret", "count": 8}]}})),
        ("/mx:root", json!({"hostname": "new", "mixed-state:state": null})),
        ("/mx:root", json!({"health": true})),
        ("/mx:root", json!({"state-label": []})),
        ("/mx:root", json!({"account": [{"token": "synthetic-secret", "telemetry": {"packets": 8}}]})),
        ("/mx:root", json!({"channel": [{"name": "first", "status": {"count": 8}}]})),
        ("/mx:root", json!({"mixed-state:branch": {"mixed-state:branch-state": {"count": 8}}})),
        ("/mx:root/mx:account[token='synthetic-secret']", json!({"count": 8, "telemetry": null})),
        ("/mx:root/mx:channel[name='first']", json!({"name": "first", "status": {}})),
        ("/mx:root/mx:channel", json!([{ "name": "first", "status": {"count": 8}}])),
        ("/mx:root/mx:branch", json!({"setting": "new", "branch-state": {"count": "synthetic-secret"}})),
    ]
}

fn writable_sample() -> mixed::types::Root {
    serde_json::from_value(json!({"hostname": "old", "branch": {"setting": "old"}})).unwrap()
}

fn populated_state() -> mixed::types::Root {
    serde_json::from_value(json!({
        "hostname": "old",
        "state": {"error": [{"reason": "synthetic-secret", "count": 7}]},
        "account": [{"token": "synthetic-secret", "count": 1, "telemetry": {"packets": 7}}],
        "channel": [{"name": "first", "setting": "old", "status": {"count": 7}}],
        "branch": {"setting": "old", "branch-state": {"count": 7}}
    })).unwrap()
}

#[test]
fn ancestor_patch_bodies_reject_state_members_atomically() {
    use mixed::patch::ConfigDelta;
    let previous = writable_sample();
    for (path, body) in state_write_bodies() {
        let path = YangPath::new(path).unwrap();
        for delta in [
            ConfigDelta::Replace(path.clone(), body.to_string()),
            ConfigDelta::Update(path.clone(), body.to_string()),
            ConfigDelta::Merge(path.clone(), body.to_string()),
        ] {
            let mut candidate = previous.clone();
            let error = mixed::patch::apply_patch(&mut candidate, &[delta]).unwrap_err();
            assert_safe_patch_error(&error, "read-only", "cannot modify read-only path");
            assert_eq!(candidate, previous);
        }
    }
}

#[test]
fn direct_patch_segments_reject_state_bodies_before_any_mutation() {
    use mixed::patch::{parse_path, ConfigOp};
    let previous = writable_sample();
    for (path, body) in state_write_bodies() {
        let segments = parse_path(path).unwrap();
        for op in [ConfigOp::Replace, ConfigOp::Update, ConfigOp::Merge] {
            let mut candidate = previous.clone();
            let error = candidate.apply_patch_segments(&op, &segments[1..], Some(&body.to_string())).unwrap_err();
            assert_safe_patch_error(&error, "read-only", "cannot modify read-only path");
            assert_eq!(candidate, previous);
        }
    }
    let mut row = populated_state().account.remove("synthetic-secret").unwrap();
    let previous_row = row.clone();
    let error = row.apply_patch_segments(&ConfigOp::Replace, &[], Some(r#"{"token":"synthetic-secret","telemetry":null}"#)).unwrap_err();
    assert_safe_patch_error(&error, "read-only", "cannot modify read-only path");
    assert_eq!(row, previous_row);
}

#[test]
fn direct_state_patch_segments_reject_every_operation() {
    use minimal::patch::{parse_path, ConfigOp};
    for op in [ConfigOp::Replace, ConfigOp::Update, ConfigOp::Merge, ConfigOp::Delete, ConfigOp::Remove] {
        let mut state = sample();
        let previous = state.clone();
        let segments = parse_path("error[reason='temporary']/count").unwrap();
        let error = state.apply_patch_segments(&op, &segments, Some("8")).unwrap_err();
        assert_safe_patch_error(&error, "read-only", "cannot modify read-only path");
        assert_eq!(state, previous);
        let mut row = previous.error.get("temporary").unwrap().clone();
        let previous_row = row.clone();
        let error = row.apply_patch_segments(&op, &[], Some(r#"{"reason":"synthetic-secret","count":8}"#)).unwrap_err();
        assert_safe_patch_error(&error, "read-only", "cannot modify read-only path");
        assert_eq!(row, previous_row);
    }
}

#[test]
fn gnmi_set_ancestor_bodies_reject_state_members_with_fixed_errors() {
    use opc_gnmi_server::{Encoding, GnmiError, GnmiPatchApplicator, NormalizedSet, NormalizedValue};
    let previous = writable_sample();
    for (path, body) in state_write_bodies() {
        let path = YangPath::new(path).unwrap();
        let value = NormalizedValue::new(Encoding::JsonIetf, body.to_string(), &MgmtLimits::default()).unwrap();
        for operation in 0..3 {
            let mut set = NormalizedSet::new();
            match operation {
                0 => set.replaces.push((path.clone(), value.clone())),
                1 => set.updates.push((path.clone(), value.clone())),
                _ => set.union_replaces.push((path.clone(), value.clone())),
            }
            let error = mixed::gnmi_set::patcher().apply_set(&previous, &set).unwrap_err();
            assert_eq!(error, GnmiError::invalid("gNMI Set patch application failed"));
            assert!(!format!("{error:?} {error}").contains("synthetic-secret"));
        }
    }
}

fn edit_node(path: &'static str, operation: opc_mgmt_schema::EditOperation) -> opc_mgmt_schema::EditConfigNode {
    opc_mgmt_schema::EditConfigNode {
        schema_path: path, operation, value: None,
        list_keys: Default::default(), children: Vec::new(),
    }
}

#[test]
fn netconf_applicator_rejects_hand_built_state_children() {
    use opc_mgmt_schema::{EditOperation, NetconfXmlEditApplicator};
    for operation in [EditOperation::Merge, EditOperation::Replace, EditOperation::Create, EditOperation::Delete, EditOperation::Remove, EditOperation::None] {
        let mut edit = edit_node("/mx:root", EditOperation::Merge);
        let mut writable = edit_node("/mx:root/mx:hostname", EditOperation::Merge);
        writable.value = Some("new".to_owned());
        let mut state = edit_node("/mx:root/mx:state", operation);
        let mut row = edit_node("/mx:root/mx:state/mx:error", EditOperation::Merge);
        row.list_keys.insert("reason".to_owned(), "synthetic-secret".to_owned());
        state.children.push(row);
        edit.children = vec![writable, state];
        let error = mixed::netconf_xml_edit::applicator().apply_edit_config(&writable_sample(), &edit).unwrap_err();
        assert_eq!(error, NetconfEditError::ReadOnly { path: "/mx:root/mx:state" });
        assert!(!format!("{error:?} {error}").contains("synthetic-secret"));
    }
    let mut edit = edit_node("/mx:root", EditOperation::Replace);
    let mut row = edit_node("/mx:root/mx:account", EditOperation::Merge);
    row.list_keys.insert("token".to_owned(), "synthetic-secret".to_owned());
    row.children.push(edit_node("/mx:root/mx:account/mx:telemetry", EditOperation::Merge));
    edit.children.push(row);
    let error = mixed::netconf_xml_edit::applicator().apply_edit_config(&writable_sample(), &edit).unwrap_err();
    assert_eq!(error, NetconfEditError::ReadOnly { path: "/mx:root/mx:account/mx:telemetry" });
}

#[test]
fn netconf_parser_rejects_state_hidden_under_configuration_ancestors() {
    for xml in [
        r#"<config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><root xmlns="urn:example:mixed-state"><hostname>new</hostname><state><error><reason>synthetic-secret</reason><count>8</count></error></state></root></config>"#,
        r#"<config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><root xmlns="urn:example:mixed-state"><account><token>synthetic-secret</token><telemetry><packets>8</packets></telemetry></account></root></config>"#,
    ] {
        let error = parse_edit_config_xml_with_limits(xml, mixed::schema_registry::registry(), EditDefaultOperation::Merge, &MgmtLimits::default()).unwrap_err();
        assert!(matches!(error, NetconfEditError::ReadOnly { .. }));
        assert!(!format!("{error:?} {error}").contains("synthetic-secret"));
    }
}

#[test]
fn ancestor_replacement_and_removal_cannot_erase_existing_state() {
    use mixed::patch::{parse_path, ConfigOp};
    use opc_mgmt_schema::{EditOperation, NetconfXmlEditApplicator};
    let previous = populated_state();
    for path in ["/mx:root", "/mx:root/mx:branch", "/mx:root/mx:account[token='synthetic-secret']", "/mx:root/mx:channel[name='first']"] {
        let segments = parse_path(path).unwrap();
        for op in [ConfigOp::Replace, ConfigOp::Delete, ConfigOp::Remove] {
            let mut candidate = previous.clone();
            let error = candidate.apply_patch_segments(&op, &segments[1..], Some("{}")).unwrap_err();
            assert_safe_patch_error(&error, "read-only", "cannot modify read-only path");
            assert_eq!(candidate, previous);
        }
    }
    let edit = edit_node("/mx:root", EditOperation::Replace);
    assert_eq!(mixed::netconf_xml_edit::applicator().apply_edit_config(&previous, &edit).unwrap_err(), NetconfEditError::ReadOnly { path: "/mx:root" });
}

#[test]
fn configuration_edits_succeed_and_retain_existing_state() {
    use mixed::patch::{parse_path, ConfigOp};
    use opc_gnmi_server::{Encoding, GnmiPatchApplicator, NormalizedSet, NormalizedValue};
    use opc_mgmt_schema::{EditOperation, NetconfXmlEditApplicator};
    let previous = populated_state();
    let mut expected = previous.clone();
    expected.hostname = mixed::types::LeafPresence::Explicit("new".to_owned());
    let mut candidate = previous.clone();
    candidate.apply_patch_segments(&ConfigOp::Merge, &[], Some(r#"{"hostname":"new"}"#)).unwrap();
    assert_eq!(candidate, expected);
    let mut set = NormalizedSet::new();
    set.updates.push((YangPath::new("/mx:root").unwrap(), NormalizedValue::new(Encoding::JsonIetf, r#"{"hostname":"new"}"#, &MgmtLimits::default()).unwrap()));
    assert_eq!(mixed::gnmi_set::patcher().apply_set(&previous, &set).unwrap(), expected);
    let mut edit = edit_node("/mx:root", EditOperation::Merge);
    let mut leaf = edit_node("/mx:root/mx:hostname", EditOperation::Merge);
    leaf.value = Some("new".to_owned());
    edit.children.push(leaf);
    assert_eq!(mixed::netconf_xml_edit::applicator().apply_edit_config(&previous, &edit).unwrap(), expected);
    let segments = parse_path("account[token='synthetic-secret']/count").unwrap();
    candidate.apply_patch_segments(&ConfigOp::Update, &segments, Some("9")).unwrap();
    assert_eq!(candidate.account.get("synthetic-secret").unwrap().count, mixed::types::LeafPresence::Explicit(9));
    assert_eq!(candidate.account.get("synthetic-secret").unwrap().telemetry, previous.account.get("synthetic-secret").unwrap().telemetry);
    let empty = mixed::types::Root::default();
    let mut replaced = empty;
    replaced.apply_patch_segments(&ConfigOp::Replace, &[], Some(r#"{"hostname":"new"}"#)).unwrap();
    assert_eq!(replaced.hostname, mixed::types::LeafPresence::Explicit("new".to_owned()));
}
