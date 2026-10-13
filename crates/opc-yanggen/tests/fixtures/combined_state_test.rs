use generated_config_false_test::combined::{self, patch, types::*};
use opc_config_model::{ConfigError, OpcConfig, YangPath};
use opc_gnmi_server::{
    Encoding, GnmiError, GnmiJsonRenderer, GnmiPatchApplicator, NormalizedSet, NormalizedValue,
    ReadSelection, ReadSelectionEntry,
};
use opc_mgmt_limits::MgmtLimits;
use opc_mgmt_schema::{
    DefaultReport, EditConfigNode, EditOperation, NetconfEditError, NetconfXmlEditApplicator,
    NetconfXmlRenderer,
};
use serde_json::json;

fn sample() -> Root {
    serde_json::from_value(json!({
        "limit": 3, "label": "edge", "aliases": ["one"],
        "route": [{"id": "18446744073709551615", "metric": 7, "stats": {"packets": "9"}}],
        "left": {"sample": [{"id": "18446744073709551615", "count": "7"}]},
        "right": {"sample": [{"token-id": "9182736451", "region": 2, "count": "8"}]},
        "authorizations": {"grant": [{"token-id": "9182736451", "count": "9"}]}
    }))
    .unwrap()
}

fn assert_error(error: &ConfigError, kind: &str, reason: &str) {
    assert_eq!(error.kind(), kind);
    assert_eq!(error.message(), reason);
    for value in ["9182736451", "synthetic-secret"] {
        assert!(!format!("{error:?} {error}").contains(value));
    }
}

#[test]
fn extended_state_keys_keep_optional_values_copy_and_distinct_types() {
    let root = sample();
    let left: &LeftSample = root
        .left
        .as_ref()
        .unwrap()
        .sample
        .get(&YangUint64(u64::MAX))
        .unwrap();
    assert_eq!(left.id, Some(YangUint64(u64::MAX)));
    assert_eq!(
        combined::serde::ExtractKey::extract_key(left),
        Some(YangUint64(u64::MAX))
    );
    let expected = RightSampleKey {
        token_id: YangUint64(9182736451),
        region: 2,
    };
    let right: &RightSample = root.right.as_ref().unwrap().sample.get(&expected).unwrap();
    assert_eq!(*right.token_id.get(), Some(YangUint64(9182736451)));
    assert_eq!(
        combined::serde::ExtractKey::extract_key(right),
        Some(expected)
    );
    let grant = root
        .authorizations
        .as_ref()
        .unwrap()
        .grant
        .get(&YangUint64(9182736451))
        .unwrap();
    let key: SensitiveKey<YangUint64> = combined::serde::ExtractKey::extract_key(grant).unwrap();
    let copied = key;
    assert_eq!(key, copied);
    assert_eq!(*key.get(), YangUint64(9182736451));
    assert_eq!(format!("{key:?}"), "<REDACTED>");
    assert!(!format!("{right:?}").contains("9182736451"));
    assert_eq!(LeftSample::default().count, None);
    let wire = serde_json::to_value(&root).unwrap();
    assert_eq!(
        wire["combined-state:left"]["sample"][0]["id"],
        "18446744073709551615"
    );
    assert_eq!(serde_json::from_value::<Root>(wire).unwrap(), root);
}

#[test]
fn combined_patch_checks_scalar_constraints_and_state_before_publication() {
    let baseline = sample();
    for (body, kind, reason) in [
        (
            json!({"limit": 256}),
            "invalid-value",
            "invalid integer value",
        ),
        (
            json!({"limit": 11}),
            "invalid-value",
            "numeric value at /cs:root/cs:limit is outside YANG range",
        ),
        (
            json!({"label": "UP"}),
            "invalid-value",
            "string violates YANG constraints",
        ),
        (
            json!({"aliases": ["longer"]}),
            "invalid-value",
            "string violates YANG constraints",
        ),
        (
            json!({"limit": 4, "left": null}),
            "read-only",
            "cannot modify read-only path",
        ),
        (
            json!({"limit": 4, "combined-state:right": {}}),
            "read-only",
            "cannot modify read-only path",
        ),
    ] {
        let mut direct = baseline.clone();
        let error = direct
            .apply_patch_segments(&patch::ConfigOp::Merge, &[], Some(&body.to_string()))
            .unwrap_err();
        assert_error(&error, kind, reason);
        assert_eq!(direct, baseline);
        let mut root = baseline.clone();
        let error = patch::apply_patch(
            &mut root,
            &[
                patch::ConfigDelta::Update(
                    YangPath::new("/cs:root/cs:limit").unwrap(),
                    "4".to_owned(),
                ),
                patch::ConfigDelta::Merge(YangPath::new("/cs:root").unwrap(), body.to_string()),
            ],
        )
        .unwrap_err();
        assert_error(&error, kind, reason);
        assert_eq!(root, baseline);
    }
    let mut candidate = baseline.clone();
    let row = candidate.route.get_mut(&YangUint64(u64::MAX)).unwrap();
    let error = row
        .apply_patch_segments(&patch::ConfigOp::Merge, &[], Some(r#"{"metric":11}"#))
        .unwrap_err();
    assert_error(
        &error,
        "invalid-value",
        "numeric value at /cs:root/cs:route/cs:metric is outside YANG range",
    );
    assert_eq!(candidate, baseline);
    let row = candidate.route.get_mut(&YangUint64(u64::MAX)).unwrap();
    let error = row
        .apply_patch_segments(&patch::ConfigOp::Delete, &[], None)
        .unwrap_err();
    assert_error(&error, "read-only", "cannot modify read-only path");
    assert_eq!(candidate, baseline);
    candidate
        .apply_patch_segments(
            &patch::ConfigOp::Merge,
            &[],
            Some(r#"{"limit":4,"label":"next","aliases":["two"]}"#),
        )
        .unwrap();
    let mut expected = baseline.clone();
    expected.limit = LeafPresence::Explicit(4);
    expected.label = LeafPresence::Explicit("next".to_owned());
    expected.aliases = vec!["two".to_owned()];
    assert_eq!(candidate, expected);
    assert_eq!(candidate.validate_syntax(), Ok(()));
}

#[test]
fn extended_state_reads_and_diffs_keep_repeated_paths_distinct() {
    let baseline = sample();
    let schema_path = "/cs:root/cs:left/cs:sample/cs:count";
    let path =
        YangPath::new("/cs:root/cs:left/cs:sample[cs:id='18446744073709551615']/cs:count").unwrap();
    let entries = [ReadSelectionEntry::new(schema_path, path.clone())];
    let updates = combined::gnmi_json::renderer()
        .render_running_json(
            &baseline,
            ReadSelection::with_entries(&[schema_path], &entries),
        )
        .unwrap();
    assert_eq!(updates.len(), 1);
    assert_eq!(updates[0].path(), &path);
    assert_eq!(updates[0].value_json(), r#""7""#);
    let xml = combined::netconf_xml::renderer()
        .render_running_config(
            &baseline,
            &["/cs:root/cs:left/cs:sample/cs:id", schema_path],
            DefaultReport::Trim,
        )
        .unwrap();
    assert!(xml.contains("<cs:id>18446744073709551615</cs:id>"));
    assert!(xml.contains("<cs:count>7</cs:count>"));
    assert!(!xml.contains("9182736451"));
    let mut changed = baseline.clone();
    changed
        .left
        .as_mut()
        .unwrap()
        .sample
        .get_mut(&YangUint64(u64::MAX))
        .unwrap()
        .count = Some(YangUint64(99));
    changed.right = None;
    let deltas = changed.diff(&baseline).unwrap();
    assert!(deltas.is_empty());
    assert!(changed
        .changed_paths(&baseline, &deltas)
        .unwrap()
        .is_empty());
}

fn edit_node(path: &'static str, operation: EditOperation) -> EditConfigNode {
    EditConfigNode {
        schema_path: path,
        operation,
        value: None,
        list_keys: Default::default(),
        children: Vec::new(),
    }
}

#[test]
fn combined_protocol_edits_retain_constraints_and_read_only_state() {
    let baseline = sample();
    for (body, reason) in [
        (json!({"limit": 11}), "gNMI Set patch application failed"),
        (json!({"label": "UP"}), "string violates YANG constraints"),
        (
            json!({"limit": 4, "left": null}),
            "gNMI Set patch application failed",
        ),
    ] {
        let mut set = NormalizedSet::new();
        set.updates.push((
            YangPath::new("/cs:root").unwrap(),
            NormalizedValue::new(Encoding::JsonIetf, body.to_string(), &MgmtLimits::default())
                .unwrap(),
        ));
        assert_eq!(
            combined::gnmi_set::patcher()
                .apply_set(&baseline, &set)
                .unwrap_err(),
            GnmiError::invalid(reason)
        );
    }
    for (path, value) in [("/cs:root/cs:limit", "11"), ("/cs:root/cs:label", "UP")] {
        let mut edit = edit_node("/cs:root", EditOperation::Merge);
        let mut leaf = edit_node(path, EditOperation::Merge);
        leaf.value = Some(value.to_owned());
        edit.children.push(leaf);
        assert_eq!(
            combined::netconf_xml_edit::applicator()
                .apply_edit_config(&baseline, &edit)
                .unwrap_err(),
            NetconfEditError::InvalidValue { path }
        );
    }
    let mut edit = edit_node("/cs:root", EditOperation::Merge);
    edit.children
        .push(edit_node("/cs:root/cs:left", EditOperation::Remove));
    assert_eq!(
        combined::netconf_xml_edit::applicator()
            .apply_edit_config(&baseline, &edit)
            .unwrap_err(),
        NetconfEditError::ReadOnly {
            path: "/cs:root/cs:left"
        }
    );
    let mut expected = baseline.clone();
    expected.label = LeafPresence::Explicit("next".to_owned());
    let mut set = NormalizedSet::new();
    set.updates.push((
        YangPath::new("/cs:root").unwrap(),
        NormalizedValue::new(
            Encoding::JsonIetf,
            r#"{"label":"next"}"#,
            &MgmtLimits::default(),
        )
        .unwrap(),
    ));
    assert_eq!(
        combined::gnmi_set::patcher()
            .apply_set(&baseline, &set)
            .unwrap(),
        expected
    );
    let mut edit = edit_node("/cs:root", EditOperation::Merge);
    let mut leaf = edit_node("/cs:root/cs:label", EditOperation::Merge);
    leaf.value = Some("next".to_owned());
    edit.children.push(leaf);
    assert_eq!(
        combined::netconf_xml_edit::applicator()
            .apply_edit_config(&baseline, &edit)
            .unwrap(),
        expected
    );
}

#[test]
fn valueless_extended_keys_still_validate_beside_retained_state() {
    let baseline = sample();
    let mut candidate = baseline.clone();
    let segments = patch::parse_path("route[id='0']").unwrap();
    let error = candidate
        .apply_patch_segments(&patch::ConfigOp::Merge, &segments, None)
        .unwrap_err();
    assert_error(
        &error,
        "invalid-value",
        "numeric value at /cs:root/cs:route/cs:id is outside YANG range",
    );
    assert_eq!(candidate, baseline);
    let segments = patch::parse_path("route[id='1']").unwrap();
    candidate
        .apply_patch_segments(&patch::ConfigOp::Merge, &segments, None)
        .unwrap();
    let mut expected = baseline.clone();
    expected.route.insert(
        YangUint64(1),
        Route {
            id: LeafPresence::Explicit(YangUint64(1)),
            ..Default::default()
        },
    );
    assert_eq!(candidate, expected);
}
