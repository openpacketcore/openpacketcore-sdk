use generated_ordered_test::{collections as model, minimal};
use model::patch::{apply_patch, ConfigDelta};
use model::types::{LeafPresence, Root, Server};
use opc_config_model::{ConfigError, OpcConfig, ValidationError, YangPath};
use opc_gnmi_server::{
    Encoding, GnmiError, GnmiJsonRenderer, GnmiPatchApplicator, NormalizedSet, NormalizedValue,
    ReadSelection, ReadSelectionEntry,
};
use opc_mgmt_limits::MgmtLimits;
use opc_mgmt_schema::{
    DefaultReport, NetconfEditError, NetconfXmlEditApplicator, NetconfXmlRenderer, NodeKind,
};
use opc_netconf_server::{parse_edit_config_xml_with_limits, EditDefaultOperation};
use serde_json::{json, Value};

fn path(value: &str) -> YangPath {
    YangPath::new(value).unwrap()
}

fn root(names: &[&str]) -> Root {
    serde_json::from_value(json!({
        "server": names.iter().map(|name| json!({"name": name, "port": 53})).collect::<Vec<_>>()
    }))
    .unwrap()
}

fn array_names(value: &Value) -> Vec<String> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["name"].as_str().unwrap().to_string())
        .collect()
}

fn names(value: &Root) -> Vec<String> {
    array_names(&serde_json::to_value(value).unwrap()["ordered-collections:server"])
}

fn apply_xml(running: &Root, body: &str) -> Result<Root, NetconfEditError> {
    let xml = format!(
        r#"<config xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0"
                    xmlns:yang="urn:ietf:params:xml:ns:yang:1">
        <root xmlns="urn:example:ordered-collections">{body}</root></config>"#
    );
    let edit = parse_edit_config_xml_with_limits(
        &xml,
        model::schema_registry::registry(),
        EditDefaultOperation::Merge,
        &MgmtLimits::default(),
    )?;
    model::netconf_xml_edit::applicator().apply_edit_config(running, &edit)
}

fn gnmi_value(value: Value) -> NormalizedValue {
    NormalizedValue::new(
        Encoding::JsonIetf,
        value.to_string(),
        &MgmtLimits::default(),
    )
    .unwrap()
}

#[test]
fn minimal_json_roundtrip_preserves_user_order_and_refuses_duplicate_keys() {
    let duplicate = serde_json::from_value::<minimal::types::Root>(json!({
        "server": [{"name": "z"}, {"name": "z"}]
    }))
    .unwrap_err();
    assert!(duplicate
        .to_string()
        .contains(minimal::serde::DUPLICATE_LIST_KEY_ERROR));

    let original: minimal::types::Root =
        serde_json::from_value(json!({"server": [{"name": "z"}, {"name": "a"}]})).unwrap();
    let encoded = serde_json::to_value(&original).unwrap();
    assert_eq!(array_names(&encoded["ordered-example:server"]), ["z", "a"]);
    let decoded: minimal::types::Root = serde_json::from_value(encoded).unwrap();
    assert_eq!(original, decoded);
    assert_eq!(
        decoded.server.keys().cloned().collect::<Vec<_>>(),
        ["z", "a"]
    );
}

#[test]
fn minimal_xml_roundtrip_preserves_user_order_and_refuses_duplicate_keys() {
    let parse = |names: &[&str]| {
        let rows = names
            .iter()
            .map(|name| format!("<server><name>{name}</name></server>"))
            .collect::<String>();
        parse_edit_config_xml_with_limits(
            &format!(r#"<config><root xmlns="urn:example:ordered">{rows}</root></config>"#),
            minimal::schema_registry::registry(),
            EditDefaultOperation::Replace,
            &MgmtLimits::default(),
        )
        .unwrap()
    };
    let initial = minimal::types::Root::default();
    assert!(matches!(
        minimal::netconf_xml_edit::applicator().apply_edit_config(&initial, &parse(&["z", "z"])),
        Err(NetconfEditError::InvalidValue {
            path: "/ex:root/ex:server"
        })
    ));
    let original = minimal::netconf_xml_edit::applicator()
        .apply_edit_config(&initial, &parse(&["z", "a"]))
        .unwrap();
    let xml = minimal::netconf_xml::renderer()
        .render_running_config(
            &original,
            minimal::paths::CONFIG_PATHS,
            DefaultReport::Explicit,
        )
        .unwrap();
    assert!(
        xml.find(">z</").unwrap() < xml.find(">a</").unwrap(),
        "{xml}"
    );
    let edit = parse_edit_config_xml_with_limits(
        &format!("<config>{xml}</config>"),
        minimal::schema_registry::registry(),
        EditDefaultOperation::Replace,
        &MgmtLimits::default(),
    )
    .unwrap();
    let decoded = minimal::netconf_xml_edit::applicator()
        .apply_edit_config(&initial, &edit)
        .unwrap();
    assert_eq!(decoded, original);
    assert_eq!(
        decoded.server.keys().cloned().collect::<Vec<_>>(),
        ["z", "a"]
    );
}

#[test]
fn system_order_is_sorted_while_user_order_is_data() {
    for input in [["z", "a"], ["a", "z"]] {
        let rows = input
            .into_iter()
            .map(|name| json!({"name": name}))
            .collect::<Vec<_>>();
        let value: Root =
            serde_json::from_value(json!({"server": rows, "system-server": rows})).unwrap();
        let encoded = serde_json::to_value(&value).unwrap();
        assert_eq!(
            array_names(&encoded["ordered-collections:system-server"]),
            ["a", "z"]
        );
        assert_eq!(array_names(&encoded["ordered-collections:server"]), input);
        let xml = model::netconf_xml::renderer()
            .render_running_config(&value, model::paths::CONFIG_PATHS, DefaultReport::Explicit)
            .unwrap();
        let system_rows = xml.split("<oc:system-server>").skip(1).collect::<Vec<_>>();
        assert!(system_rows[0].contains("<oc:name>a</oc:name>"), "{xml}");
        assert!(system_rows[1].contains("<oc:name>z</oc:name>"), "{xml}");
    }
}

#[test]
fn canonical_configuration_bytes_distinguish_order_only_changes() {
    let first = serde_json::to_value(root(&["z", "a"])).unwrap();
    let second = serde_json::to_value(root(&["a", "z"])).unwrap();
    // Canonical object keys do not make the list array an unordered set.
    assert_ne!(
        serde_json::to_vec(&first).unwrap(),
        serde_json::to_vec(&second).unwrap()
    );
    assert_eq!(
        array_names(&first["ordered-collections:server"]),
        ["z", "a"]
    );
}

#[test]
fn order_only_diff_and_apply_preserve_the_new_order() {
    let mut previous = root(&["a", "z"]);
    let current = root(&["z", "a"]);
    let deltas = current.diff(&previous).unwrap();
    assert!(
        !deltas.is_empty(),
        "list order must be part of the config diff"
    );
    assert_eq!(
        current.changed_paths(&previous, &deltas).unwrap(),
        [path("/oc:root/oc:server")]
    );
    for delta in deltas {
        previous.apply_delta(delta).unwrap();
    }
    assert_eq!(previous, current);
    assert_eq!(names(&previous), ["z", "a"]);
}

#[test]
fn keyed_collection_replacement_and_duplicate_rejection_are_atomic() {
    let mut value = root(&["old", "retired"]);
    apply_patch(
        &mut value,
        &[ConfigDelta::Replace(
            path("/oc:root/oc:server"),
            json!([{"name": "z", "port": 53}, {"name": "a", "port": 853}]).to_string(),
        )],
    )
    .unwrap();
    assert_eq!(names(&value), ["z", "a"]);
    let before = value.clone();
    let error = apply_patch(
        &mut value,
        &[ConfigDelta::Replace(
            path("/oc:root/oc:server"),
            json!([{"name": "x"}, {"name": "x"}]).to_string(),
        )],
    );
    assert_eq!(
        error,
        Err(ConfigError::new(
            "invalid-value",
            "invalid user-ordered list"
        ))
    );
    assert_eq!(value, before);
    apply_patch(
        &mut value,
        &[ConfigDelta::Replace(
            path("/oc:root/oc:server"),
            "[]".into(),
        )],
    )
    .unwrap();
    assert!(value.server.is_empty());
}

#[test]
fn patch_add_delete_and_entry_replace_keep_other_entries_in_order() {
    let mut value = root(&["z", "a"]);
    apply_patch(
        &mut value,
        &[
            ConfigDelta::Update(
                path("/oc:root/oc:server[name='m']"),
                r#"{"name":"m","port":853}"#.into(),
            ),
            ConfigDelta::Replace(
                path("/oc:root/oc:server[name='z']"),
                r#"{"name":"z","port":5353}"#.into(),
            ),
        ],
    )
    .unwrap();
    assert_eq!(names(&value), ["z", "a", "m"]);
    assert_eq!(
        value.server.get("z").unwrap().port,
        LeafPresence::Explicit(5353)
    );
    apply_patch(
        &mut value,
        &[ConfigDelta::Delete(path("/oc:root/oc:server[name='z']"))],
    )
    .unwrap();
    assert_eq!(names(&value), ["a", "m"]);
    assert!(!value.server.contains_key("z"));
    assert_eq!(value.server.get("m").unwrap().port, LeafPresence::Explicit(853));
    value.server.get_mut("a").unwrap().port = LeafPresence::Explicit(5353);
    assert_eq!(value.server.get("a").unwrap().port, LeafPresence::Explicit(5353));
    value.server.entry("m".into()).or_default().port = LeafPresence::Explicit(54);
    assert_eq!(value.server.get("m").unwrap().port, LeafPresence::Explicit(54));
    assert_eq!(names(&value), ["a", "m"]);
}

#[test]
fn public_keyed_insertion_refuses_duplicates_without_replacing_a_value() {
    let mut value = root(&["z", "a"]);
    let replacement: Server = serde_json::from_value(json!({"name": "z", "port": 853})).unwrap();
    let outcome = value.server.insert("z".to_string(), replacement);
    assert_eq!(outcome, Err(model::serde::DuplicateListKey));
    assert_eq!(
        value.server.get("z").unwrap().port,
        LeafPresence::Explicit(53),
        "{outcome:?}"
    );
    assert_eq!(names(&value), ["z", "a"]);
}

#[test]
fn xml_replacement_append_delete_and_entry_merge_preserve_order() {
    let original = root(&["old"]);
    let xml = r#"<config><root xmlns="urn:example:ordered-collections">
        <server><name>z</name><port>53</port></server>
        <server><name>a</name><port>853</port></server>
    </root></config>"#;
    let edit = parse_edit_config_xml_with_limits(
        xml,
        model::schema_registry::registry(),
        EditDefaultOperation::Replace,
        &MgmtLimits::default(),
    )
    .unwrap();
    let replaced = model::netconf_xml_edit::applicator()
        .apply_edit_config(&original, &edit)
        .unwrap();
    assert_eq!(names(&replaced), ["z", "a"]);
    let appended = apply_xml(
        &replaced,
        r#"
        <server nc:operation="create"><name>m</name></server>
        <server><name>z</name><port>5353</port></server>"#,
    )
    .unwrap();
    assert_eq!(names(&appended), ["z", "a", "m"]);
    let replaced_entry = apply_xml(
        &appended,
        r#"<server nc:operation="replace"><name>z</name><port>5354</port></server>"#,
    )
    .unwrap();
    assert_eq!(names(&replaced_entry), ["z", "a", "m"]);
    assert_eq!(
        replaced_entry.server.get("z").unwrap().port,
        LeafPresence::Explicit(5354)
    );
    let deleted = apply_xml(
        &replaced_entry,
        r#"<server nc:operation="delete"><name>z</name></server>"#,
    )
    .unwrap();
    assert_eq!(names(&deleted), ["a", "m"]);
    let duplicated = apply_xml(
        &deleted,
        r#"<server><name>x</name></server><server><name>x</name></server>"#,
    );
    assert!(matches!(
        duplicated,
        Err(NetconfEditError::InvalidValue {
            path: "/oc:root/oc:server"
        })
    ));
    assert_eq!(names(&deleted), ["a", "m"]);
}

#[test]
fn composite_keys_preserve_order_through_json_xml_diff_and_apply() {
    let current: Root = serde_json::from_value(json!({"endpoint": [
        {"region": "z", "name": "a", "port": 53},
        {"region": "a", "name": "z", "port": 853}
    ]}))
    .unwrap();
    let previous: Root = serde_json::from_value(json!({"endpoint": [
        {"region": "a", "name": "z", "port": 853},
        {"region": "z", "name": "a", "port": 53}
    ]}))
    .unwrap();
    let deltas = current.diff(&previous).unwrap();
    assert!(!deltas.is_empty());
    let mut applied = previous;
    apply_patch(&mut applied, &deltas).unwrap();
    assert_eq!(
        serde_json::to_value(&applied).unwrap()["ordered-collections:endpoint"][0]["region"],
        "z"
    );
    let xml = model::netconf_xml::renderer()
        .render_running_config(
            &applied,
            model::paths::CONFIG_PATHS,
            DefaultReport::Explicit,
        )
        .unwrap();
    let parsed = parse_edit_config_xml_with_limits(
        &format!("<config>{xml}</config>"),
        model::schema_registry::registry(),
        EditDefaultOperation::Replace,
        &MgmtLimits::default(),
    )
    .unwrap();
    let roundtrip = model::netconf_xml_edit::applicator()
        .apply_edit_config(&Root::default(), &parsed)
        .unwrap();
    assert_eq!(roundtrip, current);
    let duplicate = serde_json::from_value::<Root>(json!({"endpoint": [
        {"region": "z", "name": "a"}, {"region": "z", "name": "a"}
    ]}));
    assert_eq!(
        duplicate.unwrap_err().to_string(),
        model::serde::DUPLICATE_LIST_KEY_ERROR
    );
}

#[test]
fn gnmi_collection_replace_and_keyed_update_preserve_user_order() {
    let running = root(&["old"]);
    let candidate = model::gnmi_set::patcher()
        .apply_set(
            &running,
            &NormalizedSet {
                replaces: vec![(
                    path("/oc:root/oc:server"),
                    gnmi_value(json!([{"name":"z"}, {"name":"a"}])),
                )],
                updates: vec![(
                    path("/oc:root/oc:server[name='m']"),
                    gnmi_value(json!({"name":"m"})),
                )],
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(names(&candidate), ["z", "a", "m"]);
    assert_eq!(names(&running), ["old"]);
    let duplicate = model::gnmi_set::patcher().apply_set(
        &candidate,
        &NormalizedSet {
            replaces: vec![(
                path("/oc:root/oc:server"),
                gnmi_value(json!([{"name":"z"}, {"name":"z"}])),
            )],
            ..Default::default()
        },
    );
    assert!(
        matches!(duplicate, Err(GnmiError::InvalidArgument { detail })
        if detail == "gNMI Set patch application failed")
    );
    assert_eq!(names(&candidate), ["z", "a", "m"]);
}

#[test]
fn gnmi_read_and_redaction_preserve_user_order() {
    use model::redaction::Redactable;
    let mut value: Root = serde_json::from_value(json!({"server": [
        {"name":"z", "password":"private-z"}, {"name":"a", "password":"private-a"}
    ]}))
    .unwrap();
    value.redact_sensitive();
    assert_eq!(names(&value), ["z", "a"]);
    let bytes = serde_json::to_string(&value).unwrap();
    assert!(!bytes.contains("private-"));
    let schema_paths = ["/oc:root/oc:server", "/oc:root/oc:server/oc:name"];
    let entries = schema_paths
        .iter()
        .map(|p| ReadSelectionEntry::new(p, path(p)))
        .collect::<Vec<_>>();
    let updates = model::gnmi_json::renderer()
        .render_running_json(&value, ReadSelection::with_entries(&schema_paths, &entries))
        .unwrap();
    assert_eq!(
        updates
            .iter()
            .map(|update| update.path().as_str())
            .collect::<Vec<_>>(),
        [
            "/oc:root/oc:server[oc:name='z']",
            "/oc:root/oc:server[oc:name='a']"
        ]
    );
    assert_eq!(
        serde_json::from_str::<Value>(updates[0].value_json()).unwrap(),
        json!({"name":"z"})
    );
    assert_eq!(
        serde_json::from_str::<Value>(updates[1].value_json()).unwrap(),
        json!({"name":"a"})
    );
}

#[test]
fn user_leaf_list_json_preserves_order_and_rejects_duplicates() {
    let original: Root =
        serde_json::from_value(json!({"preference": ["z", "a"], "priority": [53, 1]})).unwrap();
    let encoded = serde_json::to_value(&original).unwrap();
    assert_eq!(encoded["ordered-collections:preference"], json!(["z", "a"]));
    assert_eq!(encoded["ordered-collections:priority"], json!([53, 1]));
    assert_eq!(
        serde_json::from_value::<Root>(json!({"preference": ["z", "z"]}))
            .unwrap_err()
            .to_string(),
        model::serde::DUPLICATE_LEAF_LIST_VALUE_ERROR
    );
    assert_eq!(
        serde_json::from_value::<Root>(json!({"priority": [53, 53]}))
            .unwrap_err()
            .to_string(),
        model::serde::DUPLICATE_LEAF_LIST_VALUE_ERROR
    );
    assert_eq!(
        serde_json::from_value::<Root>(json!({"server": [{"name":"z", "preference":["a","a"]}]}))
            .unwrap_err()
            .to_string(),
        model::serde::DUPLICATE_LEAF_LIST_VALUE_ERROR
    );
    assert_eq!(
        serde_json::from_value::<Root>(json!({"ratio": ["0", "-0.00"]}))
            .unwrap_err()
            .to_string(),
        model::serde::DUPLICATE_LEAF_LIST_VALUE_ERROR
    );
    let stored = br#"{"ordered-collections:preference":["z","a","z"]}"#;
    let load_error = serde_json::from_slice::<Root>(stored).unwrap_err();
    assert_eq!(load_error.classify(), serde_json::error::Category::Data);
    assert_eq!(
        load_error.to_string(),
        format!(
            "{} at line 1 column 48",
            model::serde::DUPLICATE_LEAF_LIST_VALUE_ERROR
        )
    );
    let reversed: Root =
        serde_json::from_value(json!({"preference": ["a", "z"], "priority": [1, 53]})).unwrap();
    let mut applied = original.clone();
    let deltas = reversed.diff(&original).unwrap();
    assert!(!deltas.is_empty());
    apply_patch(&mut applied, &deltas).unwrap();
    assert_eq!(applied, reversed);
}

#[test]
fn user_leaf_list_patch_rejects_duplicate_values_atomically() {
    let original: Root = serde_json::from_value(json!({"preference": ["z", "a"]})).unwrap();
    let mut candidate = original.clone();
    assert_eq!(
        apply_patch(
            &mut candidate,
            &[ConfigDelta::Replace(
                path("/oc:root/oc:preference"),
                r#"["a","a"]"#.into()
            )]
        ),
        Err(ConfigError::new(
            "invalid-value",
            model::serde::DUPLICATE_LEAF_LIST_VALUE_ERROR
        ))
    );
    assert_eq!(candidate, original);
    assert_eq!(
        apply_patch(
            &mut candidate,
            &[ConfigDelta::Update(
                path("/oc:root/oc:preference"),
                "z".into()
            )]
        ),
        Err(ConfigError::new(
            "invalid-value",
            model::serde::DUPLICATE_LEAF_LIST_VALUE_ERROR
        ))
    );
    assert_eq!(candidate, original);
    apply_patch(
        &mut candidate,
        &[ConfigDelta::Update(
            path("/oc:root/oc:preference"),
            "m".into(),
        )],
    )
    .unwrap();
    assert_eq!(candidate.preference, ["z", "a", "m"]);
}

#[test]
fn user_leaf_list_validation_refuses_duplicates_in_typed_state() {
    let mut candidate = Root {
        preference: vec!["z".into(), "z".into()],
        ..Default::default()
    };
    assert_eq!(
        candidate.validate_syntax(),
        Err(ValidationError::syntax(
            "duplicate leaf-list value at /oc:root/oc:preference"
        ))
    );
    assert_eq!(
        serde_json::to_string(&candidate).unwrap_err().to_string(),
        model::serde::DUPLICATE_LEAF_LIST_VALUE_ERROR
    );
    candidate.preference = vec!["z".into(), "a".into()];
    assert!(candidate.validate_syntax().is_ok());
    let mut entry: Server = serde_json::from_value(json!({"name":"a"})).unwrap();
    entry.preference = vec!["a".into(), "a".into()];
    assert_eq!(candidate.server.insert("a".into(), entry), Ok(()));
    assert_eq!(
        candidate.validate_syntax(),
        Err(ValidationError::syntax(
            "duplicate leaf-list value at /oc:root/oc:server/oc:preference"
        ))
    );
}

fn assert_position_rejected(position: &str) {
    let running = root(&["z", "a"]);
    for operation in ["create", "merge", "replace"] {
        for (element, kind, anchor) in [
            ("server", NodeKind::List, "yang:key=\"[name='z']\""),
            ("preference", NodeKind::LeafList, "yang:value=\"z\""),
        ] {
            let content = if element == "server" {
                "<name>m</name>"
            } else {
                "m"
            };
            let reference = if matches!(position, "before" | "after") {
                anchor
            } else {
                ""
            };
            let body = format!(
                r#"<{element} nc:operation="{operation}" yang:insert="{position}" {reference}>{content}</{element}>"#
            );
            let result = apply_xml(&running, &body);
            let expected_path = if element == "server" {
                "/oc:root/oc:server"
            } else {
                "/oc:root/oc:preference"
            };
            assert_eq!(
                result.unwrap_err(),
                NetconfEditError::UnsupportedShape {
                    path: expected_path,
                    kind
                }
            );
            assert_eq!(names(&running), ["z", "a"]);
        }
    }
}

#[test]
fn explicit_first_insert_or_move_is_rejected_with_a_typed_error() {
    assert_position_rejected("first");
}

#[test]
fn explicit_last_insert_or_move_is_rejected_with_a_typed_error() {
    assert_position_rejected("last");
}

#[test]
fn explicit_before_insert_or_move_is_rejected_with_a_typed_error() {
    assert_position_rejected("before");
}

#[test]
fn explicit_after_insert_or_move_is_rejected_with_a_typed_error() {
    assert_position_rejected("after");
}
