use generated_test::{gnmi_set, netconf_xml, netconf_xml_edit, patch, types::*};
use opc_config_model::{OpcConfig, YangPath};
use opc_gnmi_server::{Encoding, GnmiPatchApplicator, NormalizedSet, NormalizedValue};
use opc_mgmt_schema::{DefaultReport, EditConfigNode, EditOperation, NetconfEditError, NetconfXmlEditApplicator, NetconfXmlRenderer};
use serde_json::{json, Value};

fn set(config: &Root, name: &str, value: Value) -> Result<Root, opc_gnmi_server::GnmiError> {
    gnmi_set::patcher().apply_set(config, &NormalizedSet {
        updates: vec![(YangPath::new(format!("/ex:root/ex:{name}")).unwrap(), NormalizedValue::new(Encoding::JsonIetf, value.to_string(), &Default::default()).unwrap())],
        ..Default::default()
    })
}

fn edit(config: &Root, path: &'static str, value: &str) -> Result<Root, NetconfEditError> {
    netconf_xml_edit::applicator().apply_edit_config(config, &EditConfigNode {
        schema_path: "/ex:root", operation: EditOperation::Merge, value: None, list_keys: Default::default(),
        children: vec![EditConfigNode { schema_path: path, operation: EditOperation::Merge, value: Some(value.into()), list_keys: Default::default(), children: vec![] }],
    })
}

#[test]
fn boundaries_and_xsd_semantics_roundtrip_every_path() {
    // JSON omission is Absent; explicit Rust defaults use Defaulted presence.
    // Keep the same initial presence state on every ingress path.
    let baseline: Root = serde_json::from_value(json!({})).unwrap();
    for (name, accepted, rejected) in [
        ("code", vec!["000", "123", "999"], vec!["", "12", "1234", "x123", "123x"]),
        ("label", vec!["é", "界😀é", "abcde"], vec!["", "abcd", "abcdef"]),
        ("word", vec!["good", "badly"], vec!["bad", "Good", "1"]),
        ("consonants", vec!["bcdf"], vec!["a", "be"]),
        ("literal", vec!["^$$"], vec!["$", "", "^$"]),
        ("unicode", vec!["é界"], vec!["123", "_"]),
        ("whitespace", vec![" ", "\t", "\n", "\r"], vec!["\u{a0}", "a"]),
        ("nonspace", vec!["abc123", "é+"], vec!["_", "-", " "]),
        ("choice", vec!["ab", "cdabx", "abcd"], vec!["ababc", "abcdab", "x"]),
        ("single-digits", vec!["12", "123"], vec!["ab", "ddd"]),
        ("double-digits", vec!["12", "123"], vec!["ab", "ddd"]),
        ("bare-digits", vec!["12", "123"], vec!["ab", ""]),
        ("bare-inverted", vec!["b", "ab"], vec!["a", "aa"]),
        ("concatenated", vec!["12", "123"], vec!["ab", ""]),
        ("reference", vec!["123"], vec!["12", "1234"]),
        ("secret", vec!["123"], vec!["private-value", "1234", "abc"]),
    ] {
        let path: &'static str = Box::leak(format!("/ex:root/ex:{name}").into_boxed_str());
        for value in accepted {
            let config: Root = serde_json::from_value(json!({format!("example:{name}"): value})).unwrap();
            assert!(config.validate_syntax().is_ok());
            assert_eq!(set(&baseline.clone(), name, json!(value)).unwrap(), config);
            assert_eq!(edit(&baseline.clone(), path, value).unwrap(), config);
            let mut patched = baseline.clone();
            patch::apply_patch(&mut patched, &[patch::ConfigDelta::Update(YangPath::new(path).unwrap(), value.into())]).unwrap();
            assert_eq!(patched, config);
            assert_eq!(serde_json::from_value::<Root>(serde_json::to_value(&config).unwrap()).unwrap(), config);
            assert!(netconf_xml::renderer().render_running_config(&config, &[path], DefaultReport::Explicit).is_ok());
        }
        for value in rejected {
            let error = serde_json::from_value::<Root>(json!({format!("example:{name}"): value})).unwrap_err();
            assert_eq!(error.to_string(), "string violates YANG constraints");
            let error = set(&baseline.clone(), name, json!(value)).unwrap_err();
            assert!(matches!(error, opc_gnmi_server::GnmiError::InvalidArgument { .. }));
            assert_eq!(error, opc_gnmi_server::GnmiError::invalid("string violates YANG constraints"));
            assert_eq!(edit(&baseline.clone(), path, value).unwrap_err(), NetconfEditError::InvalidValue { path });
            let mut patched = baseline.clone();
            let error = patch::apply_patch(&mut patched, &[patch::ConfigDelta::Update(YangPath::new(path).unwrap(), value.into())]).unwrap_err();
            assert_eq!(error.kind(), "invalid-value");
            assert_eq!(error.message(), "string violates YANG constraints");
            assert_eq!(patched, baseline.clone());
        }
    }
    assert!(set(&baseline.clone(), "name", json!("😀".repeat(150))).is_ok());
    assert_eq!(set(&baseline.clone(), "name", json!("😀".repeat(151))).unwrap_err(), opc_gnmi_server::GnmiError::invalid("string violates YANG constraints"));
}

#[test]
fn subtree_list_leaf_list_and_secret_constraints_are_not_bypassed() {
    for value in [
        json!({"example:child": {"code": "bad-value"}}),
        json!({"example:labels": ["ok", "bad-value"]}),
        json!({"example:preferences": ["ok", "bad-value"]}),
        json!({"example:api-token": ["123", "bad-value"]}),
        json!({"example:account": [{"secret-id": "bad-value", "value": "x"}]}),
        json!({"example:state": {"label": "bad-value"}}),
    ] {
        assert_eq!(serde_json::from_value::<Root>(value.clone()).unwrap_err().to_string(), "string violates YANG constraints");
        let mut candidate = Root::default();
        let error = patch::apply_patch(&mut candidate, &[patch::ConfigDelta::Replace(YangPath::new("/ex:root").unwrap(), value.to_string())]).unwrap_err();
        assert_eq!(error.kind(), "invalid-value");
        assert_eq!(error.message(), "string violates YANG constraints");
        assert!(!format!("{error:?}").contains("bad-value"));
        assert_eq!(candidate, Root::default());
    }
    assert!(set(&Root::default(), "labels", json!(["é😀", "abc"])).is_ok());
    assert!(set(&Root::default(), "preferences", json!(["first", "last"])).is_ok());
    assert!(set(&Root::default(), "api-token", json!(["123", "456"])).is_ok());
}

#[test]
fn direct_validation_and_multi_delta_rejection_are_atomic() {
    let baseline = set(&Root::default(), "code", json!("123")).unwrap();
    let mut invalid = baseline.clone();
    invalid.code = LeafPresence::Explicit("bad-value".into());
    assert_eq!(invalid.validate_syntax().unwrap_err().message, "string violates YANG constraints");
    let mut candidate = baseline.clone();
    let error = patch::apply_patch(&mut candidate, &[
        patch::ConfigDelta::Update(YangPath::new("/ex:root/ex:code").unwrap(), "456".into()),
        patch::ConfigDelta::Update(YangPath::new("/ex:root/ex:secret").unwrap(), "bad-value".into()),
    ]).unwrap_err();
    assert_eq!(error.message(), "string violates YANG constraints");
    assert_eq!(candidate, baseline);
}

#[test]
fn sensitive_keys_keep_redacted_debug_and_fixed_errors() {
    let config: Root = serde_json::from_value(json!({"example:account": [{"secret-id": "987", "value": "x"}]})).unwrap();
    assert!(!format!("{config:?}").contains("987"));
    assert!(!format!("{:?}", config.account.keys().next().unwrap()).contains("987"));
    for rejected in ["private-value", "1234", "abc"] {
        let mut candidate = config.clone();
        let error = patch::apply_patch(&mut candidate, &[patch::ConfigDelta::Update(YangPath::new(format!("/ex:root/ex:account[secret-id='{rejected}']/ex:value")).unwrap(), "x".into())]).unwrap_err();
        assert_eq!(error.kind(), "invalid-value");
        assert_eq!(error.message(), "string violates YANG constraints");
        assert!(!format!("{error:?}").contains("private-value"));
        assert!(!format!("{error:?}").contains(rejected));
        assert_eq!(candidate, config);
    }
}

#[test]
fn defaults_and_ordered_uniqueness_survive_constraints() {
    assert_eq!(Root::default().defaulted, LeafPresence::Defaulted("123".into()));
    assert!(Root::default().validate_syntax().is_ok());
    assert_eq!(serde_json::from_value::<Root>(json!({"example:preferences": ["same", "same"]})).unwrap_err().to_string(), "leaf-list contains a duplicate value");
    assert_eq!(serde_json::from_value::<Root>(json!({"example:api-token": ["123", "123"]})).unwrap_err().to_string(), "leaf-list contains a duplicate value");
}

#[test]
fn malformed_payloads_keep_value_free_rejections() {
    for (name, value) in [
        ("secret", json!(123456789)), ("secret", json!(["private-value"])),
        ("secret", json!({"private-value": "private-value"})),
        ("api-token", json!([123456789])),
    ] {
        let body = json!({format!("example:{name}"): value});
        let error = serde_json::from_value::<Root>(body.clone()).unwrap_err();
        assert_eq!(error.to_string(), "string violates YANG constraints");
        let error = set(&Root::default(), name, value).unwrap_err();
        assert!(matches!(error, opc_gnmi_server::GnmiError::InvalidArgument { .. }));
        assert_eq!(error, opc_gnmi_server::GnmiError::invalid("gNMI string leaf value must be a JSON string"));
        assert!(!format!("{error:?}").contains("private-value"));
        assert!(!format!("{error:?}").contains("123456789"));
        let mut candidate = Root::default();
        let error = patch::apply_patch(&mut candidate, &[patch::ConfigDelta::Replace(YangPath::new("/ex:root").unwrap(), body.to_string())]).unwrap_err();
        assert_eq!(error.kind(), "invalid-value");
        assert_eq!(error.message(), "string violates YANG constraints");
        assert_eq!(candidate, Root::default());
    }
}

fn normalized(path: &str, value: Value) -> (YangPath, NormalizedValue) {
    (YangPath::new(path).unwrap(), NormalizedValue::new(Encoding::JsonIetf, value.to_string(), &Default::default()).unwrap())
}

#[test]
fn subtree_updates_replacements_and_gnmi_batches_enforce_constraints() {
    let baseline = set(&Root::default(), "code", json!("123")).unwrap();
    for (path, good, bad) in [
        ("/ex:root", json!({"example:child": {"code": "456"}}), json!({"example:child": {"code": "private-value"}})),
        ("/ex:root/ex:child", json!({"code": "456"}), json!({"code": "private-value"})),
        ("/ex:root/ex:account[secret-id='123']", json!({"secret-id": "123", "value": "x"}), json!({"secret-id": "123", "value": "private-value"})),
        ("/ex:root/ex:labels", json!(["abc", "é😀"]), json!(["abc", "private-value"])),
        ("/ex:root/ex:preferences", json!(["first", "last"]), json!(["first", "private-value"])),
        ("/ex:root/ex:api-token", json!(["123", "456"]), json!(["123", "private-value"])),
    ] {
        for replace in [false, true] {
            for (value, accepted) in [(&good, true), (&bad, false)] {
                let delta = if replace { patch::ConfigDelta::Replace } else { patch::ConfigDelta::Update };
                let mut candidate = baseline.clone();
                let result = patch::apply_patch(&mut candidate, &[delta(YangPath::new(path).unwrap(), value.to_string())]);
                if accepted {
                    result.unwrap();
                    assert!(candidate.validate_syntax().is_ok());
                } else {
                    let error = result.unwrap_err();
                    assert_eq!(error.kind(), "invalid-value");
                    assert_eq!(error.message(), "string violates YANG constraints");
                    assert_eq!(candidate, baseline);
                }
            }
        }
        for operation in 0..3 {
            for (value, accepted) in [(&good, true), (&bad, false)] {
                let mut request = NormalizedSet::default();
                let entries = match operation { 0 => &mut request.updates, 1 => &mut request.replaces, _ => &mut request.union_replaces };
                entries.push(normalized(path, value.clone()));
                let result = gnmi_set::patcher().apply_set(&baseline, &request);
                if accepted {
                    assert!(result.unwrap().validate_syntax().is_ok());
                } else {
                    assert_eq!(result.unwrap_err(), opc_gnmi_server::GnmiError::invalid("string violates YANG constraints"));
                }
            }
        }
    }
    let request = NormalizedSet {
        updates: vec![normalized("/ex:root/ex:code", json!("456")), normalized("/ex:root/ex:secret", json!("private-value"))],
        ..Default::default()
    };
    assert_eq!(gnmi_set::patcher().apply_set(&baseline, &request).unwrap_err(), opc_gnmi_server::GnmiError::invalid("string violates YANG constraints"));
    assert_eq!(baseline.code, LeafPresence::Explicit("123".into()));
}

fn node(path: &'static str, operation: EditOperation, value: Option<&str>, children: Vec<EditConfigNode>) -> EditConfigNode {
    EditConfigNode { schema_path: path, operation, value: value.map(str::to_string), list_keys: Default::default(), children }
}

#[test]
fn netconf_nested_edits_keys_and_leaf_lists_validate_before_commit() {
    let baseline = set(&Root::default(), "code", json!("123")).unwrap();
    for operation in [EditOperation::Merge, EditOperation::Replace, EditOperation::Create] {
        for (value, accepted) in [("456", true), ("private-value", false)] {
            for leaf_path in ["/ex:root/ex:child/ex:code", "/ex:root/ex:api-token", "/ex:root/ex:account/ex:secret-id"] {
                let child = match leaf_path {
                    "/ex:root/ex:child/ex:code" => node("/ex:root/ex:child", operation, None, vec![node(leaf_path, EditOperation::Merge, Some(value), vec![])]),
                    "/ex:root/ex:account/ex:secret-id" => {
                        let mut row = node("/ex:root/ex:account", operation, None, vec![node("/ex:root/ex:account/ex:value", EditOperation::Merge, Some("x"), vec![])]);
                        row.list_keys.insert("secret-id".into(), value.into());
                        row
                    }
                    _ => node(leaf_path, operation, Some(value), vec![]),
                };
                let request = node("/ex:root", EditOperation::Merge, None, vec![node("/ex:root/ex:code", EditOperation::Merge, Some("789"), vec![]), child]);
                let result = netconf_xml_edit::applicator().apply_edit_config(&baseline, &request);
                if accepted {
                    assert!(result.unwrap().validate_syntax().is_ok());
                } else {
                    assert_eq!(result.unwrap_err(), NetconfEditError::InvalidValue { path: leaf_path });
                    assert_eq!(baseline.code, LeafPresence::Explicit("123".into()));
                }
            }
        }
    }
}

#[test]
fn public_subtree_patch_methods_cannot_bypass_validation_or_atomicity() {
    let baseline = set(&Root::default(), "code", json!("123")).unwrap();
    for operation in [patch::ConfigOp::Update, patch::ConfigOp::Merge, patch::ConfigOp::Replace] {
        for (path, value) in [
            ("/ex:labels", json!(["abc", "private-value"])),
            ("/ex:api-token", json!(["123", "private-value"])),
            ("/ex:account[secret-id='private-value']", json!({"value": "x"})),
            ("", json!({"example:code": "456", "example:secret": "private-value"})),
        ] {
            let mut candidate = baseline.clone();
            let segments = patch::parse_path(path).unwrap();
            let error = candidate.apply_patch_segments(&operation, &segments, Some(&value.to_string())).unwrap_err();
            assert_eq!(error.kind(), "invalid-value");
            assert_eq!(error.message(), "string violates YANG constraints");
            assert_eq!(candidate, baseline);
        }
        for path in [
            "/ex:account[secret-id='12']",
            "/ex:account[secret-id='abc']",
            "/ex:pair[secret-id='12'][slot='ab']",
            "/ex:pair[secret-id='abc'][slot='ab']",
            "/ex:pair[secret-id='123'][slot='a']",
            "/ex:pair[secret-id='123'][slot='12']",
        ] {
            let mut candidate = baseline.clone();
            let segments = patch::parse_path(path).unwrap();
            let error = candidate.apply_patch_segments(&operation, &segments, None).unwrap_err();
            assert_eq!(error.kind(), "invalid-value");
            assert_eq!(error.message(), "string violates YANG constraints");
            assert_eq!(candidate, baseline);
        }
    }
}

#[test]
fn valueless_list_patches_assign_all_path_keys_and_roundtrip() {
    for operation in [patch::ConfigOp::Update, patch::ConfigOp::Merge, patch::ConfigOp::Replace] {
        for path in ["/ex:account[secret-id='123']", "/ex:pair[secret-id='123'][slot='ab']"] {
            let mut candidate = Root::default();
            let segments = patch::parse_path(path).unwrap();
            candidate.apply_patch_segments(&operation, &segments, None).unwrap();
            let wire = serde_json::to_value(&candidate).unwrap();
            let list = if path.contains("pair") { "example:pair" } else { "example:account" };
            assert_eq!(wire[list][0]["secret-id"], "123");
            if list == "example:pair" {
                assert_eq!(wire[list][0]["slot"], "ab");
            }
            assert_eq!(serde_json::from_value::<Root>(wire).unwrap(), candidate);
            let before = candidate.clone();
            candidate.apply_patch_segments(&operation, &segments, None).unwrap();
            assert_eq!(candidate, before);
        }
    }
}
