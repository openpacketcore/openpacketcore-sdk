use generated_test::{gnmi_json, gnmi_set, netconf_xml, netconf_xml_edit, patch, types::*};
use opc_config_model::{OpcConfig, YangPath};
use opc_gnmi_server::{
    Encoding, GnmiJsonRenderer, GnmiPatchApplicator, NormalizedSet, NormalizedValue, ReadSelection,
};
use opc_mgmt_schema::{
    DefaultReport, EditConfigNode, EditOperation, NetconfXmlEditApplicator, NetconfXmlRenderer,
};
use serde_json::{json, Value};

fn set(config: &System, name: &str, value: Value) -> Result<System, opc_gnmi_server::GnmiError> {
    gnmi_set::patcher().apply_set(
        config,
        &NormalizedSet {
            updates: vec![(
                YangPath::new(format!("/n:system/n:{name}")).unwrap(),
                NormalizedValue::new(Encoding::JsonIetf, value.to_string(), &Default::default())
                    .unwrap(),
            )],
            ..Default::default()
        },
    )
}

fn edit(
    config: &System,
    path: &'static str,
    value: &str,
) -> Result<System, opc_mgmt_schema::NetconfEditError> {
    netconf_xml_edit::applicator().apply_edit_config(
        config,
        &EditConfigNode {
            schema_path: "/n:system",
            operation: EditOperation::Merge,
            value: None,
            list_keys: Default::default(),
            children: vec![EditConfigNode {
                schema_path: path,
                operation: EditOperation::Merge,
                value: Some(value.into()),
                children: vec![],
                list_keys: Default::default(),
            }],
        },
    )
}

#[test]
fn integer_boundaries_roundtrip_across_protocols() {
    for (name, low, high, below, above) in [
        ("u8", "0", "255", "-1", "256"),
        ("u16", "0", "65535", "-1", "65536"),
        ("u32", "0", "4294967295", "-1", "4294967296"),
        (
            "u64",
            "0",
            "18446744073709551615",
            "-1",
            "18446744073709551616",
        ),
        ("i8", "-128", "127", "-129", "128"),
        ("i16", "-32768", "32767", "-32769", "32768"),
        (
            "i32",
            "-2147483648",
            "2147483647",
            "-2147483649",
            "2147483648",
        ),
        (
            "i64",
            "-9223372036854775808",
            "9223372036854775807",
            "-9223372036854775809",
            "9223372036854775808",
        ),
    ] {
        let path: &'static str = Box::leak(format!("/n:system/n:{name}").into_boxed_str());
        for value in [low, high] {
            let wire = if name.ends_with("64") {
                json!(value)
            } else {
                serde_json::from_str(value).unwrap()
            };
            let config = set(&System::default(), name, wire.clone()).unwrap();
            assert_eq!(
                serde_json::to_value(&config).unwrap()[format!("n:{name}")],
                wire
            );
            let serialized = serde_json::to_string(&config).unwrap();
            assert_eq!(
                serde_json::to_string(&serde_json::from_str::<System>(&serialized).unwrap())
                    .unwrap(),
                serialized
            );
            let updates = gnmi_json::renderer()
                .render_running_json(&config, ReadSelection::new(&[path]))
                .unwrap();
            assert_eq!(
                serde_json::from_str::<Value>(updates[0].value_json()).unwrap(),
                wire
            );
            let xml = netconf_xml::renderer()
                .render_running_config(&config, &[path], DefaultReport::Explicit)
                .unwrap();
            assert!(xml.contains(&format!(">{value}</n:{name}>")), "{xml}");
            assert_eq!(edit(&System::default(), path, value).unwrap(), config);
            let mut patched = System::default();
            patch::apply_patch(
                &mut patched,
                &[patch::ConfigDelta::Update(
                    YangPath::new(path).unwrap(),
                    value.into(),
                )],
            )
            .unwrap();
            assert_eq!(patched, config);
        }
        for value in [below, above] {
            let wire = if name.ends_with("64") {
                json!(value)
            } else {
                serde_json::from_str(value).unwrap()
            };
            assert!(
                set(&System::default(), name, wire.clone()).is_err(),
                "{name} {wire}"
            );
            assert!(
                edit(&System::default(), path, value).is_err(),
                "{name} {value}"
            );
            assert!(
                serde_json::from_value::<System>(json!({ format!("n:{name}"): wire })).is_err()
            );
        }
        let wrong_shape = if name.ends_with("64") {
            json!(0)
        } else {
            json!("0")
        };
        if name.ends_with("64") {
            assert!(set(&System::default(), name, wrong_shape.clone()).is_ok());
        } else {
            assert!(set(&System::default(), name, wrong_shape.clone()).is_err());
        }
        assert!(
            serde_json::from_value::<System>(json!({ format!("n:{name}"): wrong_shape })).is_err()
        );
    }
}

#[test]
fn ranges_are_exact_and_validated_for_leaves_and_lists() {
    let registry = generated_test::schema_registry::registry();
    let range = registry.integer_range("/n:system/n:bounded");
    assert_eq!(range[0].max.to_string(), u64::MAX.to_string());
    let config = set(&System::default(), "bounded", json!("18446744073709551615")).unwrap();
    assert!(config.validate_syntax().is_ok());
    assert!(set(&config, "bounded", json!("9223372036854775807")).is_err());
    assert!(edit(&config, "/n:system/n:bounded", "9223372036854775807").is_err());
    let mut invalid = config.clone();
    invalid.bounded = LeafPresence::Explicit(YangUint64(0));
    assert!(invalid.validate_syntax().is_err());
    assert!(set(&config, "signed", json!(0)).is_err());
    assert!(set(
        &config,
        "unsigned-values",
        json!(["1", "18446744073709551615"])
    )
    .is_ok());
    assert!(set(&config, "unsigned-values", json!(["0"])).is_err());
    assert!(set(&config, "signed-values", json!([-100, 100])).is_ok());
    invalid.signed_values = vec![101];
    invalid.bounded = LeafPresence::Absent;
    assert!(invalid.validate_syntax().is_err());
    assert!(set(&config, "reference", json!("18446744073709551615")).is_ok());
    assert!(set(&config, "reference", json!(12)).is_ok());
}

#[test]
fn repeated_container_and_list_names_compile_and_keep_distinct_shapes() {
    let mut config: System = serde_json::from_value(json!({
        "n:left": {"n:stats": {"n:value": -2147483648}, "n:row": [{"n:id": "18446744073709551615", "n:slot": -128}]},
        "n:right": {"n:stats": {"n:value": 255}, "n:row": [{"n:id": "9223372036854775808", "n:slot": -32768}]}
    })).unwrap();
    let _: &LeftStats = config.left.as_ref().unwrap().stats.as_ref().unwrap();
    let _: &RightStats = config.right.as_ref().unwrap().stats.as_ref().unwrap();
    let _: &LeftRow = config.left.as_ref().unwrap().row.values().next().unwrap();
    let _: &RightRow = config.right.as_ref().unwrap().row.values().next().unwrap();
    patch::apply_patch(
        &mut config,
        &[patch::ConfigDelta::Update(
            YangPath::new("/n:system/n:left/n:row[id='18446744073709551615'][slot='-128']/n:slot")
                .unwrap(),
            "-128".into(),
        )],
    )
    .unwrap();
    let wire = serde_json::to_value(&config).unwrap();
    assert_eq!(wire["n:right"]["stats"]["value"], 255);
    assert_eq!(serde_json::from_value::<System>(wire).unwrap(), config);
}

#[test]
fn numeric_leaf_lists_and_single_keys_use_their_scalar_codecs() {
    for (ty, value) in [
        ("uint8", "255"),
        ("uint16", "65535"),
        ("uint32", "4294967295"),
        ("uint64", "18446744073709551615"),
        ("int8", "-128"),
        ("int16", "-32768"),
        ("int32", "-2147483648"),
        ("int64", "-9223372036854775808"),
    ] {
        let scalar: Value = if ty.ends_with("64") {
            json!(value)
        } else {
            serde_json::from_str(value).unwrap()
        };
        let name = format!("{ty}-values");
        let config = set(&System::default(), &name, json!([scalar])).unwrap();
        let wire = serde_json::to_value(&config).unwrap();
        assert_eq!(wire[format!("n:{name}")], json!([scalar]));
        let path: &'static str = Box::leak(format!("/n:system/n:{name}").into_boxed_str());
        assert_eq!(edit(&System::default(), path, value).unwrap(), config);
        let projected = gnmi_json::renderer()
            .render_running_json(&config, ReadSelection::new(&[path]))
            .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(projected[0].value_json()).unwrap(),
            json!([scalar])
        );
        let mut config = System::default();
        let path = YangPath::new(format!("/n:system/n:by-{ty}[id='{value}']/n:value")).unwrap();
        patch::apply_patch(&mut config, &[patch::ConfigDelta::Update(path, "7".into())]).unwrap();
        let wire = serde_json::to_value(&config).unwrap();
        assert_eq!(wire[format!("n:by-{ty}")][0]["id"], scalar);
        assert_eq!(wire[format!("n:by-{ty}")][0]["value"], 7);
        let mut reproduced = System::default();
        let delta = config.diff(&reproduced).unwrap();
        patch::apply_patch(&mut reproduced, &delta).unwrap();
        assert_eq!(reproduced, config);
    }
}

#[test]
fn range_rejections_are_atomic_and_cover_subtrees_references_and_secrets() {
    let baseline = set(&System::default(), "bounded", json!("18446744073709551615")).unwrap();
    for (name, invalid) in [
        ("bounded", "0"),
        ("signed", "0"),
        ("signed-values", "101"),
        ("secret-count", "0"),
        ("secret-values", "2"),
        ("bounded-reference", "0"),
        ("chained-reference", "0"),
        ("bounded-references", "0"),
    ] {
        let mut candidate = baseline.clone();
        assert!(
            patch::apply_patch(
                &mut candidate,
                &[
                    patch::ConfigDelta::Update(
                        YangPath::new("/n:system/n:i8").unwrap(),
                        "5".into()
                    ),
                    patch::ConfigDelta::Update(
                        YangPath::new(format!("/n:system/n:{name}")).unwrap(),
                        invalid.into()
                    ),
                ]
            )
            .is_err(),
            "{name}"
        );
        assert_eq!(candidate, baseline, "{name}");
    }
    for bad in [
        json!({"n:bounded": "0"}),
        json!({"n:signed": 0}),
        json!({"n:secret-count": "0"}),
        json!({"n:secret-values": [2]}),
        json!({"n:bounded-reference": "0"}),
        json!({"n:chained-reference": "0"}),
    ] {
        assert!(serde_json::from_value::<System>(bad.clone()).is_err());
        let operation =
            NormalizedValue::new(Encoding::JsonIetf, bad.to_string(), &Default::default()).unwrap();
        assert!(gnmi_set::patcher()
            .apply_set(
                &baseline,
                &NormalizedSet {
                    updates: vec![(YangPath::new("/n:system").unwrap(), operation)],
                    ..Default::default()
                }
            )
            .is_err());
    }
    let mut invalid = baseline.clone();
    invalid.secret_values = SecretLeaf::new(vec![2]);
    assert!(invalid.validate_syntax().is_err());
    invalid.secret_values = SecretLeaf::new(vec![]);
    invalid.state = Some(State {
        count: Some(YangUint64(0)),
    });
    assert!(invalid.validate_syntax().is_err());
    for name in [
        "bounded-reference",
        "chained-reference",
        "bounded-references",
    ] {
        assert!(set(&baseline, name, json!("18446744073709551615")).is_ok());
        let path: &'static str = Box::leak(format!("/n:system/n:{name}").into_boxed_str());
        assert!(edit(&baseline, path, "18446744073709551615").is_ok());
        assert!(edit(&baseline, path, "0").is_err());
    }
    assert_eq!(
        serde_json::to_value(set(&baseline, "u64", json!(u64::MAX)).unwrap()).unwrap()["n:u64"],
        u64::MAX.to_string()
    );
    for value in [i64::MIN, i64::MAX] {
        assert_eq!(
            serde_json::to_value(set(&baseline, "i64", json!(value)).unwrap()).unwrap()["n:i64"],
            value.to_string()
        );
    }
}

#[test]
fn companion_reserved_and_second_order_names_remain_unambiguous() {
    let mut config: System = serde_json::from_value(json!({ "n:names": {
        "alpha": { "shared": [{ "id": "18446744073709551615", "slot": "-9223372036854775808" }] },
        "alpha-shared": { "value": 1 }, "gamma-item-key": { "value": 2 },
        "unique": [{ "id": "1", "slot": "2" }], "unique-key": { "value": 3 },
        "yang-int64": { "value": 4 }, "yang-uint64": { "value": 5 },
        "leaf-presence": { "value": 6 }, "sensitive-key": { "value": 7 }
    }}))
    .unwrap();
    let names = config.names.as_ref().unwrap();
    let _: &AlphaShared = names.alpha_shared.as_ref().unwrap();
    let _: &NamesAlphaShared = names
        .alpha
        .as_ref()
        .unwrap()
        .shared
        .values()
        .next()
        .unwrap();
    let _: &GammaItemKey = names.gamma_item_key.as_ref().unwrap();
    let _: &UniqueKey = names.unique_key.as_ref().unwrap();
    let _: &NamesUnique = names.unique.values().next().unwrap();
    let _: &NamesYangInt64 = names.yang_int64.as_ref().unwrap();
    let _: &NamesYangUint64 = names.yang_uint64.as_ref().unwrap();
    let _: &NamesLeafPresence = names.leaf_presence.as_ref().unwrap();
    let _: &NamesSensitiveKey = names.sensitive_key.as_ref().unwrap();
    patch::apply_patch(&mut config, &[patch::ConfigDelta::Update(
        YangPath::new("/n:system/n:names/n:alpha/n:shared[id='18446744073709551615'][slot='-9223372036854775808']/n:slot").unwrap(),
        "-9223372036854775808".into())]).unwrap();
    let selection: Vec<_> = generated_test::schema_registry::registry()
        .nodes()
        .iter()
        .filter(|node| node.path.starts_with("/n:system/n:names"))
        .map(|node| node.path)
        .collect();
    let xml = netconf_xml::renderer()
        .render_running_config(&config, &selection, DefaultReport::Explicit)
        .unwrap();
    assert!(xml.contains("<n:id>18446744073709551615</n:id>"));
    assert!(xml.contains("<n:slot>-9223372036854775808</n:slot>"));
    let updates = gnmi_json::renderer()
        .render_running_json(&config, ReadSelection::new(&selection))
        .unwrap();
    let id = updates.iter().find(|update| update.path().as_str() ==
        "/n:system/n:names/n:alpha/n:shared[n:id='18446744073709551615'][n:slot='-9223372036854775808']/n:id").unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(id.value_json()).unwrap(),
        u64::MAX.to_string()
    );
    assert_eq!(
        serde_json::from_value::<System>(serde_json::to_value(&config).unwrap()).unwrap(),
        config
    );
}

#[test]
fn prelude_and_protocol_type_names_do_not_shadow_generated_support() {
    let config: System = serde_json::from_value(json!({ "n:names": {
        "default": {"value": 1}, "box": {"value": 2}, "from": {"value": 3},
        "into-iterator": {"value": 4}, "config-error": {"value": 5}, "node-kind": {"value": 6}
    }, "n:restricted": [{"secret-id": "18446744073709551615"}]}))
    .unwrap();
    let names = config.names.as_ref().unwrap();
    let _: &NamesDefault = names.default.as_ref().unwrap();
    let _: &NamesBox = names.box_.as_ref().unwrap();
    let _: &NamesFrom = names.from.as_ref().unwrap();
    let _: &NamesIntoIterator = names.into_iterator.as_ref().unwrap();
    let _: &NamesConfigError = names.config_error.as_ref().unwrap();
    let _: &NamesNodeKind = names.node_kind.as_ref().unwrap();
    assert!(!format!("{config:?}").contains("18446744073709551615"));
    assert_eq!(config.restricted.keys().next().unwrap().get().0, u64::MAX);
}
