use generated_test::{gnmi_json, gnmi_set, netconf_xml, netconf_xml_edit, patch, types::*};
use opc_config_model::{OpcConfig, YangPath};
use opc_gnmi_server::{
    Encoding, GnmiJsonRenderer, GnmiPatchApplicator, NormalizedSet, NormalizedValue, ReadSelection,
};
use opc_mgmt_schema::{
    DefaultReport, EditConfigNode, EditOperation, NetconfXmlEditApplicator, NetconfXmlRenderer,
};
use serde_json::{json, Value};

fn context() -> opc_config_model::ValidationContext<Root> {
    use opc_config_model::{
        CommitMode, ConfigOperation, RequestId, RequestSource, TransportType, TrustedPrincipal,
        ValidationContext, WorkloadIdentity,
    };
    ValidationContext {
        request_id: RequestId::new(),
        principal: TrustedPrincipal::new(
            WorkloadIdentity::Internal("test".into()),
            opc_types::TenantId::new("test").unwrap(),
        ),
        transport: TransportType::Internal,
        source: RequestSource::Northbound,
        operation: ConfigOperation::Replace,
        mode: CommitMode::Commit,
        base_version: opc_types::ConfigVersion::INITIAL,
        previous: None,
    }
}

fn set(name: &str, value: Value) -> Result<Root, opc_gnmi_server::GnmiError> {
    gnmi_set::patcher().apply_set(
        &Root::default(),
        &NormalizedSet {
            updates: vec![(
                YangPath::new(format!("/d:root/d:{name}")).unwrap(),
                NormalizedValue::new(Encoding::JsonIetf, value.to_string(), &Default::default())
                    .unwrap(),
            )],
            ..Default::default()
        },
    )
}

fn edit(path: &'static str, value: &str) -> Result<Root, opc_mgmt_schema::NetconfEditError> {
    netconf_xml_edit::applicator().apply_edit_config(
        &Root::default(),
        &EditConfigNode {
            schema_path: "/d:root",
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
fn large_adjacent_values_roundtrip_without_rounding() {
    for value in [
        "900719925474099.21",
        "900719925474099.22",
        "92233720368547758.07",
        "-92233720368547758.08",
    ] {
        let config = set("amount", json!(value)).unwrap();
        assert_eq!(
            serde_json::to_value(&config).unwrap()["decimal64-proof:amount"],
            json!(value)
        );
        let path = "/d:root/d:amount";
        let updates = gnmi_json::renderer()
            .render_running_json(&config, ReadSelection::new(&[path]))
            .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(updates[0].value_json()).unwrap(),
            json!(value)
        );
        let xml = netconf_xml::renderer()
            .render_running_config(&config, &[path], DefaultReport::Explicit)
            .unwrap();
        assert!(xml.contains(&format!(">{value}</d:amount>")), "{xml}");
        assert_eq!(edit(path, value).unwrap(), config);
        let mut patched = Root::default();
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
}

#[test]
fn invalid_decimal_values_are_rejected_at_every_input_boundary() {
    for bad in [
        "1.234",
        "NaN",
        "inf",
        "-inf",
        "1e1",
        ".5",
        "1.",
        "",
        "92233720368547758.08",
        "-92233720368547758.09",
    ] {
        assert!(
            serde_json::from_value::<Root>(json!({"amount": bad})).is_err(),
            "JSON accepted {bad}"
        );
        assert!(set("amount", json!(bad)).is_err(), "gNMI accepted {bad}");
        assert!(edit("/d:root/d:amount", bad).is_err(), "XML accepted {bad}");
        let mut config = Root::default();
        let before = config.clone();
        assert!(patch::apply_patch(
            &mut config,
            &[patch::ConfigDelta::Update(
                YangPath::new("/d:root/d:amount").unwrap(),
                bad.into()
            )]
        )
        .is_err());
        assert_eq!(config, before);
    }
    assert!(set("amount", json!(1.25)).is_err());
    assert!(serde_json::from_value::<Root>(json!({"amount": 1.25})).is_err());
}

#[test]
fn all_eighteen_fraction_digits_survive_and_zero_is_canonical() {
    for (raw, canonical) in [
        ("9.223372036854775807", "9.223372036854775807"),
        ("-9.223372036854775808", "-9.223372036854775808"),
        ("0.000000000000000001", "0.000000000000000001"),
        ("+0001.230000000000000000000", "1.23"),
        ("-0.000", "0.0"),
        ("1", "1.0"),
    ] {
        let config = set("fine", json!(raw)).unwrap();
        assert_eq!(
            serde_json::to_value(&config).unwrap()["decimal64-proof:fine"],
            json!(canonical)
        );
    }
    for raw in [
        "9.223372036854775808",
        "-9.223372036854775809",
        "0.0000000000000000001",
    ] {
        assert!(set("fine", json!(raw)).is_err());
    }
}

#[test]
fn defaults_leafrefs_and_leaf_list_identity_use_exact_values() {
    let ctx = context();
    assert_eq!(
        serde_json::to_value(Root::default()).unwrap()["decimal64-proof:defaulted"],
        json!("900719925474099.23")
    );
    let config: Root = serde_json::from_value(json!({"amount": "900719925474099.21", "amount-ref": "900719925474099.21", "chained-ref": "900719925474099.21", "values": ["900719925474099.21", "900719925474099.22"]})).unwrap();
    config.validate_syntax().unwrap();
    config.validate_semantics(&ctx).unwrap();
    let wrong: Root = serde_json::from_value(
        json!({"amount": "900719925474099.21", "amount-ref": "900719925474099.22"}),
    )
    .unwrap();
    assert!(wrong.validate_semantics(&ctx).is_err());
    assert!(serde_json::from_value::<Root>(json!({"values": ["1.0", "+01.00"]})).is_err());
    for raw in ["900719925474099.23", "+0900719925474099.2300"] {
        let config = set("defaulted", json!(raw)).unwrap();
        let xml = netconf_xml::renderer()
            .render_running_config(&config, &["/d:root/d:defaulted"], DefaultReport::Trim)
            .unwrap();
        assert!(!xml.contains("defaulted"));
    }
    let config = set("defaulted", json!("900719925474099.22")).unwrap();
    let xml = netconf_xml::renderer()
        .render_running_config(&config, &["/d:root/d:defaulted"], DefaultReport::Trim)
        .unwrap();
    assert!(xml.contains("900719925474099.22"));
}

#[test]
fn decimal_keys_are_exact_and_preserve_row_identity() {
    let baseline: Root = serde_json::from_value(json!({"row": [
        {"id": "900719925474099.21", "label": "first"},
        {"id": "900719925474099.22", "label": "second"}]}))
    .unwrap();
    assert_eq!(baseline.row.len(), 2);
    let mut updated = baseline.clone();
    patch::apply_patch(
        &mut updated,
        &[patch::ConfigDelta::Update(
            YangPath::new("/d:root/d:row[id='900719925474099.22']/d:label").unwrap(),
            "changed".into(),
        )],
    )
    .unwrap();
    let wire = serde_json::to_value(&updated).unwrap();
    assert_eq!(wire["decimal64-proof:row"][0]["label"], "first");
    assert_eq!(wire["decimal64-proof:row"][1]["label"], "changed");
    let row_edit = |id: &str| EditConfigNode {
        schema_path: "/d:root",
        operation: EditOperation::Merge,
        value: None,
        list_keys: Default::default(),
        children: vec![EditConfigNode {
            schema_path: "/d:root/d:row",
            operation: EditOperation::Merge,
            value: None,
            list_keys: [("id".into(), id.into())].into(),
            children: vec![EditConfigNode {
                schema_path: "/d:root/d:row/d:label",
                operation: EditOperation::Merge,
                value: Some("xml".into()),
                list_keys: Default::default(),
                children: vec![],
            }],
        }],
    };
    let edited = netconf_xml_edit::applicator()
        .apply_edit_config(&baseline, &row_edit("+0900719925474099.2200"))
        .unwrap();
    let wire = serde_json::to_value(edited).unwrap();
    assert_eq!(wire["decimal64-proof:row"][0]["label"], "first");
    assert_eq!(wire["decimal64-proof:row"][1]["label"], "xml");
    assert!(
        serde_json::from_value::<Root>(json!({"row": [{"id": "1.0"}, {"id": "+01.00"}]})).is_err()
    );
    for bad in ["1.001", "NaN", "92233720368547758.08"] {
        assert!(netconf_xml_edit::applicator()
            .apply_edit_config(&baseline, &row_edit(bad))
            .is_err());
        let before = updated.clone();
        assert!(patch::apply_patch(
            &mut updated,
            &[patch::ConfigDelta::Update(
                YangPath::new(format!("/d:root/d:row[id='{bad}']/d:label")).unwrap(),
                "invalid".into()
            )]
        )
        .is_err());
        assert_eq!(updated, before);
    }
}

#[test]
fn xpath_conversion_is_separate_from_exact_storage_and_secret_diagnostics() {
    // RFC 7950 section 6.4 expressly gives XPath numeric expressions IEEE 754 semantics.
    let config: Root =
        serde_json::from_value(json!({"xpath-number": "900719925474099.01"})).unwrap();
    config.validate_semantics(&context()).unwrap();
    assert_eq!(
        serde_json::to_value(&config).unwrap()["decimal64-proof:xpath-number"],
        "900719925474099.01"
    );
    let invalid: Root =
        serde_json::from_value(json!({"xpath-number": "900719925474100.0"})).unwrap();
    assert!(invalid.validate_semantics(&context()).is_err());
    for raw in [json!("secret-value-marker"), json!(123456789.125)] {
        let error = serde_json::from_value::<Root>(json!({"api-token": raw})).unwrap_err();
        let message = error.to_string();
        assert!(!message.contains("secret-value-marker"));
        assert!(!message.contains("123456789"));
    }
}
