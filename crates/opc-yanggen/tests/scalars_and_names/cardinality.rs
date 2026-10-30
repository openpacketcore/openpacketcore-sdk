use super::{compile_fixture, input};
use opc_yanggen::{generation_input_from_yang_sources, YangSource};

#[test]
fn generated_mandatory_and_cardinality_contract() {
    compile_fixture(
        "cardinality",
        include_str!("../fixtures/cardinality.yang"),
        include_str!("../fixtures/cardinality_test.rs"),
        4,
    );
}

#[test]
fn review_generated_partial_patch_cardinality_contract() {
    compile_fixture(
        "cardinality-patch",
        include_str!("../fixtures/cardinality_patch.yang"),
        include_str!("../fixtures/cardinality_patch_test.rs"),
        3,
    );
}

#[test]
fn review_generated_sensitive_leaf_constraints_compile_and_enforce_bounds() {
    let mut parsed = input(
        r#"module example { yang-version 1.1; namespace "urn:example:sensitive-cardinality"; prefix ex;
      container root {
        container protected { leaf amount { type uint8 { range "1..10"; } mandatory true; } }
        container enabled { presence "enable"; leaf token { type string { length "1..8"; } mandatory true; } }
        list entries { key name; min-elements 1; max-elements 2; leaf name { type string; } leaf amount { type uint8 { range "1..10"; } mandatory true; } }
      }
    }"#,
    );
    for node in &mut parsed.nodes {
        if matches!(
            node.path.as_str(),
            "/ex:root/ex:protected/ex:amount"
                | "/ex:root/ex:enabled/ex:token"
                | "/ex:root/ex:entries/ex:name"
                | "/ex:root/ex:entries/ex:amount"
        ) {
            node.data_class = Some("security-secret".into());
        }
    }
    super::compile_canonical_fixture(
        "sensitive-cardinality",
        &parsed.to_canonical(),
        include_str!("../fixtures/sensitive_cardinality_test.rs"),
        2,
    );
}

#[test]
fn review_sensitive_ancestors_are_rejected_before_rust_generation() {
    let parsed = input(
        r#"module example { namespace "urn:example"; prefix ex;
            container root {
                container protected { leaf value { type uint8; mandatory true; } }
                list entries { key name; min-elements 1; leaf name { type string; } }
            }
        }"#,
    );
    for (path, kind) in [
        ("/ex:root/ex:protected", "container"),
        ("/ex:root/ex:entries", "list"),
    ] {
        let mut canonical = parsed.to_canonical();
        canonical
            .nodes
            .iter_mut()
            .find(|node| node.path == path)
            .unwrap()
            .data_class = Some("security-secret".into());
        let error = opc_yanggen::rust::generate_rust(&canonical).unwrap_err();
        assert_eq!(
            error.message(),
            format!("{kind} {path} must not be classified as sensitive; classify sensitive leaves instead")
        );
    }
}

#[test]
fn source_rejects_invalid_cardinality_statements() {
    for body in [
        "leaf x { type boolean; mandatory yes; }",
        "leaf x { type boolean; mandatory true; mandatory false; }",
        "leaf x { type boolean; mandatory true; default false; }",
        "leaf x { type boolean; min-elements 1; }",
        "container x { mandatory true; }",
        "leaf-list x { type string; mandatory true; }",
        "leaf-list x { type string; min-elements 1; default x; }",
        "leaf-list x { type string; min-elements -1; }",
        "leaf-list x { type string; min-elements 4294967296; }",
        "leaf-list x { type string; min-elements 2; max-elements 1; }",
        "leaf-list x { type string; max-elements 0; }",
        "leaf-list x { type string; max-elements 4294967296; }",
        "leaf-list x { type string; min-elements 0; min-elements 1; }",
        "leaf-list x { type string; max-elements unbounded; max-elements 2; }",
    ] {
        let source = format!(
            "module example {{ namespace 'urn:example'; prefix ex; container root {{ {body} }} }}"
        );
        let error = generation_input_from_yang_sources(
            "example",
            &[YangSource::new("example.yang", source)],
        )
        .unwrap_err();
        assert_eq!(
            error.code,
            opc_yanggen::DiagnosticCode::YangSourceSyntaxError,
            "{body}"
        );
        assert!(error.source.is_some());
    }
}

#[test]
fn cardinality_changes_the_schema_digest_without_source_text() {
    let source = "module example { namespace 'urn:example'; prefix ex; container root { leaf x { type boolean; mandatory false; } leaf-list y { type string; min-elements 0; max-elements unbounded; } } }";
    let normalized = |source: &str| {
        let mut parsed = input(source);
        parsed.lockfile.modules.clear();
        for module in &mut parsed.schema_modules {
            module.source_text = None;
        }
        opc_yanggen::emit::schema_digest(&parsed)
    };
    let baseline = normalized(source);
    for changed in [
        source.replace("mandatory false", "mandatory true"),
        source.replace("min-elements 0", "min-elements 1"),
        source.replace("max-elements unbounded", "max-elements 2"),
    ] {
        assert_ne!(normalized(&changed), baseline);
    }
}

#[test]
fn cardinality_survives_ir_round_trip_and_source_consistency_checks() {
    use opc_yanggen::source::validate_generation_input_embedded_yang_sources;
    let parsed = input(include_str!("../fixtures/cardinality.yang"));
    let restored: opc_yanggen::GenerationInput =
        serde_json::from_value(serde_json::to_value(&parsed).unwrap()).unwrap();
    assert_eq!(parsed.nodes, restored.nodes);
    validate_generation_input_embedded_yang_sources(&restored).unwrap();
    for path in ["/c:root/c:required", "/c:root/c:codes"] {
        let mut changed = restored.clone();
        let node = changed
            .nodes
            .iter_mut()
            .find(|node| node.path == path)
            .unwrap();
        if path.ends_with("required") {
            node.mandatory = None;
        } else {
            node.max_elements = None;
        }
        let error = validate_generation_input_embedded_yang_sources(&changed).unwrap_err();
        assert_eq!(error.code, opc_yanggen::DiagnosticCode::YangSourceMismatch);
        assert!(error.source.is_some());
    }
    for invalid in [0, 1] {
        let mut canonical = restored.to_canonical();
        for module in &mut canonical.schema_modules {
            module.source_text = None;
        }
        let node = canonical
            .nodes
            .iter_mut()
            .find(|node| node.path == "/c:root/c:codes")
            .unwrap();
        node.min_elements = Some(2);
        node.max_elements = Some(invalid);
        assert!(
            opc_yanggen::rust::generate_rust(&canonical).is_err(),
            "hand-built IR must not bypass bound validation"
        );
    }
}
