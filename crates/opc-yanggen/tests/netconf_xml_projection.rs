mod common;

use opc_yanggen::rust::generate_rust;
use opc_yanggen::{
    CanonicalInput, GenerationInput, SchemaModule, SchemaNode, SchemaNodeKind, StackBudget,
    TypeRef, YangSourceLocation,
};
use std::fs;
use std::process::Command;
use tempfile::tempdir;

fn build_input() -> CanonicalInput {
    let source = YangSourceLocation::new("example.yang", 1, 1);
    let module = SchemaModule {
        name: "example".to_string(),
        revision: "2026-06-01".to_string(),
        namespace: "urn:example".to_string(),
        prefix: "ex".to_string(),
        source: source.clone(),
        ..Default::default()
    };

    let nodes = vec![
        SchemaNode {
            path: "/ex:system".to_string(),
            module: "example".to_string(),
            kind: SchemaNodeKind::Container,
            config: true,
            child_paths: vec![
                "/ex:system/ex:hostname".to_string(),
                "/ex:system/ex:enabled".to_string(),
                "/ex:system/ex:secret".to_string(),
                "/ex:system/ex:uptime".to_string(),
                "/ex:system/ex:dns".to_string(),
                "/ex:system/ex:interfaces".to_string(),
                "/ex:system/ex:routes".to_string(),
                "/ex:system/ex:servers".to_string(),
                "/ex:system/ex:tags".to_string(),
                "/ex:system/ex:custom-tags".to_string(),
            ],
            source: source.clone(),
            ..Default::default()
        },
        SchemaNode {
            path: "/ex:system/ex:hostname".to_string(),
            module: "example".to_string(),
            kind: SchemaNodeKind::Leaf,
            config: true,
            type_ref: Some(TypeRef::String),
            source: source.clone(),
            ..Default::default()
        },
        SchemaNode {
            path: "/ex:system/ex:enabled".to_string(),
            module: "example".to_string(),
            kind: SchemaNodeKind::Leaf,
            config: true,
            type_ref: Some(TypeRef::Boolean),
            default: Some("true".to_string()),
            source: source.clone(),
            ..Default::default()
        },
        SchemaNode {
            path: "/ex:system/ex:secret".to_string(),
            module: "example".to_string(),
            kind: SchemaNodeKind::Leaf,
            config: true,
            type_ref: Some(TypeRef::String),
            data_class: Some("security-secret".to_string()),
            source: source.clone(),
            ..Default::default()
        },
        SchemaNode {
            path: "/ex:system/ex:uptime".to_string(),
            module: "example".to_string(),
            kind: SchemaNodeKind::Leaf,
            config: false,
            type_ref: Some(TypeRef::Uint32),
            source: source.clone(),
            ..Default::default()
        },
        SchemaNode {
            path: "/ex:system/ex:dns".to_string(),
            module: "example".to_string(),
            kind: SchemaNodeKind::Container,
            config: true,
            child_paths: vec!["/ex:system/ex:dns/ex:server".to_string()],
            source: source.clone(),
            ..Default::default()
        },
        SchemaNode {
            path: "/ex:system/ex:dns/ex:server".to_string(),
            module: "example".to_string(),
            kind: SchemaNodeKind::Leaf,
            config: true,
            type_ref: Some(TypeRef::String),
            default: Some("8.8.8.8".to_string()),
            source: source.clone(),
            ..Default::default()
        },
        SchemaNode {
            path: "/ex:system/ex:interfaces".to_string(),
            module: "example".to_string(),
            kind: SchemaNodeKind::List,
            config: true,
            key_leaves: vec!["name".to_string()],
            child_paths: vec![
                "/ex:system/ex:interfaces/ex:name".to_string(),
                "/ex:system/ex:interfaces/ex:mtu".to_string(),
                "/ex:system/ex:interfaces/ex:admin".to_string(),
                "/ex:system/ex:interfaces/ex:auth-key".to_string(),
                "/ex:system/ex:interfaces/ex:sub-interfaces".to_string(),
            ],
            source: source.clone(),
            ..Default::default()
        },
        SchemaNode {
            path: "/ex:system/ex:interfaces/ex:name".to_string(),
            module: "example".to_string(),
            kind: SchemaNodeKind::Leaf,
            config: true,
            type_ref: Some(TypeRef::String),
            source: source.clone(),
            ..Default::default()
        },
        SchemaNode {
            path: "/ex:system/ex:interfaces/ex:mtu".to_string(),
            module: "example".to_string(),
            kind: SchemaNodeKind::Leaf,
            config: true,
            type_ref: Some(TypeRef::Uint16),
            source: source.clone(),
            ..Default::default()
        },
        SchemaNode {
            path: "/ex:system/ex:interfaces/ex:admin".to_string(),
            module: "example".to_string(),
            kind: SchemaNodeKind::Leaf,
            config: true,
            type_ref: Some(TypeRef::Boolean),
            source: source.clone(),
            ..Default::default()
        },
        SchemaNode {
            path: "/ex:system/ex:interfaces/ex:auth-key".to_string(),
            module: "example".to_string(),
            kind: SchemaNodeKind::Leaf,
            config: true,
            type_ref: Some(TypeRef::String),
            data_class: Some("security-secret".to_string()),
            source: source.clone(),
            ..Default::default()
        },
        SchemaNode {
            path: "/ex:system/ex:interfaces/ex:sub-interfaces".to_string(),
            module: "example".to_string(),
            kind: SchemaNodeKind::List,
            config: true,
            key_leaves: vec!["id".to_string()],
            child_paths: vec![
                "/ex:system/ex:interfaces/ex:sub-interfaces/ex:id".to_string(),
                "/ex:system/ex:interfaces/ex:sub-interfaces/ex:description".to_string(),
            ],
            source: source.clone(),
            ..Default::default()
        },
        SchemaNode {
            path: "/ex:system/ex:interfaces/ex:sub-interfaces/ex:id".to_string(),
            module: "example".to_string(),
            kind: SchemaNodeKind::Leaf,
            config: true,
            type_ref: Some(TypeRef::Uint16),
            source: source.clone(),
            ..Default::default()
        },
        SchemaNode {
            path: "/ex:system/ex:interfaces/ex:sub-interfaces/ex:description".to_string(),
            module: "example".to_string(),
            kind: SchemaNodeKind::Leaf,
            config: true,
            type_ref: Some(TypeRef::String),
            source: source.clone(),
            ..Default::default()
        },
        SchemaNode {
            path: "/ex:system/ex:routes".to_string(),
            module: "example".to_string(),
            kind: SchemaNodeKind::List,
            config: true,
            key_leaves: vec!["dest".to_string(), "next-hop".to_string()],
            child_paths: vec![
                "/ex:system/ex:routes/ex:dest".to_string(),
                "/ex:system/ex:routes/ex:next-hop".to_string(),
                "/ex:system/ex:routes/ex:metric".to_string(),
            ],
            source: source.clone(),
            ..Default::default()
        },
        SchemaNode {
            path: "/ex:system/ex:routes/ex:dest".to_string(),
            module: "example".to_string(),
            kind: SchemaNodeKind::Leaf,
            config: true,
            type_ref: Some(TypeRef::String),
            source: source.clone(),
            ..Default::default()
        },
        SchemaNode {
            path: "/ex:system/ex:routes/ex:next-hop".to_string(),
            module: "example".to_string(),
            kind: SchemaNodeKind::Leaf,
            config: true,
            type_ref: Some(TypeRef::String),
            source: source.clone(),
            ..Default::default()
        },
        SchemaNode {
            path: "/ex:system/ex:routes/ex:metric".to_string(),
            module: "example".to_string(),
            kind: SchemaNodeKind::Leaf,
            config: true,
            type_ref: Some(TypeRef::Uint32),
            source: source.clone(),
            ..Default::default()
        },
        SchemaNode {
            path: "/ex:system/ex:servers".to_string(),
            module: "example".to_string(),
            kind: SchemaNodeKind::LeafList,
            config: true,
            type_ref: Some(TypeRef::String),
            source: source.clone(),
            ..Default::default()
        },
        SchemaNode {
            path: "/ex:system/ex:tags".to_string(),
            module: "example".to_string(),
            kind: SchemaNodeKind::LeafList,
            config: true,
            type_ref: Some(TypeRef::Uint16),
            source: source.clone(),
            ..Default::default()
        },
        SchemaNode {
            path: "/ex:system/ex:custom-tags".to_string(),
            module: "example".to_string(),
            kind: SchemaNodeKind::LeafList,
            config: true,
            type_ref: Some(TypeRef::Custom {
                name: "CustomTag".to_string(),
            }),
            source: source.clone(),
            ..Default::default()
        },
    ];

    let input = GenerationInput {
        profile: "test".to_string(),
        lockfile: opc_yanggen::ir::ModuleLockfile {
            profile: "test".to_string(),
            modules: vec![],
        },
        schema_modules: vec![module],
        nodes,
        constraints: vec![],
        unsupported_features: vec![],
        stack_budget: StackBudget::default(),
        stack_shapes: vec![],
    };

    let ir = opc_yanggen::compile(&input).unwrap();
    CanonicalInput {
        profile: opc_yanggen::emit::CanonicalProfile {
            generation: "test".to_string(),
            lockfile_mismatch: None,
        },
        locked_modules: vec![],
        schema_modules: ir.modules,
        nodes: ir.nodes,
        constraints: vec![],
        stack_shapes: ir.stack_shapes,
        stack_budget: ir.stack_budget,
        canonicalization_skipped: false,
        max_canonical_scan_stack_len: None,
    }
}

#[test]
fn generated_netconf_xml_projection() {
    let input = build_input();
    let files = generate_rust(&input).unwrap();

    let dir = tempdir().unwrap();
    let src_dir = dir.path().join("src");
    fs::create_dir(&src_dir).unwrap();

    for (name, content) in files {
        let name = if name == "mod.rs" {
            "lib.rs".to_string()
        } else {
            name
        };
        fs::write(src_dir.join(&name), content).unwrap();
        if name == "types.rs" {
            // The schema intentionally contains a custom-typed leaf-list so that
            // the projection can exercise runtime fail-closed for unsupported
            // custom types. Provide a minimal placeholder type that satisfies
            // the generated struct's trait bounds without claiming a real codec.
            let placeholder = r#"

/// Placeholder for the intentionally-unsupported custom leaf-list element type.
pub type CustomTag = String;
"#;
            let augmented = fs::read_to_string(src_dir.join("types.rs")).unwrap() + placeholder;
            fs::write(src_dir.join("types.rs"), augmented).unwrap();
        }
    }

    let workspace_dir = std::env::current_dir()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    let config_model_path = workspace_dir.join("crates/opc-config-model");
    let types_path = workspace_dir.join("crates/opc-types");
    let data_gov_path = workspace_dir.join("crates/opc-data-governance");
    let mgmt_schema_path = workspace_dir.join("crates/opc-mgmt-schema");
    let redaction_path = workspace_dir.join("crates/opc-redaction");

    let time_version = common::locked_version(&workspace_dir, "time");

    let cargo_toml = format!(
        r#"
[package]
name = "generated-test"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = {{ version = "1.0", features = ["derive"] }}
serde_json = "1.0"
time = "={}"
opc-config-model = {{ path = "{}" }}
opc-types = {{ path = "{}" }}
opc-data-governance = {{ path = "{}" }}
opc-mgmt-schema = {{ path = "{}" }}
opc-redaction = {{ path = "{}" }}
"#,
        time_version,
        config_model_path.display(),
        types_path.display(),
        data_gov_path.display(),
        mgmt_schema_path.display(),
        redaction_path.display(),
    );
    fs::write(dir.path().join("Cargo.toml"), cargo_toml).unwrap();

    let tests_dir = dir.path().join("tests");
    fs::create_dir(&tests_dir).unwrap();
    fs::write(
        tests_dir.join("netconf_xml.rs"),
        include_str!("fixtures/netconf_xml_projection_test.rs"),
    )
    .unwrap();

    let status = Command::new("cargo")
        .arg("test")
        .env("RUSTFLAGS", "-Dwarnings")
        .current_dir(dir.path())
        .status()
        .unwrap();

    assert!(status.success());
}
