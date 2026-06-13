mod common;

use opc_yanggen::rust::generate_rust;
use opc_yanggen::{
    CanonicalInput, GenerationInput, SchemaModule, SchemaNode, SchemaNodeKind, StackBudget,
    TypeRef, YangSourceLocation,
};
use std::fs;
use std::process::Command;
use tempfile::tempdir;

fn create_base_input() -> CanonicalInput {
    let source = YangSourceLocation::new("upf-slice.yang", 1, 1);
    let nodes = vec![
        SchemaNode {
            path: "/upf:system".to_string(),
            module: "upf-slice".to_string(),
            kind: SchemaNodeKind::Container,
            config: true,
            type_ref: None,
            key_leaves: vec![],
            child_paths: vec!["/upf:system/enabled".to_string()],
            source: source.clone(),
            ..Default::default()
        },
        SchemaNode {
            path: "/upf:system/enabled".to_string(),
            module: "upf-slice".to_string(),
            kind: SchemaNodeKind::Leaf,
            config: true,
            type_ref: Some(TypeRef::Boolean),
            key_leaves: vec![],
            child_paths: vec![],
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
        schema_modules: vec![SchemaModule {
            name: "upf-slice".to_string(),
            revision: "2026-06-01".to_string(),
            namespace: "urn:opc:upf-slice".to_string(),
            prefix: "upf".to_string(),
            source: source.clone(),
        }],
        nodes,
        constraints: vec![],
        unsupported_features: vec![],
        stack_budget: StackBudget::default(),
        stack_shapes: vec![],
    };

    let ir = opc_yanggen::compile(&input).unwrap();
    // For test simplicity we will just directly instantiate CanonicalInput
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
fn test_generate_and_compile() {
    let input = create_base_input();
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
        let path = src_dir.join(name.clone());
        fs::write(path, content).unwrap();
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

    // The scratch project resolves dependencies fresh (it has no lockfile),
    // which makes this test hostage to upstream releases: a transitive crate
    // published after the workspace lockfile can fail to build here while the
    // workspace itself is green. Pin the floating transitive dependencies to
    // the versions locked by the workspace so both resolve identically.
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
"#,
        time_version,
        config_model_path.display(),
        types_path.display(),
        data_gov_path.display(),
        mgmt_schema_path.display()
    );

    fs::write(dir.path().join("Cargo.toml"), cargo_toml).unwrap();

    let status = Command::new("cargo")
        .arg("check")
        .env("RUSTFLAGS", "-Dwarnings")
        .current_dir(dir.path())
        .status()
        .unwrap();

    assert!(status.success());
}
