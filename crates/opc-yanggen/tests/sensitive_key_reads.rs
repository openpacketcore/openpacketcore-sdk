//! Generated-model, authenticated protocol regressions for list identity reads.
mod common;

use opc_yanggen::rust::generate_rust;
use opc_yanggen::{
    CanonicalInput, GenerationInput, SchemaModule, SchemaNode, SchemaNodeKind, StackBudget,
    TypeRef, YangSourceLocation,
};
use std::{fs, process::Command};

fn input() -> CanonicalInput {
    let source = YangSourceLocation::new("keys.yang", 1, 1);
    let mut nodes = vec![SchemaNode {
        path: "/keys:root".into(),
        module: "keys".into(),
        kind: SchemaNodeKind::Container,
        config: true,
        source: source.clone(),
        ..Default::default()
    }];
    let lists = [
        ("public-rows", vec![("id", Some("public"))], false),
        ("sensitive-rows", vec![("id", Some("subscriber-id"))], false),
        (
            "composite-rows",
            vec![
                ("tenant", Some("network-sensitive")),
                ("id", Some("subscriber-id")),
            ],
            false,
        ),
        ("parents", vec![("id", Some("subscriber-id"))], false),
        ("ordered-rows", vec![("id", Some("subscriber-id"))], true),
        ("blocked-rows", vec![("id", Some("security-secret"))], false),
        ("lawful-rows", vec![("id", Some("lawful-intercept"))], false),
        ("named-rows", vec![("password", None)], false),
    ];
    for (list, keys, user_order) in lists {
        let path = format!("/keys:root/keys:{list}");
        nodes[0].child_paths.push(path.clone());
        let mut children = keys
            .iter()
            .map(|(key, _)| format!("{path}/keys:{key}"))
            .collect::<Vec<_>>();
        children.extend([
            format!("{path}/keys:value"),
            format!("{path}/keys:payload"),
            format!("{path}/keys:observed"),
        ]);
        if list == "parents" {
            children.push(format!("{path}/keys:children"));
        }
        nodes.push(SchemaNode {
            path: path.clone(),
            module: "keys".into(),
            kind: SchemaNodeKind::List,
            config: true,
            key_leaves: keys.iter().map(|(name, _)| name.to_string()).collect(),
            child_paths: children,
            ordered_by: user_order.then(|| "user".into()),
            source: source.clone(),
            ..Default::default()
        });
        for (name, class) in keys.into_iter().chain([
            ("value", Some("public")),
            ("payload", Some("security-secret")),
        ]) {
            nodes.push(SchemaNode {
                path: format!("{path}/keys:{name}"),
                module: "keys".into(),
                kind: SchemaNodeKind::Leaf,
                config: true,
                type_ref: Some(TypeRef::String),
                data_class: class.map(str::to_string),
                source: source.clone(),
                ..Default::default()
            });
        }
        nodes.push(SchemaNode {
            path: format!("{path}/keys:observed"),
            module: "keys".into(),
            kind: SchemaNodeKind::Leaf,
            config: false,
            type_ref: Some(TypeRef::String),
            data_class: Some("public".into()),
            source: source.clone(),
            ..Default::default()
        });
        if list == "parents" {
            let child = format!("{path}/keys:children");
            nodes.push(SchemaNode {
                path: child.clone(),
                module: "keys".into(),
                kind: SchemaNodeKind::List,
                config: true,
                key_leaves: vec!["id".into()],
                child_paths: vec![
                    format!("{child}/keys:id"),
                    format!("{child}/keys:value"),
                    format!("{child}/keys:observed"),
                ],
                source: source.clone(),
                ..Default::default()
            });
            for name in ["id", "value", "observed"] {
                nodes.push(SchemaNode {
                    path: format!("{child}/keys:{name}"),
                    module: "keys".into(),
                    kind: SchemaNodeKind::Leaf,
                    config: name != "observed",
                    type_ref: Some(TypeRef::String),
                    data_class: Some(
                        if name == "id" {
                            "subscriber-id"
                        } else {
                            "public"
                        }
                        .into(),
                    ),
                    source: source.clone(),
                    ..Default::default()
                });
            }
        }
    }
    for (parent, name, child, default) in [
        ("/keys:root", "empty-presence", "optional", None),
        (
            "/keys:root",
            "default-presence",
            "defaulted",
            Some("default-value"),
        ),
        (
            "/keys:root/keys:public-rows",
            "row-presence",
            "row-optional",
            None,
        ),
    ] {
        let path = format!("{parent}/keys:{name}");
        let child_path = format!("{path}/keys:{child}");
        nodes
            .iter_mut()
            .find(|node| node.path == parent)
            .unwrap()
            .child_paths
            .push(path.clone());
        nodes.push(SchemaNode {
            path,
            module: "keys".into(),
            kind: SchemaNodeKind::Container,
            config: true,
            presence: Some("explicitly configured presence".into()),
            child_paths: vec![child_path.clone()],
            source: source.clone(),
            ..Default::default()
        });
        nodes.push(SchemaNode {
            path: child_path,
            module: "keys".into(),
            kind: SchemaNodeKind::Leaf,
            config: true,
            type_ref: Some(TypeRef::String),
            default: default.map(str::to_string),
            source: source.clone(),
            ..Default::default()
        });
    }
    nodes[0].child_paths.push("/keys:root/keys:scope".into());
    nodes.push(SchemaNode {
        path: "/keys:root/keys:scope".into(),
        module: "keys".into(),
        kind: SchemaNodeKind::Container,
        config: true,
        presence: Some("configured member scope".into()),
        child_paths: vec!["/keys:root/keys:scope/keys:members".into()],
        source: source.clone(),
        ..Default::default()
    });
    nodes.push(SchemaNode {
        path: "/keys:root/keys:scope/keys:members".into(),
        module: "keys".into(),
        kind: SchemaNodeKind::List,
        config: true,
        key_leaves: vec!["id".into()],
        child_paths: vec![
            "/keys:root/keys:scope/keys:members/keys:id".into(),
            "/keys:root/keys:scope/keys:members/keys:value".into(),
        ],
        source: source.clone(),
        ..Default::default()
    });
    for child in ["id", "value"] {
        nodes.push(SchemaNode {
            path: format!("/keys:root/keys:scope/keys:members/keys:{child}"),
            module: "keys".into(),
            kind: SchemaNodeKind::Leaf,
            config: true,
            type_ref: Some(TypeRef::String),
            data_class: Some("public".into()),
            source: source.clone(),
            ..Default::default()
        });
    }
    let ir = opc_yanggen::compile(&GenerationInput {
        profile: "test".into(),
        lockfile: opc_yanggen::ir::ModuleLockfile {
            profile: "test".into(),
            modules: vec![],
        },
        schema_modules: vec![SchemaModule {
            name: "keys".into(),
            revision: "2026-10-12".into(),
            namespace: "urn:keys".into(),
            prefix: "keys".into(),
            source,
            ..Default::default()
        }],
        nodes,
        constraints: vec![],
        unsupported_features: vec![],
        stack_budget: StackBudget::default(),
        stack_shapes: vec![],
    })
    .unwrap();
    CanonicalInput {
        profile: opc_yanggen::emit::CanonicalProfile {
            generation: "test".into(),
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
fn generated_sensitive_key_protocol_reads() {
    let scratch = tempfile::tempdir().unwrap();
    let source = scratch.path().join("src");
    fs::create_dir(&source).unwrap();
    for (name, content) in generate_rust(&input()).unwrap() {
        fs::write(
            source.join(if name == "mod.rs" { "lib.rs" } else { &name }),
            content,
        )
        .unwrap();
    }
    let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let mut manifest = format!(
        r#"
[package]
name = "generated-sensitive-key-test"
version = "0.1.0"
edition = "2021"
[dependencies]
serde = {{ version = "1", features = ["derive"] }}
serde_json = "1"
tracing = "0.1"
time = "={}"
tokio = {{ version = "1", features = ["rt-multi-thread", "macros", "io-util"] }}
tonic = {{ version = "0.14.6", default-features = false, features = ["codegen"] }}
"#,
        common::locked_version(workspace, "time")
    );
    for name in [
        "opc-config-model",
        "opc-types",
        "opc-data-governance",
        "opc-redaction",
        "opc-mgmt-schema",
        "opc-config-bus",
        "opc-mgmt-authz",
        "opc-mgmt-audit",
        "opc-mgmt-opstate",
        "opc-mgmt-path",
        "opc-mgmt-limits",
        "opc-nacm",
        "opc-gnmi-server",
        "opc-netconf-server",
    ] {
        manifest.push_str(&format!(
            "{name} = {{ path = {:?} }}\n",
            workspace.join("crates").join(name)
        ));
    }
    fs::write(scratch.path().join("Cargo.toml"), manifest).unwrap();
    fs::create_dir(scratch.path().join("tests")).unwrap();
    fs::write(
        scratch.path().join("tests/reads.rs"),
        include_str!("fixtures/sensitive_key_reads_test.rs"),
    )
    .unwrap();
    let status = Command::new("cargo")
        .arg("test")
        .arg("--")
        .arg("--test-threads=1")
        .env("RUSTFLAGS", "-Dwarnings")
        .current_dir(scratch.path())
        .status()
        .unwrap();
    assert!(status.success());
}
