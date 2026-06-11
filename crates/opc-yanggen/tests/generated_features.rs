use opc_yanggen::rust::generate_rust;
use opc_yanggen::{
    CanonicalInput, CompareOp, ConstraintBinding, ConstraintExpr, GenerationInput, Literal,
    PathAnchor, PathExpr, SchemaModule, SchemaNode, SchemaNodeKind, StackBudget, TypeRef,
    YangSourceLocation,
};
use std::fs;
use std::process::Command;
use tempfile::tempdir;

fn create_test_input() -> CanonicalInput {
    let source = YangSourceLocation::new("test.yang", 1, 1);
    let nodes = vec![
        SchemaNode {
            path: "/test:system".to_string(),
            module: "test".to_string(),
            kind: SchemaNodeKind::Container,
            config: true,
            type_ref: None,
            key_leaves: vec![],
            child_paths: vec![
                "/test:system/enabled".to_string(),
                "/test:system/secret-key".to_string(),
            ],
            source: source.clone(),
            ..Default::default()
        },
        SchemaNode {
            path: "/test:system/enabled".to_string(),
            module: "test".to_string(),
            kind: SchemaNodeKind::Leaf,
            config: true,
            type_ref: Some(TypeRef::Boolean),
            key_leaves: vec![],
            child_paths: vec![],
            source: source.clone(),
            ..Default::default()
        },
        SchemaNode {
            path: "/test:system/secret-key".to_string(),
            module: "test".to_string(),
            kind: SchemaNodeKind::Leaf,
            config: true,
            type_ref: Some(TypeRef::String),
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
            name: "test".to_string(),
            revision: "2026-06-01".to_string(),
            namespace: "urn:opc:test".to_string(),
            prefix: "test".to_string(),
            source: source.clone(),
        }],
        nodes: nodes.clone(),
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
fn test_generated_code_features() {
    let mut input = create_test_input();
    input.constraints.push(ConstraintBinding {
        target_path: "/test:system".to_string(),
        expr: ConstraintExpr::Compare {
            op: CompareOp::Eq,
            left: Box::new(ConstraintExpr::Path(PathExpr {
                anchor: PathAnchor::Current,
                segments: vec!["enabled".to_string()],
            })),
            right: Box::new(ConstraintExpr::Literal(Literal::Bool(true))),
        },
        source: YangSourceLocation::new("test.yang", 20, 5),
        kind: None,
    });
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

    // We add a tests folder to the generated package to run tests on the generated code
    let tests_dir = dir.path().join("tests");
    fs::create_dir(&tests_dir).unwrap();

    let test_rs = r#"
    use generated_test::types::{System, SecretLeaf, LeafPresence};
    use opc_config_model::OpcConfig;
    use serde_json::json;
    
    // @req REQ-IETF-RFC7951-V1-4.2-042
    #[test]
    fn test_rfc7951_serde() {
        let sys = System {
            enabled: LeafPresence::Explicit(true),
            secret_key: SecretLeaf::new(LeafPresence::Explicit("supersecret".to_string())),
        };
        // Verify JSON representation
        let serialized = serde_json::to_value(&sys).unwrap();
        assert_eq!(serialized, json!({
            "test:enabled": true,
            "test:secret-key": "supersecret"
        }));
        
        let deserialized: System = serde_json::from_value(serialized).unwrap();
        assert_eq!(deserialized.enabled, LeafPresence::Explicit(true));
        assert_eq!(deserialized.secret_key.into_inner().into_option().unwrap(), "supersecret");
    }
    
    #[test]
    fn test_secret_leaf_redaction() {
        let sec = SecretLeaf::new(LeafPresence::Explicit("supersecret".to_string()));
        let dbg = format!("{:?}", sec);
        assert_eq!(dbg, "<REDACTED>");
        assert!(!dbg.contains("supersecret"));
    }
    
    #[test]
    fn test_patch_applicator() {
        let mut sys = System::default();
        let deltas = vec![
            generated_test::patch::ConfigDelta::Update(
                opc_config_model::YangPath::new("/test:system/enabled").unwrap(),
                "true".to_string()
            )
        ];
        
        let res = generated_test::patch::apply_patch(&mut sys, &deltas);
        assert!(res.is_ok());
        assert_eq!(sys.enabled, LeafPresence::Explicit(true));
        
        // Invalid path test
        let invalid_deltas = vec![
            generated_test::patch::ConfigDelta::Update(
                opc_config_model::YangPath::new("/test:system/invalid_path").unwrap(),
                "true".to_string()
            )
        ];
        let res_invalid = generated_test::patch::apply_patch(&mut sys, &invalid_deltas);
        assert!(res_invalid.is_err());
    }

    #[test]
    fn test_bounded_iterative_validation() {
        let tenant = opc_types::TenantId::new("tenant-a").unwrap();
        let principal = opc_config_model::TrustedPrincipal::new(
            opc_config_model::WorkloadIdentity::Internal("test".into()),
            tenant,
        );
        let sys = System {
            enabled: LeafPresence::Explicit(true),
            ..Default::default()
        };
        let ctx = opc_config_model::ValidationContext {
            request_id: opc_config_model::RequestId::new(),
            principal,
            transport: opc_config_model::TransportType::Internal,
            source: opc_config_model::RequestSource::Northbound,
            operation: opc_config_model::ConfigOperation::Replace,
            mode: opc_config_model::CommitMode::Commit,
            base_version: opc_types::ConfigVersion::INITIAL,
            previous: None,
        };
        let res = sys.validate_semantics(&ctx);
        assert!(res.is_ok());

        let invalid = System::default();
        let res_invalid = invalid.validate_semantics(&ctx);
        assert!(res_invalid.is_err());
    }
    "#;
    fs::write(tests_dir.join("generated_test.rs"), test_rs).unwrap();

    let cargo_toml = format!(
        r#"
[package]
name = "generated-test"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = {{ version = "1.0", features = ["derive"] }}
serde_json = "1.0"
opc-config-model = {{ path = "{}" }}
opc-types = {{ path = "{}" }}
opc-data-governance = {{ path = "{}" }}
"#,
        workspace_dir.join("crates/opc-config-model").display(),
        workspace_dir.join("crates/opc-types").display(),
        workspace_dir.join("crates/opc-data-governance").display()
    );

    fs::write(dir.path().join("Cargo.toml"), cargo_toml).unwrap();

    // Run tests in the generated crate
    let status = Command::new("cargo")
        .arg("test")
        .env("RUSTFLAGS", "-Dwarnings")
        .current_dir(dir.path())
        .status()
        .unwrap();

    assert!(status.success());
}

#[test]
fn test_rust_generation_rejects_unsupported_constraints() {
    let mut input = create_test_input();
    input.constraints.push(ConstraintBinding {
        target_path: "/test:system/enabled".to_string(),
        expr: ConstraintExpr::Function(opc_yanggen::ir::FunctionCall {
            name: opc_yanggen::ir::FunctionName::StartsWith,
            args: vec![],
        }),
        source: YangSourceLocation::new("test.yang", 20, 5),
        kind: None,
    });

    let err = generate_rust(&input).unwrap_err();
    assert!(err.message().contains("must/when constraints"));
}

#[test]
fn test_rust_generation_rejects_missing_children() {
    let mut input = create_test_input();
    input.nodes[0]
        .child_paths
        .push("/test:system/missing".to_string());

    let err = generate_rust(&input).unwrap_err();
    assert!(err.message().contains("references missing child"));
}
