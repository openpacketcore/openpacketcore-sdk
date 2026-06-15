mod common;

use opc_yanggen::rust::generate_rust;
use opc_yanggen::{
    BooleanOp, CanonicalInput, CompareOp, ConstraintBinding, ConstraintExpr, GenerationInput,
    Literal, PathAnchor, PathExpr, SchemaModule, SchemaNode, SchemaNodeKind, StackBudget, TypeRef,
    YangSourceLocation,
};
use std::fs;
use std::process::Command;
use tempfile::tempdir;

fn create_proof_input() -> CanonicalInput {
    let source = YangSourceLocation::new("proof.yang", 1, 1);
    let nodes = vec![
        // 1. Root Container
        SchemaNode {
            path: "/proof:system".to_string(),
            module: "proof".to_string(),
            kind: SchemaNodeKind::Container,
            config: true,
            type_ref: None,
            key_leaves: vec![],
            child_paths: vec![
                "/proof:system/proof:enabled".to_string(),
                "/proof:system/proof:presence-container".to_string(),
                "/proof:system/proof:nested-container".to_string(),
                "/proof:system/proof:config-leaf".to_string(),
                "/proof:system/proof:state-leaf".to_string(),
                "/proof:system/proof:default-leaf".to_string(),
                "/proof:system/proof:empty-leaf".to_string(),
                "/proof:system/proof:decimal-leaf".to_string(),
                "/proof:system/proof:port-range".to_string(),
                "/proof:system/proof:algo-type".to_string(),
                "/proof:system/proof:interfaces".to_string(),
                "/proof:system/proof:subscribers".to_string(),
                "/proof:system/proof:dns-servers".to_string(),
                "/proof:system/proof:admin-password".to_string(),
                "/proof:system/proof:default-interface".to_string(),
                "/proof:system/other-module:external-leaf".to_string(),
            ],
            source: source.clone(),
            ..Default::default()
        },
        // 2. Boolean Enabled
        SchemaNode {
            path: "/proof:system/proof:enabled".to_string(),
            module: "proof".to_string(),
            kind: SchemaNodeKind::Leaf,
            config: true,
            type_ref: Some(TypeRef::Boolean),
            source: source.clone(),
            ..Default::default()
        },
        // 3. Presence Container
        SchemaNode {
            path: "/proof:system/proof:presence-container".to_string(),
            module: "proof".to_string(),
            kind: SchemaNodeKind::Container,
            config: true,
            presence: Some("presence description".to_string()),
            child_paths: vec![
                "/proof:system/proof:presence-container/proof:leaf-in-presence".to_string(),
                "/proof:system/proof:presence-container/other-module:nested-external-leaf"
                    .to_string(),
            ],
            source: source.clone(),
            ..Default::default()
        },
        // 4. Leaf In Presence
        SchemaNode {
            path: "/proof:system/proof:presence-container/proof:leaf-in-presence".to_string(),
            module: "proof".to_string(),
            kind: SchemaNodeKind::Leaf,
            config: true,
            type_ref: Some(TypeRef::String),
            source: source.clone(),
            ..Default::default()
        },
        // 5. Nested Container
        SchemaNode {
            path: "/proof:system/proof:nested-container".to_string(),
            module: "proof".to_string(),
            kind: SchemaNodeKind::Container,
            config: true,
            child_paths: vec!["/proof:system/proof:nested-container/proof:inner-leaf".to_string()],
            source: source.clone(),
            ..Default::default()
        },
        // 6. Child of Nested Container
        SchemaNode {
            path: "/proof:system/proof:nested-container/proof:inner-leaf".to_string(),
            module: "proof".to_string(),
            kind: SchemaNodeKind::Leaf,
            config: true,
            type_ref: Some(TypeRef::String),
            source: source.clone(),
            ..Default::default()
        },
        // 7. Config Leaf
        SchemaNode {
            path: "/proof:system/proof:config-leaf".to_string(),
            module: "proof".to_string(),
            kind: SchemaNodeKind::Leaf,
            config: true,
            type_ref: Some(TypeRef::Uint32),
            source: source.clone(),
            ..Default::default()
        },
        // 8. State Leaf (config false)
        SchemaNode {
            path: "/proof:system/proof:state-leaf".to_string(),
            module: "proof".to_string(),
            kind: SchemaNodeKind::Leaf,
            config: false,
            type_ref: Some(TypeRef::Uint32),
            source: source.clone(),
            ..Default::default()
        },
        // 9. Default Leaf
        SchemaNode {
            path: "/proof:system/proof:default-leaf".to_string(),
            module: "proof".to_string(),
            kind: SchemaNodeKind::Leaf,
            config: true,
            type_ref: Some(TypeRef::Uint16),
            default: Some("42".to_string()),
            source: source.clone(),
            ..Default::default()
        },
        // 10. Empty Leaf
        SchemaNode {
            path: "/proof:system/proof:empty-leaf".to_string(),
            module: "proof".to_string(),
            kind: SchemaNodeKind::Leaf,
            config: true,
            type_ref: Some(TypeRef::Empty),
            source: source.clone(),
            ..Default::default()
        },
        // 11. Decimal Leaf
        SchemaNode {
            path: "/proof:system/proof:decimal-leaf".to_string(),
            module: "proof".to_string(),
            kind: SchemaNodeKind::Leaf,
            config: true,
            type_ref: Some(TypeRef::Decimal64),
            source: source.clone(),
            ..Default::default()
        },
        // 12. Port Range Leaf
        SchemaNode {
            path: "/proof:system/proof:port-range".to_string(),
            module: "proof".to_string(),
            kind: SchemaNodeKind::Leaf,
            config: true,
            type_ref: Some(TypeRef::Uint16),
            source: source.clone(),
            ..Default::default()
        },
        // 13. Identity Ref Leaf
        SchemaNode {
            path: "/proof:system/proof:algo-type".to_string(),
            module: "proof".to_string(),
            kind: SchemaNodeKind::Leaf,
            config: true,
            type_ref: Some(TypeRef::IdentityRef {
                base: "proof:cryptography".to_string(),
            }),
            source: source.clone(),
            ..Default::default()
        },
        // 14. Interfaces Container (List Parent)
        SchemaNode {
            path: "/proof:system/proof:interfaces".to_string(),
            module: "proof".to_string(),
            kind: SchemaNodeKind::Container,
            config: true,
            child_paths: vec!["/proof:system/proof:interfaces/proof:interface".to_string()],
            source: source.clone(),
            ..Default::default()
        },
        // 15. Single-Key List
        SchemaNode {
            path: "/proof:system/proof:interfaces/proof:interface".to_string(),
            module: "proof".to_string(),
            kind: SchemaNodeKind::List,
            config: true,
            key_leaves: vec!["name".to_string()],
            child_paths: vec![
                "/proof:system/proof:interfaces/proof:interface/proof:name".to_string(),
                "/proof:system/proof:interfaces/proof:interface/proof:mac-address".to_string(),
                "/proof:system/proof:interfaces/proof:interface/proof:enabled".to_string(),
            ],
            unique_constraints: vec![vec!["mac-address".to_string()]],
            source: source.clone(),
            ..Default::default()
        },
        // 16. List key leaf
        SchemaNode {
            path: "/proof:system/proof:interfaces/proof:interface/proof:name".to_string(),
            module: "proof".to_string(),
            kind: SchemaNodeKind::Leaf,
            config: true,
            type_ref: Some(TypeRef::String),
            source: source.clone(),
            ..Default::default()
        },
        // 17. List unique constraint leaf
        SchemaNode {
            path: "/proof:system/proof:interfaces/proof:interface/proof:mac-address".to_string(),
            module: "proof".to_string(),
            kind: SchemaNodeKind::Leaf,
            config: true,
            type_ref: Some(TypeRef::String),
            source: source.clone(),
            ..Default::default()
        },
        // 17b. List enabled leaf
        SchemaNode {
            path: "/proof:system/proof:interfaces/proof:interface/proof:enabled".to_string(),
            module: "proof".to_string(),
            kind: SchemaNodeKind::Leaf,
            config: true,
            type_ref: Some(TypeRef::Boolean),
            source: source.clone(),
            ..Default::default()
        },
        // 18. Subscribers Container (List Parent)
        SchemaNode {
            path: "/proof:system/proof:subscribers".to_string(),
            module: "proof".to_string(),
            kind: SchemaNodeKind::Container,
            config: true,
            child_paths: vec!["/proof:system/proof:subscribers/proof:subscriber".to_string()],
            source: source.clone(),
            ..Default::default()
        },
        // 19. Multi-Key List
        SchemaNode {
            path: "/proof:system/proof:subscribers/proof:subscriber".to_string(),
            module: "proof".to_string(),
            kind: SchemaNodeKind::List,
            config: true,
            key_leaves: vec!["imsi".to_string(), "plmn-id".to_string()],
            child_paths: vec![
                "/proof:system/proof:subscribers/proof:subscriber/proof:imsi".to_string(),
                "/proof:system/proof:subscribers/proof:subscriber/proof:plmn-id".to_string(),
            ],
            source: source.clone(),
            ..Default::default()
        },
        // 20. Subscriber Key 1 (Explicit data_class "subscriber-id")
        SchemaNode {
            path: "/proof:system/proof:subscribers/proof:subscriber/proof:imsi".to_string(),
            module: "proof".to_string(),
            kind: SchemaNodeKind::Leaf,
            config: true,
            type_ref: Some(TypeRef::String),
            data_class: Some("subscriber-id".to_string()),
            source: source.clone(),
            ..Default::default()
        },
        // 21. Subscriber Key 2
        SchemaNode {
            path: "/proof:system/proof:subscribers/proof:subscriber/proof:plmn-id".to_string(),
            module: "proof".to_string(),
            kind: SchemaNodeKind::Leaf,
            config: true,
            type_ref: Some(TypeRef::String),
            source: source.clone(),
            ..Default::default()
        },
        // 22. Leaf-list
        SchemaNode {
            path: "/proof:system/proof:dns-servers".to_string(),
            module: "proof".to_string(),
            kind: SchemaNodeKind::LeafList,
            config: true,
            type_ref: Some(TypeRef::String),
            source: source.clone(),
            ..Default::default()
        },
        // 23. Admin Password (Explicit data_class "security-secret")
        SchemaNode {
            path: "/proof:system/proof:admin-password".to_string(),
            module: "proof".to_string(),
            kind: SchemaNodeKind::Leaf,
            config: true,
            type_ref: Some(TypeRef::String),
            data_class: Some("security-secret".to_string()),
            source: source.clone(),
            ..Default::default()
        },
        // 24. Default Interface (LeafRef pointing to /proof:system/proof:interfaces/proof:interface/proof:name)
        SchemaNode {
            path: "/proof:system/proof:default-interface".to_string(),
            module: "proof".to_string(),
            kind: SchemaNodeKind::Leaf,
            config: true,
            type_ref: Some(TypeRef::LeafRef {
                target_path: "/proof:system/proof:interfaces/proof:interface/proof:name"
                    .to_string(),
            }),
            source: source.clone(),
            ..Default::default()
        },
        // 25. External Leaf from other module
        SchemaNode {
            path: "/proof:system/other-module:external-leaf".to_string(),
            module: "other-module".to_string(),
            kind: SchemaNodeKind::Leaf,
            config: true,
            type_ref: Some(TypeRef::String),
            source: source.clone(),
            ..Default::default()
        },
        // 26. Nested External Leaf from other module
        SchemaNode {
            path: "/proof:system/proof:presence-container/other-module:nested-external-leaf"
                .to_string(),
            module: "other-module".to_string(),
            kind: SchemaNodeKind::Leaf,
            config: true,
            type_ref: Some(TypeRef::String),
            source: source.clone(),
            ..Default::default()
        },
    ];

    let constraints = vec![
        // when constraint: presence-container is valid when /proof:system/proof:enabled is true
        ConstraintBinding {
            target_path: "/proof:system/proof:presence-container".to_string(),
            expr: ConstraintExpr::Compare {
                op: CompareOp::Eq,
                left: Box::new(ConstraintExpr::Path(PathExpr {
                    anchor: PathAnchor::Parent,
                    segments: vec!["enabled".to_string()],
                })),
                right: Box::new(ConstraintExpr::Literal(Literal::Bool(true))),
            },
            source: source.clone(),
            kind: Some("when".to_string()),
        },
        // must constraint: port-range must be 1024..65535
        ConstraintBinding {
            target_path: "/proof:system/proof:port-range".to_string(),
            expr: ConstraintExpr::Boolean {
                op: BooleanOp::And,
                terms: vec![
                    ConstraintExpr::Compare {
                        op: CompareOp::Gte,
                        left: Box::new(ConstraintExpr::Path(PathExpr {
                            anchor: PathAnchor::Current,
                            segments: vec![],
                        })),
                        right: Box::new(ConstraintExpr::Literal(Literal::Number(1024))),
                    },
                    ConstraintExpr::Compare {
                        op: CompareOp::Lte,
                        left: Box::new(ConstraintExpr::Path(PathExpr {
                            anchor: PathAnchor::Current,
                            segments: vec![],
                        })),
                        right: Box::new(ConstraintExpr::Literal(Literal::Number(65535))),
                    },
                ],
            },
            source: source.clone(),
            kind: Some("must".to_string()),
        },
    ];

    let input = GenerationInput {
        profile: "proof".to_string(),
        lockfile: opc_yanggen::ir::ModuleLockfile {
            profile: "proof".to_string(),
            modules: vec![],
        },
        schema_modules: vec![
            SchemaModule {
                name: "proof".to_string(),
                revision: "2026-06-08".to_string(),
                namespace: "urn:opc:proof".to_string(),
                prefix: "proof".to_string(),
                source: source.clone(),
                ..Default::default()
            },
            SchemaModule {
                name: "other-module".to_string(),
                revision: "2026-06-08".to_string(),
                namespace: "urn:opc:other-module".to_string(),
                prefix: "other-module".to_string(),
                source: source.clone(),
                ..Default::default()
            },
        ],
        nodes,
        constraints,
        unsupported_features: vec![],
        stack_budget: StackBudget::default(),
        stack_shapes: vec![],
    };

    let ir = opc_yanggen::compile(&input).unwrap();
    CanonicalInput {
        profile: opc_yanggen::emit::CanonicalProfile {
            generation: "proof".to_string(),
            lockfile_mismatch: None,
        },
        locked_modules: vec![],
        schema_modules: ir.modules,
        nodes: ir.nodes,
        constraints: ir.constraints,
        stack_shapes: ir.stack_shapes,
        stack_budget: ir.stack_budget,
        canonicalization_skipped: false,
        max_canonical_scan_stack_len: None,
    }
}

#[test]
fn test_production_proof_codegen() {
    let input = create_proof_input();
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

    let tests_dir = dir.path().join("tests");
    fs::create_dir(&tests_dir).unwrap();

    let test_rs = r#"
    use generated_test::types::{
        System, SecretLeaf, LeafPresence, YangDecimal64, YangEmpty, SubscriberKey,
    };
    use generated_test::redaction::Redactable;
    use generated_test::metadata::{get_data_classes, get_data_class_for_path};
    use generated_test::patch::{apply_patch, ConfigDelta};
    use opc_config_model::{OpcConfig, YangPath, ValidationContext, ConfigError};
    use opc_data_governance::DataClass;
    use serde_json::json;
    
    fn create_ctx() -> ValidationContext<System> {
        let tenant = opc_types::TenantId::new("tenant-a").unwrap();
        let principal = opc_config_model::TrustedPrincipal::new(
            opc_config_model::WorkloadIdentity::Internal("test".into()),
            tenant,
        );
        ValidationContext {
            request_id: opc_config_model::RequestId::new(),
            principal,
            transport: opc_config_model::TransportType::Internal,
            source: opc_config_model::RequestSource::Northbound,
            operation: opc_config_model::ConfigOperation::Replace,
            mode: opc_config_model::CommitMode::Commit,
            base_version: opc_types::ConfigVersion::INITIAL,
            previous: None,
        }
    }

    #[test]
    fn test_rfc7951_serialization() {
        let mut sys = System::default();
        sys.enabled = LeafPresence::Explicit(true);
        sys.empty_leaf = LeafPresence::Explicit(YangEmpty);
        sys.decimal_leaf = LeafPresence::Explicit(YangDecimal64(3.14));
        sys.default_leaf = LeafPresence::Explicit(42);

        // Verify top-level is qualified and nested containers/lists are unqualified
        let serialized = serde_json::to_value(&sys).unwrap();
        
        // Under RFC 7951 conditional namespace:
        // Top-level children of the root container (enabled, empty-leaf, etc.) are qualified.
        assert_eq!(serialized.get("proof:enabled").unwrap(), &json!(true));
        assert_eq!(serialized.get("proof:empty-leaf").unwrap(), &json!([null]));
        assert_eq!(serialized.get("proof:decimal-leaf").unwrap(), &json!("3.14"));

        // Let's test deserialization using both qualified and unqualified aliases
        let de_json = json!({
            "enabled": true,
            "proof:empty-leaf": [null],
            "decimal-leaf": "3.14"
        });
        let de_sys: System = serde_json::from_value(de_json).unwrap();
        assert_eq!(de_sys.enabled, LeafPresence::Explicit(true));
        assert_eq!(de_sys.empty_leaf, LeafPresence::Explicit(YangEmpty));
        assert_eq!(de_sys.decimal_leaf, LeafPresence::Explicit(YangDecimal64(3.14)));
    }

    #[test]
    fn test_patch_rejection_of_readonly_paths() {
        let mut sys = System::default();
        let deltas = vec![
            ConfigDelta::Update(YangPath::new("/proof:system/state-leaf").unwrap(), "10".to_string())
        ];
        let res = apply_patch(&mut sys, &deltas);
        assert!(res.is_err());
        match res.unwrap_err() {
            ConfigError { .. } => {} // matches ConfigError
        }
    }

    #[test]
    fn test_patch_fail_closed_on_invalid_paths() {
        let mut sys = System::default();
        let deltas = vec![
            ConfigDelta::Update(YangPath::new("/proof:system/enabled").unwrap(), "true".to_string()),
            ConfigDelta::Update(YangPath::new("/proof:system/invalid-path-here").unwrap(), "42".to_string()),
        ];
        // If we fail-closed, "enabled" must NOT remain mutated to true!
        let res = apply_patch(&mut sys, &deltas);
        assert!(res.is_err());
        assert_eq!(sys.enabled, LeafPresence::Absent);
    }

    #[test]
    fn test_patch_merge_and_remove_ops() {
        let mut sys = System::default();
        
        // Test Merge
        let deltas = vec![
            ConfigDelta::Update(YangPath::new("/proof:system/enabled").unwrap(), "true".to_string()),
            ConfigDelta::Merge(YangPath::new("/proof:system/nested-container").unwrap(), json!({
                "inner-leaf": "hello"
            }).to_string()),
        ];
        assert!(apply_patch(&mut sys, &deltas).is_ok());
        assert_eq!(sys.enabled, LeafPresence::Explicit(true));
        assert_eq!(sys.nested_container.as_ref().unwrap().inner_leaf, LeafPresence::Explicit("hello".to_string()));

        // Test Remove (silent fail-safe on non-existent list entries)
        let remove_deltas = vec![
            ConfigDelta::Remove(YangPath::new("/proof:system/interfaces/interface[name='non-existent']").unwrap())
        ];
        assert!(apply_patch(&mut sys, &remove_deltas).is_ok());
    }

    #[test]
    fn test_patch_key_mismatch_prevention() {
        let mut sys = System::default();
        // Path says eth0, body says eth1. Must be forced to match the path (eth0) or fail.
        let deltas = vec![
            ConfigDelta::Update(
                YangPath::new("/proof:system/interfaces/interface[name='eth0']").unwrap(),
                json!({
                    "name": "eth1",
                    "mac-address": "aa:bb:cc"
                }).to_string()
            )
        ];
        assert!(apply_patch(&mut sys, &deltas).is_ok());
        let entry = sys.interfaces.as_ref().unwrap().interface.get("eth0").unwrap();
        // Key is forced to be eth0
        assert_eq!(entry.name, LeafPresence::Explicit("eth0".to_string()));
    }

    #[test]
    fn test_unique_constraints_skip_absent() {
        let ctx = create_ctx();
        let mut sys = System::default();
        
        // Two interfaces without MAC address (mac-address is Absent)
        // This must NOT fail uniqueness check since absent unique fields are skipped!
        let deltas = vec![
            ConfigDelta::Update(YangPath::new("/proof:system/interfaces/interface[name='eth0']").unwrap(), json!({}).to_string()),
            ConfigDelta::Update(YangPath::new("/proof:system/interfaces/interface[name='eth1']").unwrap(), json!({}).to_string()),
        ];
        assert!(apply_patch(&mut sys, &deltas).is_ok());
        if let Err(e) = sys.validate_semantics(&ctx) {
            panic!("Expected validation to succeed, but got error: {:?}", e);
        }

        // Now set duplicate MAC addresses, this MUST fail!
        let duplicate_deltas = vec![
            ConfigDelta::Update(YangPath::new("/proof:system/interfaces/interface[name='eth0']/mac-address").unwrap(), "aa:bb".to_string()),
            ConfigDelta::Update(YangPath::new("/proof:system/interfaces/interface[name='eth1']/mac-address").unwrap(), "aa:bb".to_string()),
        ];
        assert!(apply_patch(&mut sys, &duplicate_deltas).is_ok());
        assert!(sys.validate_semantics(&ctx).is_err());
    }

    #[test]
    fn test_when_constraint_validation() {
        let ctx = create_ctx();
        let mut sys = System::default();
        
        // enabled is false (Absent)
        // Setting presence-container must fail validation because enabled is false!
        let deltas = vec![
            ConfigDelta::Update(YangPath::new("/proof:system/presence-container").unwrap(), json!({
                "leaf-in-presence": "value"
            }).to_string())
        ];
        assert!(apply_patch(&mut sys, &deltas).is_ok());
        assert!(sys.validate_semantics(&ctx).is_err());

        // Now enable the system, validation should succeed!
        let enable_deltas = vec![
            ConfigDelta::Update(YangPath::new("/proof:system/enabled").unwrap(), "true".to_string())
        ];
        assert!(apply_patch(&mut sys, &enable_deltas).is_ok());
        if let Err(e) = sys.validate_semantics(&ctx) {
            panic!("Expected validation to succeed when enabled is true, but got error: {:?}", e);
        }
    }

    #[test]
    fn test_must_range_validation() {
        let ctx = create_ctx();
        let mut sys = System::default();
        
        // Out of range (99)
        let deltas = vec![
            ConfigDelta::Update(YangPath::new("/proof:system/port-range").unwrap(), "99".to_string())
        ];
        assert!(apply_patch(&mut sys, &deltas).is_ok());
        assert!(sys.validate_semantics(&ctx).is_err());

        // In range (2026)
        let ok_deltas = vec![
            ConfigDelta::Update(YangPath::new("/proof:system/port-range").unwrap(), "2026".to_string())
        ];
        assert!(apply_patch(&mut sys, &ok_deltas).is_ok());
        assert!(sys.validate_semantics(&ctx).is_ok());
    }

    #[test]
    fn test_leafref_o_n_log_n_validation() {
        let ctx = create_ctx();
        let mut sys = System::default();
        
        // Point to non-existent interface
        let deltas = vec![
            ConfigDelta::Update(YangPath::new("/proof:system/default-interface").unwrap(), "eth0".to_string())
        ];
        assert!(apply_patch(&mut sys, &deltas).is_ok());
        assert!(sys.validate_semantics(&ctx).is_err());

        // Now add the interface, should succeed!
        let add_interface = vec![
            ConfigDelta::Update(YangPath::new("/proof:system/interfaces/interface[name='eth0']").unwrap(), json!({}).to_string())
        ];
        assert!(apply_patch(&mut sys, &add_interface).is_ok());
        if let Err(e) = sys.validate_semantics(&ctx) {
            panic!("Expected validation to succeed after adding target interface, but got error: {:?}", e);
        }
    }

    #[test]
    fn test_data_class_metadata_resolver() {
        let classes = get_data_classes();
        let secret_path = YangPath::new("/proof:system/proof:admin-password").unwrap();
        assert_eq!(classes.get(&secret_path).cloned(), Some(DataClass::SecuritySecret));

        // Instance path mapping:
        let instance_path = YangPath::new("/proof:system/proof:subscribers/proof:subscriber[proof:imsi='123'][proof:plmn-id='456']/proof:imsi").unwrap();
        assert_eq!(get_data_class_for_path(&instance_path), Some(DataClass::SubscriberId));
    }

    #[test]
    fn test_recursive_redaction() {
        let mut sys = System::default();
        
        // Set sensitive fields
        sys.admin_password = SecretLeaf::new(LeafPresence::Explicit("secret123".to_string()));
        
        let mut sub = generated_test::types::Subscriber::default();
        sub.imsi = SecretLeaf::new(LeafPresence::Explicit("12345".to_string()));
        let mut subs = generated_test::types::Subscribers::default();
        subs.subscriber.insert(SubscriberKey { imsi: "12345".to_string(), plmn_id: "456".to_string() }, sub);
        sys.subscribers = Some(subs);

        // Run redact
        sys.redact_sensitive();

        // Fields must be set to Absent
        assert_eq!(sys.admin_password.get(), &LeafPresence::Absent);
        
        // Key is hashed and matches inner item
        let (redacted_key, redacted_sub) = sys.subscribers.as_ref().unwrap().subscriber.iter().next().unwrap();
        assert_ne!(redacted_key.imsi, "");
        assert_ne!(redacted_key.imsi, "12345");
        assert_eq!(redacted_key.imsi, redacted_sub.imsi.get().as_option().cloned().unwrap());
    }

    #[test]
    fn test_multiple_subscribers_redaction_does_not_collapse() {
        let mut sys = System::default();
        
        let mut sub1 = generated_test::types::Subscriber::default();
        sub1.imsi = SecretLeaf::new(LeafPresence::Explicit("11111".to_string()));
        let mut sub2 = generated_test::types::Subscriber::default();
        sub2.imsi = SecretLeaf::new(LeafPresence::Explicit("22222".to_string()));
        
        let mut subs = generated_test::types::Subscribers::default();
        subs.subscriber.insert(SubscriberKey { imsi: "11111".to_string(), plmn_id: "456".to_string() }, sub1);
        subs.subscriber.insert(SubscriberKey { imsi: "22222".to_string(), plmn_id: "456".to_string() }, sub2);
        sys.subscribers = Some(subs);

        sys.redact_sensitive();

        // Check that there are still 2 entries in the map
        let subscriber_map = &sys.subscribers.as_ref().unwrap().subscriber;
        assert_eq!(subscriber_map.len(), 2);

        // Verify that keys are hashed and match the inner field
        for (k, val) in subscriber_map {
            assert_ne!(k.imsi, "11111");
            assert_ne!(k.imsi, "22222");
            assert_eq!(k.imsi, val.imsi.get().as_option().cloned().unwrap());
        }
    }

    #[test]
    fn test_parsing_brackets_in_quotes() {
        use generated_test::patch::parse_path;
        let path_str = "/proof:system/proof:interfaces/proof:interface[proof:name='eth[0]']/proof:enabled";
        let parsed = parse_path(path_str).expect("Should successfully parse bracket inside quotes");
        
        assert_eq!(parsed.len(), 4);
        assert_eq!(parsed[0].name, "proof:system");
        assert_eq!(parsed[1].name, "proof:interfaces");
        assert_eq!(parsed[2].name, "proof:interface");
        assert_eq!(parsed[2].keys.get("name").map(|s| s.as_str()), Some("eth[0]"));
        assert_eq!(parsed[3].name, "proof:enabled");
    }

    #[test]
    fn test_rfc7951_serialization_adversarial() {
        use serde_json::json;
        
        // 1. Floating-point precision edge cases
        let mut sys = System::default();
        let subnormal = 1e-40f64;
        let large_float = 1e300f64;
        
        sys.decimal_leaf = LeafPresence::Explicit(YangDecimal64(subnormal));
        let serialized = serde_json::to_value(&sys).unwrap();
        assert_eq!(serialized.get("proof:decimal-leaf").unwrap(), &json!(subnormal.to_string()));
        
        sys.decimal_leaf = LeafPresence::Explicit(YangDecimal64(large_float));
        let serialized = serde_json::to_value(&sys).unwrap();
        assert_eq!(serialized.get("proof:decimal-leaf").unwrap(), &json!(large_float.to_string()));
        
        // Test extra float edge cases: NaN, Infinity, -Infinity, -0.0
        let edge_cases = vec![
            f64::INFINITY,
            f64::NEG_INFINITY,
            -0.0,
        ];
        for val in edge_cases {
            sys.decimal_leaf = LeafPresence::Explicit(YangDecimal64(val));
            let ser = serde_json::to_value(&sys).unwrap();
            let val_str = ser.get("proof:decimal-leaf").unwrap().as_str().unwrap();
            let parsed_val = val_str.parse::<f64>().unwrap();
            assert_eq!(val, parsed_val);
        }
        
        // Test NaN
        sys.decimal_leaf = LeafPresence::Explicit(YangDecimal64(f64::NAN));
        let ser = serde_json::to_value(&sys).unwrap();
        let val_str = ser.get("proof:decimal-leaf").unwrap().as_str().unwrap();
        assert!(val_str.parse::<f64>().unwrap().is_nan());
        
        // Let's test large numbers
        sys.config_leaf = LeafPresence::Explicit(u32::MAX);
        let serialized = serde_json::to_value(&sys).unwrap();
        assert_eq!(serialized.get("proof:config-leaf").unwrap(), &json!(u32::MAX));
        
        // Deep namespace qualification boundaries:
        // Top-level must be qualified, children not qualified
        let serialized = serde_json::to_value(&sys).unwrap();
        assert!(serialized.get("proof:config-leaf").is_some());
        assert!(serialized.get("config-leaf").is_none());

        // Cross-module deep namespace qualification validation
        sys.external_leaf = LeafPresence::Explicit("ext_val".to_string());
        let mut presence = generated_test::types::PresenceContainer::default();
        presence.leaf_in_presence = LeafPresence::Explicit("nested_val".to_string());
        presence.nested_external_leaf = LeafPresence::Explicit("nested_ext_val".to_string());
        sys.presence_container = Some(presence);

        let serialized = serde_json::to_value(&sys).unwrap();
        assert_eq!(serialized.get("other-module:external-leaf").unwrap(), &json!("ext_val"));
        
        let presence_json = serialized.get("proof:presence-container").unwrap();
        assert_eq!(presence_json.get("leaf-in-presence").unwrap(), &json!("nested_val"));
        assert_eq!(presence_json.get("other-module:nested-external-leaf").unwrap(), &json!("nested_ext_val"));

        // Verify deserialization works with cross-module names
        let de_json = json!({
            "other-module:external-leaf": "ext_val_de",
            "proof:presence-container": {
                "leaf-in-presence": "nested_val_de",
                "other-module:nested-external-leaf": "nested_ext_val_de"
            }
        });
        let de_sys: System = serde_json::from_value(de_json).unwrap();
        assert_eq!(de_sys.external_leaf, LeafPresence::Explicit("ext_val_de".to_string()));
        let de_presence = de_sys.presence_container.as_ref().unwrap();
        assert_eq!(de_presence.leaf_in_presence, LeafPresence::Explicit("nested_val_de".to_string()));
        assert_eq!(de_presence.nested_external_leaf, LeafPresence::Explicit("nested_ext_val_de".to_string()));
    }

    #[test]
    fn test_leafref_validation_complexity() {
        let ctx = create_ctx();
        let mut sys = System::default();
        
        // Add 2000 interfaces
        let mut deltas = Vec::new();
        for i in 0..2000 {
            let name = format!("eth{}", i);
            deltas.push(ConfigDelta::Update(
                YangPath::new(&format!("/proof:system/interfaces/interface[name='{}']", name)).unwrap(),
                json!({}).to_string(),
            ));
        }
        apply_patch(&mut sys, &deltas).unwrap();
        
        // Set default-interface to eth1999
        apply_patch(&mut sys, &[
            ConfigDelta::Update(YangPath::new("/proof:system/default-interface").unwrap(), "eth1999".to_string())
        ]).unwrap();
        
        let start = std::time::Instant::now();
        sys.validate_semantics(&ctx).unwrap();
        let duration = start.elapsed();
        println!("Validation took: {:?}", duration);
        assert!(duration < std::time::Duration::from_millis(150), "Validation took too long (potential cubic complexity): {:?}", duration);
    }

    #[test]
    fn test_btree_map_redaction_collision_and_sync() {
        let mut sys = System::default();
        let mut subs = generated_test::types::Subscribers::default();
        
        // 1000 subscribers to verify zero collision rate and key/val synchronization
        for i in 0..1000 {
            let imsi = format!("imsi_{:04}", i);
            let plmn = "456".to_string();
            let mut sub = generated_test::types::Subscriber::default();
            sub.imsi = SecretLeaf::new(LeafPresence::Explicit(imsi.clone()));
            subs.subscriber.insert(SubscriberKey { imsi, plmn_id: plmn }, sub);
        }
        sys.subscribers = Some(subs);
        
        sys.redact_sensitive();
        
        let redacted_map = &sys.subscribers.as_ref().unwrap().subscriber;
        assert_eq!(redacted_map.len(), 1000, "Entries were dropped due to collision!");
        
        for (k, val) in redacted_map {
            assert_ne!(k.imsi, "");
            assert_eq!(k.imsi, val.imsi.get().as_option().cloned().unwrap(), "Key and value IMSI are out of sync!");
        }
    }

    #[test]
    fn test_path_parser_robustness() {
        use generated_test::patch::parse_path;
        
        // Trailing slashes
        let p = parse_path("/proof:system/proof:interfaces/").unwrap();
        assert_eq!(p.len(), 2);
        assert_eq!(p[0].name, "proof:system");
        
        // Quoted brackets
        let p = parse_path("/proof:system/proof:interfaces/proof:interface[proof:name='eth[0]']/proof:enabled").unwrap();
        assert_eq!(p.len(), 4);
        assert_eq!(p[2].keys.get("name").map(|s| s.as_str()), Some("eth[0]"));
        // Escape characters: check if it parses or fails
        let path_esc = "/proof:system/proof:interfaces/proof:interface[proof:name='eth\\'0']/proof:enabled";
        let p = parse_path(path_esc).unwrap();
        assert_eq!(p.len(), 4);
        assert_eq!(p[2].keys.get("name").map(|s| s.as_str()), Some("eth'0"));

        let path_backslash =
            "/proof:system/proof:interfaces/proof:interface[proof:name='eth\\\\0']/proof:enabled";
        let p = parse_path(path_backslash).unwrap();
        assert_eq!(p[2].keys.get("name").map(|s| s.as_str()), Some("eth\\0"));

        let path_trailing_backslash =
            "/proof:system/proof:interfaces/proof:interface[proof:name='eth\\\\']/proof:enabled";
        let p = parse_path(path_trailing_backslash).unwrap();
        assert_eq!(p[2].keys.get("name").map(|s| s.as_str()), Some("eth\\"));

        // Additional adversarial inputs for safety and no-panic guarantee
        let adversarial = vec![
            "/proof:system/proof:interfaces/proof:interface[proof:name='eth[0][1][2]']/proof:enabled",
            "/proof:system/proof:interfaces/proof:interface[proof:name=eth[0][1][2]]/proof:enabled",
            "/proof:system/proof:interfaces/proof:interface[proof:name=\"eth\\\"0\"]/proof:enabled",
            "/",
            "///",
            "",
            "   ",
            "/proof:system/proof:interfaces/proof:interface[proof:name='eth0'",
            "/proof:system/proof:interfaces/proof:interface[proof:name=",
            "[a=b[c]]",
            "/[][][]",
        ];
        for path in adversarial {
            let _ = parse_path(path); // must not panic
        }
    }

    #[test]
    fn test_patch_path_with_quoted_brackets() {
        use opc_config_model::YangPath;
        use generated_test::patch::apply_patch;
        use generated_test::patch::ConfigDelta;
        
        let mut sys = System::default();
        let deltas = vec![
            ConfigDelta::Update(
                YangPath::new("/proof:system/interfaces/interface[name='eth[0]']").unwrap(),
                serde_json::json!({}).to_string()
            )
        ];
        
        let res = apply_patch(&mut sys, &deltas);
        assert!(res.is_ok());
    }

    #[test]
    fn test_is_valid_path_with_quoted_brackets() {
        use generated_test::paths::is_valid_path;
        let path = "/proof:system/proof:interfaces/proof:interface[proof:name='eth[0]']/proof:enabled";
        assert!(is_valid_path(path));
    }

    #[test]
    fn test_diff_root_escapes_key_values() {
        use generated_test::patch::{diff_root, ConfigDelta};
        use generated_test::types::{Interface, Interfaces, LeafPresence};

        let mut current = System::default();
        let mut interfaces = Interfaces::default();
        let mut interface = Interface::default();
        interface.enabled = LeafPresence::Explicit(true);
        interfaces.interface.insert("eth\\'0".to_string(), interface);
        current.interfaces = Some(interfaces);

        let deltas = diff_root(&current, &System::default()).unwrap();
        let paths: Vec<&str> = deltas
            .iter()
            .map(|delta| match delta {
                ConfigDelta::Update(path, _)
                | ConfigDelta::Replace(path, _)
                | ConfigDelta::Delete(path)
                | ConfigDelta::Merge(path, _)
                | ConfigDelta::Remove(path) => path.as_str(),
            })
            .collect();
        assert!(paths
            .iter()
            .any(|path| path.contains("interface[name='eth\\\\\\'0']")));
    }

    #[test]
    fn test_schema_registry_rich() {
        use generated_test::schema_registry::registry;
        // Methods are called on the `&dyn SchemaRegistry` trait object, which does
        // not require the trait itself to be in scope.
        use opc_config_model::OpcConfig;
        use opc_mgmt_schema::{DataClass, DefaultReport, LeafType, NacmAction, NodeKind};

        let reg = registry();

        // Two served modules (proof + other-module).
        let names: Vec<&str> = reg.served_models().iter().map(|m| m.name).collect();
        assert!(names.contains(&"proof"));
        assert!(names.contains(&"other-module"));

        // State (config=false) node: read-only NACM, leaf type preserved.
        assert!(!reg.is_config_path("/proof:system/proof:state-leaf"));
        assert_eq!(
            reg.nacm_actions("/proof:system/proof:state-leaf"),
            &[NacmAction::Read]
        );
        assert_eq!(
            reg.leaf_type("/proof:system/proof:state-leaf"),
            Some(LeafType::Uint32)
        );
        let typed_digest = System::default().schema_digest();
        assert_eq!(typed_digest.to_hex().len(), 64);
        assert_ne!(
            typed_digest.to_hex(),
            "0000000000000000000000000000000000000000000000000000000000000000"
        );

        // Config node: full datastore action set.
        let cfg = reg.nacm_actions("/proof:system/proof:config-leaf");
        assert!(cfg.contains(&NacmAction::Create) && cfg.contains(&NacmAction::Replace));

        // Default metadata drives with-defaults.
        assert_eq!(
            reg.leaf_type("/proof:system/proof:default-leaf"),
            Some(LeafType::Uint16)
        );
        assert_eq!(
            reg.default_for("/proof:system/proof:default-leaf", DefaultReport::ReportAll),
            Some("42")
        );
        assert_eq!(
            reg.default_for("/proof:system/proof:default-leaf", DefaultReport::Trim),
            None
        );

        // Single-key and multi-key lists preserve key order verbatim.
        assert_eq!(
            reg.key_leaves("/proof:system/proof:interfaces/proof:interface"),
            Some(&["name"][..])
        );
        assert_eq!(
            reg.key_leaves("/proof:system/proof:subscribers/proof:subscriber"),
            Some(&["imsi", "plmn-id"][..])
        );

        // Special leaf types round-trip through the registry.
        assert_eq!(
            reg.leaf_type("/proof:system/proof:empty-leaf"),
            Some(LeafType::Empty)
        );
        assert_eq!(
            reg.leaf_type("/proof:system/proof:decimal-leaf"),
            Some(LeafType::Decimal64)
        );
        assert!(matches!(
            reg.leaf_type("/proof:system/proof:algo-type"),
            Some(LeafType::IdentityRef { .. })
        ));
        assert!(matches!(
            reg.leaf_type("/proof:system/proof:default-interface"),
            Some(LeafType::LeafRef { .. })
        ));
        assert_eq!(
            reg.node("/proof:system/proof:dns-servers").map(|n| n.kind),
            Some(NodeKind::LeafList)
        );

        // Data classes MUST agree with the generated metadata resolver.
        for path in [
            "/proof:system/proof:admin-password",
            "/proof:system/proof:subscribers/proof:subscriber/proof:imsi",
        ] {
            let yp = opc_config_model::YangPath::new(path).unwrap();
            assert_eq!(
                reg.data_class(path),
                generated_test::metadata::get_data_class_for_path(&yp)
            );
        }
        assert_eq!(
            reg.data_class("/proof:system/proof:admin-password"),
            Some(DataClass::SecuritySecret)
        );
        assert_eq!(
            reg.data_class("/proof:system/proof:subscribers/proof:subscriber/proof:imsi"),
            Some(DataClass::SubscriberId)
        );

        // Origins: each served module, plus the default "" spanning all (sorted).
        assert_eq!(reg.modules_for_origin("proof"), Some(&["proof"][..]));
        assert_eq!(
            reg.modules_for_origin("other-module"),
            Some(&["other-module"][..])
        );
        assert_eq!(
            reg.modules_for_origin(""),
            Some(&["other-module", "proof"][..])
        );
        assert_eq!(reg.modules_for_origin("nope"), None);

        // A node from the other module still resolves.
        assert!(reg.is_valid_path("/proof:system/other-module:external-leaf"));
        assert!(!reg.is_valid_path("/proof:system/bogus:external-leaf"));
        assert!(!reg.is_valid_path(
            "/proof:system/proof:interfaces/proof:interface[bogus:name='eth0']/proof:enabled"
        ));
        assert!(!reg.is_valid_path(
            "/proof:system/proof:interfaces/proof:interface[proof:name='eth0'/proof:enabled"
        ));

        // Integrity holds on the full schema.
        assert_eq!(reg.self_check(), Ok(()));
    }
    "#;
    fs::write(tests_dir.join("production_proof_test.rs"), test_rs).unwrap();

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
opc-gnmi-server = {{ path = "{}" }}
opc-redaction = {{ path = "{}" }}
"#,
        common::locked_version(&workspace_dir, "time"),
        workspace_dir.join("crates/opc-config-model").display(),
        workspace_dir.join("crates/opc-types").display(),
        workspace_dir.join("crates/opc-data-governance").display(),
        workspace_dir.join("crates/opc-mgmt-schema").display(),
        workspace_dir.join("crates/opc-gnmi-server").display(),
        workspace_dir.join("crates/opc-redaction").display()
    );

    fs::write(dir.path().join("Cargo.toml"), cargo_toml).unwrap();

    // Run tests in the generated crate
    let output = Command::new("cargo")
        .arg("test")
        .env("RUSTFLAGS", "-Dwarnings")
        .current_dir(dir.path())
        .output()
        .unwrap();

    if !output.status.success() {
        println!(
            "=== GENERATED TEST STDOUT ===\n{}",
            String::from_utf8_lossy(&output.stdout)
        );
        println!(
            "=== GENERATED TEST STDERR ===\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    assert!(output.status.success());
}
