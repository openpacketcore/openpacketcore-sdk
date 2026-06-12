use opc_yanggen::{
    compile, emit_fixture, emit_stack_metadata, format_constraint_expr, lower_constraint,
    schema_digest, AllocationStrategy, BooleanOp, CompareOp, ConstraintBinding, ConstraintExpr,
    DiagnosticCode, FunctionCall, FunctionName, GenerationInput, Literal, LockedModule,
    ModuleImport, ModuleLockfile, PathAnchor, PathExpr, RawConstraintExpr, SchemaModule,
    SchemaNode, SchemaNodeKind, StackBudget, StackScope, StackShape, TypeRef, UnsupportedFeature,
    UnsupportedFeatureKind, YangSourceLocation, MAX_CONSTRAINT_EXPR_DEPTH,
};

fn create_base_input() -> GenerationInput {
    let import1 = ModuleImport {
        name: "ietf-yang-types".to_string(),
        revision: "2023-01-01".to_string(),
    };
    let locked1 = LockedModule {
        name: "ietf-interfaces".to_string(),
        revision: "2026-05-19".to_string(),
        namespace: "urn:ietf:params:xml:ns:yang:ietf-interfaces".to_string(),
        checksum: "sha256:abc1234567890abcdef".to_string(),
        imports: vec![import1],
    };
    let locked2 = LockedModule {
        name: "upf-slice".to_string(),
        revision: "2026-05-20".to_string(),
        namespace: "urn:openpacketcore:yang:upf-slice".to_string(),
        checksum: "sha256:fedcba0987654321cba".to_string(),
        imports: vec![],
    };

    let lockfile = ModuleLockfile {
        profile: "carrier-default".to_string(),
        modules: vec![locked1, locked2],
    };

    let schema_mod1 = SchemaModule {
        name: "ietf-interfaces".to_string(),
        revision: "2026-05-19".to_string(),
        namespace: "urn:ietf:params:xml:ns:yang:ietf-interfaces".to_string(),
        prefix: "if".to_string(),
        source: YangSourceLocation::new("ietf-interfaces.yang", 1, 1),
    };

    let node1 = SchemaNode {
        path: "/upf:system".to_string(),
        module: "upf-slice".to_string(),
        kind: SchemaNodeKind::Container,
        config: true,
        type_ref: None,
        key_leaves: vec![],
        child_paths: vec!["/upf:system/interfaces".to_string()],
        source: YangSourceLocation::new("upf-slice.yang", 10, 5),
        ..Default::default()
    };

    let node2 = SchemaNode {
        path: "/upf:system/interfaces".to_string(),
        module: "upf-slice".to_string(),
        kind: SchemaNodeKind::Container,
        config: true,
        type_ref: None,
        key_leaves: vec![],
        child_paths: vec!["/upf:system/interfaces/interface".to_string()],
        source: YangSourceLocation::new("upf-slice.yang", 15, 5),
        ..Default::default()
    };

    let node3 = SchemaNode {
        path: "/upf:system/interfaces/interface".to_string(),
        module: "upf-slice".to_string(),
        kind: SchemaNodeKind::List,
        config: true,
        type_ref: None,
        key_leaves: vec!["name".to_string()],
        child_paths: vec![],
        source: YangSourceLocation::new("upf-slice.yang", 20, 5),
        ..Default::default()
    };

    let expr = ConstraintExpr::Boolean {
        op: BooleanOp::And,
        terms: vec![ConstraintExpr::Compare {
            op: CompareOp::Eq,
            left: Box::new(ConstraintExpr::Path(PathExpr {
                anchor: PathAnchor::Current,
                segments: vec!["enabled".to_string()],
            })),
            right: Box::new(ConstraintExpr::Literal(Literal::Bool(true))),
        }],
    };

    let constraint1 = ConstraintBinding {
        target_path: "/upf:system/interfaces/interface".to_string(),
        expr,
        source: YangSourceLocation::new("upf-slice.yang", 20, 7),
        kind: None,
    };

    let shape1 = StackShape {
        rust_type: "generated::System".to_string(),
        yang_path: "/upf:system".to_string(),
        scope: StackScope::Root,
        estimated_size: 736,
        allocation: AllocationStrategy::Inline,
    };

    let shape2 = StackShape {
        rust_type: "generated::Interface".to_string(),
        yang_path: "/upf:system/interfaces/interface".to_string(),
        scope: StackScope::Nested,
        estimated_size: 1536,
        allocation: AllocationStrategy::Boxed,
    };

    GenerationInput {
        profile: "carrier-default".to_string(),
        lockfile,
        schema_modules: vec![schema_mod1],
        nodes: vec![node1, node2, node3],
        constraints: vec![constraint1],
        stack_budget: StackBudget::default(),
        stack_shapes: vec![shape1, shape2],
        unsupported_features: vec![],
    }
}

fn append_interface_leaf_nodes(input: &mut GenerationInput) -> (String, String) {
    let enabled_path = "/upf:system/interfaces/interface/enabled".to_string();
    let tenant_path = "/upf:system/interfaces/interface/tenant".to_string();

    input.nodes.push(SchemaNode {
        path: enabled_path.clone(),
        module: "upf-slice".to_string(),
        kind: SchemaNodeKind::Leaf,
        config: true,
        type_ref: Some(TypeRef::Boolean),
        key_leaves: vec![],
        child_paths: vec![],
        source: YangSourceLocation::new("upf-slice.yang", 25, 7),
        ..Default::default()
    });
    input.nodes.push(SchemaNode {
        path: tenant_path.clone(),
        module: "upf-slice".to_string(),
        kind: SchemaNodeKind::Leaf,
        config: true,
        type_ref: Some(TypeRef::String),
        key_leaves: vec![],
        child_paths: vec![],
        source: YangSourceLocation::new("upf-slice.yang", 26, 7),
        ..Default::default()
    });

    (enabled_path, tenant_path)
}

#[test]
fn test_deterministic_output_ordering() {
    let input1 = create_base_input();
    let mut input2 = create_base_input();

    // Reorder modules inside lockfile
    input2.lockfile.modules.swap(0, 1);

    // Reorder nodes
    input2.nodes.swap(0, 2);

    // Reorder stack shapes
    input2.stack_shapes.swap(0, 1);

    let fixture1 = emit_fixture(&input1);
    let fixture2 = emit_fixture(&input2);

    assert_eq!(
        fixture1, fixture2,
        "Emitter output must be deterministic regardless of input ordering"
    );
}

#[test]
fn test_identical_constraint_expr_source_ordering_is_deterministic() {
    let mut input1 = create_base_input();
    let mut input2 = create_base_input();

    let first = input1.constraints[0].clone();
    let mut second = first.clone();
    second.source = YangSourceLocation::new("upf-slice.yang", 30, 7);

    input1.constraints = vec![first.clone(), second.clone()];
    input2.constraints = vec![second, first];

    let fixture1 = emit_fixture(&input1);
    let fixture2 = emit_fixture(&input2);

    assert_eq!(
        schema_digest(&input1),
        schema_digest(&input2),
        "Schema digest must ignore identical-constraint source-order differences"
    );
    assert_eq!(
        fixture1, fixture2,
        "Emitter output must be deterministic when identical constraints arrive in reverse source order"
    );
}

fn nested_typed_boolean_expr(depth: u16, leaf_name: &str) -> ConstraintExpr {
    if depth == 0 {
        ConstraintExpr::Compare {
            op: CompareOp::Eq,
            left: Box::new(ConstraintExpr::Path(PathExpr {
                anchor: PathAnchor::Current,
                segments: vec![leaf_name.to_string()],
            })),
            right: Box::new(ConstraintExpr::Literal(Literal::Bool(true))),
        }
    } else {
        ConstraintExpr::Boolean {
            op: BooleanOp::And,
            terms: vec![nested_typed_boolean_expr(depth - 1, leaf_name)],
        }
    }
}

#[test]
fn test_schema_digest_stability() {
    let input1 = create_base_input();
    let mut input2 = create_base_input();

    // Reorder modules inside lockfile
    input2.lockfile.modules.swap(0, 1);

    // Reorder nodes
    input2.nodes.swap(0, 2);

    // Reorder stack shapes
    input2.stack_shapes.swap(0, 1);

    let digest1 = schema_digest(&input1);
    let digest2 = schema_digest(&input2);

    assert_eq!(
        digest1, digest2,
        "Schema digest must be stable across input reorderings"
    );
    assert!(
        digest1.starts_with("fnv1a64:"),
        "Digest must use fnv1a64 encoding prefix"
    );
}

#[test]
fn test_profile_changes_affect_digest_and_fixture() {
    let input1 = create_base_input();
    let mut input2 = create_base_input();

    input2.profile = "carrier-lab".to_string();
    input2.lockfile.profile = "carrier-lab".to_string();

    assert_ne!(
        schema_digest(&input1),
        schema_digest(&input2),
        "Schema digest must change when the generation profile changes"
    );
    assert_ne!(
        emit_fixture(&input1),
        emit_fixture(&input2),
        "Fixture emission must change when the generation profile changes"
    );
}

#[test]
fn test_profile_mismatch_is_visible_in_fixture() {
    let baseline = create_base_input();
    let mut input = create_base_input();
    input.lockfile.profile = "carrier-lab".to_string();

    let fixture = emit_fixture(&input);

    assert!(fixture.contains("profile carrier-default"));
    assert!(fixture.contains("lockfile-profile=carrier-lab mismatch=true"));
    assert_ne!(
        schema_digest(&baseline),
        schema_digest(&input),
        "Schema digest must surface lockfile-profile mismatches"
    );
}

#[test]
fn test_over_depth_typed_constraint_ordering_is_deterministic() {
    let mut input1 = create_base_input();
    let mut input2 = create_base_input();

    let first = ConstraintBinding {
        target_path: "/upf:system/interfaces/interface".to_string(),
        expr: nested_typed_boolean_expr(MAX_CONSTRAINT_EXPR_DEPTH + 1, "enabled"),
        source: YangSourceLocation::new("upf-slice.yang", 40, 7),
        kind: None,
    };
    let second = ConstraintBinding {
        target_path: "/upf:system/interfaces/interface".to_string(),
        expr: nested_typed_boolean_expr(MAX_CONSTRAINT_EXPR_DEPTH + 1, "tenant"),
        source: YangSourceLocation::new("upf-slice.yang", 40, 7),
        kind: None,
    };

    input1.constraints = vec![first.clone(), second.clone()];
    input2.constraints = vec![second, first];

    assert_eq!(
        schema_digest(&input1),
        schema_digest(&input2),
        "Schema digest must remain deterministic for directly-constructed over-depth typed IR"
    );
    assert_eq!(
        emit_fixture(&input1),
        emit_fixture(&input2),
        "Fixture emission must remain deterministic for directly-constructed over-depth typed IR"
    );
}

/// Build a nested Boolean expression of the given depth where the
/// innermost Boolean contains the supplied terms.
fn nested_boolean_with_terms_at_depth(depth: u16, terms: Vec<ConstraintExpr>) -> ConstraintExpr {
    if depth == 0 {
        ConstraintExpr::Boolean {
            op: BooleanOp::And,
            terms,
        }
    } else {
        ConstraintExpr::Boolean {
            op: BooleanOp::And,
            terms: vec![nested_boolean_with_terms_at_depth(depth - 1, terms)],
        }
    }
}

#[test]
fn test_over_depth_reversed_boolean_terms_are_deterministic() {
    let mut input1 = create_base_input();
    let mut input2 = create_base_input();

    let term_a = ConstraintExpr::Compare {
        op: CompareOp::Eq,
        left: Box::new(ConstraintExpr::Path(PathExpr {
            anchor: PathAnchor::Current,
            segments: vec!["enabled".to_string()],
        })),
        right: Box::new(ConstraintExpr::Literal(Literal::Bool(true))),
    };
    let term_b = ConstraintExpr::Compare {
        op: CompareOp::Eq,
        left: Box::new(ConstraintExpr::Path(PathExpr {
            anchor: PathAnchor::Current,
            segments: vec!["tenant".to_string()],
        })),
        right: Box::new(ConstraintExpr::Literal(Literal::String("gold".to_string()))),
    };

    // The innermost Boolean with two terms is at depth MAX+1,
    // which exceeds the old recursion guard.
    let expr1 = nested_boolean_with_terms_at_depth(
        MAX_CONSTRAINT_EXPR_DEPTH + 1,
        vec![term_a.clone(), term_b.clone()],
    );
    let expr2 = nested_boolean_with_terms_at_depth(
        MAX_CONSTRAINT_EXPR_DEPTH + 1,
        vec![term_b.clone(), term_a.clone()],
    );

    input1.constraints[0].expr = expr1;
    input2.constraints[0].expr = expr2;

    assert_eq!(
        schema_digest(&input1),
        schema_digest(&input2),
        "Schema digest must normalize boolean-term ordering even beyond MAX_CONSTRAINT_EXPR_DEPTH"
    );
    assert_eq!(
        emit_fixture(&input1),
        emit_fixture(&input2),
        "Fixture emission must normalize boolean-term ordering even beyond MAX_CONSTRAINT_EXPR_DEPTH"
    );
}

#[test]
fn test_boolean_terms_sorted_at_depth_boundary() {
    let mut input1 = create_base_input();
    let mut input2 = create_base_input();

    let term_a = ConstraintExpr::Compare {
        op: CompareOp::Eq,
        left: Box::new(ConstraintExpr::Path(PathExpr {
            anchor: PathAnchor::Current,
            segments: vec!["enabled".to_string()],
        })),
        right: Box::new(ConstraintExpr::Literal(Literal::Bool(true))),
    };
    let term_b = ConstraintExpr::Compare {
        op: CompareOp::Eq,
        left: Box::new(ConstraintExpr::Path(PathExpr {
            anchor: PathAnchor::Current,
            segments: vec!["tenant".to_string()],
        })),
        right: Box::new(ConstraintExpr::Literal(Literal::String("gold".to_string()))),
    };

    // The innermost Boolean with two terms is at depth MAX-1,
    // which is still within the old recursion guard and exercises
    // terms.sort() on a multi-element vector.
    let expr1 = nested_boolean_with_terms_at_depth(
        MAX_CONSTRAINT_EXPR_DEPTH - 1,
        vec![term_a.clone(), term_b.clone()],
    );
    let expr2 = nested_boolean_with_terms_at_depth(
        MAX_CONSTRAINT_EXPR_DEPTH - 1,
        vec![term_b.clone(), term_a.clone()],
    );

    input1.constraints[0].expr = expr1;
    input2.constraints[0].expr = expr2;

    assert_eq!(
        schema_digest(&input1),
        schema_digest(&input2),
        "Schema digest must normalize boolean-term ordering at depth MAX-1"
    );
    assert_eq!(
        emit_fixture(&input1),
        emit_fixture(&input2),
        "Fixture emission must normalize boolean-term ordering at depth MAX-1"
    );
}

#[test]
fn test_function_argument_order_remains_semantic() {
    let mut input1 = create_base_input();
    let mut input2 = create_base_input();

    input1.constraints[0].expr = ConstraintExpr::Function(FunctionCall {
        name: FunctionName::StartsWith,
        args: vec![
            ConstraintExpr::Path(PathExpr {
                anchor: PathAnchor::Current,
                segments: vec!["name".to_string()],
            }),
            ConstraintExpr::Literal(Literal::String("tun".to_string())),
        ],
    });
    input2.constraints[0].expr = ConstraintExpr::Function(FunctionCall {
        name: FunctionName::StartsWith,
        args: vec![
            ConstraintExpr::Literal(Literal::String("tun".to_string())),
            ConstraintExpr::Path(PathExpr {
                anchor: PathAnchor::Current,
                segments: vec!["name".to_string()],
            }),
        ],
    });

    assert_ne!(
        schema_digest(&input1),
        schema_digest(&input2),
        "Schema digest must preserve positional function-argument semantics"
    );
    assert_ne!(
        emit_fixture(&input1),
        emit_fixture(&input2),
        "Fixture emission must preserve positional function-argument semantics"
    );
}

#[test]
fn test_constraint_expr_lowering() {
    let raw = RawConstraintExpr::Compare {
        op: "=".to_string(),
        left: Box::new(RawConstraintExpr::Path {
            anchor: "current()".to_string(),
            segments: vec!["enabled".to_string()],
        }),
        right: Box::new(RawConstraintExpr::Literal(Literal::Bool(true))),
    };

    let source = YangSourceLocation::new("upf-slice.yang", 20, 7);
    let lowered = lower_constraint(&raw, source).expect("Should lower valid XPath");

    if let ConstraintExpr::Compare { op, left, right } = lowered {
        assert_eq!(op, CompareOp::Eq);
        if let ConstraintExpr::Path(path) = *left {
            assert_eq!(path.anchor, PathAnchor::Current);
            assert_eq!(path.segments, vec!["enabled".to_string()]);
        } else {
            panic!("Expected PathExpr on the left of comparison");
        }
        if let ConstraintExpr::Literal(Literal::Bool(val)) = *right {
            assert!(val);
        } else {
            panic!("Expected Bool literal on the right of comparison");
        }
    } else {
        panic!("Expected Compare variant of ConstraintExpr");
    }
}

#[test]
fn test_unsupported_feature_diagnostic() {
    let mut input = create_base_input();
    let unsupported = UnsupportedFeature {
        kind: UnsupportedFeatureKind::IfFeature,
        name: "vendor:turbo-boost".to_string(),
        source: YangSourceLocation::new("upf-slice.yang", 27, 9),
    };
    input.unsupported_features.push(unsupported);

    let result = compile(&input);
    assert!(result.is_err(), "Compile must fail on unsupported features");

    let diag = result.unwrap_err();
    assert_eq!(diag.code, DiagnosticCode::UnsupportedYangFeature);
    assert_eq!(diag.source.unwrap().to_string(), "upf-slice.yang:27:9");
    assert!(diag
        .message
        .contains("unsupported YANG if-feature `vendor:turbo-boost`"));
    assert!(diag
        .help
        .unwrap()
        .contains("remove the construct or add an explicit lowering strategy"));
}

#[test]
fn test_generated_stack_size_metadata_fixture() {
    let budget = StackBudget {
        max_size_of_root: 4096,
        max_size_of_any_struct: 1024,
    };

    let shape1 = StackShape {
        rust_type: "generated::System".to_string(),
        yang_path: "/upf:system".to_string(),
        scope: StackScope::Root,
        estimated_size: 736,
        allocation: AllocationStrategy::Inline,
    };

    let shape2 = StackShape {
        rust_type: "generated::Interface".to_string(),
        yang_path: "/upf:system/interfaces/interface".to_string(),
        scope: StackScope::Nested,
        estimated_size: 1536,
        allocation: AllocationStrategy::Boxed,
    };

    let metadata = emit_stack_metadata(&[shape1, shape2], &budget);

    assert!(metadata.contains("stack-budget root=4096 nested=1024"));
    assert!(metadata.contains("  root generated::System path=/upf:system estimated=736 budget=4096 allocation=inline status=within-budget"));
    assert!(metadata.contains("  nested generated::Interface path=/upf:system/interfaces/interface estimated=1536 budget=1024 allocation=boxed status=boxed-to-fit"));
}

#[test]
fn test_schema_digest_ignores_stack_metadata() {
    let base = create_base_input();
    let mut modified = create_base_input();

    modified.stack_budget = StackBudget {
        max_size_of_root: 8192,
        max_size_of_any_struct: 2048,
    };
    modified.stack_shapes[0].estimated_size = 2048;
    modified.stack_shapes[0].allocation = AllocationStrategy::Boxed;
    modified.stack_shapes[1].estimated_size = 128;
    modified.stack_shapes[1].allocation = AllocationStrategy::Inline;

    assert_eq!(
        schema_digest(&base),
        schema_digest(&modified),
        "Schema digest must ignore stack-budget and stack-shape metadata"
    );
}

#[test]
fn test_duplicate_rust_type_stack_shapes_are_deterministic() {
    let mut input1 = create_base_input();
    let mut input2 = create_base_input();

    let shape_a = StackShape {
        rust_type: "generated::SharedLeaf".to_string(),
        yang_path: "/upf:system/interfaces/interface/enabled".to_string(),
        scope: StackScope::Nested,
        estimated_size: 16,
        allocation: AllocationStrategy::Inline,
    };
    let shape_b = StackShape {
        rust_type: "generated::SharedLeaf".to_string(),
        yang_path: "/upf:system/interfaces/interface/name".to_string(),
        scope: StackScope::Nested,
        estimated_size: 24,
        allocation: AllocationStrategy::Inline,
    };

    input1.stack_shapes = vec![shape_a.clone(), shape_b.clone()];
    input2.stack_shapes = vec![shape_b, shape_a];

    assert_eq!(
        emit_stack_metadata(&input1.stack_shapes, &input1.stack_budget),
        emit_stack_metadata(&input2.stack_shapes, &input2.stack_budget),
        "Stack metadata emission must be deterministic for duplicate rust_type entries"
    );
    assert_eq!(
        emit_fixture(&input1),
        emit_fixture(&input2),
        "Fixture emission must be deterministic for duplicate rust_type entries"
    );
}

#[test]
fn test_trailing_slash_anchors_rejected() {
    let source = YangSourceLocation::new("upf-slice.yang", 20, 7);

    // Root anchor "/" with empty segments must be rejected
    let raw_root_empty = RawConstraintExpr::Path {
        anchor: "/".to_string(),
        segments: vec![],
    };
    let res = lower_constraint(&raw_root_empty, source.clone());
    assert!(res.is_err());
    assert_eq!(res.unwrap_err().code, DiagnosticCode::InvalidPathExpression);

    // Parent anchor ".." with empty segments must be rejected
    let raw_parent_empty = RawConstraintExpr::Path {
        anchor: "..".to_string(),
        segments: vec![],
    };
    let res = lower_constraint(&raw_parent_empty, source.clone());
    assert!(res.is_err());
    assert_eq!(res.unwrap_err().code, DiagnosticCode::InvalidPathExpression);

    // Path segments containing ".." must be rejected
    let raw_segment_parent = RawConstraintExpr::Path {
        anchor: "current()".to_string(),
        segments: vec!["..".to_string()],
    };
    let res = lower_constraint(&raw_segment_parent, source.clone());
    assert!(res.is_err());
    assert_eq!(res.unwrap_err().code, DiagnosticCode::InvalidPathExpression);

    // Path segments containing "." must be rejected
    let raw_segment_self = RawConstraintExpr::Path {
        anchor: "current()".to_string(),
        segments: vec![".".to_string()],
    };
    let res = lower_constraint(&raw_segment_self, source.clone());
    assert!(res.is_err());
    assert_eq!(res.unwrap_err().code, DiagnosticCode::InvalidPathExpression);
}

#[test]
fn test_xpath_functions_are_unsupported_in_skeleton_phase() {
    let source = YangSourceLocation::new("upf-slice.yang", 20, 7);

    for (name, args) in [
        (
            "count",
            vec![RawConstraintExpr::Path {
                anchor: "current()".to_string(),
                segments: vec!["enabled".to_string()],
            }],
        ),
        ("current", vec![]),
        ("not", vec![RawConstraintExpr::Literal(Literal::Bool(true))]),
        (
            "starts-with",
            vec![
                RawConstraintExpr::Path {
                    anchor: "/".to_string(),
                    segments: vec!["name".to_string()],
                },
                RawConstraintExpr::Literal(Literal::String("tun".to_string())),
            ],
        ),
    ] {
        let raw = RawConstraintExpr::Function {
            name: name.to_string(),
            args,
        };
        let err = lower_constraint(&raw, source.clone()).expect_err("function must be rejected");
        assert_eq!(err.code, DiagnosticCode::UnsupportedXPathFunction);
        assert!(err.message.contains(name));
        assert!(err
            .help
            .as_deref()
            .unwrap_or_default()
            .contains("reference-engine differential tests"));
    }
}

/// Build a nested Boolean expression of the given depth.
fn nested_boolean_expr(depth: u16) -> RawConstraintExpr {
    if depth == 0 {
        RawConstraintExpr::Literal(Literal::Bool(true))
    } else {
        RawConstraintExpr::Boolean {
            op: "and".to_string(),
            terms: vec![nested_boolean_expr(depth - 1)],
        }
    }
}

#[test]
fn test_constraint_depth_limit_at_max_succeeds() {
    let source = YangSourceLocation::new("upf-slice.yang", 20, 7);
    // A nested Boolean expression of depth MAX_CONSTRAINT_EXPR_DEPTH should succeed.
    let raw = nested_boolean_expr(MAX_CONSTRAINT_EXPR_DEPTH);
    let result = lower_constraint(&raw, source);
    assert!(
        result.is_ok(),
        "Lowering at depth {MAX_CONSTRAINT_EXPR_DEPTH} should succeed"
    );
}

#[test]
fn test_constraint_depth_limit_exceeded_fails() {
    let source = YangSourceLocation::new("upf-slice.yang", 20, 7);
    // A nested Boolean expression of depth MAX_CONSTRAINT_EXPR_DEPTH + 1 should fail.
    let raw = nested_boolean_expr(MAX_CONSTRAINT_EXPR_DEPTH + 1);
    let result = lower_constraint(&raw, source);
    assert!(
        result.is_err(),
        "Lowering at depth {} should fail",
        MAX_CONSTRAINT_EXPR_DEPTH + 1
    );
    let diag = result.unwrap_err();
    assert_eq!(diag.code, DiagnosticCode::ConstraintDepthExceeded);
    assert!(diag.message.contains("exceeds maximum depth"));
}

#[test]
fn test_unsupported_xpath_construct_rejected() {
    let source = YangSourceLocation::new("upf-slice.yang", 20, 7);

    // Predicate
    let raw = RawConstraintExpr::Path {
        anchor: "current()".to_string(),
        segments: vec!["foo[bar=1]".to_string()],
    };
    let res = lower_constraint(&raw, source.clone());
    assert!(res.is_err());
    assert_eq!(res.unwrap_err().code, DiagnosticCode::InvalidPathExpression);

    // Axis
    let raw = RawConstraintExpr::Path {
        anchor: "current()".to_string(),
        segments: vec!["child::foo".to_string()],
    };
    let res = lower_constraint(&raw, source.clone());
    assert!(res.is_err());
    assert_eq!(res.unwrap_err().code, DiagnosticCode::InvalidPathExpression);

    // Attribute selector
    let raw = RawConstraintExpr::Path {
        anchor: "current()".to_string(),
        segments: vec!["@name".to_string()],
    };
    let res = lower_constraint(&raw, source.clone());
    assert!(res.is_err());
    assert_eq!(res.unwrap_err().code, DiagnosticCode::InvalidPathExpression);

    // Wildcard
    let raw = RawConstraintExpr::Path {
        anchor: "current()".to_string(),
        segments: vec!["*".to_string()],
    };
    let res = lower_constraint(&raw, source.clone());
    assert!(res.is_err());
    assert_eq!(res.unwrap_err().code, DiagnosticCode::InvalidPathExpression);
}

// ---------------------------------------------------------------------------
// Golden fixture tests (exact-output regression)
// ---------------------------------------------------------------------------

#[test]
fn test_deterministic_emitter_fixture() {
    let fixture = emit_fixture(&create_base_input());
    let expected = include_str!("fixtures/deterministic-emitter.txt");
    assert_eq!(
        fixture, expected,
        "emit_fixture output must match golden fixture"
    );
}

#[test]
fn test_constraint_lowering_fixture() {
    let raw = RawConstraintExpr::Compare {
        op: "=".to_string(),
        left: Box::new(RawConstraintExpr::Path {
            anchor: "current()".to_string(),
            segments: vec!["enabled".to_string()],
        }),
        right: Box::new(RawConstraintExpr::Literal(Literal::Bool(true))),
    };
    let source = YangSourceLocation::new("upf-slice.yang", 20, 7);
    let lowered = lower_constraint(&raw, source.clone()).unwrap();

    let rendered = format!(
        "raw: current()/enabled = true\nlowered: {}\nsource: {}\n",
        format_constraint_expr(&lowered),
        source,
    );
    let expected = include_str!("fixtures/constraint-lowering.txt");
    assert_eq!(
        rendered, expected,
        "Constraint lowering output must match golden fixture"
    );
}

#[test]
fn test_stack_metadata_fixture() {
    let budget = StackBudget {
        max_size_of_root: 4096,
        max_size_of_any_struct: 1024,
    };
    let shape1 = StackShape {
        rust_type: "generated::System".to_string(),
        yang_path: "/upf:system".to_string(),
        scope: StackScope::Root,
        estimated_size: 736,
        allocation: AllocationStrategy::Inline,
    };
    let shape2 = StackShape {
        rust_type: "generated::Interface".to_string(),
        yang_path: "/upf:system/interfaces/interface".to_string(),
        scope: StackScope::Nested,
        estimated_size: 1536,
        allocation: AllocationStrategy::Boxed,
    };
    let metadata = emit_stack_metadata(&[shape1, shape2], &budget);
    let expected = include_str!("fixtures/stack-metadata.txt");
    assert_eq!(
        metadata, expected,
        "Stack metadata output must match golden fixture"
    );
}

// ---------------------------------------------------------------------------
// Digest stability: source-location-only changes must not affect digest
// ---------------------------------------------------------------------------

#[test]
fn test_schema_digest_ignores_source_location() {
    let base = create_base_input();
    let mut modified = create_base_input();

    // Change only source locations across all semantic items
    modified.schema_modules[0].source = YangSourceLocation::new("different.yang", 99, 99);
    modified.nodes[0].source = YangSourceLocation::new("different.yang", 99, 99);
    modified.nodes[1].source = YangSourceLocation::new("different.yang", 99, 99);
    modified.nodes[2].source = YangSourceLocation::new("different.yang", 99, 99);
    modified.constraints[0].source = YangSourceLocation::new("different.yang", 99, 99);

    let digest_base = schema_digest(&base);
    let digest_modified = schema_digest(&modified);
    assert_eq!(
        digest_base, digest_modified,
        "Schema digest must be stable when only source locations change"
    );
}

#[test]
fn test_schema_digest_normalizes_child_path_order() {
    let mut input1 = create_base_input();
    let mut input2 = create_base_input();

    let (enabled_path, tenant_path) = append_interface_leaf_nodes(&mut input1);
    append_interface_leaf_nodes(&mut input2);

    input1.nodes[2].child_paths = vec![enabled_path.clone(), tenant_path.clone()];
    input2.nodes[2].child_paths = vec![tenant_path, enabled_path];

    assert_eq!(
        schema_digest(&input1),
        schema_digest(&input2),
        "Schema digest must ignore child traversal order in flattened schema nodes"
    );
    assert_eq!(
        emit_fixture(&input1),
        emit_fixture(&input2),
        "Fixture emission must ignore child traversal order in flattened schema nodes"
    );
}

#[test]
fn test_schema_digest_normalizes_boolean_term_order() {
    let mut input1 = create_base_input();
    let mut input2 = create_base_input();

    let left = ConstraintExpr::Compare {
        op: CompareOp::Eq,
        left: Box::new(ConstraintExpr::Path(PathExpr {
            anchor: PathAnchor::Current,
            segments: vec!["enabled".to_string()],
        })),
        right: Box::new(ConstraintExpr::Literal(Literal::Bool(true))),
    };
    let right = ConstraintExpr::Compare {
        op: CompareOp::Eq,
        left: Box::new(ConstraintExpr::Path(PathExpr {
            anchor: PathAnchor::Current,
            segments: vec!["tenant".to_string()],
        })),
        right: Box::new(ConstraintExpr::Literal(Literal::String("gold".to_string()))),
    };

    input1.constraints[0].expr = ConstraintExpr::Boolean {
        op: BooleanOp::And,
        terms: vec![left.clone(), right.clone()],
    };
    input2.constraints[0].expr = ConstraintExpr::Boolean {
        op: BooleanOp::And,
        terms: vec![right, left],
    };

    assert_eq!(
        schema_digest(&input1),
        schema_digest(&input2),
        "Schema digest must normalize boolean-term ordering"
    );
    assert_eq!(
        emit_fixture(&input1),
        emit_fixture(&input2),
        "Fixture emission must normalize boolean-term ordering"
    );
}

// ---------------------------------------------------------------------------
// DiagnosticCode wire-format consistency
// ---------------------------------------------------------------------------

#[test]
fn test_diagnostic_code_serde_consistency() {
    // UnsupportedXPathFunction must serialize as "unsupported-xpath-function"
    // to match its Display impl, not "unsupported-x-path-function".
    let code = DiagnosticCode::UnsupportedXPathFunction;
    let json = serde_json::to_string(&code).expect("serialization must succeed");
    assert_eq!(json, "\"unsupported-xpath-function\"");
    assert_eq!(code.to_string(), "unsupported-xpath-function");
}

#[test]
fn test_unsupported_feature_kind_serde_consistency() {
    let kind = UnsupportedFeatureKind::IfFeature;
    let json = serde_json::to_string(&kind).expect("serialization must succeed");
    assert_eq!(json, "\"if-feature\"");
}

#[test]
fn test_canonical_node_limit_graceful_abort() {
    // Construct a deeply nested ConstraintExpr that exceeds MAX_CANONICALIZATION_NODES
    let mut expr = ConstraintExpr::Literal(Literal::Bool(true));
    for _ in 0..1100 {
        expr = ConstraintExpr::Boolean {
            op: BooleanOp::Or,
            terms: vec![expr, ConstraintExpr::Literal(Literal::Bool(false))],
        };
    }

    let base = expr.clone();
    let mut input = create_base_input();
    input.constraints[0].expr = expr;

    // This should complete successfully and abort canonicalization when node count crosses the limit,
    // returning the original unmodified deep expression instead of panic or unbounded growth.
    let canonical = input.to_canonical();
    assert_eq!(canonical.constraints[0].expr, base);
    // The canonicalization_skipped flag must be set so callers can detect this
    // programmatically without relying on a tracing subscriber.
    assert!(
        canonical.canonicalization_skipped,
        "canonicalization_skipped must be true when budget is exceeded"
    );
}

#[test]
fn test_canonical_node_limit_wide_sibling_stack_bounded() {
    // Wide sibling case: L0 has 600 children; 599 are cheap Literals, one is a
    // branching Boolean. This keeps total nodes at ~1,800 (vs 216M in the naive
    // approach) while still exercising the scan_stack.len() pre-flight check.
    //
    // L1 is placed LAST in L0's terms so it is popped FIRST (LIFO). This keeps
    // node_count minimal when the branch budget check fires, forcing the old guard
    // (node_count + terms.len() only) to PASS the check and continue processing
    // L2's 600 literals before eventually aborting at L0 — exercising the full
    // unbounded-scan-stack regression. The new guard (node_count + scan_stack.len()
    // + terms.len()) aborts earlier because it counts the already-queued siblings.
    //
    // Without scan_stack.len(), the pre-scan allows unbounded stack growth:
    // node_count stays ~3 while scan_stack grows to ~1200 items before the
    // top-of-loop guard fires — O(MAX²) bound. With scan_stack.len() in the check,
    // the pre-flight aborts as soon as the pending work exceeds
    // MAX_CANONICALIZATION_NODES, keeping scan_stack bounded at O(MAX).
    //
    // Shape (only one branching child per level, placed last in each terms vec):
    //   L0_Boolean(599×Literal + 1×L1_Boolean)   ← L1 popped first (LIFO)
    //     L1_Boolean(599×Literal + 1×L2_Boolean(600×Literal))  ← L2 popped first
    //
    // After pushing L0's children: scan_stack.len() = 600, node_count = 1
    // Pop L1 (first, LIFO): node_count = 2, scan_stack.len() = 599 (other L0 literals)
    // L1 budget: 2 + 599 + 600 = 1201 > 1000 → new guard aborts here
    // Old guard at L1: 2 + 600 = 602 ≤ 1000 → continues into L2
    // Old guard at L2: 3 + 600 = 603 ≤ 1000 → continues, processes all 600 L2 literals
    // Old guard at L0 literals: node_count=603, scan_stack.len()=1198 → aborts
    //
    // Both guards return the same expression (l0) with canonicalization_skipped=true.
    // The regression is in scan_stack size: new guard keeps it ≤ 600; old guard
    // grows it to ~1200 before aborting.
    let l2_leaf = || ConstraintExpr::Literal(Literal::Bool(false));
    let l2 = ConstraintExpr::Boolean {
        op: BooleanOp::Or,
        terms: (0..600).map(|_| l2_leaf()).collect(),
    };
    let l1_branching = ConstraintExpr::Boolean {
        op: BooleanOp::Or,
        // 599 cheap leaves + 1 branching L2; L2 is placed LAST so it pops first (LIFO)
        terms: std::iter::once(ConstraintExpr::Literal(Literal::Bool(false)))
            .chain((0..598).map(|_| ConstraintExpr::Literal(Literal::Bool(false))))
            .chain(std::iter::once(l2))
            .collect(),
    };
    let l0 = ConstraintExpr::Boolean {
        op: BooleanOp::Or,
        // 599 cheap leaves + 1 branching L1; L1 is placed LAST so it pops first (LIFO)
        terms: (0..599)
            .map(|_| ConstraintExpr::Literal(Literal::Bool(false)))
            .chain(std::iter::once(l1_branching))
            .collect(),
    };

    let mut input = create_base_input();
    input.constraints[0].expr = l0.clone();

    // Canonicalization must abort during pre-scan, returning the unmodified
    // expression (terms not sorted) rather than panicking or growing unbounded.
    let canonical = input.to_canonical();
    assert_eq!(canonical.constraints[0].expr, l0);
    // The canonicalization_skipped flag must be set so callers can detect this
    // programmatically without relying on a tracing subscriber.
    assert!(
        canonical.canonicalization_skipped,
        "canonicalization_skipped must be true when budget is exceeded"
    );

    // The key regression: max_canonical_scan_stack_len is bounded at O(MAX) by the
    // scan_stack.len() budget term. Without that term, the old guard would allow
    // scan_stack to grow to ~1200 before aborting (O(MAX²) path). With the fix,
    // the queue is capped at ~600 when L1's pre-check fires.
    //
    // Specifically: the new guard fires at L1's pre-check (2 + 599 queued + 600 new >
    // 1000), so max_scan_stack_len = 600 (after pushing L0's 600 children).
    // The old guard would pass L1's check (2 + 600 = 602 ≤ 1000), continue into L2,
    // and grow the queue to ~1199 before the top-of-loop abort.
    assert!(
        canonical.max_canonical_scan_stack_len.is_some(),
        "max_canonical_scan_stack_len must be recorded when skipped"
    );
    let max_stack = canonical.max_canonical_scan_stack_len.unwrap();
    // With the new guard, the scan_stack peaks at ~600; without it, it reaches ~1200.
    // A threshold of 800 cleanly separates the two implementations.
    assert!(
        max_stack < 800,
        "max_canonical_scan_stack_len ({max_stack}) must be < 800 with the scan_stack.len() guard"
    );
}

#[test]
fn test_compile_with_diagnostics_returns_all_unsupported_features() {
    use opc_yanggen::{compile, compile_with_diagnostics, UnsupportedFeature};
    let mut input = create_base_input();
    let source1 = YangSourceLocation::new("slice.yang", 5, 2);
    let source2 = YangSourceLocation::new("slice.yang", 12, 4);

    input.unsupported_features = vec![
        UnsupportedFeature {
            name: "deviate-delete".to_string(),
            kind: UnsupportedFeatureKind::Deviation,
            source: source1,
        },
        UnsupportedFeature {
            name: "custom-extension".to_string(),
            kind: UnsupportedFeatureKind::Extension,
            source: source2,
        },
    ];

    // compile() only returns the first error:
    let res_single = compile(&input);
    assert!(res_single.is_err());
    let err_single = res_single.unwrap_err();
    assert_eq!(err_single.code, DiagnosticCode::UnsupportedYangFeature);
    assert!(err_single.message.contains("deviate-delete"));

    // compile_with_diagnostics() returns all errors in one Vec:
    let res_multi = compile_with_diagnostics(&input);
    assert!(res_multi.is_err());
    let errs = res_multi.unwrap_err();
    assert_eq!(errs.len(), 2);
    assert_eq!(errs[0].code, DiagnosticCode::UnsupportedYangFeature);
    assert!(errs[0].message.contains("deviate-delete"));
    assert_eq!(errs[1].code, DiagnosticCode::UnsupportedYangFeature);
    assert!(errs[1].message.contains("custom-extension"));
}

#[test]
fn test_canonical_shared_emission() {
    use opc_yanggen::{emit_fixture_from_canonical, schema_digest_from_canonical};
    let input = create_base_input();

    // Verify that we can canonicalize once, then compute digest and emit fixture
    // using the shared canonical representation without duplicate sort/clone.
    let canonical = input.to_canonical();

    let digest1 = schema_digest(&input);
    let digest2 = schema_digest_from_canonical(&canonical);
    assert_eq!(digest1, digest2);

    let fixture1 = emit_fixture(&input);
    let fixture2 = emit_fixture_from_canonical(&canonical);
    assert_eq!(fixture1, fixture2);
}
