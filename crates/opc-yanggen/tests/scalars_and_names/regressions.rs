use super::{compile_canonical_fixture, compile_fixture, compile_generated_fixture, input};
use opc_yanggen::{
    emit::format_constraint_expr, rust::generate_rust, CompareOp, ConstraintBinding,
    ConstraintExpr, Literal, NumericRangeInterval, PathAnchor, PathExpr, StringLengthInterval,
    StringPattern, TypeRef,
};

#[test]
fn pattern_arguments_preserve_yang_quoting_and_concatenation() {
    for (argument, expected) in [
        (r"'\d+'", r"\d+"),
        (r#""\\d+""#, r"\d+"),
        (r"\d+", r"\d+"),
        ("[0-9]+", "[0-9]+"),
        ("a+", "a+"),
        ("'a' + /* between */ \"b\"+'c'", "abc"),
        (r#""\n\t\"\\d""#, "\n\t\"\\d"),
        ("'a  \n  b'", "a  \n  b"),
        ("\"a \"", "a "),
        ("a\u{a0}b", "a\u{a0}b"),
    ] {
        assert_pattern_argument(argument, expected);
    }
}

fn assert_pattern_argument(argument: &str, expected: &str) {
    assert_pattern_statement(&format!("pattern {argument};"), expected);
}

fn assert_pattern_statement(statement: &str, expected: &str) {
    let parsed = input(&format!(
        "module example {{ namespace 'urn:example'; prefix ex;\ncontainer root {{ leaf value {{ type string {{\n{statement}\n}} }} }} }}"
    ));
    let leaf = parsed
        .nodes
        .iter()
        .find(|node| node.path == "/ex:root/ex:value")
        .unwrap();
    let Some(TypeRef::RestrictedString { patterns, .. }) = &leaf.type_ref else {
        panic!("expected a restricted string");
    };
    assert_eq!(patterns[0].expression, expected, "{statement:?}");
}

#[test]
fn double_quoted_arguments_trim_before_escape_substitution_and_concatenation() {
    // The opening quote is in column 9; tabs examined for indentation each
    // expand to eight spaces, including the unstripped remainder of a tab.
    for (argument, expected) in [
        ("\"a  \n           b\"", "a\n  b"),
        ("\"a\t\r\n\t\tb\"", "a\r\n       b"),
        ("\"a\\t  \n         b\"", "a\t\nb"),
        ("\"a  \\n  b\"", "a  \n  b"),
        ("\"a  \n   b\" + '  c'", "a\nb  c"),
        ("\"a\n         \tb\"", "a\n\tb"),
    ] {
        assert_pattern_argument(argument, expected);
    }
    assert_pattern_statement("\tpattern \"a\n                 b\";", "a\nb");
}

#[test]
fn malformed_quoted_arguments_are_refused_without_rewriting() {
    use opc_yanggen::{generation_input_from_yang_sources, DiagnosticCode, YangSource};
    for argument in [r#""\d+""#, r#""a\.b""#, r#""\r""#, r#""\q""#] {
        let source = format!("module example {{ namespace 'urn:example'; prefix ex; container root {{ leaf value {{ type string {{ pattern {argument}; }} }} }} }}");
        let error = generation_input_from_yang_sources(
            "example",
            &[YangSource::new("example.yang", source)],
        )
        .unwrap_err();
        assert_eq!(error.code, DiagnosticCode::YangSourceSyntaxError);
        assert_eq!(error.message, "invalid escape in double-quoted YANG string");
        assert!(error.source.is_some());
    }
    for argument in [
        "'a' 'b'",
        "a b",
        "a + 'b'",
        "'a' + b",
        "'a' +",
        "'a' ++ 'b'",
    ] {
        let source = format!("module example {{ namespace 'urn:example'; prefix ex; container root {{ leaf value {{ type string {{ pattern {argument}; }} }} }} }}");
        let error = generation_input_from_yang_sources(
            "example",
            &[YangSource::new("example.yang", source)],
        )
        .unwrap_err();
        assert_eq!(error.code, DiagnosticCode::YangSourceSyntaxError);
        assert_eq!(
            error.message,
            "YANG arguments require one string or quoted strings joined by '+'"
        );
    }
}

#[test]
fn integer_defaults_use_the_yang_radix_before_range_checks() {
    for ty in [
        "uint8", "uint16", "uint32", "uint64", "int8", "int16", "int32", "int64",
    ] {
        for (value, valid) in [
            ("010", true),
            ("+010", true),
            ("0x8", true),
            ("+0x8", true),
            ("012", false),
            ("08", false),
            ("0X8", false),
            ("0x", false),
            ("0x+8", false),
            ("++8", false),
        ] {
            let source = format!("module example {{ namespace 'urn:example'; prefix ex; container root {{ leaf value {{ type {ty} {{ range '8'; }} default '{value}'; }} }} }}");
            let result = generate_rust(&input(&source).to_canonical());
            if valid {
                result.unwrap_or_else(|error| panic!("{ty} {value}: {error}"));
            } else {
                assert_eq!(result.unwrap_err().message(), "integer default at /ex:root/ex:value is invalid or outside its type or declared range");
            }
        }
    }
}

#[test]
fn integer_refusals_are_value_free_without_string_restrictions() {
    compile_fixture(
        "integer-errors",
        &integer_error_model(false),
        include_str!("../fixtures/integer_errors_test.rs"),
        10,
    );
}

#[test]
fn integer_refusals_are_value_free_with_string_restrictions() {
    compile_fixture(
        "integer-errors-with-strings",
        &integer_error_model(true),
        include_str!("../fixtures/integer_errors_test.rs"),
        10,
    );
}

fn integer_error_model(with_strings: bool) -> String {
    let mut source =
        "module example { namespace 'urn:example'; prefix ex; container root {".to_string();
    for ty in [
        "uint8", "uint16", "uint32", "uint64", "int8", "int16", "int32", "int64",
    ] {
        source.push_str(&format!(
            "leaf secret-{ty} {{ type {ty}; }}
             leaf bounded-{ty} {{ type {ty} {{ range '0..1'; }} }}
             leaf-list secret-{ty}-values {{ type {ty}; }}
             list by-{ty} {{ key secret-id; leaf secret-id {{ type {ty}; }}
               leaf value {{ type uint8; }} }}"
        ));
    }
    source.push_str(
        "container child { leaf secret-value { type uint64; } }
         container state { config false; leaf counter { type int16; } }
         list pair { key 'secret-id slot'; leaf secret-id { type uint8; }
           leaf slot { type uint64; } leaf value { type uint8; } }",
    );
    if with_strings {
        source.push_str("leaf code { type string { pattern '[a-z]+'; } }");
    }
    source.push_str("} }");
    source
}

const SEMANTIC_TEST_SUPPORT: &str = r#"
use generated_test::types::Root;
use opc_config_model::{OpcConfig, ValidationContext, ValidationError};
use serde_json::{json, Value};

fn semantics(body: Value) -> Result<(), ValidationError> {
    let config: Root = serde_json::from_value(body).unwrap();
    let ctx = ValidationContext {
        request_id: opc_config_model::RequestId::new(),
        principal: opc_config_model::TrustedPrincipal::new(
            opc_config_model::WorkloadIdentity::Internal("test".into()),
            opc_types::TenantId::new("test").unwrap(),
        ),
        transport: opc_config_model::TransportType::Internal,
        source: opc_config_model::RequestSource::Northbound,
        operation: opc_config_model::ConfigOperation::Replace,
        mode: opc_config_model::CommitMode::Commit,
        base_version: opc_types::ConfigVersion::INITIAL,
        previous: None,
    };
    config.validate_semantics(&ctx)
}
"#;

#[test]
fn small_integer_comparisons_preserve_literals_in_both_operand_orders() {
    let mut source =
        "module example { namespace 'urn:example'; prefix ex; container root {".to_string();
    let mut constraints = Vec::new();
    let mut tests = SEMANTIC_TEST_SUPPORT.to_string();
    let mut count = 0;
    for (ty, min, max) in [
        ("uint8", 0_i64, 255_i64),
        ("uint16", 0, 65535),
        ("uint32", 0, 4294967295),
        ("int8", -128, 127),
        ("int16", -32768, 32767),
        ("int32", -2147483648, 2147483647),
    ] {
        // Every constant is representable by the public IR but the two outer
        // constants are deliberately outside the leaf's storage type.
        for constant in [min - 1, min, max, max + 1] {
            for (op, reversed) in [(CompareOp::Lt, false), (CompareOp::Lte, true)] {
                let case = format!("case{count}");
                source.push_str(&format!(
                    "container {case} {{ leaf value {{ type {ty}; }} }}"
                ));
                let path = ConstraintExpr::Path(PathExpr {
                    anchor: PathAnchor::Current,
                    segments: vec!["value".into()],
                });
                let literal = ConstraintExpr::Literal(Literal::Number(constant));
                let (left, right) = if reversed {
                    (literal, path)
                } else {
                    (path, literal)
                };
                let expr = ConstraintExpr::Compare {
                    op,
                    left: Box::new(left),
                    right: Box::new(right),
                };
                let reason = format!("Constraint failed: {}", format_constraint_expr(&expr));
                constraints.push(ConstraintBinding {
                    target_path: format!("/ex:root/ex:{case}"),
                    expr,
                    ..Default::default()
                });
                tests.push_str(&format!("#[test]\nfn {case}() {{\n"));
                for value in [min, min + 1, max] {
                    let accepts = if reversed {
                        constant <= value
                    } else {
                        value < constant
                    };
                    let expected = if accepts {
                        "Ok(())".to_string()
                    } else {
                        format!("Err(ValidationError::semantics({reason:?}))")
                    };
                    tests.push_str(&format!(
                        "assert_eq!(semantics(json!({{{:?}: {{\"value\": {value}_i64}}}})), {expected});\n",
                        format!("example:{case}")
                    ));
                }
                tests.push_str("}\n");
                count += 1;
            }
        }
    }
    // Keep the exact upper-constant reproduction in addition to the matrix:
    // uint8 value <= 256 must accept 255.
    source.push_str("container upper { leaf value { type uint8; } }");
    constraints.push(ConstraintBinding {
        target_path: "/ex:root/ex:upper".into(),
        expr: ConstraintExpr::Compare {
            op: CompareOp::Lte,
            left: Box::new(ConstraintExpr::Path(PathExpr {
                anchor: PathAnchor::Current,
                segments: vec!["value".into()],
            })),
            right: Box::new(ConstraintExpr::Literal(Literal::Number(256))),
        },
        ..Default::default()
    });
    tests.push_str(
        "#[test]\nfn uint8_upper_constant_does_not_wrap() {
           assert_eq!(semantics(json!({\"example:upper\": {\"value\": 255}})), Ok(()));
         }\n",
    );
    source.push_str("} }");
    let mut canonical = input(&source).to_canonical();
    canonical.constraints = constraints;
    compile_canonical_fixture("small-integer-comparisons", &canonical, &tests, count + 1);
}

#[test]
fn wide_integer_comparisons_and_resolved_leafrefs_compile_and_execute() {
    let mut source =
        "module example { namespace 'urn:example'; prefix ex; container root {".to_string();
    let mut constraints = Vec::new();
    let mut tests = SEMANTIC_TEST_SUPPORT.to_string();
    let mut count = 0;
    for ty in ["uint64", "int64"] {
        for op in [
            CompareOp::Eq,
            CompareOp::NotEq,
            CompareOp::Lt,
            CompareOp::Lte,
            CompareOp::Gt,
            CompareOp::Gte,
        ] {
            for reversed in [false, true] {
                for reference in [false, true] {
                    let case = format!("case{count}");
                    source.push_str(&format!(
                        "container {case} {{
                           leaf value {{ type {ty}; }}
                           leaf reference {{ type leafref {{ path '/ex:root/ex:{case}/ex:value'; }} }}
                           leaf chained {{ type leafref {{ path '/ex:root/ex:{case}/ex:reference'; }} }}
                         }}"
                    ));
                    let path = ConstraintExpr::Path(PathExpr {
                        anchor: PathAnchor::Current,
                        segments: vec![if reference { "chained" } else { "value" }.into()],
                    });
                    let literal = ConstraintExpr::Literal(Literal::Number(1));
                    let (left, right) = if reversed {
                        (literal, path)
                    } else {
                        (path, literal)
                    };
                    let expr = ConstraintExpr::Compare {
                        op,
                        left: Box::new(left),
                        right: Box::new(right),
                    };
                    let reason = format!("Constraint failed: {}", format_constraint_expr(&expr));
                    constraints.push(ConstraintBinding {
                        target_path: format!("/ex:root/ex:{case}"),
                        expr,
                        ..Default::default()
                    });
                    tests.push_str(&format!("#[test]\nfn {case}() {{\n"));
                    let limits = if ty == "uint64" {
                        vec![0_i128, 1, i128::from(i64::MAX) + 1, i128::from(u64::MAX)]
                    } else {
                        vec![i128::from(i64::MIN), 0, 1, i128::from(i64::MAX)]
                    };
                    for value in limits {
                        let (left, right) = if reversed { (1, value) } else { (value, 1) };
                        let accepts = match op {
                            CompareOp::Eq => left == right,
                            CompareOp::NotEq => left != right,
                            CompareOp::Lt => left < right,
                            CompareOp::Lte => left <= right,
                            CompareOp::Gt => left > right,
                            CompareOp::Gte => left >= right,
                        };
                        let expected = if accepts {
                            "Ok(())".to_string()
                        } else {
                            format!("Err(ValidationError::semantics({reason:?}))")
                        };
                        let value = value.to_string();
                        tests.push_str(&format!(
                            "assert_eq!(semantics(json!({{{:?}: {{\"value\": {value:?}, \"reference\": {value:?}, \"chained\": {value:?}}}}})), {expected});\n",
                            format!("example:{case}")
                        ));
                    }
                    tests.push_str("}\n");
                    count += 1;
                }
            }
        }
    }
    source.push_str("} }");
    let mut canonical = input(&source).to_canonical();
    canonical.constraints = constraints;
    compile_canonical_fixture("wide-integer-comparisons", &canonical, &tests, count);
}

#[test]
fn integer_comparisons_cover_current_count_and_mixed_width_paths() {
    use opc_yanggen::{FunctionCall, FunctionName};
    let mut canonical = input(
        r"module example { namespace 'urn:example'; prefix ex;
      container root {
        container current { leaf value { type uint64; } }
        container counts { leaf-list values { type uint16; } }
        container mixed { leaf unsigned { type uint64; } leaf signed { type int64; } }
      }
    }",
    )
    .to_canonical();
    let path = |name: &str| {
        ConstraintExpr::Path(PathExpr {
            anchor: PathAnchor::Current,
            segments: vec![name.into()],
        })
    };
    let current = ConstraintExpr::Function(FunctionCall {
        name: FunctionName::Current,
        args: vec![],
    });
    let count = ConstraintExpr::Function(FunctionCall {
        name: FunctionName::Count,
        args: vec![path("values")],
    });
    let mut tests = SEMANTIC_TEST_SUPPORT.to_string();
    for (name, target, left, right, op, cases) in [
        (
            "current",
            "/ex:root/ex:current/ex:value",
            current,
            ConstraintExpr::Literal(Literal::Number(i64::MAX)),
            CompareOp::Gt,
            vec![
                (
                    r#"{"example:current":{"value":"18446744073709551615"}}"#,
                    true,
                ),
                (
                    r#"{"example:current":{"value":"9223372036854775807"}}"#,
                    false,
                ),
            ],
        ),
        (
            "counts",
            "/ex:root/ex:counts",
            ConstraintExpr::Literal(Literal::Number(-1)),
            count,
            CompareOp::Lt,
            vec![
                (r#"{"example:counts":{"values":[0,1]}}"#, true),
                (r#"{"example:counts":{}}"#, true),
            ],
        ),
        (
            "mixed",
            "/ex:root/ex:mixed",
            path("unsigned"),
            path("signed"),
            CompareOp::Gt,
            vec![
                (
                    r#"{"example:mixed":{"unsigned":"18446744073709551615","signed":"9223372036854775807"}}"#,
                    true,
                ),
                (
                    r#"{"example:mixed":{"unsigned":"0","signed":"-9223372036854775808"}}"#,
                    true,
                ),
                (r#"{"example:mixed":{"unsigned":"0","signed":"0"}}"#, false),
                (r#"{"example:mixed":{"unsigned":"0"}}"#, false),
                (r#"{"example:mixed":{}}"#, false),
            ],
        ),
    ] {
        let expr = ConstraintExpr::Compare {
            op,
            left: Box::new(left),
            right: Box::new(right),
        };
        let reason = format!("Constraint failed: {}", format_constraint_expr(&expr));
        canonical.constraints.push(ConstraintBinding {
            target_path: target.into(),
            expr,
            ..Default::default()
        });
        tests.push_str(&format!("#[test]\nfn {name}() {{\n"));
        for (body, accepted) in cases {
            let expected = if accepted {
                "Ok(())".to_string()
            } else {
                format!("Err(ValidationError::semantics({reason:?}))")
            };
            tests.push_str(&format!(
                "assert_eq!(semantics(serde_json::from_str({body:?}).unwrap()), {expected});\n"
            ));
        }
        tests.push_str("}\n");
    }
    // json! is used by the shared fixture support and must remain exercised.
    tests.push_str("#[test]\nfn empty_configuration_is_valid() { assert_eq!(semantics(json!({})), Ok(())); }\n");
    compile_canonical_fixture("integer-comparison-operands", &canonical, &tests, 4);
}

mod comparison_guards {
    use super::{generate_rust, input};
    use opc_yanggen::{
        CanonicalInput, CompareOp, ConstraintBinding, ConstraintExpr, FunctionCall, FunctionName,
        Literal, PathAnchor, PathExpr,
    };

    fn comparison(target: &str, left: ConstraintExpr, right: ConstraintExpr) -> CanonicalInput {
        let mut canonical = input(
            r#"module n {
              namespace "urn:n"; prefix n;
              container root {
                leaf value { type uint8; }
                leaf label { type string; }
                leaf-list values { type uint8; }
              }
            }"#,
        )
        .to_canonical();
        canonical.constraints.push(ConstraintBinding {
            target_path: target.into(),
            expr: ConstraintExpr::Compare {
                op: CompareOp::Eq,
                left: Box::new(left),
                right: Box::new(right),
            },
            ..Default::default()
        });
        canonical
    }

    fn path(name: &str) -> ConstraintExpr {
        ConstraintExpr::Path(PathExpr {
            anchor: PathAnchor::Current,
            segments: vec![name.into()],
        })
    }

    fn number() -> ConstraintExpr {
        ConstraintExpr::Literal(Literal::Number(1))
    }

    #[test]
    fn integer_current_rejects_arguments_before_emission() {
        let current = |args| {
            ConstraintExpr::Function(FunctionCall {
                name: FunctionName::Current,
                args,
            })
        };
        generate_rust(&comparison("/n:root/n:value", current(vec![]), number())).unwrap();
        assert_eq!(
            generate_rust(&comparison(
                "/n:root/n:value",
                current(vec![number()]),
                number(),
            ))
            .unwrap_err()
            .message(),
            "current() expects no arguments"
        );
    }

    #[test]
    fn integer_comparison_rejects_a_leaf_list_operand() {
        generate_rust(&comparison("/n:root", path("value"), number())).unwrap();
        assert_eq!(
            generate_rust(&comparison("/n:root", path("values"), number()))
                .unwrap_err()
                .message(),
            "integer comparisons require scalar leaf operands"
        );
    }

    #[test]
    fn integer_comparison_rejects_a_mixed_scalar_operand() {
        generate_rust(&comparison("/n:root", path("value"), number())).unwrap();
        assert_eq!(
            generate_rust(&comparison("/n:root", path("label"), number()))
                .unwrap_err()
                .message(),
            "integer comparisons require integer leaf or number operands"
        );
    }
}

#[test]
fn case_distinct_pattern_helpers_compile_and_keep_their_own_constraints() {
    compile_fixture(
        "case-distinct-patterns",
        r"module example { yang-version 1.1; namespace 'urn:example'; prefix ex;
          container root {
            container a { leaf code { type string { pattern '[0-9]+'; } } }
            container A { leaf code { type string { pattern '[a-z]+'; } } }
            leaf digit-reference { type leafref { path '/ex:root/ex:a/ex:code'; } }
            leaf letter-reference { type leafref { path '/ex:root/ex:A/ex:code'; } }
          }
        }",
        r#"
use generated_test::types::Root;
use opc_config_model::OpcConfig;
use serde_json::json;
#[test]
fn case_distinct_paths_use_distinct_patterns() {
    let valid: Root = serde_json::from_value(json!({
        "example:a": {"code": "123"}, "example:A": {"code": "abc"},
        "example:digit-reference": "123", "example:letter-reference": "abc"
    })).unwrap();
    assert_eq!(valid.validate_syntax(), Ok(()));
    for invalid in [
        json!({"example:a": {"code": "abc"}}),
        json!({"example:A": {"code": "123"}}),
        json!({"example:digit-reference": "abc"}),
        json!({"example:letter-reference": "123"}),
    ] {
        assert_eq!(serde_json::from_value::<Root>(invalid).unwrap_err().to_string(),
                   "string violates YANG constraints");
    }
}

"#,
        1,
    );
}

#[test]
fn direct_patch_admission_rejects_before_mutating_a_scalar_or_leaf_list() {
    let canonical = input(
        r"module example { namespace 'urn:example'; prefix ex;
      container root {
        leaf code { type string { pattern '[a-z]+'; } }
        leaf-list labels { type string { length '3'; } }
      }
    }",
    )
    .to_canonical();
    let mut files = generate_rust(&canonical).unwrap();
    files
        .get_mut("patch.rs")
        .unwrap()
        .push_str(include_str!("../fixtures/patch_admission_test.rs"));
    compile_generated_fixture("direct-string-admission", files, "", 1);
}

#[test]
fn invalid_string_defaults_isolate_length_from_pattern() {
    for (restriction, accepted, rejected) in [
        ("length '3';", "abc", "abcd"),
        ("pattern '[0-9]+';", "123", "abc"),
        ("length '3'; pattern '[0-9]+';", "123", "1234"),
        ("length '3'; pattern '[0-9]+';", "123", "abc"),
    ] {
        for (value, valid) in [(accepted, true), (rejected, false)] {
            let source = format!(
                "module example {{ namespace 'urn:example'; prefix ex; container root {{
                   leaf value {{ type string {{ {restriction} }} default '{value}'; }}
                 }} }}"
            );
            let result = generate_rust(&input(&source).to_canonical());
            if valid {
                result.unwrap();
            } else {
                assert_eq!(
                    result.unwrap_err().message(),
                    "string default violates YANG constraints"
                );
            }
        }
    }
}

#[test]
fn integer_defaults_isolate_declared_range_from_type_bounds() {
    for ty in [
        "uint8", "uint16", "uint32", "uint64", "int8", "int16", "int32", "int64",
    ] {
        for (value, valid) in [("1", true), ("2", false)] {
            let source = format!(
                "module example {{ namespace 'urn:example'; prefix ex; container root {{
                   leaf value {{ type {ty} {{ range '0..1'; }} default '{value}'; }}
                 }} }}"
            );
            let result = generate_rust(&input(&source).to_canonical());
            if valid {
                result.unwrap();
            } else {
                assert_eq!(result.unwrap_err().message(),
                    "integer default at /ex:root/ex:value is invalid or outside its type or declared range");
            }
        }
    }
}

#[test]
fn raw_length_intervals_reject_overlap_without_other_invalid_restrictions() {
    let original = input(
        "module example { namespace 'urn:example'; prefix ex; container root {
           leaf value { type string { length '1..3 | 5..7'; } }
         } }",
    )
    .to_canonical();
    generate_rust(&original).unwrap();
    for intervals in [
        vec![(1, 3), (3, 7)],
        vec![(1, 5), (2, 3)],
        vec![(5, 7), (1, 3)],
    ] {
        let mut changed = original.clone();
        changed
            .nodes
            .iter_mut()
            .find(|n| n.path == "/ex:root/ex:value")
            .unwrap()
            .type_ref = Some(TypeRef::RestrictedString {
            length: intervals
                .into_iter()
                .map(|(min, max)| StringLengthInterval { min, max })
                .collect(),
            patterns: vec![],
        });
        assert_eq!(
            generate_rust(&changed).unwrap_err().message(),
            "invalid or excessive string restrictions"
        );
    }
}

#[test]
fn raw_integer_ranges_reject_only_bounds_outside_each_storage_type() {
    for (ty, min, max) in [
        ("uint8", 0_i128, 255_i128),
        ("uint16", 0, 65535),
        ("uint32", 0, 4294967295),
        ("uint64", 0, i128::from(u64::MAX)),
        ("int8", -128, 127),
        ("int16", -32768, 32767),
        ("int32", -2147483648, 2147483647),
        ("int64", i128::from(i64::MIN), i128::from(i64::MAX)),
    ] {
        let source = format!(
            "module example {{ namespace 'urn:example'; prefix ex; container root {{
                leaf value {{ type {ty} {{ range 'min..max'; }} }}
             }} }}"
        );
        let original = input(&source).to_canonical();
        generate_rust(&original).unwrap();
        for (low, high) in [(min - 1, min), (max, max + 1)] {
            let mut changed = original.clone();
            changed
                .nodes
                .iter_mut()
                .find(|n| n.path == "/ex:root/ex:value")
                .unwrap()
                .numeric_range = vec![NumericRangeInterval {
                min: low,
                max: high,
            }];
            assert_eq!(
                generate_rust(&changed).unwrap_err().message(),
                "numeric range metadata at /ex:root/ex:value exceeds the base integer type bounds"
            );
        }
    }
}

#[test]
fn source_pattern_count_and_modifier_children_have_exact_diagnostics() {
    for (restriction, reason) in [
        (
            "pattern 'a';".repeat(65),
            "string type exceeds the 64-pattern limit",
        ),
        (
            "pattern 'a' { modifier invert-match { description 'nested'; } }".into(),
            "pattern modifier must be one invert-match statement",
        ),
    ] {
        let source = format!(
            "module example {{ namespace 'urn:example'; prefix ex; container root {{
                leaf value {{ type string {{ {restriction} }} }}
             }} }}"
        );
        let error = opc_yanggen::generation_input_from_yang_sources(
            "example",
            &[opc_yanggen::YangSource::new("example.yang", source)],
        )
        .unwrap_err();
        assert_eq!(
            error.code,
            opc_yanggen::DiagnosticCode::YangSourceSyntaxError
        );
        assert_eq!(error.message, reason);
        assert!(error.source.is_some());
    }
    let accepted = format!(
        "module example {{ namespace 'urn:example'; prefix ex; container root {{
            leaf value {{ type string {{ {} }} }}
         }} }}",
        "pattern 'a';".repeat(64)
    );
    generate_rust(&input(&accepted).to_canonical()).unwrap();
}

#[test]
fn raw_pattern_count_accepts_the_limit_and_refuses_one_more() {
    let mut canonical = input(
        "module example { namespace 'urn:example'; prefix ex; container root {
            leaf value { type string; }
         } }",
    )
    .to_canonical();
    for (count, valid) in [(64, true), (65, false)] {
        canonical
            .nodes
            .iter_mut()
            .find(|n| n.path == "/ex:root/ex:value")
            .unwrap()
            .type_ref = Some(TypeRef::RestrictedString {
            length: vec![],
            patterns: vec![
                StringPattern {
                    expression: "a".into(),
                    invert_match: false
                };
                count
            ],
        });
        let result = generate_rust(&canonical);
        if valid {
            result.unwrap();
        } else {
            assert_eq!(
                result.unwrap_err().message(),
                "invalid or excessive string restrictions"
            );
        }
    }
}
