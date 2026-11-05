use super::{compile_canonical_fixture, input};
use opc_yanggen::{generation_input_from_yang_sources, rust::generate_rust, YangSource};

#[test]
fn generated_decimal64_is_exact_across_interfaces() {
    use opc_yanggen::{
        CompareOp, ConstraintBinding, ConstraintExpr, Literal, PathAnchor, PathExpr,
    };
    let mut canonical = input(include_str!("../fixtures/decimal64.yang")).to_canonical();
    // Must/when source lowering is explicitly unsupported; exercise the public IR contract.
    for module in &mut canonical.schema_modules {
        module.source_text = None;
    }
    canonical.constraints.push(ConstraintBinding {
        target_path: "/d:root/d:xpath-number".into(),
        kind: Some("must".into()),
        expr: ConstraintExpr::Compare {
            op: CompareOp::Eq,
            left: Box::new(ConstraintExpr::Path(PathExpr {
                anchor: PathAnchor::Current,
                segments: vec![],
            })),
            right: Box::new(ConstraintExpr::Literal(Literal::Number(900719925474099))),
        },
        ..Default::default()
    });
    let mut current = canonical.constraints[0].clone();
    if let ConstraintExpr::Compare { left, .. } = &mut current.expr {
        **left = ConstraintExpr::Function(opc_yanggen::FunctionCall {
            name: opc_yanggen::FunctionName::Current,
            args: vec![],
        });
    }
    canonical.constraints.push(current);
    compile_canonical_fixture(
        "decimal64",
        &canonical,
        include_str!("../fixtures/decimal64_test.rs"),
        6,
    );
}

#[test]
fn decimal64_fraction_digits_are_required_unique_and_bounded() {
    for statements in [
        "",
        "fraction-digits 0;",
        "fraction-digits 19;",
        "fraction-digits -1;",
        "fraction-digits two;",
        "fraction-digits 2; fraction-digits 3;",
    ] {
        let source = format!("module example {{ namespace 'urn:example'; prefix ex; container root {{ leaf x {{ type decimal64 {{ {statements} }} }} }} }}");
        let result = generation_input_from_yang_sources(
            "example",
            &[YangSource::new("example.yang", source)],
        );
        assert!(
            result.is_err(),
            "invalid fraction-digits accepted: {statements}"
        );
    }
}

#[test]
fn decimal64_defaults_and_ir_cannot_bypass_scale() {
    let source = "module example { namespace 'urn:example'; prefix ex; container root { leaf x { type decimal64 { fraction-digits 2; } default '1.23'; } } }";
    for bad in [
        "1.234",
        "NaN",
        "inf",
        "1e1",
        "92233720368547758.08",
        "-92233720368547758.09",
    ] {
        let parsed = input(&source.replace("1.23", bad));
        assert!(
            generate_rust(&parsed.to_canonical()).is_err(),
            "invalid default accepted: {bad}"
        );
        assert!(opc_yanggen::rust::types::generate(&parsed.to_canonical()).is_err());
    }
    let digest = |source: &str| {
        let mut parsed = input(source);
        parsed.lockfile.modules.clear();
        for module in &mut parsed.schema_modules {
            module.source_text = None;
        }
        opc_yanggen::emit::schema_digest(&parsed)
    };
    assert_ne!(
        digest(source),
        digest(&source.replace("fraction-digits 2", "fraction-digits 3"))
    );
    let parsed = input(source);
    let roundtrip: opc_yanggen::GenerationInput =
        serde_json::from_value(serde_json::to_value(&parsed).unwrap()).unwrap();
    assert_eq!(parsed.nodes, roundtrip.nodes);
    for scale in [0, 19, 255] {
        let mut canonical = parsed.to_canonical();
        for module in &mut canonical.schema_modules {
            module.source_text = None;
        }
        let leaf = canonical
            .nodes
            .iter_mut()
            .find(|node| node.path.ends_with(":x"))
            .unwrap();
        leaf.type_ref = Some(opc_yanggen::TypeRef::Decimal64 {
            fraction_digits: scale,
        });
        assert!(generate_rust(&canonical).is_err());
    }
}
