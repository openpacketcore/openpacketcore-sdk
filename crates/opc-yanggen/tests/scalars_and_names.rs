mod common;
#[path = "scalars_and_names/regressions.rs"]
mod regressions;

use opc_yanggen::{generation_input_from_yang_sources, rust::generate_rust, YangSource};
use std::{fs, path::Path, process::Command};

fn input(source: &str) -> opc_yanggen::GenerationInput {
    generation_input_from_yang_sources("example", &[YangSource::new("example.yang", source)])
        .expect("ordinary YANG scalar restrictions must ingest")
}

#[test]
fn source_supports_all_integer_widths_and_exact_ranges() {
    for (ty, min, max) in [
        ("uint8", "0", "255"),
        ("uint16", "0", "65535"),
        ("uint32", "0", "4294967295"),
        ("uint64", "0", "18446744073709551615"),
        ("int8", "-128", "127"),
        ("int16", "-32768", "32767"),
        ("int32", "-2147483648", "2147483647"),
        ("int64", "-9223372036854775808", "9223372036854775807"),
    ] {
        let source = format!("module example {{ namespace 'urn:example'; prefix ex; container root {{ leaf value {{ type {ty} {{ range 'min..max'; }} }} }} }}");
        let parsed = input(&source);
        let leaf = parsed
            .nodes
            .iter()
            .find(|n| n.kind == opc_yanggen::SchemaNodeKind::Leaf)
            .unwrap();
        assert_eq!(serde_json::to_value(&leaf.type_ref).unwrap()["type"], ty);
        assert_eq!(leaf.numeric_range[0].min.to_string(), min);
        assert_eq!(leaf.numeric_range[0].max.to_string(), max);
        let json = serde_json::to_value(&parsed).unwrap();
        assert_eq!(
            serde_json::from_value::<opc_yanggen::GenerationInput>(json)
                .unwrap()
                .nodes,
            parsed.nodes
        );
        let invalid = source.replace(
            "min..max",
            &format!("{min}..{}", max.parse::<i128>().unwrap() + 1),
        );
        let error = generation_input_from_yang_sources(
            "example",
            &[YangSource::new("example.yang", invalid)],
        )
        .unwrap_err();
        assert_eq!(
            error.code,
            opc_yanggen::DiagnosticCode::YangSourceSyntaxError
        );
        assert_eq!(
            error.message,
            "range interval exceeds the base integer type bounds"
        );
        assert!(error.source.is_some());
    }
}

#[test]
fn repeated_nested_names_generate_distinct_types() {
    let parsed = input(
        r#"module example { namespace "urn:example"; prefix ex;
      container root {
        container left { container stats { leaf enabled { type boolean; } } }
        container right { container stats { leaf count { type uint32; } } }
      }
    }"#,
    );
    let files = generate_rust(&parsed.to_canonical()).unwrap();
    assert!(files["types.rs"].contains("struct LeftStats"));
    assert!(files["types.rs"].contains("struct RightStats"));
    assert!(files["types.rs"].contains("struct Root"));
}

#[test]
fn source_accepts_string_length_reproduction() {
    let parsed = input(
        r#"module example { yang-version 1.1; namespace "urn:example:yang:example"; prefix ex; revision 2026-10-12;
      container example { leaf node-name { type string { length "1..150"; } } }
    }"#,
    );
    assert!(generate_rust(&parsed.to_canonical()).is_ok());
}

#[test]
fn source_accepts_string_pattern_reproduction() {
    let parsed = input(
        r#"module example { yang-version 1.1; namespace "urn:example:yang:example"; prefix ex; revision 2026-10-12;
      container example { leaf mcc { type string { pattern "[0-9]{3}"; } } }
    }"#,
    );
    assert!(generate_rust(&parsed.to_canonical()).is_ok());
}

#[test]
fn generated_integer_and_nested_name_contract() {
    compile_fixture(
        "integer-scalars",
        include_str!("fixtures/integers.yang"),
        include_str!("fixtures/integers_test.rs"),
        7,
    );
}

#[test]
fn generated_string_constraints_contract() {
    compile_fixture(
        "string-scalars",
        include_str!("fixtures/strings.yang"),
        include_str!("fixtures/strings_test.rs"),
        9,
    );
}

#[test]
fn legacy_constructs_keep_every_generated_file_byte_identical() {
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;
    use std::fmt::Write;
    // Captured from d50c92ad1 with its exact locked dependency versions.
    let expected: BTreeMap<String, String> =
        serde_json::from_str(include_str!("fixtures/legacy_constructs_digests.json")).unwrap();
    let parsed = generation_input_from_yang_sources(
        "compatibility",
        &[YangSource::new(
            "legacy_constructs.yang",
            include_str!("fixtures/legacy_constructs.yang"),
        )],
    )
    .unwrap();
    let files = generate_rust(&parsed.to_canonical()).unwrap();
    let actual: BTreeMap<_, _> = files
        .into_iter()
        .map(|(file, content)| {
            let mut hash = String::new();
            for byte in Sha256::digest(content.as_bytes()) {
                write!(hash, "{byte:02x}").unwrap();
            }
            (file, hash)
        })
        .collect();
    assert_eq!(actual.len(), 13);
    assert_eq!(actual, expected);
}

#[test]
fn string_restrictions_survive_ir_and_change_the_digest() {
    use opc_yanggen::{schema_digest, TypeRef};
    let source = include_str!("fixtures/strings.yang");
    let original = input(source);
    let roundtrip: opc_yanggen::GenerationInput =
        serde_json::from_value(serde_json::to_value(&original).unwrap()).unwrap();
    assert_eq!(roundtrip.nodes, original.nodes);
    let label = original
        .nodes
        .iter()
        .find(|n| n.path == "/ex:root/ex:label")
        .unwrap();
    match label.type_ref.as_ref().unwrap() {
        TypeRef::RestrictedString { length, patterns } => {
            assert_eq!(
                length.iter().map(|r| (r.min, r.max)).collect::<Vec<_>>(),
                [(1, 3), (5, 5)]
            );
            assert!(patterns.is_empty());
        }
        other => panic!("restriction was lost: {other:?}"),
    }
    for changed in [
        source.replace("1..3 | 5", "1..4 | 6"),
        source.replacen("[0-9]{3}", "[0-9]{4}", 1),
        source.replace("pattern 'bad' { modifier invert-match; }", "pattern 'bad';"),
    ] {
        assert_ne!(schema_digest(&original), schema_digest(&input(&changed)));
    }
    // Diagnostic-only source text cannot hide an IR change from the digest.
    let mut changed = original.clone();
    let word = changed
        .nodes
        .iter_mut()
        .find(|n| n.path == "/ex:root/ex:word")
        .unwrap();
    let Some(TypeRef::RestrictedString { patterns, .. }) = word.type_ref.as_mut() else {
        panic!("missing restriction")
    };
    assert!(patterns[1].invert_match);
    patterns[1].invert_match = false;
    assert_ne!(schema_digest(&original), schema_digest(&changed));
}

#[test]
fn malformed_and_unsupported_string_restrictions_fail_closed() {
    for (restriction, reason) in [
        (
            "length '-1';",
            "range interval exceeds the base integer type bounds",
        ),
        (
            "length '5..1';",
            "range lower bound must not exceed upper bound",
        ),
        (
            "length '2..4 | 4..7';",
            "string length intervals must be ascending and disjoint",
        ),
        (
            "length '5 | 1';",
            "string length intervals must be ascending and disjoint",
        ),
        (
            "length '1'; length '2';",
            "duplicate string length statement",
        ),
        (
            "length '18446744073709551616';",
            "range interval exceeds the base integer type bounds",
        ),
        ("pattern '(?i)secret';", "invalid XSD regular expression"),
        ("pattern '[z-a]';", "invalid XSD regular expression"),
        ("pattern 'a+?';", "invalid XSD regular expression"),
        (
            "pattern 'a' { modifier invalid; }",
            "pattern modifier must be one invert-match statement",
        ),
        (
            "pattern 'a' { modifier invert-match; modifier invert-match; }",
            "pattern modifier must be one invert-match statement",
        ),
    ] {
        let source = format!("module example {{ namespace 'urn:example'; prefix ex; container root {{ leaf value {{ type string {{ {restriction} }} }} }} }}");
        let error = generation_input_from_yang_sources(
            "example",
            &[YangSource::new("example.yang", source)],
        )
        .unwrap_err();
        assert_eq!(
            error.code,
            opc_yanggen::DiagnosticCode::YangSourceSyntaxError,
            "{restriction}: {error:?}"
        );
        assert_eq!(error.message, reason);
        assert!(error.source.is_some());
    }
    for pattern in [r"\i\c*", r"\p{IsBasicLatin}"] {
        let source = format!("module example {{ namespace 'urn:example'; prefix ex; container root {{ leaf value {{ type string {{ pattern '{pattern}'; }} }} }} }}");
        let error = generation_input_from_yang_sources(
            "example",
            &[YangSource::new("example.yang", source)],
        )
        .unwrap_err();
        assert_eq!(
            error.code,
            opc_yanggen::DiagnosticCode::UnsupportedYangFeature
        );
        assert_eq!(
            error.message,
            "unsupported XSD XML-name or Unicode-block escape"
        );
    }
}

#[test]
fn invalid_defaults_and_raw_ir_restrictions_are_rejected() {
    use opc_yanggen::{StringLengthInterval, StringPattern, TypeRef};
    for (ty, value) in [
        ("uint64", "18446744073709551616"),
        ("int8", "-129"),
        ("string { length '3'; pattern '[0-9]+'; }", "private-value"),
    ] {
        let semicolon = if ty.ends_with('}') { "" } else { ";" };
        let source = format!("module example {{ namespace 'urn:example'; prefix ex; container root {{ leaf value {{ type {ty}{semicolon} default '{value}'; }} }} }}");
        let error = generate_rust(&input(&source).to_canonical()).unwrap_err();
        assert!(error.message().contains("default"));
        assert!(!error.message().contains(value));
        assert_eq!(
            error.message(),
            if ty.starts_with("string") {
                "string default violates YANG constraints"
            } else {
                "integer default at /ex:root/ex:value is invalid or outside its type or declared range"
            }
        );
    }
    let original = input(include_str!("fixtures/strings.yang")).to_canonical();
    for restricted in [
        TypeRef::RestrictedString {
            length: vec![StringLengthInterval { min: 5, max: 1 }],
            patterns: vec![],
        },
        TypeRef::RestrictedString {
            length: vec![],
            patterns: vec![StringPattern {
                expression: "(?i)private-value".into(),
                invert_match: false,
            }],
        },
        TypeRef::RestrictedString {
            length: vec![],
            patterns: vec![
                StringPattern {
                    expression: "a".into(),
                    invert_match: false
                };
                65
            ],
        },
    ] {
        let reason = if matches!(&restricted, TypeRef::RestrictedString { patterns, .. } if patterns.first().is_some_and(|pattern| pattern.expression.starts_with("(?i)")))
        {
            "invalid XSD regular expression"
        } else {
            "invalid or excessive string restrictions"
        };
        let mut changed = original.clone();
        changed
            .nodes
            .iter_mut()
            .find(|n| n.path == "/ex:root/ex:code")
            .unwrap()
            .type_ref = Some(restricted);
        let error = generate_rust(&changed).unwrap_err();
        assert!(!error.message().contains("private-value"));
        assert_eq!(error.message(), reason);
    }
}

#[test]
fn constrained_models_have_deterministic_cli_check() {
    for source in [
        include_str!("fixtures/strings.yang"),
        include_str!("fixtures/integers.yang"),
    ] {
        let scratch = tempfile::tempdir().unwrap();
        let yang = scratch.path().join("example.yang");
        let generated = scratch.path().join("generated");
        fs::write(&yang, source).unwrap();
        let args = [
            "generate-rust",
            "--profile",
            "example",
            "--yang",
            yang.to_str().unwrap(),
            "--out-dir",
            generated.to_str().unwrap(),
        ];
        let result = Command::new(env!("CARGO_BIN_EXE_opc-yanggen"))
            .args(args)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let result = Command::new(env!("CARGO_BIN_EXE_opc-yanggen"))
            .args(args)
            .arg("--check")
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let file = generated.join(if source.contains("pattern") {
            "strings.rs"
        } else {
            "types.rs"
        });
        let original = fs::read(&file).unwrap();
        fs::write(&file, "changed generated source").unwrap();
        let result = Command::new(env!("CARGO_BIN_EXE_opc-yanggen"))
            .args(args)
            .arg("--check")
            .output()
            .unwrap();
        assert!(!result.status.success());
        assert_eq!(result.status.code(), Some(1));
        let diagnostic: serde_json::Value = serde_json::from_slice(&result.stderr).unwrap();
        assert_eq!(diagnostic["status"], "error");
        assert_eq!(diagnostic["diagnostic"]["code"], "yang-source-mismatch");
        assert_eq!(
            diagnostic["diagnostic"]["message"],
            format!(
                "generated Rust artifact `{}` differs from expected output",
                file.file_name().unwrap().to_str().unwrap()
            )
        );
        assert_eq!(
            fs::read_to_string(&file).unwrap(),
            "changed generated source"
        );
        fs::write(&file, original).unwrap();
        let result = Command::new(env!("CARGO_BIN_EXE_opc-yanggen"))
            .args(args)
            .arg("--check")
            .output()
            .unwrap();
        assert!(result.status.success());
    }
}

fn compile_fixture(name: &str, source: &str, tests: &str, expected_tests: usize) {
    let parsed = input(source);
    let canonical = parsed.to_canonical();
    compile_canonical_fixture(name, &canonical, tests, expected_tests);
}

fn compile_canonical_fixture(
    name: &str,
    canonical: &opc_yanggen::CanonicalInput,
    tests: &str,
    expected_tests: usize,
) {
    let files = generate_rust(canonical).unwrap();
    let mut reversed = canonical.clone();
    reversed.nodes.reverse();
    assert_eq!(files, generate_rust(&reversed).unwrap());
    compile_generated_fixture(name, files, tests, expected_tests);
}

fn compile_generated_fixture(
    name: &str,
    files: std::collections::HashMap<String, String>,
    tests: &str,
    expected_tests: usize,
) {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let scratch = tempfile::tempdir().unwrap();
    fs::create_dir(scratch.path().join("src")).unwrap();
    fs::create_dir(scratch.path().join("tests")).unwrap();
    for (file, content) in files {
        let file = if file == "mod.rs" {
            "lib.rs".to_string()
        } else {
            file
        };
        fs::write(scratch.path().join("src").join(file), content).unwrap();
    }
    fs::write(scratch.path().join("tests/contract.rs"), tests).unwrap();
    let deps: String = [
        "opc-config-model",
        "opc-types",
        "opc-data-governance",
        "opc-mgmt-schema",
        "opc-mgmt-limits",
        "opc-redaction",
        "opc-gnmi-server",
    ]
    .iter()
    .map(|name| {
        format!(
            "{name} = {{ path = {:?} }}\n",
            workspace.join("crates").join(name)
        )
    })
    .collect();
    fs::write(
        scratch.path().join("Cargo.toml"),
        format!(
            r#"[workspace]
[package]
name = "yanggen-{name}-test"
version = "0.1.0"
edition = "2021"
[lib]
name = "generated_test"
[dependencies]
serde = {{ version = "1.0", features = ["derive"] }}
serde_json = "1.0"
time = "={}"
{deps}"#,
            common::locked_version(workspace, "time")
        ),
    )
    .unwrap();
    let output = Command::new("cargo")
        .args(["test", "--", "--test-threads=4"])
        .env("RUSTFLAGS", "-Dwarnings")
        .env(
            "CARGO_TARGET_DIR",
            workspace.join("target/yanggen-generated"),
        )
        .current_dir(scratch.path())
        .output()
        .unwrap();
    use std::io::Write;
    std::io::stdout().write_all(&output.stdout).unwrap();
    std::io::stderr().write_all(&output.stderr).unwrap();
    assert!(output.status.success(), "generated {name} fixture failed");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(
        stdout
            .lines()
            .filter(|l| l.starts_with("test ") && l.ends_with(" ... ok"))
            .count(),
        expected_tests
    );
}
