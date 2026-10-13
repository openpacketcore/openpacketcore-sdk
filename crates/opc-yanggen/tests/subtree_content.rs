mod common;

use std::fs;
use std::process::Command;

use opc_yanggen::rust::generate_rust;
use opc_yanggen::{generation_input_from_yang_sources, CanonicalInput, YangSource};

#[test]
fn generated_subtree_content_service() {
    let source = YangSource::new(
        "subtree-content.yang",
        include_str!("fixtures/subtree-content.yang"),
    );
    let input = generation_input_from_yang_sources("subtree-content", &[source]).unwrap();
    let ir = opc_yanggen::compile(&input).unwrap();
    let canonical = CanonicalInput {
        profile: opc_yanggen::emit::CanonicalProfile {
            generation: "subtree-content".into(),
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
    };
    let project = tempfile::tempdir().unwrap();
    let src = project.path().join("src");
    fs::create_dir(&src).unwrap();
    for (name, contents) in generate_rust(&canonical).unwrap() {
        fs::write(
            src.join(if name == "mod.rs" { "lib.rs" } else { &name }),
            contents,
        )
        .unwrap();
    }
    let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let mut manifest = format!(
        "[package]\nname = \"subtree-content-service\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\n[dependencies]\nserde = {{ version = \"1\", features = [\"derive\"] }}\nserde_json = \"1\"\ntime = \"={}\"\ntokio = {{ version = \"1\", features = [\"macros\", \"rt\", \"time\", \"io-util\", \"sync\"] }}\ntracing = \"0.1\"\ntracing-subscriber = {{ version = \"0.3\", features = [\"fmt\"] }}\n",
        common::locked_version(workspace, "time"),
    );
    for name in [
        "opc-config-model",
        "opc-config-bus",
        "opc-types",
        "opc-data-governance",
        "opc-mgmt-schema",
        "opc-redaction",
        "opc-gnmi-server",
        "opc-netconf-server",
        "opc-mgmt-authz",
        "opc-mgmt-audit",
        "opc-mgmt-limits",
        "opc-mgmt-opstate",
        "opc-nacm",
    ] {
        manifest.push_str(&format!(
            "{name} = {{ path = {:?} }}\n",
            workspace.join("crates").join(name),
        ));
    }
    manifest.push_str("\n[workspace]\n");
    fs::write(project.path().join("Cargo.toml"), manifest).unwrap();
    let tests = project.path().join("tests");
    fs::create_dir(&tests).unwrap();
    fs::write(
        tests.join("content.rs"),
        include_str!("fixtures/subtree_content_test.rs"),
    )
    .unwrap();
    let status = Command::new("cargo")
        .args([
            "test",
            "--quiet",
            "--test",
            "content",
            "--",
            "--test-threads=1",
        ])
        .env("RUSTFLAGS", "-Dwarnings")
        .current_dir(project.path())
        .status()
        .unwrap();
    assert!(
        status.success(),
        "generated authenticated subtree content tests failed"
    );
}
