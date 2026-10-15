mod common;

use std::collections::BTreeMap;
use std::fmt::Write;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use opc_yanggen::{generation_input_from_yang_sources, rust::generate_rust, YangSource};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

#[test]
fn pinned_models_without_state_lists_pass_strict_clippy() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let scratch = tempfile::tempdir().unwrap();
    let directory = scratch.path();
    let src = directory.join("src");
    fs::create_dir(&src).unwrap();
    let evidence = std::env::var_os("OPC_YANGGEN_PINNED_LINT_EVIDENCE_DIR").map(PathBuf::from);
    if let Some(evidence) = &evidence {
        fs::create_dir_all(evidence).unwrap();
    }
    let system_pins: BTreeMap<String, BTreeMap<String, String>> =
        serde_json::from_str(include_str!("fixtures/system_ordered_digests.json")).unwrap();
    let legacy_pins: BTreeMap<String, String> =
        serde_json::from_str(include_str!("fixtures/legacy_constructs_digests.json")).unwrap();
    let models = [
        (
            "legacy_constructs",
            "compatibility",
            "legacy_constructs.yang",
            include_str!("fixtures/legacy_constructs.yang"),
            &legacy_pins,
        ),
        (
            "system_ordered_base",
            "review",
            "opc-test.yang",
            include_str!("fixtures/system_ordered_base.yang").trim_start(),
            &system_pins["base"],
        ),
        (
            "system_ordered_comments",
            "review",
            "opc-test.yang",
            include_str!("fixtures/system_ordered_comments.yang").trim_start(),
            &system_pins["comments"],
        ),
    ];
    let mut lib = String::new();
    let mut sources = BTreeMap::new();
    for (name, profile, filename, source, expected) in models {
        let input =
            generation_input_from_yang_sources(profile, &[YangSource::new(filename, source)])
                .unwrap();
        let generated = generate_rust(&input.to_canonical()).unwrap();
        let actual: BTreeMap<_, _> = generated
            .iter()
            .map(|(file, content)| {
                let mut digest = String::with_capacity(64);
                for byte in Sha256::digest(content.as_bytes()) {
                    write!(digest, "{byte:02x}").unwrap();
                }
                (file.clone(), digest)
            })
            .collect();
        assert_eq!(actual.len(), 13, "all generated files for {name}");
        assert_eq!(
            &actual, expected,
            "compile the exact pinned files for {name}"
        );
        sources.insert(name, actual);
        let module = src.join(name);
        fs::create_dir(&module).unwrap();
        for (file, content) in generated {
            fs::write(module.join(&file), &content).unwrap();
            if let Some(evidence) = &evidence {
                let output = evidence.join("generated").join(name);
                fs::create_dir_all(&output).unwrap();
                fs::write(output.join(file), content).unwrap();
            }
        }
        lib.push_str(&format!("pub mod {name};\n"));
    }
    fs::write(src.join("lib.rs"), lib).unwrap();
    let dependencies = [
        "opc-config-model",
        "opc-types",
        "opc-data-governance",
        "opc-mgmt-schema",
        "opc-mgmt-limits",
        "opc-redaction",
        "opc-gnmi-server",
        "opc-netconf-server",
    ]
    .into_iter()
    .map(|name| {
        format!(
            "{name} = {{ path = {:?} }}\n",
            workspace.join("crates").join(name)
        )
    })
    .collect::<String>();
    fs::write(
        directory.join("Cargo.toml"),
        format!(
            r#"[package]
name = "generated-pinned-lints"
version = "0.1.0"
edition = "2021"

[workspace]

[dependencies]
serde = {{ version = "1.0", features = ["derive"] }}
serde_json = "1.0"
time = "={}"
{dependencies}"#,
            common::locked_version(workspace, "time"),
        ),
    )
    .unwrap();
    let args = [
        "clippy",
        "--all-targets",
        "--message-format=json",
        "--",
        "-D",
        "warnings",
    ];
    let output = Command::new("cargo")
        .current_dir(directory)
        .env(
            "CARGO_TARGET_DIR",
            workspace.join("target/yanggen-generated"),
        )
        .env_remove("RUSTFLAGS")
        .args(args)
        .output()
        .unwrap();
    if let Some(evidence) = &evidence {
        fs::write(evidence.join("clippy.stdout"), &output.stdout).unwrap();
        fs::write(evidence.join("clippy.stderr"), &output.stderr).unwrap();
        fs::write(
            evidence.join("result.json"),
            serde_json::to_vec_pretty(&json!({
                "source_sha256": sources,
                "command": args,
                "exit_code": output.status.code(),
            }))
            .unwrap(),
        )
        .unwrap();
    }
    let diagnostics: Vec<Value> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|message| message["reason"] == "compiler-message")
        .map(|message| message["message"].clone())
        .collect();
    assert!(
        output.status.success(),
        "strict Clippy failed for pinned models:\n{}\n{}",
        diagnostics
            .iter()
            .filter_map(|message| message["rendered"].as_str())
            .collect::<Vec<_>>()
            .join("\n"),
        String::from_utf8_lossy(&output.stderr),
    );
}
