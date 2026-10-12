mod common;

use opc_yanggen::{generation_input_from_yang_sources, rust::generate_rust, YangSource};
use std::fs;
use std::path::Path;
use std::process::Command;

const MINIMAL_STATE: &str = r#"
module minimal-state {
  yang-version 1.1;
  namespace "urn:example:minimal-state";
  prefix ms;
  revision 2026-10-12;
  container state {
    config false;
    list error {
      key "reason";
      leaf reason { type string; }
      leaf count { type uint32; }
    }
  }
}
"#;

const MIXED_STATE: &str = r#"
module mixed-state {
  yang-version 1.1;
  namespace "urn:example:mixed-state";
  prefix mx;
  revision 2026-10-12;
  container root {
    leaf hostname { type string; }
    container state {
      config false;
      list error {
        key "reason";
        leaf reason { type string; }
        leaf count { type uint32; }
      }
    }
  }
}
"#;

#[test]
fn generated_config_false_keyed_lists_compile_and_pass_clippy() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let scratch = tempfile::tempdir().unwrap();
    let src = scratch.path().join("src");
    fs::create_dir(&src).unwrap();
    let mut lib = String::new();
    for (name, source) in [
        ("minimal", MINIMAL_STATE),
        ("mixed", MIXED_STATE),
        ("keys", include_str!("fixtures/config_false_lists.yang")),
    ] {
        // Use an already supported counter type so this regression isolates
        // state-list emission from support for additional integer widths.
        let input = generation_input_from_yang_sources(
            "config-false-lists",
            &[YangSource::new(format!("{name}.yang"), source)],
        )
        .unwrap();
        let output = src.join(name);
        fs::create_dir(&output).unwrap();
        for (file, content) in generate_rust(&input.to_canonical()).unwrap() {
            fs::write(output.join(file), content).unwrap();
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
        scratch.path().join("Cargo.toml"),
        format!(
            r#"[package]
name = "generated-config-false-test"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = {{ version = "1.0", features = ["derive"] }}
serde_json = "1.0"
time = "={}"
{}"#,
            common::locked_version(workspace, "time"),
            dependencies,
        ),
    )
    .unwrap();
    let tests = scratch.path().join("tests");
    fs::create_dir(&tests).unwrap();
    fs::write(
        tests.join("state_lists.rs"),
        include_str!("fixtures/config_false_lists_test.rs"),
    )
    .unwrap();

    for args in [
        vec!["test", "--no-fail-fast", "--", "--test-threads=4"],
        vec!["clippy", "--all-targets", "--", "-D", "warnings"],
    ] {
        let status = Command::new("cargo")
            .args(&args)
            .env("RUSTFLAGS", "-Dwarnings")
            .env(
                "CARGO_TARGET_DIR",
                workspace.join("target/yanggen-generated"),
            )
            .current_dir(scratch.path())
            .status()
            .unwrap();
        assert!(status.success(), "generated state-list {args:?} failed");
    }
}
