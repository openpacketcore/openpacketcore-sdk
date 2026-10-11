mod common;

use opc_yanggen::{generation_input_from_yang_sources, rust::generate_rust, YangSource};
use std::fs;
use std::path::Path;
use std::process::Command;

const MINIMAL: &str = r#"
module ordered-example {
  yang-version 1.1;
  namespace "urn:example:ordered";
  prefix ex;
  revision 2026-10-10;
  container root {
    list server {
      key "name";
      ordered-by user;
      leaf name { type string; }
    }
  }
}
"#;

const COLLECTIONS: &str = r#"
module ordered-collections {
  yang-version 1.1;
  namespace "urn:example:ordered-collections";
  prefix oc;
  revision 2026-10-10;
  container root {
    list server {
      key "name";
      ordered-by user;
      leaf name { type string; }
      leaf port { type uint16; }
      leaf password { type string; }
      leaf-list preference { type string; ordered-by user; }
    }
    list system-server {
      key "name";
      ordered-by system;
      leaf name { type string; }
    }
    list endpoint {
      key "region name";
      ordered-by user;
      leaf region { type string; }
      leaf name { type string; }
      leaf port { type uint16; }
    }
    leaf-list preference { type string; ordered-by user; }
    leaf-list priority { type uint16; ordered-by user; }
  }
}
"#;

fn generate_module(directory: &Path, name: &str, source: &str) {
    let input = generation_input_from_yang_sources(
        "ordered-collections",
        &[YangSource::new(format!("{name}.yang"), source)],
    )
    .unwrap();
    let output = directory.join(name);
    fs::create_dir(&output).unwrap();
    for (file, content) in generate_rust(&input.to_canonical()).unwrap() {
        fs::write(output.join(file), content).unwrap();
    }
}

#[test]
fn generated_user_ordered_collections() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let scratch = tempfile::tempdir().unwrap();
    let src = scratch.path().join("src");
    fs::create_dir(&src).unwrap();
    generate_module(&src, "minimal", MINIMAL);
    generate_module(&src, "collections", COLLECTIONS);
    fs::write(
        src.join("lib.rs"),
        "pub mod minimal;\npub mod collections;\n",
    )
    .unwrap();
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
name = "generated-ordered-test"
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
        tests.join("ordered.rs"),
        include_str!("fixtures/ordered_by_user_test.rs"),
    )
    .unwrap();

    // Keep dependency compilation reusable across regenerated source revisions.
    // The scratch source is disposable; the worktree-local build cache is not.
    let status = Command::new("cargo")
        .args(["test", "--", "--test-threads=4"])
        .env("RUSTFLAGS", "-Dwarnings")
        .env(
            "CARGO_TARGET_DIR",
            workspace.join("target/yanggen-generated"),
        )
        .current_dir(scratch.path())
        .status()
        .unwrap();
    assert!(status.success(), "generated ordering regressions failed");
}
