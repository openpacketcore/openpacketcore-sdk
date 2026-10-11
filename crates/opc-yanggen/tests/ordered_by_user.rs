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
      list hop {
        key "name";
        leaf name { type string; }
        leaf cost { type uint32; }
      }
    }
    list system-server {
      key "name";
      ordered-by system;
      leaf name { type string; }
      leaf port { type uint16; }
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
    leaf-list ratio { type decimal64 { fraction-digits 2; } ordered-by user; }
  }
}
"#;

const DEFAULTS: &str = r#"
module ordered-defaults {
  yang-version 1.1;
  namespace "urn:example:ordered-defaults";
  prefix od;
  revision 2026-10-11;
  container root {
    list server {
      key "name";
      ordered-by user;
      leaf name { type string; }
      leaf port { type uint16; default 53; }
    }
  }
}
"#;

const SECRETS: &str = r#"
module ordered-secrets {
  yang-version 1.1;
  namespace "urn:example:ordered-secrets";
  prefix os;
  revision 2026-10-11;
  container root {
    leaf-list api-token { type string; ordered-by user; }
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
    compile_fixture(
        &[
            ("minimal", MINIMAL),
            ("collections", COLLECTIONS),
            ("defaults", DEFAULTS),
        ],
        &[
            ("ordered", include_str!("fixtures/ordered_by_user_test.rs")),
            (
                "authorization",
                include_str!("fixtures/ordered_by_user_authorization_test.rs"),
            ),
            (
                "regressions",
                include_str!("fixtures/ordered_by_user_regressions_test.rs"),
            ),
        ],
    );
}

#[test]
fn generated_sensitive_user_ordered_leaf_lists() {
    compile_fixture(
        &[("secrets", SECRETS)],
        &[(
            "secrets",
            include_str!("fixtures/ordered_by_user_secrets_test.rs"),
        )],
    );
}

fn compile_fixture(modules: &[(&str, &str)], fixtures: &[(&str, &str)]) {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let scratch = tempfile::tempdir().unwrap();
    let src = scratch.path().join("src");
    fs::create_dir(&src).unwrap();
    let mut lib = String::new();
    for (name, source) in modules {
        generate_module(&src, name, source);
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
        "opc-config-bus",
        "opc-mgmt-authz",
        "opc-nacm",
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
tokio = {{ version = "1", features = ["macros", "rt-multi-thread"] }}
time = "={}"
{}"#,
            common::locked_version(workspace, "time"),
            dependencies,
        ),
    )
    .unwrap();
    let tests = scratch.path().join("tests");
    fs::create_dir(&tests).unwrap();
    for (name, source) in fixtures {
        fs::write(tests.join(format!("{name}.rs")), source).unwrap();
    }

    // Keep dependency compilation reusable across regenerated source revisions.
    // The scratch source is disposable; the worktree-local build cache is not.
    let status = Command::new("cargo")
        .args(["test", "--no-fail-fast", "--", "--test-threads=4"])
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
