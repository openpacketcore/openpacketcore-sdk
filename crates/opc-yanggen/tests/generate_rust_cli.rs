use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;
use tempfile::tempdir;

const TEST_YANG: &str = r#"
module opc-rust-gen {
  yang-version 1.1;
  namespace "urn:opc:rust-gen";
  prefix gen;

  revision 2026-06-28 {
    description "Initial test model.";
  }

  container system {
    leaf enabled {
      type boolean;
      default "true";
    }

    list peer {
      key "name";

      leaf name {
        type string;
      }

      leaf port {
        type uint16;
      }
    }
  }
}
"#;

const INVALID_YANG: &str = r#"
module broken {
  namespace "urn:opc:broken";
  prefix broken;
  container system {
"#;

const UNSUPPORTED_YANG: &str = r#"
module unsupported {
  yang-version 1.1;
  namespace "urn:opc:unsupported";
  prefix bad;

  revision 2026-06-28;

  container system {
    must "enabled";

    leaf enabled {
      type boolean;
    }
  }
}
"#;

const EXPECTED_FILES: &[&str] = &[
    "gnmi_json.rs",
    "gnmi_set.rs",
    "metadata.rs",
    "mod.rs",
    "netconf_xml.rs",
    "netconf_xml_edit.rs",
    "patch.rs",
    "paths.rs",
    "redaction.rs",
    "schema_registry.rs",
    "serde.rs",
    "types.rs",
    "validate.rs",
];

fn write_yang(dir: &Path, text: &str) -> PathBuf {
    let path = dir.join("module.yang");
    fs::write(&path, text).expect("write YANG source");
    path
}

fn generate_args(yang_path: &Path, out_dir: &Path) -> Vec<String> {
    vec![
        "generate-rust".to_string(),
        "--profile".to_string(),
        "test-profile".to_string(),
        "--yang".to_string(),
        yang_path.display().to_string(),
        "--out-dir".to_string(),
        out_dir.display().to_string(),
    ]
}

fn run(args: &[String]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_opc-yanggen"))
        .args(args)
        .output()
        .expect("opc-yanggen CLI should run")
}

fn assert_success_json(output: Output) -> Value {
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("stdout should be JSON")
}

fn assert_error_json(output: Output) -> Value {
    assert!(
        !output.status.success(),
        "stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    serde_json::from_slice(&output.stderr).expect("stderr should be diagnostic JSON")
}

fn read_expected_files(out_dir: &Path) -> BTreeMap<String, Vec<u8>> {
    EXPECTED_FILES
        .iter()
        .map(|name| {
            (
                (*name).to_string(),
                fs::read(out_dir.join(name)).expect("generated file should exist"),
            )
        })
        .collect()
}

#[test]
fn generate_rust_writes_all_expected_files() {
    let dir = tempdir().expect("tempdir");
    let yang_path = write_yang(dir.path(), TEST_YANG);
    let out_dir = dir.path().join("generated");

    let output = run(&generate_args(&yang_path, &out_dir));
    let json = assert_success_json(output);

    assert_eq!(json["status"], "ok");
    let schema_digest = json["schema_digest"]
        .as_str()
        .expect("schema_digest should be a string");
    assert!(schema_digest.starts_with("fnv1a64:"));
    let schema_registry = fs::read_to_string(out_dir.join("schema_registry.rs"))
        .expect("schema_registry.rs should be generated");
    assert!(
        schema_registry.contains(&format!("\"{schema_digest}\"")),
        "CLI schema_digest must match generated registry digest"
    );
    let files = json["files"]
        .as_array()
        .expect("files should be an array")
        .iter()
        .map(|value| value.as_str().expect("file should be string"))
        .collect::<Vec<_>>();
    assert_eq!(files, EXPECTED_FILES);
    for name in EXPECTED_FILES {
        assert!(out_dir.join(name).is_file(), "{name} should be generated");
    }
}

#[test]
fn generate_rust_repeated_runs_are_byte_stable() {
    let dir = tempdir().expect("tempdir");
    let yang_path = write_yang(dir.path(), TEST_YANG);
    let out_dir = dir.path().join("generated");
    let args = generate_args(&yang_path, &out_dir);

    assert_success_json(run(&args));
    let first = read_expected_files(&out_dir);
    assert_success_json(run(&args));
    let second = read_expected_files(&out_dir);

    assert_eq!(first, second);
}

#[test]
fn generate_rust_check_passes_after_generation() {
    let dir = tempdir().expect("tempdir");
    let yang_path = write_yang(dir.path(), TEST_YANG);
    let out_dir = dir.path().join("generated");
    let mut args = generate_args(&yang_path, &out_dir);

    assert_success_json(run(&args));
    args.push("--check".to_string());
    let json = assert_success_json(run(&args));

    assert_eq!(json["status"], "ok");
    assert_eq!(json["mode"], "check");
}

#[test]
fn generate_rust_check_fails_after_generated_file_is_modified() {
    let dir = tempdir().expect("tempdir");
    let yang_path = write_yang(dir.path(), TEST_YANG);
    let out_dir = dir.path().join("generated");
    let mut args = generate_args(&yang_path, &out_dir);

    assert_success_json(run(&args));
    fs::write(out_dir.join("types.rs"), "// local edit\n").expect("modify generated file");

    args.push("--check".to_string());
    let json = assert_error_json(run(&args));

    assert_eq!(json["status"], "error");
    assert_eq!(json["diagnostic"]["code"], "yang-source-mismatch");
    assert!(json["diagnostic"]["message"]
        .as_str()
        .expect("message should be a string")
        .contains("types.rs"));
}

#[test]
fn generate_rust_rejects_stale_rs_files_by_default() {
    let dir = tempdir().expect("tempdir");
    let yang_path = write_yang(dir.path(), TEST_YANG);
    let out_dir = dir.path().join("generated");
    let args = generate_args(&yang_path, &out_dir);

    assert_success_json(run(&args));
    fs::write(out_dir.join("stale.rs"), "// stale\n").expect("write stale file");

    let json = assert_error_json(run(&args));

    assert_eq!(json["diagnostic"]["code"], "yang-source-mismatch");
    assert!(json["diagnostic"]["message"]
        .as_str()
        .expect("message should be a string")
        .contains("stale.rs"));
}

#[test]
fn generate_rust_prune_removes_stale_rs_files() {
    let dir = tempdir().expect("tempdir");
    let yang_path = write_yang(dir.path(), TEST_YANG);
    let out_dir = dir.path().join("generated");
    let mut args = generate_args(&yang_path, &out_dir);

    assert_success_json(run(&args));
    fs::write(out_dir.join("stale.rs"), "// stale\n").expect("write stale file");

    args.push("--prune".to_string());
    assert_success_json(run(&args));

    assert!(!out_dir.join("stale.rs").exists());
}

#[test]
fn generate_rust_invalid_yang_returns_structured_diagnostic_json() {
    let dir = tempdir().expect("tempdir");
    let yang_path = write_yang(dir.path(), INVALID_YANG);
    let out_dir = dir.path().join("generated");

    let json = assert_error_json(run(&generate_args(&yang_path, &out_dir)));

    assert_eq!(json["status"], "error");
    assert_eq!(json["diagnostic"]["code"], "yang-source-syntax-error");
}

#[test]
fn generate_rust_unsupported_yang_returns_structured_diagnostic_json() {
    let dir = tempdir().expect("tempdir");
    let yang_path = write_yang(dir.path(), UNSUPPORTED_YANG);
    let out_dir = dir.path().join("generated");

    let json = assert_error_json(run(&generate_args(&yang_path, &out_dir)));

    assert_eq!(json["status"], "error");
    assert_eq!(json["diagnostic"]["code"], "unsupported-yang-feature");
}

#[test]
fn generate_rust_missing_required_flags_are_rejected() {
    let dir = tempdir().expect("tempdir");
    let yang_path = write_yang(dir.path(), TEST_YANG);
    let out_dir = dir.path().join("generated");
    let missing_profile = vec![
        "generate-rust".to_string(),
        "--yang".to_string(),
        yang_path.display().to_string(),
        "--out-dir".to_string(),
        out_dir.display().to_string(),
    ];
    let missing_yang = vec![
        "generate-rust".to_string(),
        "--profile".to_string(),
        "test-profile".to_string(),
        "--out-dir".to_string(),
        out_dir.display().to_string(),
    ];
    let missing_out_dir = vec![
        "generate-rust".to_string(),
        "--profile".to_string(),
        "test-profile".to_string(),
        "--yang".to_string(),
        yang_path.display().to_string(),
    ];

    for args in [missing_profile, missing_yang, missing_out_dir] {
        let json = assert_error_json(run(&args));
        assert_eq!(json["status"], "error");
        assert_eq!(json["diagnostic"]["code"], "yang-source-syntax-error");
    }
}

#[test]
fn system_ordered_model_keeps_all_generated_file_digests() {
    use sha2::{Digest, Sha256};
    use std::fmt::Write as _;

    // Captured from the generator before user ordering support (1d880a21c).
    // The patch.rs pin retains #1268 safe diagnostics. Read renderer pins include
    // #1269 authorized projection and #1270 canonical gNMI key literals. Every
    // generated file remains covered by its complete-file assertion.
    // Changing unaffected generated output requires an explicit baseline update.
    let expected = [
        (
            "gnmi_json.rs",
            // #1269 permits authorized sensitive keys; #1270 builds XPath literals.
            "537d5deb527ae2d47434f6538ddf0c9768694ce9fc0e3d24388d97fbfa7b6b87",
        ),
        (
            "gnmi_set.rs",
            "44d8054c5e0487ebbc45731b525a78d6f6f84363c652b63207362cafed0671f2",
        ),
        (
            "metadata.rs",
            "495fa1fed834545dae179353807296e6348b08407d4afc8d38e76525349042af",
        ),
        (
            "mod.rs",
            "3f775be9ce2a372626eb7b451b05a8eb0ae714f16c40a497d2e9d956b13ba2b8",
        ),
        (
            "netconf_xml.rs",
            // #1270 native instance trees plus #1272 bounded content projection.
            "7fe7ed1f527dbe1309d32f5dbac3cf4881ee7de1caf10ce3bdd05576716004ac",
        ),
        (
            "netconf_xml_edit.rs",
            "8a074295566f9aba912957c936426c12eb4a09c22ba7f7742e7c09efe437e021",
        ),
        (
            "patch.rs",
            "2d08d6ffe3b0b30eb090009a39afeafe96e0ae75976b7f86880050f123a448ee",
        ),
        (
            "paths.rs",
            "b495af2bf7495054e5a0a3b76fd81c6ffc4b7158dd148d690297e333746fa66b",
        ),
        (
            "redaction.rs",
            "d65423aa71cb4165450848080d5b69c0f3e6a4e96d7979fa48a56fed90184f07",
        ),
        (
            "schema_registry.rs",
            "85f0f52bd04dfb2757edbfd8073f387079478089ec95eba805851cfd0d0b642b",
        ),
        (
            "serde.rs",
            "d21e3ad8d2e3b9f2739a49d75d1658fded7ff6b0adeb90fbbc0f257b46e8028a",
        ),
        (
            "types.rs",
            "e0ad76b62b3e5eea0c0009c2d8762129ecfa3f9f5d840a460ee73a29871ac0f7",
        ),
        (
            "validate.rs",
            "015d1dbfaf08e401371c27d5e20b738291f0fc6d5771969e0ae572545ec990c4",
        ),
    ];
    let dir = tempdir().expect("tempdir");
    let yang_path = write_yang(dir.path(), TEST_YANG.trim_start());
    let out_dir = dir.path().join("generated");
    let mut args = generate_args(&yang_path, &out_dir);
    args[2] = "review".into();
    assert_success_json(run(&args));
    let generated = read_expected_files(&out_dir);
    assert_eq!(generated.len(), expected.len());
    for (name, expected_digest) in expected {
        let mut actual = String::with_capacity(64);
        for byte in Sha256::digest(&generated[name]) {
            write!(actual, "{byte:02x}").unwrap();
        }
        assert_eq!(actual, expected_digest, "generated output changed: {name}");
    }
}
