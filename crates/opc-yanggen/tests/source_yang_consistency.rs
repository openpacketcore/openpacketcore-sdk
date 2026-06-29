use std::fs;
use std::process::Command;

use opc_yanggen::{
    generation_input_from_yang_sources, schema_digest, validate_generation_input_yang_sources,
    DiagnosticCode, GenerationInput, SchemaNodeKind, TypeRef, YangSource,
};
use tempfile::tempdir;

const BASE_YANG: &str = r#"
module opc-test {
  yang-version 1.1;
  namespace "urn:opc:test";
  prefix test;

  import opc-annotations {
    prefix opc;
    revision-date 2026-01-01;
  }

  revision 2026-06-28 {
    description "Initial test model.";
  }

  container system {
    description "Config root.";

    leaf enabled {
      type boolean;
      default "true";
    }

    leaf secret {
      type string;
      opc:data-class "security-secret";
    }

    list peer {
      key "name";
      unique "port";

      leaf name {
        type string;
      }

      leaf port {
        type uint16;
      }
    }

    container state {
      config false;

      leaf uptime {
        type uint32;
      }
    }
  }
}
"#;

const COMMENT_ONLY_YANG: &str = r#"
module opc-test {
  yang-version 1.1;
  namespace "urn:opc:test";
  prefix test;

  import opc-annotations {
    prefix opc;
    revision-date 2026-01-01;
  }

  revision 2026-06-28 {
    description "Only this documentation changed.";
  }

  container system {
    description "A different description should not affect schema digest.";

    leaf enabled {
      type boolean;
      default "true";
      description "Documentation-only change.";
    }

    leaf secret {
      type string;
      opc:data-class "security-secret";
    }

    list peer {
      key "name";
      unique "port";

      leaf name {
        type string;
      }

      leaf port {
        type uint16;
      }
    }

    container state {
      config false;

      leaf uptime {
        type uint32;
      }
    }
  }
}
"#;

const ENUM_YANG: &str = r#"
module opc-test {
  yang-version 1.1;
  namespace "urn:opc:test";
  prefix test;

  revision 2026-06-28 {
    description "Initial test model.";
  }

  container system {
    leaf mode {
      type enumeration {
        enum standalone {
          description "Single-node mode.";
        }
        enum active-standby;
      }
    }
  }
}
"#;

fn source(text: &str) -> YangSource {
    YangSource::new("opc-test.yang", text)
}

fn base_input() -> GenerationInput {
    generation_input_from_yang_sources("test-profile", &[source(BASE_YANG)])
        .expect("base YANG should ingest")
}

fn assert_source_mismatch(input: &GenerationInput) {
    let err = validate_generation_input_yang_sources(input, &[source(BASE_YANG)])
        .expect_err("input/source mismatch should be rejected");
    assert_eq!(err.code, DiagnosticCode::YangSourceMismatch);
}

#[test]
fn source_yang_ingests_and_validates_successfully() {
    let input = base_input();

    validate_generation_input_yang_sources(&input, &[source(BASE_YANG)])
        .expect("source and generated input should match");

    assert_eq!(input.schema_modules[0].name, "opc-test");
    assert_eq!(input.schema_modules[0].revision, "2026-06-28");
    assert_eq!(input.schema_modules[0].namespace, "urn:opc:test");
    assert_eq!(input.schema_modules[0].prefix, "test");
    assert_eq!(
        input.schema_modules[0].source_text.as_deref(),
        Some(BASE_YANG)
    );

    let peer = input
        .nodes
        .iter()
        .find(|node| node.path == "/test:system/peer")
        .expect("peer list should be present");
    assert_eq!(peer.kind, SchemaNodeKind::List);
    assert_eq!(peer.key_leaves, vec!["name"]);
    assert_eq!(peer.unique_constraints, vec![vec!["port".to_string()]]);

    let uptime = input
        .nodes
        .iter()
        .find(|node| node.path == "/test:system/state/uptime")
        .expect("state leaf should be present");
    assert!(!uptime.config);

    let secret = input
        .nodes
        .iter()
        .find(|node| node.path == "/test:system/secret")
        .expect("secret leaf should be present");
    assert_eq!(secret.data_class.as_deref(), Some("security-secret"));
}

#[test]
fn source_yang_ingests_enumeration_type_metadata() {
    let input = generation_input_from_yang_sources("test-profile", &[source(ENUM_YANG)])
        .expect("enum YANG should ingest");

    let mode = input
        .nodes
        .iter()
        .find(|node| node.path == "/test:system/mode")
        .expect("mode leaf should be present");

    match &mode.type_ref {
        Some(TypeRef::Enumeration { values }) => {
            assert_eq!(values.len(), 2);
            assert_eq!(values[0].name, "standalone");
            assert_eq!(values[0].description.as_deref(), Some("Single-node mode."));
            assert_eq!(values[1].name, "active-standby");
        }
        other => panic!("unexpected mode type: {other:?}"),
    }
}

#[test]
fn module_metadata_mismatch_rejects() {
    let mut name = base_input();
    name.schema_modules[0].name = "different-module".to_string();
    assert_source_mismatch(&name);

    let mut revision = base_input();
    revision.schema_modules[0].revision = "2026-06-29".to_string();
    assert_source_mismatch(&revision);

    let mut namespace = base_input();
    namespace.schema_modules[0].namespace = "urn:opc:different".to_string();
    assert_source_mismatch(&namespace);

    let mut prefix = base_input();
    prefix.schema_modules[0].prefix = "other".to_string();
    assert_source_mismatch(&prefix);
}

#[test]
fn missing_node_rejects() {
    let mut input = base_input();
    input
        .nodes
        .retain(|node| node.path != "/test:system/peer/port");

    assert_source_mismatch(&input);
}

#[test]
fn list_key_mismatch_rejects() {
    let mut input = base_input();
    let peer = input
        .nodes
        .iter_mut()
        .find(|node| node.path == "/test:system/peer")
        .expect("peer list should be present");
    peer.key_leaves = vec!["port".to_string()];

    assert_source_mismatch(&input);
}

#[test]
fn child_path_mismatch_rejects() {
    let mut input = base_input();
    let system = input
        .nodes
        .iter_mut()
        .find(|node| node.path == "/test:system")
        .expect("system container should be present");
    system
        .child_paths
        .retain(|path| path != "/test:system/secret");

    assert_source_mismatch(&input);
}

#[test]
fn unsupported_construct_returns_diagnostic_shape() {
    let unsupported = BASE_YANG.replace(
        "leaf enabled {\n      type boolean;",
        "leaf enabled {\n      must \"../secret\";\n      type boolean;",
    );

    let err = generation_input_from_yang_sources("test-profile", &[source(&unsupported)])
        .expect_err("must constraints are not lowered by the source gate yet");

    assert_eq!(err.code, DiagnosticCode::UnsupportedYangFeature);
    assert!(err.message.contains("must"));
    assert!(err.source.is_some());
    assert!(err.help.is_some());
}

#[test]
fn schema_digest_changes_for_schema_significant_source_changes() {
    let base = base_input();
    let changed = BASE_YANG.replace("type uint16;", "type uint32;");
    let changed = generation_input_from_yang_sources("test-profile", &[source(&changed)])
        .expect("changed YANG should ingest");

    assert_ne!(schema_digest(&base), schema_digest(&changed));
}

#[test]
fn comment_and_description_changes_do_not_change_schema_digest() {
    let base = base_input();
    let docs_changed =
        generation_input_from_yang_sources("test-profile", &[source(COMMENT_ONLY_YANG)])
            .expect("documentation-only YANG should ingest");

    assert_eq!(schema_digest(&base), schema_digest(&docs_changed));
}

#[test]
fn cli_validate_source_succeeds_for_downstream_ci() {
    let dir = tempdir().expect("tempdir");
    let yang_path = dir.path().join("opc-test.yang");
    let input_path = dir.path().join("generation-input.json");
    let input = base_input();

    fs::write(&yang_path, BASE_YANG).expect("write YANG");
    fs::write(
        &input_path,
        serde_json::to_string_pretty(&input).expect("input serializes"),
    )
    .expect("write input");

    let output = Command::new(env!("CARGO_BIN_EXE_opc-yanggen"))
        .arg("validate-source")
        .arg("--input")
        .arg(&input_path)
        .arg("--yang")
        .arg(&yang_path)
        .output()
        .expect("opc-yanggen CLI should run");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");
    assert!(stdout.contains("\"status\": \"ok\""));
    assert!(stdout.contains(&schema_digest(&input)));
}
