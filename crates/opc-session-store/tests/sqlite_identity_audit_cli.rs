use std::process::{Command, Output};

use opc_session_store::SqliteSessionBackend;
use rusqlite::{params, Connection};

fn database() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::Builder::new()
        .prefix("audit-path-must-not-leak")
        .tempdir()
        .expect("tempdir");
    let path = dir.path().join("sensitive-database-name.db");
    drop(SqliteSessionBackend::open(&path).expect("create schema"));
    (dir, path)
}

fn run(path: &std::path::Path, max_rows: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_opc-session-store-audit"))
        .args([
            "identity-invariants",
            "--database",
            path.to_str().expect("UTF-8 test path"),
            "--max-rows",
            max_rows,
            "--max-entry-json-bytes",
            "4096",
            "--max-total-json-bytes",
            "4096",
        ])
        .output()
        .expect("run audit CLI")
}

#[test]
fn cli_returns_versioned_count_only_json_and_stable_exit_codes() {
    let (_dir, path) = database();

    let compliant = run(&path, "10");
    assert_eq!(compliant.status.code(), Some(0));
    let compliant_json: serde_json::Value =
        serde_json::from_slice(&compliant.stdout).expect("compliant JSON");
    assert_eq!(compliant_json["report_version"], 3);
    assert_eq!(compliant_json["status"], "compliant");
    assert!(compliant.stderr.is_empty());

    let conn = Connection::open(&path).expect("open fixture");
    let raw_key = "raw-custom-key-must-not-leak".repeat(10);
    conn.execute(
        r#"
        INSERT INTO key_fences (tenant, nf_kind, key_type, stable_id, fence)
        VALUES ('tenant-a', 'smf', ?1, X'01', 1)
        "#,
        params![raw_key],
    )
    .expect("insert invalid key type");
    drop(conn);

    let violations = run(&path, "10");
    assert_eq!(violations.status.code(), Some(1));
    let violations_json: serde_json::Value =
        serde_json::from_slice(&violations.stdout).expect("violations JSON");
    assert_eq!(violations_json["status"], "violations_found");
    assert_eq!(
        violations_json["violations"]["invalid_session_key_type_fields"],
        1
    );

    let conn = Connection::open(&path).expect("open fixture");
    conn.execute(
        r#"
        INSERT INTO key_fences (tenant, nf_kind, key_type, stable_id, fence)
        VALUES ('tenant-a', 'smf', 'valid-custom-key', X'02', 1)
        "#,
        [],
    )
    .expect("insert second key");
    drop(conn);

    let incomplete = run(&path, "1");
    assert_eq!(incomplete.status.code(), Some(2));
    let incomplete_json: serde_json::Value =
        serde_json::from_slice(&incomplete.stdout).expect("incomplete JSON");
    assert_eq!(incomplete_json["status"], "incomplete");
    assert_eq!(incomplete_json["incomplete_reason"], "row_budget_exceeded");

    let combined = [
        compliant.stdout,
        compliant.stderr,
        violations.stdout,
        violations.stderr,
        incomplete.stdout,
        incomplete.stderr,
    ]
    .concat();
    let rendered = String::from_utf8(combined).expect("UTF-8 output");
    assert!(!rendered.contains(path.to_string_lossy().as_ref()));
    assert!(!rendered.contains("audit-path-must-not-leak"));
    assert!(!rendered.contains("sensitive-database-name"));
    assert!(!rendered.contains("raw-custom-key-must-not-leak"));
    assert!(!rendered.contains("tenant-a"));
}

#[test]
fn cli_rejects_missing_or_invalid_required_budgets_without_echoing_arguments() {
    let (_dir, path) = database();
    let invalid = run(&path, "0");
    assert_eq!(invalid.status.code(), Some(2));
    assert!(invalid.stdout.is_empty());
    let error: serde_json::Value = serde_json::from_slice(&invalid.stderr).expect("error JSON");
    assert_eq!(error["status"], "error");
    assert_eq!(error["reason"], "invalid_limits");
    assert!(!String::from_utf8_lossy(&invalid.stderr).contains(path.to_string_lossy().as_ref()));

    let missing = Command::new(env!("CARGO_BIN_EXE_opc-session-store-audit"))
        .args(["identity-invariants", "--database"])
        .output()
        .expect("run audit CLI");
    assert_eq!(missing.status.code(), Some(2));
    let missing_error: serde_json::Value =
        serde_json::from_slice(&missing.stderr).expect("missing-arg JSON");
    assert_eq!(missing_error["reason"], "invalid_arguments");
}

#[test]
fn cli_help_is_json_only() {
    let output = Command::new(env!("CARGO_BIN_EXE_opc-session-store-audit"))
        .arg("--help")
        .output()
        .expect("run audit CLI help");
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let help: serde_json::Value = serde_json::from_slice(&output.stdout).expect("help JSON");
    assert_eq!(help["status"], "help");
    assert!(help["usage"].as_str().is_some());
}

#[cfg(unix)]
#[test]
fn cli_non_utf8_database_path_is_redacted_json_not_a_panic() {
    use std::os::unix::ffi::{OsStrExt, OsStringExt};

    let dir = tempfile::tempdir().expect("tempdir");
    let sentinel = b"sensitive-non-utf8-\xff.db";
    let mut path = dir.path().as_os_str().as_bytes().to_vec();
    path.push(b'/');
    path.extend_from_slice(sentinel);
    let path = std::ffi::OsString::from_vec(path);

    let output = Command::new(env!("CARGO_BIN_EXE_opc-session-store-audit"))
        .arg("identity-invariants")
        .arg("--database")
        .arg(path)
        .args([
            "--max-rows",
            "10",
            "--max-entry-json-bytes",
            "4096",
            "--max-total-json-bytes",
            "4096",
        ])
        .output()
        .expect("run audit CLI");

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let error: serde_json::Value =
        serde_json::from_slice(&output.stderr).expect("redacted error JSON");
    assert_eq!(error["status"], "error");
    assert_eq!(error["reason"], "database_open_failed");
    assert!(!output
        .stderr
        .windows(sentinel.len())
        .any(|window| window == sentinel));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("panicked"));
}
