use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use opc_session_testkit::qualification::{
    SESSION_HA_CANDIDATE_EVIDENCE_SCHEMA_JSON, SESSION_HA_CONCURRENT_HISTORY_SCHEMA_JSON,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

const EVIDENCE_FIXTURE: &str = include_str!("fixtures/session-ha/candidate-evidence-v3.json");
const HISTORY_FIXTURE: &str = include_str!("fixtures/session-ha/concurrent-history-v3-valid.jsonl");
type HistoryMutation = fn(&mut [Value]);

fn checker_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../scripts/check-session-ha-concurrent-history.py")
}

fn history_fixture_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/session-ha/concurrent-history-v3-valid.jsonl")
}

fn evidence_fixture_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/session-ha/candidate-evidence-v3.json")
}

fn run_checker(evidence: &Path, history: &Path) -> Output {
    Command::new("python3")
        .arg(checker_path())
        .arg("--evidence")
        .arg(evidence)
        .arg("--history")
        .arg(history)
        .output()
        .expect("run independent concurrent-history checker")
}

fn exact_sha256(raw: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(raw))
}

fn write_bound_evidence(directory: &Path, history: &[u8]) -> PathBuf {
    let mut evidence: Value = serde_json::from_str(EVIDENCE_FIXTURE).expect("evidence fixture");
    evidence["history"]["sha256"] = exact_sha256(history).into();
    evidence["checker"]["sha256"] =
        exact_sha256(&fs::read(checker_path()).expect("checker bytes")).into();
    let path = directory.join("evidence.json");
    fs::write(
        &path,
        serde_json::to_vec_pretty(&evidence).expect("encode bound evidence"),
    )
    .expect("write bound evidence");
    path
}

fn encode_rows(rows: &[Value]) -> Vec<u8> {
    let mut encoded = rows
        .iter()
        .map(|row| serde_json::to_string(row).expect("encode history row"))
        .collect::<Vec<_>>()
        .join("\n")
        .into_bytes();
    encoded.push(b'\n');
    encoded
}

fn fixture_rows() -> Vec<Value> {
    HISTORY_FIXTURE
        .lines()
        .map(|line| serde_json::from_str(line).expect("history fixture row"))
        .collect()
}

fn run_mutated(rows: &[Value]) -> Output {
    let directory = tempfile::tempdir().expect("checker fixture directory");
    let history = encode_rows(rows);
    let history_path = directory.path().join("history.jsonl");
    fs::write(&history_path, &history).expect("write history");
    let evidence_path = write_bound_evidence(directory.path(), &history);
    run_checker(&evidence_path, &history_path)
}

fn output_json(output: &Output) -> Value {
    assert!(
        output.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("canonical checker output")
}

fn structural_schema_for_lightweight_validator(mut schema: Value) -> Value {
    match &mut schema {
        Value::Object(object) => {
            for unsupported in [
                "$comment",
                "maxItems",
                "maxLength",
                "maximum",
                "pattern",
                "uniqueItems",
            ] {
                object.remove(unsupported);
            }
            for value in object.values_mut() {
                *value = structural_schema_for_lightweight_validator(value.take());
            }
        }
        Value::Array(values) => {
            for value in values {
                *value = structural_schema_for_lightweight_validator(value.take());
            }
        }
        _ => {}
    }
    schema
}

fn inline_local_refs(schema: &Value, root: &Value) -> Value {
    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        let name = reference
            .strip_prefix("#/$defs/")
            .expect("qualification schemas use only local definitions");
        return inline_local_refs(
            root.get("$defs")
                .and_then(|definitions| definitions.get(name))
                .expect("referenced local definition exists"),
            root,
        );
    }
    match schema {
        Value::Object(object) => Value::Object(
            object
                .iter()
                .filter(|(key, _)| key.as_str() != "$defs")
                .map(|(key, value)| (key.clone(), inline_local_refs(value, root)))
                .collect(),
        ),
        Value::Array(values) => Value::Array(
            values
                .iter()
                .map(|value| inline_local_refs(value, root))
                .collect(),
        ),
        _ => schema.clone(),
    }
}

fn validate_structural_schema(schema: &Value, instance: &Value) -> Result<(), String> {
    opc_schema_validate::validate(
        &structural_schema_for_lightweight_validator(inline_local_refs(schema, schema)),
        instance,
    )
}

#[test]
fn v3_candidate_contract_and_concurrent_fixture_are_closed_and_incomplete() {
    let evidence_schema: Value = serde_json::from_str(SESSION_HA_CANDIDATE_EVIDENCE_SCHEMA_JSON)
        .expect("candidate evidence schema");
    let history_schema: Value = serde_json::from_str(SESSION_HA_CONCURRENT_HISTORY_SCHEMA_JSON)
        .expect("concurrent history schema");
    let evidence: Value = serde_json::from_str(EVIDENCE_FIXTURE).expect("candidate evidence");
    validate_structural_schema(&evidence_schema, &evidence)
        .expect("candidate evidence satisfies its closed schema");
    for row in fixture_rows() {
        validate_structural_schema(&history_schema, &row)
            .expect("history row satisfies its closed schema");
    }

    assert_eq!(evidence["experimental"], true);
    assert_eq!(evidence["qualification_complete"], false);
    assert_eq!(evidence["counts_for_production"], false);

    let mut unsupported_claim = evidence.clone();
    unsupported_claim["qualification_complete"] = true.into();
    assert!(validate_structural_schema(&evidence_schema, &unsupported_claim).is_err());
    unsupported_claim["qualification_complete"] = false.into();
    unsupported_claim["counts_for_production"] = true.into();
    assert!(validate_structural_schema(&evidence_schema, &unsupported_claim).is_err());

    let mut incomplete_inventory = evidence;
    incomplete_inventory["remaining_acceptance"]
        .as_array_mut()
        .expect("remaining acceptance inventory")
        .pop();
    assert!(validate_structural_schema(&evidence_schema, &incomplete_inventory).is_err());
}

#[test]
fn independent_checker_accepts_overlapping_atomic_history_and_all_four_surfaces() {
    let rows = fixture_rows();
    assert!(rows[0]["started_ns"].as_u64() < rows[1]["completed_ns"].as_u64());
    assert!(rows[1]["started_ns"].as_u64() < rows[0]["completed_ns"].as_u64());

    let output = run_checker(&evidence_fixture_path(), &history_fixture_path());
    assert!(output.status.success());
    let result = output_json(&output);
    assert_eq!(result["status"], "pass");
    assert_eq!(result["history_operations_checked"], 12);
    assert_eq!(
        result["operation_counts"],
        serde_json::json!({"batch": 3, "readiness": 9, "restore": 1, "watch": 1})
    );
    assert_eq!(result["violation_codes"], serde_json::json!([]));
    assert_eq!(result["inconclusive_codes"], serde_json::json!([]));
}

#[test]
fn checker_rejects_batch_watch_restore_and_readiness_violations() {
    let cases: [(&str, HistoryMutation); 6] = [
        ("batch_atomicity_violation", |rows| {
            rows[2]["operation"]["mutations"][0]["expected_generation"] = Value::Null;
        }),
        ("watch_gap_or_reorder", |rows| {
            rows[3]["operation"]["events"]
                .as_array_mut()
                .expect("watch events")
                .remove(1);
        }),
        ("restore_state_violation", |rows| {
            rows[4]["operation"]["records"][0]["generation"] = 1.into();
        }),
        ("readiness_gating_violation", |rows| {
            rows[5]["operation"]["state"] = "ready".into();
            rows[5]["operation"]["term"] = 1.into();
            rows[5]["operation"]["commit_index"] = 0.into();
            rows[5]["operation"]["applied_index"] = 0.into();
        }),
        ("real_time_order_violation", |rows| {
            rows[1]["started_ns"] = 400.into();
            rows[1]["operation"]["linearization_index"] = 9.into();
        }),
        ("readiness_sampling_order_violation", |rows| {
            rows[6]["started_ns"] = 0.into();
            rows[6]["completed_ns"] = 0.into();
        }),
    ];

    for (expected, mutate) in cases {
        let mut rows = fixture_rows();
        mutate(&mut rows);
        let output = run_mutated(&rows);
        assert_eq!(output.status.code(), Some(1), "{expected}");
        let result = output_json(&output);
        assert_eq!(result["status"], "fail", "{expected}");
        assert!(
            result["violation_codes"]
                .as_array()
                .expect("violation codes")
                .iter()
                .any(|value| value == expected),
            "expected {expected}, got {}",
            result["violation_codes"]
        );
    }
}

#[test]
fn checker_keeps_unknown_batch_outcomes_inconclusive() {
    let mut rows = fixture_rows();
    rows[2]["operation"]["outcome"] = "unavailable".into();
    rows[2]["operation"]["linearization_index"] = Value::Null;

    let output = run_mutated(&rows);
    assert_eq!(output.status.code(), Some(2));
    let result = output_json(&output);
    assert_eq!(result["status"], "inconclusive");
    assert_eq!(
        result["inconclusive_codes"],
        serde_json::json!(["state_depends_on_unknown_batch", "unknown_batch_outcome"])
    );
}

#[test]
fn checker_fails_closed_on_malformed_or_unbound_input() {
    let directory = tempfile::tempdir().expect("invalid checker directory");
    let malformed = format!("{{\"value\":{}}}\n", "9".repeat(32 * 1024));
    let history_path = directory.path().join("malformed.jsonl");
    fs::write(&history_path, malformed.as_bytes()).expect("write malformed history");
    let evidence_path = write_bound_evidence(directory.path(), malformed.as_bytes());
    let malformed_output = run_checker(&evidence_path, &history_path);
    assert_eq!(malformed_output.status.code(), Some(3));
    assert_eq!(output_json(&malformed_output)["status"], "invalid_input");

    let duplicate = b"{\"value\":1,\"value\":2}\n";
    let duplicate_path = directory.path().join("duplicate.jsonl");
    fs::write(&duplicate_path, duplicate).expect("write duplicate-field history");
    let duplicate_evidence = write_bound_evidence(directory.path(), duplicate);
    let duplicate_output = run_checker(&duplicate_evidence, &duplicate_path);
    assert_eq!(duplicate_output.status.code(), Some(3));
    assert_eq!(output_json(&duplicate_output)["status"], "invalid_input");

    let mut evidence: Value = serde_json::from_str(EVIDENCE_FIXTURE).expect("evidence fixture");
    evidence["history"]["sha256"] =
        "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".into();
    let unbound_path = directory.path().join("unbound-evidence.json");
    fs::write(
        &unbound_path,
        serde_json::to_vec(&evidence).expect("encode unbound evidence"),
    )
    .expect("write unbound evidence");
    let unbound_output = run_checker(&unbound_path, &history_fixture_path());
    assert_eq!(unbound_output.status.code(), Some(3));
    assert_eq!(output_json(&unbound_output)["status"], "invalid_input");

    let mut incomplete: Value = serde_json::from_str(EVIDENCE_FIXTURE).expect("evidence fixture");
    incomplete["remaining_acceptance"]
        .as_array_mut()
        .expect("remaining acceptance inventory")
        .pop();
    let incomplete_path = directory.path().join("incomplete-evidence.json");
    fs::write(
        &incomplete_path,
        serde_json::to_vec(&incomplete).expect("encode incomplete evidence"),
    )
    .expect("write incomplete evidence");
    let incomplete_output = run_checker(&incomplete_path, &history_fixture_path());
    assert_eq!(incomplete_output.status.code(), Some(3));
    assert_eq!(output_json(&incomplete_output)["status"], "invalid_input");
}
