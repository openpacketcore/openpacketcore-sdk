use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use opc_session_testkit::qualification::{
    SESSION_HA_CANDIDATE_EVIDENCE_V5_SCHEMA_JSON, SESSION_HA_CONCURRENT_HISTORY_V5_SCHEMA_JSON,
    SESSION_HA_FAULT_SCHEDULE_V5_SCHEMA_JSON,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

const EVIDENCE_FIXTURE: &str = include_str!("fixtures/session-ha/candidate-evidence-v5.json");
const HISTORY_FIXTURE: &str = include_str!("fixtures/session-ha/concurrent-history-v5-valid.jsonl");
const FAULT_SCHEDULE_FIXTURE: &str =
    include_str!("fixtures/session-ha/fault-schedule-v5-valid.json");
type HistoryMutation = fn(&mut [Value]);

fn checker_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../scripts/check-session-ha-concurrent-history-v5.py")
}

fn history_fixture_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/session-ha/concurrent-history-v5-valid.jsonl")
}

fn evidence_fixture_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/session-ha/candidate-evidence-v5.json")
}

fn fault_schedule_fixture_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/session-ha/fault-schedule-v5-valid.json")
}

fn run_checker(evidence: &Path, fault_schedule: &Path, history: &Path) -> Output {
    Command::new("python3")
        .arg(checker_path())
        .arg("--evidence")
        .arg(evidence)
        .arg("--fault-schedule")
        .arg(fault_schedule)
        .arg("--history")
        .arg(history)
        .output()
        .expect("run independent per-slot concurrent-history checker")
}

fn exact_sha256(raw: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(raw))
}

fn write_bound_evidence_with(
    directory: &Path,
    history: &[u8],
    fault_schedule: &[u8],
    mutate: impl FnOnce(&mut Value),
) -> PathBuf {
    let mut evidence: Value = serde_json::from_str(EVIDENCE_FIXTURE).expect("evidence fixture");
    evidence["history"]["sha256"] = exact_sha256(history).into();
    evidence["checker"]["sha256"] =
        exact_sha256(&fs::read(checker_path()).expect("checker bytes")).into();
    evidence["execution"]["fault_schedule_sha256"] = exact_sha256(fault_schedule).into();
    mutate(&mut evidence);
    let path = directory.join("evidence.json");
    fs::write(
        &path,
        serde_json::to_vec_pretty(&evidence).expect("encode bound evidence"),
    )
    .expect("write bound evidence");
    path
}

fn write_bound_evidence(directory: &Path, history: &[u8]) -> PathBuf {
    write_bound_evidence_with(
        directory,
        history,
        FAULT_SCHEDULE_FIXTURE.as_bytes(),
        |_| {},
    )
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
    run_checker(
        &evidence_path,
        &fault_schedule_fixture_path(),
        &history_path,
    )
}

fn run_mutated_fault_schedule(schedule: &Value) -> Output {
    let directory = tempfile::tempdir().expect("checker fixture directory");
    let history = HISTORY_FIXTURE.as_bytes();
    let history_path = directory.path().join("history.jsonl");
    fs::write(&history_path, history).expect("write history");
    let schedule_bytes = serde_json::to_vec_pretty(schedule).expect("encode fault schedule");
    let schedule_path = directory.path().join("fault-schedule.json");
    fs::write(&schedule_path, &schedule_bytes).expect("write fault schedule");
    let evidence_path =
        write_bound_evidence_with(directory.path(), history, &schedule_bytes, |_| {});
    run_checker(&evidence_path, &schedule_path, &history_path)
}

fn run_mutated_with_fault_schedule(rows: &[Value], schedule: &Value) -> Output {
    let directory = tempfile::tempdir().expect("checker fixture directory");
    let history = encode_rows(rows);
    let history_path = directory.path().join("history.jsonl");
    fs::write(&history_path, &history).expect("write history");
    let schedule_bytes = serde_json::to_vec_pretty(schedule).expect("encode fault schedule");
    let schedule_path = directory.path().join("fault-schedule.json");
    fs::write(&schedule_path, &schedule_bytes).expect("write fault schedule");
    let evidence_path =
        write_bound_evidence_with(directory.path(), &history, &schedule_bytes, |_| {});
    run_checker(&evidence_path, &schedule_path, &history_path)
}

fn run_mutated_evidence(mutate: impl FnOnce(&mut Value)) -> Output {
    let directory = tempfile::tempdir().expect("checker fixture directory");
    let evidence_path = write_bound_evidence_with(
        directory.path(),
        HISTORY_FIXTURE.as_bytes(),
        FAULT_SCHEDULE_FIXTURE.as_bytes(),
        mutate,
    );
    run_checker(
        &evidence_path,
        &fault_schedule_fixture_path(),
        &history_fixture_path(),
    )
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

fn assert_violation(expected: &str, output: &Output) {
    assert_eq!(output.status.code(), Some(1), "{expected}");
    let result = output_json(output);
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

fn assert_invalid(output: &Output) {
    assert_eq!(output.status.code(), Some(3));
    assert_eq!(output_json(output)["status"], "invalid_input");
}

#[test]
fn v5_candidate_contract_is_closed_additive_and_non_production() {
    let evidence_schema: Value = serde_json::from_str(SESSION_HA_CANDIDATE_EVIDENCE_V5_SCHEMA_JSON)
        .expect("candidate evidence schema");
    let history_schema: Value = serde_json::from_str(SESSION_HA_CONCURRENT_HISTORY_V5_SCHEMA_JSON)
        .expect("concurrent history schema");
    let fault_schedule_schema: Value =
        serde_json::from_str(SESSION_HA_FAULT_SCHEDULE_V5_SCHEMA_JSON)
            .expect("fault schedule schema");
    let evidence: Value = serde_json::from_str(EVIDENCE_FIXTURE).expect("candidate evidence");
    let fault_schedule: Value =
        serde_json::from_str(FAULT_SCHEDULE_FIXTURE).expect("fault schedule");
    validate_structural_schema(&evidence_schema, &evidence)
        .expect("candidate evidence satisfies its closed schema");
    for row in fixture_rows() {
        validate_structural_schema(&history_schema, &row)
            .expect("history row satisfies its closed schema");
    }
    validate_structural_schema(&fault_schedule_schema, &fault_schedule)
        .expect("fault schedule satisfies its closed schema");

    assert_eq!(evidence["experimental"], true);
    assert_eq!(evidence["qualification_complete"], false);
    assert_eq!(evidence["counts_for_production"], false);
    assert_eq!(evidence["coverage"]["cas_batch_per_slot_outcomes"], true);
    assert_eq!(evidence["workload"]["initial_journal_head"], 9);
    assert_eq!(
        evidence["workload"]["records_non_expiring_through_campaign"],
        true
    );
    assert_eq!(evidence["workload"]["state_class"], "authoritative-session");
    assert_eq!(
        evidence["workload"]["no_lease_mutations_in_history_window"],
        true
    );
    assert_eq!(
        evidence["workload"]["preacquired_leases"]
            .as_array()
            .expect("pre-acquired leases")
            .len(),
        2
    );
    assert!(evidence["coverage"]
        .get("atomic_batch_serialization")
        .is_none());

    let mut unsupported_claim = evidence.clone();
    unsupported_claim["qualification_complete"] = true.into();
    assert!(validate_structural_schema(&evidence_schema, &unsupported_claim).is_err());

    let mut expiring_records = evidence.clone();
    expiring_records["workload"]["records_non_expiring_through_campaign"] = false.into();
    assert!(validate_structural_schema(&evidence_schema, &expiring_records).is_err());

    let mut old_index_domain = fixture_rows()[2].clone();
    let watch = old_index_domain["operation"]
        .as_object_mut()
        .expect("watch operation");
    let requested = watch
        .remove("requested_after_journal_sequence")
        .expect("journal cursor");
    watch.insert("requested_after_index".into(), requested);
    assert!(validate_structural_schema(&history_schema, &old_index_domain).is_err());
}

#[test]
fn independent_checker_accepts_partial_batch_and_separate_index_domains() {
    let rows = fixture_rows();
    assert_eq!(rows[0]["operation"]["slots"][0]["outcome"], "success");
    assert_eq!(rows[0]["operation"]["slots"][1]["outcome"], "conflict");
    assert_eq!(rows[0]["operation"]["slots"][2]["outcome"], "success");
    assert_ne!(
        rows[5]["operation"]["raft_commit_index"],
        rows[5]["operation"]["journal_head"]
    );

    let output = run_checker(
        &evidence_fixture_path(),
        &fault_schedule_fixture_path(),
        &history_fixture_path(),
    );
    assert!(output.status.success());
    let result = output_json(&output);
    assert_eq!(result["status"], "pass");
    assert_eq!(result["history_operations_checked"], 19);
    assert_eq!(
        result["operation_counts"],
        serde_json::json!({"batch": 2, "readiness": 15, "restore": 1, "watch": 1})
    );
    assert_eq!(result["violation_codes"], serde_json::json!([]));
    assert_eq!(result["inconclusive_codes"], serde_json::json!([]));
}

#[test]
fn checker_rejects_per_slot_watch_restore_and_readiness_violations() {
    let cases: [(&str, HistoryMutation); 8] = [
        ("batch_slot_success_violation", |rows| {
            rows[0]["operation"]["slots"][0]["mutation"]["expected_generation"] = 0.into();
        }),
        ("batch_slot_conflict_violation", |rows| {
            rows[0]["operation"]["slots"][1]["mutation"]["expected_generation"] = 1.into();
        }),
        ("application_journal_order_violation", |rows| {
            rows[0]["operation"]["slots"][2]["journal_sequence"] = 9.into();
        }),
        ("watch_gap_or_reorder", |rows| {
            rows[2]["operation"]["events"]
                .as_array_mut()
                .expect("watch events")
                .remove(1);
        }),
        ("restore_state_violation", |rows| {
            rows[3]["operation"]["records"][0]["generation"] = 1.into();
        }),
        ("readiness_gating_violation", |rows| {
            rows[6]["operation"]["state"] = "ready".into();
            rows[6]["operation"]["raft_term"] = 2.into();
            rows[6]["operation"]["raft_commit_index"] = 6.into();
            rows[6]["operation"]["raft_applied_index"] = 6.into();
            rows[6]["operation"]["journal_head"] = 12.into();
        }),
        ("readiness_authority_violation", |rows| {
            rows[5]["operation"]["raft_applied_index"] = 3.into();
        }),
        ("overlapping_batch_invocations", |rows| {
            rows[1]["started_ns"] = 250.into();
        }),
    ];

    for (expected, mutate) in cases {
        let mut rows = fixture_rows();
        mutate(&mut rows);
        let output = run_mutated(&rows);
        assert_violation(expected, &output);
    }
}

#[test]
fn checker_rejects_a_missing_application_journal_position() {
    let mut rows = fixture_rows();
    rows[0]["operation"]["slots"][2]["journal_sequence"] = 12.into();
    rows[1]["operation"]["slots"][0]["journal_sequence"] = 13.into();
    rows[2]["operation"]["complete_through_journal_sequence"] = 13.into();
    rows[2]["operation"]["events"][1]["journal_sequence"] = 12.into();
    rows[2]["operation"]["events"][2]["journal_sequence"] = 13.into();
    for row in &mut rows[4..] {
        if row["operation"]["state"] == "ready"
            && row["operation"]["journal_head"]
                .as_u64()
                .is_some_and(|head| head >= 12)
        {
            row["operation"]["journal_head"] = 13.into();
        }
    }

    let output = run_mutated(&rows);
    assert_violation("application_journal_gap", &output);
}

#[test]
fn checker_rejects_forged_baseline_and_post_history_head_jump() {
    let directory = tempfile::tempdir().expect("forged-baseline fixture directory");
    let evidence_path = write_bound_evidence_with(
        directory.path(),
        HISTORY_FIXTURE.as_bytes(),
        FAULT_SCHEDULE_FIXTURE.as_bytes(),
        |evidence| evidence["workload"]["initial_journal_head"] = 8.into(),
    );
    let forged_baseline = run_checker(
        &evidence_path,
        &fault_schedule_fixture_path(),
        &history_fixture_path(),
    );
    assert_violation("initial_journal_head_mismatch", &forged_baseline);

    let mut rows = fixture_rows();
    for row_index in [8, 13, 18] {
        rows[row_index]["operation"]["journal_head"] = 13.into();
    }
    let post_history_jump = run_mutated(&rows);
    assert_violation("readiness_authority_violation", &post_history_jump);
    assert_violation("end_of_campaign_journal_head_violation", &post_history_jump);
}

#[test]
fn checker_binds_fixed_campaign_lease_guards_and_record_profile() {
    let mut lower_fence = fixture_rows();
    lower_fence[0]["operation"]["slots"][2]["mutation"]["fence"] = 1.into();
    assert_violation("lease_contract_violation", &run_mutated(&lower_fence));

    let mut switched_owner = fixture_rows();
    switched_owner[1]["operation"]["slots"][0]["mutation"]["owner_sha256"] =
        "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".into();
    assert_violation("lease_contract_violation", &run_mutated(&switched_owner));

    let mut wrong_state_type = fixture_rows();
    wrong_state_type[1]["operation"]["slots"][0]["mutation"]["state_type_sha256"] =
        "sha256:8888888888888888888888888888888888888888888888888888888888888888".into();
    assert_violation("record_contract_violation", &run_mutated(&wrong_state_type));

    let expired = run_mutated_evidence(|evidence| {
        evidence["workload"]["preacquired_leases"][0]["valid_through_ns"] = 1000.into();
    });
    assert_invalid(&expired);
    let stale_at_start = run_mutated_evidence(|evidence| {
        evidence["workload"]["preacquired_leases"][0]["valid_from_ns"] = 1.into();
    });
    assert_invalid(&stale_at_start);

    let mut wrong_class = fixture_rows();
    wrong_class[0]["operation"]["slots"][0]["mutation"]["state_class"] = "telemetry-derived".into();
    assert_invalid(&run_mutated(&wrong_class));
    let mut expiring_record = fixture_rows();
    expiring_record[0]["operation"]["slots"][0]["mutation"]["expires_at_ns"] = 999.into();
    assert_invalid(&run_mutated(&expiring_record));

    let mut restore_wrong_type = fixture_rows();
    restore_wrong_type[3]["operation"]["records"][0]["state_type_sha256"] =
        "sha256:8888888888888888888888888888888888888888888888888888888888888888".into();
    assert_violation("restore_state_violation", &run_mutated(&restore_wrong_type));
}

#[test]
fn checker_caps_observer_heads_before_batches_starting_at_completion() {
    let mut rows = fixture_rows();
    rows[2]["operation"]["requested_after_journal_sequence"] = 13.into();
    rows[2]["operation"]["complete_through_journal_sequence"] = 13.into();
    rows[2]["operation"]["events"] = serde_json::json!([]);

    assert_violation("watch_future_journal_violation", &run_mutated(&rows));

    let mut boundary_future_watch = fixture_rows();
    boundary_future_watch[2]["completed_ns"] = 350.into();
    assert_violation(
        "watch_future_journal_violation",
        &run_mutated(&boundary_future_watch),
    );

    let mut boundary_future_readiness = fixture_rows();
    boundary_future_readiness[5]["started_ns"] = 350.into();
    boundary_future_readiness[5]["completed_ns"] = 350.into();
    assert_violation(
        "readiness_authority_violation",
        &run_mutated(&boundary_future_readiness),
    );
}

#[test]
fn checker_requires_bound_batch_order_and_real_partial_slot_coverage() {
    let mut invalid_sequence = fixture_rows();
    invalid_sequence[0]["operation"]["invocation_sequence"] = 2.into();
    invalid_sequence[1]["operation"]["invocation_sequence"] = 3.into();
    assert_violation(
        "batch_invocation_sequence_violation",
        &run_mutated(&invalid_sequence),
    );

    let mut no_partial_batch = fixture_rows();
    no_partial_batch[0]["operation"]["slots"]
        .as_array_mut()
        .expect("batch slots")
        .remove(1);
    no_partial_batch[0]["operation"]["slots"][1]["slot_index"] = 2.into();
    no_partial_batch[2]["operation"]["events"][1]["slot_index"] = 2.into();
    assert_violation(
        "partial_batch_coverage_violation",
        &run_mutated(&no_partial_batch),
    );
}

#[test]
fn checker_derives_readiness_from_faults_and_bounds_observation_recovery() {
    let mut mismatched_schedule_claim = fixture_rows();
    mismatched_schedule_claim[5]["operation"]["expected_quorum"] = false.into();
    assert_violation(
        "readiness_schedule_mismatch",
        &run_mutated(&mismatched_schedule_claim),
    );

    let mut missing_initial_authority = fixture_rows();
    for row_index in [4, 9, 14] {
        missing_initial_authority[row_index]["operation"]["state"] = "not_ready".into();
        missing_initial_authority[row_index]["operation"]["raft_term"] = Value::Null;
        missing_initial_authority[row_index]["operation"]["raft_commit_index"] = Value::Null;
        missing_initial_authority[row_index]["operation"]["raft_applied_index"] = Value::Null;
        missing_initial_authority[row_index]["operation"]["journal_head"] = Value::Null;
    }
    assert_violation(
        "initial_authority_observation_violation",
        &run_mutated(&missing_initial_authority),
    );

    let mut no_bounded_recovery = fixture_rows();
    no_bounded_recovery[5]["operation"]["state"] = "not_ready".into();
    no_bounded_recovery[5]["operation"]["raft_term"] = Value::Null;
    no_bounded_recovery[5]["operation"]["raft_commit_index"] = Value::Null;
    no_bounded_recovery[5]["operation"]["raft_applied_index"] = Value::Null;
    no_bounded_recovery[5]["operation"]["journal_head"] = Value::Null;
    assert_violation(
        "readiness_recovery_violation",
        &run_mutated(&no_bounded_recovery),
    );

    let mut overlong_sample = fixture_rows();
    overlong_sample[5]["started_ns"] = 0.into();
    overlong_sample[5]["completed_ns"] = 550.into();
    assert_violation("readiness_sampling_gap", &run_mutated(&overlong_sample));

    let mut malformed_schedule: Value =
        serde_json::from_str(FAULT_SCHEDULE_FIXTURE).expect("fault schedule fixture");
    malformed_schedule["intervals"][0]["running_process_ids"][0] = "node-x".into();
    assert_invalid(&run_mutated_fault_schedule(&malformed_schedule));

    let mut skipped_loss_schedule: Value =
        serde_json::from_str(FAULT_SCHEDULE_FIXTURE).expect("fault schedule fixture");
    skipped_loss_schedule["intervals"][0]["completed_ns"] = 749.into();
    skipped_loss_schedule["intervals"][1]["started_ns"] = 750.into();
    skipped_loss_schedule["intervals"][1]["completed_ns"] = 751.into();
    skipped_loss_schedule["intervals"][2]["started_ns"] = 752.into();
    let mut skipped_loss_rows = fixture_rows();
    for row_index in [6, 11, 16] {
        skipped_loss_rows[row_index]["operation"]["expected_quorum"] = true.into();
        skipped_loss_rows[row_index]["operation"]["state"] = "ready".into();
        skipped_loss_rows[row_index]["operation"]["raft_term"] = 2.into();
        skipped_loss_rows[row_index]["operation"]["raft_commit_index"] = 6.into();
        skipped_loss_rows[row_index]["operation"]["raft_applied_index"] = 6.into();
        skipped_loss_rows[row_index]["operation"]["journal_head"] = 12.into();
    }
    assert_violation(
        "readiness_loss_observation_violation",
        &run_mutated_with_fault_schedule(&skipped_loss_rows, &skipped_loss_schedule),
    );

    let mut skipped_recovery_schedule: Value =
        serde_json::from_str(FAULT_SCHEDULE_FIXTURE).expect("fault schedule fixture");
    let intervals = skipped_recovery_schedule["intervals"]
        .as_array()
        .expect("fault intervals");
    let initial = intervals[0].clone();
    let first_loss = intervals[1].clone();
    let mut brief_recovery = intervals[0].clone();
    brief_recovery["interval_sequence"] = 3.into();
    brief_recovery["started_ns"] = 800.into();
    brief_recovery["completed_ns"] = 801.into();
    let mut second_loss = intervals[1].clone();
    second_loss["interval_sequence"] = 4.into();
    second_loss["started_ns"] = 802.into();
    second_loss["completed_ns"] = 899.into();
    let mut final_recovery = intervals[2].clone();
    final_recovery["interval_sequence"] = 5.into();
    final_recovery["started_ns"] = 900.into();
    skipped_recovery_schedule["intervals"] = Value::Array(vec![
        initial,
        first_loss,
        brief_recovery,
        second_loss,
        final_recovery,
    ]);
    let mut skipped_recovery_rows = fixture_rows();
    for row_index in [7, 12, 17] {
        skipped_recovery_rows[row_index]["started_ns"] = 850.into();
        skipped_recovery_rows[row_index]["completed_ns"] = 850.into();
        skipped_recovery_rows[row_index]["operation"]["expected_quorum"] = false.into();
        skipped_recovery_rows[row_index]["operation"]["state"] = "not_ready".into();
        skipped_recovery_rows[row_index]["operation"]["raft_term"] = Value::Null;
        skipped_recovery_rows[row_index]["operation"]["raft_commit_index"] = Value::Null;
        skipped_recovery_rows[row_index]["operation"]["raft_applied_index"] = Value::Null;
        skipped_recovery_rows[row_index]["operation"]["journal_head"] = Value::Null;
    }
    assert_violation(
        "readiness_recovery_observation_violation",
        &run_mutated_with_fault_schedule(&skipped_recovery_rows, &skipped_recovery_schedule),
    );
}

#[test]
fn checker_accepts_real_probe_intervals_and_brackets_batch_history() {
    let rows = fixture_rows();
    for row_index in [4, 9, 14] {
        assert!(rows[row_index]["started_ns"].as_u64() < rows[row_index]["completed_ns"].as_u64());
        assert!(rows[row_index]["completed_ns"].as_u64() <= Some(100));
    }
    for row_index in [8, 13, 18] {
        assert!(rows[row_index]["started_ns"].as_u64() < rows[row_index]["completed_ns"].as_u64());
        assert!(rows[row_index]["started_ns"].as_u64() >= Some(450));
    }
    assert_eq!(output_json(&run_mutated(&rows))["status"], "pass");

    let mut initial_probe_overlaps_batch = fixture_rows();
    initial_probe_overlaps_batch[4]["started_ns"] = 90.into();
    initial_probe_overlaps_batch[4]["completed_ns"] = 110.into();
    assert_violation(
        "initial_authority_observation_violation",
        &run_mutated(&initial_probe_overlaps_batch),
    );

    let mut no_post_batch_authority = fixture_rows();
    no_post_batch_authority[1]["completed_ns"] = 971.into();
    assert_violation(
        "end_of_campaign_journal_head_violation",
        &run_mutated(&no_post_batch_authority),
    );
}

#[test]
fn checker_requires_terminal_watch_and_post_batch_restore_coverage() {
    let mut trivial_watch = fixture_rows();
    trivial_watch[2]["started_ns"] = 50.into();
    trivial_watch[2]["completed_ns"] = 90.into();
    trivial_watch[2]["operation"]["complete_through_journal_sequence"] = 9.into();
    trivial_watch[2]["operation"]["events"] = serde_json::json!([]);
    assert_violation(
        "watch_terminal_coverage_violation",
        &run_mutated(&trivial_watch),
    );

    let mut pre_batch_restore = fixture_rows();
    pre_batch_restore[3]["started_ns"] = 50.into();
    pre_batch_restore[3]["completed_ns"] = 90.into();
    pre_batch_restore[3]["operation"]["records"] = serde_json::json!([]);
    assert_violation(
        "restore_terminal_coverage_violation",
        &run_mutated(&pre_batch_restore),
    );
}

#[test]
fn checker_rejects_non_integer_fault_schedule_envelope_times() {
    let mut false_start: Value =
        serde_json::from_str(FAULT_SCHEDULE_FIXTURE).expect("fault schedule fixture");
    false_start["campaign_started_ns"] = false.into();
    assert_invalid(&run_mutated_fault_schedule(&false_start));
}

#[test]
fn checker_indexes_restore_prefixes_once() {
    let checker = fs::read_to_string(checker_path()).expect("checker source");
    assert!(checker.contains("class PrefixStateIndex"));
    assert!(checker.contains("heads_by_state"));
    assert!(checker.contains("bisect.bisect_left"));
    assert!(!checker.contains("def state_through"));
}

#[test]
fn checker_keeps_unknown_slot_outcomes_inconclusive() {
    let mut rows = fixture_rows();
    rows[1]["operation"]["outcome"] = "indeterminate".into();
    rows[1]["operation"]["slots"][0]["outcome"] = "indeterminate".into();
    rows[1]["operation"]["slots"][0]["journal_sequence"] = Value::Null;

    let output = run_mutated(&rows);
    assert_eq!(output.status.code(), Some(2));
    let result = output_json(&output);
    assert_eq!(result["status"], "inconclusive");
    assert_eq!(
        result["inconclusive_codes"],
        serde_json::json!([
            "unknown_batch_invocation_outcome",
            "unknown_batch_slot_outcome"
        ])
    );
    assert_eq!(result["violation_codes"], serde_json::json!([]));
}

#[test]
fn checker_rejects_cross_domain_fields_and_unbound_input() {
    let mut rows = fixture_rows();
    let readiness = rows[5]["operation"]
        .as_object_mut()
        .expect("readiness operation");
    let commit = readiness
        .remove("raft_commit_index")
        .expect("raft commit index");
    readiness.insert("commit_index".into(), commit);
    let output = run_mutated(&rows);
    assert_eq!(output.status.code(), Some(3));
    assert_eq!(output_json(&output)["status"], "invalid_input");

    let directory = tempfile::tempdir().expect("invalid checker directory");
    let mut evidence: Value = serde_json::from_str(EVIDENCE_FIXTURE).expect("evidence fixture");
    evidence["history"]["sha256"] =
        "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".into();
    let unbound_path = directory.path().join("unbound-evidence.json");
    fs::write(
        &unbound_path,
        serde_json::to_vec(&evidence).expect("encode unbound evidence"),
    )
    .expect("write unbound evidence");
    let unbound_output = run_checker(
        &unbound_path,
        &fault_schedule_fixture_path(),
        &history_fixture_path(),
    );
    assert_eq!(unbound_output.status.code(), Some(3));
    assert_eq!(output_json(&unbound_output)["status"], "invalid_input");
}

#[test]
fn checker_fails_closed_on_malformed_or_duplicate_json() {
    let directory = tempfile::tempdir().expect("invalid checker directory");
    let malformed = format!("{{\"value\":{}}}\n", "9".repeat(32 * 1024));
    let history_path = directory.path().join("malformed.jsonl");
    fs::write(&history_path, malformed.as_bytes()).expect("write malformed history");
    let evidence_path = write_bound_evidence(directory.path(), malformed.as_bytes());
    let malformed_output = run_checker(
        &evidence_path,
        &fault_schedule_fixture_path(),
        &history_path,
    );
    assert_eq!(malformed_output.status.code(), Some(3));
    assert_eq!(output_json(&malformed_output)["status"], "invalid_input");

    let duplicate = b"{\"value\":1,\"value\":2}\n";
    let duplicate_path = directory.path().join("duplicate.jsonl");
    fs::write(&duplicate_path, duplicate).expect("write duplicate-field history");
    let duplicate_evidence = write_bound_evidence(directory.path(), duplicate);
    let duplicate_output = run_checker(
        &duplicate_evidence,
        &fault_schedule_fixture_path(),
        &duplicate_path,
    );
    assert_eq!(duplicate_output.status.code(), Some(3));
    assert_eq!(output_json(&duplicate_output)["status"], "invalid_input");

    assert_invalid(&run_mutated_evidence(|evidence| {
        evidence["source_tree_status"] = serde_json::json!([]);
    }));

    let mut object_enum = fixture_rows();
    object_enum[0]["operation"]["slots"][0]["outcome"] = serde_json::json!({});
    assert_invalid(&run_mutated(&object_enum));
}
