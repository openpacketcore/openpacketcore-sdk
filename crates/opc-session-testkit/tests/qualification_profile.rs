use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::{Command, Output};

use opc_session_net::{
    CURRENT_SESSION_CONSENSUS_CONTRACT_PROFILE, MAX_NEGOTIATED_FRAME_SIZE,
    MIN_SESSION_CONSENSUS_FRAME_SIZE, SESSION_CONSENSUS_ALPN, SESSION_CONSENSUS_TRANSPORT_REVISION,
};
use opc_session_store::{
    DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT, MAX_REPLICATION_LOG_PAGE_ENTRIES,
    MAX_REPLICATION_OPERATIONS_PER_ENTRY, MAX_REPLICATION_OPERATION_DEPTH,
    MAX_REPLICATION_WATCH_BACKLOG_ENTRIES, MAX_SESSION_TTL, QUORUM_TOPOLOGY_MAX_MEMBERS,
    REPLICATION_TX_ID_MAX_BYTES, RESTORE_SCAN_MAX_EXAMINED_ROWS_PER_PAGE,
    RESTORE_SCAN_MAX_PAGE_PAYLOAD_BYTES, RESTORE_SCAN_MAX_PAGE_SIZE,
    RESTORE_SCAN_MAX_SQLITE_WORK_MILLIS, SESSION_CONSENSUS_MAX_RPC_PAYLOAD_BYTES,
    SESSION_CONSENSUS_SCHEMA_VERSION, STABLE_ID_MAX_BYTES,
};
use opc_session_testkit::qualification::{
    SessionHaQualificationProfile, SESSION_HA_EVIDENCE_SCHEMA_JSON, SESSION_HA_HISTORY_SCHEMA_JSON,
    SESSION_HA_PROFILE_JSON, SESSION_HA_PROFILE_SCHEMA_JSON, SESSION_HA_SCHEDULE_SCHEMA_JSON,
};
use serde_json::Value;

const EVIDENCE_FIXTURE: &str = include_str!("fixtures/session-ha/evidence-fixture.json");
const HISTORY_FIXTURE: &str = include_str!("fixtures/session-ha/history-valid.jsonl");
const SCHEDULE_FIXTURE: &str = include_str!("fixtures/session-ha/schedule-valid.jsonl");
const OMITTED_HISTORY_FIXTURE: &str =
    include_str!("fixtures/session-ha/history-invalid-omitted.jsonl");

fn run_checker(history: &str) -> Output {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    Command::new("python3")
        .arg(manifest.join("../../scripts/check-session-ha-history.py"))
        .arg("--schedule")
        .arg(manifest.join("tests/fixtures/session-ha/schedule-valid.jsonl"))
        .arg("--history")
        .arg(manifest.join("tests/fixtures/session-ha").join(history))
        .output()
        .expect("run independent history checker")
}

fn run_checker_pair(schedule: &str, history: &str) -> Output {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    Command::new("python3")
        .arg(manifest.join("../../scripts/check-session-ha-history.py"))
        .arg("--schedule")
        .arg(manifest.join("tests/fixtures/session-ha").join(schedule))
        .arg("--history")
        .arg(manifest.join("tests/fixtures/session-ha").join(history))
        .output()
        .expect("run independent history checker pair")
}

fn structural_schema_for_lightweight_validator(mut schema: Value) -> Value {
    match &mut schema {
        Value::Object(object) => {
            for unsupported in ["maxItems", "maxLength", "maximum", "pattern", "uniqueItems"] {
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

fn validate_structural_schema(schema: &Value, instance: &Value) -> Result<(), String> {
    opc_schema_validate::validate(
        &structural_schema_for_lightweight_validator(schema.clone()),
        instance,
    )
}

fn is_lower_hex(value: &str, width: usize) -> bool {
    value.len() == width
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_sha256(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|digest| is_lower_hex(digest, 64))
}

fn validate_exact_evidence_fields(evidence: &Value) -> Result<(), String> {
    let revision = evidence["source_revision"]
        .as_str()
        .ok_or_else(|| "source revision missing".to_owned())?;
    if !is_lower_hex(revision, 40) {
        return Err("source revision is not exact lowercase hexadecimal".to_owned());
    }
    let mut digests = vec![
        evidence["artifact"]["sha256"].as_str(),
        evidence["execution"]["profile_sha256"].as_str(),
        evidence["execution"]["configuration_sha256"].as_str(),
        evidence["execution"]["fault_schedule_sha256"].as_str(),
        evidence["history"]["sha256"].as_str(),
        evidence["history"]["schedule_sha256"].as_str(),
        evidence["checker"]["sha256"].as_str(),
        evidence["checker"]["output_sha256"].as_str(),
    ];
    if let Some(container_digest) = evidence["environment"]["container_image_digest"].as_str() {
        digests.push(Some(container_digest));
    }
    for field in ["logs", "metrics"] {
        digests.extend(
            evidence[field]["digests"]
                .as_array()
                .into_iter()
                .flatten()
                .map(Value::as_str),
        );
    }
    digests.extend(
        evidence["topology"]["storage_identity_sha256"]
            .as_array()
            .into_iter()
            .flatten()
            .map(Value::as_str),
    );
    if !digests
        .into_iter()
        .all(|digest| digest.is_some_and(is_sha256))
    {
        return Err("evidence digest is not exact lowercase SHA-256".to_owned());
    }
    let members = evidence["topology"]["members"]
        .as_u64()
        .ok_or_else(|| "member count missing".to_owned())? as usize;
    if !matches!(members, 3 | 5) {
        return Err("member count is outside the exact profile".to_owned());
    }
    let storage = evidence["topology"]["storage_identity_sha256"]
        .as_array()
        .ok_or_else(|| "storage identities missing".to_owned())?;
    let distinct_storage = storage
        .iter()
        .filter_map(Value::as_str)
        .collect::<BTreeSet<_>>();
    if storage.len() != members || distinct_storage.len() != storage.len() {
        return Err("storage identities are not distinct per voter".to_owned());
    }
    Ok(())
}

fn validate_history_shape(history: &str, schema: &Value) -> Result<(), String> {
    let mut operations = Vec::new();
    for line in history.lines() {
        let operation: Value = serde_json::from_str(line).map_err(|_| "invalid JSON line")?;
        validate_structural_schema(schema, &operation)?;
        if !operation["schedule_sha256"].as_str().is_some_and(is_sha256) {
            return Err("invalid exact schedule digest".to_owned());
        }
        for field in ["key_sha256", "owner_sha256", "value_sha256"] {
            if let Some(value) = operation["operation"].get(field).and_then(Value::as_str) {
                if !is_sha256(value) {
                    return Err("invalid exact history digest".to_owned());
                }
            }
        }
        if let Some(record) = operation["operation"].get("record") {
            for field in ["owner_sha256", "value_sha256"] {
                if let Some(value) = record.get(field).and_then(Value::as_str) {
                    if !is_sha256(value) {
                        return Err("invalid exact record digest".to_owned());
                    }
                }
            }
        }
        operations.push(operation);
    }
    let expected_count = operations
        .first()
        .and_then(|operation| operation["history_operation_count"].as_u64())
        .ok_or_else(|| "history operation count missing".to_owned())?
        as usize;
    let expected_history_id = operations
        .first()
        .and_then(|operation| operation["history_id"].as_str())
        .ok_or_else(|| "history ID missing".to_owned())?;
    if operations.len() != expected_count {
        return Err("history omitted an invocation".to_owned());
    }
    let mut operation_ids = BTreeSet::new();
    for (offset, operation) in operations.iter().enumerate() {
        let operation_id = operation["operation_id"]
            .as_str()
            .ok_or_else(|| "operation ID missing".to_owned())?;
        let started_ns = operation["started_ns"]
            .as_u64()
            .ok_or_else(|| "operation start missing".to_owned())?;
        let completed_ns = operation["completed_ns"]
            .as_u64()
            .ok_or_else(|| "operation completion missing".to_owned())?;
        if operation["history_operation_count"].as_u64() != Some(expected_count as u64)
            || operation["history_id"].as_str() != Some(expected_history_id)
            || operation["operation_index"].as_u64() != Some((offset + 1) as u64)
            || started_ns > completed_ns
            || !operation_ids.insert(operation_id)
        {
            return Err("history invocation envelope is inconsistent".to_owned());
        }
    }
    Ok(())
}

#[test]
fn exact_profile_matches_the_compiled_consensus_and_store_contract() {
    let profile_value: Value = serde_json::from_str(SESSION_HA_PROFILE_JSON).expect("profile JSON");
    let profile_schema: Value =
        serde_json::from_str(SESSION_HA_PROFILE_SCHEMA_JSON).expect("profile schema JSON");
    validate_structural_schema(&profile_schema, &profile_value)
        .expect("profile satisfies its committed schema");
    let profile: SessionHaQualificationProfile =
        serde_json::from_value(profile_value).expect("strict typed profile");

    assert_eq!(profile.schema_version, "opc-session-ha-profile/v1");
    assert_eq!(profile.profile_id, "opc-session-openraft-ha/v1");
    assert_eq!(profile.maturity, "experimental");
    assert!(!profile.qualification_complete);
    assert_eq!(profile.workspace.version, env!("CARGO_PKG_VERSION"));
    assert_eq!(profile.workspace.rust_msrv, "1.88");
    assert_eq!(profile.workspace.source_revision, "required-in-evidence");

    assert_eq!(profile.topology.member_counts, [3, 5]);
    assert_eq!(
        profile.topology.maximum_members,
        QUORUM_TOPOLOGY_MAX_MEMBERS
    );
    assert_eq!(profile.topology.quorum_rule, "floor(n/2)+1");
    assert!(profile.topology.distinct_failure_domain_per_voter);
    assert!(profile.topology.distinct_backing_store_per_voter);
    assert!(profile.topology.stable_identity_independent_of_route);

    let contract = CURRENT_SESSION_CONSENSUS_CONTRACT_PROFILE;
    assert_eq!(
        profile.protocol.consensus_alpn.as_bytes(),
        SESSION_CONSENSUS_ALPN
    );
    assert_eq!(
        profile.protocol.transport_revision,
        SESSION_CONSENSUS_TRANSPORT_REVISION
    );
    assert_eq!(
        profile.protocol.wire_schema_revision,
        contract.wire_schema_revision
    );
    assert_eq!(
        profile.protocol.error_set_revision,
        contract.error_set_revision
    );
    assert_eq!(
        profile.protocol.consensus_schema_version,
        SESSION_CONSENSUS_SCHEMA_VERSION
    );
    assert_eq!(
        profile.protocol.min_frame_bytes,
        MIN_SESSION_CONSENSUS_FRAME_SIZE
    );
    assert_eq!(profile.protocol.max_frame_bytes, MAX_NEGOTIATED_FRAME_SIZE);
    assert_eq!(
        profile.protocol.max_rpc_payload_bytes,
        SESSION_CONSENSUS_MAX_RPC_PAYLOAD_BYTES
    );
    assert!(!profile.protocol.legacy_direct_backend_enabled);

    assert_eq!(
        profile.bounds.operation_timeout_millis,
        DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT.as_millis() as u64
    );
    assert_eq!(
        profile.bounds.max_session_ttl_seconds,
        MAX_SESSION_TTL.as_secs()
    );
    assert_eq!(profile.bounds.max_stable_id_bytes, STABLE_ID_MAX_BYTES);
    assert_eq!(
        profile.bounds.max_replication_transaction_id_bytes,
        REPLICATION_TX_ID_MAX_BYTES
    );
    assert_eq!(
        profile.bounds.max_replication_operation_depth,
        MAX_REPLICATION_OPERATION_DEPTH
    );
    assert_eq!(
        profile.bounds.max_replication_operations_per_entry,
        MAX_REPLICATION_OPERATIONS_PER_ENTRY
    );
    assert_eq!(
        profile.bounds.max_replication_log_page_entries,
        MAX_REPLICATION_LOG_PAGE_ENTRIES
    );
    assert_eq!(
        profile.bounds.max_watch_backlog_entries,
        MAX_REPLICATION_WATCH_BACKLOG_ENTRIES
    );
    assert_eq!(
        profile.bounds.max_restore_page_records,
        RESTORE_SCAN_MAX_PAGE_SIZE
    );
    assert_eq!(
        profile.bounds.max_restore_page_payload_bytes,
        RESTORE_SCAN_MAX_PAGE_PAYLOAD_BYTES
    );
    assert_eq!(
        profile.bounds.max_restore_examined_rows,
        RESTORE_SCAN_MAX_EXAMINED_ROWS_PER_PAGE
    );
    assert_eq!(
        profile.bounds.max_restore_sqlite_work_millis,
        RESTORE_SCAN_MAX_SQLITE_WORK_MILLIS
    );

    let artifact_names = profile
        .artifacts
        .iter()
        .map(|artifact| artifact.crate_name.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(artifact_names.len(), profile.artifacts.len());
    assert_eq!(
        artifact_names,
        BTreeSet::from([
            "openraft",
            "opc-consensus",
            "opc-session-net",
            "opc-session-store"
        ])
    );
    let network = profile
        .artifacts
        .iter()
        .find(|artifact| artifact.crate_name == "opc-session-net")
        .expect("network artifact inventory");
    assert!(!network.publish);
    assert!(network.required_features.is_empty());
    assert_eq!(
        network.excluded_features,
        ["insecure-test", "legacy-session-net-compat"]
    );
    assert!(profile
        .platforms
        .iter()
        .all(|platform| platform.status == "qualification-pending"));

    assert_eq!(
        profile.provisional_test_thresholds.acknowledged_write_loss,
        0
    );
    assert_eq!(
        profile
            .provisional_test_thresholds
            .stale_owner_mutation_successes,
        0
    );
    assert_eq!(
        profile
            .provisional_test_thresholds
            .conflicting_committed_entries,
        0
    );
    assert_eq!(profile.provisional_test_thresholds.watch_gaps, 0);
    assert!(profile.provisional_test_thresholds.max_startup_millis > 0);
    assert!(
        profile
            .provisional_test_thresholds
            .max_single_member_failover_millis
            > 0
    );
    assert!(
        profile
            .provisional_test_thresholds
            .max_restart_catchup_millis
            > 0
    );
    assert!(profile.provisional_test_thresholds.minimum_soak_seconds > 0);
    assert_eq!(
        profile.evidence.foundation_transport_mode,
        "loopback-plaintext-test-only"
    );
    assert_eq!(profile.evidence.required_transport_modes, ["mtls"]);
    assert!(!profile.evidence.foundation_counts_for_tls_rotation);
    assert_eq!(
        profile.evidence.foundation_payload_protection,
        "fixed-memory-provider-synthetic-wrapper-only"
    );
    assert!(!profile.evidence.foundation_counts_for_production_encryption);
    assert_eq!(
        profile.evidence.unresolved_dependencies,
        [143, 158, 163, 164]
    );

    let exact_artifacts = profile
        .artifacts
        .iter()
        .map(|artifact| (artifact.crate_name.as_str(), artifact))
        .collect::<BTreeMap<_, _>>();
    let consensus = exact_artifacts["opc-consensus"];
    assert_eq!(consensus.version, "0.2.0");
    assert!(consensus.publish);
    assert!(consensus.required_features.is_empty());
    assert!(consensus.excluded_features.is_empty());

    let store = exact_artifacts["opc-session-store"];
    assert_eq!(store.version, "0.2.0");
    assert!(store.publish);
    assert!(store.required_features.is_empty());
    assert!(store.excluded_features.is_empty());

    let network = exact_artifacts["opc-session-net"];
    assert_eq!(network.version, "0.2.0");
    assert!(!network.publish);
    assert!(network.required_features.is_empty());
    assert_eq!(
        network.excluded_features,
        ["insecure-test", "legacy-session-net-compat"]
    );

    let openraft = exact_artifacts["openraft"];
    assert_eq!(openraft.version, "0.9.24");
    assert!(openraft.publish);
    assert_eq!(
        openraft.required_features,
        ["serde", "single-term-leader", "storage-v2"]
    );
    assert!(openraft.excluded_features.is_empty());
    assert_eq!(
        profile
            .platforms
            .iter()
            .map(|platform| platform.target.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["aarch64-unknown-linux-gnu", "x86_64-unknown-linux-gnu"])
    );
    assert_eq!(profile.evidence.required_topologies, [3, 5]);
    assert_eq!(
        profile.evidence.schedule_schema,
        "session-ha-schedule.schema.json"
    );
    serde_json::from_str::<Value>(SESSION_HA_SCHEDULE_SCHEMA_JSON).expect("schedule schema JSON");
}

#[test]
fn inventory_pins_workspace_msrv_publish_state_and_openraft_version() {
    let workspace = include_str!("../../../Cargo.toml");
    assert!(workspace.contains("rust-version = \"1.88\""));
    let network_manifest = include_str!("../../opc-session-net/Cargo.toml");
    assert!(network_manifest.contains("publish = false"));
    let lockfile = include_str!("../../../Cargo.lock");
    assert!(lockfile.contains("name = \"openraft\"\nversion = \"0.9.24\""));
}

#[test]
fn history_and_evidence_fixtures_satisfy_strict_schemas() {
    let schedule_schema: Value =
        serde_json::from_str(SESSION_HA_SCHEDULE_SCHEMA_JSON).expect("schedule schema JSON");
    for line in SCHEDULE_FIXTURE.lines() {
        let operation: Value = serde_json::from_str(line).expect("schedule fixture line");
        validate_structural_schema(&schedule_schema, &operation)
            .expect("schedule operation satisfies schema");
    }
    let history_schema: Value =
        serde_json::from_str(SESSION_HA_HISTORY_SCHEMA_JSON).expect("history schema JSON");
    for line in HISTORY_FIXTURE.lines() {
        let operation: Value = serde_json::from_str(line).expect("history fixture line");
        validate_structural_schema(&history_schema, &operation)
            .expect("history operation satisfies schema");
    }

    let evidence_schema: Value =
        serde_json::from_str(SESSION_HA_EVIDENCE_SCHEMA_JSON).expect("evidence schema JSON");
    let evidence: Value = serde_json::from_str(EVIDENCE_FIXTURE).expect("evidence fixture JSON");
    validate_structural_schema(&evidence_schema, &evidence)
        .expect("evidence fixture satisfies schema");
    validate_exact_evidence_fields(&evidence).expect("evidence exact digests and topology");
    validate_history_shape(HISTORY_FIXTURE, &history_schema)
        .expect("history fixture is complete and exact");
    assert!(validate_history_shape(OMITTED_HISTORY_FIXTURE, &history_schema).is_err());
}

#[test]
fn independent_checker_binds_schedule_and_preserves_unknown_invocations() {
    let passed = run_checker("history-valid.jsonl");
    assert!(
        passed.status.success(),
        "{}",
        String::from_utf8_lossy(&passed.stderr)
    );
    let passed_output: Value = serde_json::from_slice(&passed.stdout).expect("checker pass output");
    assert_eq!(passed_output["status"], "pass");
    assert_eq!(passed_output["operations_checked"], 7);

    let omitted = run_checker("history-invalid-omitted.jsonl");
    assert_eq!(omitted.status.code(), Some(2));
    let omitted_output: Value =
        serde_json::from_slice(&omitted.stdout).expect("checker omission output");
    assert_eq!(omitted_output["status"], "inconclusive");
    assert_eq!(
        omitted_output["inconclusive_codes"],
        serde_json::json!(["dependent_on_unknown_outcome", "missing_history_operation"])
    );

    let invalid = run_checker("history-invalid-outcome.jsonl");
    assert_eq!(invalid.status.code(), Some(3));
    let invalid_output: Value =
        serde_json::from_slice(&invalid.stdout).expect("checker invalid output");
    assert_eq!(invalid_output["status"], "invalid_input");

    let ambiguous = run_checker_pair(
        "schedule-lease-expiry-ambiguous.jsonl",
        "history-lease-expiry-ambiguous.jsonl",
    );
    assert_eq!(ambiguous.status.code(), Some(2));
    let ambiguous_output: Value =
        serde_json::from_slice(&ambiguous.stdout).expect("checker ambiguity output");
    assert_eq!(ambiguous_output["status"], "inconclusive");
    assert_eq!(
        ambiguous_output["inconclusive_codes"],
        serde_json::json!(["lease_expiry_ambiguity"])
    );

    let crossing = run_checker_pair(
        "schedule-lease-expiry-crossing.jsonl",
        "history-lease-expiry-crossing.jsonl",
    );
    assert_eq!(crossing.status.code(), Some(2));
    let crossing_output: Value =
        serde_json::from_slice(&crossing.stdout).expect("checker crossing output");
    assert_eq!(crossing_output["status"], "inconclusive");
    assert_eq!(
        crossing_output["inconclusive_codes"],
        serde_json::json!(["lease_expiry_ambiguity"])
    );
}

#[test]
fn schemas_prevent_premature_production_or_tls_rotation_claims() {
    let profile_schema: Value =
        serde_json::from_str(SESSION_HA_PROFILE_SCHEMA_JSON).expect("profile schema JSON");
    let mut profile: Value = serde_json::from_str(SESSION_HA_PROFILE_JSON).expect("profile JSON");
    profile["maturity"] = "production".into();
    assert!(validate_structural_schema(&profile_schema, &profile).is_err());

    let evidence_schema: Value =
        serde_json::from_str(SESSION_HA_EVIDENCE_SCHEMA_JSON).expect("evidence schema JSON");
    let mut evidence: Value =
        serde_json::from_str(EVIDENCE_FIXTURE).expect("evidence fixture JSON");
    evidence["topology"]["counts_for_tls_rotation"] = true.into();
    assert!(validate_structural_schema(&evidence_schema, &evidence).is_err());
    evidence["topology"]["counts_for_tls_rotation"] = false.into();
    evidence["qualification_complete"] = true.into();
    assert!(validate_structural_schema(&evidence_schema, &evidence).is_err());

    evidence["qualification_complete"] = false.into();
    evidence["source_revision"] = "ABC".into();
    assert!(validate_exact_evidence_fields(&evidence).is_err());
    evidence["source_revision"] = "0000000000000000000000000000000000000000".into();
    evidence["artifact"]["sha256"] = "sha256:ABC".into();
    assert!(validate_exact_evidence_fields(&evidence).is_err());
}
