use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::process::{Command, Output};

use opc_consensus::{DURABLE_CONSENSUS_TIMING_PROFILE, DURABLE_OPENRAFT_PROFILE};
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
    SESSION_MTLS_CANDIDATE_EVIDENCE_SCHEMA_JSON,
};
use serde_json::Value;

const EVIDENCE_FIXTURE: &str = include_str!("fixtures/session-ha/evidence-fixture-v2.json");
const HISTORY_FIXTURE: &str = include_str!("fixtures/session-ha/history-valid.jsonl");
const SCHEDULE_FIXTURE: &str = include_str!("fixtures/session-ha/schedule-valid.jsonl");
const OMITTED_HISTORY_FIXTURE: &str =
    include_str!("fixtures/session-ha/history-invalid-omitted.jsonl");
const MTLS_CANDIDATE_REMAINING_ACCEPTANCE: [&str; 7] = [
    "five_member_mtls_matrix",
    "projected_material_rotation_under_continuous_traffic",
    "old_and_new_trust_overlap",
    "post_overlap_old_trust_rejection",
    "certificate_expiry_retirement",
    "bounded_drain_and_reconnect_evidence",
    "platform_and_soak_matrix",
];

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

fn run_checker_paths(schedule: &Path, history: &Path) -> Output {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    Command::new("python3")
        .arg(manifest.join("../../scripts/check-session-ha-history.py"))
        .arg("--schedule")
        .arg(schedule)
        .arg("--history")
        .arg(history)
        .output()
        .expect("run independent history checker with generated inputs")
}

fn assert_canonical_invalid_input(output: &Output) {
    assert_eq!(output.status.code(), Some(3));
    assert!(output.stderr.is_empty());
    assert_eq!(
        output.stdout,
        b"{\"checker\":\"check-session-ha-history.py\",\"checker_version\":\"1\",\"inconclusive_codes\":[],\"operations_checked\":0,\"status\":\"invalid_input\",\"violation_codes\":[]}\n"
    );
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

fn validate_mtls_candidate_evidence(schema: &Value, evidence: &Value) -> Result<(), String> {
    validate_structural_schema(schema, evidence)?;
    if evidence["topology"]["members"].as_u64() != Some(3)
        || evidence["observations"]["directed_handshake_count"].as_u64() != Some(6)
    {
        return Err("mTLS candidate topology does not match the v1 checkpoint".to_owned());
    }
    let remaining = evidence["remaining_acceptance"]
        .as_array()
        .ok_or_else(|| "mTLS remaining acceptance is missing".to_owned())?;
    let actual = remaining
        .iter()
        .filter_map(Value::as_str)
        .collect::<BTreeSet<_>>();
    let expected = MTLS_CANDIDATE_REMAINING_ACCEPTANCE
        .into_iter()
        .collect::<BTreeSet<_>>();
    if remaining.len() != MTLS_CANDIDATE_REMAINING_ACCEPTANCE.len()
        || actual.len() != remaining.len()
        || actual != expected
    {
        return Err("mTLS remaining acceptance is not exact and unique".to_owned());
    }
    Ok(())
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

fn is_utc_timestamp(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 20
        && [4, 7].into_iter().all(|index| bytes[index] == b'-')
        && bytes[10] == b'T'
        && [13, 16].into_iter().all(|index| bytes[index] == b':')
        && bytes[19] == b'Z'
        && bytes.iter().enumerate().all(|(index, byte)| {
            matches!(index, 4 | 7 | 10 | 13 | 16 | 19) || byte.is_ascii_digit()
        })
}

fn validate_exact_evidence_fields(evidence: &Value) -> Result<(), String> {
    let revision = evidence["source_revision"]
        .as_str()
        .ok_or_else(|| "source revision missing".to_owned())?;
    if !is_lower_hex(revision, 40) {
        return Err("source revision is not exact lowercase hexadecimal".to_owned());
    }
    if !matches!(
        evidence["source_tree_status"].as_str(),
        Some("clean" | "dirty_unqualified")
    ) || evidence["artifact"]["foundation_feature_overrides"]
        != serde_json::json!(["opc-session-net/insecure-test"])
    {
        return Err("source state or foundation feature profile is invalid".to_owned());
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

    let started = evidence["execution"]["started_at_utc"]
        .as_str()
        .ok_or_else(|| "execution start missing".to_owned())?;
    let completed = evidence["execution"]["completed_at_utc"]
        .as_str()
        .ok_or_else(|| "execution completion missing".to_owned())?;
    if !is_utc_timestamp(started) || !is_utc_timestamp(completed) || started > completed {
        return Err("execution timestamps are malformed or reversed".to_owned());
    }

    let profile: SessionHaQualificationProfile = serde_json::from_str(SESSION_HA_PROFILE_JSON)
        .map_err(|_| "profile unavailable".to_owned())?;
    let results = &evidence["results"];
    let startup_within_bound = results["startup_millis"]
        .as_u64()
        .is_some_and(|value| value <= profile.provisional_test_thresholds.max_startup_millis);
    let continuity_within_bound = results["single_member_stop_service_continuity_millis"]
        .as_u64()
        .is_some_and(|value| {
            value
                <= profile
                    .provisional_test_thresholds
                    .max_single_member_stop_service_continuity_millis
        });
    let catchup_within_bound = results["restart_catchup_millis"]
        .as_u64()
        .is_some_and(|value| {
            value
                <= profile
                    .provisional_test_thresholds
                    .max_restart_catchup_millis
        });
    let leader_failover_within_bound =
        results["leader_failover_millis"]
            .as_u64()
            .is_some_and(|value| {
                value
                    <= profile
                        .provisional_test_thresholds
                        .max_leader_failover_millis
            });
    let leader_restart_within_bound = results["leader_restart_catchup_millis"]
        .as_u64()
        .is_some_and(|value| {
            value
                <= profile
                    .provisional_test_thresholds
                    .max_leader_restart_catchup_millis
        });
    if !(startup_within_bound
        && continuity_within_bound
        && catchup_within_bound
        && leader_failover_within_bound
        && leader_restart_within_bound
        && results["leader_outage_store_read_succeeded"] == true)
    {
        return Err("execution result is missing or outside provisional bounds".to_owned());
    }

    for field in ["logs", "metrics"] {
        let status = evidence[field]["collection_status"].as_str();
        let digest_count = evidence[field]["digests"]
            .as_array()
            .map(Vec::len)
            .ok_or_else(|| "collection digests missing".to_owned())?;
        if !matches!(
            (status, digest_count),
            (Some("collected"), 1..) | (Some("not_collected_in_foundation"), 0)
        ) {
            return Err("collection status and digests disagree".to_owned());
        }
    }
    let faults = evidence["faults"]
        .as_array()
        .ok_or_else(|| "fault evidence missing".to_owned())?;
    let first_fault = faults
        .first()
        .ok_or_else(|| "fault evidence missing".to_owned())?;
    let expected_target = first_fault["target_process"]
        .as_str()
        .filter(|target| matches!(*target, "node-0" | "node-2"))
        .ok_or_else(|| "fault target is outside the bounded candidate set".to_owned())?;
    let expected_node_id = first_fault["observed_node_id"]
        .as_u64()
        .filter(|value| *value > 0)
        .ok_or_else(|| "fault observation node is invalid".to_owned())?;
    let expected_leader_id = first_fault["observed_leader_id"]
        .as_u64()
        .filter(|value| *value > 0 && *value != expected_node_id)
        .ok_or_else(|| "fault observation leader is invalid".to_owned())?;
    let expected_term = first_fault["observed_term"]
        .as_u64()
        .filter(|value| *value > 0)
        .ok_or_else(|| "fault observation term is invalid".to_owned())?;
    let leader_fault = faults
        .get(2)
        .ok_or_else(|| "leader fault evidence missing".to_owned())?;
    let leader_target = leader_fault["target_process"]
        .as_str()
        .filter(|target| target.starts_with("node-"))
        .ok_or_else(|| "leader fault target is invalid".to_owned())?;
    let old_leader_id = leader_fault["observed_node_id"]
        .as_u64()
        .filter(|value| *value > 0)
        .ok_or_else(|| "leader fault node is invalid".to_owned())?;
    let old_term = leader_fault["observed_term"]
        .as_u64()
        .filter(|value| *value > 0)
        .ok_or_else(|| "leader fault term is invalid".to_owned())?;
    if faults.len() != 4
        || !faults[..2].iter().all(|fault| {
            fault["target_process"] == expected_target
                && fault["target_role"] == "follower"
                && fault["observed_node_id"].as_u64() == Some(expected_node_id)
                && fault["observed_leader_id"].as_u64() == Some(expected_leader_id)
                && fault["observed_term"].as_u64() == Some(expected_term)
        })
        || !faults[2..].iter().all(|fault| {
            fault["target_process"] == leader_target
                && fault["target_role"] == "leader"
                && fault["observed_node_id"].as_u64() == Some(old_leader_id)
                && fault["observed_leader_id"].as_u64() == Some(old_leader_id)
                && fault["observed_term"].as_u64() == Some(old_term)
        })
    {
        return Err(
            "fault evidence does not identify observed follower and leader roles".to_owned(),
        );
    }
    let transition = &evidence["leader_transition"];
    let new_leader_id = transition["new_leader_node_id"]
        .as_u64()
        .filter(|value| *value > 0 && *value != old_leader_id)
        .ok_or_else(|| "replacement leader is invalid".to_owned())?;
    let new_term = transition["new_term"]
        .as_u64()
        .filter(|value| *value > old_term)
        .ok_or_else(|| "replacement leader term did not advance".to_owned())?;
    if transition["old_leader_process"] != leader_target
        || transition["old_leader_node_id"].as_u64() != Some(old_leader_id)
        || transition["old_term"].as_u64() != Some(old_term)
        || transition["new_leader_process"]
            .as_str()
            .is_none_or(|process| !process.starts_with("node-"))
        || transition["new_leader_node_id"].as_u64() != Some(new_leader_id)
        || transition["new_term"].as_u64() != Some(new_term)
    {
        return Err("leader transition does not match observed fault evidence".to_owned());
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

    assert_eq!(profile.schema_version, "opc-session-ha-profile/v2");
    assert_eq!(profile.profile_id, "opc-session-openraft-ha/v2");
    assert_eq!(profile.maturity, "experimental");
    assert!(!profile.qualification_complete);
    assert_eq!(profile.workspace.version, env!("CARGO_PKG_VERSION"));
    assert_eq!(profile.workspace.rust_msrv, "1.88");
    assert_eq!(profile.workspace.source_revision, "required-in-evidence");
    assert_eq!(profile.source_build_gate.tracking_issue, 143);
    assert_eq!(
        profile.source_build_gate.openraft_git,
        "https://github.com/openpacketcore/openraft"
    );
    assert_eq!(
        profile.source_build_gate.openraft_rev,
        "f607e636406b16bd0ad7925dbb631da1b7a4cd96"
    );
    assert_eq!(
        profile.source_build_gate.affected_workspace_crates,
        [
            "opc-alarm",
            "opc-alarm-k8s",
            "opc-alarm-testkit",
            "opc-alarm-yang",
            "opc-amf-lite",
            "opc-amf-lite-testkit",
            "opc-config-bus",
            "opc-consensus",
            "opc-gnmi-server",
            "opc-ipsec-lb",
            "opc-mgmt-authz",
            "opc-mgmt-transport",
            "opc-netconf-server",
            "opc-persist",
            "opc-runtime",
            "opc-sa-mirror",
            "opc-sbi",
            "opc-sdk",
            "opc-sdk-integration",
            "opc-session-cache",
            "opc-session-net",
            "opc-session-store",
            "opc-session-testkit",
            "operator-controller",
            "operator-lifecycle",
            "operator-lifecycle-cli"
        ]
    );
    assert_eq!(profile.source_build_gate.crates_io_check_date, "2026-07-13");
    assert!(profile.source_build_gate.crates_io_exact_matches.is_empty());
    assert_eq!(
        profile.source_build_gate.removal_condition,
        "official stable Openraft release containing the fix, registry pin and checksum, and full issue #143 requalification"
    );

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

    let timing = DURABLE_CONSENSUS_TIMING_PROFILE;
    assert_eq!(
        profile.consensus_timing.cold_connect_budget_composition,
        "contained-within-family-deadline"
    );
    assert_eq!(
        profile.consensus_timing.cold_connect_timeout_millis,
        timing.cold_connect_timeout_millis
    );
    assert_eq!(
        profile.consensus_timing.append_entries_timeout_millis,
        timing.append_entries_timeout_millis
    );
    assert_eq!(
        profile.consensus_timing.heartbeat_interval_millis,
        DURABLE_OPENRAFT_PROFILE.heartbeat_interval_millis
    );
    assert_eq!(
        profile.consensus_timing.vote_timeout_millis,
        timing.vote_timeout_millis
    );
    assert_eq!(
        profile.consensus_timing.election_timeout_min_millis,
        DURABLE_OPENRAFT_PROFILE.election_timeout_min_millis
    );
    assert_eq!(
        profile.consensus_timing.election_timeout_max_millis,
        DURABLE_OPENRAFT_PROFILE.election_timeout_max_millis
    );
    assert_eq!(
        profile.consensus_timing.install_snapshot_timeout_millis,
        DURABLE_OPENRAFT_PROFILE.install_snapshot_timeout_millis
    );
    assert_eq!(
        profile.consensus_timing.forward_mutation_timeout_millis,
        timing.forward_mutation_timeout_millis
    );
    assert_eq!(
        profile.consensus_timing.read_barrier_timeout_millis,
        timing.read_barrier_timeout_millis
    );
    assert_eq!(
        profile.consensus_timing.server_idle_timeout_millis,
        timing.server_idle_timeout_millis
    );
    assert_eq!(
        profile.consensus_timing.server_handler_timeout_millis,
        timing.server_handler_timeout_millis
    );
    assert_eq!(
        profile.consensus_timing.heartbeat_interval_millis,
        profile.consensus_timing.append_entries_timeout_millis
    );
    assert!(
        profile.consensus_timing.cold_connect_timeout_millis
            < profile.consensus_timing.append_entries_timeout_millis
    );
    assert!(
        profile.consensus_timing.election_timeout_min_millis
            >= profile.consensus_timing.heartbeat_interval_millis * 2
    );
    assert!(
        profile.consensus_timing.election_timeout_min_millis
            < profile.consensus_timing.election_timeout_max_millis
    );

    assert_eq!(
        profile.bounds.operation_timeout_millis,
        DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT.as_millis() as u64
    );
    assert_eq!(
        profile.bounds.operation_timeout_millis,
        timing.operation_timeout_millis
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
            "opc-persist",
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
            .max_single_member_stop_service_continuity_millis
            > 0
    );
    assert!(
        profile
            .provisional_test_thresholds
            .max_restart_catchup_millis
            > 0
    );
    assert!(
        profile
            .provisional_test_thresholds
            .max_leader_failover_millis
            > 0
    );
    assert!(
        profile
            .provisional_test_thresholds
            .max_leader_restart_catchup_millis
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
    assert!(!consensus.publish);
    assert!(consensus.required_features.is_empty());
    assert!(consensus.excluded_features.is_empty());

    let store = exact_artifacts["opc-session-store"];
    assert_eq!(store.version, "0.2.0");
    assert!(!store.publish);
    assert!(store.required_features.is_empty());
    assert!(store.excluded_features.is_empty());

    let persist = exact_artifacts["opc-persist"];
    assert_eq!(persist.version, "0.2.0");
    assert!(!persist.publish);
    assert!(persist.required_features.is_empty());
    assert!(persist.excluded_features.is_empty());

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
    assert!(!openraft.publish);
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
fn inventory_pins_workspace_msrv_source_build_gate_and_openraft_revision() {
    let workspace = include_str!("../../../Cargo.toml");
    assert!(workspace.contains("rust-version = \"1.88\""));
    assert!(workspace.contains(
        "openraft = { version = \"=0.9.24\", git = \"https://github.com/openpacketcore/openraft\", rev = \"f607e636406b16bd0ad7925dbb631da1b7a4cd96\""
    ));
    for manifest in [
        include_str!("../../opc-alarm/Cargo.toml"),
        include_str!("../../opc-consensus/Cargo.toml"),
        include_str!("../../opc-persist/Cargo.toml"),
        include_str!("../../opc-sdk/Cargo.toml"),
        include_str!("../../opc-session-cache/Cargo.toml"),
        include_str!("../../opc-session-store/Cargo.toml"),
        include_str!("../../opc-session-net/Cargo.toml"),
    ] {
        assert!(manifest.contains("publish = false"));
    }
    let lockfile = include_str!("../../../Cargo.lock");
    assert!(lockfile.contains("name = \"openraft\"\nversion = \"0.9.24\""));
    assert!(lockfile.contains(
        "source = \"git+https://github.com/openpacketcore/openraft?rev=f607e636406b16bd0ad7925dbb631da1b7a4cd96#f607e636406b16bd0ad7925dbb631da1b7a4cd96\""
    ));
}

#[test]
fn cargo_metadata_matches_the_exact_openraft_and_foundation_feature_profile() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let repository = manifest.join("../..");
    let output = Command::new("cargo")
        .args(["metadata", "--format-version", "1", "--locked"])
        .current_dir(repository)
        .output()
        .expect("run locked Cargo metadata");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let metadata: Value = serde_json::from_slice(&output.stdout).expect("Cargo metadata JSON");
    let packages = metadata["packages"].as_array().expect("metadata packages");
    let package = |name: &str| {
        packages
            .iter()
            .find(|package| package["name"] == name)
            .unwrap_or_else(|| panic!("missing metadata package {name}"))
    };

    let consensus = package("opc-consensus");
    let openraft = consensus["dependencies"]
        .as_array()
        .expect("opc-consensus dependencies")
        .iter()
        .find(|dependency| dependency["name"] == "openraft")
        .expect("Openraft dependency");
    assert_eq!(openraft["req"], "=0.9.24");
    assert_eq!(
        openraft["source"],
        "git+https://github.com/openpacketcore/openraft?rev=f607e636406b16bd0ad7925dbb631da1b7a4cd96"
    );
    assert_eq!(
        openraft["features"],
        serde_json::json!(["serde", "storage-v2", "single-term-leader"])
    );
    assert_eq!(openraft["uses_default_features"], true);
    let resolved_openraft = package("openraft");
    assert_eq!(resolved_openraft["version"], "0.9.24");
    assert_eq!(
        resolved_openraft["source"],
        "git+https://github.com/openpacketcore/openraft?rev=f607e636406b16bd0ad7925dbb631da1b7a4cd96#f607e636406b16bd0ad7925dbb631da1b7a4cd96"
    );
    let fork_source = resolved_openraft["source"]
        .as_str()
        .expect("resolved Openraft source");
    let fork_packages = packages
        .iter()
        .filter(|package| package["source"].as_str() == Some(fork_source))
        .map(|package| {
            (
                package["name"].as_str().expect("fork package name"),
                package["version"].as_str().expect("fork package version"),
            )
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        fork_packages,
        BTreeSet::from([("openraft", "0.9.24"), ("openraft-macros", "0.9.24")])
    );

    let source_build_only = BTreeSet::from([
        "opc-alarm",
        "opc-alarm-k8s",
        "opc-alarm-testkit",
        "opc-alarm-yang",
        "opc-amf-lite",
        "opc-amf-lite-testkit",
        "opc-config-bus",
        "opc-consensus",
        "opc-gnmi-server",
        "opc-ipsec-lb",
        "opc-mgmt-authz",
        "opc-mgmt-transport",
        "opc-netconf-server",
        "opc-persist",
        "opc-runtime",
        "opc-sa-mirror",
        "opc-sbi",
        "opc-sdk",
        "opc-sdk-integration",
        "opc-session-cache",
        "opc-session-net",
        "opc-session-store",
        "opc-session-testkit",
        "operator-controller",
        "operator-lifecycle",
        "operator-lifecycle-cli",
    ]);
    let mut computed_source_closure =
        BTreeSet::from(["opc-consensus", "opc-persist", "opc-session-store"]);
    loop {
        let before = computed_source_closure.len();
        for workspace_package in packages
            .iter()
            .filter(|package| package["source"].is_null())
        {
            let name = workspace_package["name"]
                .as_str()
                .expect("workspace package name");
            if workspace_package["dependencies"]
                .as_array()
                .expect("workspace package dependencies")
                .iter()
                .any(|dependency| {
                    dependency["kind"].is_null()
                        && dependency["name"]
                            .as_str()
                            .is_some_and(|name| computed_source_closure.contains(name))
                })
            {
                computed_source_closure.insert(name);
            }
        }
        if computed_source_closure.len() == before {
            break;
        }
    }
    assert_eq!(computed_source_closure, source_build_only);
    for name in &source_build_only {
        assert_eq!(package(name)["publish"], serde_json::json!([]));
    }
    for publishable in packages
        .iter()
        .filter(|package| package["publish"].is_null())
    {
        let dependencies = publishable["dependencies"]
            .as_array()
            .expect("package dependencies");
        assert!(
            dependencies.iter().all(|dependency| {
                dependency["kind"].as_str() == Some("dev")
                    || dependency["name"]
                        .as_str()
                        .is_none_or(|name| !source_build_only.contains(name))
            }),
            "publishable package {} has a normal dependency on the source-build-only closure",
            publishable["name"]
        );
    }

    let network = package("opc-session-net");
    assert_eq!(
        network["features"],
        serde_json::json!({
            "default": [],
            "insecure-test": [],
            "legacy-session-net-compat": []
        })
    );
    let testkit = package("opc-session-testkit");
    assert_eq!(
        testkit["features"],
        serde_json::json!({
            "default": [],
            "foundation-insecure": ["opc-session-net/insecure-test"]
        })
    );
    let foundation_network = testkit["dependencies"]
        .as_array()
        .expect("testkit dependencies")
        .iter()
        .find(|dependency| dependency["name"] == "opc-session-net")
        .expect("testkit session-net dependency");
    assert_eq!(foundation_network["features"], serde_json::json!([]));
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
fn checker_rejects_hostile_bounded_json_without_traceback_or_stderr() {
    let directory = tempfile::tempdir().expect("hostile checker directory");
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let history = manifest.join("tests/fixtures/session-ha/history-valid.jsonl");

    let huge_integer = directory.path().join("huge-integer.jsonl");
    let huge = format!("{{\"value\":{}}}\n", "9".repeat(32 * 1024));
    assert!(huge.len() <= 64 * 1024);
    fs::write(&huge_integer, huge).expect("write bounded huge integer");
    assert_canonical_invalid_input(&run_checker_paths(&huge_integer, &history));

    let deep_nesting = directory.path().join("deep-nesting.jsonl");
    let nested = format!("{}0{}", "[".repeat(2_000), "]".repeat(2_000));
    let deep = format!("{{\"value\":{nested}}}\n");
    assert!(deep.len() <= 64 * 1024);
    fs::write(&deep_nesting, deep).expect("write bounded deep nesting");
    assert_canonical_invalid_input(&run_checker_paths(&deep_nesting, &history));
}

#[test]
fn checker_rejects_equal_and_descending_scheduled_cas_generations() {
    let directory = tempfile::tempdir().expect("CAS checker directory");
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let history = manifest.join("tests/fixtures/session-ha/history-valid.jsonl");
    let base = SCHEDULE_FIXTURE
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("schedule row"))
        .collect::<Vec<_>>();

    for (name, expected, new) in [("equal", 1, 1), ("descending", 2, 1)] {
        let mut rows = base.clone();
        rows[5]["operation"]["expected_generation"] = expected.into();
        rows[5]["operation"]["new_generation"] = new.into();
        let mut encoded = rows
            .iter()
            .map(|row| serde_json::to_string(row).expect("encode schedule row"))
            .collect::<Vec<_>>()
            .join("\n");
        encoded.push('\n');
        let schedule = directory.path().join(format!("{name}.jsonl"));
        fs::write(&schedule, encoded).expect("write invalid CAS schedule");
        assert_canonical_invalid_input(&run_checker_paths(&schedule, &history));
    }
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

    let mut evidence: Value =
        serde_json::from_str(EVIDENCE_FIXTURE).expect("evidence fixture JSON");
    evidence["source_tree_status"] = "unknown".into();
    assert!(validate_exact_evidence_fields(&evidence).is_err());

    let mut evidence: Value =
        serde_json::from_str(EVIDENCE_FIXTURE).expect("evidence fixture JSON");
    evidence["execution"]["completed_at_utc"] = "2026-07-12T23:59:59Z".into();
    assert!(validate_exact_evidence_fields(&evidence).is_err());

    let mut evidence: Value =
        serde_json::from_str(EVIDENCE_FIXTURE).expect("evidence fixture JSON");
    evidence["results"]["startup_millis"] = (-1).into();
    assert!(validate_exact_evidence_fields(&evidence).is_err());

    let mut evidence: Value =
        serde_json::from_str(EVIDENCE_FIXTURE).expect("evidence fixture JSON");
    evidence["logs"]["digests"] = serde_json::json!([
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    ]);
    assert!(validate_exact_evidence_fields(&evidence).is_err());
}

#[test]
fn mtls_candidate_checkpoint_is_strictly_incomplete_and_excludes_insecure_test() {
    let schema: Value = serde_json::from_str(SESSION_MTLS_CANDIDATE_EVIDENCE_SCHEMA_JSON)
        .expect("mTLS candidate evidence schema JSON");
    let mut evidence = serde_json::json!({
        "schema_version": "opc-session-mtls-candidate-evidence/v1",
        "experimental": true,
        "qualification_complete": false,
        "artifact": {
            "crate_name": "opc-session-testkit",
            "default_features_only": true,
            "insecure_test_enabled": false
        },
        "topology": {
            "members": 3,
            "distinct_processes": true,
            "distinct_sqlite_databases": true,
            "transport_mode": "projected_svid_mtls",
            "counts_for_seamless_tls_rotation": false
        },
        "observations": {
            "material_status_collected": true,
            "durable_readiness_reached": true,
            "directed_fresh_handshakes_succeeded": true,
            "directed_handshake_count": 6,
            "lifecycle_metrics_collected": true
        },
        "remaining_acceptance": [
            "five_member_mtls_matrix",
            "projected_material_rotation_under_continuous_traffic",
            "old_and_new_trust_overlap",
            "post_overlap_old_trust_rejection",
            "certificate_expiry_retirement",
            "bounded_drain_and_reconnect_evidence",
            "platform_and_soak_matrix"
        ]
    });
    validate_mtls_candidate_evidence(&schema, &evidence)
        .expect("candidate checkpoint satisfies strict schema");

    evidence["qualification_complete"] = true.into();
    assert!(validate_mtls_candidate_evidence(&schema, &evidence).is_err());
    evidence["qualification_complete"] = false.into();
    evidence["artifact"]["insecure_test_enabled"] = true.into();
    assert!(validate_mtls_candidate_evidence(&schema, &evidence).is_err());
    evidence["artifact"]["insecure_test_enabled"] = false.into();
    evidence["topology"]["counts_for_seamless_tls_rotation"] = true.into();
    assert!(validate_mtls_candidate_evidence(&schema, &evidence).is_err());

    evidence["topology"]["counts_for_seamless_tls_rotation"] = false.into();
    evidence["topology"]["members"] = 5.into();
    evidence["observations"]["directed_handshake_count"] = 6.into();
    assert!(validate_mtls_candidate_evidence(&schema, &evidence).is_err());

    evidence["topology"]["members"] = 3.into();
    let omitted = evidence["remaining_acceptance"]
        .as_array_mut()
        .expect("remaining acceptance array")
        .pop()
        .expect("remaining acceptance item");
    assert!(validate_mtls_candidate_evidence(&schema, &evidence).is_err());
    evidence["remaining_acceptance"]
        .as_array_mut()
        .expect("remaining acceptance array")
        .push(omitted);

    let duplicate = evidence["remaining_acceptance"][0].clone();
    evidence["remaining_acceptance"][6] = duplicate;
    assert!(validate_mtls_candidate_evidence(&schema, &evidence).is_err());
}
