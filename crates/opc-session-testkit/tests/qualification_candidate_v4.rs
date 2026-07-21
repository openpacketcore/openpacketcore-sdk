use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use opc_session_testkit::qualification::{
    QualificationCandidateContractError, QualificationSha256, SessionHaCandidateManifestV4,
    SessionHaCandidateQualificationProfileV4, SessionHaCandidateQualificationProfileV5,
    SESSION_HA_CANDIDATE_ACCEPTANCE_GATES_V4, SESSION_HA_CANDIDATE_ACCEPTANCE_GATES_V5,
    SESSION_HA_CANDIDATE_MANIFEST_V4_MAX_BYTES, SESSION_HA_CANDIDATE_MANIFEST_V4_SCHEMA_JSON,
    SESSION_HA_CANDIDATE_PROFILE_V4_JSON, SESSION_HA_CANDIDATE_PROFILE_V4_MAX_BYTES,
    SESSION_HA_CANDIDATE_PROFILE_V4_SCHEMA_JSON, SESSION_HA_CANDIDATE_PROFILE_V5_JSON,
    SESSION_HA_CANDIDATE_PROFILE_V5_MAX_BYTES, SESSION_HA_CANDIDATE_PROFILE_V5_SCHEMA_JSON,
};
use opc_session_testkit::qualification_kubernetes_concurrent_v5_artifacts::QUALIFICATION_KUBERNETES_CONCURRENT_V5_ARTIFACT_SUMMARY_SCHEMA;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const MANIFEST_FIXTURE: &str = include_str!("fixtures/session-ha/candidate-manifest-v4.json");
const SEQUENTIAL_SCHEDULE: &[u8] = include_bytes!("fixtures/session-ha/schedule-valid.jsonl");
const SEQUENTIAL_HISTORY: &[u8] = include_bytes!("fixtures/session-ha/history-valid.jsonl");
const CONCURRENT_EVIDENCE: &[u8] = include_bytes!("fixtures/session-ha/candidate-evidence-v3.json");
const CONCURRENT_HISTORY: &[u8] =
    include_bytes!("fixtures/session-ha/concurrent-history-v3-valid.jsonl");

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn sequential_checker_path() -> PathBuf {
    repository_root().join("scripts/check-session-ha-history.py")
}

fn concurrent_checker_path() -> PathBuf {
    repository_root().join("scripts/check-session-ha-concurrent-history.py")
}

fn fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/session-ha")
        .join(name)
}

fn run_sequential_checker() -> Output {
    Command::new("python3")
        .arg(sequential_checker_path())
        .arg("--schedule")
        .arg(fixture_path("schedule-valid.jsonl"))
        .arg("--history")
        .arg(fixture_path("history-valid.jsonl"))
        .output()
        .expect("run independent sequential checker")
}

fn run_concurrent_checker() -> Output {
    Command::new("python3")
        .arg(concurrent_checker_path())
        .arg("--evidence")
        .arg(fixture_path("candidate-evidence-v3.json"))
        .arg("--history")
        .arg(fixture_path("concurrent-history-v3-valid.jsonl"))
        .output()
        .expect("run independent concurrent checker")
}

fn exact_sha256(raw: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(raw))
}

fn manifest_value() -> Value {
    serde_json::from_str(MANIFEST_FIXTURE).expect("v4 candidate manifest fixture")
}

fn decode_manifest(
    value: &Value,
) -> Result<SessionHaCandidateManifestV4, QualificationCandidateContractError> {
    let encoded = serde_json::to_vec(value).expect("encode candidate manifest mutation");
    SessionHaCandidateManifestV4::from_json(&encoded)
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
fn v4_profile_is_an_additive_frozen_candidate_contract() {
    let profile_schema: Value = serde_json::from_str(SESSION_HA_CANDIDATE_PROFILE_V4_SCHEMA_JSON)
        .expect("v4 profile schema");
    let profile_value: Value =
        serde_json::from_str(SESSION_HA_CANDIDATE_PROFILE_V4_JSON).expect("v4 profile");
    validate_structural_schema(&profile_schema, &profile_value)
        .expect("v4 profile satisfies its closed schema");

    let profile = SessionHaCandidateQualificationProfileV4::from_json(
        SESSION_HA_CANDIDATE_PROFILE_V4_JSON.as_bytes(),
    )
    .expect("strict typed v4 profile");
    assert_eq!(
        profile.schema_version,
        "opc-session-ha-profile/v4-candidate"
    );
    assert_eq!(profile.profile_id, "opc-session-openraft-ha/v4-candidate");
    assert_eq!(profile.maturity, "experimental");
    assert!(!profile.qualification_complete);
    assert_eq!(
        profile.evidence.acceptance_gates,
        SESSION_HA_CANDIDATE_ACCEPTANCE_GATES_V4
    );

    let baseline: Value =
        serde_json::from_str(include_str!("../qualification/v2/session-ha-profile.json"))
            .expect("v2 profile");
    for field in [
        "workspace",
        "source_build_gate",
        "artifacts",
        "platforms",
        "topology",
        "protocol",
        "consensus_timing",
        "bounds",
        "provisional_test_thresholds",
    ] {
        assert_eq!(
            profile_value[field], baseline[field],
            "v4 drifted at {field}"
        );
    }

    let manifest = manifest_value();
    assert_eq!(
        manifest["profile"]["sha256"],
        exact_sha256(SESSION_HA_CANDIDATE_PROFILE_V4_JSON.as_bytes())
    );

    let mut drifted = profile_value.clone();
    drifted["artifacts"][0]["crate_name"] = "unreviewed-consensus".into();
    assert!(validate_structural_schema(&profile_schema, &drifted).is_err());
    let encoded = serde_json::to_vec(&drifted).expect("encode drifted profile");
    assert_eq!(
        SessionHaCandidateQualificationProfileV4::from_json(&encoded),
        Err(QualificationCandidateContractError::InvalidProfile)
    );

    let mut unsupported_claim = profile_value;
    unsupported_claim["qualification_complete"] = true.into();
    assert!(validate_structural_schema(&profile_schema, &unsupported_claim).is_err());
}

#[test]
fn v5_profile_closes_the_deployed_collector_inventory_without_graduating_it() {
    let profile_schema: Value = serde_json::from_str(SESSION_HA_CANDIDATE_PROFILE_V5_SCHEMA_JSON)
        .expect("v5 profile schema");
    let profile_value: Value =
        serde_json::from_str(SESSION_HA_CANDIDATE_PROFILE_V5_JSON).expect("v5 profile");
    validate_structural_schema(&profile_schema, &profile_value)
        .expect("v5 profile satisfies its closed schema");

    let profile = SessionHaCandidateQualificationProfileV5::from_json(
        SESSION_HA_CANDIDATE_PROFILE_V5_JSON.as_bytes(),
    )
    .expect("strict typed v5 profile");
    assert_eq!(
        profile.schema_version,
        "opc-session-ha-profile/v5-candidate"
    );
    assert_eq!(profile.profile_id, "opc-session-openraft-ha/v5-candidate");
    assert_eq!(profile.maturity, "experimental");
    assert!(!profile.qualification_complete);
    assert_eq!(
        profile.evidence.acceptance_gates,
        SESSION_HA_CANDIDATE_ACCEPTANCE_GATES_V5
    );

    let baseline: Value =
        serde_json::from_str(include_str!("../qualification/v2/session-ha-profile.json"))
            .expect("v2 profile");
    for field in [
        "workspace",
        "source_build_gate",
        "artifacts",
        "platforms",
        "topology",
        "protocol",
        "consensus_timing",
        "bounds",
        "provisional_test_thresholds",
    ] {
        assert_eq!(
            profile_value[field], baseline[field],
            "v5 drifted at {field}"
        );
    }

    let evidence: Value = serde_json::from_slice(include_bytes!(
        "fixtures/session-ha/candidate-evidence-v5.json"
    ))
    .expect("v5 evidence fixture");
    assert_eq!(evidence["profile_id"], profile.profile_id);
    assert_eq!(
        evidence["schema_version"],
        "opc-session-ha-candidate-evidence/v5"
    );
    assert_eq!(
        profile.evidence.concurrent_evidence_schema,
        "qualification/v5/session-ha-candidate-evidence.schema.json"
    );
    assert_eq!(
        profile.evidence.concurrent_history_schema,
        "qualification/v5/session-ha-concurrent-history.schema.json"
    );
    assert_eq!(
        profile.evidence.concurrent_fault_schedule_schema,
        "qualification/v5/session-ha-fault-schedule.schema.json"
    );
    assert_eq!(
        profile.evidence.candidate_artifact_summary_schema,
        QUALIFICATION_KUBERNETES_CONCURRENT_V5_ARTIFACT_SUMMARY_SCHEMA
    );

    let mut drifted = profile_value.clone();
    drifted["evidence"]["candidate_artifact_summary_schema"] =
        "opc-session-kubernetes-concurrent-v5-artifacts/v1".into();
    assert!(validate_structural_schema(&profile_schema, &drifted).is_err());
    let encoded = serde_json::to_vec(&drifted).expect("encode drifted profile");
    assert_eq!(
        SessionHaCandidateQualificationProfileV5::from_json(&encoded),
        Err(QualificationCandidateContractError::InvalidProfile)
    );

    let mut unsupported_claim = profile_value;
    unsupported_claim["qualification_complete"] = true.into();
    assert!(validate_structural_schema(&profile_schema, &unsupported_claim).is_err());
    let encoded = serde_json::to_vec(&unsupported_claim).expect("encode unsupported claim");
    assert_eq!(
        SessionHaCandidateQualificationProfileV5::from_json(&encoded),
        Err(QualificationCandidateContractError::UnsupportedClaim)
    );
}

#[test]
fn v5_profile_decoder_is_bounded_and_closed() {
    let mut exact_limit = SESSION_HA_CANDIDATE_PROFILE_V5_JSON.as_bytes().to_vec();
    exact_limit.resize(SESSION_HA_CANDIDATE_PROFILE_V5_MAX_BYTES, b' ');
    SessionHaCandidateQualificationProfileV5::from_json(&exact_limit)
        .expect("valid v5 profile at exact document limit");

    exact_limit.push(b' ');
    assert_eq!(
        SessionHaCandidateQualificationProfileV5::from_json(&exact_limit),
        Err(QualificationCandidateContractError::DocumentTooLarge)
    );

    let mut unknown: Value =
        serde_json::from_str(SESSION_HA_CANDIDATE_PROFILE_V5_JSON).expect("v5 profile value");
    unknown["unreviewed"] = true.into();
    assert_eq!(
        SessionHaCandidateQualificationProfileV5::from_json(
            &serde_json::to_vec(&unknown).expect("encode unknown field")
        ),
        Err(QualificationCandidateContractError::InvalidDocument)
    );
}

#[test]
fn v4_manifest_binds_both_independent_checkers_and_component_bytes() {
    let schema: Value = serde_json::from_str(SESSION_HA_CANDIDATE_MANIFEST_V4_SCHEMA_JSON)
        .expect("v4 manifest schema");
    let value = manifest_value();
    validate_structural_schema(&schema, &value).expect("v4 manifest satisfies its closed schema");
    let manifest = SessionHaCandidateManifestV4::from_json(MANIFEST_FIXTURE.as_bytes())
        .expect("strict typed v4 manifest");

    assert_eq!(
        manifest.profile.sha256.as_str(),
        exact_sha256(SESSION_HA_CANDIDATE_PROFILE_V4_JSON.as_bytes())
    );
    assert_eq!(
        manifest.sequential.schedule_sha256.as_str(),
        exact_sha256(SEQUENTIAL_SCHEDULE)
    );
    assert_eq!(
        manifest.sequential.history_sha256.as_str(),
        exact_sha256(SEQUENTIAL_HISTORY)
    );
    assert_eq!(
        manifest.sequential.checker.sha256.as_str(),
        exact_sha256(&std::fs::read(sequential_checker_path()).expect("sequential checker bytes"))
    );
    assert_eq!(
        manifest.concurrent.evidence_sha256.as_str(),
        exact_sha256(CONCURRENT_EVIDENCE)
    );
    assert_eq!(
        manifest.concurrent.history_sha256.as_str(),
        exact_sha256(CONCURRENT_HISTORY)
    );
    assert_eq!(
        manifest.concurrent.checker.sha256.as_str(),
        exact_sha256(&std::fs::read(concurrent_checker_path()).expect("concurrent checker bytes"))
    );

    let sequential_output = run_sequential_checker();
    assert!(sequential_output.status.success());
    assert!(sequential_output.stderr.is_empty());
    assert_eq!(
        manifest.sequential.checker.output_sha256.as_str(),
        exact_sha256(&sequential_output.stdout)
    );
    let concurrent_output = run_concurrent_checker();
    assert!(concurrent_output.status.success());
    assert!(concurrent_output.stderr.is_empty());
    assert_eq!(
        manifest.concurrent.checker.output_sha256.as_str(),
        exact_sha256(&concurrent_output.stdout)
    );

    let evidence: Value =
        serde_json::from_slice(CONCURRENT_EVIDENCE).expect("v3 concurrent evidence fixture");
    assert_eq!(evidence["source_revision"], manifest.source_revision);
    assert_eq!(evidence["source_tree_status"], value["source_tree_status"]);
    assert_eq!(evidence["artifact"]["name"], manifest.artifact.name);
    assert_eq!(evidence["artifact"]["version"], manifest.artifact.version);
    assert_eq!(
        evidence["artifact"]["sha256"],
        manifest.artifact.binary_sha256.as_str()
    );
    assert_eq!(
        evidence["artifact"]["exact_release_artifact"],
        manifest.artifact.exact_release_artifact
    );
    assert_eq!(
        evidence["execution"]["topology_members"],
        manifest.campaign.topology_members
    );
    assert_eq!(
        evidence["execution"]["fault_schedule_sha256"],
        manifest.bindings.fault_schedule_sha256.as_str()
    );
    assert_eq!(
        evidence["workload"]["schedule_sha256"],
        manifest.concurrent.workload_schedule_sha256.as_str()
    );
    assert_eq!(
        evidence["history"]["sha256"],
        manifest.concurrent.history_sha256.as_str()
    );
    assert_eq!(
        evidence["checker"]["sha256"],
        manifest.concurrent.checker.sha256.as_str()
    );

    for row in std::str::from_utf8(SEQUENTIAL_HISTORY)
        .expect("sequential history is UTF-8")
        .lines()
    {
        let row: Value = serde_json::from_str(row).expect("sequential history row");
        assert_eq!(
            row["schedule_sha256"],
            manifest.sequential.schedule_sha256.as_str()
        );
    }

    let mut candidate_gate = value.clone();
    candidate_gate["acceptance"]["deployed_kubernetes_3_5"] = json!({
        "status": "candidate_evidence",
        "evidence_sha256": format!("sha256:{}", "a".repeat(64))
    });
    let candidate_gate = decode_manifest(&candidate_gate).expect("candidate gate evidence");
    assert!(!candidate_gate.counts_for_production);

    let mut exact_release = value;
    exact_release["source_revision"] = "1111111111111111111111111111111111111111".into();
    exact_release["source_tree_status"] = "clean".into();
    exact_release["artifact"]["cargo_profile"] = "release".into();
    exact_release["artifact"]["exact_release_artifact"] = true.into();
    exact_release["artifact"]["container_image_sha256"] =
        format!("sha256:{}", "b".repeat(64)).into();
    decode_manifest(&exact_release).expect("coherent exact release candidate");
}

#[test]
fn v4_manifest_rejects_claim_artifact_campaign_checker_and_gate_tampering() {
    let cases: Vec<(&str, Value, QualificationCandidateContractError)> = vec![
        (
            "qualification claim",
            {
                let mut value = manifest_value();
                value["qualification_complete"] = true.into();
                value
            },
            QualificationCandidateContractError::UnsupportedClaim,
        ),
        (
            "production credit",
            {
                let mut value = manifest_value();
                value["counts_for_production"] = true.into();
                value
            },
            QualificationCandidateContractError::UnsupportedClaim,
        ),
        (
            "source revision",
            {
                let mut value = manifest_value();
                value["source_revision"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into();
                value
            },
            QualificationCandidateContractError::InvalidRevision,
        ),
        (
            "profile digest",
            {
                let mut value = manifest_value();
                value["profile"]["sha256"] = format!("sha256:{}", "1".repeat(64)).into();
                value
            },
            QualificationCandidateContractError::InvalidProfile,
        ),
        (
            "artifact version control character",
            {
                let mut value = manifest_value();
                value["artifact"]["version"] = "0.2.0\nforged".into();
                value
            },
            QualificationCandidateContractError::InvalidArtifact,
        ),
        (
            "insecure feature",
            {
                let mut value = manifest_value();
                value["artifact"]["foundation_insecure_enabled"] = true.into();
                value
            },
            QualificationCandidateContractError::InvalidArtifact,
        ),
        (
            "dirty exact release",
            {
                let mut value = manifest_value();
                value["artifact"]["exact_release_artifact"] = true.into();
                value
            },
            QualificationCandidateContractError::InvalidArtifact,
        ),
        (
            "placeholder exact release revision",
            {
                let mut value = manifest_value();
                value["source_tree_status"] = "clean".into();
                value["artifact"]["cargo_profile"] = "release".into();
                value["artifact"]["exact_release_artifact"] = true.into();
                value["artifact"]["container_image_sha256"] =
                    format!("sha256:{}", "b".repeat(64)).into();
                value
            },
            QualificationCandidateContractError::InvalidArtifact,
        ),
        (
            "reversed campaign",
            {
                let mut value = manifest_value();
                value["campaign"]["started_at_utc"] = "2026-07-15T00:00:02Z".into();
                value
            },
            QualificationCandidateContractError::InvalidCampaign,
        ),
        (
            "invalid calendar timestamp",
            {
                let mut value = manifest_value();
                value["campaign"]["completed_at_utc"] = "2026-02-31T00:00:01Z".into();
                value
            },
            QualificationCandidateContractError::InvalidCampaign,
        ),
        (
            "shared storage",
            {
                let mut value = manifest_value();
                value["campaign"]["independent_disks"] = false.into();
                value
            },
            QualificationCandidateContractError::InvalidCampaign,
        ),
        (
            "component schema",
            {
                let mut value = manifest_value();
                value["concurrent"]["history_schema_version"] =
                    "opc-session-ha-concurrent-history/v2".into();
                value
            },
            QualificationCandidateContractError::InvalidComponent,
        ),
        (
            "checker exit",
            {
                let mut value = manifest_value();
                value["sequential"]["checker"]["exit_code"] = 1.into();
                value
            },
            QualificationCandidateContractError::InvalidChecker,
        ),
        (
            "checker inconclusive count",
            {
                let mut value = manifest_value();
                value["concurrent"]["checker"]["inconclusive_count"] = 1.into();
                value
            },
            QualificationCandidateContractError::InvalidChecker,
        ),
        (
            "unproven gate with evidence",
            {
                let mut value = manifest_value();
                value["acceptance"]["remote_hkms_rotation"]["evidence_sha256"] =
                    format!("sha256:{}", "a".repeat(64)).into();
                value
            },
            QualificationCandidateContractError::InvalidAcceptance,
        ),
        (
            "candidate gate without evidence",
            {
                let mut value = manifest_value();
                value["acceptance"]["signed_release_bundle"]["status"] =
                    "candidate_evidence".into();
                value
            },
            QualificationCandidateContractError::InvalidAcceptance,
        ),
    ];

    for (name, value, expected) in cases {
        assert_eq!(decode_manifest(&value), Err(expected), "{name}");
    }
}

#[test]
fn v4_bounded_decoders_reject_malformed_unknown_and_oversized_documents() {
    assert_eq!(
        SessionHaCandidateManifestV4::from_json(b"{"),
        Err(QualificationCandidateContractError::InvalidDocument)
    );

    let mut malformed_digest = manifest_value();
    malformed_digest["artifact"]["binary_sha256"] = "sha256:ABC".into();
    assert_eq!(
        decode_manifest(&malformed_digest),
        Err(QualificationCandidateContractError::InvalidDocument)
    );

    let mut unknown = manifest_value();
    unknown["raw_peer_address"] = "must-not-be-admitted".into();
    assert_eq!(
        decode_manifest(&unknown),
        Err(QualificationCandidateContractError::InvalidDocument)
    );

    assert_eq!(
        SessionHaCandidateManifestV4::from_json(&vec![
            b' ';
            SESSION_HA_CANDIDATE_MANIFEST_V4_MAX_BYTES
                + 1
        ]),
        Err(QualificationCandidateContractError::DocumentTooLarge)
    );
    assert_eq!(
        SessionHaCandidateQualificationProfileV4::from_json(&vec![
            b' ';
            SESSION_HA_CANDIDATE_PROFILE_V4_MAX_BYTES
                + 1
        ]),
        Err(QualificationCandidateContractError::DocumentTooLarge)
    );
}

#[test]
fn v4_closed_schemas_reject_missing_or_unknown_acceptance_and_production_claims() {
    let schema: Value = serde_json::from_str(SESSION_HA_CANDIDATE_MANIFEST_V4_SCHEMA_JSON)
        .expect("v4 manifest schema");

    let mut missing_gate = manifest_value();
    missing_gate["acceptance"]
        .as_object_mut()
        .expect("acceptance object")
        .remove("remote_hkms_rotation");
    assert!(validate_structural_schema(&schema, &missing_gate).is_err());

    let mut unknown_gate = manifest_value();
    unknown_gate["acceptance"]["future_unreviewed_gate"] = json!({
        "status": "unproven",
        "evidence_sha256": null
    });
    assert!(validate_structural_schema(&schema, &unknown_gate).is_err());

    let mut production_claim = manifest_value();
    production_claim["counts_for_production"] = true.into();
    assert!(validate_structural_schema(&schema, &production_claim).is_err());

    let mut mismatched_gate = manifest_value();
    mismatched_gate["acceptance"]["crash_point_matrix"]["status"] = "candidate_evidence".into();
    assert!(validate_structural_schema(&schema, &mismatched_gate).is_err());
}

#[test]
fn candidate_digests_are_strict_and_debug_redacted() {
    let digest = QualificationSha256::digest(b"bounded candidate bytes");
    assert!(digest.as_str().starts_with("sha256:"));
    assert_eq!(format!("{digest:?}"), "QualificationSha256(<sha256>)");
    assert_eq!(
        QualificationSha256::new(format!("sha256:{}", "A".repeat(64))),
        Err(QualificationCandidateContractError::InvalidDigest)
    );
    assert_eq!(
        QualificationSha256::new(format!("sha256:{}", "a".repeat(63))),
        Err(QualificationCandidateContractError::InvalidDigest)
    );
}

#[test]
fn pre_v4_contract_bytes_remain_frozen() {
    let frozen: [(&[u8], &str); 11] = [
        (
            include_bytes!("../qualification/v1/session-ha-evidence.schema.json"),
            "e6fed091b7f60c0f2441d8cc1fb0afb87ac261ea698a6f2c69ad50968efe8764",
        ),
        (
            include_bytes!("../qualification/v1/session-ha-history.schema.json"),
            "cd623d443a39586ae3f5ca87b36e14836eda4752ef774cc6f0bd16918c437faf",
        ),
        (
            include_bytes!("../qualification/v1/session-ha-profile.json"),
            "2f95deab778055bae35d057b2f0a2c034852a4fc4859259b14303d10bb681c24",
        ),
        (
            include_bytes!("../qualification/v1/session-ha-profile.schema.json"),
            "ff8ae1a3fd8f54f30b37f0969f82984353fcba7cd39c660555a828baecd6e532",
        ),
        (
            include_bytes!("../qualification/v1/session-ha-schedule.schema.json"),
            "867f868d7397f811ae5e18085f6d9de7625f9410756ff7c5fd12f91b081c524b",
        ),
        (
            include_bytes!("../qualification/v1/session-mtls-candidate-evidence.schema.json"),
            "8ff3c09be050c25d752839c10c4fc8840c75a360fa6b625329197fd4dc7b85e0",
        ),
        (
            include_bytes!("../qualification/v2/session-ha-evidence.schema.json"),
            "d4c459892c22bd7f0bd6c8c7e6e7bd84d58bd25cd732076cf7caa706e92cd770",
        ),
        (
            include_bytes!("../qualification/v2/session-ha-profile.json"),
            "826bc8285e5206f2c52f788eeb5712ab902fb16c3180b9dfd8245ae9c0c9160a",
        ),
        (
            include_bytes!("../qualification/v2/session-ha-profile.schema.json"),
            "c797b5d603389b1fae1dad6b773bd19e04b9d7826a6348be321ec8f36f582605",
        ),
        (
            include_bytes!("../qualification/v3/session-ha-candidate-evidence.schema.json"),
            "040bf1459a054d4336cf7ec80d0bd1fdd5e9415e4f7b61ef64ed297c146f9c9e",
        ),
        (
            include_bytes!("../qualification/v3/session-ha-concurrent-history.schema.json"),
            "9856cfb92042c25c3a37595b9aff35c90ce488706c7256fb685377559d7b22e0",
        ),
    ];

    for (bytes, expected) in frozen {
        assert_eq!(format!("{:x}", Sha256::digest(bytes)), expected);
    }
}
