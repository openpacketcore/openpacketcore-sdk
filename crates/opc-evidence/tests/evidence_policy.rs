mod evidence_common;
use evidence_common::*;
use std::str::FromStr;

fn relaxed_release_policy() -> GatePolicy {
    GatePolicy {
        mode: PolicyMode::Release,
        require_sbom: false,
        require_vex: false,
        require_provenance: false,
        require_performance: false,
        require_data_governance: false,
        allow_dirty_worktree: false,
        expected_git_commit: None,
    }
}

#[test]
fn waived_status_without_waiver_record_is_rejected() {
    let req_id = RequirementId::from_str("REQ-IETF-RFC7951-V1-4.2-099").unwrap();
    let record = EvidenceRecord::new(req_id, ConformanceStatus::Waived);
    let policy = relaxed_release_policy();
    let evaluator = GateEvaluator::new(&policy);

    let res = evaluator.evaluate(
        &[record],
        &[],
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    );

    assert!(
        matches!(res, Err(EvidenceError::GapGateFailed(_))),
        "waived status without a first-class waiver record must fail, got: {res:?}"
    );
}

#[test]
fn waived_status_requires_approved_unexpired_matching_waiver() {
    let req_id = RequirementId::from_str("REQ-IETF-RFC7951-V1-4.2-100").unwrap();
    let mut record = EvidenceRecord::new(req_id.clone(), ConformanceStatus::Waived);
    record.waiver_refs.push("WAIVER-100".to_string());
    let policy = relaxed_release_policy();
    let evaluator = GateEvaluator::new(&policy);

    let mut waiver = WaiverRecord {
        id: "WAIVER-100".to_string(),
        requirement_id: req_id,
        approver: "security-reviewer".to_string(),
        justification: "Temporary release exception with tracked remediation".to_string(),
        expires_at: time::OffsetDateTime::now_utc() + time::Duration::days(7),
        approved: false,
        ticket_ref: Some("SEC-100".to_string()),
    };

    let res = evaluator.evaluate_with_waivers(
        &[record.clone()],
        &[],
        &[waiver.clone()],
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    );
    assert!(
        matches!(res, Err(EvidenceError::GapGateFailed(_))),
        "unapproved waiver must fail, got: {res:?}"
    );

    waiver.approved = true;
    waiver.expires_at = time::OffsetDateTime::now_utc() - time::Duration::days(1);
    let res = evaluator.evaluate_with_waivers(
        &[record.clone()],
        &[],
        &[waiver.clone()],
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    );
    assert!(
        matches!(res, Err(EvidenceError::GapGateFailed(_))),
        "expired waiver must fail, got: {res:?}"
    );

    waiver.expires_at = time::OffsetDateTime::now_utc() + time::Duration::days(7);
    let res = evaluator.evaluate_with_waivers(
        &[record],
        &[],
        &[waiver],
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    );
    assert!(
        res.is_ok(),
        "approved unexpired waiver should pass: {res:?}"
    );
}

#[test]
fn test_gap_006_006_gate_policy() {
    let req_id = RequirementId::from_str("REQ-IETF-RFC7951-V1-4.2-042").unwrap();

    let mut record = EvidenceRecord::new(req_id.clone(), ConformanceStatus::Full);
    record.source_refs.push("src/lib.rs:10".to_string());
    record.test_refs.push("tests/pipeline.rs:25".to_string());

    let policy = GatePolicy {
        mode: PolicyMode::Release,
        require_sbom: true,
        require_vex: true,
        require_provenance: true,
        require_performance: true,
        require_data_governance: false,
        allow_dirty_worktree: false,
        expected_git_commit: Some("abcdef0123456789abcdef0123456789abcdef01".to_string()),
    };

    let evaluator = GateEvaluator::new(&policy);

    let sbom_json = r#"{"bomFormat":"CycloneDX"}"#;
    let vex_json = r#"{"vulnerability_id":"CVE-2026-1234"}"#;
    let prov_json = r#"{
        "_type": "https://in-toto.io/Statement/v0.1",
        "subject": [],
        "predicateType": "https://slsa.dev/provenance/v0.2",
        "predicate": {
            "builder": {"id": "builder-id"},
            "build_type": "build",
            "invocation": {
                "command": [],
                "environment": {
                    "git_commit": "abcdef0123456789abcdef0123456789abcdef01",
                    "worktree_dirty": false,
                    "sdk_version": "0.1.0",
                    "tool_version": "0.1.0"
                }
            },
            "metadata": {"build_started_on": "ts", "reproducible": true},
            "materials": []
        }
    }"#;
    let perf_json = r#"{"benchmark":"test"}"#;

    let manifest = Manifest {
        schema_version: "1.0.0".to_string(),
        sdk_version: "0.1.0".to_string(),
        git_commit: "abcdef0123456789abcdef0123456789abcdef01".to_string(),
        artifact_digests: vec![],
        file_digests: vec![ManifestEntry {
            path: "evidence/sbom.json".to_string(),
            digest: compute_digest(b"{}"),
        }],
        signing_identity: "mock-identity-policy-key".to_string(),
        generation_tool: "opc-evidence".to_string(),
        generation_tool_version: "0.1.0".to_string(),
        generation_timestamp: "2026-06-08T12:00:00Z".to_string(),
        known_incomplete_sections: vec![],
        metadata: std::collections::HashMap::new(),
    };
    let signer = MockSigner::new("policy-key");
    let verifier = MockVerifier::new("policy-key");
    let mut bundle = EvidenceBundle {
        manifest,
        signature: String::new(),
        conformance_report: Some("{}".to_string()),
        sbom: Some(sbom_json.to_string()),
        vex: Some(vex_json.to_string()),
        provenance: Some(prov_json.to_string()),
        performance_baseline: Some(perf_json.to_string()),
        data_governance_report: None,
    };
    // Sign over the manifest AND the embedded blobs.
    bundle.signature = signer
        .sign(&bundle_signing_bytes(&bundle).unwrap())
        .unwrap();
    let mut bundle_files = std::collections::HashMap::new();
    bundle_files.insert("evidence/sbom.json".to_string(), b"{}".to_vec());

    let res = evaluator.evaluate(
        &[record.clone()],
        &[],
        Some(&bundle),
        Some("conformance report content"),
        Some(sbom_json),
        Some(vex_json),
        Some(prov_json),
        Some(perf_json),
        None,
        Some(&verifier),
        Some(&bundle_files),
    );
    assert!(res.is_ok());

    let mut bad_record = record.clone();
    bad_record.source_refs.clear();
    let res = evaluator.evaluate(
        &[bad_record],
        &[],
        None,
        None,
        Some(sbom_json),
        Some(vex_json),
        Some(prov_json),
        Some(perf_json),
        None,
        None,
        None,
    );
    assert!(res.is_err());

    let mut partial_record = record.clone();
    partial_record.status = ConformanceStatus::Partial;
    let res = evaluator.evaluate(
        &[partial_record.clone()],
        &[],
        None,
        None,
        Some(sbom_json),
        Some(vex_json),
        Some(prov_json),
        Some(perf_json),
        None,
        None,
        None,
    );
    assert!(res.is_err());

    let mut closed_gap_record = partial_record.clone();
    closed_gap_record.gap_refs.push("GAP-001".to_string());

    let created_date = time::Date::from_calendar_date(2026, time::Month::June, 8).unwrap();
    let gap = Gap {
        id: "GAP-001".to_string(),
        title: "Some gap".to_string(),
        status: GapStatus::Closed,
        severity: GapSeverity::Medium,
        applies_to: vec![],
        owner: Some("owner".to_string()),
        created: created_date,
        target_release: None,
        mitigation: Some("no mitigation".to_string()),
        security_impact: None,
        security_approval: None,
        performance_impact: None,
    };

    let res = evaluator.evaluate(
        &[closed_gap_record],
        &[gap],
        None,
        None,
        Some(sbom_json),
        Some(vex_json),
        Some(prov_json),
        Some(perf_json),
        None,
        None,
        None,
    );
    assert!(res.is_err());

    let res = evaluator.evaluate(
        &[record.clone()],
        &[],
        None,
        None,
        None,
        Some(vex_json),
        Some(prov_json),
        Some(perf_json),
        None,
        None,
        None,
    );
    assert!(res.is_err());

    let res = evaluator.evaluate(
        &[record.clone()],
        &[],
        None,
        None,
        Some(sbom_json),
        Some(vex_json),
        Some(prov_json),
        Some(perf_json),
        None,
        None,
        None,
    );
    assert!(res.is_err());

    let prov_wrong_commit = prov_json.replace(
        "abcdef0123456789abcdef0123456789abcdef01",
        "wrongcommit0123456789abcdef0123456789abc",
    );
    let res = evaluator.evaluate(
        &[record.clone()],
        &[],
        Some(&bundle),
        None,
        Some(sbom_json),
        Some(vex_json),
        Some(&prov_wrong_commit),
        Some(perf_json),
        None,
        Some(&verifier),
        Some(&bundle_files),
    );
    assert!(res.is_err());

    let prov_dirty = prov_json.replace("\"worktree_dirty\": false", "\"worktree_dirty\": true");
    let res = evaluator.evaluate(
        &[record.clone()],
        &[],
        Some(&bundle),
        None,
        Some(sbom_json),
        Some(vex_json),
        Some(&prov_dirty),
        Some(perf_json),
        None,
        Some(&verifier),
        Some(&bundle_files),
    );
    assert!(res.is_err());

    let res = evaluator.evaluate(
        &[record.clone()],
        &[],
        None,
        Some("my report contains absolute path: /Users/example/secret"),
        Some(sbom_json),
        Some(vex_json),
        Some(prov_json),
        Some(perf_json),
        None,
        None,
        None,
    );
    assert!(res.is_err());

    let res = evaluator.evaluate(
        &[record],
        &[],
        Some(&bundle),
        Some(r#"{"token":"secret-value","endpoint":"192.0.2.10"}"#),
        Some(sbom_json),
        Some(vex_json),
        Some(prov_json),
        Some(perf_json),
        None,
        Some(&verifier),
        Some(&bundle_files),
    );
    let err = res.expect_err("unsafe evidence must fail");
    assert!(!err.to_string().contains("secret-value"));
    assert!(!err.to_string().contains("192.0.2.10"));
}

#[test]
fn test_data_governance_gate_policy() {
    let req_id = RequirementId::from_str("REQ-IETF-RFC7951-V1-4.2-042").unwrap();
    let mut record = EvidenceRecord::new(req_id, ConformanceStatus::Full);
    record.source_refs.push("src/lib.rs:10".to_string());
    record.test_refs.push("tests/pipeline.rs:25".to_string());

    let policy = GatePolicy {
        mode: PolicyMode::PullRequest,
        require_sbom: false,
        require_vex: false,
        require_provenance: false,
        require_performance: false,
        require_data_governance: true,
        allow_dirty_worktree: true,
        expected_git_commit: None,
    };
    let evaluator = GateEvaluator::new(&policy);

    let report = DataGovernanceEvidenceReport {
        observed_data_classes: vec![opc_data_governance::DataClass::Public],
        support_bundle_redaction_policy_version: "1.0.0".to_string(),
        retention_policy_ids: vec!["ret-1".to_string()],
        minimization_policy_ids: vec!["min-1".to_string()],
        validation_status: "pass".to_string(),
        sanitized_findings: vec!["none".to_string()],
    };
    let report_json = serde_json::to_string(&report).unwrap();

    let res = evaluator.evaluate(
        &[record.clone()],
        &[],
        None,
        None,
        None,
        None,
        None,
        None,
        Some(&report_json),
        None,
        None,
    );
    assert!(res.is_ok());

    let res = evaluator.evaluate(
        &[record.clone()],
        &[],
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    );
    assert!(res.is_err());

    let res = evaluator.evaluate(
        &[record.clone()],
        &[],
        None,
        None,
        None,
        None,
        None,
        None,
        Some("invalid-json"),
        None,
        None,
    );
    assert!(res.is_err());

    let unsafe_report = report_json.replace("none", "/Users/example/passwords.txt");
    let res = evaluator.evaluate(
        &[record.clone()],
        &[],
        None,
        None,
        None,
        None,
        None,
        None,
        Some(&unsafe_report),
        None,
        None,
    );
    assert!(res.is_err());

    let mut failed_report = report;
    failed_report.validation_status = "fail".to_string();
    let failed_json = serde_json::to_string(&failed_report).unwrap();
    let res = evaluator.evaluate(
        &[record],
        &[],
        None,
        None,
        None,
        None,
        None,
        None,
        Some(&failed_json),
        None,
        None,
    );
    assert!(res.is_err());
}
