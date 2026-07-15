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

fn conformance_report_json(
    records: &[EvidenceRecord],
    sdk_version: &str,
    git_commit: &str,
) -> String {
    let mut summary = std::collections::BTreeMap::<String, u64>::new();
    let requirements = records
        .iter()
        .map(|record| {
            let status = serde_json::to_value(record.status).unwrap();
            *summary
                .entry(status.as_str().unwrap().to_string())
                .or_default() += 1;
            serde_json::json!({
                "requirement_id": record.requirement_id,
                "calculated_status": record.status,
                "raw_evidence": [record],
                "gap_refs": record.gap_refs,
            })
        })
        .collect::<Vec<_>>();
    serde_json::to_string(&serde_json::json!({
        "schema_version": "1.0.0",
        "sdk_version": sdk_version,
        "git_commit": git_commit,
        "generated_at": "2026-07-15T00:00:00Z",
        "requirements": requirements,
        "summary": summary,
    }))
    .unwrap()
}

#[test]
fn release_policy_rejects_mock_bundle_verifier() {
    let policy = GatePolicy {
        mode: PolicyMode::Release,
        require_sbom: true,
        require_vex: false,
        require_provenance: false,
        require_performance: false,
        require_data_governance: false,
        allow_dirty_worktree: false,
        expected_git_commit: None,
    };
    let evaluator = GateEvaluator::new(&policy);
    let signer = MockSigner::new("policy-key");
    let verifier = MockVerifier::new("policy-key");
    let mut bundle = EvidenceBundle {
        manifest: Manifest {
            schema_version: "1.0.0".to_string(),
            sdk_version: "0.1.0".to_string(),
            git_commit: "abcdef0123456789abcdef0123456789abcdef01".to_string(),
            artifact_digests: vec![],
            file_digests: vec![],
            signing_identity: "mock-identity-policy-key".to_string(),
            generation_tool: "opc-evidence".to_string(),
            generation_tool_version: "0.1.0".to_string(),
            generation_timestamp: "2026-06-08T12:00:00Z".to_string(),
            known_incomplete_sections: vec![],
            metadata: std::collections::HashMap::new(),
        },
        signature: String::new(),
        conformance_report: None,
        sbom: Some("{}".to_string()),
        vex: None,
        provenance: None,
        performance_baseline: None,
        data_governance_report: None,
    };
    bundle.signature = signer
        .sign(&bundle_signing_bytes(&bundle).unwrap())
        .unwrap();

    let res = evaluator.evaluate(
        &[],
        &[],
        Some(&bundle),
        None,
        Some("{}"),
        None,
        None,
        None,
        None,
        Some(&verifier),
        Some(&std::collections::HashMap::new()),
    );

    let err = res.expect_err("release policy must reject mock bundle verifiers");
    assert!(
        err.to_string().contains("non-mock bundle verifier"),
        "unexpected error: {err}"
    );

    let identityless_verifier = MockVerifier::new_release_capable_without_identity("policy-key");
    let res = evaluator.evaluate(
        &[],
        &[],
        Some(&bundle),
        None,
        Some("{}"),
        None,
        None,
        None,
        None,
        Some(&identityless_verifier),
        Some(&std::collections::HashMap::new()),
    );
    let err = res.expect_err("release verification must authenticate a signing identity");
    assert!(err
        .to_string()
        .contains("authenticated bundle signing identity"));
}

#[test]
fn release_policy_rejects_every_unsigned_supplied_artifact() {
    let policy = relaxed_release_policy();
    let evaluator = GateEvaluator::new(&policy);
    let json = "{}";
    let data_governance = serde_json::to_string(&DataGovernanceEvidenceReport {
        observed_data_classes: vec![opc_data_governance::DataClass::Public],
        support_bundle_redaction_policy_version: "1.0.0".to_string(),
        retention_policy_ids: vec!["ret-1".to_string()],
        minimization_policy_ids: vec!["min-1".to_string()],
        validation_status: "pass".to_string(),
        sanitized_findings: vec!["none".to_string()],
    })
    .unwrap();
    let cases = [
        (
            "conformance report",
            [Some(json), None, None, None, None, None],
        ),
        ("SBOM", [None, Some(json), None, None, None, None]),
        ("VEX", [None, None, Some(json), None, None, None]),
        ("provenance", [None, None, None, Some(json), None, None]),
        (
            "performance baseline",
            [None, None, None, None, Some(json), None],
        ),
        (
            "data governance report",
            [None, None, None, None, None, Some(data_governance.as_str())],
        ),
    ];

    for (label, artifacts) in cases {
        let err = evaluator
            .evaluate(
                &[],
                &[],
                None,
                artifacts[0],
                artifacts[1],
                artifacts[2],
                artifacts[3],
                artifacts[4],
                artifacts[5],
                None,
                None,
            )
            .expect_err("release artifacts must be authenticated by a signed bundle");
        assert!(
            err.to_string().contains("signed evidence bundle"),
            "{label} produced an unexpected error: {err}"
        );
    }
}

#[test]
fn expected_commit_policy_requires_provenance_without_echoing_values() {
    let mut policy = relaxed_release_policy();
    policy.expected_git_commit = Some("attacker-controlled-expected-value".to_string());
    let evaluator = GateEvaluator::new(&policy);
    let err = evaluator
        .evaluate(
            &[],
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
        )
        .expect_err("an expected commit requires provenance");
    assert!(err.to_string().contains("Provenance is missing"));
    assert!(!err.to_string().contains("attacker-controlled"));
}

#[test]
fn structured_gate_input_digest_binds_records_gaps_and_waivers() {
    let instant = time::OffsetDateTime::parse(
        "2026-07-15T00:00:00Z",
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap();
    let mut record = EvidenceRecord::new(
        RequirementId::from_str("REQ-IETF-RFC7951-V1-4.2-101").unwrap(),
        ConformanceStatus::Partial,
    );
    record.source_refs = vec!["z.rs:2".to_string(), "a.rs:1".to_string()];
    record.test_refs = vec!["z_test".to_string(), "a_test".to_string()];
    record.gap_refs = vec!["GAP-000101".to_string()];
    record.waiver_refs = vec!["WAIVER-101".to_string()];
    record.artifact_digests = vec![compute_digest(b"artifact")];
    record.reviewed_by = vec!["z-reviewer".to_string(), "a-reviewer".to_string()];
    record.last_updated = Some(instant);
    let gap = Gap {
        id: "GAP-000101".to_string(),
        title: "Tracked qualification gap".to_string(),
        status: GapStatus::Open,
        severity: GapSeverity::Medium,
        applies_to: vec!["z".to_string(), "a".to_string()],
        owner: Some("release".to_string()),
        created: time::Date::from_calendar_date(2026, time::Month::July, 15).unwrap(),
        target_release: Some("0.3.0".to_string()),
        mitigation: Some("fail closed".to_string()),
        security_impact: Some("bounded".to_string()),
        security_approval: Some("security".to_string()),
        performance_impact: Some("none".to_string()),
    };
    let waiver = WaiverRecord {
        id: "WAIVER-101".to_string(),
        requirement_id: record.requirement_id.clone(),
        approver: "security".to_string(),
        justification: "bounded exception".to_string(),
        expires_at: instant + time::Duration::days(7),
        approved: true,
        ticket_ref: Some("SEC-101".to_string()),
    };

    let empty = gate_inputs_digest(&[], &[], &[]).unwrap();
    assert_ne!(
        gate_inputs_digest(std::slice::from_ref(&record), &[], &[]).unwrap(),
        empty
    );
    assert_ne!(
        gate_inputs_digest(&[], std::slice::from_ref(&gap), &[]).unwrap(),
        empty
    );
    assert_ne!(
        gate_inputs_digest(&[], &[], std::slice::from_ref(&waiver)).unwrap(),
        empty
    );

    let mut reordered_gap = gap.clone();
    reordered_gap.applies_to.reverse();
    let digest = gate_inputs_digest(
        std::slice::from_ref(&record),
        std::slice::from_ref(&gap),
        std::slice::from_ref(&waiver),
    )
    .unwrap();
    assert_eq!(
        digest,
        gate_inputs_digest(
            std::slice::from_ref(&record),
            std::slice::from_ref(&reordered_gap),
            std::slice::from_ref(&waiver),
        )
        .unwrap()
    );

    let offset = time::UtcOffset::from_hms(-6, 0, 0).unwrap();
    let mut offset_record = record.clone();
    offset_record.last_updated = offset_record
        .last_updated
        .map(|timestamp| timestamp.to_offset(offset));
    let mut offset_waiver = waiver.clone();
    offset_waiver.expires_at = offset_waiver.expires_at.to_offset(offset);
    assert_eq!(
        digest,
        gate_inputs_digest(
            std::slice::from_ref(&offset_record),
            std::slice::from_ref(&gap),
            std::slice::from_ref(&offset_waiver),
        )
        .unwrap(),
        "equal instants with different stored offsets must canonicalize identically"
    );
    assert_eq!(
        digest,
        "sha256:506b2160db1a05d45a15ae571bd9a4e97bb3fc6f940b788460ed2c92fae83d34"
    );
}

#[test]
fn release_bundle_rejects_omitted_nonempty_signed_gate_inputs() {
    let record = EvidenceRecord::new(
        RequirementId::from_str("REQ-IETF-RFC7951-V1-4.2-103").unwrap(),
        ConformanceStatus::NotApplicable,
    );
    let mut manifest = Manifest {
        schema_version: "1.0.0".to_string(),
        sdk_version: "0.2.0".to_string(),
        git_commit: "abcdef0123456789abcdef0123456789abcdef01".to_string(),
        artifact_digests: vec![],
        file_digests: vec![],
        signing_identity: "mock-identity-policy-key".to_string(),
        generation_tool: "opc-evidence".to_string(),
        generation_tool_version: "0.2.0".to_string(),
        generation_timestamp: "2026-07-15T00:00:00Z".to_string(),
        known_incomplete_sections: vec![],
        metadata: std::collections::HashMap::new(),
    };
    bind_gate_inputs(&mut manifest, std::slice::from_ref(&record), &[], &[]).unwrap();
    let signer = MockSigner::new("policy-key");
    let verifier = MockVerifier::new_release_capable("policy-key");
    let mut bundle = EvidenceBundle {
        manifest,
        signature: String::new(),
        conformance_report: None,
        sbom: None,
        vex: None,
        provenance: None,
        performance_baseline: None,
        data_governance_report: None,
    };
    sign_bundle(&mut bundle, &signer).unwrap();

    let err = GateEvaluator::new(&relaxed_release_policy())
        .evaluate(
            &[],
            &[],
            Some(&bundle),
            None,
            None,
            None,
            None,
            None,
            None,
            Some(&verifier),
            Some(&std::collections::HashMap::new()),
        )
        .expect_err("omitting non-empty signed gate inputs must fail");
    assert!(err.to_string().contains("structured gate inputs"));
}

#[test]
fn waived_status_without_waiver_record_is_rejected() {
    let req_id = RequirementId::from_str("REQ-IETF-RFC7951-V1-4.2-099").unwrap();
    let record = EvidenceRecord::new(req_id, ConformanceStatus::Waived);
    let mut policy = relaxed_release_policy();
    policy.mode = PolicyMode::PullRequest;
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
    let mut policy = relaxed_release_policy();
    policy.mode = PolicyMode::PullRequest;
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

    let mut manifest = Manifest {
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
    bind_gate_inputs(&mut manifest, &[record.clone()], &[], &[]).unwrap();
    let conformance_report = conformance_report_json(
        &[record.clone()],
        &manifest.sdk_version,
        "abcdef0123456789abcdef0123456789abcdef01",
    );
    let signer = MockSigner::new("policy-key");
    let verifier = MockVerifier::new_release_capable("policy-key");
    let mut bundle = EvidenceBundle {
        manifest,
        signature: String::new(),
        conformance_report: Some(conformance_report.clone()),
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
        Some(&conformance_report),
        Some(sbom_json),
        Some(vex_json),
        Some(prov_json),
        Some(perf_json),
        None,
        Some(&verifier),
        Some(&bundle_files),
    );
    assert!(res.is_ok(), "signed release evidence should pass: {res:?}");

    let err = evaluator
        .evaluate(
            &[],
            &[],
            Some(&bundle),
            Some(&conformance_report),
            Some(sbom_json),
            Some(vex_json),
            Some(prov_json),
            Some(perf_json),
            None,
            Some(&verifier),
            Some(&bundle_files),
        )
        .expect_err("unsigned structured gate-input substitution must fail");
    assert!(err.to_string().contains("structured gate inputs"));

    let mut inconsistent_report_bundle = bundle.clone();
    bind_gate_inputs(&mut inconsistent_report_bundle.manifest, &[], &[], &[]).unwrap();
    sign_bundle(&mut inconsistent_report_bundle, &signer).unwrap();
    let err = evaluator
        .evaluate(
            &[],
            &[],
            Some(&inconsistent_report_bundle),
            Some(&conformance_report),
            Some(sbom_json),
            Some(vex_json),
            Some(prov_json),
            Some(perf_json),
            None,
            Some(&verifier),
            Some(&bundle_files),
        )
        .expect_err("signed report records and signed gate inputs must agree");
    assert!(err.to_string().contains("signed conformance report"));

    let mut contradictory_report_value: serde_json::Value =
        serde_json::from_str(&conformance_report).unwrap();
    contradictory_report_value["requirements"][0]["calculated_status"] =
        serde_json::Value::String("partial".to_string());
    contradictory_report_value["summary"] = serde_json::json!({"partial": 1});
    let contradictory_report = serde_json::to_string(&contradictory_report_value).unwrap();
    let mut contradictory_report_bundle = bundle.clone();
    contradictory_report_bundle.conformance_report = Some(contradictory_report.clone());
    sign_bundle(&mut contradictory_report_bundle, &signer).unwrap();
    let err = evaluator
        .evaluate(
            std::slice::from_ref(&record),
            &[],
            Some(&contradictory_report_bundle),
            Some(&contradictory_report),
            Some(sbom_json),
            Some(vex_json),
            Some(prov_json),
            Some(perf_json),
            None,
            Some(&verifier),
            Some(&bundle_files),
        )
        .expect_err("calculated status must agree with bound raw evidence");
    assert!(err.to_string().contains("calculated status"));

    let substituted_sbom = r#"{"bomFormat":"substituted"}"#;
    let res = evaluator.evaluate(
        &[record.clone()],
        &[],
        Some(&bundle),
        Some(&conformance_report),
        Some(substituted_sbom),
        Some(vex_json),
        Some(prov_json),
        Some(perf_json),
        None,
        Some(&verifier),
        Some(&bundle_files),
    );
    let err = res.expect_err("evaluated artifacts must be the exact signed bytes");
    assert!(err.to_string().contains("SBOM"));
    assert!(!err.to_string().contains("substituted"));

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
    let mut wrong_commit_bundle = bundle.clone();
    wrong_commit_bundle.provenance = Some(prov_wrong_commit.clone());
    sign_bundle(&mut wrong_commit_bundle, &signer).unwrap();
    let res = evaluator.evaluate(
        &[record.clone()],
        &[],
        Some(&wrong_commit_bundle),
        Some(&conformance_report),
        Some(sbom_json),
        Some(vex_json),
        Some(&prov_wrong_commit),
        Some(perf_json),
        None,
        Some(&verifier),
        Some(&bundle_files),
    );
    let err = res.expect_err("inconsistent provenance and manifest commits must fail");
    assert!(err.to_string().contains("git commit"));
    assert!(!err.to_string().contains("wrongcommit"));

    let prov_dirty = prov_json.replace("\"worktree_dirty\": false", "\"worktree_dirty\": true");
    let mut dirty_bundle = bundle.clone();
    dirty_bundle.provenance = Some(prov_dirty.clone());
    sign_bundle(&mut dirty_bundle, &signer).unwrap();
    let res = evaluator.evaluate(
        &[record.clone()],
        &[],
        Some(&dirty_bundle),
        Some(&conformance_report),
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

    let unsafe_report = r#"{"token":"secret-value","endpoint":"192.0.2.10"}"#;
    let mut unsafe_bundle = bundle.clone();
    unsafe_bundle.conformance_report = Some(unsafe_report.to_string());
    sign_bundle(&mut unsafe_bundle, &signer).unwrap();
    let res = evaluator.evaluate(
        &[record],
        &[],
        Some(&unsafe_bundle),
        Some(unsafe_report),
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
