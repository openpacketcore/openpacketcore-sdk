use opc_data_governance::{DataClass, DisposalAction, PolicyError, RetentionPolicy};
use opc_evidence::{
    ConformanceStatus, DataGovernanceEvidenceReport, EvidenceRecord, GateEvaluator, GatePolicy,
    PolicyMode, RequirementId,
};
use opc_export::{ExportError, ExportMetadata, ExportedItem, PayloadState};
use opc_privacy::{CohortRecord, MinimizationPolicy};
use opc_redaction::{redact_support_bundle, BundleMode, DiagnosticEntry, RedactionLevel};
use std::time::Duration;

#[test]
fn test_support_bundle_redaction_integration() {
    let entries = vec![
        DiagnosticEntry::Log("Subscriber 208950000000001 connected from 10.0.0.5".to_string()),
        DiagnosticEntry::ConfigSnapshot(
            "database_path = /var/lib/opc/amf.db\nclient_secret = super-secret-token".to_string(),
        ),
        DiagnosticEntry::ArbitraryDiagnosticAttachment {
            name: "safe_manifest".to_string(),
            content: b"version: 1.0.0\nstatus: active".to_vec(),
            is_safe_metadata: true,
        },
    ];

    // 1. Check redaction in development mode
    let dev_bundle = redact_support_bundle(&entries, BundleMode::Development).unwrap();
    assert!(dev_bundle.redaction_applied);

    // Check that sensitive parts are redacted
    let log_content = &dev_bundle.entries[0].content;
    assert!(log_content.contains("[REDACTED_SUBSCRIBER_ID]"));
    assert!(log_content.contains("[REDACTED_IPV4]"));
    assert!(!log_content.contains("208950000000001"));
    assert!(!log_content.contains("10.0.0.5"));

    let config_content = &dev_bundle.entries[1].content;
    assert!(config_content.contains("[REDACTED_DB_FILE]"));
    assert!(config_content.contains("[REDACTED_LINE_CONTAINING_SECRET]"));

    // Check summary counters
    assert_eq!(dev_bundle.redaction_summary.subscriber_identifiers, 1);
    assert_eq!(dev_bundle.redaction_summary.ip_addresses, 1);
    assert_eq!(dev_bundle.redaction_summary.paths_and_files, 1); // /var/lib/opc/amf.db
    assert_eq!(dev_bundle.redaction_summary.secrets, 1);

    // 2. Check failing closed on unknown / unsafe attachments in Production mode
    let unsafe_entries = vec![
        DiagnosticEntry::Log("clean log".to_string()),
        DiagnosticEntry::ArbitraryDiagnosticAttachment {
            name: "raw_dump".to_string(),
            content: vec![0x00, 0x11, 0x22],
            is_safe_metadata: false,
        },
    ];
    let prod_res = redact_support_bundle(&unsafe_entries, BundleMode::Production);
    assert!(prod_res.is_err());
}

#[test]
fn test_retention_policy_and_legal_hold_integration() {
    // Valid policy
    let valid_policy = RetentionPolicy {
        data_class: DataClass::SubscriberId,
        retention_duration: Some(Duration::from_secs(86400)),
        legal_hold: false,
        disposal_action: DisposalAction::Purge,
        policy_source_id: Some("policy-rfc-010".to_string()),
        tenant_id: Some("tenant-3gpp-a".to_string()),
    };
    assert!(valid_policy.validate(true).is_ok());
    assert!(valid_policy.can_delete());

    // Invalid policy: Zero duration in production unless immediate
    let invalid_policy = RetentionPolicy {
        data_class: DataClass::SubscriberId,
        retention_duration: Some(Duration::from_secs(0)),
        legal_hold: false,
        disposal_action: DisposalAction::Purge,
        policy_source_id: Some("policy-rfc-010".to_string()),
        tenant_id: Some("tenant-3gpp-a".to_string()),
    };
    assert_eq!(
        invalid_policy.validate(true),
        Err(PolicyError::InvalidDuration)
    );

    // Legal hold active: blocks deletion decisions
    let hold_policy = RetentionPolicy {
        data_class: DataClass::SubscriberId,
        retention_duration: Some(Duration::from_secs(86400)),
        legal_hold: true,
        disposal_action: DisposalAction::Purge,
        policy_source_id: Some("policy-rfc-010".to_string()),
        tenant_id: Some("tenant-3gpp-a".to_string()),
    };
    assert_eq!(
        hold_policy.validate(true),
        Err(PolicyError::LegalHoldBlocked)
    );
    assert!(!hold_policy.can_delete());
}

#[test]
fn test_export_metadata_and_validation_integration() {
    let policy = RetentionPolicy {
        data_class: DataClass::SubscriberId,
        retention_duration: Some(Duration::from_secs(86400)),
        legal_hold: false,
        disposal_action: DisposalAction::Purge,
        policy_source_id: Some("policy-rfc-010".to_string()),
        tenant_id: Some("tenant-a".to_string()),
    };

    let item = ExportedItem {
        metadata: ExportMetadata {
            data_class: DataClass::SubscriberId,
            redaction_level: RedactionLevel::Cleartext,
            retention_policy: policy,
            tenant_id: "tenant-a".to_string(),
            schema_version: "1.0.0".to_string(),
            payload_state: PayloadState::Raw,
        },
        payload: b"raw supi data".to_vec(),
    };

    // Rejects raw sensitive payload in production
    assert!(item.validate_for_export(true).is_err());

    // Allows in development
    assert!(item.validate_for_export(false).is_ok());

    // Rejects a caller relabeling cleartext as encrypted in production
    let mut encrypted_item = item.clone();
    encrypted_item.metadata.payload_state = PayloadState::Encrypted;
    assert_eq!(
        encrypted_item.validate_for_export(true),
        Err(ExportError::PayloadStateInvalid)
    );

    // Allows if envelope-shaped encrypted bytes are supplied in production
    encrypted_item.payload = valid_export_envelope_payload();
    assert!(encrypted_item.validate_for_export(true).is_ok());

    let mut mismatched_item = encrypted_item.clone();
    mismatched_item.metadata.retention_policy.data_class = DataClass::Operational;
    assert!(mismatched_item.validate_for_export(true).is_err());

    let mut invalid_policy_item = encrypted_item;
    invalid_policy_item
        .metadata
        .retention_policy
        .policy_source_id = Some("   ".to_string());
    assert!(invalid_policy_item.validate_for_export(true).is_err());
}

fn valid_export_envelope_payload() -> Vec<u8> {
    let key_id = b"backup-key-1";
    let nonce = [0x42; 12];
    let aad = b"export-aad";
    let ciphertext_and_tag = [0x24; 16];
    let mut out = Vec::new();
    out.extend_from_slice(b"OPCE");
    out.extend_from_slice(&1_u16.to_be_bytes());
    out.extend_from_slice(&1_u16.to_be_bytes());
    out.extend_from_slice(&(key_id.len() as u16).to_be_bytes());
    out.extend_from_slice(&(nonce.len() as u16).to_be_bytes());
    out.extend_from_slice(&(aad.len() as u32).to_be_bytes());
    out.extend_from_slice(key_id);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(aad);
    out.extend_from_slice(&ciphertext_and_tag);
    out
}

#[test]
fn test_analytics_minimization_integration() {
    let policy = MinimizationPolicy {
        policy_id: "minimization-policy-v1".to_string(),
        min_cohort_size: 10,
        enforce_k_anonymity: true,
        allowed_classes: vec![DataClass::AnalyticsSensitive, DataClass::Public],
    };

    // cohort size 15 is allowed
    let ok_cohorts = vec![CohortRecord {
        keys: vec!["age:20-30".to_string()],
        count: 15,
    }];
    assert!(policy.validate_cohorts(&ok_cohorts).is_ok());

    // cohort size 5 is rejected
    let bad_cohorts = vec![CohortRecord {
        keys: vec!["age:20-30".to_string()],
        count: 5,
    }];
    assert!(policy.validate_cohorts(&bad_cohorts).is_err());

    // Reject direct identifiers
    assert!(policy.check_class_allowed(DataClass::SubscriberId).is_err());

    let invalid_policy = MinimizationPolicy {
        policy_id: "bad-policy".to_string(),
        min_cohort_size: 0,
        enforce_k_anonymity: true,
        allowed_classes: vec![DataClass::AnalyticsSensitive],
    };
    assert!(invalid_policy.validate().is_err());
}

#[test]
fn test_evidence_data_governance_report_gate_integration() {
    use std::str::FromStr;
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

    // Valid report
    let report = DataGovernanceEvidenceReport {
        observed_data_classes: vec![DataClass::Public, DataClass::AnalyticsSensitive],
        support_bundle_redaction_policy_version: "1.0.0".to_string(),
        retention_policy_ids: vec!["ret-1".to_string()],
        minimization_policy_ids: vec!["min-1".to_string()],
        validation_status: "pass".to_string(),
        sanitized_findings: vec!["no leaks".to_string()],
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

    // Fails on missing report
    let res_missing = evaluator.evaluate(
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
    assert!(res_missing.is_err());

    // Fails on malformed JSON
    let res_malformed = evaluator.evaluate(
        &[record.clone()],
        &[],
        None,
        None,
        None,
        None,
        None,
        None,
        Some("not-json"),
        None,
        None,
    );
    assert!(res_malformed.is_err());

    // Fails on unsafe report containing secrets or IPs
    let unsafe_report = report_json.replace("no leaks", "found password=admin");
    let res_unsafe = evaluator.evaluate(
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
    assert!(res_unsafe.is_err());

    let mut failed_report = report;
    failed_report.validation_status = "fail".to_string();
    let failed_json = serde_json::to_string(&failed_report).unwrap();
    let res_failed = evaluator.evaluate(
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
    assert!(res_failed.is_err());
}
