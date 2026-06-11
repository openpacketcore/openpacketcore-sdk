mod lifecycle_common;

use lifecycle_common::*;
use operator_lifecycle::{evaluate_config_apply, evaluate_rollback_target, generate_upgrade_plan};

#[test]
fn test_pending_commit_confirmed_blocks_unsafe_upgrade() {
    let current_version = ConfigVersion::INITIAL;
    let target_digest = SchemaDigest::from_bytes([1; 32]);
    let candidate = CandidateMetadata {
        version: current_version.next().unwrap(),
        schema_digest: target_digest,
        is_commit_confirmed: true,
        confirm_timeout_secs: Some(60),
        operator_release: None,
        nf_release: None,
        compatibility_matrix: None,
        evidence: None,
    };
    let status = LifecycleStatus::new(1);

    let pending = PendingConfirmationState {
        version: current_version.next().unwrap(),
        previous_confirmed_version: current_version,
        applied_at: OffsetDateTime::now_utc(),
        timeout_secs: 60,
    };

    // Attempt upgrade to version + 2 (different from pending)
    let new_candidate = CandidateMetadata {
        version: current_version.next().unwrap().next().unwrap(),
        schema_digest: SchemaDigest::from_bytes([2; 32]),
        is_commit_confirmed: false,
        confirm_timeout_secs: None,
        operator_release: None,
        nf_release: None,
        compatibility_matrix: None,
        evidence: None,
    };

    let decision = evaluate_config_apply(
        2,
        1,
        current_version,
        SchemaDigest::from_bytes([0; 32]),
        Some(&new_candidate),
        &status,
        &[],
        Some(&pending),
        None,
        OffsetDateTime::now_utc(),
    );

    assert!(matches!(decision, ConfigApplyDecision::Reject(_)));
    if let ConfigApplyDecision::Reject(msg) = decision {
        assert!(msg.contains("Unsafe upgrade blocked"));
    }

    // Now test if we try to apply the same version (confirm it): decision should be Apply
    let confirm_decision = evaluate_config_apply(
        1,
        1,
        current_version,
        SchemaDigest::from_bytes([0; 32]),
        Some(&candidate),
        &status,
        &[],
        Some(&pending),
        None,
        OffsetDateTime::now_utc(),
    );
    assert_eq!(confirm_decision, ConfigApplyDecision::Apply);
}

#[test]
fn test_recovery_required_blocks_config_apply() {
    let mut status = LifecycleStatus::new(1);
    status.set_phase(LifecyclePhase::RecoveryRequired);

    let candidate = CandidateMetadata {
        version: ConfigVersion::INITIAL.next().unwrap(),
        schema_digest: SchemaDigest::from_bytes([1; 32]),
        is_commit_confirmed: false,
        confirm_timeout_secs: None,
        operator_release: None,
        nf_release: None,
        compatibility_matrix: None,
        evidence: None,
    };

    let decision = evaluate_config_apply(
        2,
        1,
        ConfigVersion::INITIAL,
        SchemaDigest::from_bytes([0; 32]),
        Some(&candidate),
        &status,
        &[],
        None,
        None,
        OffsetDateTime::now_utc(),
    );

    assert!(matches!(decision, ConfigApplyDecision::RecoveryRequired(_)));
}

#[test]
fn test_critical_alarm_blocks_readiness_and_rollout() {
    let status = LifecycleStatus::new(1);
    let candidate = CandidateMetadata {
        version: ConfigVersion::INITIAL.next().unwrap(),
        schema_digest: SchemaDigest::from_bytes([1; 32]),
        is_commit_confirmed: false,
        confirm_timeout_secs: None,
        operator_release: None,
        nf_release: None,
        compatibility_matrix: None,
        evidence: None,
    };
    let critical_alarm = create_alarm(Severity::Critical, AlarmState::Raised);

    // 1. Blocks config-apply
    let decision = evaluate_config_apply(
        2,
        1,
        ConfigVersion::INITIAL,
        SchemaDigest::from_bytes([0; 32]),
        Some(&candidate),
        &status,
        std::slice::from_ref(&critical_alarm),
        None,
        None,
        OffsetDateTime::now_utc(),
    );
    assert!(matches!(decision, ConfigApplyDecision::Reject(_)));
    if let ConfigApplyDecision::Reject(msg) = decision {
        assert!(msg.contains("one or more critical alarms are active"));
    }

    // 2. Blocks upgrade planning
    let plan = generate_upgrade_plan(
        LifecyclePhase::Ready,
        true,
        &[critical_alarm],
        ConfigVersion::INITIAL,
        ConfigVersion::INITIAL.next().unwrap(),
        None,
        true,
        false,
        true,
    );
    assert!(plan.is_blocked);
    assert!(plan
        .block_reason
        .unwrap()
        .contains("Critical active alarm blocks"));

    let cleared_critical_alarm = create_alarm(Severity::Critical, AlarmState::Cleared);
    let decision = evaluate_config_apply(
        2,
        1,
        ConfigVersion::INITIAL,
        SchemaDigest::from_bytes([0; 32]),
        Some(&candidate),
        &status,
        &[cleared_critical_alarm],
        None,
        None,
        OffsetDateTime::now_utc(),
    );
    assert_eq!(decision, ConfigApplyDecision::Apply);
}

#[test]
fn test_degraded_state_allows_only_safe_operations() {
    let mut status = LifecycleStatus::new(1);
    status.set_phase(LifecyclePhase::Degraded);

    // Upgrade candidate
    let upgrade = CandidateMetadata {
        version: ConfigVersion::INITIAL.next().unwrap(),
        schema_digest: SchemaDigest::from_bytes([1; 32]),
        is_commit_confirmed: false,
        confirm_timeout_secs: None,
        operator_release: None,
        nf_release: None,
        compatibility_matrix: None,
        evidence: None,
    };

    let decision = evaluate_config_apply(
        2,
        1,
        ConfigVersion::INITIAL,
        SchemaDigest::from_bytes([0; 32]),
        Some(&upgrade),
        &status,
        &[],
        None,
        None,
        OffsetDateTime::now_utc(),
    );
    assert!(matches!(decision, ConfigApplyDecision::Reject(_)));

    // Downgrade / Rollback candidate (version is same or older)
    let downgrade = CandidateMetadata {
        version: ConfigVersion::INITIAL,
        schema_digest: SchemaDigest::from_bytes([0; 32]),
        is_commit_confirmed: false,
        confirm_timeout_secs: None,
        operator_release: None,
        nf_release: None,
        compatibility_matrix: None,
        evidence: None,
    };

    let decision_downgrade = evaluate_config_apply(
        2,
        1,
        ConfigVersion::INITIAL.next().unwrap(),
        SchemaDigest::from_bytes([9; 32]),
        Some(&downgrade),
        &status,
        &[],
        None,
        None,
        OffsetDateTime::now_utc(),
    );
    assert_eq!(decision_downgrade, ConfigApplyDecision::Apply);
}

#[test]
fn test_rollback_evaluator_never_chooses_unconfirmed_config() {
    let v0 = ConfigVersion::INITIAL;
    let v1 = v0.next().unwrap();
    let v2 = v1.next().unwrap();

    let history = vec![
        StoredConfigMetadata {
            version: v0,
            tx_id: TxId::new(),
            parent_tx_id: None,
            is_confirmed: true,
            label: Some("v0-label".to_string()),
        },
        StoredConfigMetadata {
            version: v1,
            tx_id: TxId::new(),
            parent_tx_id: Some(TxId::new()),
            is_confirmed: false, // unconfirmed!
            label: Some("v1-label".to_string()),
        },
        StoredConfigMetadata {
            version: v2,
            tx_id: TxId::new(),
            parent_tx_id: Some(TxId::new()),
            is_confirmed: false, // unconfirmed!
            label: Some("v2-label".to_string()),
        },
    ];

    // Rollback Target Previous must choose v0 (the latest confirmed), skipping v1 and v2
    let target = evaluate_rollback_target(opc_config_model::RollbackTarget::Previous, &history);
    assert_eq!(target, Ok(v0));

    // Rollback to unconfirmed v1 explicitly must fail
    let target_v1 =
        evaluate_rollback_target(opc_config_model::RollbackTarget::Version(v1), &history);
    assert!(target_v1.is_err());
}

#[test]
fn test_compatibility_config_apply_integration() {
    let matrix = create_test_compatibility_matrix();
    let op = OperatorReleaseDescriptor {
        operator_version: "1.1.0".to_string(),
        sdk_version: "1.5.2".to_string(),
    };
    let nf = NfReleaseDescriptor {
        nf_kind: "upf".to_string(),
        nf_version: "1.2.5".to_string(),
        crd_api_version: "openpacketcore.org/v1beta1".to_string(),
        config_schema_version: "1.0.1".to_string(),
        state_schema_version: "1.0.1".to_string(),
    };
    let ev = vec![CompatibilityEvidence {
        evidence_id: "ev-1".to_string(),
        approved_by: "admin".to_string(),
        timestamp: "2026-06-08T12:00:00Z".to_string(),
    }];

    let candidate = CandidateMetadata {
        version: ConfigVersion::new(2),
        schema_digest: SchemaDigest::from_bytes([1; 32]),
        is_commit_confirmed: false,
        confirm_timeout_secs: None,
        operator_release: Some(op),
        nf_release: Some(nf),
        compatibility_matrix: Some(matrix),
        evidence: Some(ev),
    };

    let status = LifecycleStatus::new(1);
    let decision = evaluate_config_apply(
        2,
        1,
        ConfigVersion::new(1),
        SchemaDigest::from_bytes([0; 32]),
        Some(&candidate),
        &status,
        &[],
        None,
        None,
        OffsetDateTime::now_utc(),
    );
    assert_eq!(decision, ConfigApplyDecision::Apply);
}

#[test]
fn test_data_plane_preflight_config_apply_rejection() {
    let status = LifecycleStatus::new(1);
    let candidate = CandidateMetadata {
        version: ConfigVersion::new(2),
        schema_digest: SchemaDigest::from_bytes([1; 32]),
        is_commit_confirmed: false,
        confirm_timeout_secs: None,
        operator_release: None,
        nf_release: None,
        compatibility_matrix: None,
        evidence: None,
    };

    // Construct a failing preflight report
    let preflight_report = opc_node_resources::DataPlanePreflightReport {
        passed: false,
        blocks_readiness: true,
        messages: vec!["Reserved core overlap detected".to_string()],
        evidence_ids: vec![],
        lab_fallback_active: false,
        checks: vec![],
    };

    let decision = evaluate_config_apply(
        2,
        1,
        ConfigVersion::new(1),
        SchemaDigest::from_bytes([0; 32]),
        Some(&candidate),
        &status,
        &[],
        None,
        Some(&preflight_report),
        OffsetDateTime::now_utc(),
    );

    assert!(matches!(decision, ConfigApplyDecision::Reject(_)));
    if let ConfigApplyDecision::Reject(msg) = decision {
        assert!(msg.contains("Rollout blocked: data-plane preflight check failed"));
        assert!(msg.contains("Reserved core overlap detected"));
    }
}
