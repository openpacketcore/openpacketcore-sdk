use opc_config_model::{
    ApplyPlan, ApplyPlanChange, ApplyPlanWarning, ChangeImpact, ChangeImpactClass, CommitError,
    CommitErrorCode, CommitResult, CommitStatus, YangPath,
};
use opc_mgmt_opstate::{
    ConfigApplyPlanState, ConfigCandidateStatus, ConfigWorkflowActionConflictReason,
    ConfigWorkflowActionStatus, ConfigWorkflowActionTarget, ConfigWorkflowCompletion,
};
use opc_types::{ConfigVersion, TxId};

fn plan(class: ChangeImpactClass, reason_code: &str) -> ApplyPlan {
    ApplyPlan {
        class,
        changes: vec![ApplyPlanChange {
            path: YangPath::new("/system/hostname").expect("path"),
            class,
            reason_code: reason_code.into(),
            affected_sessions_estimate: Some(9),
        }],
        impact: ChangeImpact {
            class: ChangeImpactClass::Hot,
            affected_sessions_estimate: None,
            requires_external_workflow: false,
        },
        rollback_target: None,
        hard_errors: Vec::new(),
        warnings: Vec::new(),
    }
    .normalize()
}

#[test]
fn accepted_workflow_plan_projects_traffic_block_state() {
    let state = ConfigApplyPlanState::new()
        .with_active_config(Some(ConfigVersion::new(3)), Some(TxId::new()))
        .with_last_accepted_apply_plan(plan(
            ChangeImpactClass::DrainRequired,
            "hostname_drain_required",
        ));

    let json = state.to_json_value();

    assert_eq!(json["traffic-blocked-until-workflow"], true);
    assert_eq!(json["traffic-block-reason-code"], "hostname_drain_required");
    assert_eq!(json["last-accepted-apply-plan"]["class"], "drain-required");
    assert!(json.get("active-config-version").is_some());
    assert!(json.get("active-tx-id").is_some());

    let value = state
        .to_operational_value(YangPath::new("/openpacketcore/config-apply").expect("path"))
        .expect("valid operational value");
    assert_eq!(value.path().as_str(), "/openpacketcore/config-apply");
    serde_json::from_str::<serde_json::Value>(value.value_json()).expect("valid json");
}

#[test]
fn empty_state_omits_unknown_fields() {
    let json = ConfigApplyPlanState::new().to_json_value();

    assert_eq!(json["traffic-blocked-until-workflow"], false);
    assert!(json.get("last-accepted-apply-plan").is_none());
    assert!(json.get("last-rejected-apply-plan").is_none());
    assert!(json.get("active-config-version").is_none());
    assert!(json.get("active-tx-id").is_none());
    assert!(json.get("traffic-block-reason-code").is_none());
    assert!(json.get("active-revision-label").is_none());
    assert!(json.get("candidate-status").is_none());
    assert!(json.get("workflow-completion").is_none());
}

#[test]
fn rejected_plan_does_not_create_active_traffic_block() {
    let state = ConfigApplyPlanState::new().with_last_rejected_apply_plan(plan(
        ChangeImpactClass::ForbiddenLive,
        "session_store_backend_changed",
    ));
    let json = state.to_json_value();

    assert_eq!(json["traffic-blocked-until-workflow"], false);
    assert!(json.get("traffic-block-reason-code").is_none());
    assert_eq!(json["last-rejected-apply-plan"]["class"], "forbidden-live");
}

#[test]
fn workflow_completion_by_config_version_clears_block_and_preserves_plan() {
    let state = ConfigApplyPlanState::new()
        .with_active_config(Some(ConfigVersion::new(3)), Some(TxId::new()))
        .with_last_accepted_apply_plan(plan(
            ChangeImpactClass::DrainRequired,
            "hostname_drain_required",
        ))
        .with_workflow_completion(ConfigWorkflowCompletion::for_config_version(
            ConfigVersion::new(3),
        ));

    let json = state.to_json_value();

    assert_eq!(json["traffic-blocked-until-workflow"], false);
    assert!(json.get("traffic-block-reason-code").is_none());
    assert_eq!(json["last-accepted-apply-plan"]["class"], "drain-required");
    assert_eq!(json["workflow-completion"]["config-version"], 3);
    assert_eq!(
        json["workflow-completion"]["workflow-class"],
        "drain-required"
    );
    assert_eq!(
        json["workflow-completion"]["workflow-reason-code"],
        "hostname_drain_required"
    );
    assert!(state.workflow_requirement().is_none());
}

#[test]
fn workflow_completion_by_tx_id_clears_block() {
    let tx_id = TxId::new();
    let state = ConfigApplyPlanState::new()
        .with_active_config(Some(ConfigVersion::new(3)), Some(tx_id))
        .with_last_accepted_apply_plan(plan(ChangeImpactClass::DrainRequired, "drain_required"))
        .with_workflow_completion(ConfigWorkflowCompletion::for_tx_id(tx_id));

    let json = state.to_json_value();

    assert_eq!(json["traffic-blocked-until-workflow"], false);
    assert_eq!(json["workflow-completion"]["tx-id"], tx_id.to_string());
    assert_eq!(
        json["workflow-completion"]["workflow-class"],
        "drain-required"
    );
    assert!(state.workflow_requirement().is_none());
}

#[test]
fn stale_workflow_completion_does_not_clear_active_block() {
    let state = ConfigApplyPlanState::new()
        .with_active_config(Some(ConfigVersion::new(4)), Some(TxId::new()))
        .with_last_accepted_apply_plan(plan(
            ChangeImpactClass::DrainRequired,
            "hostname_drain_required",
        ))
        .with_workflow_completion(ConfigWorkflowCompletion::for_config_version(
            ConfigVersion::new(3),
        ));

    let json = state.to_json_value();

    assert_eq!(json["traffic-blocked-until-workflow"], true);
    assert_eq!(json["traffic-block-reason-code"], "hostname_drain_required");
    assert!(json.get("workflow-completion").is_none());
    assert_eq!(
        state
            .workflow_requirement()
            .expect("workflow required")
            .reason_code,
        "hostname_drain_required"
    );
}

#[test]
fn revision_label_workflow_completion_clears_block() {
    let state = ConfigApplyPlanState::new()
        .with_active_revision_label(" running-rev-7 ")
        .with_last_accepted_apply_plan(plan(ChangeImpactClass::RestartRequired, "restart_required"))
        .with_workflow_completion(ConfigWorkflowCompletion::for_revision_label(
            "running-rev-7",
        ));

    let json = state.to_json_value();

    assert_eq!(json["traffic-blocked-until-workflow"], false);
    assert_eq!(json["active-revision-label"], "running-rev-7");
    assert_eq!(
        json["workflow-completion"]["revision-label"],
        "running-rev-7"
    );
    assert_eq!(
        json["workflow-completion"]["workflow-class"],
        "restart-required"
    );
    assert_eq!(
        json["workflow-completion"]["workflow-reason-code"],
        "restart_required"
    );
}

#[test]
fn non_workflow_plan_does_not_create_completion_metadata() {
    let state = ConfigApplyPlanState::new()
        .with_active_config(Some(ConfigVersion::new(3)), Some(TxId::new()))
        .with_last_accepted_apply_plan(plan(ChangeImpactClass::Hot, "hostname_changed"))
        .with_workflow_completion(ConfigWorkflowCompletion::for_config_version(
            ConfigVersion::new(3),
        ));

    let json = state.to_json_value();

    assert_eq!(json["traffic-blocked-until-workflow"], false);
    assert!(json.get("traffic-block-reason-code").is_none());
    assert!(json.get("workflow-completion").is_none());
    assert!(state.workflow_requirement().is_none());
}

#[test]
fn all_supplied_workflow_completion_keys_must_match() {
    let active_tx_id = TxId::new();
    let stale_tx_id = TxId::new();

    let state = ConfigApplyPlanState::new()
        .with_active_config(Some(ConfigVersion::new(5)), Some(active_tx_id))
        .with_last_accepted_apply_plan(plan(ChangeImpactClass::DrainRequired, "drain_required"))
        .with_workflow_completion(
            ConfigWorkflowCompletion::for_config_version(ConfigVersion::new(5))
                .with_tx_id(stale_tx_id),
        );

    let json = state.to_json_value();

    assert_eq!(json["traffic-blocked-until-workflow"], true);
    assert_eq!(json["traffic-block-reason-code"], "drain_required");
    assert!(json.get("workflow-completion").is_none());
}

#[test]
fn workflow_action_completion_by_revision_updates_state_and_result() {
    let (state, result) = ConfigApplyPlanState::new()
        .with_active_revision_label(" rev-drain ")
        .with_last_accepted_apply_plan(plan(ChangeImpactClass::DrainRequired, "drain_required"))
        .complete_workflow_action(ConfigWorkflowActionTarget::for_revision_label("rev-drain"));
    let result_json = serde_json::to_value(&result).expect("result json");
    let state_json = state.to_json_value();

    assert!(result.is_completed());
    assert_eq!(result.status, ConfigWorkflowActionStatus::Completed);
    assert!(result.reason.is_none());
    assert_eq!(result_json["status"], "completed");
    assert!(result_json.get("reason").is_none());
    assert_eq!(result_json["requested"]["revision-label"], "rev-drain");
    assert_eq!(result_json["running"]["revision-label"], "rev-drain");
    assert_eq!(result_json["completion"]["revision-label"], "rev-drain");
    assert_eq!(
        result_json["completion"]["workflow-reason-code"],
        "drain_required"
    );
    assert_eq!(state_json["traffic-blocked-until-workflow"], false);
    assert!(state_json.get("traffic-block-reason-code").is_none());
    assert_eq!(
        state_json["workflow-completion"]["revision-label"],
        "rev-drain"
    );
    assert_eq!(
        state_json["last-accepted-apply-plan"]["class"],
        "drain-required"
    );
}

#[test]
fn workflow_action_rejects_no_running_config_without_mutating_state() {
    let initial = ConfigApplyPlanState::new()
        .with_last_accepted_apply_plan(plan(ChangeImpactClass::DrainRequired, "drain_required"));
    let (state, result) = initial
        .clone()
        .complete_workflow_action(ConfigWorkflowActionTarget::for_revision_label("rev-drain"));
    let result_json = serde_json::to_value(&result).expect("result json");

    assert_eq!(state, initial);
    assert!(!result.is_completed());
    assert_eq!(result.status, ConfigWorkflowActionStatus::Rejected);
    assert_eq!(
        result.reason,
        Some(ConfigWorkflowActionConflictReason::NoRunningConfig)
    );
    assert_eq!(result_json["status"], "rejected");
    assert_eq!(result_json["reason"], "no-running-config");
    assert!(result_json.get("running").is_none());
}

#[test]
fn workflow_action_rejects_revision_mismatch_before_workflow_check() {
    let initial = ConfigApplyPlanState::new()
        .with_active_revision_label("rev-active")
        .with_last_accepted_apply_plan(plan(ChangeImpactClass::Hot, "hostname_changed"));
    let (state, result) = initial
        .clone()
        .complete_workflow_action(ConfigWorkflowActionTarget::for_revision_label("rev-stale"));
    let result_json = serde_json::to_value(&result).expect("result json");

    assert_eq!(state, initial);
    assert_eq!(
        result.reason,
        Some(ConfigWorkflowActionConflictReason::RevisionMismatch)
    );
    assert_eq!(result_json["reason"], "revision-mismatch");
    assert_eq!(result_json["running"]["revision-label"], "rev-active");
    assert_eq!(result_json["requested"]["revision-label"], "rev-stale");
    assert!(result_json.get("completion").is_none());
}

#[test]
fn workflow_action_rejects_no_workflow_required() {
    let initial = ConfigApplyPlanState::new()
        .with_active_revision_label("rev-hot")
        .with_last_accepted_apply_plan(plan(ChangeImpactClass::Hot, "hostname_changed"));
    let (state, result) = initial
        .clone()
        .complete_workflow_action(ConfigWorkflowActionTarget::for_revision_label("rev-hot"));
    let result_json = serde_json::to_value(&result).expect("result json");

    assert_eq!(state, initial);
    assert_eq!(
        result.reason,
        Some(ConfigWorkflowActionConflictReason::NoWorkflowRequired)
    );
    assert_eq!(result_json["reason"], "no-workflow-required");
    assert_eq!(result_json["running"]["revision-label"], "rev-hot");
    assert!(result_json.get("completion").is_none());
}

#[test]
fn workflow_action_rejects_repeated_completion_as_no_workflow_required() {
    let (completed_state, completed_result) = ConfigApplyPlanState::new()
        .with_active_revision_label("rev-drain")
        .with_last_accepted_apply_plan(plan(ChangeImpactClass::DrainRequired, "drain_required"))
        .complete_workflow_action(ConfigWorkflowActionTarget::for_revision_label("rev-drain"));

    assert!(completed_result.is_completed());

    let (state, repeated_result) = completed_state
        .clone()
        .complete_workflow_action(ConfigWorkflowActionTarget::for_revision_label("rev-drain"));

    assert_eq!(state, completed_state);
    assert_eq!(
        repeated_result.reason,
        Some(ConfigWorkflowActionConflictReason::NoWorkflowRequired)
    );
}

#[test]
fn workflow_action_requires_all_supplied_keys_to_match() {
    let active_tx_id = TxId::new();
    let stale_tx_id = TxId::new();
    let initial = ConfigApplyPlanState::new()
        .with_active_config(Some(ConfigVersion::new(5)), Some(active_tx_id))
        .with_last_accepted_apply_plan(plan(ChangeImpactClass::DrainRequired, "drain_required"));
    let (state, result) = initial.clone().complete_workflow_action(
        ConfigWorkflowActionTarget::for_config_version(ConfigVersion::new(5))
            .with_tx_id(stale_tx_id),
    );
    let result_json = serde_json::to_value(&result).expect("result json");

    assert_eq!(state, initial);
    assert_eq!(
        result.reason,
        Some(ConfigWorkflowActionConflictReason::RevisionMismatch)
    );
    assert_eq!(result_json["running"]["config-version"], 5);
    assert_eq!(result_json["running"]["tx-id"], active_tx_id.to_string());
    assert_eq!(result_json["requested"]["tx-id"], stale_tx_id.to_string());
}

#[test]
fn pending_candidate_status_projects_warning_metadata_without_messages() {
    let mut candidate_plan = plan(ChangeImpactClass::Warm, "hostname_changed");
    candidate_plan.warnings.push(ApplyPlanWarning {
        code: " operator_review ".to_string(),
        path: Some(YangPath::new("/system/hostname").expect("path")),
        message: "raw warning body /Users/operator/private.yaml".to_string(),
    });

    let state = ConfigApplyPlanState::new().with_pending_candidate(
        ConfigCandidateStatus::pending_revision_label(" rev-candidate ")
            .with_apply_plan_metadata(&candidate_plan),
    );
    let json = state.to_json_value();

    assert_eq!(json["candidate-status"]["state"], "pending");
    assert_eq!(json["candidate-status"]["revision-label"], "rev-candidate");
    assert_eq!(json["candidate-status"]["warning-count"], 1);
    assert_eq!(
        json["candidate-status"]["warning-codes"][0],
        "operator_review"
    );
    assert_eq!(json["candidate-status"]["apply-plan-class"], "warm");
    assert!(json["candidate-status"].get("error-codes").is_none());
    assert!(!json["candidate-status"]
        .to_string()
        .contains("/Users/operator/private.yaml"));
}

#[test]
fn rejected_candidate_status_projects_redaction_safe_commit_metadata() {
    let mut rejected_plan = plan(ChangeImpactClass::ForbiddenLive, "requires_maintenance");
    rejected_plan.warnings.push(ApplyPlanWarning {
        code: "operator_review".to_string(),
        path: None,
        message: "warning body should stay out".to_string(),
    });
    rejected_plan = rejected_plan.normalize();
    let error = CommitError::apply_plan_rejected(rejected_plan.clone());

    let state = ConfigApplyPlanState::new()
        .with_rejected_candidate_error(
            ConfigCandidateStatus::pending_revision_label("rev-bad"),
            &error,
        )
        .with_last_rejected_apply_plan(rejected_plan);
    let json = state.to_json_value();

    assert_eq!(json["candidate-status"]["state"], "rejected");
    assert_eq!(json["candidate-status"]["revision-label"], "rev-bad");
    assert_eq!(
        json["candidate-status"]["rejection-code"],
        "apply_plan_rejected"
    );
    assert_eq!(
        json["candidate-status"]["management-status"],
        "FAILED_PRECONDITION"
    );
    assert_eq!(
        json["candidate-status"]["netconf-error-type"],
        "application"
    );
    assert_eq!(
        json["candidate-status"]["netconf-error-tag"],
        "operation-failed"
    );
    assert_eq!(json["candidate-status"]["warning-count"], 1);
    assert_eq!(
        json["candidate-status"]["warning-codes"][0],
        "operator_review"
    );
    assert_eq!(
        json["candidate-status"]["apply-plan-class"],
        "forbidden-live"
    );
    assert_eq!(
        json["candidate-status"]["error-codes"][0],
        "apply_plan_rejected"
    );
    assert_eq!(
        json["candidate-status"]["error-codes"][1],
        "forbidden_live_requires_maintenance_workflow"
    );
    assert_eq!(json["last-rejected-apply-plan"]["class"], "forbidden-live");
}

#[test]
fn candidate_rejection_status_does_not_copy_error_message() {
    let error = CommitError::new(
        CommitErrorCode::SemanticValidationFailed,
        "raw /Users/operator/private.yaml should stay out",
    );

    let state = ConfigApplyPlanState::new().with_rejected_candidate_error(
        ConfigCandidateStatus::pending_revision_label("rev-bad"),
        &error,
    );
    let json = state.to_json_value();

    assert_eq!(
        json["candidate-status"]["error-codes"][0],
        "semantic_validation_failed"
    );
    assert_eq!(
        json["candidate-status"]["management-status"],
        "INVALID_ARGUMENT"
    );
    assert!(!json["candidate-status"]
        .to_string()
        .contains("/Users/operator/private.yaml"));
}

#[test]
fn commit_result_with_new_version_clears_rejected_candidate_metadata() {
    let rejected = CommitError::new(
        CommitErrorCode::SemanticValidationFailed,
        "semantic failure",
    );
    let tx_id = TxId::new();
    let state = ConfigApplyPlanState::new()
        .with_rejected_candidate_error(
            ConfigCandidateStatus::pending_revision_label("rev-bad"),
            &rejected,
        )
        .with_last_rejected_apply_plan(plan(ChangeImpactClass::ForbiddenLive, "bad_candidate"))
        .with_commit_result(&CommitResult {
            tx_id,
            base_version: ConfigVersion::new(3),
            new_version: Some(ConfigVersion::new(4)),
            status: CommitStatus::Committed,
            changed_paths: Vec::new(),
            apply_plan: Some(plan(ChangeImpactClass::Hot, "config_changed")),
        });

    let json = state.to_json_value();

    assert_eq!(json["active-config-version"], 4);
    assert_eq!(json["active-tx-id"], tx_id.to_string());
    assert!(json.get("candidate-status").is_none());
    assert!(json.get("last-rejected-apply-plan").is_none());
    assert_eq!(json["last-accepted-apply-plan"]["class"], "hot");
}

#[test]
fn validate_only_result_does_not_mutate_running_status() {
    let state = ConfigApplyPlanState::new()
        .with_active_config(Some(ConfigVersion::new(3)), Some(TxId::new()))
        .with_pending_candidate(ConfigCandidateStatus::pending_revision_label("rev-next"))
        .with_commit_result(&CommitResult {
            tx_id: TxId::new(),
            base_version: ConfigVersion::new(3),
            new_version: None,
            status: CommitStatus::Validated,
            changed_paths: Vec::new(),
            apply_plan: Some(plan(ChangeImpactClass::Warm, "validated_only")),
        });

    let json = state.to_json_value();

    assert_eq!(json["active-config-version"], 3);
    assert_eq!(json["candidate-status"]["state"], "pending");
    assert_eq!(json["candidate-status"]["revision-label"], "rev-next");
    assert!(json.get("last-accepted-apply-plan").is_none());
}

#[test]
fn unkeyed_rejection_is_not_reported_as_candidate_status() {
    let error = CommitError::new(
        CommitErrorCode::RollbackUnavailable,
        "rollback is unavailable",
    );

    let state = ConfigApplyPlanState::new()
        .with_rejected_candidate(ConfigCandidateStatus::default().with_rejection(&error));

    let json = state.to_json_value();

    assert!(json.get("candidate-status").is_none());
}
