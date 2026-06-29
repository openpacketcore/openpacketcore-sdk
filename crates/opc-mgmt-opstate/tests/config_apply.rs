use opc_config_model::{ApplyPlan, ApplyPlanChange, ChangeImpact, ChangeImpactClass, YangPath};
use opc_mgmt_opstate::{ConfigApplyPlanState, ConfigWorkflowCompletion};
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
