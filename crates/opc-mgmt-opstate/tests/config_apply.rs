use opc_config_model::{ApplyPlan, ApplyPlanChange, ChangeImpact, ChangeImpactClass, YangPath};
use opc_mgmt_opstate::ConfigApplyPlanState;
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
