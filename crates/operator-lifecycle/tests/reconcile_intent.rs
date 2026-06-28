use operator_lifecycle::{
    lifecycle_condition_intent, reject_app_config_fields, BootstrapRef, BootstrapRefKind,
    CnfImageIntent, CnfWorkloadIntent, ConditionSeverity, ConditionStatus,
    ManagementExposureIntent, NetworkAttachmentIntent, NetworkAttachmentKind, PlacementIntent,
    ReconcileIntentError, ReplicaIntent, SessionStoreRef, StatusPatchIntent, TrafficStatusIntent,
    UpgradeDrainPolicy,
};
use time::OffsetDateTime;

fn valid_workload_intent() -> CnfWorkloadIntent {
    CnfWorkloadIntent {
        image: CnfImageIntent {
            repository: "registry.example/opc/upf".to_string(),
            tag: None,
            digest: Some("sha256:abc123".to_string()),
        },
        replicas: ReplicaIntent {
            replicas: 3,
            min_available: Some(2),
        },
        placement: PlacementIntent::default(),
        network_attachments: vec![NetworkAttachmentIntent {
            name: "n3".to_string(),
            kind: NetworkAttachmentKind::IpsecGateway,
            interface_name: Some("net1".to_string()),
        }],
        management: ManagementExposureIntent {
            health: true,
            metrics: true,
            admin: true,
            service_names: vec!["upf-management".to_string()],
        },
        bootstrap_refs: vec![BootstrapRef {
            name: "bootstrap-secret".to_string(),
            kind: BootstrapRefKind::Secret,
        }],
        session_store: Some(SessionStoreRef {
            backend_profile: "quorum".to_string(),
            credential_ref: Some("session-store-secret".to_string()),
            config_ref: Some("session-store-endpoints".to_string()),
        }),
        upgrade_drain: UpgradeDrainPolicy::default(),
    }
}

#[test]
fn cnf_workload_intent_validates_platform_owned_fields() {
    assert!(valid_workload_intent().validate().is_ok());

    let mut missing_image = valid_workload_intent();
    missing_image.image.repository.clear();
    assert!(matches!(
        missing_image.validate(),
        Err(ReconcileIntentError::InvalidIntent(_))
    ));

    let mut bad_replicas = valid_workload_intent();
    bad_replicas.replicas.min_available = Some(4);
    assert!(matches!(
        bad_replicas.validate(),
        Err(ReconcileIntentError::InvalidIntent(_))
    ));
}

#[test]
fn status_patch_intent_keeps_lifecycle_and_traffic_text_safe() {
    let condition = lifecycle_condition_intent(
        "Ready",
        ConditionStatus::False,
        "RestoreBlocked",
        "blocked by peer 192.0.2.10 and path /var/lib/opc/session.db",
        7,
        ConditionSeverity::Warning,
        OffsetDateTime::now_utc(),
    );
    assert!(condition.redaction_safe_text);
    assert!(condition.message.contains("[REDACTED_IPV4]"));
    assert!(condition.message.contains("[REDACTED_DB_FILE]"));

    let patch = StatusPatchIntent::new(
        7,
        TrafficStatusIntent::blocked("RestoreBlocked", "session restore gate is active"),
    )
    .with_lifecycle_condition(condition);
    assert!(patch.validate().is_ok());
    assert!(!patch.traffic.traffic_ready);
}

#[test]
fn status_patch_intent_rejects_invalid_conflict_retry() {
    let mut patch = StatusPatchIntent::new(
        1,
        TrafficStatusIntent::ready("Ready", "traffic readiness evidence accepted"),
    );
    patch.conflict_retry.max_attempts = 0;

    assert!(matches!(
        patch.validate(),
        Err(ReconcileIntentError::InvalidIntent(_))
    ));
}

#[test]
fn platform_spec_boundary_rejects_raw_app_config_fields() {
    let valid = serde_json::json!({
        "image": "registry.example/opc/upf@sha256:abc",
        "bootstrapRefs": [{"name": "bootstrap-secret"}],
        "sessionStoreRef": {"backendProfile": "quorum"}
    });
    assert!(reject_app_config_fields(&valid).is_ok());

    for key in [
        "appConfig",
        "yangConfig",
        "gnmi",
        "netconfConfig",
        "candidateConfig",
    ] {
        let invalid = serde_json::json!({ key: {"raw": "payload"} });
        assert!(matches!(
            reject_app_config_fields(&invalid),
            Err(ReconcileIntentError::AppConfigFieldRejected { .. })
        ));
    }
}
