use operator_lifecycle::{
    lifecycle_condition_intent, reject_app_config_fields, BootstrapRef, BootstrapRefKind,
    CnfImageIntent, CnfWorkloadIntent, ConditionSeverity, ConditionStatus,
    ManagementExposureIntent, ManagementIdentityIntent, ManagementMaterialRef,
    ManagementMtlsIdentityIntent, ManagementNorthboundIntent, ManagementPortIntent,
    NetconfSshIdentityIntent, NetworkAttachmentIntent, NetworkAttachmentKind, PlacementIntent,
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
            identity: ManagementIdentityIntent::default(),
            northbound: ManagementNorthboundIntent::default(),
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
fn management_tls_exposure_requires_mtls_identity_refs() {
    let mut intent = valid_workload_intent();
    intent.management.northbound.gnmi_tls = Some(ManagementPortIntent::new("gnmi-tls", 57400));

    assert!(matches!(
        intent.validate(),
        Err(ReconcileIntentError::InvalidIntent(message))
            if message.contains("requires mTLS identity refs")
    ));

    intent.management.identity.mtls = Some(ManagementMtlsIdentityIntent {
        svid_ref: ManagementMaterialRef::secret("mgmt-svid"),
        trust_bundle_ref: ManagementMaterialRef::config_map("mgmt-trust-bundle"),
    });

    assert!(intent.validate().is_ok());
}

#[test]
fn management_netconf_ssh_requires_host_and_authorized_key_refs() {
    let mut intent = valid_workload_intent();
    intent.management.northbound.netconf_ssh = Some(ManagementPortIntent::new("netconf-ssh", 830));

    assert!(matches!(
        intent.validate(),
        Err(ReconcileIntentError::InvalidIntent(message))
            if message.contains("NETCONF SSH exposure requires")
    ));

    intent.management.identity.netconf_ssh = Some(NetconfSshIdentityIntent {
        host_key_ref: ManagementMaterialRef::secret("netconf-host-key"),
        authorized_keys_ref: ManagementMaterialRef::config_map("netconf-authorized-keys"),
    });

    assert!(intent.validate().is_ok());
}

#[test]
fn management_northbound_rejects_zero_and_colliding_ports() {
    let mut intent = valid_workload_intent();
    intent.management.identity.mtls = Some(ManagementMtlsIdentityIntent {
        svid_ref: ManagementMaterialRef::secret("mgmt-svid"),
        trust_bundle_ref: ManagementMaterialRef::config_map("mgmt-trust-bundle"),
    });
    intent.management.northbound.gnmi_tls = Some(ManagementPortIntent::new("gnmi-tls", 0));

    assert!(matches!(
        intent.validate(),
        Err(ReconcileIntentError::InvalidIntent(message))
            if message.contains("must be non-zero")
    ));

    intent.management.northbound.gnmi_tls = Some(ManagementPortIntent::new("northbound", 57400));
    intent.management.northbound.netconf_tls = Some(ManagementPortIntent::new("northbound", 6513));

    assert!(matches!(
        intent.validate(),
        Err(ReconcileIntentError::InvalidIntent(message))
            if message.contains("port name")
    ));
}

#[test]
fn management_exposure_deserializes_legacy_shape_with_default_identity() {
    let decoded: ManagementExposureIntent = match serde_json::from_value(serde_json::json!({
        "health": true,
        "metrics": true,
        "admin": false,
        "service_names": ["upf-management"]
    })) {
        Ok(value) => value,
        Err(error) => panic!("legacy management exposure decode failed: {error}"),
    };

    assert!(decoded.health);
    assert!(decoded.identity.mtls.is_none());
    assert!(decoded.northbound.gnmi_tls.is_none());
    assert!(decoded.validate().is_ok());
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
