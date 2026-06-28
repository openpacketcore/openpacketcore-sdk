use opc_alarm::{
    AffectedObject, Alarm, AlarmDetails, AlarmId, AlarmState, AlarmType, ProbableCause,
    RedactedText, Severity,
};
use opc_runtime::profile::RuntimeMode;
use opc_types::ConfigVersion;
use operator_controller::{
    conversion::{
        apply_defaults_v1alpha1, apply_defaults_v1beta1, convert_v1alpha1_to_v1beta1,
        convert_v1beta1_to_v1alpha1, v1alpha1, v1beta1,
    },
    drain::{
        DrainExecutor, FakeNrfClient, FakeQuorumClient, FakeSessionDrainClient,
        FakeWorkloadFenceClient,
    },
    migration::{
        evaluate_migration_readiness, execute_migration, validate_migration_plan,
        MigrationBlockReason, MigrationDriver, MigrationPlan, MigrationStep, SafetyClassification,
    },
    multicluster::{ClusterRolloutStatus, MultiClusterRolloutPhase, MultiClusterRolloutStatus},
};
use operator_lifecycle::{
    AdminAuthSpec, AdmissionRequest, ConditionStatus, IdentitySpec, LifecyclePhase,
    LifecycleStatus, PendingConfirmationState, ResourceProfileSpec, UpgradeAction,
};
use std::time::Duration;
use time::OffsetDateTime;

// --- Helper Functions to Create Mock Data ---

fn valid_bpf_artifact(interface_name: &str) -> opc_node_resources::BpfArtifact {
    use opc_node_resources::LinuxCapability;
    use std::collections::BTreeSet;

    opc_node_resources::BpfArtifact {
        name: "upf-xdp-fastpath".to_string(),
        digest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            .to_string(),
        signature_ref: "cosign://registry.example/upf-xdp-fastpath@sha256:012345".to_string(),
        signer_identity: "spiffe://openpacketcore.test/ns/platform/sa/release-signer".to_string(),
        program_type: "xdp".to_string(),
        expected_attach_point: interface_name.to_string(),
        allowed_capabilities: BTreeSet::from([
            LinuxCapability::CapBpf,
            LinuxCapability::CapNetAdmin,
            LinuxCapability::CapNetRaw,
        ]),
        evidence_id: Some("platform-preflight-ev-1".to_string()),
    }
}

fn valid_node_capability_report() -> opc_node_resources::NodeCapabilityReport {
    use opc_node_resources::{
        BpfCapabilities, CpuManagerPolicy, HugepagePool, KernelVersion, NicCapability,
        NodeCapabilityReport, NodeCpuCapabilities, NodeMemoryCapabilities, TopologyManagerPolicy,
        XdpMode,
    };
    use std::collections::{BTreeMap, BTreeSet};

    NodeCapabilityReport {
        kernel: KernelVersion::new(6, 8, 0),
        bpf: BpfCapabilities {
            cap_bpf: true,
            xdp_supported: true,
            btf_available: true,
            cap_sys_admin_required: false,
            available_xdp_modes: BTreeSet::from([XdpMode::Native]),
        },
        cpu: NodeCpuCapabilities {
            manager_policy: CpuManagerPolicy::Static,
            isolated_cores: BTreeSet::from([2, 3]),
            numa_nodes: 1,
            cpu_ids: BTreeSet::from([0, 1, 2, 3]),
            reserved_cores: BTreeSet::from([0, 1]),
            topology_manager_policy: TopologyManagerPolicy::SingleNumaNode,
            cpu_numa_map: BTreeMap::from([(0, 0), (1, 0), (2, 0), (3, 0)]),
        },
        memory: NodeMemoryCapabilities {
            hugepages_2mi: 1024,
            hugepages_1gi: 4,
            hugepage_pools: vec![HugepagePool {
                numa_node: 0,
                size: "2Mi".to_string(),
                total: 512,
                free: 512,
            }],
        },
        nics: vec![NicCapability {
            name: "ens5f0".to_string(),
            driver: "ice".to_string(),
            sriov_vfs: 4,
            xdp_modes: BTreeSet::from([XdpMode::Native]),
            queues: 4,
            numa_node: Some(0),
        }],
        ipsec_gateway: None,
    }
}

fn create_alarm(severity: Severity, state: AlarmState) -> Alarm {
    Alarm {
        alarm_id: AlarmId::new("alarm-999"),
        alarm_type: AlarmType::new("crd.migration.alarm"),
        severity,
        probable_cause: ProbableCause::PeerUnreachable,
        affected_object: AffectedObject::NfInstance {
            kind: "upf".to_string(),
            instance: "upf-1".to_string(),
        },
        tenant: None,
        slice: None,
        region: None,
        text: RedactedText::new("Migration threat active"),
        details: AlarmDetails::empty(),
        state,
        raised_at: OffsetDateTime::now_utc(),
        updated_at: OffsetDateTime::now_utc(),
        cleared_at: None,
        correlation_id: None,
    }
}

fn create_admission_request(mode: RuntimeMode, token: Option<String>) -> AdmissionRequest {
    let matrix = CompatibilityMatrix {
        rules: vec![CompatibilityRule {
            rule_id: "rule-default".to_string(),
            operator_version_range: SupportedVersionRange(">=1.0.0, <2.0.0".to_string()),
            sdk_version_range: SupportedVersionRange(">=1.5.0".to_string()),
            nf_kind: "upf".to_string(),
            nf_version_range: SupportedVersionRange("^1.2.0".to_string()),
            crd_api_version_range: SupportedVersionRange("openpacketcore.org/v1beta1".to_string()),
            config_schema_version_range: SupportedVersionRange(">=1.0.0".to_string()),
            state_schema_version_range: SupportedVersionRange(">=1.0.0".to_string()),
            required_features: vec![
                CompatibilityFeature::ConsensusConfigBackend,
                CompatibilityFeature::QuorumSessionBackend,
            ],
            required_runtime_modes: vec![
                RuntimeMode::Production,
                RuntimeMode::Lab,
                RuntimeMode::Conformance,
            ],
            required_persistence_profiles: vec!["consensus".to_string(), "quorum".to_string()],
            allowed_migrations: vec![MigrationCompatibility {
                source_version_range: SupportedVersionRange(">=0.0.0".to_string()),
                target_version_range: SupportedVersionRange(">=0.0.0".to_string()),
                allowed_rollback: true,
            }],
        }],
    };
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
        evidence_id: "ev-default".to_string(),
        approved_by: "admin".to_string(),
        timestamp: "2026-06-08T12:00:00Z".to_string(),
    }];

    AdmissionRequest {
        uid: "uid-000".to_string(),
        runtime_mode: mode,
        claims_ha: true,
        config_backend: "consensus".to_string(),
        session_backend: "quorum".to_string(),
        admin_auth: AdminAuthSpec {
            token_enabled: token.is_some(),
            admin_token: token,
        },
        identity: IdentitySpec {
            kms_enabled: true,
            spiffe_enabled: true,
        },
        resource_profile: Some(ResourceProfileSpec {
            nf_kind: "upf".to_string(),
            data_plane_profile: "AfXdpFastPath".to_string(),
            numa_policy: "Require".to_string(),
            generic_xdp_fallback_allowed: false,
            isolated_cores: vec![2, 3],
            require_exclusive_cores: true,
            data_plane_interfaces: vec!["ens5f0".to_string()],
            data_plane_numa_node: Some(0),
            hugepage_numa_node: Some(0),
            pod_security_evidence_id: Some("platform-preflight-ev-1".to_string()),
            bpf_artifacts: vec![valid_bpf_artifact("ens5f0")],
            sriov_resource_name: Some("intel.com/ice_sriov".to_string()),
            sriov_allowed_device_drivers: vec!["ice".to_string()],
        }),
        node_capabilities: Some(valid_node_capability_report()),
        operator_release: Some(op),
        nf_release: Some(nf),
        compatibility_matrix: Some(matrix),
        evidence: Some(ev),
    }
}

// --- GAP-009-004: CRD Conversion Tests ---

#[test]
fn test_crd_conversion_round_trip() {
    let original = v1alpha1::NetworkFunction {
        api_version: "openpacketcore.org/v1alpha1".to_string(),
        kind: "NfDeployment".to_string(),
        spec: v1alpha1::NetworkFunctionSpec {
            kind: "upf".to_string(),
            replicas: 2,
            profile: Some("AfXdpFastPath".to_string()),
            config_backend: Some("consensus".to_string()),
            session_backend: Some("quorum".to_string()),
            admin_token: Some("verylongsecuresupersecretadmintoken123456789".to_string()),
            token_enabled: Some(true),
        },
        status: Some(v1alpha1::NetworkFunctionStatus {
            lifecycle: Some(LifecycleStatus::new(3)),
            conditions: Some(vec![]),
            observed_generation: Some(3),
        }),
    };

    // Convert v1alpha1 -> v1beta1
    let beta = convert_v1alpha1_to_v1beta1(&original, None)
        .expect("Failed v1alpha1 -> v1beta1 conversion");
    assert_eq!(beta.api_version, "openpacketcore.org/v1beta1");
    assert_eq!(beta.spec.kind, "upf");
    assert_eq!(beta.spec.replicas, 2);
    assert_eq!(beta.spec.config_backend, "consensus");
    assert!(beta.spec.admin_auth.token_enabled);
    assert_eq!(
        beta.spec.admin_auth.admin_token,
        Some("verylongsecuresupersecretadmintoken123456789".to_string())
    );

    // Convert v1beta1 -> v1alpha1
    let round_tripped =
        convert_v1beta1_to_v1alpha1(&beta, None).expect("Failed v1beta1 -> v1alpha1 conversion");
    assert_eq!(round_tripped.api_version, "openpacketcore.org/v1alpha1");
    assert_eq!(round_tripped.spec.kind, "upf");
    assert_eq!(round_tripped.spec.replicas, 2);
    assert_eq!(
        round_tripped.spec.config_backend,
        Some("consensus".to_string())
    );
    assert_eq!(round_tripped.spec.token_enabled, Some(true));
    assert_eq!(
        round_tripped.spec.admin_token,
        Some("verylongsecuresupersecretadmintoken123456789".to_string())
    );
}

#[test]
fn test_crd_conversion_unknown_field_rejection() {
    // Attempting to deserialize JSON with unknown fields on structs decorated with deny_unknown_fields
    let json_v1alpha1 = r#"{
        "apiVersion": "openpacketcore.org/v1alpha1",
        "kind": "NfDeployment",
        "spec": {
            "kind": "upf",
            "replicas": 2,
            "profile": "AfXdpFastPath",
            "unknownExtraField": "somevalue"
        },
        "status": null
    }"#;

    let res: Result<v1alpha1::NetworkFunction, _> = serde_json::from_str(json_v1alpha1);
    assert!(
        res.is_err(),
        "Expected unknown field rejection to fail deserialization"
    );
    let err_str = res.err().unwrap().to_string();
    assert!(err_str.contains("unknown field `unknownExtraField`"));
}

#[test]
fn test_crd_conversion_uses_kubernetes_json_names() {
    let json_v1alpha1 = r#"{
        "apiVersion": "openpacketcore.org/v1alpha1",
        "kind": "NfDeployment",
        "spec": {
            "kind": "upf",
            "replicas": 2,
            "profile": "AfXdpFastPath",
            "configBackend": "consensus",
            "sessionBackend": "quorum",
            "tokenEnabled": true,
            "adminToken": "verylongsecuresupersecretadmintoken123456789"
        },
        "status": {
            "observedGeneration": 4,
            "conditions": [],
            "lifecycle": {
                "phase": "Ready",
                "conditions": [],
                "observedGeneration": 4
            }
        }
    }"#;

    let alpha: v1alpha1::NetworkFunction =
        serde_json::from_str(json_v1alpha1).expect("canonical Kubernetes JSON should parse");
    assert_eq!(alpha.api_version, "openpacketcore.org/v1alpha1");
    assert_eq!(alpha.spec.config_backend, Some("consensus".to_string()));
    assert_eq!(alpha.spec.session_backend, Some("quorum".to_string()));
    assert_eq!(alpha.spec.token_enabled, Some(true));

    let beta = convert_v1alpha1_to_v1beta1(&alpha, None).expect("conversion should succeed");
    let serialized = serde_json::to_string(&beta).expect("serialize beta resource");

    assert!(serialized.contains("\"apiVersion\""));
    assert!(serialized.contains("\"configBackend\""));
    assert!(serialized.contains("\"sessionBackend\""));
    assert!(serialized.contains("\"adminAuth\""));
    assert!(serialized.contains("\"adminToken\""));
    assert!(serialized.contains("\"observedGeneration\""));
    assert!(!serialized.contains("api_version"));
    assert!(!serialized.contains("config_backend"));
    assert!(!serialized.contains("admin_token"));
}

#[test]
fn test_crd_conversion_defaulting() {
    let mut spec1a = v1alpha1::NetworkFunctionSpec {
        kind: "amf".to_string(),
        replicas: 1,
        profile: None,
        config_backend: None,
        session_backend: None,
        admin_token: None,
        token_enabled: None,
    };
    apply_defaults_v1alpha1(&mut spec1a);
    assert_eq!(spec1a.config_backend, Some("sqlite".to_string()));
    assert_eq!(spec1a.session_backend, Some("fake".to_string()));
    assert_eq!(spec1a.token_enabled, Some(false));

    let mut spec1b = v1beta1::NetworkFunctionSpec {
        kind: "amf".to_string(),
        replicas: 1,
        profile: None,
        config_backend: "consensus".to_string(),
        session_backend: "quorum".to_string(),
        admin_auth: v1beta1::AdminAuthSpec {
            token_enabled: false,
            admin_token: None,
        },
        resource_profile: None,
    };
    apply_defaults_v1beta1(&mut spec1b);
    assert!(spec1b.resource_profile.is_some());
    let rp = spec1b.resource_profile.unwrap();
    assert_eq!(rp.data_plane_profile, "ControlPlaneOnly");
    assert_eq!(rp.numa_policy, "Ignore");
}

#[test]
fn test_crd_conversion_redaction() {
    // If conversion is attempted with an insecure token, it should fail-closed and redact the error message
    let bad_resource = v1alpha1::NetworkFunction {
        api_version: "openpacketcore.org/v1alpha1".to_string(),
        kind: "NfDeployment".to_string(),
        spec: v1alpha1::NetworkFunctionSpec {
            kind: "upf".to_string(),
            replicas: 1,
            profile: None,
            config_backend: None,
            session_backend: None,
            admin_token: Some("admin123".to_string()),
            token_enabled: Some(true),
        },
        status: None,
    };

    let result = convert_v1alpha1_to_v1beta1(&bad_resource, None);
    assert!(result.is_err());
    let err = result.err().unwrap();
    let err_msg = err.to_string();
    assert!(
        !err_msg.contains("admin123"),
        "Secret leaked in conversion error"
    );
    assert!(
        err_msg.contains("[redacted-token]"),
        "Secret was not properly redacted"
    );
}

// --- GAP-009-005: State Migration Orchestration Tests ---

struct MockMigrationDriver {
    executed_steps: Vec<MigrationStep>,
    should_fail_step: Option<usize>,
    should_fail_publish: bool,
    published_version: Option<ConfigVersion>,
}

impl MigrationDriver for MockMigrationDriver {
    fn execute_step(&mut self, step: &MigrationStep) -> Result<(), String> {
        let index = self.executed_steps.len();
        self.executed_steps.push(step.clone());
        if let Some(fail_idx) = self.should_fail_step {
            if index == fail_idx {
                return Err("Failed to modify database: access token admin123 expired".to_string());
            }
        }
        Ok(())
    }

    fn publish_success(&mut self, target_version: ConfigVersion) -> Result<(), String> {
        if self.should_fail_publish {
            return Err(
                "Failed to commit final transaction to sqlite database at /db/main.sqlite"
                    .to_string(),
            );
        }
        self.published_version = Some(target_version);
        Ok(())
    }
}

#[test]
fn test_migration_readiness_blocks() {
    let plan = MigrationPlan {
        source_version: ConfigVersion::INITIAL,
        target_version: ConfigVersion::INITIAL.next().unwrap(),
        steps: vec![MigrationStep::ValidateSourceSchema],
        rollback_eligible: true,
        evidence_ids: vec!["T-migration-readiness".to_string()],
        safety_classification: SafetyClassification::SafeOnline,
    };

    // 1. Blocked when Node is in RecoveryRequired phase
    let mut status = LifecycleStatus::new(1);
    status.set_phase(LifecyclePhase::RecoveryRequired);
    let alarms = vec![];
    let adm_req = create_admission_request(
        RuntimeMode::Production,
        Some("verylongsecuresupersecrettoken1234".to_string()),
    );

    let res = evaluate_migration_readiness(&plan, &status, None, &alarms, &adm_req);
    assert_eq!(res, Err(MigrationBlockReason::RecoveryRequired));

    // Reset status to Ready
    status.set_phase(LifecyclePhase::Ready);

    // 2. Blocked when critical alarms are active
    let critical_alarm = create_alarm(Severity::Critical, AlarmState::Raised);
    let res = evaluate_migration_readiness(&plan, &status, None, &[critical_alarm], &adm_req);
    assert_eq!(res, Err(MigrationBlockReason::CriticalAlarmsActive));

    // 3. Blocked when a commit-confirmation is pending
    let pending = PendingConfirmationState {
        version: ConfigVersion::INITIAL.next().unwrap(),
        previous_confirmed_version: ConfigVersion::INITIAL,
        applied_at: OffsetDateTime::now_utc(),
        timeout_secs: 60,
    };
    let res = evaluate_migration_readiness(&plan, &status, Some(&pending), &[], &adm_req);
    assert_eq!(res, Err(MigrationBlockReason::PendingCommitConfirmation));

    // 4. Blocked when preflight admission fails (e.g. invalid insecure token in production)
    let bad_adm_req =
        create_admission_request(RuntimeMode::Production, Some("admin123".to_string()));
    let res = evaluate_migration_readiness(&plan, &status, None, &[], &bad_adm_req);
    assert!(matches!(res, Err(MigrationBlockReason::AdmissionFailed(_))));
}

#[test]
fn test_valid_migration_readiness_allows_safe_plan() {
    let plan = MigrationPlan {
        source_version: ConfigVersion::INITIAL,
        target_version: ConfigVersion::INITIAL.next().unwrap(),
        steps: vec![
            MigrationStep::ValidateSourceSchema,
            MigrationStep::VerifyTargetIntegrity,
        ],
        rollback_eligible: true,
        evidence_ids: vec!["ev-default".to_string()],
        safety_classification: SafetyClassification::SafeOnline,
    };
    let mut status = LifecycleStatus::new(1);
    status.set_phase(LifecyclePhase::Ready);
    let adm_req = create_admission_request(
        RuntimeMode::Production,
        Some("verylongsecuresupersecrettoken1234".to_string()),
    );

    let res = evaluate_migration_readiness(&plan, &status, None, &[], &adm_req);
    assert_eq!(res, Ok(()));
}

#[test]
fn test_migration_readiness_rejects_unapproved_plan_evidence() {
    let plan = MigrationPlan {
        source_version: ConfigVersion::INITIAL,
        target_version: ConfigVersion::INITIAL.next().unwrap(),
        steps: vec![MigrationStep::VerifyTargetIntegrity],
        rollback_eligible: true,
        evidence_ids: vec!["missing-evidence".to_string()],
        safety_classification: SafetyClassification::SafeOnline,
    };
    let mut status = LifecycleStatus::new(1);
    status.set_phase(LifecyclePhase::Ready);
    let adm_req = create_admission_request(
        RuntimeMode::Production,
        Some("verylongsecuresupersecrettoken1234".to_string()),
    );

    let res = evaluate_migration_readiness(&plan, &status, None, &[], &adm_req);
    assert!(matches!(res, Err(MigrationBlockReason::AdmissionFailed(_))));
    let err = res.unwrap_err().to_string();
    assert!(err.contains("evidence ids not present"));
    assert!(!err.contains("/"));
    assert!(!err.contains("token"));
}

#[test]
fn test_invalid_migration_plans_fail_closed() {
    let invalid_empty = MigrationPlan {
        source_version: ConfigVersion::INITIAL,
        target_version: ConfigVersion::INITIAL.next().unwrap(),
        steps: vec![],
        rollback_eligible: true,
        evidence_ids: vec!["T-empty-plan".to_string()],
        safety_classification: SafetyClassification::SafeOnline,
    };
    assert!(matches!(
        validate_migration_plan(&invalid_empty),
        Err(MigrationBlockReason::InvalidPlan(_))
    ));

    let invalid_version = MigrationPlan {
        source_version: ConfigVersion::INITIAL.next().unwrap(),
        target_version: ConfigVersion::INITIAL,
        steps: vec![MigrationStep::ValidateSourceSchema],
        rollback_eligible: true,
        evidence_ids: vec!["T-version-plan".to_string()],
        safety_classification: SafetyClassification::SafeOnline,
    };
    assert!(matches!(
        validate_migration_plan(&invalid_version),
        Err(MigrationBlockReason::InvalidPlan(_))
    ));

    let invalid_evidence = MigrationPlan {
        source_version: ConfigVersion::INITIAL,
        target_version: ConfigVersion::INITIAL.next().unwrap(),
        steps: vec![MigrationStep::ValidateSourceSchema],
        rollback_eligible: true,
        evidence_ids: vec![" ".to_string()],
        safety_classification: SafetyClassification::SafeOnline,
    };
    assert!(matches!(
        validate_migration_plan(&invalid_evidence),
        Err(MigrationBlockReason::InvalidPlan(_))
    ));

    let unsafe_without_rollback = MigrationPlan {
        source_version: ConfigVersion::INITIAL,
        target_version: ConfigVersion::INITIAL.next().unwrap(),
        steps: vec![MigrationStep::MigrateSessionStoreSchema {
            table: "sessions".to_string(),
        }],
        rollback_eligible: false,
        evidence_ids: vec!["T-unsafe-plan".to_string()],
        safety_classification: SafetyClassification::HighRiskOffline,
    };
    assert!(matches!(
        validate_migration_plan(&unsafe_without_rollback),
        Err(MigrationBlockReason::InvalidPlan(_))
    ));
}

#[test]
fn test_partial_migration_fails_closed_and_redacts() {
    let plan = MigrationPlan {
        source_version: ConfigVersion::INITIAL,
        target_version: ConfigVersion::INITIAL.next().unwrap(),
        steps: vec![
            MigrationStep::ValidateSourceSchema,
            MigrationStep::ApplyYangSchemaTransform {
                xpath: "/nf-spec/data-plane".to_string(),
            },
            MigrationStep::VerifyTargetIntegrity,
        ],
        rollback_eligible: true,
        evidence_ids: vec!["T-partial-fail".to_string()],
        safety_classification: SafetyClassification::SafeOnline,
    };

    let mut driver = MockMigrationDriver {
        executed_steps: vec![],
        should_fail_step: Some(1), // Fail on step 2 (ApplyYangSchemaTransform)
        should_fail_publish: false,
        published_version: None,
    };

    let res = execute_migration(&plan, &mut driver);
    assert!(res.is_err());
    let err_msg = res.err().unwrap();
    assert!(
        err_msg.contains("[redacted-token]"),
        "Error message failed to sanitize credentials"
    );
    assert!(
        !err_msg.contains("admin123"),
        "Error message leaked raw password/token"
    );

    // Verify it failed closed:
    // - execution stopped at the second step
    assert_eq!(driver.executed_steps.len(), 2);
    // - publish_success was never called
    assert_eq!(driver.published_version, None);
}

#[test]
fn test_invalid_migration_execution_never_publishes() {
    let plan = MigrationPlan {
        source_version: ConfigVersion::INITIAL,
        target_version: ConfigVersion::INITIAL.next().unwrap(),
        steps: vec![],
        rollback_eligible: true,
        evidence_ids: vec!["T-invalid-exec".to_string()],
        safety_classification: SafetyClassification::SafeOnline,
    };
    let mut driver = MockMigrationDriver {
        executed_steps: vec![],
        should_fail_step: None,
        should_fail_publish: false,
        published_version: None,
    };

    let res = execute_migration(&plan, &mut driver);
    assert!(res.is_err());
    assert_eq!(driver.executed_steps.len(), 0);
    assert_eq!(driver.published_version, None);
}

// --- GAP-009-006: Out-of-Process Drain Execution Tests ---

#[tokio::test]
async fn test_drain_execution_success() {
    let nrf = FakeNrfClient {
        should_fail: false,
        error_message: "".to_string(),
    };
    let session = FakeSessionDrainClient::new(false, "".to_string(), 2);
    let quorum = FakeQuorumClient {
        should_fail: false,
        error_message: "".to_string(),
    };
    let fence = FakeWorkloadFenceClient {
        should_fail: false,
        error_message: "".to_string(),
    };

    let executor = DrainExecutor::new(nrf, session, quorum, fence);
    let mut status = LifecycleStatus::new(1);
    status.set_phase(LifecyclePhase::Ready);

    let actions = vec![
        UpgradeAction::DeregisterFromNrf,
        UpgradeAction::DrainSessions,
        UpgradeAction::WaitForQuorum,
        UpgradeAction::FenceWorkload,
    ];

    let current_time = OffsetDateTime::now_utc();
    let res = executor
        .execute_drain_plan(
            &actions,
            &mut status,
            1,
            Duration::from_secs(1),
            current_time,
        )
        .await;

    assert!(res.is_ok());
    assert_eq!(status.phase, LifecyclePhase::Upgrading);

    // Verify condition updates
    let draining_cond = status
        .conditions
        .iter()
        .find(|c| c.r#type == "Draining")
        .unwrap();
    assert_eq!(draining_cond.status, ConditionStatus::False);
    assert_eq!(draining_cond.reason, "FenceWorkloadCompleted");
}

#[tokio::test]
async fn test_drain_execution_failure_redacted() {
    let nrf = FakeNrfClient {
        should_fail: true,
        error_message: "NRF connection timeout using token=admin123".to_string(),
    };
    let session = FakeSessionDrainClient::new(false, "".to_string(), 0);
    let quorum = FakeQuorumClient {
        should_fail: false,
        error_message: "".to_string(),
    };
    let fence = FakeWorkloadFenceClient {
        should_fail: false,
        error_message: "".to_string(),
    };

    let executor = DrainExecutor::new(nrf, session, quorum, fence);
    let mut status = LifecycleStatus::new(1);
    status.set_phase(LifecyclePhase::Ready);

    let actions = vec![UpgradeAction::DeregisterFromNrf];
    let res = executor
        .execute_drain_plan(
            &actions,
            &mut status,
            1,
            Duration::from_secs(1),
            OffsetDateTime::now_utc(),
        )
        .await;

    assert!(res.is_err());
    let err_msg = res.err().unwrap();
    assert!(
        !err_msg.contains("admin123"),
        "Raw password leaked in error"
    );
    assert!(err_msg.contains("[redacted-token]"));

    // Verify fail closed stance: phase transitions to Failed
    assert_eq!(status.phase, LifecyclePhase::Failed);
    let ready_cond = status
        .conditions
        .iter()
        .find(|c| c.r#type == "Ready")
        .unwrap();
    assert_eq!(ready_cond.status, ConditionStatus::False);
    assert_eq!(ready_cond.reason, "DeregisterFromNrfFailed");
    assert!(ready_cond.message.contains("[redacted-token]"));
}

#[tokio::test]
async fn test_drain_execution_empty_plan_fails_closed() {
    let nrf = FakeNrfClient {
        should_fail: false,
        error_message: "".to_string(),
    };
    let session = FakeSessionDrainClient::new(false, "".to_string(), 0);
    let quorum = FakeQuorumClient {
        should_fail: false,
        error_message: "".to_string(),
    };
    let fence = FakeWorkloadFenceClient {
        should_fail: false,
        error_message: "".to_string(),
    };

    let executor = DrainExecutor::new(nrf, session, quorum, fence);
    let mut status = LifecycleStatus::new(1);
    status.set_phase(LifecyclePhase::Ready);

    let res = executor
        .execute_drain_plan(
            &[UpgradeAction::ApplyConfig],
            &mut status,
            1,
            Duration::from_secs(1),
            OffsetDateTime::now_utc(),
        )
        .await;

    assert!(res.is_err());
    assert_eq!(status.phase, LifecyclePhase::Failed);
    let ready_cond = status
        .conditions
        .iter()
        .find(|c| c.r#type == "Ready")
        .unwrap();
    assert_eq!(ready_cond.reason, "NoDrainActions");
}

// --- GAP-009-008: Multi-Cluster Rollout Status Tests ---

#[test]
fn test_multi_cluster_rollout_aggregation_and_split_brain() {
    let mut mc_status = MultiClusterRolloutStatus::new(1);

    // Initialize individual cluster status values
    let c1_status = ClusterRolloutStatus {
        cluster_id: "cluster-us-east".to_string(),
        observed_generation: 1,
        resource_version: 1,
        phase: LifecyclePhase::Ready,
        conditions: vec![],
    };

    let c2_status = ClusterRolloutStatus {
        cluster_id: "cluster-us-west".to_string(),
        observed_generation: 1,
        resource_version: 1,
        phase: LifecyclePhase::Upgrading,
        conditions: vec![],
    };

    // 1. Partial rollout state
    mc_status
        .update_cluster_status("cluster-us-east", c1_status.clone())
        .unwrap();
    mc_status
        .update_cluster_status("cluster-us-west", c2_status)
        .unwrap();

    // Aggregated state should be Progressing (one ready, one upgrading)
    assert_eq!(
        mc_status.aggregated_phase,
        MultiClusterRolloutPhase::Progressing
    );
    assert_eq!(mc_status.observed_generation, 1);
    let ready_cond = mc_status
        .conditions
        .iter()
        .find(|c| c.r#type == "Ready")
        .unwrap();
    assert_eq!(ready_cond.status, ConditionStatus::False);
    assert_eq!(ready_cond.reason, "RolloutProgressing");

    // 2. Split-brain / failure disagreement
    let c2_failed_status = ClusterRolloutStatus {
        cluster_id: "cluster-us-west".to_string(),
        observed_generation: 1,
        resource_version: 2,
        phase: LifecyclePhase::Failed,
        conditions: vec![],
    };
    mc_status
        .update_cluster_status("cluster-us-west", c2_failed_status)
        .unwrap();

    // Aggregated state must be RollbackRequired (one ready, one failed). Healthy cluster cannot mask failure!
    assert_eq!(
        mc_status.aggregated_phase,
        MultiClusterRolloutPhase::RollbackRequired
    );
    let ready_cond2 = mc_status
        .conditions
        .iter()
        .find(|c| c.r#type == "Ready")
        .unwrap();
    assert_eq!(ready_cond2.status, ConditionStatus::False);
    assert_eq!(ready_cond2.reason, "RollbackRequired");
}

#[test]
fn test_multi_cluster_stale_status_rejection() {
    let mut mc_status = MultiClusterRolloutStatus::new(1);

    let status_gen2 = ClusterRolloutStatus {
        cluster_id: "cluster-us-east".to_string(),
        observed_generation: 2,
        resource_version: 2,
        phase: LifecyclePhase::Ready,
        conditions: vec![],
    };

    mc_status
        .update_cluster_status("cluster-us-east", status_gen2)
        .unwrap();

    let status_gen1 = ClusterRolloutStatus {
        cluster_id: "cluster-us-east".to_string(),
        observed_generation: 1, // Stale generation
        resource_version: 3,
        phase: LifecyclePhase::Ready,
        conditions: vec![],
    };

    let res = mc_status.update_cluster_status("cluster-us-east", status_gen1);
    assert!(res.is_err(), "Expected stale status to be rejected");
    let err_msg = res.err().unwrap();
    assert!(err_msg.contains("Stale status update rejected"));
}

#[test]
fn test_multi_cluster_identity_and_resource_version_checks() {
    let mut mc_status = MultiClusterRolloutStatus::new(1);

    let initial = ClusterRolloutStatus {
        cluster_id: "cluster-us-east".to_string(),
        observed_generation: 2,
        resource_version: 5,
        phase: LifecyclePhase::Ready,
        conditions: vec![],
    };
    mc_status
        .update_cluster_status("cluster-us-east", initial)
        .unwrap();

    let mismatched = ClusterRolloutStatus {
        cluster_id: "cluster-us-west".to_string(),
        observed_generation: 2,
        resource_version: 6,
        phase: LifecyclePhase::Ready,
        conditions: vec![],
    };
    let res = mc_status.update_cluster_status("cluster-us-east", mismatched);
    assert!(res.is_err());
    assert!(res.unwrap_err().contains("identity mismatch"));

    let stale_resource_version = ClusterRolloutStatus {
        cluster_id: "cluster-us-east".to_string(),
        observed_generation: 2,
        resource_version: 4,
        phase: LifecyclePhase::Ready,
        conditions: vec![],
    };
    let res = mc_status.update_cluster_status("cluster-us-east", stale_resource_version);
    assert!(res.is_err());
    assert!(res.unwrap_err().contains("resource version"));

    let conflicting_same_version = ClusterRolloutStatus {
        cluster_id: "cluster-us-east".to_string(),
        observed_generation: 2,
        resource_version: 5,
        phase: LifecyclePhase::Failed,
        conditions: vec![],
    };
    let res = mc_status.update_cluster_status("cluster-us-east", conflicting_same_version);
    assert!(res.is_err());
    assert!(res
        .unwrap_err()
        .contains("without advancing resource version"));
}

use operator_lifecycle::{
    CompatibilityEvidence, CompatibilityFeature, CompatibilityMatrix, CompatibilityRule,
    ConditionSeverity, LifecycleCondition, MigrationCompatibility, NfReleaseDescriptor,
    OperatorReleaseDescriptor, SupportedVersionRange,
};

fn create_controller_compatibility_matrix() -> CompatibilityMatrix {
    CompatibilityMatrix {
        rules: vec![CompatibilityRule {
            rule_id: "rule-c".to_string(),
            operator_version_range: SupportedVersionRange(">=1.0.0, <2.0.0".to_string()),
            sdk_version_range: SupportedVersionRange(">=1.5.0".to_string()),
            nf_kind: "upf".to_string(),
            nf_version_range: SupportedVersionRange("^1.2.0".to_string()),
            crd_api_version_range: SupportedVersionRange("openpacketcore.org/v1beta1".to_string()),
            config_schema_version_range: SupportedVersionRange(">=1.0.0".to_string()),
            state_schema_version_range: SupportedVersionRange(">=1.0.0".to_string()),
            required_features: vec![
                CompatibilityFeature::ConsensusConfigBackend,
                CompatibilityFeature::QuorumSessionBackend,
            ],
            required_runtime_modes: vec![RuntimeMode::Production],
            required_persistence_profiles: vec!["consensus".to_string(), "quorum".to_string()],
            allowed_migrations: vec![MigrationCompatibility {
                source_version_range: SupportedVersionRange("1.0.0".to_string()),
                target_version_range: SupportedVersionRange("2.0.0".to_string()),
                allowed_rollback: true,
            }],
        }],
    }
}

#[test]
fn test_controller_compatibility_crd_conversion() {
    let matrix = create_controller_compatibility_matrix();
    let original = v1alpha1::NetworkFunction {
        api_version: "openpacketcore.org/v1alpha1".to_string(),
        kind: "NfDeployment".to_string(),
        spec: v1alpha1::NetworkFunctionSpec {
            kind: "upf".to_string(),
            replicas: 2,
            profile: Some("AfXdpFastPath".to_string()),
            config_backend: Some("consensus".to_string()),
            session_backend: Some("quorum".to_string()),
            admin_token: Some("verylongsecuresupersecretadmintoken123456789".to_string()),
            token_enabled: Some(true),
        },
        status: None,
    };

    // The matrix specifies crd_api_version_range as "openpacketcore.org/v1beta1",
    // which does not match "openpacketcore.org/v1alpha1".
    // Therefore, the conversion should be rejected by the matrix.
    let result = convert_v1alpha1_to_v1beta1(&original, Some(&matrix));
    assert!(result.is_err());
    let err_msg = result.err().unwrap().to_string();
    assert!(err_msg.contains("unsupported source CRD API version"));
}

#[test]
fn test_controller_compatibility_migration_readiness() {
    let matrix = create_controller_compatibility_matrix();
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

    // Set up admission request with compatibility matrix
    let mut req = create_admission_request(
        RuntimeMode::Production,
        Some("verylongsecuresupersecretadmintoken123456789".to_string()),
    );
    req.operator_release = Some(op);
    req.nf_release = Some(nf);
    req.compatibility_matrix = Some(matrix);
    req.evidence = Some(ev);

    // 1. Valid migration plan: 1.0.0 -> 2.0.0 is allowed by policy
    let valid_plan = MigrationPlan {
        source_version: ConfigVersion::new(1),
        target_version: ConfigVersion::new(2),
        steps: vec![MigrationStep::VerifyTargetIntegrity],
        rollback_eligible: true,
        evidence_ids: vec!["ev-1".to_string()],
        safety_classification: SafetyClassification::SafeOnline,
    };
    let status = LifecycleStatus::new(1);
    let res = evaluate_migration_readiness(&valid_plan, &status, None, &[], &req);
    assert!(
        res.is_ok(),
        "Expected valid migration plan to be allowed: {:?}",
        res.err()
    );

    // 2. Invalid migration plan: 2.0.0 -> 3.0.0 is not in allowed migrations
    let invalid_plan = MigrationPlan {
        source_version: ConfigVersion::new(2),
        target_version: ConfigVersion::new(3),
        steps: vec![MigrationStep::VerifyTargetIntegrity],
        rollback_eligible: true,
        evidence_ids: vec!["ev-1".to_string()],
        safety_classification: SafetyClassification::SafeOnline,
    };
    let res = evaluate_migration_readiness(&invalid_plan, &status, None, &[], &req);
    assert!(res.is_err());
    let err_msg = res.err().unwrap().to_string();
    assert!(err_msg.contains("Migration path not allowed by policy"));
}

#[test]
fn test_controller_compatibility_multicluster_masking() {
    let mut mc_status = MultiClusterRolloutStatus::new(1);

    // Cluster 1: healthy and Ready
    let cluster1 = ClusterRolloutStatus {
        cluster_id: "cluster-1".to_string(),
        observed_generation: 1,
        resource_version: 1,
        phase: LifecyclePhase::Ready,
        conditions: vec![],
    };
    mc_status
        .update_cluster_status("cluster-1", cluster1)
        .unwrap();
    assert_eq!(mc_status.aggregated_phase, MultiClusterRolloutPhase::Ready);

    // Cluster 2: blocked due to compatibility check
    let block_time = time::OffsetDateTime::now_utc();
    let cluster2 = ClusterRolloutStatus {
        cluster_id: "cluster-2".to_string(),
        observed_generation: 1,
        resource_version: 1,
        phase: LifecyclePhase::Pending,
        conditions: vec![LifecycleCondition {
            r#type: "Blocked".to_string(),
            status: ConditionStatus::True,
            reason: "CompatibilityBlocked".to_string(),
            message: "Compatibility checks failed on cluster".to_string(),
            observed_generation: 1,
            last_transition_time: block_time,
            severity: ConditionSeverity::Error,
            redaction_safe_text: true,
        }],
    };
    mc_status
        .update_cluster_status("cluster-2", cluster2)
        .unwrap();

    // The aggregated phase must be Blocked. The healthy Cluster 1 cannot mask the blocked Cluster 2!
    assert_eq!(
        mc_status.aggregated_phase,
        MultiClusterRolloutPhase::Blocked
    );
}
