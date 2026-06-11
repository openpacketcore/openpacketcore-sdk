#![allow(dead_code, unused_imports)]
pub use opc_alarm::{
    AffectedObject, Alarm, AlarmDetails, AlarmId, AlarmState, AlarmType, ProbableCause,
    RedactedText, Severity,
};
pub use opc_runtime::profile::RuntimeMode;
pub use opc_types::{ConfigVersion, SchemaDigest, TxId};
pub use operator_lifecycle::{
    evaluate_admission, evaluate_config_apply, evaluate_rollback_target, generate_upgrade_plan,
    sanitize_denial_message, AdminAuthSpec, AdmissionRequest, CandidateMetadata,
    CompatibilityBlockReason, CompatibilityDecision, CompatibilityEvidence, CompatibilityFeature,
    CompatibilityMatrix, CompatibilityRule, ConditionSeverity, ConditionStatus,
    ConfigApplyDecision, IdentitySpec, LifecyclePhase, LifecycleStatus, MigrationCompatibility,
    NfReleaseDescriptor, OperatorReleaseDescriptor, PendingConfirmationState, ResourceProfileSpec,
    StoredConfigMetadata, SupportedVersionRange, UpgradeAction,
};
pub use time::OffsetDateTime;

pub fn valid_bpf_artifact(interface_name: &str) -> opc_node_resources::BpfArtifact {
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

pub fn valid_node_capability_report() -> opc_node_resources::NodeCapabilityReport {
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
            isolated_cores: BTreeSet::from([2, 3, 4]),
            numa_nodes: 1,
            cpu_ids: BTreeSet::from([0, 1, 2, 3, 4]),
            reserved_cores: BTreeSet::from([0, 1]),
            topology_manager_policy: TopologyManagerPolicy::SingleNumaNode,
            cpu_numa_map: BTreeMap::from([(0, 0), (1, 0), (2, 0), (3, 0), (4, 0)]),
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
    }
}

pub fn create_alarm(severity: Severity, state: AlarmState) -> Alarm {
    let cleared_at = if matches!(state, AlarmState::Cleared | AlarmState::Expired) {
        Some(OffsetDateTime::now_utc())
    } else {
        None
    };
    Alarm {
        alarm_id: AlarmId::new("alarm-123"),
        alarm_type: AlarmType::new("test.alarm"),
        severity,
        probable_cause: ProbableCause::PeerUnreachable,
        affected_object: AffectedObject::NfInstance {
            kind: "amf".to_string(),
            instance: "amf-1".to_string(),
        },
        tenant: None,
        slice: None,
        region: None,
        text: RedactedText::new("A test alarm occurred"),
        details: AlarmDetails::empty(),
        state,
        raised_at: OffsetDateTime::now_utc(),
        updated_at: OffsetDateTime::now_utc(),
        cleared_at,
        correlation_id: None,
    }
}

pub fn create_base_admission_request() -> AdmissionRequest {
    AdmissionRequest {
        uid: "test-uid-123".to_string(),
        runtime_mode: RuntimeMode::Production,
        claims_ha: true,
        config_backend: "consensus".to_string(),
        session_backend: "quorum".to_string(),
        admin_auth: AdminAuthSpec {
            token_enabled: true,
            admin_token: Some("verylongsecuresupersecretadmintoken123456789".to_string()),
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
            isolated_cores: vec![2, 3, 4],
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
        operator_release: None,
        nf_release: None,
        compatibility_matrix: None,
        evidence: None,
    }
}

pub fn create_test_compatibility_matrix() -> CompatibilityMatrix {
    CompatibilityMatrix {
        rules: vec![CompatibilityRule {
            rule_id: "rule-1".to_string(),
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
            allowed_migrations: vec![
                MigrationCompatibility {
                    source_version_range: SupportedVersionRange("1.0.0".to_string()),
                    target_version_range: SupportedVersionRange("2.0.0".to_string()),
                    allowed_rollback: true,
                },
                MigrationCompatibility {
                    source_version_range: SupportedVersionRange("2.0.0".to_string()),
                    target_version_range: SupportedVersionRange("3.0.0".to_string()),
                    allowed_rollback: false,
                },
            ],
        }],
    }
}
