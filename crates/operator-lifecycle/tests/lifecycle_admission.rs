mod lifecycle_common;

use lifecycle_common::*;
use operator_lifecycle::evaluate_admission;

#[test]
fn test_production_sqlite_backend_rejected() {
    let mut req = create_base_admission_request();
    req.session_backend = "sqlite".to_string();

    let res = evaluate_admission(&req);
    assert!(!res.allowed);
    let status = res.status.unwrap();
    assert!(status
        .message
        .contains("standalone SQLite or Fake session backend"));

    let mut req = create_base_admission_request();
    req.session_backend = "SQLite".to_string();

    let res = evaluate_admission(&req);
    assert!(!res.allowed);
    assert_eq!(
        res.status.unwrap().reason,
        "HAClaimsRejectedWithSingleNodeBackend"
    );
}

#[test]
fn test_production_single_node_config_backend_rejected() {
    let mut req = create_base_admission_request();
    req.config_backend = "sqlite".to_string();

    let res = evaluate_admission(&req);
    assert!(!res.allowed);
    let status = res.status.unwrap();
    assert_eq!(status.reason, "HAClaimsRejectedWithSingleNodeConfigBackend");
    assert!(status
        .message
        .contains("standalone SQLite/Fake config backend"));

    let mut req = create_base_admission_request();
    req.config_backend = "unknown-backend".to_string();

    let res = evaluate_admission(&req);
    assert!(!res.allowed);
    assert_eq!(res.status.unwrap().reason, "HAConfigBackendUnsupported");
}

#[test]
fn test_production_missing_admin_token_rejected() {
    // 1. Missing entirely
    let mut req = create_base_admission_request();
    req.admin_auth.admin_token = None;

    let res = evaluate_admission(&req);
    assert!(!res.allowed);
    assert_eq!(res.status.unwrap().reason, "AdminTokenMissing");

    // 2. Token disabled
    let mut req = create_base_admission_request();
    req.admin_auth.token_enabled = false;

    let res = evaluate_admission(&req);
    assert!(!res.allowed);
    assert_eq!(res.status.unwrap().reason, "AdminTokenMissing");

    // 3. Unsafe / short token
    let mut req = create_base_admission_request();
    req.admin_auth.admin_token = Some("admin123".to_string());

    let res = evaluate_admission(&req);
    assert!(!res.allowed);
    let status = res.status.unwrap();
    assert_eq!(status.reason, "AdminTokenUnsafe");
    assert!(!status.message.contains("admin123"));
    assert!(status.message.contains("[redacted-token]"));
}

#[test]
fn test_production_missing_kms_or_spiffe_rejected() {
    // 1. Missing KMS
    let mut req = create_base_admission_request();
    req.identity.kms_enabled = false;

    let res = evaluate_admission(&req);
    assert!(!res.allowed);
    assert_eq!(res.status.unwrap().reason, "MissingKmsSpiffeIdentity");

    // 2. Missing SPIFFE
    let mut req = create_base_admission_request();
    req.identity.spiffe_enabled = false;

    let res = evaluate_admission(&req);
    assert!(!res.allowed);
    assert_eq!(res.status.unwrap().reason, "MissingKmsSpiffeIdentity");
}

#[test]
fn test_production_missing_resource_profile_rejected() {
    let mut req = create_base_admission_request();
    req.resource_profile = None;

    let res = evaluate_admission(&req);
    assert!(!res.allowed);
    assert_eq!(res.status.unwrap().reason, "ResourceProfileMissing");
}

#[test]
fn test_production_requires_node_capabilities_for_preflight() {
    let mut req = create_base_admission_request();
    req.node_capabilities = None;
    req.claims_ha = false;
    req.compatibility_matrix = None;

    let res = evaluate_admission(&req);

    assert!(!res.allowed);
    let status = res.status.unwrap();
    assert_eq!(status.reason, "NodeCapabilitiesMissing");
    assert!(status.message.contains("node capability report"));
}

#[test]
fn test_compatibility_admission_integration() {
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

    let mut req = create_base_admission_request();
    req.operator_release = Some(op);
    req.nf_release = Some(nf);
    req.compatibility_matrix = Some(matrix);
    req.evidence = Some(ev);

    let res = evaluate_admission(&req);
    assert!(
        res.allowed,
        "Admission should be allowed with compatible policy: {:?}",
        res.status
    );
}

#[test]
fn test_data_plane_preflight_admission_rejection() {
    use opc_node_resources::{
        BpfCapabilities, CpuManagerPolicy, IpsecCapabilities, KernelVersion, NodeCapabilityReport,
        NodeCpuCapabilities, NodeMemoryCapabilities, TopologyManagerPolicy,
    };
    use std::collections::BTreeSet;

    let mut req = create_base_admission_request();

    // Node is missing isolated cores and cpu manager policy is None
    let node_report = NodeCapabilityReport {
        kernel: KernelVersion::new(6, 8, 0),
        bpf: BpfCapabilities {
            cap_bpf: true,
            xdp_supported: true,
            btf_available: true,
            cap_sys_admin_required: false,
            available_xdp_modes: BTreeSet::from([opc_node_resources::XdpMode::Native]),
        },
        cpu: NodeCpuCapabilities {
            manager_policy: CpuManagerPolicy::None,
            isolated_cores: BTreeSet::new(),
            numa_nodes: 1,
            cpu_ids: BTreeSet::from([0, 1, 2, 3]),
            reserved_cores: BTreeSet::from([0, 1]),
            topology_manager_policy: TopologyManagerPolicy::None,
            cpu_numa_map: std::collections::BTreeMap::from([(0, 0), (1, 0), (2, 0), (3, 0)]),
        },
        memory: NodeMemoryCapabilities {
            hugepages_2mi: 1024,
            hugepages_1gi: 4,
            hugepage_pools: vec![],
        },
        nics: vec![opc_node_resources::NicCapability {
            name: "ens5f0".to_string(),
            driver: "ice".to_string(),
            sriov_vfs: 4,
            xdp_modes: BTreeSet::from([opc_node_resources::XdpMode::Native]),
            queues: 4,
            numa_node: Some(0),
        }],
        ipsec: IpsecCapabilities::default(),
        ipsec_gateway: None,
    };

    req.node_capabilities = Some(node_report);

    let res = evaluate_admission(&req);
    assert!(!res.allowed);
    let status = res.status.unwrap();
    assert!(status
        .message
        .contains("Production admission blocked by data-plane preflight"));
}

#[test]
fn test_data_plane_preflight_admission_rejects_missing_bpf_artifact() {
    let mut req = create_base_admission_request();
    req.claims_ha = false;
    req.compatibility_matrix = None;
    req.resource_profile.as_mut().unwrap().bpf_artifacts.clear();

    let res = evaluate_admission(&req);

    assert!(!res.allowed);
    let status = res.status.unwrap();
    assert_eq!(status.reason, "DataPlanePreflightFailed");
    assert!(status.message.contains("governed BPF artifact"));
}

#[test]
fn test_data_plane_preflight_admission_success() {
    use opc_node_resources::{
        BpfCapabilities, CpuManagerPolicy, IpsecCapabilities, KernelVersion, NodeCapabilityReport,
        NodeCpuCapabilities, NodeMemoryCapabilities, TopologyManagerPolicy,
    };
    use std::collections::BTreeSet;

    let mut req = create_base_admission_request();

    // Node is healthy and satisfies all requirements
    let node_report = NodeCapabilityReport {
        kernel: KernelVersion::new(6, 8, 0),
        bpf: BpfCapabilities {
            cap_bpf: true,
            xdp_supported: true,
            btf_available: true,
            cap_sys_admin_required: false,
            available_xdp_modes: BTreeSet::from([opc_node_resources::XdpMode::Native]),
        },
        cpu: NodeCpuCapabilities {
            manager_policy: CpuManagerPolicy::Static,
            isolated_cores: BTreeSet::from([2, 3, 4]),
            numa_nodes: 1,
            cpu_ids: BTreeSet::from([0, 1, 2, 3, 4]),
            reserved_cores: BTreeSet::from([0, 1]),
            topology_manager_policy: TopologyManagerPolicy::SingleNumaNode,
            cpu_numa_map: std::collections::BTreeMap::from([
                (0, 0),
                (1, 0),
                (2, 0),
                (3, 0),
                (4, 0),
            ]),
        },
        memory: NodeMemoryCapabilities {
            hugepages_2mi: 1024,
            hugepages_1gi: 4,
            hugepage_pools: vec![opc_node_resources::HugepagePool {
                numa_node: 0,
                size: "2Mi".to_string(),
                total: 512,
                free: 512,
            }],
        },
        nics: vec![opc_node_resources::NicCapability {
            name: "ens5f0".to_string(),
            driver: "ice".to_string(),
            sriov_vfs: 4,
            xdp_modes: BTreeSet::from([opc_node_resources::XdpMode::Native]),
            queues: 4,
            numa_node: Some(0),
        }],
        ipsec: IpsecCapabilities::default(),
        ipsec_gateway: None,
    };

    req.node_capabilities = Some(node_report);

    // Let's clear compatibility parameters so it doesn't fail on compatibility metadata
    req.claims_ha = false;
    req.compatibility_matrix = None;

    let res = evaluate_admission(&req);
    assert!(res.allowed, "Admission failed: {:?}", res.status);
}
