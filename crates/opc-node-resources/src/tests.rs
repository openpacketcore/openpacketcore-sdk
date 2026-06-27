use crate::network::available_xdp_modes;
use crate::types::*;
use crate::validation::{run_data_plane_preflight, validate_resource_profile};
use std::collections::{BTreeMap, BTreeSet};

static DEFAULT_ALLOWLIST: SriovAllowlistPolicy = SriovAllowlistPolicy {
    allowed_resources: BTreeMap::new(),
};

// ------------------------------------------------------------------------
// Helper builders
// ------------------------------------------------------------------------

fn signed_bpf_artifact(interface_name: &str) -> BpfArtifact {
    BpfArtifact {
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

fn production_af_xdp_profile() -> ResourceProfile {
    let mut profile = ResourceProfile::new(
        NetworkFunctionKind::Upf,
        DataPlaneProfile::AfXdpFastPath,
        Environment::Production,
    );
    profile.pod_security.security_evidence_id = Some("platform-preflight-ev-1".to_string());
    profile.pod_security.added_capabilities = BTreeSet::from([
        LinuxCapability::CapBpf,
        LinuxCapability::CapNetAdmin,
        LinuxCapability::CapNetRaw,
    ]);
    profile.af_xdp = Some(AfXdpProfile {
        minimum_kernel: KernelVersion::new(6, 8, 0),
        required_btf: true,
        required_xdp_mode: XdpMode::Native,
        required_capabilities: BTreeSet::from([
            LinuxCapability::CapBpf,
            LinuxCapability::CapNetAdmin,
            LinuxCapability::CapNetRaw,
        ]),
        required_maps: vec!["/sys/fs/bpf/upf-fastpath".to_string()],
        required_pin_paths: vec!["/sys/fs/bpf".to_string()],
        generic_xdp_fallback_allowed: false,
        bpf_artifacts: vec![signed_bpf_artifact("ens5f0")],
    });
    profile
}

fn capable_node() -> NodeCapabilityReport {
    NodeCapabilityReport {
        kernel: KernelVersion::new(6, 8, 0),
        bpf: BpfCapabilities {
            cap_bpf: true,
            xdp_supported: true,
            btf_available: true,
            cap_sys_admin_required: false,
            available_xdp_modes: BTreeSet::from([XdpMode::Native, XdpMode::Generic]),
        },
        cpu: NodeCpuCapabilities {
            manager_policy: CpuManagerPolicy::Static,
            isolated_cores: BTreeSet::from([2, 3, 4, 5]),
            numa_nodes: 2,
            cpu_ids: BTreeSet::from([0, 1, 2, 3, 4, 5, 6, 7]),
            reserved_cores: BTreeSet::from([0, 1]),
            topology_manager_policy: TopologyManagerPolicy::SingleNumaNode,
            cpu_numa_map: BTreeMap::from([
                (0, 0),
                (1, 0),
                (2, 0),
                (3, 0),
                (4, 1),
                (5, 1),
                (6, 1),
                (7, 1),
            ]),
        },
        memory: NodeMemoryCapabilities {
            hugepages_2mi: 4096,
            hugepages_1gi: 8,
            hugepage_pools: vec![
                HugepagePool {
                    numa_node: 0,
                    size: "2Mi".to_string(),
                    total: 2048,
                    free: 2048,
                },
                HugepagePool {
                    numa_node: 0,
                    size: "1Gi".to_string(),
                    total: 4,
                    free: 4,
                },
                HugepagePool {
                    numa_node: 1,
                    size: "2Mi".to_string(),
                    total: 2048,
                    free: 2048,
                },
                HugepagePool {
                    numa_node: 1,
                    size: "1Gi".to_string(),
                    total: 4,
                    free: 4,
                },
            ],
        },
        nics: vec![NicCapability {
            name: "ens5f0".to_string(),
            driver: "ice".to_string(),
            sriov_vfs: 16,
            xdp_modes: BTreeSet::from([XdpMode::Native, XdpMode::Generic]),
            queues: 32,
            numa_node: Some(0),
        }],
        ipsec: IpsecCapabilities {
            xfrm_netlink_available: true,
            xfrm_user_policy_available: true,
            esp_supported: true,
            udp_500_bind_allowed: true,
            udp_4500_bind_allowed: true,
            sctp_supported: true,
            available_kernel_modules: BTreeSet::from(["xfrm_user".to_string(), "esp4".to_string()]),
            supported_esp_algorithms: BTreeSet::from([
                "aes-cbc".to_string(),
                "hmac-sha256".to_string(),
            ]),
        },
    }
}

fn standard_cpu_layout() -> CpuLayout {
    CpuLayout {
        data_plane_cores: vec![2, 3],
        control_plane_cores: vec![0],
        management_cores: vec![1],
        numa_node: Some(0),
    }
}

fn make_context<'a>(
    node: &'a NodeCapabilityReport,
    cpu_layout: &'a CpuLayout,
    interfaces: &'a [String],
    hugepage_numa_node: Option<NumaNodeId>,
) -> ValidationContext<'a> {
    ValidationContext {
        node,
        cpu_layout,
        data_plane_interfaces: interfaces,
        hugepage_numa_node,
        sriov_allowlist: &DEFAULT_ALLOWLIST,
    }
}

fn make_sriov_allowlist() -> SriovAllowlistPolicy {
    SriovAllowlistPolicy {
        allowed_resources: BTreeMap::from([(
            NetworkFunctionKind::Upf,
            BTreeSet::from(["intel.com/ice_sriov".to_string()]),
        )]),
    }
}

// ------------------------------------------------------------------------
// AF_XDP profile validation
// ------------------------------------------------------------------------

#[test]
fn af_xdp_profile_validation_passes_for_production_node() {
    let profile = production_af_xdp_profile();
    let node = capable_node();
    let cpu_layout = standard_cpu_layout();
    let interfaces = vec!["ens5f0".to_string()];
    let ctx = make_context(&node, &cpu_layout, &interfaces, Some(0));

    let report = validate_resource_profile(&profile, &ctx);

    assert!(report.errors.is_empty(), "{report:#?}");
    assert!(!report.fallback_status.active);
}

#[test]
fn production_rejects_cap_sys_admin_for_af_xdp() {
    let mut profile = production_af_xdp_profile();
    profile
        .pod_security
        .added_capabilities
        .insert(LinuxCapability::CapSysAdmin);
    let node = capable_node();
    let cpu_layout = standard_cpu_layout();
    let interfaces = vec!["ens5f0".to_string()];
    let ctx = make_context(&node, &cpu_layout, &interfaces, Some(0));

    let report = validate_resource_profile(&profile, &ctx);

    assert!(report
        .errors
        .contains(&ValidationError::ProductionCapSysAdminForbidden));
}

// ------------------------------------------------------------------------
// SR-IOV resource allowlist
// ------------------------------------------------------------------------

#[test]
fn sriov_resource_must_be_allowlisted() {
    let mut profile = ResourceProfile::new(
        NetworkFunctionKind::Upf,
        DataPlaneProfile::SriovFastPath,
        Environment::Production,
    );
    profile.sriov = Some(SriovProfile {
        resource_name: "intel.com/ice_sriov".to_string(),
        vf_trust: true,
        spoof_check: true,
        vlan_policy: Some("trunk".to_string()),
        link_state_policy: LinkStatePolicy::Enable,
        allowed_device_drivers: BTreeSet::from(["ice".to_string()]),
        ipam_mode: IpamMode::Static,
    });
    let node = capable_node();
    let cpu_layout = standard_cpu_layout();
    let interfaces = vec!["ens5f0".to_string()];
    let allowlist = SriovAllowlistPolicy {
        allowed_resources: BTreeMap::from([(
            NetworkFunctionKind::Upf,
            BTreeSet::from(["intel.com/other_sriov".to_string()]),
        )]),
    };
    let ctx = ValidationContext {
        node: &node,
        cpu_layout: &cpu_layout,
        data_plane_interfaces: &interfaces,
        hugepage_numa_node: Some(0),
        sriov_allowlist: &allowlist,
    };

    let report = validate_resource_profile(&profile, &ctx);

    assert!(report
        .errors
        .contains(&ValidationError::SriovResourceNotAllowlisted {
            nf_kind: NetworkFunctionKind::Upf,
            resource_name: "intel.com/ice_sriov".to_string(),
        }));
}

// ------------------------------------------------------------------------
// NUMA mismatch — NIC interface path
// ------------------------------------------------------------------------

#[test]
fn numa_mismatch_is_detected_before_readiness() {
    let profile = production_af_xdp_profile();
    let mut node = capable_node();
    node.nics[0].numa_node = Some(1);
    let cpu_layout = standard_cpu_layout();
    let interfaces = vec!["ens5f0".to_string()];
    let ctx = make_context(&node, &cpu_layout, &interfaces, Some(0));

    let report = validate_resource_profile(&profile, &ctx);

    assert!(report.errors.contains(&ValidationError::NumaMismatchError {
        component: NumaComponent::Interface("ens5f0".to_string()),
        expected: 0,
        observed: 1,
    }));
}

// ------------------------------------------------------------------------
// NUMA mismatch — huge-page path
// ------------------------------------------------------------------------

#[test]
fn hugepage_numa_mismatch_is_detected_before_readiness() {
    let profile = production_af_xdp_profile();
    let node = capable_node();
    let cpu_layout = standard_cpu_layout();
    let interfaces = vec!["ens5f0".to_string()];
    // hugepage_numa_node differs from cpu_layout.numa_node (0)
    let ctx = make_context(&node, &cpu_layout, &interfaces, Some(1));

    let report = validate_resource_profile(&profile, &ctx);

    assert!(report.errors.contains(&ValidationError::NumaMismatchError {
        component: NumaComponent::Hugepages,
        expected: 0,
        observed: 1,
    }));
}

#[test]
fn out_of_range_hugepage_numa_node_is_rejected_before_mismatch_comparison() {
    let mut profile = production_af_xdp_profile();
    profile.cpu_policy.numa_locality = NumaPolicy::Warn;
    let node = capable_node();
    let cpu_layout = standard_cpu_layout();
    let interfaces = vec!["ens5f0".to_string()];
    let ctx = make_context(&node, &cpu_layout, &interfaces, Some(99));

    let report = validate_resource_profile(&profile, &ctx);

    assert!(!report.is_eligible());
    assert!(report
        .errors
        .contains(&ValidationError::NumaNodeOutOfRange {
            requested: 99,
            available: 2,
        }));
    assert!(!report
        .warnings
        .iter()
        .any(|warning| matches!(warning, ValidationWarning::NumaMismatchWarning { .. })));
}

// ------------------------------------------------------------------------
// NUMA mismatch — NumaPolicy::Warn
// ------------------------------------------------------------------------

#[test]
fn numa_mismatch_under_warn_policy_produces_warning_not_error() {
    let mut profile = production_af_xdp_profile();
    profile.cpu_policy.numa_locality = NumaPolicy::Warn;

    let mut node = capable_node();
    node.nics[0].numa_node = Some(1); // mismatch: node 0 expected, node 1 observed
    let cpu_layout = standard_cpu_layout();
    let interfaces = vec!["ens5f0".to_string()];
    let ctx = make_context(&node, &cpu_layout, &interfaces, Some(0));

    let report = validate_resource_profile(&profile, &ctx);

    // Should be eligible (warning only)
    assert!(report.is_eligible(), "{:#?}", report.errors);
    assert!(report
        .warnings
        .contains(&ValidationWarning::NumaMismatchWarning {
            component: NumaComponent::Interface("ens5f0".to_string()),
            expected: 0,
            observed: 1,
        }));
}

// ------------------------------------------------------------------------
// NUMA mismatch — NumaPolicy::Ignore
// ------------------------------------------------------------------------

#[test]
fn numa_mismatch_under_ignore_policy_produces_no_warning_or_error() {
    let mut profile = production_af_xdp_profile();
    profile.cpu_policy.numa_locality = NumaPolicy::Ignore;

    let mut node = capable_node();
    node.nics[0].numa_node = Some(1);
    let cpu_layout = standard_cpu_layout();
    let interfaces = vec!["ens5f0".to_string()];
    // Also set mismatched hugepages to verify both paths are suppressed
    let ctx = make_context(&node, &cpu_layout, &interfaces, Some(1));

    let report = validate_resource_profile(&profile, &ctx);

    assert!(report.is_eligible());
    // Neither error nor warning should be present for NUMA mismatch
    assert!(!report
        .warnings
        .iter()
        .any(|w| matches!(w, ValidationWarning::NumaMismatchWarning { .. })));
    assert!(!report
        .errors
        .iter()
        .any(|e| matches!(e, ValidationError::NumaMismatchError { .. })));
}

// ------------------------------------------------------------------------
// Lab fallback — generic XDP
// ------------------------------------------------------------------------

#[test]
fn lab_fallback_status_is_visible_when_generic_xdp_is_used() {
    let mut profile = production_af_xdp_profile();
    profile.environment = Environment::Lab;
    profile.lab_fallback.allow_generic_xdp = true;
    profile
        .af_xdp
        .as_mut()
        .unwrap()
        .generic_xdp_fallback_allowed = true;

    let mut node = capable_node();
    node.bpf.available_xdp_modes = BTreeSet::from([XdpMode::Generic]);
    node.nics[0].xdp_modes = BTreeSet::from([XdpMode::Generic]);

    let cpu_layout = standard_cpu_layout();
    let interfaces = vec!["ens5f0".to_string()];
    let ctx = make_context(&node, &cpu_layout, &interfaces, Some(0));

    let report = validate_resource_profile(&profile, &ctx);

    assert!(report.errors.is_empty(), "{report:#?}");
    assert!(report.fallback_status.active);
    assert!(report
        .fallback_status
        .modes
        .contains(&FallbackMode::GenericXdp));
    assert!(report
        .warnings
        .contains(&ValidationWarning::LabFallbackActivated {
            mode: FallbackMode::GenericXdp,
            reason: "required XDP mode unavailable; using generic XDP fallback in lab mode"
                .to_string(),
        }));
}

// ------------------------------------------------------------------------
// Lab fallback — software packet path (blocking regression test)
//
// A lab node that lacks every AF_XDP fast-path prerequisite should still
// be eligible when allow_software_packet_path=true.  The fallback is the
// generic lab escape hatch for any AF_XDP preflight failure (RFC 011 §13).
// ------------------------------------------------------------------------

#[test]
fn lab_node_without_xdp_prerequisites_activates_software_packet_fallback() {
    let mut profile = production_af_xdp_profile();
    profile.environment = Environment::Lab;
    profile.lab_fallback.allow_software_packet_path = true;

    // Node lacks all fast-path prerequisites:
    // - old kernel (below minimum 6.8.0)
    // - no CAP_BPF
    // - no XDP support
    // - empty XDP mode list
    let node = NodeCapabilityReport {
        kernel: KernelVersion::new(5, 15, 0), // below AF_XDP minimum
        bpf: BpfCapabilities {
            cap_bpf: false,
            xdp_supported: false,
            btf_available: false,
            cap_sys_admin_required: false,
            available_xdp_modes: BTreeSet::new(),
        },
        cpu: NodeCpuCapabilities {
            manager_policy: CpuManagerPolicy::Static,
            isolated_cores: BTreeSet::from([2, 3, 4, 5]),
            numa_nodes: 2,
            cpu_ids: BTreeSet::from([0, 1, 2, 3, 4, 5, 6, 7]),
            reserved_cores: BTreeSet::from([0, 1]),
            topology_manager_policy: TopologyManagerPolicy::SingleNumaNode,
            cpu_numa_map: BTreeMap::from([
                (0, 0),
                (1, 0),
                (2, 0),
                (3, 0),
                (4, 1),
                (5, 1),
                (6, 1),
                (7, 1),
            ]),
        },
        memory: NodeMemoryCapabilities {
            hugepages_2mi: 4096,
            hugepages_1gi: 8,
            hugepage_pools: vec![
                HugepagePool {
                    numa_node: 0,
                    size: "2Mi".to_string(),
                    total: 2048,
                    free: 2048,
                },
                HugepagePool {
                    numa_node: 0,
                    size: "1Gi".to_string(),
                    total: 4,
                    free: 4,
                },
                HugepagePool {
                    numa_node: 1,
                    size: "2Mi".to_string(),
                    total: 2048,
                    free: 2048,
                },
                HugepagePool {
                    numa_node: 1,
                    size: "1Gi".to_string(),
                    total: 4,
                    free: 4,
                },
            ],
        },
        nics: vec![NicCapability {
            name: "ens5f0".to_string(),
            driver: "ice".to_string(),
            sriov_vfs: 16,
            xdp_modes: BTreeSet::new(),
            queues: 32,
            numa_node: Some(0),
        }],
        ipsec: IpsecCapabilities::default(),
    };

    let cpu_layout = standard_cpu_layout();
    let interfaces = vec!["ens5f0".to_string()];
    let ctx = make_context(&node, &cpu_layout, &interfaces, Some(0));

    let report = validate_resource_profile(&profile, &ctx);

    // The software-packet fallback should be activated (visible in status)
    assert!(
        report.fallback_status.active,
        "fallback should be active: {report:#?}"
    );
    assert!(report
        .fallback_status
        .modes
        .contains(&FallbackMode::SoftwarePacketPath));
    // The node should be eligible (no errors)
    assert!(report.is_eligible(), "eligible but got: {report:#?}",);
}

// ------------------------------------------------------------------------
// NUMA node out-of-range
// ------------------------------------------------------------------------

#[test]
fn out_of_range_numa_node_id_rejected() {
    let profile = production_af_xdp_profile();
    let node = capable_node();
    // cpu_layout.numa_node = 99 but node only has 2 NUMA nodes (0 and 1)
    let cpu_layout = CpuLayout {
        data_plane_cores: vec![2, 3],
        control_plane_cores: vec![0],
        management_cores: vec![1],
        numa_node: Some(99),
    };
    let interfaces = vec!["ens5f0".to_string()];
    let ctx = make_context(&node, &cpu_layout, &interfaces, Some(0));

    let report = validate_resource_profile(&profile, &ctx);

    assert!(report
        .errors
        .contains(&ValidationError::NumaNodeOutOfRange {
            requested: 99,
            available: 2,
        }));
}

// ------------------------------------------------------------------------
// CAP_SYS_ADMIN — lab fallback
// ------------------------------------------------------------------------

#[test]
fn lab_node_with_cap_sys_admin_required_activates_software_packet_fallback() {
    let mut profile = production_af_xdp_profile();
    profile.environment = Environment::Lab;
    profile.lab_fallback.allow_software_packet_path = true;

    let mut node = capable_node();
    node.bpf.cap_sys_admin_required = true;

    let cpu_layout = standard_cpu_layout();
    let interfaces = vec!["ens5f0".to_string()];
    let ctx = make_context(&node, &cpu_layout, &interfaces, Some(0));

    let report = validate_resource_profile(&profile, &ctx);

    assert!(report.is_eligible(), "{report:#?}");
    assert!(report.fallback_status.active);
    assert!(report
        .fallback_status
        .modes
        .contains(&FallbackMode::SoftwarePacketPath));
}

// ------------------------------------------------------------------------
// CAP_SYS_ADMIN — production rejection
// ------------------------------------------------------------------------

#[test]
fn production_node_with_cap_sys_admin_required_is_rejected() {
    let mut profile = production_af_xdp_profile();
    profile.environment = Environment::Production;
    profile.lab_fallback.allow_software_packet_path = false; // explicit

    let mut node = capable_node();
    node.bpf.cap_sys_admin_required = true;

    let cpu_layout = standard_cpu_layout();
    let interfaces = vec!["ens5f0".to_string()];
    let ctx = make_context(&node, &cpu_layout, &interfaces, Some(0));

    let report = validate_resource_profile(&profile, &ctx);

    assert!(!report.is_eligible());
    assert!(report
        .errors
        .contains(&ValidationError::NodeRequiresCapSysAdmin));
}

// ------------------------------------------------------------------------
// CPU Manager Policy
// ------------------------------------------------------------------------

#[test]
fn fast_path_rejected_when_cpu_manager_policy_is_none() {
    let profile = production_af_xdp_profile();
    let mut node = capable_node();
    node.cpu.manager_policy = CpuManagerPolicy::None;
    let cpu_layout = standard_cpu_layout();
    let interfaces = vec!["ens5f0".to_string()];
    let ctx = make_context(&node, &cpu_layout, &interfaces, Some(0));

    let report = validate_resource_profile(&profile, &ctx);

    assert!(!report.is_eligible());
    assert!(report
        .errors
        .contains(&ValidationError::CpuManagerPolicyIncompatible {
            required: CpuManagerPolicy::Static,
            found: CpuManagerPolicy::None,
        }));
}

#[test]
fn control_plane_only_profile_with_no_data_plane_cores_allows_non_static_cpu_manager() {
    let mut profile = ResourceProfile::new(
        NetworkFunctionKind::Smf,
        DataPlaneProfile::ControlPlaneOnly,
        Environment::Production,
    );
    // ControlPlaneOnly does not require exclusive data-plane cores.
    profile.cpu_policy.require_exclusive_data_plane_cores = false;
    let mut node = capable_node();
    node.cpu.manager_policy = CpuManagerPolicy::None;
    let cpu_layout = CpuLayout {
        data_plane_cores: vec![],
        control_plane_cores: vec![0],
        management_cores: vec![1],
        numa_node: Some(0),
    };
    let ctx = make_context(&node, &cpu_layout, &[], Some(0));

    let report = validate_resource_profile(&profile, &ctx);

    assert!(report.is_eligible(), "{report:#?}");
    assert!(!report
        .errors
        .iter()
        .any(|error| { matches!(error, ValidationError::CpuManagerPolicyIncompatible { .. }) }));
}

#[test]
fn lab_relaxed_cpu_pinning_allows_non_static_cpu_manager() {
    let mut profile = production_af_xdp_profile();
    profile.environment = Environment::Lab;
    profile.lab_fallback.allow_relaxed_cpu_pinning = true;

    let mut node = capable_node();
    node.cpu.manager_policy = CpuManagerPolicy::None;
    node.cpu.isolated_cores.clear();

    let cpu_layout = standard_cpu_layout();
    let interfaces = vec!["ens5f0".to_string()];
    let ctx = make_context(&node, &cpu_layout, &interfaces, Some(0));

    let report = validate_resource_profile(&profile, &ctx);

    assert!(report.is_eligible(), "{report:#?}");
    assert!(report.fallback_status.active);
    assert!(report
        .fallback_status
        .modes
        .contains(&FallbackMode::RelaxedCpuPinning));
}

// ------------------------------------------------------------------------
// Fast-path profile with empty data-plane cores
// ------------------------------------------------------------------------

/// Regression: a production fast-path profile that declares no data-plane
/// cores must be rejected, regardless of the node's CPU manager policy.
#[test]
fn fast_path_rejected_when_data_plane_cores_is_empty() {
    let profile = production_af_xdp_profile();
    // Explicitly set require_exclusive_data_plane_cores=true (fast-path default)
    // but leave data_plane_cores empty to reproduce the bypass bug.
    let cpu_layout = CpuLayout {
        data_plane_cores: vec![],
        control_plane_cores: vec![0],
        management_cores: vec![1],
        numa_node: Some(0),
    };

    // Case 1: CpuManagerPolicy::None — should be rejected with
    // FastPathRequiresDataPlaneCores (empty cores are self-contradictory).
    let mut node = capable_node();
    node.cpu.manager_policy = CpuManagerPolicy::None;
    let ctx = make_context(&node, &cpu_layout, &[], Some(0));
    let report = validate_resource_profile(&profile, &ctx);
    assert!(!report.is_eligible(), "{report:#?}");
    assert!(report
        .errors
        .contains(&ValidationError::FastPathRequiresDataPlaneCores));

    // Case 2: CpuManagerPolicy::Static with no isolated cores —
    // FastPathRequiresDataPlaneCores fires even though the manager is correct.
    let mut node2 = capable_node();
    node2.cpu.manager_policy = CpuManagerPolicy::Static;
    node2.cpu.isolated_cores.clear();
    let ctx2 = make_context(&node2, &cpu_layout, &[], Some(0));
    let report2 = validate_resource_profile(&profile, &ctx2);
    assert!(!report2.is_eligible(), "{report2:#?}");
    assert!(report2
        .errors
        .contains(&ValidationError::FastPathRequiresDataPlaneCores));
}

// ------------------------------------------------------------------------
// AF_XDP — empty data-plane interfaces
// ------------------------------------------------------------------------

#[test]
fn af_xdp_rejected_when_no_data_plane_interfaces() {
    let profile = production_af_xdp_profile();
    let node = capable_node();
    let cpu_layout = standard_cpu_layout();
    // Empty interface list
    let ctx = make_context(&node, &cpu_layout, &[], None);

    let report = validate_resource_profile(&profile, &ctx);

    assert!(!report.is_eligible());
    assert!(report
        .errors
        .contains(&ValidationError::AfXdpNoDataPlaneInterfaces));
}

#[test]
fn af_xdp_rejects_blank_required_map_identifier() {
    let mut profile = production_af_xdp_profile();
    profile.af_xdp.as_mut().unwrap().required_maps = vec!["   ".to_string()];
    let node = capable_node();
    let cpu_layout = standard_cpu_layout();
    let interfaces = vec!["ens5f0".to_string()];
    let ctx = make_context(&node, &cpu_layout, &interfaces, Some(0));

    let report = validate_resource_profile(&profile, &ctx);

    assert!(!report.is_eligible());
    assert!(report.errors.contains(&ValidationError::InvalidBpfMapName {
        map_name: "   ".to_string(),
    }));
}

#[test]
fn af_xdp_rejects_pin_path_outside_controlled_bpffs_namespace() {
    let mut profile = production_af_xdp_profile();
    profile.af_xdp.as_mut().unwrap().required_pin_paths = vec!["/tmp/upf-fastpath".to_string()];
    let node = capable_node();
    let cpu_layout = standard_cpu_layout();
    let interfaces = vec!["ens5f0".to_string()];
    let ctx = make_context(&node, &cpu_layout, &interfaces, Some(0));

    let report = validate_resource_profile(&profile, &ctx);

    assert!(!report.is_eligible());
    assert!(report.errors.contains(&ValidationError::InvalidBpfPinPath {
        path: "/tmp/upf-fastpath".to_string(),
    }));
}

#[test]
fn af_xdp_rejects_pin_path_traversal_outside_controlled_bpffs_namespace() {
    let mut profile = production_af_xdp_profile();
    profile.af_xdp.as_mut().unwrap().required_pin_paths =
        vec!["/sys/fs/bpf/../tmp/escape".to_string()];
    let node = capable_node();
    let cpu_layout = standard_cpu_layout();
    let interfaces = vec!["ens5f0".to_string()];
    let ctx = make_context(&node, &cpu_layout, &interfaces, Some(0));

    let report = validate_resource_profile(&profile, &ctx);

    assert!(!report.is_eligible());
    assert!(report.errors.contains(&ValidationError::InvalidBpfPinPath {
        path: "/sys/fs/bpf/../tmp/escape".to_string(),
    }));
}

// ------------------------------------------------------------------------
// SR-IOV — empty data-plane interfaces
// ------------------------------------------------------------------------

#[test]
fn sriov_rejected_when_no_data_plane_interfaces() {
    let mut profile = ResourceProfile::new(
        NetworkFunctionKind::Upf,
        DataPlaneProfile::SriovFastPath,
        Environment::Production,
    );
    profile.sriov = Some(SriovProfile {
        resource_name: "intel.com/ice_sriov".to_string(),
        vf_trust: false,
        spoof_check: true,
        vlan_policy: None,
        link_state_policy: LinkStatePolicy::Auto,
        allowed_device_drivers: BTreeSet::from(["ice".to_string()]),
        ipam_mode: IpamMode::Static,
    });
    let node = capable_node();
    let cpu_layout = standard_cpu_layout();
    let allowlist = make_sriov_allowlist();
    let ctx = ValidationContext {
        node: &node,
        cpu_layout: &cpu_layout,
        data_plane_interfaces: &[],
        hugepage_numa_node: None,
        sriov_allowlist: &allowlist,
    };

    let report = validate_resource_profile(&profile, &ctx);

    assert!(!report.is_eligible());
    assert!(report
        .errors
        .contains(&ValidationError::SriovNoDataPlaneInterfaces));
}

/// Regression: even in lab mode with veth fallback allowed, an empty
/// data_plane_interfaces list still produces SriovNoDataPlaneInterfaces
/// (fatal). A veth fallback cannot substitute for missing N3/N6
/// attachment definitions (RFC 011 §9.1/§12).
#[test]
fn sriov_lab_veth_rejected_when_no_data_plane_interfaces() {
    let mut profile = ResourceProfile::new(
        NetworkFunctionKind::Upf,
        DataPlaneProfile::SriovFastPath,
        Environment::Lab,
    );
    profile.lab_fallback.allow_veth = true;
    profile.sriov = Some(SriovProfile {
        resource_name: "intel.com/ice_sriov".to_string(),
        vf_trust: false,
        spoof_check: true,
        vlan_policy: None,
        link_state_policy: LinkStatePolicy::Auto,
        allowed_device_drivers: BTreeSet::from(["ice".to_string()]),
        ipam_mode: IpamMode::Static,
    });
    let node = capable_node();
    let cpu_layout = standard_cpu_layout();
    let allowlist = make_sriov_allowlist();
    let ctx = ValidationContext {
        node: &node,
        cpu_layout: &cpu_layout,
        data_plane_interfaces: &[],
        hugepage_numa_node: None,
        sriov_allowlist: &allowlist,
    };

    let report = validate_resource_profile(&profile, &ctx);

    assert!(!report.is_eligible(), "{report:#?}");
    assert!(report
        .errors
        .contains(&ValidationError::SriovNoDataPlaneInterfaces));
}

/// End-to-end regression: in lab SR-IOV with veth fallback allowed,
/// an absent declared interface activates FallbackMode::Veth (not a fatal
/// UnknownInterface). This tests both validate_cpu_layout suppressing
/// UnknownInterface and validate_sriov activating the fallback.
#[test]
fn sriov_lab_veth_fallback_activates_when_declared_interface_is_missing() {
    let mut profile = ResourceProfile::new(
        NetworkFunctionKind::Upf,
        DataPlaneProfile::SriovFastPath,
        Environment::Lab,
    );
    profile.lab_fallback.allow_veth = true;
    profile.sriov = Some(SriovProfile {
        resource_name: "intel.com/ice_sriov".to_string(),
        vf_trust: false,
        spoof_check: true,
        vlan_policy: None,
        link_state_policy: LinkStatePolicy::Auto,
        allowed_device_drivers: BTreeSet::from(["ice".to_string()]),
        ipam_mode: IpamMode::Static,
    });
    let node = capable_node();
    let cpu_layout = standard_cpu_layout();
    // One declared interface that exists, plus one that doesn't.
    let interfaces = vec!["ens5f0".to_string(), "ens6f0".to_string()];
    let allowlist = SriovAllowlistPolicy {
        allowed_resources: BTreeMap::from([(
            NetworkFunctionKind::Upf,
            BTreeSet::from(["intel.com/ice_sriov".to_string()]),
        )]),
    };
    let ctx = ValidationContext {
        node: &node,
        cpu_layout: &cpu_layout,
        data_plane_interfaces: &interfaces,
        hugepage_numa_node: Some(0),
        sriov_allowlist: &allowlist,
    };

    let report = validate_resource_profile(&profile, &ctx);

    assert!(report.is_eligible(), "{report:#?}");
    assert!(report.fallback_status.active);
    assert!(report.fallback_status.modes.contains(&FallbackMode::Veth));
    assert!(!report.errors.iter().any(|e| {
        matches!(e, ValidationError::UnknownInterface { .. })
            | matches!(e, ValidationError::SriovNicZeroVfs { .. })
    }));
}

// ------------------------------------------------------------------------
// available_xdp_modes — BPF intersection with specified interfaces
//
// When specific interfaces are named, the result is the intersection of
// those NICs' XDP modes AND the BPF subsystem's available modes.
// A mode must be usable by both the NICs AND the BPF subsystem.
// ------------------------------------------------------------------------

#[test]
fn available_xdp_modes_intersects_nic_and_bpf_modes() {
    // BPF subsystem reports only Generic; specific NIC supports Native and Generic.
    // The intersection should include Generic (present in both).
    let mut node = capable_node();
    node.bpf.available_xdp_modes = BTreeSet::from([XdpMode::Generic]);
    node.nics[0].xdp_modes = BTreeSet::from([XdpMode::Native, XdpMode::Generic]);

    let modes = available_xdp_modes(&node, &["ens5f0".to_string()]);

    // Generic is in both BPF and NIC → present
    assert!(modes.contains(&XdpMode::Generic));
    // Native is only in NIC, not BPF → excluded by intersection
    assert!(!modes.contains(&XdpMode::Native));
}

#[test]
fn available_xdp_modes_skips_unknown_interfaces() {
    let mut node = capable_node();
    node.bpf.available_xdp_modes = BTreeSet::from([XdpMode::Generic]);
    node.nics[0].xdp_modes = BTreeSet::from([XdpMode::Native, XdpMode::Generic]);

    // "typo0" does not exist and should be skipped, so it intersects with ens5f0's modes.
    let modes = available_xdp_modes(&node, &["ens5f0".to_string(), "typo0".to_string()]);

    assert!(modes.contains(&XdpMode::Generic));
    assert!(!modes.contains(&XdpMode::Native));

    // If only unknown interfaces are specified, it returns BPF available modes.
    let modes_only_unknown = available_xdp_modes(&node, &["typo0".to_string()]);
    assert!(modes_only_unknown.contains(&XdpMode::Generic));
}

// ------------------------------------------------------------------------
// SR-IOV — zero VF NIC
// ------------------------------------------------------------------------

#[test]
fn sriov_rejected_when_nic_exposes_zero_vfs() {
    let mut profile = ResourceProfile::new(
        NetworkFunctionKind::Upf,
        DataPlaneProfile::SriovFastPath,
        Environment::Production,
    );
    profile.sriov = Some(SriovProfile {
        resource_name: "intel.com/ice_sriov".to_string(),
        vf_trust: false,
        spoof_check: true,
        vlan_policy: None,
        link_state_policy: LinkStatePolicy::Auto,
        allowed_device_drivers: BTreeSet::from(["ice".to_string()]),
        ipam_mode: IpamMode::Static,
    });
    let mut node = capable_node();
    node.nics[0].sriov_vfs = 0; // zero VFs — cannot assign
    let cpu_layout = standard_cpu_layout();
    let interfaces = vec!["ens5f0".to_string()];
    let allowlist = make_sriov_allowlist();
    let ctx = ValidationContext {
        node: &node,
        cpu_layout: &cpu_layout,
        data_plane_interfaces: &interfaces,
        hugepage_numa_node: Some(0),
        sriov_allowlist: &allowlist,
    };

    let report = validate_resource_profile(&profile, &ctx);

    assert!(!report.is_eligible());
    assert!(report.errors.contains(&ValidationError::SriovNicZeroVfs {
        interface_name: "ens5f0".to_string(),
    }));
}

#[test]
fn sriov_lab_veth_fallback_activates_when_nic_exposes_zero_vfs() {
    let mut profile = ResourceProfile::new(
        NetworkFunctionKind::Upf,
        DataPlaneProfile::SriovFastPath,
        Environment::Lab,
    );
    profile.lab_fallback.allow_veth = true;
    profile.sriov = Some(SriovProfile {
        resource_name: "intel.com/ice_sriov".to_string(),
        vf_trust: false,
        spoof_check: true,
        vlan_policy: None,
        link_state_policy: LinkStatePolicy::Auto,
        allowed_device_drivers: BTreeSet::from(["ice".to_string()]),
        ipam_mode: IpamMode::Static,
    });

    let mut node = capable_node();
    node.nics[0].sriov_vfs = 0;
    let cpu_layout = standard_cpu_layout();
    let interfaces = vec!["ens5f0".to_string()];
    let allowlist = SriovAllowlistPolicy {
        allowed_resources: BTreeMap::from([(
            NetworkFunctionKind::Upf,
            BTreeSet::from(["intel.com/ice_sriov".to_string()]),
        )]),
    };
    let ctx = ValidationContext {
        node: &node,
        cpu_layout: &cpu_layout,
        data_plane_interfaces: &interfaces,
        hugepage_numa_node: Some(0),
        sriov_allowlist: &allowlist,
    };

    let report = validate_resource_profile(&profile, &ctx);

    assert!(report.is_eligible(), "{report:#?}");
    assert!(report.fallback_status.active);
    assert!(report.fallback_status.modes.contains(&FallbackMode::Veth));
    assert!(report
        .warnings
        .contains(&ValidationWarning::LabFallbackActivated {
            mode: FallbackMode::Veth,
            reason: "SR-IOV interface ens5f0 exposes zero VFs; using lab veth fallback".to_string(),
        }));
    assert!(!report
        .errors
        .iter()
        .any(|error| matches!(error, ValidationError::SriovNicZeroVfs { .. })));
}

// ------------------------------------------------------------------------
// CAP_SYS_ADMIN — required_capabilities path (not just added_capabilities)
//
// ProductionCapSysAdminForbidden is emitted when CapSysAdmin appears in
// af_xdp.required_capabilities (caught by the AF_XDP loop), not just
// when it appears in added_capabilities (caught by validate_pod_security).
// ------------------------------------------------------------------------

#[test]
fn production_rejects_cap_sys_admin_in_af_xdp_required_capabilities() {
    let mut profile = production_af_xdp_profile();
    // Put CapSysAdmin in required_capabilities (the AF_XDP-loop path), not
    // in added_capabilities.
    profile
        .af_xdp
        .as_mut()
        .unwrap()
        .required_capabilities
        .insert(LinuxCapability::CapSysAdmin);
    // Ensure it's NOT in added_capabilities to isolate this code path.
    profile
        .pod_security
        .added_capabilities
        .retain(|c| *c != LinuxCapability::CapSysAdmin);
    let node = capable_node();
    let cpu_layout = standard_cpu_layout();
    let interfaces = vec!["ens5f0".to_string()];
    let ctx = make_context(&node, &cpu_layout, &interfaces, Some(0));

    let report = validate_resource_profile(&profile, &ctx);

    assert!(!report.is_eligible());
    assert!(report
        .errors
        .contains(&ValidationError::ProductionCapSysAdminForbidden));
}

// ------------------------------------------------------------------------
// CAP_SYS_ADMIN — deduplication
//
// When CapSysAdmin is in BOTH required_capabilities and added_capabilities,
// ProductionCapSysAdminForbidden should be emitted exactly once, not twice.
// ------------------------------------------------------------------------

#[test]
fn production_cap_sys_admin_forbidden_emitted_once_when_duplicated() {
    let mut profile = production_af_xdp_profile();
    // Add CapSysAdmin to both places.
    profile
        .pod_security
        .added_capabilities
        .insert(LinuxCapability::CapSysAdmin);
    profile
        .af_xdp
        .as_mut()
        .unwrap()
        .required_capabilities
        .insert(LinuxCapability::CapSysAdmin);
    let node = capable_node();
    let cpu_layout = standard_cpu_layout();
    let interfaces = vec!["ens5f0".to_string()];
    let ctx = make_context(&node, &cpu_layout, &interfaces, Some(0));

    let report = validate_resource_profile(&profile, &ctx);

    assert!(!report.is_eligible());
    let count = report
        .errors
        .iter()
        .filter(|e| matches!(e, ValidationError::ProductionCapSysAdminForbidden))
        .count();
    assert_eq!(
        count, 1,
        "ProductionCapSysAdminForbidden should appear exactly once, got {count}"
    );
}

#[test]
fn af_xdp_profile_with_require_exclusive_false_and_static_policy_passes() {
    let mut profile = production_af_xdp_profile();
    profile.cpu_policy.require_exclusive_data_plane_cores = false;
    let node = capable_node();
    let cpu_layout = standard_cpu_layout();
    let interfaces = vec!["ens5f0".to_string()];
    let ctx = make_context(&node, &cpu_layout, &interfaces, Some(0));

    let report = validate_resource_profile(&profile, &ctx);

    assert!(report.errors.is_empty(), "{report:#?}");
}

#[test]
fn af_xdp_profile_with_require_exclusive_false_and_none_policy_fails() {
    let mut profile = production_af_xdp_profile();
    profile.cpu_policy.require_exclusive_data_plane_cores = false;
    let mut node = capable_node();
    node.cpu.manager_policy = CpuManagerPolicy::None;
    let cpu_layout = standard_cpu_layout();
    let interfaces = vec!["ens5f0".to_string()];
    let ctx = make_context(&node, &cpu_layout, &interfaces, Some(0));

    let report = validate_resource_profile(&profile, &ctx);

    assert!(
        report
            .errors
            .contains(&ValidationError::CpuManagerPolicyIncompatible {
                required: CpuManagerPolicy::Static,
                found: CpuManagerPolicy::None,
            }),
        "{report:#?}"
    );
}

#[test]
fn af_xdp_profile_with_require_exclusive_false_but_empty_cores_fails() {
    let mut profile = production_af_xdp_profile();
    profile.cpu_policy.require_exclusive_data_plane_cores = false;
    let node = capable_node();
    let mut cpu_layout = standard_cpu_layout();
    cpu_layout.data_plane_cores = vec![];
    let interfaces = vec!["ens5f0".to_string()];
    let ctx = make_context(&node, &cpu_layout, &interfaces, Some(0));

    let report = validate_resource_profile(&profile, &ctx);

    assert!(
        report
            .errors
            .contains(&ValidationError::FastPathRequiresDataPlaneCores),
        "{report:#?}"
    );
}

#[test]
fn default_control_plane_only_profile_with_empty_data_plane_cores_passes() {
    let profile = ResourceProfile::new(
        NetworkFunctionKind::Smf,
        DataPlaneProfile::ControlPlaneOnly,
        Environment::Production,
    );
    let node = capable_node();
    let mut cpu_layout = standard_cpu_layout();
    cpu_layout.data_plane_cores = vec![];
    let interfaces = vec![];
    let ctx = make_context(&node, &cpu_layout, &interfaces, None);

    let report = validate_resource_profile(&profile, &ctx);

    assert!(report.errors.is_empty(), "{report:#?}");
}

#[test]
fn af_xdp_with_missing_numa_node_on_multi_numa_fails() {
    let profile = production_af_xdp_profile();
    let node = capable_node();
    let mut cpu_layout = standard_cpu_layout();
    cpu_layout.numa_node = None;
    let interfaces = vec!["ens5f0".to_string()];
    let ctx = make_context(&node, &cpu_layout, &interfaces, Some(0));

    let report = validate_resource_profile(&profile, &ctx);

    assert!(
        report.errors.contains(&ValidationError::MissingNumaNode),
        "{report:#?}"
    );
}

#[test]
fn af_xdp_with_missing_numa_node_under_ignore_policy_fails() {
    let mut profile = production_af_xdp_profile();
    profile.cpu_policy.numa_locality = NumaPolicy::Ignore;
    let node = capable_node();
    let mut cpu_layout = standard_cpu_layout();
    cpu_layout.numa_node = None;
    let interfaces = vec!["ens5f0".to_string()];
    let ctx = make_context(&node, &cpu_layout, &interfaces, Some(0));

    let report = validate_resource_profile(&profile, &ctx);

    assert!(
        report.errors.contains(&ValidationError::MissingNumaNode),
        "{report:#?}"
    );
}

#[test]
fn af_xdp_with_missing_numa_node_on_single_numa_passes() {
    let profile = production_af_xdp_profile();
    let mut node = capable_node();
    node.cpu.numa_nodes = 1;
    let mut cpu_layout = standard_cpu_layout();
    cpu_layout.numa_node = None;
    let interfaces = vec!["ens5f0".to_string()];
    let ctx = make_context(&node, &cpu_layout, &interfaces, Some(0));

    let report = validate_resource_profile(&profile, &ctx);

    assert!(report.errors.is_empty(), "{report:#?}");
}

#[test]
fn control_plane_only_with_missing_numa_node_on_multi_numa_passes() {
    let mut profile = ResourceProfile::new(
        NetworkFunctionKind::Smf,
        DataPlaneProfile::ControlPlaneOnly,
        Environment::Production,
    );
    profile.cpu_policy.numa_locality = NumaPolicy::Require;
    let node = capable_node();
    let mut cpu_layout = standard_cpu_layout();
    cpu_layout.numa_node = None;
    let interfaces = vec![];
    let ctx = make_context(&node, &cpu_layout, &interfaces, None);

    let report = validate_resource_profile(&profile, &ctx);

    assert!(report.errors.is_empty(), "{report:#?}");
}

#[test]
fn numa_node_out_of_range_and_non_isolated_core_reported_together() {
    let profile = production_af_xdp_profile();
    let mut node = capable_node();
    node.cpu.isolated_cores = BTreeSet::new(); // No isolated cores
    let mut cpu_layout = standard_cpu_layout();
    cpu_layout.numa_node = Some(999); // Out of range NUMA node
    let interfaces = vec!["ens5f0".to_string()];
    let ctx = make_context(&node, &cpu_layout, &interfaces, Some(0));

    let report = validate_resource_profile(&profile, &ctx);

    assert!(
        report
            .errors
            .contains(&ValidationError::NumaNodeOutOfRange {
                requested: 999,
                available: 2
            }),
        "{report:#?}"
    );
    assert!(
        report
            .errors
            .contains(&ValidationError::DataPlaneCoreNotIsolated { core: 2 })
            || report
                .errors
                .contains(&ValidationError::DataPlaneCoreNotIsolated { core: 3 }),
        "{report:#?}"
    );
}

#[test]
fn af_xdp_with_missing_numa_node_and_unknown_interface_reports_both() {
    let profile = production_af_xdp_profile();
    let node = capable_node();
    let mut cpu_layout = standard_cpu_layout();
    cpu_layout.numa_node = None;
    let interfaces = vec!["typo0".to_string()];
    let ctx = make_context(&node, &cpu_layout, &interfaces, Some(0));

    let report = validate_resource_profile(&profile, &ctx);

    assert!(
        report.errors.contains(&ValidationError::MissingNumaNode),
        "{report:#?}"
    );
    assert!(
        report.errors.contains(&ValidationError::UnknownInterface {
            interface_name: "typo0".to_string()
        }),
        "{report:#?}"
    );
}

#[test]
fn sriov_production_unknown_interface_reported_exactly_once() {
    let mut profile = ResourceProfile::new(
        NetworkFunctionKind::Upf,
        DataPlaneProfile::SriovFastPath,
        Environment::Production,
    );
    profile.sriov = Some(SriovProfile {
        resource_name: "intel.com/ice_sriov".to_string(),
        vf_trust: false,
        spoof_check: true,
        vlan_policy: None,
        link_state_policy: LinkStatePolicy::Auto,
        allowed_device_drivers: BTreeSet::from(["ice".to_string()]),
        ipam_mode: IpamMode::Static,
    });
    let node = capable_node();
    let cpu_layout = standard_cpu_layout();
    let allowlist = make_sriov_allowlist();
    let interfaces = vec!["typo0".to_string()];
    let ctx = ValidationContext {
        node: &node,
        cpu_layout: &cpu_layout,
        data_plane_interfaces: &interfaces,
        hugepage_numa_node: Some(0),
        sriov_allowlist: &allowlist,
    };

    let report = validate_resource_profile(&profile, &ctx);

    assert!(!report.is_eligible());
    let count = report
        .errors
        .iter()
        .filter(|e| matches!(e, ValidationError::UnknownInterface { .. }))
        .count();
    assert_eq!(
        count, 1,
        "UnknownInterface should be reported exactly once, got {count}"
    );
    assert!(
        report.errors.contains(&ValidationError::UnknownInterface {
            interface_name: "typo0".to_string()
        }),
        "{report:#?}"
    );
}

#[test]
fn signaling_heavy_profile_with_require_exclusive_true_and_none_cpu_manager_fails() {
    let mut profile = ResourceProfile::new(
        NetworkFunctionKind::Upf,
        DataPlaneProfile::SignalingHeavy,
        Environment::Production,
    );
    profile.cpu_policy.require_exclusive_data_plane_cores = true;
    let mut node = capable_node();
    node.cpu.manager_policy = CpuManagerPolicy::None;
    let cpu_layout = standard_cpu_layout();
    let interfaces = vec![];
    let ctx = make_context(&node, &cpu_layout, &interfaces, Some(0));

    let report = validate_resource_profile(&profile, &ctx);

    assert!(!report.is_eligible());
    assert!(
        report
            .errors
            .contains(&ValidationError::CpuManagerPolicyIncompatible {
                required: CpuManagerPolicy::Static,
                found: CpuManagerPolicy::None,
            }),
        "{report:#?}"
    );
}

#[test]
fn af_xdp_with_missing_hugepage_numa_under_require_policy_fails() {
    let mut profile = production_af_xdp_profile();
    profile.cpu_policy.numa_locality = NumaPolicy::Require;
    let node = capable_node();
    let cpu_layout = standard_cpu_layout();
    let interfaces = vec!["ens5f0".to_string()];
    let ctx = make_context(&node, &cpu_layout, &interfaces, None);

    let report = validate_resource_profile(&profile, &ctx);

    assert!(!report.is_eligible());
    assert!(
        report
            .errors
            .contains(&ValidationError::MissingHugepageNumaNode),
        "{report:#?}"
    );
}

#[test]
fn af_xdp_with_missing_hugepage_numa_under_warn_policy_warns() {
    let mut profile = production_af_xdp_profile();
    profile.cpu_policy.numa_locality = NumaPolicy::Warn;
    let node = capable_node();
    let cpu_layout = standard_cpu_layout();
    let interfaces = vec!["ens5f0".to_string()];
    let ctx = make_context(&node, &cpu_layout, &interfaces, None);

    let report = validate_resource_profile(&profile, &ctx);

    assert!(report.is_eligible());
    assert!(
        report
            .warnings
            .contains(&ValidationWarning::MissingHugepageNumaNode),
        "{report:#?}"
    );
}

#[test]
fn disallowed_capability_in_both_added_and_required_is_reported_exactly_once() {
    let mut profile = production_af_xdp_profile();
    profile
        .pod_security
        .added_capabilities
        .insert(LinuxCapability::CapSysAdmin);
    profile
        .af_xdp
        .as_mut()
        .unwrap()
        .required_capabilities
        .insert(LinuxCapability::CapSysAdmin);

    let node = capable_node();
    let cpu_layout = standard_cpu_layout();
    let interfaces = vec!["ens5f0".to_string()];
    let ctx = make_context(&node, &cpu_layout, &interfaces, Some(0));

    let report = validate_resource_profile(&profile, &ctx);

    assert!(!report.is_eligible());
    let count = report
        .errors
        .iter()
        .filter(|e| {
            matches!(
                e,
                ValidationError::CapabilityNotAllowed {
                    capability: LinuxCapability::CapSysAdmin,
                    ..
                }
            )
        })
        .count();
    assert_eq!(
        count, 1,
        "CapabilityNotAllowed should be reported exactly once, got {count}"
    );
}

#[test]
fn af_xdp_with_missing_hugepage_numa_under_ignore_policy_is_completely_ignored() {
    let mut profile = production_af_xdp_profile();
    profile.cpu_policy.numa_locality = NumaPolicy::Ignore;
    let node = capable_node();
    let cpu_layout = standard_cpu_layout();
    let interfaces = vec!["ens5f0".to_string()];
    let ctx = make_context(&node, &cpu_layout, &interfaces, None);

    let report = validate_resource_profile(&profile, &ctx);

    assert!(report.is_eligible());
    assert!(report.errors.is_empty(), "{:#?}", report.errors);
    assert!(
        !report
            .warnings
            .contains(&ValidationWarning::MissingHugepageNumaNode),
        "{report:#?}"
    );
}

#[test]
fn af_xdp_accepts_pin_path_with_trailing_slash() {
    let mut profile = production_af_xdp_profile();
    profile.af_xdp.as_mut().unwrap().required_pin_paths =
        vec!["/sys/fs/bpf/upf-fastpath/".to_string()];
    let node = capable_node();
    let cpu_layout = standard_cpu_layout();
    let interfaces = vec!["ens5f0".to_string()];
    let ctx = make_context(&node, &cpu_layout, &interfaces, Some(0));

    let report = validate_resource_profile(&profile, &ctx);

    assert!(report.is_eligible());
    assert!(report.errors.is_empty(), "{:#?}", report.errors);
}

#[test]
fn test_bpf_governance_requires_artifact_in_production() {
    let mut profile = production_af_xdp_profile();
    profile.af_xdp.as_mut().unwrap().bpf_artifacts.clear();
    let node = capable_node();
    let cpu_layout = standard_cpu_layout();
    let interfaces = vec!["ens5f0".to_string()];
    let ctx = make_context(&node, &cpu_layout, &interfaces, Some(0));

    let report = validate_resource_profile(&profile, &ctx);

    assert!(!report.is_eligible());
    assert!(report.errors.contains(&ValidationError::BpfArtifactMissing));
}

#[test]
fn test_bpf_governance_missing_digest() {
    let mut profile = production_af_xdp_profile();
    profile.af_xdp.as_mut().unwrap().bpf_artifacts = vec![BpfArtifact {
        name: "test-prog".to_string(),
        digest: "".to_string(),
        signature_ref: "sig-ref".to_string(),
        signer_identity: "signer".to_string(),
        program_type: "xdp".to_string(),
        expected_attach_point: "ens5f0".to_string(),
        allowed_capabilities: BTreeSet::new(),
        evidence_id: None,
    }];
    let node = capable_node();
    let cpu_layout = standard_cpu_layout();
    let interfaces = vec!["ens5f0".to_string()];
    let ctx = make_context(&node, &cpu_layout, &interfaces, Some(0));

    let report = validate_resource_profile(&profile, &ctx);
    assert!(!report.is_eligible());
    assert!(report
        .errors
        .iter()
        .any(|e| matches!(e, ValidationError::BpfMissingDigest { .. })));
}

#[test]
fn test_bpf_governance_unsigned_tag() {
    let mut profile = production_af_xdp_profile();
    profile.af_xdp.as_mut().unwrap().bpf_artifacts = vec![BpfArtifact {
        name: "test-prog".to_string(),
        digest: "latest".to_string(),
        signature_ref: "sig-ref".to_string(),
        signer_identity: "signer".to_string(),
        program_type: "xdp".to_string(),
        expected_attach_point: "ens5f0".to_string(),
        allowed_capabilities: BTreeSet::new(),
        evidence_id: None,
    }];
    let node = capable_node();
    let cpu_layout = standard_cpu_layout();
    let interfaces = vec!["ens5f0".to_string()];
    let ctx = make_context(&node, &cpu_layout, &interfaces, Some(0));

    let report = validate_resource_profile(&profile, &ctx);
    assert!(!report.is_eligible());
    assert!(report
        .errors
        .iter()
        .any(|e| matches!(e, ValidationError::BpfUnsignedArtifact { .. })));
}

#[test]
fn test_bpf_governance_wrong_attach_point() {
    let mut profile = production_af_xdp_profile();
    profile.af_xdp.as_mut().unwrap().bpf_artifacts = vec![BpfArtifact {
        name: "test-prog".to_string(),
        digest: "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
            .to_string(),
        signature_ref: "sig-ref".to_string(),
        signer_identity: "signer".to_string(),
        program_type: "xdp".to_string(),
        expected_attach_point: "wrong-nic".to_string(),
        allowed_capabilities: BTreeSet::new(),
        evidence_id: None,
    }];
    let node = capable_node();
    let cpu_layout = standard_cpu_layout();
    let interfaces = vec!["ens5f0".to_string()];
    let ctx = make_context(&node, &cpu_layout, &interfaces, Some(0));

    let report = validate_resource_profile(&profile, &ctx);
    assert!(!report.is_eligible());
    assert!(report
        .errors
        .iter()
        .any(|e| matches!(e, ValidationError::BpfWrongAttachPoint { .. })));
}

#[test]
fn test_bpf_governance_wrong_signer() {
    let mut profile = production_af_xdp_profile();
    profile.af_xdp.as_mut().unwrap().bpf_artifacts = vec![BpfArtifact {
        name: "test-prog".to_string(),
        digest: "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
            .to_string(),
        signature_ref: "".to_string(),
        signer_identity: "".to_string(),
        program_type: "xdp".to_string(),
        expected_attach_point: "ens5f0".to_string(),
        allowed_capabilities: BTreeSet::new(),
        evidence_id: None,
    }];
    let node = capable_node();
    let cpu_layout = standard_cpu_layout();
    let interfaces = vec!["ens5f0".to_string()];
    let ctx = make_context(&node, &cpu_layout, &interfaces, Some(0));

    let report = validate_resource_profile(&profile, &ctx);
    assert!(!report.is_eligible());
    assert!(report
        .errors
        .iter()
        .any(|e| matches!(e, ValidationError::BpfWrongSigner { .. })));
}

#[test]
fn test_bpf_governance_capability_escalation() {
    let mut profile = production_af_xdp_profile();
    profile.af_xdp.as_mut().unwrap().bpf_artifacts = vec![BpfArtifact {
        name: "test-prog".to_string(),
        digest: "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
            .to_string(),
        signature_ref: "sig-ref".to_string(),
        signer_identity: "signer".to_string(),
        program_type: "xdp".to_string(),
        expected_attach_point: "ens5f0".to_string(),
        allowed_capabilities: BTreeSet::from([LinuxCapability::CapSysAdmin]),
        evidence_id: None,
    }];
    let node = capable_node();
    let cpu_layout = standard_cpu_layout();
    let interfaces = vec!["ens5f0".to_string()];
    let ctx = make_context(&node, &cpu_layout, &interfaces, Some(0));

    let report = validate_resource_profile(&profile, &ctx);
    assert!(!report.is_eligible());
    assert!(report
        .errors
        .iter()
        .any(|e| matches!(e, ValidationError::BpfCapabilityEscalation { .. })));
}

#[test]
fn test_bpf_governance_structural_checks_apply_in_lab() {
    // A lab profile may run unsigned artifacts, but the structural checks
    // (capabilities, program type, attach point) must still fire — they guard
    // against capability escalation and mis-attachment regardless of
    // environment. Only the strict provenance checks are Production-gated.
    let mut profile = production_af_xdp_profile();
    profile.environment = Environment::Lab;
    profile.af_xdp.as_mut().unwrap().bpf_artifacts = vec![BpfArtifact {
        name: "lab-prog".to_string(),
        digest: String::new(),        // unsigned: permitted in lab
        signature_ref: String::new(), // unsigned: permitted in lab
        signer_identity: String::new(),
        program_type: "xdp".to_string(),
        expected_attach_point: "ens5f0".to_string(),
        allowed_capabilities: BTreeSet::from([LinuxCapability::CapSysAdmin]),
        evidence_id: None,
    }];
    let node = capable_node();
    let cpu_layout = standard_cpu_layout();
    let interfaces = vec!["ens5f0".to_string()];
    let ctx = make_context(&node, &cpu_layout, &interfaces, Some(0));

    let report = validate_resource_profile(&profile, &ctx);
    // Capability escalation is rejected even in lab.
    assert!(report
        .errors
        .iter()
        .any(|e| matches!(e, ValidationError::BpfCapabilityEscalation { .. })));
    // Provenance (missing digest / unsigned) is NOT enforced in lab.
    assert!(!report.errors.iter().any(|e| matches!(
        e,
        ValidationError::BpfMissingDigest { .. } | ValidationError::BpfUnsignedArtifact { .. }
    )));
}

#[test]
fn test_pod_security_privileged_without_evidence() {
    let mut profile = production_af_xdp_profile();
    profile.pod_security.privileged = true;
    profile.pod_security.security_evidence_id = None;

    let node = capable_node();
    let cpu_layout = standard_cpu_layout();
    let interfaces = vec!["ens5f0".to_string()];
    let ctx = make_context(&node, &cpu_layout, &interfaces, Some(0));

    let report = validate_resource_profile(&profile, &ctx);
    assert!(!report.is_eligible());
    assert!(report
        .errors
        .contains(&ValidationError::SecurityPrivilegedWithoutEvidence));
}

#[test]
fn test_pod_security_host_network_without_evidence() {
    let mut profile = production_af_xdp_profile();
    profile.pod_security.host_network = true;
    profile.pod_security.security_evidence_id = None;

    let node = capable_node();
    let cpu_layout = standard_cpu_layout();
    let interfaces = vec!["ens5f0".to_string()];
    let ctx = make_context(&node, &cpu_layout, &interfaces, Some(0));

    let report = validate_resource_profile(&profile, &ctx);
    assert!(!report.is_eligible());
    assert!(report
        .errors
        .contains(&ValidationError::SecurityHostNetworkWithoutEvidence));
}

#[test]
fn test_pod_security_writable_host_mount_without_evidence() {
    let mut profile = production_af_xdp_profile();
    profile.pod_security.host_path_mounts = vec![HostPathMount {
        host_path: "/sys/fs/bpf".to_string(),
        mount_path: "/sys/fs/bpf".to_string(),
        read_only: false,
    }];
    profile.pod_security.security_evidence_id = None;

    let node = capable_node();
    let cpu_layout = standard_cpu_layout();
    let interfaces = vec!["ens5f0".to_string()];
    let ctx = make_context(&node, &cpu_layout, &interfaces, Some(0));

    let report = validate_resource_profile(&profile, &ctx);
    assert!(!report.is_eligible());
    assert!(report
        .errors
        .contains(&ValidationError::SecurityWritableHostMountWithoutEvidence {
            host_path: "/sys/fs/bpf".to_string()
        }));
}

#[test]
fn test_pod_security_unapproved_host_mount() {
    let mut profile = production_af_xdp_profile();
    profile.pod_security.host_path_mounts = vec![HostPathMount {
        host_path: "/etc/shadow".to_string(),
        mount_path: "/etc/shadow".to_string(),
        read_only: true,
    }];
    profile.pod_security.security_evidence_id = Some("EVID-999".to_string());

    let node = capable_node();
    let cpu_layout = standard_cpu_layout();
    let interfaces = vec!["ens5f0".to_string()];
    let ctx = make_context(&node, &cpu_layout, &interfaces, Some(0));

    let report = validate_resource_profile(&profile, &ctx);
    assert!(!report.is_eligible());
    assert!(report
        .errors
        .contains(&ValidationError::SecurityHostPathMountUnapproved {
            host_path: "/etc/shadow".to_string()
        }));
}

#[test]
fn test_production_rejects_lab_fallbacks() {
    let mut profile = production_af_xdp_profile();
    profile.lab_fallback.allow_relaxed_cpu_pinning = true;

    let node = capable_node();
    let cpu_layout = standard_cpu_layout();
    let interfaces = vec!["ens5f0".to_string()];
    let ctx = make_context(&node, &cpu_layout, &interfaces, Some(0));

    let report = validate_resource_profile(&profile, &ctx);
    assert!(!report.is_eligible());
    assert!(report
        .errors
        .contains(&ValidationError::ProductionLabFallbackForbidden));
}

#[test]
fn test_cpu_topology_manager_policy_incompatible() {
    let profile = production_af_xdp_profile();
    let mut node = capable_node();
    node.cpu.topology_manager_policy = TopologyManagerPolicy::None;
    let cpu_layout = standard_cpu_layout();
    let interfaces = vec!["ens5f0".to_string()];
    let ctx = make_context(&node, &cpu_layout, &interfaces, Some(0));

    let report = validate_resource_profile(&profile, &ctx);
    assert!(!report.is_eligible());
    assert!(report
        .errors
        .contains(&ValidationError::TopologyManagerPolicyIncompatible {
            required: TopologyManagerPolicy::SingleNumaNode,
            found: TopologyManagerPolicy::None,
        }));
}

#[test]
fn test_cpu_reserved_core_overlap() {
    let profile = production_af_xdp_profile();
    let mut node = capable_node();
    node.cpu.reserved_cores = BTreeSet::from([2]);
    let cpu_layout = standard_cpu_layout();
    let interfaces = vec!["ens5f0".to_string()];
    let ctx = make_context(&node, &cpu_layout, &interfaces, Some(0));

    let report = validate_resource_profile(&profile, &ctx);
    assert!(!report.is_eligible());
    assert!(report
        .errors
        .contains(&ValidationError::CpuCoreReservedOverlap { core: 2 }));
}

#[test]
fn test_hugepage_pools_missing() {
    let profile = production_af_xdp_profile();
    let mut node = capable_node();
    node.memory.hugepage_pools = vec![];
    let cpu_layout = standard_cpu_layout();
    let interfaces = vec!["ens5f0".to_string()];
    let ctx = make_context(&node, &cpu_layout, &interfaces, Some(0));

    let report = validate_resource_profile(&profile, &ctx);
    assert!(!report.is_eligible());
    assert!(report
        .errors
        .contains(&ValidationError::HugepagesMissingOrWrongNuma { numa_node: 0 }));
}

#[test]
fn test_run_data_plane_preflight_report() {
    let profile = production_af_xdp_profile();
    let node = capable_node();
    let cpu_layout = standard_cpu_layout();
    let interfaces = vec!["ens5f0".to_string()];
    let ctx = make_context(&node, &cpu_layout, &interfaces, Some(0));

    let report = run_data_plane_preflight(&profile, &ctx);
    assert!(report.passed, "preflight should pass: {report:#?}");
    assert!(!report.blocks_readiness);
    assert_eq!(report.checks.len(), 5);
    assert!(report.checks.iter().all(|c| c.passed));
}

// ------------------------------------------------------------------------
// IPsec gateway profile validation
// ------------------------------------------------------------------------

fn production_ipsec_gateway_profile() -> ResourceProfile {
    let mut profile = ResourceProfile::new(
        NetworkFunctionKind::Amf,
        DataPlaneProfile::IpsecGateway,
        Environment::Production,
    );
    profile.pod_security.security_evidence_id = Some("ipsec-preflight-ev-1".to_string());
    profile.pod_security.added_capabilities =
        BTreeSet::from([LinuxCapability::CapNetAdmin, LinuxCapability::CapNetRaw]);
    profile.ipsec = Some(IpsecGatewayProfile {
        minimum_kernel: KernelVersion::new(5, 15, 0),
        required_capabilities: BTreeSet::from([
            LinuxCapability::CapNetAdmin,
            LinuxCapability::CapNetRaw,
        ]),
        require_xfrm: true,
        require_udp_500: true,
        require_udp_4500: true,
        require_sctp: true,
        required_kernel_modules: BTreeSet::from(["xfrm_user".to_string(), "esp4".to_string()]),
        required_esp_algorithms: BTreeSet::from(["aes-cbc".to_string(), "hmac-sha256".to_string()]),
        network_attachments: vec![IpsecNetworkAttachment {
            interface_name: "ens5f0".to_string(),
            plane: "nwu".to_string(),
            cni_type: "multus".to_string(),
            static_ip: None,
            mtu: Some(1500),
            vlan_id: None,
        }],
        allow_userspace_esp_fallback: false,
    });
    profile
}

#[test]
fn ipsec_gateway_validation_passes_for_production_node() {
    let profile = production_ipsec_gateway_profile();
    let node = capable_node();
    let cpu_layout = standard_cpu_layout();
    let interfaces = vec!["ens5f0".to_string()];
    let ctx = make_context(&node, &cpu_layout, &interfaces, Some(0));

    let report = validate_resource_profile(&profile, &ctx);

    assert!(report.errors.is_empty(), "{report:#?}");
    assert!(!report.fallback_status.active);
}

#[test]
fn ipsec_production_rejects_cap_sys_admin() {
    let mut profile = production_ipsec_gateway_profile();
    profile
        .pod_security
        .added_capabilities
        .insert(LinuxCapability::CapSysAdmin);
    let node = capable_node();
    let cpu_layout = standard_cpu_layout();
    let interfaces = vec!["ens5f0".to_string()];
    let ctx = make_context(&node, &cpu_layout, &interfaces, Some(0));

    let report = validate_resource_profile(&profile, &ctx);

    assert!(report
        .errors
        .contains(&ValidationError::ProductionCapSysAdminForbidden));
}

#[test]
fn ipsec_missing_required_capability_is_rejected() {
    let mut profile = production_ipsec_gateway_profile();
    profile.pod_security.added_capabilities.clear();
    let node = capable_node();
    let cpu_layout = standard_cpu_layout();
    let interfaces = vec!["ens5f0".to_string()];
    let ctx = make_context(&node, &cpu_layout, &interfaces, Some(0));

    let report = validate_resource_profile(&profile, &ctx);

    assert!(!report.is_eligible());
    assert!(report.errors.contains(&ValidationError::MissingCapability {
        capability: LinuxCapability::CapNetAdmin,
    }));
    assert!(report.errors.contains(&ValidationError::MissingCapability {
        capability: LinuxCapability::CapNetRaw,
    }));
}

#[test]
fn ipsec_disallowed_capability_is_rejected() {
    let mut profile = production_ipsec_gateway_profile();
    profile
        .pod_security
        .added_capabilities
        .insert(LinuxCapability::CapBpf);
    let node = capable_node();
    let cpu_layout = standard_cpu_layout();
    let interfaces = vec!["ens5f0".to_string()];
    let ctx = make_context(&node, &cpu_layout, &interfaces, Some(0));

    let report = validate_resource_profile(&profile, &ctx);

    assert!(!report.is_eligible());
    assert!(report
        .errors
        .contains(&ValidationError::CapabilityNotAllowed {
            capability: LinuxCapability::CapBpf,
            profile: DataPlaneProfile::IpsecGateway,
        }));
}

#[test]
fn ipsec_missing_xfrm_netlink_support_is_rejected() {
    let profile = production_ipsec_gateway_profile();
    let mut node = capable_node();
    node.ipsec.xfrm_netlink_available = false;
    let cpu_layout = standard_cpu_layout();
    let interfaces = vec!["ens5f0".to_string()];
    let ctx = make_context(&node, &cpu_layout, &interfaces, Some(0));

    let report = validate_resource_profile(&profile, &ctx);

    assert!(!report.is_eligible());
    assert!(report
        .errors
        .contains(&ValidationError::MissingNodeCapability {
            capability: "xfrm_netlink_available".to_string(),
        }));
}

#[test]
fn ipsec_missing_xfrm_user_policy_support_is_rejected() {
    let profile = production_ipsec_gateway_profile();
    let mut node = capable_node();
    node.ipsec.xfrm_user_policy_available = false;
    let cpu_layout = standard_cpu_layout();
    let interfaces = vec!["ens5f0".to_string()];
    let ctx = make_context(&node, &cpu_layout, &interfaces, Some(0));

    let report = validate_resource_profile(&profile, &ctx);

    assert!(!report.is_eligible());
    assert!(report
        .errors
        .contains(&ValidationError::MissingNodeCapability {
            capability: "xfrm_user_policy_available".to_string(),
        }));
}

#[test]
fn ipsec_missing_kernel_esp_support_is_rejected() {
    let profile = production_ipsec_gateway_profile();
    let mut node = capable_node();
    node.ipsec.esp_supported = false;
    let cpu_layout = standard_cpu_layout();
    let interfaces = vec!["ens5f0".to_string()];
    let ctx = make_context(&node, &cpu_layout, &interfaces, Some(0));

    let report = validate_resource_profile(&profile, &ctx);

    assert!(!report.is_eligible());
    assert!(report
        .errors
        .contains(&ValidationError::MissingNodeCapability {
            capability: "esp_supported".to_string(),
        }));
}

#[test]
fn ipsec_missing_udp_500_bind_is_rejected() {
    let profile = production_ipsec_gateway_profile();
    let mut node = capable_node();
    node.ipsec.udp_500_bind_allowed = false;
    let cpu_layout = standard_cpu_layout();
    let interfaces = vec!["ens5f0".to_string()];
    let ctx = make_context(&node, &cpu_layout, &interfaces, Some(0));

    let report = validate_resource_profile(&profile, &ctx);

    assert!(!report.is_eligible());
    assert!(report
        .errors
        .contains(&ValidationError::MissingNodeCapability {
            capability: "udp_500_bind_allowed".to_string(),
        }));
}

#[test]
fn ipsec_missing_udp_4500_bind_is_rejected() {
    let profile = production_ipsec_gateway_profile();
    let mut node = capable_node();
    node.ipsec.udp_4500_bind_allowed = false;
    let cpu_layout = standard_cpu_layout();
    let interfaces = vec!["ens5f0".to_string()];
    let ctx = make_context(&node, &cpu_layout, &interfaces, Some(0));

    let report = validate_resource_profile(&profile, &ctx);

    assert!(!report.is_eligible());
    assert!(report
        .errors
        .contains(&ValidationError::MissingNodeCapability {
            capability: "udp_4500_bind_allowed".to_string(),
        }));
}

#[test]
fn ipsec_missing_sctp_support_is_rejected() {
    let profile = production_ipsec_gateway_profile();
    let mut node = capable_node();
    node.ipsec.sctp_supported = false;
    let cpu_layout = standard_cpu_layout();
    let interfaces = vec!["ens5f0".to_string()];
    let ctx = make_context(&node, &cpu_layout, &interfaces, Some(0));

    let report = validate_resource_profile(&profile, &ctx);

    assert!(!report.is_eligible());
    assert!(report
        .errors
        .contains(&ValidationError::MissingNodeCapability {
            capability: "sctp_supported".to_string(),
        }));
}

#[test]
fn ipsec_unsupported_kernel_version_is_rejected() {
    let profile = production_ipsec_gateway_profile();
    let mut node = capable_node();
    node.kernel = KernelVersion::new(5, 10, 0);
    let cpu_layout = standard_cpu_layout();
    let interfaces = vec!["ens5f0".to_string()];
    let ctx = make_context(&node, &cpu_layout, &interfaces, Some(0));

    let report = validate_resource_profile(&profile, &ctx);

    assert!(!report.is_eligible());
    assert!(report
        .errors
        .contains(&ValidationError::UnsupportedKernelVersion {
            found: KernelVersion::new(5, 10, 0),
            minimum: KernelVersion::new(5, 15, 0),
        }));
}

#[test]
fn ipsec_lab_missing_xfrm_netlink_activates_software_packet_fallback() {
    let mut profile = production_ipsec_gateway_profile();
    profile.environment = Environment::Lab;
    profile.lab_fallback.allow_software_packet_path = true;
    let mut node = capable_node();
    node.ipsec.xfrm_netlink_available = false;
    let cpu_layout = standard_cpu_layout();
    let interfaces = vec!["ens5f0".to_string()];
    let ctx = make_context(&node, &cpu_layout, &interfaces, Some(0));

    let report = validate_resource_profile(&profile, &ctx);

    assert!(report.is_eligible(), "{report:#?}");
    assert!(report.fallback_status.active);
    assert!(report
        .fallback_status
        .modes
        .contains(&FallbackMode::SoftwarePacketPath));
}

#[test]
fn ipsec_lab_missing_xfrm_user_policy_activates_software_packet_fallback() {
    let mut profile = production_ipsec_gateway_profile();
    profile.environment = Environment::Lab;
    profile.lab_fallback.allow_software_packet_path = true;
    let mut node = capable_node();
    node.ipsec.xfrm_user_policy_available = false;
    let cpu_layout = standard_cpu_layout();
    let interfaces = vec!["ens5f0".to_string()];
    let ctx = make_context(&node, &cpu_layout, &interfaces, Some(0));

    let report = validate_resource_profile(&profile, &ctx);

    assert!(report.is_eligible(), "{report:#?}");
    assert!(report.fallback_status.active);
    assert!(report
        .fallback_status
        .modes
        .contains(&FallbackMode::SoftwarePacketPath));
}

#[test]
fn ipsec_lab_kernel_esp_unavailable_activates_userspace_esp_fallback() {
    let mut profile = production_ipsec_gateway_profile();
    profile.environment = Environment::Lab;
    profile.ipsec.as_mut().unwrap().allow_userspace_esp_fallback = true;
    let mut node = capable_node();
    node.ipsec.esp_supported = false;
    let cpu_layout = standard_cpu_layout();
    let interfaces = vec!["ens5f0".to_string()];
    let ctx = make_context(&node, &cpu_layout, &interfaces, Some(0));

    let report = validate_resource_profile(&profile, &ctx);

    assert!(report.is_eligible(), "{report:#?}");
    assert!(report.fallback_status.active);
    assert!(report
        .fallback_status
        .modes
        .contains(&FallbackMode::UserspaceEsp));
}

#[test]
fn ipsec_lab_missing_udp_500_bind_activates_software_packet_fallback() {
    let mut profile = production_ipsec_gateway_profile();
    profile.environment = Environment::Lab;
    profile.lab_fallback.allow_software_packet_path = true;
    let mut node = capable_node();
    node.ipsec.udp_500_bind_allowed = false;
    let cpu_layout = standard_cpu_layout();
    let interfaces = vec!["ens5f0".to_string()];
    let ctx = make_context(&node, &cpu_layout, &interfaces, Some(0));

    let report = validate_resource_profile(&profile, &ctx);

    assert!(report.is_eligible(), "{report:#?}");
    assert!(report.fallback_status.active);
    assert!(report
        .fallback_status
        .modes
        .contains(&FallbackMode::SoftwarePacketPath));
}

#[test]
fn ipsec_lab_missing_udp_4500_bind_activates_software_packet_fallback() {
    let mut profile = production_ipsec_gateway_profile();
    profile.environment = Environment::Lab;
    profile.lab_fallback.allow_software_packet_path = true;
    let mut node = capable_node();
    node.ipsec.udp_4500_bind_allowed = false;
    let cpu_layout = standard_cpu_layout();
    let interfaces = vec!["ens5f0".to_string()];
    let ctx = make_context(&node, &cpu_layout, &interfaces, Some(0));

    let report = validate_resource_profile(&profile, &ctx);

    assert!(report.is_eligible(), "{report:#?}");
    assert!(report.fallback_status.active);
    assert!(report
        .fallback_status
        .modes
        .contains(&FallbackMode::SoftwarePacketPath));
}

#[test]
fn ipsec_lab_missing_sctp_activates_software_packet_fallback() {
    let mut profile = production_ipsec_gateway_profile();
    profile.environment = Environment::Lab;
    profile.lab_fallback.allow_software_packet_path = true;
    let mut node = capable_node();
    node.ipsec.sctp_supported = false;
    let cpu_layout = standard_cpu_layout();
    let interfaces = vec!["ens5f0".to_string()];
    let ctx = make_context(&node, &cpu_layout, &interfaces, Some(0));

    let report = validate_resource_profile(&profile, &ctx);

    assert!(report.is_eligible(), "{report:#?}");
    assert!(report.fallback_status.active);
    assert!(report
        .fallback_status
        .modes
        .contains(&FallbackMode::SoftwarePacketPath));
}

#[test]
fn ipsec_lab_unsupported_kernel_activates_software_packet_fallback() {
    let mut profile = production_ipsec_gateway_profile();
    profile.environment = Environment::Lab;
    profile.lab_fallback.allow_software_packet_path = true;
    let mut node = capable_node();
    node.kernel = KernelVersion::new(5, 10, 0);
    let cpu_layout = standard_cpu_layout();
    let interfaces = vec!["ens5f0".to_string()];
    let ctx = make_context(&node, &cpu_layout, &interfaces, Some(0));

    let report = validate_resource_profile(&profile, &ctx);

    assert!(report.is_eligible(), "{report:#?}");
    assert!(report.fallback_status.active);
    assert!(report
        .fallback_status
        .modes
        .contains(&FallbackMode::SoftwarePacketPath));
}

#[test]
fn ipsec_no_data_plane_interfaces_is_rejected() {
    let profile = production_ipsec_gateway_profile();
    let node = capable_node();
    let cpu_layout = standard_cpu_layout();
    let ctx = make_context(&node, &cpu_layout, &[], Some(0));

    let report = validate_resource_profile(&profile, &ctx);

    assert!(!report.is_eligible());
    assert!(report
        .errors
        .contains(&ValidationError::IpsecNoDataPlaneInterfaces));
}

#[test]
fn ipsec_profile_missing_is_rejected() {
    let mut profile = production_ipsec_gateway_profile();
    profile.ipsec = None;
    let node = capable_node();
    let cpu_layout = standard_cpu_layout();
    let interfaces = vec!["ens5f0".to_string()];
    let ctx = make_context(&node, &cpu_layout, &interfaces, Some(0));

    let report = validate_resource_profile(&profile, &ctx);

    assert!(!report.is_eligible());
    assert!(report
        .errors
        .contains(&ValidationError::IpsecProfileMissing));
}

#[test]
fn ipsec_missing_required_kernel_module_is_rejected() {
    let profile = production_ipsec_gateway_profile();
    let mut node = capable_node();
    node.ipsec.available_kernel_modules = BTreeSet::new();
    let cpu_layout = standard_cpu_layout();
    let interfaces = vec!["ens5f0".to_string()];
    let ctx = make_context(&node, &cpu_layout, &interfaces, Some(0));

    let report = validate_resource_profile(&profile, &ctx);

    assert!(!report.is_eligible());
    assert!(report
        .errors
        .contains(&ValidationError::MissingNodeCapability {
            capability: "kernel_module:xfrm_user".to_string(),
        }));
}

#[test]
fn ipsec_missing_required_esp_algorithm_is_rejected() {
    let profile = production_ipsec_gateway_profile();
    let mut node = capable_node();
    node.ipsec.supported_esp_algorithms = BTreeSet::new();
    let cpu_layout = standard_cpu_layout();
    let interfaces = vec!["ens5f0".to_string()];
    let ctx = make_context(&node, &cpu_layout, &interfaces, Some(0));

    let report = validate_resource_profile(&profile, &ctx);

    assert!(!report.is_eligible());
    assert!(report
        .errors
        .contains(&ValidationError::MissingNodeCapability {
            capability: "esp_algorithm:aes-cbc".to_string(),
        }));
}

#[test]
fn ipsec_empty_network_attachments_is_rejected() {
    let mut profile = production_ipsec_gateway_profile();
    profile.ipsec.as_mut().unwrap().network_attachments = vec![];
    let node = capable_node();
    let cpu_layout = standard_cpu_layout();
    let interfaces = vec!["ens5f0".to_string()];
    let ctx = make_context(&node, &cpu_layout, &interfaces, Some(0));

    let report = validate_resource_profile(&profile, &ctx);

    assert!(!report.is_eligible());
    assert!(report
        .errors
        .contains(&ValidationError::IpsecNetworkAttachmentInvalid {
            detail: "at least one IPsec network attachment is required".to_string(),
        }));
}

#[test]
fn ipsec_network_attachment_missing_plane_is_rejected() {
    let mut profile = production_ipsec_gateway_profile();
    profile.ipsec.as_mut().unwrap().network_attachments[0].plane = "   ".to_string();
    let node = capable_node();
    let cpu_layout = standard_cpu_layout();
    let interfaces = vec!["ens5f0".to_string()];
    let ctx = make_context(&node, &cpu_layout, &interfaces, Some(0));

    let report = validate_resource_profile(&profile, &ctx);

    assert!(!report.is_eligible());
    assert!(report
        .errors
        .contains(&ValidationError::IpsecNetworkAttachmentInvalid {
            detail: "plane is required for interface ens5f0".to_string(),
        }));
}

#[test]
fn ipsec_network_attachment_unknown_interface_is_rejected() {
    let mut profile = production_ipsec_gateway_profile();
    profile.ipsec.as_mut().unwrap().network_attachments[0].interface_name = "ens6f0".to_string();
    let node = capable_node();
    let cpu_layout = standard_cpu_layout();
    let interfaces = vec!["ens5f0".to_string()];
    let ctx = make_context(&node, &cpu_layout, &interfaces, Some(0));

    let report = validate_resource_profile(&profile, &ctx);

    assert!(!report.is_eligible());
    assert!(report.errors.contains(&ValidationError::UnknownInterface {
        interface_name: "ens6f0".to_string(),
    }));
}

#[test]
fn ipsec_network_attachment_invalid_vlan_is_rejected() {
    let mut profile = production_ipsec_gateway_profile();
    profile.ipsec.as_mut().unwrap().network_attachments[0].vlan_id = Some(5000);
    let node = capable_node();
    let cpu_layout = standard_cpu_layout();
    let interfaces = vec!["ens5f0".to_string()];
    let ctx = make_context(&node, &cpu_layout, &interfaces, Some(0));

    let report = validate_resource_profile(&profile, &ctx);

    assert!(!report.is_eligible());
    assert!(report
        .errors
        .contains(&ValidationError::IpsecNetworkAttachmentInvalid {
            detail: "vlan_id 5000 is outside valid 1-4094 range for interface ens5f0".to_string(),
        }));
}

#[test]
fn ipsec_preflight_network_check_fails_when_profile_missing() {
    let mut profile = production_ipsec_gateway_profile();
    profile.ipsec = None;
    let node = capable_node();
    let cpu_layout = standard_cpu_layout();
    let interfaces = vec!["ens5f0".to_string()];
    let ctx = make_context(&node, &cpu_layout, &interfaces, Some(0));

    let report = run_data_plane_preflight(&profile, &ctx);

    assert!(!report.passed);
    let network_check = report
        .checks
        .iter()
        .find(|c| c.name == "Network_Attachments")
        .expect("Network_Attachments check missing");
    assert!(!network_check.passed);
}

#[test]
fn ipsec_preflight_network_check_fails_when_no_data_plane_interfaces() {
    let profile = production_ipsec_gateway_profile();
    let node = capable_node();
    let cpu_layout = standard_cpu_layout();
    let ctx = make_context(&node, &cpu_layout, &[], Some(0));

    let report = run_data_plane_preflight(&profile, &ctx);

    assert!(!report.passed);
    let network_check = report
        .checks
        .iter()
        .find(|c| c.name == "Network_Attachments")
        .expect("Network_Attachments check missing");
    assert!(!network_check.passed);
}
