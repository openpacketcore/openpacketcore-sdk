use crate::network::{validate_af_xdp, validate_ipsec_gateway, validate_sriov};
use crate::pod_security::validate_pod_security;
use crate::types::*;

pub fn validate_resource_profile(
    profile: &ResourceProfile,
    context: &ValidationContext<'_>,
) -> ValidationReport {
    let mut report = ValidationReport::default();

    validate_pod_security(profile, &mut report);
    validate_cpu_layout(profile, context, &mut report);

    match profile.data_plane_profile {
        DataPlaneProfile::AfXdpFastPath => validate_af_xdp(profile, context, &mut report),
        DataPlaneProfile::SriovFastPath => validate_sriov(profile, context, &mut report),
        DataPlaneProfile::IpsecGateway => validate_ipsec_gateway(profile, context, &mut report),
        DataPlaneProfile::ControlPlaneOnly
        | DataPlaneProfile::SignalingHeavy
        | DataPlaneProfile::KernelNetworking => {}
    }

    report
}

pub fn run_data_plane_preflight(
    profile: &ResourceProfile,
    context: &ValidationContext<'_>,
) -> DataPlanePreflightReport {
    let report = validate_resource_profile(profile, context);

    let mut checks = Vec::new();
    let mut messages = Vec::new();
    let mut evidence_ids = Vec::new();

    // Check 1: CPU, NUMA & Topology Manager policy
    let cpu_passed = report.errors.iter().all(|e| {
        !matches!(
            e,
            ValidationError::FastPathRequiresDataPlaneCores
                | ValidationError::CpuManagerPolicyIncompatible { .. }
                | ValidationError::TopologyManagerPolicyIncompatible { .. }
                | ValidationError::CpuCoreOverlap { .. }
                | ValidationError::CpuCoreReservedOverlap { .. }
                | ValidationError::DataPlaneCoreNotIsolated { .. }
                | ValidationError::NumaMismatchError { .. }
                | ValidationError::NumaNodeOutOfRange { .. }
                | ValidationError::MissingNumaNode
        )
    });
    checks.push(PreflightCheckResult {
        name: "CPU_NUMA_Topology".to_string(),
        passed: cpu_passed,
        message: if cpu_passed {
            "CPU, NUMA, and isolation topologies meet requirements.".to_string()
        } else {
            "CPU manager, topology policy, or isolated core selection is incompatible.".to_string()
        },
    });

    // Check 2: Hugepage pools by size and NUMA node
    let is_fast_path = matches!(
        profile.data_plane_profile,
        DataPlaneProfile::AfXdpFastPath
            | DataPlaneProfile::SriovFastPath
            | DataPlaneProfile::IpsecGateway
    );
    let mut hugepages_passed = true;
    if is_fast_path {
        if let Some(expected_numa) = context.cpu_layout.numa_node {
            let pool_found = context.node.memory.hugepage_pools.iter().any(|pool| {
                pool.numa_node == expected_numa
                    && (pool.size == "2Mi" || pool.size == "1Gi")
                    && pool.free > 0
            });
            if !pool_found {
                hugepages_passed = false;
            }
        } else if context.node.cpu.numa_nodes > 1 {
            hugepages_passed = false;
        }
    }
    let hp_passed = if profile.environment == Environment::Production {
        hugepages_passed
            && !report.errors.iter().any(|e| {
                matches!(
                    e,
                    ValidationError::MissingHugepageNumaNode
                        | ValidationError::HugepagesMissingOrWrongNuma { .. }
                )
            })
    } else {
        true
    };
    checks.push(PreflightCheckResult {
        name: "Hugepage_Pools".to_string(),
        passed: hp_passed,
        message: if hp_passed {
            "Required hugepage pools exist on the target NUMA nodes.".to_string()
        } else {
            "Missing hugepages or incorrect NUMA affinity for fast path.".to_string()
        },
    });

    // Check 3: Network interface / attachment checks
    let net_passed = report.errors.iter().all(|e| {
        !matches!(
            e,
            ValidationError::UnknownInterface { .. }
                | ValidationError::SriovNicZeroVfs { .. }
                | ValidationError::UnsupportedSriovDriver { .. }
                | ValidationError::SriovNoDataPlaneInterfaces
                | ValidationError::IpsecGatewayNoDataPlaneInterfaces
                | ValidationError::AfXdpNoDataPlaneInterfaces
                | ValidationError::IpsecNetworkAttachmentInvalid { .. }
        )
    });
    checks.push(PreflightCheckResult {
        name: "Network_Attachments".to_string(),
        passed: net_passed,
        message: if net_passed {
            "Network interfaces and driver requirements match specifications.".to_string()
        } else {
            "Network interface attachment or driver mismatch.".to_string()
        },
    });

    // Check 4: eBPF Governance
    let bpf_passed = report.errors.iter().all(|e| {
        !matches!(
            e,
            ValidationError::InvalidBpfMapName { .. }
                | ValidationError::InvalidBpfPinPath { .. }
                | ValidationError::XdpModeUnavailable { .. }
                | ValidationError::BpfArtifactMissing
                | ValidationError::BpfUnsignedArtifact { .. }
                | ValidationError::BpfMissingDigest { .. }
                | ValidationError::BpfWrongAttachPoint { .. }
                | ValidationError::BpfWrongSigner { .. }
                | ValidationError::BpfWrongProgramType { .. }
                | ValidationError::BpfCapabilityEscalation { .. }
        )
    });
    checks.push(PreflightCheckResult {
        name: "BPF_Governance".to_string(),
        passed: bpf_passed,
        message: if bpf_passed {
            "BPF programs are digest-pinned, signed, and capability-bounded.".to_string()
        } else {
            "BPF program validation failed: unsigned, bad digest, or cap escalation.".to_string()
        },
    });

    // Check 5: XFRM/IPsec gateway capability evidence
    if profile.data_plane_profile == DataPlaneProfile::IpsecGateway {
        let ipsec_passed = report.errors.iter().all(|e| {
            !matches!(
                e,
                ValidationError::IpsecGatewayProfileMissing
                    | ValidationError::IpsecGatewayCapabilitiesMissing
                    | ValidationError::MissingIpsecGatewayFeature { .. }
            )
        });
        checks.push(PreflightCheckResult {
            name: "XFRM_IPsec_Gateway".to_string(),
            passed: ipsec_passed,
            message: if ipsec_passed {
                "XFRM/IPsec gateway kernel, namespace, and route/rule prerequisites are evidenced."
                    .to_string()
            } else {
                "XFRM/IPsec gateway capability evidence is missing or incomplete.".to_string()
            },
        });
    }

    // Check 6: Pod Security exceptions
    let sec_passed = report.errors.iter().all(|e| {
        !matches!(
            e,
            ValidationError::BaselinePodSecurityViolated { .. }
                | ValidationError::ProductionCapSysAdminForbidden
                | ValidationError::CapabilityNotAllowed { .. }
                | ValidationError::MissingCapability { .. }
                | ValidationError::SecurityPrivilegedWithoutEvidence
                | ValidationError::SecurityWritableHostMountWithoutEvidence { .. }
                | ValidationError::SecurityHostNetworkWithoutEvidence
                | ValidationError::SecurityHostPathMountUnapproved { .. }
        )
    });
    checks.push(PreflightCheckResult {
        name: "Pod_Security".to_string(),
        passed: sec_passed,
        message: if sec_passed {
            "Pod security exceptions are minimal and correctly evidence-linked.".to_string()
        } else {
            "Pod security exceptions contain disallowed or unlinked policy escapes.".to_string()
        },
    });

    // Check 6: IPsec capability and fallback policy requirements
    let ipsec_passed = if profile.data_plane_profile == DataPlaneProfile::IpsecGateway {
        report.errors.iter().all(|e| {
            !matches!(
                e,
                ValidationError::MissingNodeCapability { .. }
                    | ValidationError::ProductionLabFallbackForbidden
                    | ValidationError::UnsupportedKernelVersion { .. }
                    | ValidationError::IpsecGatewayProfileMissing
                    | ValidationError::InvalidKernelModuleId { .. }
                    | ValidationError::InvalidEspAlgorithmId { .. }
            )
        })
    } else {
        true
    };
    checks.push(PreflightCheckResult {
        name: "IPsec_Capabilities".to_string(),
        passed: ipsec_passed,
        message: if ipsec_passed {
            "IPsec kernel capabilities and fallback policy meet requirements.".to_string()
        } else {
            "IPsec kernel capability or fallback policy requirement is unmet.".to_string()
        },
    });

    // Collect redaction-safe messages
    for err in &report.errors {
        messages.push(format!("{err}"));
    }
    for warning in &report.warnings {
        messages.push(format!("{warning}"));
    }

    // Evidence IDs
    if let Some(ref ev) = profile.pod_security.security_evidence_id {
        evidence_ids.push(ev.clone());
    }
    if let Some(ref af) = profile.af_xdp {
        for art in &af.bpf_artifacts {
            if let Some(ref ev) = art.evidence_id {
                evidence_ids.push(ev.clone());
            }
        }
    }
    if profile.data_plane_profile == DataPlaneProfile::IpsecGateway {
        if let Some(ref ipsec) = profile.ipsec_gateway {
            if let Some(ref ev) = ipsec.evidence_id {
                evidence_ids.push(ev.clone());
            }
        }
        if let Some(ref ipsec) = context.node.ipsec_gateway {
            if let Some(ref ev) = ipsec.evidence_id {
                evidence_ids.push(ev.clone());
            }
        }
    }

    let overall_passed = report.is_eligible() && hp_passed;

    DataPlanePreflightReport {
        passed: overall_passed,
        blocks_readiness: !overall_passed,
        messages,
        evidence_ids,
        lab_fallback_active: report.fallback_status.active,
        checks,
    }
}

fn validate_cpu_layout(
    profile: &ResourceProfile,
    context: &ValidationContext<'_>,
    report: &mut ValidationReport,
) {
    // 1. CPU validation
    crate::cpu::validate_cpu(profile, context, report);

    // 2. Validate NUMA node range
    let layout = context.cpu_layout;
    let numa_node_valid = if let Some(numa) = layout.numa_node {
        crate::numa::check_numa_node_range(numa, context.node.cpu.numa_nodes, report)
    } else {
        true
    };

    let is_fast_path = matches!(
        profile.data_plane_profile,
        DataPlaneProfile::AfXdpFastPath
            | DataPlaneProfile::SriovFastPath
            | DataPlaneProfile::IpsecGateway
    );

    // 3. Verify that all declared data-plane interfaces exist on the node.
    if profile.data_plane_profile != DataPlaneProfile::SriovFastPath {
        for interface_name in context.data_plane_interfaces {
            if context.node.nic(interface_name).is_none() {
                report.push_error(ValidationError::UnknownInterface {
                    interface_name: interface_name.clone(),
                });
            }
        }
    }

    if !numa_node_valid {
        return;
    }

    let Some(expected_numa) = layout.numa_node else {
        if is_fast_path && context.node.cpu.numa_nodes > 1 {
            report.push_error(ValidationError::MissingNumaNode);
        }
        return;
    };

    // 4. Check huge-page NUMA affinity
    crate::hugepages::validate_hugepage_numa_affinity(
        profile,
        context,
        expected_numa,
        is_fast_path,
        report,
    );

    // 5. Check each data-plane interface NUMA affinity
    for interface_name in context.data_plane_interfaces {
        if let Some(nic) = context.node.nic(interface_name) {
            if let Some(observed) = nic.numa_node {
                crate::numa::maybe_record_numa_mismatch(
                    profile.cpu_policy.numa_locality,
                    NumaComponent::Interface(interface_name.clone()),
                    expected_numa,
                    observed,
                    report,
                );
            }
        }
    }
}
