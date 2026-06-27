use crate::bpf::{is_controlled_bpffs_path, validate_bpf_artifacts};
use crate::types::*;
use std::collections::BTreeSet;

pub fn validate_af_xdp(
    profile: &ResourceProfile,
    context: &ValidationContext<'_>,
    report: &mut ValidationReport,
) {
    let Some(af_xdp) = profile.af_xdp.as_ref() else {
        report.push_error(ValidationError::AfXdpProfileMissing);
        return;
    };

    // RFC 011 §9.1: AF_XDP requires at least one named data-plane attachment.
    if context.data_plane_interfaces.is_empty() {
        report.push_error(ValidationError::AfXdpNoDataPlaneInterfaces);
    }

    let allowed_capabilities = af_xdp_allowed_capabilities();
    for capability in &profile.pod_security.added_capabilities {
        if !allowed_capabilities.contains(capability) {
            let error = ValidationError::CapabilityNotAllowed {
                capability: capability.clone(),
                profile: DataPlaneProfile::AfXdpFastPath,
            };
            if !report.errors.contains(&error) {
                report.push_error(error);
            }
        }
    }

    for capability in &af_xdp.required_capabilities {
        if capability == &LinuxCapability::CapSysAdmin
            && profile.environment == Environment::Production
        {
            // Deduplicate: also emitted by validate_pod_security if CapSysAdmin
            // is in added_capabilities.
            if !report
                .errors
                .contains(&ValidationError::ProductionCapSysAdminForbidden)
            {
                report.push_error(ValidationError::ProductionCapSysAdminForbidden);
            }
        }
        if !allowed_capabilities.contains(capability) {
            let error = ValidationError::CapabilityNotAllowed {
                capability: capability.clone(),
                profile: DataPlaneProfile::AfXdpFastPath,
            };
            if !report.errors.contains(&error) {
                report.push_error(error);
            }
        }
        if !profile.pod_security.added_capabilities.contains(capability) {
            report.push_error(ValidationError::MissingCapability {
                capability: capability.clone(),
            });
        }
    }

    for required_map in &af_xdp.required_maps {
        let trimmed = required_map.trim();
        if trimmed.is_empty() || trimmed != required_map {
            report.push_error(ValidationError::InvalidBpfMapName {
                map_name: required_map.clone(),
            });
        }
    }

    for pin_path in &af_xdp.required_pin_paths {
        let trimmed = pin_path.trim();
        let normalized = if trimmed.len() > 1 && trimmed.ends_with('/') {
            &trimmed[..trimmed.len() - 1]
        } else {
            trimmed
        };
        if trimmed.is_empty() || trimmed != pin_path || !is_controlled_bpffs_path(normalized) {
            report.push_error(ValidationError::InvalidBpfPinPath {
                path: pin_path.clone(),
            });
        }
    }

    let is_lab_software_fallback_allowed =
        profile.environment == Environment::Lab && profile.lab_fallback.allow_software_packet_path;

    // kernel version check
    if context.node.kernel < af_xdp.minimum_kernel {
        if is_lab_software_fallback_allowed {
            report.activate_fallback(
                FallbackMode::SoftwarePacketPath,
                format!(
                    "kernel {:?} is below AF_XDP minimum {:?}; using lab software packet path",
                    context.node.kernel, af_xdp.minimum_kernel,
                ),
            );
        } else {
            report.push_error(ValidationError::UnsupportedKernelVersion {
                found: context.node.kernel,
                minimum: af_xdp.minimum_kernel,
            });
        }
    }

    // CAP_BPF check
    if !context.node.bpf.cap_bpf {
        if is_lab_software_fallback_allowed {
            report.activate_fallback(
                FallbackMode::SoftwarePacketPath,
                "node lacks CAP_BPF; using lab software packet path",
            );
        } else {
            report.push_error(ValidationError::MissingNodeCapability {
                capability: "cap_bpf".to_string(),
            });
        }
    }

    // XDP supported check
    if !context.node.bpf.xdp_supported {
        if is_lab_software_fallback_allowed {
            report.activate_fallback(
                FallbackMode::SoftwarePacketPath,
                "node lacks XDP support; using lab software packet path",
            );
        } else {
            report.push_error(ValidationError::MissingNodeCapability {
                capability: "xdp_supported".to_string(),
            });
        }
    }

    // BTF check
    if af_xdp.required_btf && !context.node.bpf.btf_available {
        if is_lab_software_fallback_allowed {
            report.activate_fallback(
                FallbackMode::SoftwarePacketPath,
                "node lacks BTF; using lab software packet path",
            );
        } else {
            report.push_error(ValidationError::MissingNodeCapability {
                capability: "btf_available".to_string(),
            });
        }
    }

    // CAP_SYS_ADMIN — handled separately because it is a policy choice
    // (node-reported), not a missing kernel feature.
    if context.node.bpf.cap_sys_admin_required {
        if is_lab_software_fallback_allowed {
            report.activate_fallback(
                FallbackMode::SoftwarePacketPath,
                "node requires CAP_SYS_ADMIN for AF_XDP; using lab software packet path",
            );
        } else {
            report.push_error(ValidationError::NodeRequiresCapSysAdmin);
        }
    }

    // XDP mode check
    let available_modes = available_xdp_modes(context.node, context.data_plane_interfaces);
    if !available_modes.contains(&af_xdp.required_xdp_mode) {
        let can_use_generic_fallback = profile.environment == Environment::Lab
            && profile.lab_fallback.allow_generic_xdp
            && af_xdp.generic_xdp_fallback_allowed
            && available_modes.contains(&XdpMode::Generic);

        if can_use_generic_fallback {
            report.activate_fallback(
                FallbackMode::GenericXdp,
                "required XDP mode unavailable; using generic XDP fallback in lab mode",
            );
        } else if is_lab_software_fallback_allowed {
            report.activate_fallback(
                FallbackMode::SoftwarePacketPath,
                format!(
                    "required XDP mode {:?} unavailable and generic XDP fallback not available; using lab software packet path",
                    af_xdp.required_xdp_mode,
                ),
            );
        } else {
            report.push_error(ValidationError::XdpModeUnavailable {
                required: af_xdp.required_xdp_mode,
                available: available_modes,
            });
        }
    }

    // BPF Artifact Governance
    validate_bpf_artifacts(profile, context, af_xdp, report);
}

pub fn validate_sriov(
    profile: &ResourceProfile,
    context: &ValidationContext<'_>,
    report: &mut ValidationReport,
) {
    let Some(sriov) = profile.sriov.as_ref() else {
        report.push_error(ValidationError::SriovProfileMissing);
        return;
    };

    let is_lab_veth_fallback_allowed =
        profile.environment == Environment::Lab && profile.lab_fallback.allow_veth;

    // Always enforce the operator's SR-IOV resource allowlist first — before any
    // early-return guards — so a typo'd or disallowed resource_name is caught even
    // when the interface list is empty and lab veth fallback would otherwise apply.
    if !context
        .sriov_allowlist
        .is_allowed(&profile.nf_kind, &sriov.resource_name)
    {
        report.push_error(ValidationError::SriovResourceNotAllowlisted {
            nf_kind: profile.nf_kind.clone(),
            resource_name: sriov.resource_name.clone(),
        });
    }

    // RFC 011 §9.1: SR-IOV requires at least one named data-plane attachment.
    // This is always fatal — a veth fallback cannot substitute for missing N3/N6
    // attachment definitions (RFC 011 §9.1/§12).
    if context.data_plane_interfaces.is_empty() {
        report.push_error(ValidationError::SriovNoDataPlaneInterfaces);
    }

    for interface_name in context.data_plane_interfaces {
        let Some(nic) = context.node.nic(interface_name) else {
            if is_lab_veth_fallback_allowed {
                report.activate_fallback(
                    FallbackMode::Veth,
                    format!(
                        "SR-IOV interface {interface_name} is unavailable; using lab veth fallback"
                    ),
                );
            } else {
                report.push_error(ValidationError::UnknownInterface {
                    interface_name: interface_name.clone(),
                });
            }
            continue;
        };

        // RFC 011 §9.2: an SR-IOV profile requires a NIC that exposes at least one VF.
        if nic.sriov_vfs == 0 {
            if is_lab_veth_fallback_allowed {
                report.activate_fallback(
                    FallbackMode::Veth,
                    format!(
                        "SR-IOV interface {interface_name} exposes zero VFs; using lab veth fallback"
                    ),
                );
            } else {
                report.push_error(ValidationError::SriovNicZeroVfs {
                    interface_name: interface_name.clone(),
                });
            }
        }

        if !sriov.allowed_device_drivers.is_empty()
            && !sriov.allowed_device_drivers.contains(&nic.driver)
        {
            if is_lab_veth_fallback_allowed {
                report.activate_fallback(
                    FallbackMode::Veth,
                    format!(
                        "SR-IOV interface {interface_name} uses unsupported driver {:?}; using lab veth fallback",
                        nic.driver
                    ),
                );
            } else {
                report.push_error(ValidationError::UnsupportedSriovDriver {
                    interface_name: interface_name.clone(),
                    driver: nic.driver.clone(),
                });
            }
        }
    }
}

pub fn af_xdp_allowed_capabilities() -> BTreeSet<LinuxCapability> {
    BTreeSet::from([
        LinuxCapability::CapBpf,
        LinuxCapability::CapNetAdmin,
        LinuxCapability::CapNetRaw,
    ])
}

pub fn ipsec_gateway_allowed_capabilities() -> BTreeSet<LinuxCapability> {
    BTreeSet::from([LinuxCapability::CapNetAdmin, LinuxCapability::CapNetRaw])
}

pub fn validate_ipsec_gateway(
    profile: &ResourceProfile,
    context: &ValidationContext<'_>,
    report: &mut ValidationReport,
) {
    let Some(ipsec) = profile.ipsec.as_ref() else {
        report.push_error(ValidationError::IpsecProfileMissing);
        return;
    };

    // RFC 011 §9.1: IPsec gateway requires at least one named data-plane attachment.
    if context.data_plane_interfaces.is_empty() {
        report.push_error(ValidationError::IpsecNoDataPlaneInterfaces);
    }

    let allowed_capabilities = ipsec_gateway_allowed_capabilities();
    for capability in &profile.pod_security.added_capabilities {
        if !allowed_capabilities.contains(capability) {
            let error = ValidationError::CapabilityNotAllowed {
                capability: capability.clone(),
                profile: DataPlaneProfile::IpsecGateway,
            };
            if !report.errors.contains(&error) {
                report.push_error(error);
            }
        }
    }

    for capability in &ipsec.required_capabilities {
        if capability == &LinuxCapability::CapSysAdmin
            && profile.environment == Environment::Production
            && !report
                .errors
                .contains(&ValidationError::ProductionCapSysAdminForbidden)
        {
            report.push_error(ValidationError::ProductionCapSysAdminForbidden);
        }
        if !allowed_capabilities.contains(capability) {
            let error = ValidationError::CapabilityNotAllowed {
                capability: capability.clone(),
                profile: DataPlaneProfile::IpsecGateway,
            };
            if !report.errors.contains(&error) {
                report.push_error(error);
            }
        }
        if !profile.pod_security.added_capabilities.contains(capability) {
            report.push_error(ValidationError::MissingCapability {
                capability: capability.clone(),
            });
        }
    }

    let is_lab_software_fallback_allowed =
        profile.environment == Environment::Lab && profile.lab_fallback.allow_software_packet_path;

    // Kernel version check
    if context.node.kernel < ipsec.minimum_kernel {
        if is_lab_software_fallback_allowed {
            report.activate_fallback(
                FallbackMode::SoftwarePacketPath,
                format!(
                    "kernel {:?} is below IPsec gateway minimum {:?}; using lab software packet path",
                    context.node.kernel, ipsec.minimum_kernel,
                ),
            );
        } else {
            report.push_error(ValidationError::UnsupportedKernelVersion {
                found: context.node.kernel,
                minimum: ipsec.minimum_kernel,
            });
        }
    }

    // XFRM support check
    if ipsec.require_xfrm && !context.node.ipsec.xfrm_supported {
        if is_lab_software_fallback_allowed {
            report.activate_fallback(
                FallbackMode::SoftwarePacketPath,
                "node lacks XFRM support; using lab software packet path",
            );
        } else {
            report.push_error(ValidationError::MissingNodeCapability {
                capability: "xfrm_supported".to_string(),
            });
        }
    }

    // UDP 500/4500 encapsulation check
    if ipsec.require_udp_encap && !context.node.ipsec.udp_encap_supported {
        if is_lab_software_fallback_allowed {
            report.activate_fallback(
                FallbackMode::SoftwarePacketPath,
                "node lacks UDP 500/4500 encapsulation support; using lab software packet path",
            );
        } else {
            report.push_error(ValidationError::MissingNodeCapability {
                capability: "udp_encap_supported".to_string(),
            });
        }
    }

    // SCTP support check
    if ipsec.require_sctp && !context.node.ipsec.sctp_supported {
        if is_lab_software_fallback_allowed {
            report.activate_fallback(
                FallbackMode::SoftwarePacketPath,
                "node lacks SCTP support; using lab software packet path",
            );
        } else {
            report.push_error(ValidationError::MissingNodeCapability {
                capability: "sctp_supported".to_string(),
            });
        }
    }
}

pub fn available_xdp_modes(
    node: &NodeCapabilityReport,
    interfaces: &[String],
) -> BTreeSet<XdpMode> {
    if interfaces.is_empty() {
        // No interfaces specified: return the union of BPF-level and all NIC modes.
        let mut modes = node.bpf.available_xdp_modes.clone();
        for nic in &node.nics {
            modes.extend(nic.xdp_modes.iter().copied());
        }
        return modes;
    }

    // Interfaces specified: compute the intersection of all named NICs' modes,
    // then intersect that with the BPF subsystem's available modes.
    // A mode must be supported by every named NIC AND by the BPF subsystem.
    // Unknown interfaces are skipped to prevent returning empty immediately.
    let mut nics = interfaces.iter().filter_map(|name| node.nic(name));
    let Some(first_nic) = nics.next() else {
        return node.bpf.available_xdp_modes.clone();
    };

    let mut modes = first_nic.xdp_modes.clone();

    for nic in nics {
        modes = modes
            .intersection(&nic.xdp_modes)
            .copied()
            .collect::<BTreeSet<_>>();
    }

    // Intersect with BPF subsystem modes.
    modes = modes
        .intersection(&node.bpf.available_xdp_modes)
        .copied()
        .collect();

    modes
}
