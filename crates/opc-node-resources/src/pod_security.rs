use crate::types::*;

pub fn validate_pod_security(profile: &ResourceProfile, report: &mut ValidationReport) {
    let pod_security = &profile.pod_security;

    if !pod_security.run_as_non_root {
        report.push_error(ValidationError::BaselinePodSecurityViolated {
            field: "run_as_non_root".to_string(),
        });
    }
    if !pod_security.read_only_root_filesystem {
        report.push_error(ValidationError::BaselinePodSecurityViolated {
            field: "read_only_root_filesystem".to_string(),
        });
    }
    if pod_security.allow_privilege_escalation {
        report.push_error(ValidationError::BaselinePodSecurityViolated {
            field: "allow_privilege_escalation".to_string(),
        });
    }
    if !pod_security.drop_all_capabilities {
        report.push_error(ValidationError::BaselinePodSecurityViolated {
            field: "drop_all_capabilities".to_string(),
        });
    }
    if matches!(pod_security.seccomp_profile, SeccompProfile::Unconfined) {
        report.push_error(ValidationError::BaselinePodSecurityViolated {
            field: "seccomp_profile".to_string(),
        });
    }

    if profile.environment == Environment::Production {
        if pod_security
            .added_capabilities
            .contains(&LinuxCapability::CapSysAdmin)
        {
            // Deduplicate: also emitted by validate_af_xdp if CapSysAdmin is in
            // af_xdp.required_capabilities.
            if !report
                .errors
                .contains(&ValidationError::ProductionCapSysAdminForbidden)
            {
                report.push_error(ValidationError::ProductionCapSysAdminForbidden);
            }
        }

        // 1. Production must reject broad privileged mode unless explicitly required and evidence-linked
        if pod_security.privileged && pod_security.security_evidence_id.is_none() {
            report.push_error(ValidationError::SecurityPrivilegedWithoutEvidence);
        }

        // 2. Production must reject host networking when not required/evidence-linked
        if pod_security.host_network && pod_security.security_evidence_id.is_none() {
            report.push_error(ValidationError::SecurityHostNetworkWithoutEvidence);
        }

        // 3. Production must reject writable host mounts unless evidence-linked
        // 4. HostPath mounts outside approved bpffs/device/socket paths must be rejected in Production.
        for mount in &pod_security.host_path_mounts {
            if !mount.read_only && pod_security.security_evidence_id.is_none() {
                report.push_error(ValidationError::SecurityWritableHostMountWithoutEvidence {
                    host_path: mount.host_path.clone(),
                });
            }

            let path = &mount.host_path;
            let approved = path.starts_with("/sys/fs/bpf")
                || path.starts_with("/dev/vfio")
                || path.starts_with("/var/run");
            if !approved {
                report.push_error(ValidationError::SecurityHostPathMountUnapproved {
                    host_path: path.clone(),
                });
            }
        }

        // 5. Production mode must reject lab fallback paths configured in the profile
        let fallback = &profile.lab_fallback;
        if fallback.allow_veth
            || fallback.allow_generic_xdp
            || fallback.allow_software_packet_path
            || fallback.allow_relaxed_cpu_pinning
            || fallback.allow_no_hugepages
        {
            report.push_error(ValidationError::ProductionLabFallbackForbidden);
        }
    }
}
