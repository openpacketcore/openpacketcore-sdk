use crate::types::*;
use std::collections::BTreeSet;

pub fn validate_cpu(
    profile: &ResourceProfile,
    context: &ValidationContext<'_>,
    report: &mut ValidationReport,
) {
    let layout = context.cpu_layout;
    let mut seen = BTreeSet::new();
    let require_exclusive = profile.cpu_policy.require_exclusive_data_plane_cores;
    let has_data_plane_cores = !layout.data_plane_cores.is_empty();
    let is_lab_relaxed_cpu_pinning_allowed =
        profile.environment == Environment::Lab && profile.lab_fallback.allow_relaxed_cpu_pinning;

    // Fast-path profiles must declare at least one data-plane core — it is
    // self-contradictory to claim exclusive scheduling without naming any cores.
    let is_fast_path = matches!(
        profile.data_plane_profile,
        DataPlaneProfile::AfXdpFastPath
            | DataPlaneProfile::SriovFastPath
            | DataPlaneProfile::IpsecGateway
    );
    if (require_exclusive || is_fast_path) && !has_data_plane_cores {
        report.push_error(ValidationError::FastPathRequiresDataPlaneCores);
    }

    // RFC 011 §6 requires CPU Manager Static policy for data-plane scheduling.
    // Check this whenever exclusive cores are required, even if the core list is
    // empty.
    if (require_exclusive || is_fast_path)
        && context.node.cpu.manager_policy != CpuManagerPolicy::Static
    {
        if is_lab_relaxed_cpu_pinning_allowed {
            report.activate_fallback(
                FallbackMode::RelaxedCpuPinning,
                format!(
                    "CPU manager policy {:?} does not provide exclusive data-plane cores",
                    context.node.cpu.manager_policy
                ),
            );
        } else {
            report.push_error(ValidationError::CpuManagerPolicyIncompatible {
                required: CpuManagerPolicy::Static,
                found: context.node.cpu.manager_policy,
            });
        }
    }

    // Production mode requires topology manager policy compatibility (SingleNumaNode or Restricted)
    if profile.environment == Environment::Production
        && (require_exclusive || is_fast_path)
        && !matches!(
            context.node.cpu.topology_manager_policy,
            TopologyManagerPolicy::SingleNumaNode | TopologyManagerPolicy::Restricted
        )
    {
        report.push_error(ValidationError::TopologyManagerPolicyIncompatible {
            required: TopologyManagerPolicy::SingleNumaNode,
            found: context.node.cpu.topology_manager_policy,
        });
    }

    // Check for CPU core overlaps.
    for core in layout
        .data_plane_cores
        .iter()
        .chain(layout.control_plane_cores.iter())
        .chain(layout.management_cores.iter())
    {
        if !seen.insert(*core) {
            report.push_error(ValidationError::CpuCoreOverlap { core: *core });
        }
    }

    // Check for overlap of data-plane cores with node reserved cores.
    for core in &layout.data_plane_cores {
        if context.node.cpu.reserved_cores.contains(core) {
            report.push_error(ValidationError::CpuCoreReservedOverlap { core: *core });
        }
    }

    // Data-plane core isolation check.
    if require_exclusive && has_data_plane_cores {
        for core in &layout.data_plane_cores {
            if !context.node.cpu.isolated_cores.contains(core) {
                if is_lab_relaxed_cpu_pinning_allowed {
                    report.activate_fallback(
                        FallbackMode::RelaxedCpuPinning,
                        format!("data-plane core {core} is not isolated"),
                    );
                } else {
                    report.push_error(ValidationError::DataPlaneCoreNotIsolated { core: *core });
                }
            }
        }
    }
}
