use crate::numa::maybe_record_numa_mismatch;
use crate::types::*;

pub fn validate_hugepage_numa_affinity(
    profile: &ResourceProfile,
    context: &ValidationContext<'_>,
    expected_numa: NumaNodeId,
    is_fast_path: bool,
    report: &mut ValidationReport,
) {
    if let Some(observed) = context.hugepage_numa_node {
        if observed >= context.node.cpu.numa_nodes {
            report.push_error(ValidationError::NumaNodeOutOfRange {
                requested: observed,
                available: context.node.cpu.numa_nodes,
            });
        } else {
            maybe_record_numa_mismatch(
                profile.cpu_policy.numa_locality,
                NumaComponent::Hugepages,
                expected_numa,
                observed,
                report,
            );

            // Production verification that hugepages are actually present on that NUMA node
            if profile.environment == Environment::Production && is_fast_path {
                let has_pool = context.node.memory.hugepage_pools.iter().any(|pool| {
                    pool.numa_node == observed
                        && (pool.size == "2Mi" || pool.size == "1Gi")
                        && pool.free > 0
                });
                if !has_pool {
                    report.push_error(ValidationError::HugepagesMissingOrWrongNuma {
                        numa_node: observed,
                    });
                }
            }
        }
    } else if is_fast_path && context.node.cpu.numa_nodes > 1 {
        match profile.cpu_policy.numa_locality {
            NumaPolicy::Require => report.push_error(ValidationError::MissingHugepageNumaNode),
            NumaPolicy::Warn => report.push_warning(ValidationWarning::MissingHugepageNumaNode),
            NumaPolicy::Ignore => {}
        }
    }
}
