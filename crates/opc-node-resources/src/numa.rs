use crate::types::*;

pub fn check_numa_node_range(
    numa: NumaNodeId,
    numa_nodes: NumaNodeId,
    report: &mut ValidationReport,
) -> bool {
    if numa >= numa_nodes {
        report.push_error(ValidationError::NumaNodeOutOfRange {
            requested: numa,
            available: numa_nodes,
        });
        false
    } else {
        true
    }
}

pub fn maybe_record_numa_mismatch(
    policy: NumaPolicy,
    component: NumaComponent,
    expected: NumaNodeId,
    observed: NumaNodeId,
    report: &mut ValidationReport,
) {
    if expected == observed {
        return;
    }

    match policy {
        NumaPolicy::Ignore => {}
        NumaPolicy::Warn => report.push_warning(ValidationWarning::NumaMismatchWarning {
            component,
            expected,
            observed,
        }),
        NumaPolicy::Require => report.push_error(ValidationError::NumaMismatchError {
            component,
            expected,
            observed,
        }),
    }
}
