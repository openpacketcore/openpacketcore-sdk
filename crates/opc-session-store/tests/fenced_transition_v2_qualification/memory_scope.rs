//! Memory observations for the in-process SDK-741 workload.
//!
//! Each of the three voters owns replicated state in the same process as the
//! driver. An aggregate measurement cannot establish a per-voter RSS budget,
//! even when divided by the number of voters. Legacy v1 acceptance remains a
//! separate, explicitly aggregate regression profile.

use super::{QUALIFICATION_PROCESS_PEAK_RSS_CEILING_KIB, VOTERS};
use std::sync::atomic::{AtomicU64, Ordering};

pub(super) fn record_vmhwm_estimate(observed: &AtomicU64, current: u64) -> u64 {
    assert!(current > 0, "aggregate process RSS observation absent");
    observed.fetch_max(current, Ordering::Relaxed).max(current)
}

pub(super) fn aggregate_harness_memory(peak_rss_kib: u64) -> serde_json::Value {
    assert!(peak_rss_kib > 0, "aggregate process RSS observation absent");
    serde_json::json!({
        "scope": "three_in_process_voters_and_workload_driver",
        "measurement": "maximum_observed_linux_proc_self_status_vmhwm_estimate_kib",
        "voter_instances": VOTERS,
        "processes_measured": 1,
        "observed_process_vmhwm_kib": peak_rss_kib,
        "includes_workload_driver_and_fixture": true,
        "legacy_v1_aggregate_budget_kib": QUALIFICATION_PROCESS_PEAK_RSS_CEILING_KIB,
        "exceeds_legacy_v1_aggregate_budget": peak_rss_kib > QUALIFICATION_PROCESS_PEAK_RSS_CEILING_KIB,
        "per_voter_rss_kib": null,
        "deployment_memory_qualified": false,
    })
}

#[test]
fn a_later_lower_kernel_estimate_cannot_erase_an_observed_peak() {
    let observed = AtomicU64::new(0);
    assert_eq!(record_vmhwm_estimate(&observed, 2_082_624), 2_082_624);
    assert_eq!(record_vmhwm_estimate(&observed, 2_070_052), 2_082_624);
    assert_eq!(record_vmhwm_estimate(&observed, 3_704_140), 3_704_140);
    assert_eq!(record_vmhwm_estimate(&observed, 1), 3_704_140);
}

#[test]
fn aggregate_memory_above_or_below_legacy_budget_never_qualifies_a_voter() {
    for peak in [1, 2 * 1024 * 1024, 3_704_140] {
        let report = aggregate_harness_memory(peak);
        assert_eq!(report["observed_process_vmhwm_kib"], peak);
        assert_eq!(report["processes_measured"], 1);
        assert_eq!(report["voter_instances"], 3);
        assert!(report["per_voter_rss_kib"].is_null());
        assert_eq!(report["deployment_memory_qualified"], false);
        assert_eq!(
            report["exceeds_legacy_v1_aggregate_budget"],
            peak > 2 * 1024 * 1024,
        );
    }
    assert!(std::panic::catch_unwind(|| aggregate_harness_memory(0)).is_err());
}
