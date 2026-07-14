use opc_redaction::metrics::{SdkMetrics, SecurityMetricsReader};
use std::sync::atomic::{AtomicI64, Ordering};

#[test]
fn sdk_metrics_remains_externally_constructible_with_struct_update() {
    let metrics = SdkMetrics {
        config_bus_pending_commits: AtomicI64::new(7),
        ..SdkMetrics::new()
    };

    assert_eq!(
        metrics.config_bus_pending_commits.load(Ordering::Relaxed),
        7
    );
}

#[test]
fn sdk_metrics_reset_preserves_process_security_observation() {
    let reader = SecurityMetricsReader::global();
    let before = reader.snapshot();

    SdkMetrics::new().reset_all();

    assert_eq!(reader.snapshot(), before);
}
