use std::sync::atomic::Ordering;

pub(crate) fn record_subscriber_notification_failure() {
    opc_redaction::metrics::METRICS
        .config_bus_subscriber_notification_failures
        .fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn record_recovery_fence_active(active: bool) {
    opc_redaction::metrics::METRICS
        .config_bus_recovery_fence_active
        .store(if active { 1 } else { 0 }, Ordering::Relaxed);
}

pub(crate) fn increment_pending_commits() {
    opc_redaction::metrics::METRICS
        .config_bus_pending_commits
        .fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn decrement_pending_commits() {
    opc_redaction::metrics::METRICS
        .config_bus_pending_commits
        .fetch_sub(1, Ordering::Relaxed);
}

pub(crate) fn record_commit_confirmed_deadline_expiry() {
    opc_redaction::metrics::METRICS
        .config_bus_commit_confirmed_deadline_expiry
        .fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn record_rollback_failure() {
    opc_redaction::metrics::METRICS
        .config_bus_rollback_failure
        .fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn record_rollback_success() {
    opc_redaction::metrics::METRICS
        .config_bus_rollback_success
        .fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn observe_validate_latency(secs: f64) {
    opc_redaction::metrics::METRICS
        .config_bus_phase_latency_validate
        .observe(secs);
}

pub(crate) fn observe_apply_latency(secs: f64) {
    opc_redaction::metrics::METRICS
        .config_bus_phase_latency_apply
        .observe(secs);
}

pub(crate) fn observe_persist_latency(secs: f64) {
    opc_redaction::metrics::METRICS
        .config_bus_phase_latency_persist
        .observe(secs);
}

pub(crate) fn observe_notify_latency(secs: f64) {
    opc_redaction::metrics::METRICS
        .config_bus_phase_latency_notify
        .observe(secs);
}
