//! Global alarm observability hooks (RFC 013 §16), recorded into the shared
//! `opc_redaction::metrics::METRICS` registry: the active-alarm gauge keyed
//! by `(severity, probable cause)` — rebuilt from the active set after every
//! manager mutation — and the audit success/failure counters incremented on
//! the policy-protected admin paths.

use crate::model::Alarm;
use std::sync::atomic::Ordering;

pub(crate) fn update_global_metrics(active_alarms: &[Alarm]) {
    if let Ok(mut count_map) = opc_redaction::metrics::METRICS.alarm_active_count.lock() {
        count_map.clear();
        for alarm in active_alarms {
            let sev_str = alarm.severity.to_string();
            let cause_str = alarm.probable_cause.to_string();
            let entry = count_map.entry((sev_str, cause_str)).or_insert(0);
            *entry += 1;
        }
    }
}

pub(crate) fn record_audit_success() {
    opc_redaction::metrics::METRICS
        .alarm_audit_success
        .fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn record_audit_failure() {
    opc_redaction::metrics::METRICS
        .alarm_audit_failure
        .fetch_add(1, Ordering::Relaxed);
}
