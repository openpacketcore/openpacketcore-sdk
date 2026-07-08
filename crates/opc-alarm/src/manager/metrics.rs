//! Global alarm observability hooks (RFC 013 §16), recorded into the shared
//! `opc_redaction::metrics::METRICS` registry: the active-alarm gauge keyed
//! by `(severity, probable cause)` — rebuilt from the active set after every
//! manager mutation — and the audit success/failure counters incremented on
//! the policy-protected admin paths.

use crate::model::Alarm;
use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::{MutexGuard, PoisonError};

type AlarmActiveCountMap = HashMap<(String, String), i64>;

pub(crate) fn update_global_metrics(active_alarms: &[Alarm]) {
    let mut count_map = alarm_active_count_guard();
    rebuild_alarm_active_count(&mut count_map, active_alarms);
}

#[cfg(test)]
pub(crate) fn update_global_metrics_snapshot_for_test(
    active_alarms: &[Alarm],
) -> AlarmActiveCountMap {
    let mut count_map = alarm_active_count_guard();
    rebuild_alarm_active_count(&mut count_map, active_alarms);
    count_map.clone()
}

fn rebuild_alarm_active_count(count_map: &mut AlarmActiveCountMap, active_alarms: &[Alarm]) {
    count_map.clear();
    for alarm in active_alarms {
        let sev_str = alarm.severity.to_string();
        let cause_str = alarm.probable_cause.to_string();
        let entry = count_map.entry((sev_str, cause_str)).or_insert(0);
        *entry += 1;
    }
}

fn alarm_active_count_guard() -> MutexGuard<'static, AlarmActiveCountMap> {
    opc_redaction::metrics::METRICS
        .alarm_active_count
        .lock()
        .unwrap_or_else(recover_alarm_metrics_poison)
}

fn recover_alarm_metrics_poison(
    poisoned: PoisonError<MutexGuard<'static, AlarmActiveCountMap>>,
) -> MutexGuard<'static, AlarmActiveCountMap> {
    opc_redaction::metrics::METRICS
        .alarm_active_count
        .clear_poison();
    poisoned.into_inner()
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
