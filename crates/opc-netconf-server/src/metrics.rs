//! NETCONF metrics recorders backed by the shared SDK registry.

use std::time::Duration;

use opc_mgmt_errors::NetconfErrorTag;
use opc_redaction::metrics::{metrics_label_safe, LatencyHistogram, METRICS};

/// Low-cardinality NETCONF operation labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NetconfOperation {
    /// `<edit-config>`.
    EditConfig,
    /// `<commit>`.
    Commit,
    /// `<cancel-commit>`.
    CancelCommit,
    /// `<discard-changes>`.
    DiscardChanges,
    /// `<copy-config>`.
    CopyConfig,
    /// `<delete-config>`.
    DeleteConfig,
    /// `<close-session>`.
    CloseSession,
    /// `<lock>`.
    Lock,
    /// `<unlock>`.
    Unlock,
    /// `<kill-session>`.
    KillSession,
    /// `<validate>`.
    Validate,
    /// `<get>`.
    Get,
    /// `<get-config>`.
    GetConfig,
    /// RFC 6022 `<get-schema>`.
    GetSchema,
    /// RFC 5277 `<create-subscription>`.
    CreateSubscription,
    /// A known operation parsed only to reject as unsupported.
    Unsupported(&'static str),
    /// Operation was not known because envelope parsing failed.
    Unknown,
}

impl NetconfOperation {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::EditConfig => "edit-config",
            Self::Commit => "commit",
            Self::CancelCommit => "cancel-commit",
            Self::DiscardChanges => "discard-changes",
            Self::CopyConfig => "copy-config",
            Self::DeleteConfig => "delete-config",
            Self::CloseSession => "close-session",
            Self::Lock => "lock",
            Self::Unlock => "unlock",
            Self::KillSession => "kill-session",
            Self::Validate => "validate",
            Self::Get => "get",
            Self::GetConfig => "get-config",
            Self::GetSchema => "get-schema",
            Self::CreateSubscription => "create-subscription",
            Self::Unsupported(operation) => operation,
            Self::Unknown => "unknown",
        }
    }
}

/// Low-cardinality notification delivery outcomes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NetconfNotificationOutcome {
    /// Notification frame was written to the session.
    Success,
    /// Notification could not be rendered or delivered.
    Failure,
}

impl NetconfNotificationOutcome {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Success => OUTCOME_SUCCESS,
            Self::Failure => OUTCOME_FAILURE,
        }
    }
}

/// NETCONF read-side NACM action labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NetconfNacmAction {
    /// Read authorization.
    Read,
}

impl NetconfNacmAction {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
        }
    }
}

/// Listener transport label for NETCONF over TLS.
pub(crate) const TRANSPORT_NETCONF_TLS: &str = "netconf-tls";
/// Listener transport label for NETCONF over SSH.
pub(crate) const TRANSPORT_NETCONF_SSH: &str = "netconf-ssh";

const OUTCOME_SUCCESS: &str = "success";
const OUTCOME_FAILURE: &str = "failure";

/// Records a successful NETCONF RPC.
pub(crate) fn record_rpc_success(operation: NetconfOperation, elapsed: Duration) {
    increment_rpc_request(operation, OUTCOME_SUCCESS);
    observe_rpc_latency(operation, elapsed);
}

/// Records a failed NETCONF RPC.
pub(crate) fn record_rpc_error(
    operation: NetconfOperation,
    error_tag: NetconfErrorTag,
    elapsed: Duration,
) {
    increment_rpc_request(operation, OUTCOME_FAILURE);
    increment_rpc_error(operation, error_tag);
    observe_rpc_latency(operation, elapsed);
}

/// Records read NACM denials filtered from a NETCONF response.
pub(crate) fn record_nacm_denials(action: NetconfNacmAction, count: usize) {
    if count == 0 {
        return;
    }
    if let Ok(mut map) = METRICS.netconf_nacm_denials_total.lock() {
        let entry = map.entry(safe_label(action.as_str())).or_insert(0);
        *entry = entry.saturating_add(count.try_into().unwrap_or(u64::MAX));
    }
}

/// Records a NETCONF notification delivery outcome.
pub(crate) fn record_notification(stream: &str, outcome: NetconfNotificationOutcome) {
    if let Ok(mut map) = METRICS.netconf_notifications_total.lock() {
        let entry = map
            .entry((safe_label(stream), safe_label(outcome.as_str())))
            .or_insert(0);
        *entry = entry.saturating_add(1);
    }
}

/// Increments the active-session gauge and returns a guard that decrements it.
pub(crate) fn active_session(transport: &'static str) -> ActiveSessionGuard {
    adjust_active_sessions(transport, 1);
    ActiveSessionGuard { transport }
}

/// Drop guard for `opc_netconf_sessions_active`.
#[derive(Debug)]
pub(crate) struct ActiveSessionGuard {
    transport: &'static str,
}

impl Drop for ActiveSessionGuard {
    fn drop(&mut self) {
        adjust_active_sessions(self.transport, -1);
    }
}

fn increment_rpc_request(operation: NetconfOperation, outcome: &'static str) {
    if let Ok(mut map) = METRICS.netconf_rpc_requests_total.lock() {
        let entry = map
            .entry((safe_label(operation.as_str()), safe_label(outcome)))
            .or_insert(0);
        *entry = entry.saturating_add(1);
    }
}

fn increment_rpc_error(operation: NetconfOperation, error_tag: NetconfErrorTag) {
    if let Ok(mut map) = METRICS.netconf_rpc_errors_total.lock() {
        let entry = map
            .entry((
                safe_label(operation.as_str()),
                safe_label(error_tag.as_str()),
            ))
            .or_insert(0);
        *entry = entry.saturating_add(1);
    }
}

fn observe_rpc_latency(operation: NetconfOperation, elapsed: Duration) {
    if let Ok(mut map) = METRICS.netconf_rpc_seconds.lock() {
        map.entry(safe_label(operation.as_str()))
            .or_insert_with(LatencyHistogram::new)
            .observe(elapsed.as_secs_f64());
    }
}

fn adjust_active_sessions(transport: &'static str, delta: i64) {
    if let Ok(mut map) = METRICS.netconf_sessions_active.lock() {
        let entry = map.entry(safe_label(transport)).or_insert(0);
        if delta >= 0 {
            *entry = entry.saturating_add(delta);
        } else {
            *entry = entry.saturating_sub(delta.saturating_abs());
        }
    }
}

fn safe_label(label: &str) -> String {
    metrics_label_safe(label)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use opc_mgmt_errors::NetconfErrorTag;
    use opc_redaction::metrics::{export_prometheus_text, METRICS};

    use super::*;

    #[test]
    fn records_rpc_metrics_with_stable_sanitized_labels() {
        let before = rpc_request_count(NetconfOperation::Get, OUTCOME_SUCCESS);
        record_rpc_success(NetconfOperation::Get, Duration::from_millis(1));
        assert!(rpc_request_count(NetconfOperation::Get, OUTCOME_SUCCESS) > before);

        let before = rpc_request_count(NetconfOperation::CloseSession, OUTCOME_SUCCESS);
        record_rpc_success(NetconfOperation::CloseSession, Duration::from_millis(1));
        assert!(rpc_request_count(NetconfOperation::CloseSession, OUTCOME_SUCCESS) > before);

        let before = rpc_request_count(NetconfOperation::GetConfig, OUTCOME_SUCCESS);
        record_rpc_success(NetconfOperation::GetConfig, Duration::from_millis(1));
        assert!(rpc_request_count(NetconfOperation::GetConfig, OUTCOME_SUCCESS) > before);

        let before = rpc_request_count(NetconfOperation::GetSchema, OUTCOME_SUCCESS);
        record_rpc_success(NetconfOperation::GetSchema, Duration::from_millis(1));
        assert!(rpc_request_count(NetconfOperation::GetSchema, OUTCOME_SUCCESS) > before);

        let before = rpc_request_count(NetconfOperation::CreateSubscription, OUTCOME_SUCCESS);
        record_rpc_success(
            NetconfOperation::CreateSubscription,
            Duration::from_millis(1),
        );
        assert!(rpc_request_count(NetconfOperation::CreateSubscription, OUTCOME_SUCCESS) > before);

        let before = rpc_error_count(NetconfOperation::GetConfig, NetconfErrorTag::ResourceDenied);
        record_rpc_error(
            NetconfOperation::GetConfig,
            NetconfErrorTag::ResourceDenied,
            Duration::from_millis(1),
        );
        assert!(
            rpc_error_count(NetconfOperation::GetConfig, NetconfErrorTag::ResourceDenied) > before
        );

        let exported = export_prometheus_text();
        assert!(exported
            .contains("opc_netconf_rpc_requests_total{operation=\"get\",outcome=\"success\"}"));
        assert!(exported.contains(
            "opc_netconf_rpc_requests_total{operation=\"close-session\",outcome=\"success\"}"
        ));
        assert!(exported.contains(
            "opc_netconf_rpc_requests_total{operation=\"get-config\",outcome=\"success\"}"
        ));
        assert!(exported.contains(
            "opc_netconf_rpc_requests_total{operation=\"get-schema\",outcome=\"success\"}"
        ));
        assert!(exported.contains(
            "opc_netconf_rpc_requests_total{operation=\"create-subscription\",outcome=\"success\"}"
        ));
        assert!(exported.contains(
            "opc_netconf_rpc_errors_total{operation=\"get-config\",error_tag=\"resource-denied\"}"
        ));
        assert!(exported.contains("opc_netconf_rpc_seconds_bucket{operation=\"get-config\""));
    }

    #[test]
    fn records_notification_metrics() {
        let before = notification_count("NETCONF", OUTCOME_SUCCESS);
        record_notification("NETCONF", NetconfNotificationOutcome::Success);
        assert!(notification_count("NETCONF", OUTCOME_SUCCESS) > before);

        let exported = export_prometheus_text();
        assert!(exported
            .contains("opc_netconf_notifications_total{stream=\"NETCONF\",outcome=\"success\"}"));
    }

    #[test]
    fn active_session_guard_balances_the_transport_gauge() {
        const TEST_TRANSPORT: &str = "netconf-test";

        let before = active_sessions(TEST_TRANSPORT);
        {
            let _guard = active_session(TEST_TRANSPORT);
            assert!(active_sessions(TEST_TRANSPORT) > before);
        }
        assert!(active_sessions(TEST_TRANSPORT) <= before);
    }

    fn rpc_request_count(operation: NetconfOperation, outcome: &'static str) -> u64 {
        METRICS
            .netconf_rpc_requests_total
            .lock()
            .ok()
            .and_then(|map| {
                map.get(&(safe_label(operation.as_str()), safe_label(outcome)))
                    .copied()
            })
            .unwrap_or(0)
    }

    fn rpc_error_count(operation: NetconfOperation, error_tag: NetconfErrorTag) -> u64 {
        METRICS
            .netconf_rpc_errors_total
            .lock()
            .ok()
            .and_then(|map| {
                map.get(&(
                    safe_label(operation.as_str()),
                    safe_label(error_tag.as_str()),
                ))
                .copied()
            })
            .unwrap_or(0)
    }

    fn active_sessions(transport: &'static str) -> i64 {
        METRICS
            .netconf_sessions_active
            .lock()
            .ok()
            .and_then(|map| map.get(&safe_label(transport)).copied())
            .unwrap_or(0)
    }

    fn notification_count(stream: &str, outcome: &'static str) -> u64 {
        METRICS
            .netconf_notifications_total
            .lock()
            .ok()
            .and_then(|map| map.get(&(safe_label(stream), safe_label(outcome))).copied())
            .unwrap_or(0)
    }
}
