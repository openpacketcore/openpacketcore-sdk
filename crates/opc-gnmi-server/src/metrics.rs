//! gNMI metrics recorders backed by the shared SDK registry.

use std::time::Duration;

use opc_mgmt_errors::MgmtStatus;
use opc_redaction::metrics::{metrics_label_safe, LatencyHistogram, METRICS};

/// Low-cardinality gNMI RPC labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GnmiOperation {
    /// `Capabilities`.
    Capabilities,
    /// `Get`.
    Get,
    /// `Set`.
    Set,
    /// `Subscribe`.
    Subscribe,
}

impl GnmiOperation {
    /// Stable RPC label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Capabilities => "Capabilities",
            Self::Get => "Get",
            Self::Set => "Set",
            Self::Subscribe => "Subscribe",
        }
    }
}

/// gNMI read/write authorization action label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GnmiNacmAction {
    /// Read authorization.
    Read,
    /// Subscribe authorization.
    Subscribe,
    /// Write authorization.
    Write,
}

impl GnmiNacmAction {
    /// Stable action label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Subscribe => "subscribe",
            Self::Write => "write",
        }
    }
}

/// Listener transport label for gNMI over TLS.
pub(crate) const TRANSPORT_GNMI_TLS: &str = "gnmi-tls";

const OUTCOME_SUCCESS: &str = "success";
const OUTCOME_FAILURE: &str = "failure";

/// Records a successful gNMI RPC.
pub fn record_rpc_success(operation: GnmiOperation, elapsed: Duration) {
    increment_rpc_request(operation, OUTCOME_SUCCESS);
    observe_rpc_latency(operation, elapsed);
}

/// Records a failed gNMI RPC.
pub fn record_rpc_error(operation: GnmiOperation, status: MgmtStatus, elapsed: Duration) {
    increment_rpc_request(operation, OUTCOME_FAILURE);
    increment_rpc_error(operation, status);
    observe_rpc_latency(operation, elapsed);
}

/// Records gNMI Set commit latency.
pub fn record_set_commit_latency(operation: SetCommitMetric, elapsed: Duration) {
    if let Ok(mut map) = METRICS.gnmi_set_commit_seconds.lock() {
        map.entry(safe_label(operation.as_str()))
            .or_insert_with(LatencyHistogram::new)
            .observe(elapsed.as_secs_f64());
    }
}

/// Low-cardinality Set commit shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetCommitMetric {
    /// Pure delete.
    Delete,
    /// Pure replace.
    Replace,
    /// Patch/mixed update.
    Patch,
}

impl SetCommitMetric {
    /// Stable label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Delete => "delete",
            Self::Replace => "replace",
            Self::Patch => "patch",
        }
    }
}

/// Records NACM denials filtered from gNMI handling.
pub fn record_nacm_denials(action: GnmiNacmAction, count: usize) {
    if count == 0 {
        return;
    }
    if let Ok(mut map) = METRICS.gnmi_nacm_denials_total.lock() {
        let entry = map.entry(safe_label(action.as_str())).or_insert(0);
        *entry = entry.saturating_add(count.try_into().unwrap_or(u64::MAX));
    }
}

/// Records extension validation/handling outcomes.
pub fn record_extension(extension: &str, outcome: ExtensionMetricOutcome) {
    if let Ok(mut map) = METRICS.gnmi_extensions_total.lock() {
        let entry = map
            .entry((safe_label(extension), safe_label(outcome.as_str())))
            .or_insert(0);
        *entry = entry.saturating_add(1);
    }
}

/// Records a low-cardinality gNMI listener lifecycle or pressure event.
pub(crate) fn record_listener_event(transport: &'static str, event: GnmiListenerEvent) {
    if let Ok(mut map) = METRICS.gnmi_listener_events_total.lock() {
        let entry = map
            .entry((safe_label(transport), safe_label(event.as_str())))
            .or_insert(0);
        *entry = entry.saturating_add(1);
    }
}

/// gNMI listener event labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GnmiListenerEvent {
    /// Listener task started serving.
    Start,
    /// Listener task stopped cleanly.
    Stop,
    /// Authenticated connection was accepted.
    Accepted,
    /// Connection was rejected before reading peer payload.
    Rejected,
    /// Listener, accept, TLS, or serve failure.
    Failure,
}

impl GnmiListenerEvent {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Stop => "stop",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Failure => "failure",
        }
    }
}

/// Extension metric outcome labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtensionMetricOutcome {
    /// Accepted/handled.
    Accepted,
    /// Ignored because it was unknown and non-critical.
    Ignored,
    /// Rejected because it was critical and unsupported.
    Rejected,
}

impl ExtensionMetricOutcome {
    /// Stable label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Ignored => "ignored",
            Self::Rejected => "rejected",
        }
    }
}

/// Increments active Subscribe streams and returns a guard that decrements on
/// drop.
pub fn active_stream(mode: SubscribeModeMetric) -> ActiveStreamGuard {
    adjust_active_streams(mode.as_str(), 1);
    ActiveStreamGuard { mode }
}

/// Increments the active-session gauge and returns a guard that decrements it.
pub(crate) fn active_session(transport: &'static str) -> ActiveSessionGuard {
    adjust_active_sessions(transport, 1);
    ActiveSessionGuard { transport }
}

/// Subscribe mode labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubscribeModeMetric {
    /// ONCE mode.
    Once,
    /// POLL mode.
    Poll,
    /// STREAM mode.
    Stream,
}

impl SubscribeModeMetric {
    /// Stable label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Once => "once",
            Self::Poll => "poll",
            Self::Stream => "stream",
        }
    }
}

/// Active-stream gauge guard.
#[derive(Debug)]
pub struct ActiveStreamGuard {
    mode: SubscribeModeMetric,
}

impl Drop for ActiveStreamGuard {
    fn drop(&mut self) {
        adjust_active_streams(self.mode.as_str(), -1);
    }
}

/// Active-session gauge guard.
#[derive(Debug)]
pub(crate) struct ActiveSessionGuard {
    transport: &'static str,
}

impl Drop for ActiveSessionGuard {
    fn drop(&mut self) {
        adjust_active_sessions(self.transport, -1);
    }
}

fn increment_rpc_request(operation: GnmiOperation, outcome: &'static str) {
    if let Ok(mut map) = METRICS.gnmi_rpc_requests_total.lock() {
        let entry = map
            .entry((safe_label(operation.as_str()), safe_label(outcome)))
            .or_insert(0);
        *entry = entry.saturating_add(1);
    }
}

fn increment_rpc_error(operation: GnmiOperation, status: MgmtStatus) {
    if let Ok(mut map) = METRICS.gnmi_rpc_errors_total.lock() {
        let entry = map
            .entry((safe_label(operation.as_str()), safe_label(status.as_str())))
            .or_insert(0);
        *entry = entry.saturating_add(1);
    }
}

fn observe_rpc_latency(operation: GnmiOperation, elapsed: Duration) {
    if let Ok(mut map) = METRICS.gnmi_rpc_seconds.lock() {
        map.entry(safe_label(operation.as_str()))
            .or_insert_with(LatencyHistogram::new)
            .observe(elapsed.as_secs_f64());
    }
}

fn adjust_active_streams(mode: &'static str, delta: i64) {
    if let Ok(mut map) = METRICS.gnmi_active_streams.lock() {
        let entry = map.entry(safe_label(mode)).or_insert(0);
        if delta >= 0 {
            *entry = entry.saturating_add(delta);
        } else {
            *entry = entry.saturating_sub(delta.saturating_abs());
        }
    }
}

fn adjust_active_sessions(transport: &'static str, delta: i64) {
    if let Ok(mut map) = METRICS.gnmi_sessions_active.lock() {
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
    use super::*;

    #[test]
    fn records_low_cardinality_metrics() {
        let capability_success_before = rpc_request_count(GnmiOperation::Capabilities, "success");
        let get_failure_before = rpc_request_count(GnmiOperation::Get, "failure");
        let get_error_before =
            rpc_error_count(GnmiOperation::Get, MgmtStatus::InvalidArgument.as_str());
        let read_denials_before = nacm_denial_count(GnmiNacmAction::Read);
        let active_stream_before = active_stream_count(SubscribeModeMetric::Stream);
        let active_session_before = active_session_count(TRANSPORT_GNMI_TLS);
        let listener_start_before =
            listener_event_count(TRANSPORT_GNMI_TLS, GnmiListenerEvent::Start);

        record_rpc_success(GnmiOperation::Capabilities, Duration::from_millis(10));
        record_rpc_error(
            GnmiOperation::Get,
            MgmtStatus::InvalidArgument,
            Duration::from_millis(5),
        );
        record_nacm_denials(GnmiNacmAction::Read, 2);
        record_extension("unknown", ExtensionMetricOutcome::Rejected);
        record_listener_event(TRANSPORT_GNMI_TLS, GnmiListenerEvent::Start);
        record_set_commit_latency(SetCommitMetric::Patch, Duration::from_millis(20));
        {
            let _guard = active_stream(SubscribeModeMetric::Stream);
            assert_eq!(
                active_stream_count(SubscribeModeMetric::Stream),
                active_stream_before + 1
            );
        }
        {
            let _guard = active_session(TRANSPORT_GNMI_TLS);
            assert_eq!(
                active_session_count(TRANSPORT_GNMI_TLS),
                active_session_before + 1
            );
        }

        assert!(
            rpc_request_count(GnmiOperation::Capabilities, "success") > capability_success_before
        );
        assert!(rpc_request_count(GnmiOperation::Get, "failure") > get_failure_before);
        assert!(
            rpc_error_count(GnmiOperation::Get, MgmtStatus::InvalidArgument.as_str())
                > get_error_before
        );
        assert!(nacm_denial_count(GnmiNacmAction::Read) >= read_denials_before + 2);
        assert_eq!(
            active_stream_count(SubscribeModeMetric::Stream),
            active_stream_before
        );
        assert_eq!(
            active_session_count(TRANSPORT_GNMI_TLS),
            active_session_before
        );
        assert!(
            listener_event_count(TRANSPORT_GNMI_TLS, GnmiListenerEvent::Start)
                > listener_start_before
        );
    }

    fn rpc_request_count(operation: GnmiOperation, outcome: &str) -> u64 {
        METRICS
            .gnmi_rpc_requests_total
            .lock()
            .expect("metrics")
            .get(&(operation.as_str().to_string(), outcome.to_string()))
            .copied()
            .unwrap_or_default()
    }

    fn rpc_error_count(operation: GnmiOperation, status: &str) -> u64 {
        METRICS
            .gnmi_rpc_errors_total
            .lock()
            .expect("metrics")
            .get(&(operation.as_str().to_string(), status.to_string()))
            .copied()
            .unwrap_or_default()
    }

    fn nacm_denial_count(action: GnmiNacmAction) -> u64 {
        METRICS
            .gnmi_nacm_denials_total
            .lock()
            .expect("metrics")
            .get(action.as_str())
            .copied()
            .unwrap_or_default()
    }

    fn active_stream_count(mode: SubscribeModeMetric) -> i64 {
        METRICS
            .gnmi_active_streams
            .lock()
            .expect("metrics")
            .get(mode.as_str())
            .copied()
            .unwrap_or_default()
    }

    fn active_session_count(transport: &'static str) -> i64 {
        METRICS
            .gnmi_sessions_active
            .lock()
            .expect("metrics")
            .get(transport)
            .copied()
            .unwrap_or_default()
    }

    fn listener_event_count(transport: &'static str, event: GnmiListenerEvent) -> u64 {
        METRICS
            .gnmi_listener_events_total
            .lock()
            .expect("metrics")
            .get(&(transport.to_string(), event.as_str().to_string()))
            .copied()
            .unwrap_or_default()
    }
}
