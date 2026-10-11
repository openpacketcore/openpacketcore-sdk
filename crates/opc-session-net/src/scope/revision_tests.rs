//! Diagnostic state is bounded and never becomes an admission latch.
use super::revision::*;
use std::time::{Duration, Instant};

#[test]
fn revision_mismatches_are_exported_with_bounded_labels_even_when_logs_are_limited() {
    const CHILD: &str = "OPC_SCOPE_REVISION_METRICS_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "scope::revision_tests::revision_mismatches_are_exported_with_bounded_labels_even_when_logs_are_limited", "--nocapture"])
            .env(CHILD, "1")
            .output().unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
        return;
    }
    for _ in 0..2 {
        assert!(matches!(
            rpc_handshake_error(
                WORKER_RESPONSE,
                opc_tls::ScopeTlsError::TransportRevisionMismatch,
                super::ScopeRpcError::Retry
            ),
            super::ScopeRpcError::TransportRevisionMismatch
        ));
    }
    let observer = DiagnosticContext::new(
        ScopeTransportRole::Observer,
        ScopeTransportPurpose::ScopeResponse,
        ScopeTransportDirection::Inbound,
    );
    assert!(matches!(
        rpc_handshake_error(
            observer,
            opc_tls::ScopeTlsError::TransportRevisionMismatch,
            super::ScopeRpcError::Retry
        ),
        super::ScopeRpcError::TransportRevisionMismatch
    ));
    assert_eq!(
        signal(
            ScopeTransportRole::Worker,
            ScopeTransportPurpose::Handshake,
            ScopeTransportDirection::Outbound
        ),
        (2, 0, true)
    );
    for (role, purpose, direction) in [
        ("claimed-peer", "handshake", "outbound"),
        ("worker", "request-id", "outbound"),
        ("worker", "handshake", "peer-address"),
    ] {
        opc_redaction::metrics::METRICS
            .record_scope_transport_revision_mismatch(role, purpose, direction);
    }
    let exposition = opc_redaction::metrics::export_prometheus_text();
    assert!(exposition
        .lines()
        .any(|line| line == "# TYPE scope_transport_revision_mismatch_total counter"));
    assert!(exposition.lines().any(|line| line ==
        "scope_transport_revision_mismatch_total{role=\"worker\",purpose=\"handshake\",direction=\"outbound\"} 2"),
        "both signals must be exported, including the rate-limited log's event");
    assert!(exposition.lines().any(|line| line ==
        "scope_transport_revision_mismatch_total{role=\"observer\",purpose=\"handshake\",direction=\"inbound\"} 1"),
        "roles and directions must retain separate counter buckets");
    let buckets: Vec<_> = exposition
        .lines()
        .filter(|line| line.starts_with("scope_transport_revision_mismatch_total{"))
        .collect();
    assert_eq!(
        buckets.len(),
        50,
        "unknown labels allocate no additional buckets"
    );
    assert!(buckets.iter().all(|line| !line.contains("claimed-peer")
        && !line.contains("request-id")
        && !line.contains("peer-address")));
    opc_redaction::metrics::METRICS.reset_all();
    assert!(opc_redaction::metrics::export_prometheus_text()
        .lines()
        .filter(|line| line.starts_with("scope_transport_revision_mismatch_total{"))
        .all(|line| line.ends_with(" 0")));
}

pub(super) fn signal(
    role: ScopeTransportRole,
    purpose: ScopeTransportPurpose,
    direction: ScopeTransportDirection,
) -> (u64, u64, bool) {
    let entry = scope_transport_revision_diagnostics()
        .into_iter()
        .find(|entry| {
            entry.role == role && entry.purpose == purpose && entry.direction == direction
        })
        .unwrap();
    (entry.total, entry.authenticated, entry.active)
}

#[test]
fn revision_diagnostics_count_every_signal_but_limit_logs_across_reconnects() {
    let diagnostics = Diagnostics::default();
    let context = DiagnosticContext::new(
        ScopeTransportRole::Worker,
        ScopeTransportPurpose::Handshake,
        ScopeTransportDirection::Outbound,
    );
    let start = Instant::now();
    for event in 0..20 {
        assert_eq!(diagnostics.record(context, false, start), event == 0);
    }
    let first = diagnostics.snapshot(context);
    assert_eq!(
        (first.total, first.authenticated, first.active),
        (20, 0, true)
    );

    diagnostics.authenticated(context.role, context.direction);
    let cleared = diagnostics.snapshot(context);
    assert_eq!(
        (cleared.total, cleared.authenticated, cleared.active),
        (20, 0, false)
    );
    assert!(!diagnostics.record(context, false, start + Duration::from_secs(1)));
    assert!(!diagnostics.record(context, false, start + Duration::from_secs(29)));
    assert!(diagnostics.record(context, false, start + Duration::from_secs(30)));
    let later = diagnostics.snapshot(context);
    assert_eq!(
        (later.total, later.authenticated, later.active),
        (23, 0, true)
    );
}

#[test]
fn revision_diagnostics_keep_only_fixed_role_purpose_direction_buckets() {
    let diagnostics = Diagnostics::default();
    let start = Instant::now();
    let all = DiagnosticContext::all();
    assert_eq!(all.len(), 50);
    for (index, context) in all.iter().copied().enumerate() {
        assert!(!all[..index].contains(&context));
        assert!(diagnostics.record(
            context,
            context.purpose != ScopeTransportPurpose::Handshake,
            start
        ));
        let event = diagnostics.snapshot(context);
        assert_eq!(event.total, 1);
        assert_eq!(
            event.authenticated,
            u64::from(context.purpose != ScopeTransportPurpose::Handshake)
        );
        assert!(event.active);
    }
    diagnostics.authenticated(
        ScopeTransportRole::Worker,
        ScopeTransportDirection::Outbound,
    );
    for context in all {
        let cleared = context.role == ScopeTransportRole::Worker
            && context.direction == ScopeTransportDirection::Outbound;
        let event = diagnostics.snapshot(context);
        assert_eq!(event.active, !cleared);
        assert_eq!(event.total, 1, "recovery cannot erase the event counter");
        assert!(
            !diagnostics.record(context, false, start + Duration::from_secs(1)),
            "a handshake cannot reset the per-bucket log limiter"
        );
    }
    assert_eq!(
        SCOPE_TRANSPORT_REVISION_MISMATCH_COUNTER,
        "scope_transport_revision_mismatch_total"
    );
}
