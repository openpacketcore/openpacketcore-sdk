//! Diagnostic state is bounded and never becomes an admission latch.
use super::revision::*;
use std::time::{Duration, Instant};

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
