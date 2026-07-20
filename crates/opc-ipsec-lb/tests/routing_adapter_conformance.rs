//! Conformance tests for the typed prefix-advertisement tier (#309).
//!
//! Every acceptance criterion of the routing-adapter contract is proven
//! deterministically against the conformance fake: delta-exact reconcile, no
//! out-of-set origination under arbitrary call sequences, bounded lease-expiry
//! withdrawal on an injected clock, stale-generation fail-closed behavior, and
//! session-down-before-prefix-withdrawn event ordering.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use opc_session_store::TokioVirtualClock;

use opc_ipsec_lb::{
    AdvertisedPrefix, AdvertisementLease, ConformanceFakeRoutingStack, FakeApplyFailure,
    HostPrefix, IpAddress, IpsecLbError, LeaseGeneration, PathHealth, PeerIdentity,
    PeerObservation, PeerSessionChangeReason, PeerSessionState, PrefixAdvertisementState,
    PrefixAdvertiserConfig, PrefixAdvertiserService, PrefixApplyOutcome, PrefixRejectReason,
    PrefixWithdrawReason, ReconcileDisposition, RecordedStackMutation, RoutingDomainTag,
    RoutingEventKind,
};

use proptest::prelude::*;

const DOMAIN_A: u64 = 64512;
const DOMAIN_B: u64 = 64513;

fn domain(tag: u64) -> RoutingDomainTag {
    RoutingDomainTag::new(tag)
}

fn prefix(last: u8) -> HostPrefix {
    HostPrefix::new(IpAddress::V4([203, 0, 113, last]))
}

fn prefixes(set: &[u8]) -> BTreeSet<HostPrefix> {
    set.iter().map(|last| prefix(*last)).collect()
}

fn lease(generation: u64) -> AdvertisementLease {
    AdvertisementLease::new(LeaseGeneration::new(generation).unwrap(), 3_600).unwrap()
}

fn short_lease(generation: u64, ttl_secs: u32) -> AdvertisementLease {
    AdvertisementLease::new(LeaseGeneration::new(generation).unwrap(), ttl_secs).unwrap()
}

fn service(
    stack: ConformanceFakeRoutingStack,
) -> PrefixAdvertiserService<ConformanceFakeRoutingStack> {
    PrefixAdvertiserService::new(stack, PrefixAdvertiserConfig::default()).unwrap()
}

fn observation(
    tag: u64,
    name: &str,
    session: PeerSessionState,
    health: PathHealth,
) -> PeerObservation {
    PeerObservation {
        domain: domain(tag),
        peer: PeerIdentity::named(name).with_address(IpAddress::V4([192, 0, 2, 1])),
        session,
        path_health: health,
    }
}

fn collect_events(
    receiver: &mut tokio::sync::broadcast::Receiver<opc_ipsec_lb::RoutingEvent>,
) -> Vec<opc_ipsec_lb::RoutingEvent> {
    let mut events = Vec::new();
    while let Ok(event) = receiver.try_recv() {
        events.push(event);
    }
    events
}

#[tokio::test]
async fn reconcile_delta_is_exact_and_events_only_cover_the_delta() {
    let stack = ConformanceFakeRoutingStack::new();
    let service = service(stack.clone());
    let mut events = service.subscribe_events();

    let report = service
        .reconcile(domain(DOMAIN_A), prefixes(&[10, 11]), Some(lease(1)))
        .await
        .unwrap();
    assert_eq!(report.disposition, ReconcileDisposition::Advertised);
    assert_eq!(stack.originated(domain(DOMAIN_A)), prefixes(&[10, 11]));

    let report = service
        .reconcile(domain(DOMAIN_A), prefixes(&[11, 12]), Some(lease(2)))
        .await
        .unwrap();
    assert_eq!(report.disposition, ReconcileDisposition::Advertised);
    assert_eq!(stack.originated(domain(DOMAIN_A)), prefixes(&[11, 12]));

    // Exactly two applies carried exactly the caller-supplied sets.
    let calls = stack.apply_calls();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].desired, prefixes(&[10, 11]));
    assert_eq!(calls[0].originated_after, prefixes(&[10, 11]));
    assert_eq!(calls[1].desired, prefixes(&[11, 12]));
    assert_eq!(calls[1].originated_after, prefixes(&[11, 12]));

    // Events cover exactly the delta: 10 withdrawn, 12 advertised, 11 silent.
    let events = collect_events(&mut events);
    let withdrawn: Vec<AdvertisedPrefix> = events
        .iter()
        .filter_map(|event| match &event.kind {
            RoutingEventKind::PrefixWithdrawn { prefix, reason }
                if *reason == PrefixWithdrawReason::CallerDrain =>
            {
                Some(*prefix)
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        withdrawn,
        vec![AdvertisedPrefix::new(domain(DOMAIN_A), prefix(10))]
    );
    let advertised: Vec<AdvertisedPrefix> = events
        .iter()
        .filter_map(|event| match &event.kind {
            RoutingEventKind::PrefixAdvertised { prefix, .. } => Some(*prefix),
            _ => None,
        })
        .collect();
    assert_eq!(
        advertised,
        vec![
            AdvertisedPrefix::new(domain(DOMAIN_A), prefix(10)),
            AdvertisedPrefix::new(domain(DOMAIN_A), prefix(11)),
            AdvertisedPrefix::new(domain(DOMAIN_A), prefix(12)),
        ]
    );
    assert!(!events.iter().any(|event| match &event.kind {
        RoutingEventKind::PrefixWithdrawn {
            prefix: withdrawn, ..
        } => {
            withdrawn.prefix() == prefix(11)
        }
        _ => false,
    }));
}

#[tokio::test]
async fn identical_reconcile_is_an_idempotent_noop() {
    let stack = ConformanceFakeRoutingStack::new();
    let service = service(stack.clone());

    service
        .reconcile(domain(DOMAIN_A), prefixes(&[10]), Some(lease(1)))
        .await
        .unwrap();
    let report = service
        .reconcile(domain(DOMAIN_A), prefixes(&[10]), Some(lease(1)))
        .await
        .unwrap();

    assert_eq!(report.disposition, ReconcileDisposition::Retained);
    assert_eq!(
        report.outcomes.get(&prefix(10)),
        Some(&PrefixApplyOutcome::Accepted)
    );
    assert_eq!(stack.apply_calls().len(), 1);
}

#[tokio::test]
async fn typed_per_prefix_results_cover_accepted_rejected_and_unreachable() {
    let stack = ConformanceFakeRoutingStack::new();
    stack.reject_prefix(prefix(11));
    let service = service(stack.clone());

    let report = service
        .reconcile(domain(DOMAIN_A), prefixes(&[10, 11]), Some(lease(1)))
        .await
        .unwrap();
    assert_eq!(report.disposition, ReconcileDisposition::PartiallyRejected);
    assert_eq!(
        report.outcomes.get(&prefix(10)),
        Some(&PrefixApplyOutcome::Accepted)
    );
    assert_eq!(
        report.outcomes.get(&prefix(11)),
        Some(&PrefixApplyOutcome::Rejected(
            PrefixRejectReason::PolicyDenied
        ))
    );
    assert_eq!(stack.originated(domain(DOMAIN_A)), prefixes(&[10]));
    let snapshot = service
        .prefix_snapshot(domain(DOMAIN_A), prefix(11))
        .unwrap();
    assert_eq!(snapshot.state, PrefixAdvertisementState::Rejected);

    stack.set_unreachable(true);
    let report = service
        .reconcile(domain(DOMAIN_B), prefixes(&[10]), Some(lease(1)))
        .await
        .unwrap();
    assert_eq!(
        report.outcomes.get(&prefix(10)),
        Some(&PrefixApplyOutcome::Unreachable)
    );
    assert!(stack.originated(domain(DOMAIN_B)).is_empty());
}

#[tokio::test]
async fn stale_generation_never_readvertises_after_drain() {
    let stack = ConformanceFakeRoutingStack::new();
    let service = service(stack.clone());
    let mut events = service.subscribe_events();

    service
        .reconcile(domain(DOMAIN_A), prefixes(&[10, 11]), Some(lease(5)))
        .await
        .unwrap();
    assert_eq!(stack.originated(domain(DOMAIN_A)), prefixes(&[10, 11]));

    // Drain (fence/quorum/health loss at the caller's gating component).
    let report = service
        .reconcile(domain(DOMAIN_A), BTreeSet::new(), None)
        .await
        .unwrap();
    assert_eq!(report.disposition, ReconcileDisposition::Withdrawn);
    assert!(stack.originated(domain(DOMAIN_A)).is_empty());

    // The same generation is now stale and fails closed without any apply.
    let report = service
        .reconcile(domain(DOMAIN_A), prefixes(&[10, 11]), Some(lease(5)))
        .await
        .unwrap();
    assert_eq!(report.disposition, ReconcileDisposition::StaleRejected);
    assert_eq!(
        report.outcomes.get(&prefix(10)),
        Some(&PrefixApplyOutcome::Rejected(
            PrefixRejectReason::StaleGeneration
        ))
    );
    assert!(stack.originated(domain(DOMAIN_A)).is_empty());

    // An older generation is equally stale.
    let report = service
        .reconcile(domain(DOMAIN_A), prefixes(&[10]), Some(lease(4)))
        .await
        .unwrap();
    assert_eq!(report.disposition, ReconcileDisposition::StaleRejected);
    assert!(stack.originated(domain(DOMAIN_A)).is_empty());

    // Only a strictly newer generation advertises again.
    let report = service
        .reconcile(domain(DOMAIN_A), prefixes(&[10]), Some(lease(6)))
        .await
        .unwrap();
    assert_eq!(report.disposition, ReconcileDisposition::Advertised);
    assert_eq!(stack.originated(domain(DOMAIN_A)), prefixes(&[10]));

    let events = collect_events(&mut events);
    let drain_withdrawals = events.iter().filter(|event| {
        matches!(
            &event.kind,
            RoutingEventKind::PrefixWithdrawn { reason, .. }
                if *reason == PrefixWithdrawReason::CallerDrain
        )
    });
    assert_eq!(drain_withdrawals.count(), 2);
}

#[tokio::test]
async fn expired_lease_cannot_be_refreshed_with_the_same_generation() {
    let stack = ConformanceFakeRoutingStack::new();
    let clock = Arc::new(TokioVirtualClock::new());
    let service = PrefixAdvertiserService::with_clock(
        stack.clone(),
        PrefixAdvertiserConfig::default(),
        clock,
    )
    .unwrap();

    service
        .reconcile(domain(DOMAIN_A), prefixes(&[10]), Some(short_lease(1, 1)))
        .await
        .unwrap();
    // Let the lease lapse, then attempt a same-generation refresh.
    tokio::time::sleep(Duration::from_secs(2)).await;
    let report = service
        .reconcile(
            domain(DOMAIN_A),
            prefixes(&[10]),
            Some(short_lease(1, 3_600)),
        )
        .await
        .unwrap();
    assert_eq!(report.disposition, ReconcileDisposition::StaleRejected);
    assert!(stack.originated(domain(DOMAIN_A)).is_empty());
}

#[tokio::test(start_paused = true)]
async fn lease_expiry_withdraws_all_gated_prefixes_within_one_poll_interval() {
    let stack = ConformanceFakeRoutingStack::new();
    let clock = Arc::new(TokioVirtualClock::new());
    let service = Arc::new(
        PrefixAdvertiserService::with_clock(
            stack.clone(),
            PrefixAdvertiserConfig {
                poll_interval: Duration::from_secs(5),
                ..PrefixAdvertiserConfig::default()
            },
            clock,
        )
        .unwrap(),
    );
    let mut events = service.subscribe_events();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let runner = tokio::spawn({
        let service = Arc::clone(&service);
        async move { service.run(shutdown_rx).await }
    });

    service
        .reconcile(
            domain(DOMAIN_A),
            prefixes(&[10, 11]),
            Some(short_lease(1, 10)),
        )
        .await
        .unwrap();
    service
        .reconcile(domain(DOMAIN_B), prefixes(&[20]), Some(short_lease(1, 10)))
        .await
        .unwrap();
    assert_eq!(stack.originated(domain(DOMAIN_A)), prefixes(&[10, 11]));

    // Before expiry, nothing is withdrawn.
    tokio::time::advance(Duration::from_secs(9)).await;
    for _ in 0..32 {
        tokio::task::yield_now().await;
    }
    assert_eq!(stack.originated(domain(DOMAIN_A)), prefixes(&[10, 11]));
    assert!(stack.withdraw_all_calls().is_empty());

    // Deadline is t=10; the next watchdog tick (t=10, one interval later at
    // worst) withdraws every gated prefix in every domain.
    tokio::time::advance(Duration::from_secs(6)).await;
    for _ in 0..32 {
        tokio::task::yield_now().await;
    }
    assert!(stack.originated(domain(DOMAIN_A)).is_empty());
    assert!(stack.originated(domain(DOMAIN_B)).is_empty());
    assert_eq!(
        stack.withdraw_all_calls(),
        vec![domain(DOMAIN_A), domain(DOMAIN_B)]
    );

    let events = collect_events(&mut events);
    let mut expired: Vec<AdvertisedPrefix> = events
        .iter()
        .filter_map(|event| match &event.kind {
            RoutingEventKind::PrefixWithdrawn { prefix, reason }
                if *reason == PrefixWithdrawReason::LeaseExpired =>
            {
                Some(*prefix)
            }
            _ => None,
        })
        .collect();
    expired.sort();
    assert_eq!(
        expired,
        vec![
            AdvertisedPrefix::new(domain(DOMAIN_A), prefix(10)),
            AdvertisedPrefix::new(domain(DOMAIN_A), prefix(11)),
            AdvertisedPrefix::new(domain(DOMAIN_B), prefix(20)),
        ]
    );

    // A same-generation retry after expiry stays withdrawn.
    let report = service
        .reconcile(
            domain(DOMAIN_A),
            prefixes(&[10]),
            Some(short_lease(1, 3_600)),
        )
        .await
        .unwrap();
    assert_eq!(report.disposition, ReconcileDisposition::StaleRejected);

    shutdown_tx.send(true).unwrap();
    runner.await.unwrap();
}

#[tokio::test]
async fn session_down_is_observed_before_prefix_withdrawn_for_the_same_cause() {
    let stack = ConformanceFakeRoutingStack::new();
    stack.set_observations(vec![observation(
        DOMAIN_A,
        "edge-a",
        PeerSessionState::Established,
        PathHealth::Up,
    )]);
    let service = service(stack.clone());
    let mut events = service.subscribe_events();

    service
        .reconcile(domain(DOMAIN_A), prefixes(&[10, 11]), Some(lease(1)))
        .await
        .unwrap();
    service.observe_once().await.unwrap();
    let snapshot = service
        .prefix_snapshot(domain(DOMAIN_A), prefix(10))
        .unwrap();
    assert_eq!(snapshot.state, PrefixAdvertisementState::Advertised);
    assert_eq!(snapshot.advertised_to.len(), 1);

    // BFD drops first; the stack then reports the session down.
    stack.set_observations(vec![observation(
        DOMAIN_A,
        "edge-a",
        PeerSessionState::Down,
        PathHealth::Down,
    )]);
    service.observe_once().await.unwrap();

    let events = collect_events(&mut events);
    let session_down = events
        .iter()
        .position(|event| {
            matches!(
                &event.kind,
                RoutingEventKind::PeerSessionChanged {
                    state: PeerSessionState::Down,
                    reason: PeerSessionChangeReason::BfdPathDown,
                    ..
                }
            )
        })
        .expect("session-down event");
    let first_withdrawn = events
        .iter()
        .position(|event| {
            matches!(
                &event.kind,
                RoutingEventKind::PrefixWithdrawn {
                    reason: PrefixWithdrawReason::PeerSessionDown,
                    ..
                }
            )
        })
        .expect("prefix-withdrawn event");
    assert!(session_down < first_withdrawn);
    assert!(events[session_down].sequence < events[first_withdrawn].sequence);

    let withdrawn: Vec<AdvertisedPrefix> = events
        .iter()
        .filter_map(|event| match &event.kind {
            RoutingEventKind::PrefixWithdrawn { prefix, reason }
                if *reason == PrefixWithdrawReason::PeerSessionDown =>
            {
                Some(*prefix)
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        withdrawn,
        vec![
            AdvertisedPrefix::new(domain(DOMAIN_A), prefix(10)),
            AdvertisedPrefix::new(domain(DOMAIN_A), prefix(11)),
        ]
    );
    // BFD path health is relayed, never synthesized.
    assert!(events.iter().any(|event| matches!(
        &event.kind,
        RoutingEventKind::PathHealthChanged {
            health: PathHealth::Down,
            ..
        }
    )));

    let snapshot = service
        .prefix_snapshot(domain(DOMAIN_A), prefix(10))
        .unwrap();
    assert_eq!(snapshot.state, PrefixAdvertisementState::Withdrawn);
    assert_eq!(
        snapshot.last_withdraw_reason,
        Some(PrefixWithdrawReason::PeerSessionDown)
    );
    assert!(snapshot.advertised_to.is_empty());
    assert!(snapshot.last_transition.is_some());
}

#[tokio::test]
async fn session_reestablish_readvertises_originated_prefixes() {
    let stack = ConformanceFakeRoutingStack::new();
    stack.set_observations(vec![observation(
        DOMAIN_A,
        "edge-a",
        PeerSessionState::Established,
        PathHealth::Up,
    )]);
    let service = service(stack.clone());
    let mut events = service.subscribe_events();

    service
        .reconcile(domain(DOMAIN_A), prefixes(&[10]), Some(lease(1)))
        .await
        .unwrap();
    service.observe_once().await.unwrap();
    stack.set_observations(vec![observation(
        DOMAIN_A,
        "edge-a",
        PeerSessionState::Down,
        PathHealth::Unknown,
    )]);
    service.observe_once().await.unwrap();
    stack.set_observations(vec![observation(
        DOMAIN_A,
        "edge-a",
        PeerSessionState::Established,
        PathHealth::Up,
    )]);
    service.observe_once().await.unwrap();

    let events = collect_events(&mut events);
    let readvertised = events.iter().any(|event| {
        matches!(
            &event.kind,
            RoutingEventKind::PrefixAdvertised { prefix: advertised, .. }
                if advertised.prefix() == prefix(10)
        )
    });
    assert!(readvertised);
    let snapshot = service
        .prefix_snapshot(domain(DOMAIN_A), prefix(10))
        .unwrap();
    assert_eq!(snapshot.state, PrefixAdvertisementState::Advertised);
    assert_eq!(snapshot.advertised_to.len(), 1);
}

#[tokio::test]
async fn routing_stack_death_closes_sessions_and_unconfirms_prefixes() {
    let stack = ConformanceFakeRoutingStack::new();
    stack.set_observations(vec![observation(
        DOMAIN_A,
        "edge-a",
        PeerSessionState::Established,
        PathHealth::Up,
    )]);
    let service = service(stack.clone());
    let mut events = service.subscribe_events();

    service
        .reconcile(domain(DOMAIN_A), prefixes(&[10]), Some(lease(1)))
        .await
        .unwrap();
    service.observe_once().await.unwrap();

    stack.set_unreachable(true);
    service.observe_once().await.unwrap();

    let events = collect_events(&mut events);
    let session_lost = events
        .iter()
        .position(|event| {
            matches!(
                &event.kind,
                RoutingEventKind::PeerSessionChanged {
                    state: PeerSessionState::Down,
                    reason: PeerSessionChangeReason::ObservationLost,
                    ..
                }
            )
        })
        .expect("session-lost event");
    let unconfirmed = events
        .iter()
        .position(|event| {
            matches!(
                &event.kind,
                RoutingEventKind::PrefixUnconfirmed {
                    reason: PrefixWithdrawReason::RoutingStackUnreachable,
                    ..
                }
            )
        })
        .expect("prefix-unconfirmed event");
    assert!(session_lost < unconfirmed);
    assert!(events[unconfirmed].sequence > events[session_lost].sequence);
    // Unreachability is not a withdrawal: the snapshot reports the prefix as
    // unconfirmed, and no PrefixWithdrawn event was emitted for this cause.
    let snapshot = service
        .prefix_snapshot(domain(DOMAIN_A), prefix(10))
        .unwrap();
    assert_eq!(snapshot.state, PrefixAdvertisementState::Unknown);
    assert!(!events.iter().any(|event| matches!(
        &event.kind,
        RoutingEventKind::PrefixWithdrawn {
            reason: PrefixWithdrawReason::RoutingStackUnreachable,
            ..
        }
    )));
}

#[tokio::test]
async fn renewal_after_shrink_is_an_idempotent_noop() {
    let stack = ConformanceFakeRoutingStack::new();
    let service = service(stack.clone());

    service
        .reconcile(domain(DOMAIN_A), prefixes(&[10, 11]), Some(lease(1)))
        .await
        .unwrap();
    let report = service
        .reconcile(domain(DOMAIN_A), prefixes(&[11]), Some(lease(2)))
        .await
        .unwrap();
    assert_eq!(report.disposition, ReconcileDisposition::Advertised);
    assert_eq!(stack.originated(domain(DOMAIN_A)), prefixes(&[11]));
    assert_eq!(stack.apply_calls().len(), 2);

    // Same-generation renewal of the shrunk set: historical tracks of the
    // dropped prefix must not poison retention.
    let report = service
        .reconcile(domain(DOMAIN_A), prefixes(&[11]), Some(lease(2)))
        .await
        .unwrap();
    assert_eq!(report.disposition, ReconcileDisposition::Retained);
    assert_eq!(stack.apply_calls().len(), 2);
    assert_eq!(stack.originated(domain(DOMAIN_A)), prefixes(&[11]));
    // The dropped prefix's terminal track is pruned; the live one is kept.
    assert!(service
        .prefix_snapshot(domain(DOMAIN_A), prefix(10))
        .is_none());
    let snapshot = service
        .prefix_snapshot(domain(DOMAIN_A), prefix(11))
        .unwrap();
    assert_eq!(snapshot.state, PrefixAdvertisementState::Advertised);
}

#[tokio::test]
async fn renewal_after_partial_rejection_and_shrink_is_an_idempotent_noop() {
    let stack = ConformanceFakeRoutingStack::new();
    stack.reject_prefix(prefix(11));
    let service = service(stack.clone());

    let report = service
        .reconcile(domain(DOMAIN_A), prefixes(&[10, 11]), Some(lease(1)))
        .await
        .unwrap();
    assert_eq!(report.disposition, ReconcileDisposition::PartiallyRejected);
    stack.clear_rejections();

    let report = service
        .reconcile(domain(DOMAIN_A), prefixes(&[10]), Some(lease(2)))
        .await
        .unwrap();
    assert_eq!(report.disposition, ReconcileDisposition::Advertised);
    assert_eq!(stack.apply_calls().len(), 2);

    // The rejected prefix's historical track must not poison renewal of the
    // surviving set.
    let report = service
        .reconcile(domain(DOMAIN_A), prefixes(&[10]), Some(lease(2)))
        .await
        .unwrap();
    assert_eq!(report.disposition, ReconcileDisposition::Retained);
    assert_eq!(stack.apply_calls().len(), 2);
    assert_eq!(stack.originated(domain(DOMAIN_A)), prefixes(&[10]));
}

#[tokio::test]
async fn partial_apply_disconnect_retries_with_the_same_generation() {
    let stack = ConformanceFakeRoutingStack::new();
    stack.fail_next_apply(FakeApplyFailure::DisconnectAfterPartialApply);
    let service = service(stack.clone());

    // The apply fails ambiguously after originating only prefix 10.
    let error = service
        .reconcile(domain(DOMAIN_A), prefixes(&[10, 11]), Some(lease(1)))
        .await
        .unwrap_err();
    assert!(matches!(error, IpsecLbError::Io { .. }));
    assert_eq!(stack.originated(domain(DOMAIN_A)), prefixes(&[10]));

    // The generation is current and the lease unexpired: the identical
    // intent retries declaratively instead of failing closed as stale.
    let report = service
        .reconcile(domain(DOMAIN_A), prefixes(&[10, 11]), Some(lease(1)))
        .await
        .unwrap();
    assert_eq!(report.disposition, ReconcileDisposition::Advertised);
    assert_eq!(stack.originated(domain(DOMAIN_A)), prefixes(&[10, 11]));
    for last in [10, 11] {
        let snapshot = service
            .prefix_snapshot(domain(DOMAIN_A), prefix(last))
            .unwrap();
        assert_eq!(snapshot.state, PrefixAdvertisementState::Advertised);
    }
}

#[tokio::test]
async fn cancelled_reconcile_driver_completes_to_consistent_state() {
    let stack = ConformanceFakeRoutingStack::new();
    let gate = stack.gate_next_apply();
    let service = Arc::new(service(stack.clone()));

    let task = tokio::spawn({
        let service = Arc::clone(&service);
        async move {
            service
                .reconcile(domain(DOMAIN_A), prefixes(&[10]), Some(lease(1)))
                .await
        }
    });
    // The adapter side effect has landed; the caller is cancelled before
    // the outcome is applied, yet the detached driver must finish the job.
    gate.wait_landed().await;
    task.abort();
    gate.release();

    let mut advertised = false;
    for _ in 0..64 {
        if service
            .prefix_snapshot(domain(DOMAIN_A), prefix(10))
            .is_some_and(|snapshot| snapshot.state == PrefixAdvertisementState::Advertised)
        {
            advertised = true;
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(
        advertised,
        "driver must finalize state after caller cancellation"
    );
    assert_eq!(stack.originated(domain(DOMAIN_A)), prefixes(&[10]));
    let report = service
        .reconcile(domain(DOMAIN_A), prefixes(&[10]), Some(lease(1)))
        .await
        .unwrap();
    assert_eq!(report.disposition, ReconcileDisposition::Retained);
}

/// The reviewer's F1 probe: abort after the side effect lands, drain, then
/// release the gate. The stale driver must not re-originate the drained
/// prefix, and no apply may reach the adapter after the drain's withdrawal.
#[tokio::test]
async fn cancel_then_drain_cannot_reoriginate_or_leave_phantom_belief() {
    let stack = ConformanceFakeRoutingStack::new();
    let gate = stack.gate_next_apply();
    let service = Arc::new(service(stack.clone()));

    let task = tokio::spawn({
        let service = Arc::clone(&service);
        async move {
            service
                .reconcile(domain(DOMAIN_A), prefixes(&[10]), Some(lease(1)))
                .await
        }
    });
    gate.wait_landed().await;
    task.abort();

    // The drain queues behind the parked driver on the apply lock; once the
    // driver finishes, the withdrawal is the last adapter effect.
    let drain = tokio::spawn({
        let service = Arc::clone(&service);
        async move {
            service
                .reconcile(domain(DOMAIN_A), BTreeSet::new(), None)
                .await
        }
    });
    tokio::task::yield_now().await;
    gate.release();
    let report = drain.await.unwrap().unwrap();

    assert_eq!(report.disposition, ReconcileDisposition::Withdrawn);
    assert!(stack.originated(domain(DOMAIN_A)).is_empty());
    assert_eq!(
        stack.mutation_log(),
        vec![
            RecordedStackMutation::Apply {
                domain: domain(DOMAIN_A),
                desired: prefixes(&[10]),
            },
            RecordedStackMutation::WithdrawAll {
                domain: domain(DOMAIN_A),
            },
        ],
        "the drain's withdrawal must be the final adapter effect"
    );
    assert!(service
        .prefix_snapshots(domain(DOMAIN_A))
        .iter()
        .all(|snapshot| snapshot.state != PrefixAdvertisementState::Advertised));
}

/// Two queued drivers plus a drain totally order on the apply lock: the
/// newer intent overwrites the stale one and the drain wins overall.
#[tokio::test]
async fn queued_stale_driver_cannot_overwrite_newer_intent() {
    let stack = ConformanceFakeRoutingStack::new();
    let gate = stack.gate_next_apply();
    let service = Arc::new(service(stack.clone()));

    let task = tokio::spawn({
        let service = Arc::clone(&service);
        async move {
            service
                .reconcile(domain(DOMAIN_A), prefixes(&[10]), Some(lease(1)))
                .await
        }
    });
    gate.wait_landed().await;
    task.abort();

    // A newer intent queues its driver behind the parked stale driver.
    let newer = tokio::spawn({
        let service = Arc::clone(&service);
        async move {
            service
                .reconcile(domain(DOMAIN_A), prefixes(&[11]), Some(lease(2)))
                .await
        }
    });
    tokio::task::yield_now().await;
    gate.release();
    let report = newer.await.unwrap().unwrap();

    assert_eq!(report.disposition, ReconcileDisposition::Advertised);
    assert_eq!(stack.originated(domain(DOMAIN_A)), prefixes(&[11]));
    assert_eq!(
        stack.mutation_log(),
        vec![
            RecordedStackMutation::Apply {
                domain: domain(DOMAIN_A),
                desired: prefixes(&[10]),
            },
            RecordedStackMutation::Apply {
                domain: domain(DOMAIN_A),
                desired: prefixes(&[11]),
            },
        ],
        "the newer intent must be the last adapter effect"
    );
    let snapshot = service
        .prefix_snapshot(domain(DOMAIN_A), prefix(11))
        .unwrap();
    assert_eq!(snapshot.state, PrefixAdvertisementState::Advertised);
    // The stale driver's prefix left the desired set and was converged out.
    assert!(service
        .prefix_snapshot(domain(DOMAIN_A), prefix(10))
        .is_none_or(|snapshot| snapshot.state != PrefixAdvertisementState::Advertised));
}

#[tokio::test(start_paused = true)]
async fn lease_enforcement_attempts_every_expired_domain_despite_errors() {
    let stack = ConformanceFakeRoutingStack::new();
    let clock = Arc::new(TokioVirtualClock::new());
    let service = PrefixAdvertiserService::with_clock(
        stack.clone(),
        PrefixAdvertiserConfig::default(),
        clock,
    )
    .unwrap();

    service
        .reconcile(domain(DOMAIN_A), prefixes(&[10]), Some(short_lease(1, 1)))
        .await
        .unwrap();
    service
        .reconcile(domain(DOMAIN_B), prefixes(&[20]), Some(short_lease(1, 1)))
        .await
        .unwrap();

    stack.set_unreachable(true);
    tokio::time::advance(Duration::from_secs(2)).await;
    let error = service.enforce_lease_once().await.unwrap_err();
    assert!(matches!(error, IpsecLbError::Io { .. }));
    // Both expired domains were attempted; the first failure did not block
    // the second.
    assert_eq!(
        stack.withdraw_all_calls(),
        vec![domain(DOMAIN_A), domain(DOMAIN_B)]
    );
    // The lease deadlines stay armed, so recovery retries the withdrawal.
    stack.set_unreachable(false);
    service.enforce_lease_once().await.unwrap();
    assert!(stack.originated(domain(DOMAIN_A)).is_empty());
    assert!(stack.originated(domain(DOMAIN_B)).is_empty());
}

#[tokio::test(start_paused = true)]
async fn vanished_peer_is_pruned_after_retention_and_relearned_as_new() {
    let stack = ConformanceFakeRoutingStack::new();
    stack.set_observations(vec![observation(
        DOMAIN_A,
        "edge-a",
        PeerSessionState::Established,
        PathHealth::Up,
    )]);
    let clock = Arc::new(TokioVirtualClock::new());
    let service = PrefixAdvertiserService::with_clock(
        stack.clone(),
        PrefixAdvertiserConfig {
            peer_retention_secs: 60,
            ..PrefixAdvertiserConfig::default()
        },
        clock,
    )
    .unwrap();
    let mut events = service.subscribe_events();

    service
        .reconcile(domain(DOMAIN_A), prefixes(&[10]), Some(lease(1)))
        .await
        .unwrap();
    service.observe_once().await.unwrap();
    stack.set_observations(Vec::new());
    service.observe_once().await.unwrap();

    // Past the retention bound the peer is pruned.
    tokio::time::advance(Duration::from_secs(120)).await;
    service.observe_once().await.unwrap();
    stack.set_observations(vec![observation(
        DOMAIN_A,
        "edge-a",
        PeerSessionState::Connecting,
        PathHealth::Unknown,
    )]);
    service.observe_once().await.unwrap();

    let events = collect_events(&mut events);
    let closed = events.iter().any(|event| {
        matches!(
            &event.kind,
            RoutingEventKind::PeerSessionChanged {
                state: PeerSessionState::Down,
                reason: PeerSessionChangeReason::SessionClosed,
                ..
            }
        )
    });
    assert!(closed, "vanishing peer transitions to session down");
    // A pruned peer re-sighted in a non-established state is a first
    // sighting and reports peer_observed, never session_closed.
    let relearned = events.iter().any(|event| {
        matches!(
            &event.kind,
            RoutingEventKind::PeerSessionChanged {
                state: PeerSessionState::Connecting,
                reason: PeerSessionChangeReason::PeerObserved,
                ..
            }
        )
    });
    assert!(relearned, "pruned peer is relearned as a fresh observation");
    assert!(!events.iter().any(|event| {
        matches!(
            &event.kind,
            RoutingEventKind::PeerSessionChanged {
                state: PeerSessionState::Connecting,
                reason: PeerSessionChangeReason::SessionClosed,
                ..
            }
        )
    }));
}

#[tokio::test]
async fn domains_are_independent_groups() {
    let stack = ConformanceFakeRoutingStack::new();
    let service = service(stack.clone());

    service
        .reconcile(domain(DOMAIN_A), prefixes(&[10]), Some(lease(1)))
        .await
        .unwrap();
    service
        .reconcile(domain(DOMAIN_B), prefixes(&[20, 21]), Some(lease(1)))
        .await
        .unwrap();
    service
        .reconcile(domain(DOMAIN_A), BTreeSet::new(), None)
        .await
        .unwrap();

    assert!(stack.originated(domain(DOMAIN_A)).is_empty());
    assert_eq!(stack.originated(domain(DOMAIN_B)), prefixes(&[20, 21]));
}

#[tokio::test]
async fn telemetry_debug_output_never_prints_prefixes_or_peer_addresses() {
    let stack = ConformanceFakeRoutingStack::new();
    stack.set_observations(vec![observation(
        DOMAIN_A,
        "edge-a",
        PeerSessionState::Established,
        PathHealth::Up,
    )]);
    let service = service(stack.clone());
    let mut events = service.subscribe_events();

    service
        .reconcile(domain(DOMAIN_A), prefixes(&[10, 11]), Some(lease(1)))
        .await
        .unwrap();
    service.observe_once().await.unwrap();
    service
        .reconcile(domain(DOMAIN_A), BTreeSet::new(), None)
        .await
        .unwrap();

    let mut rendered = String::new();
    for event in collect_events(&mut events) {
        rendered.push_str(&format!("{event:?}"));
    }
    for snapshot in service.prefix_snapshots(domain(DOMAIN_A)) {
        rendered.push_str(&format!("{snapshot:?}"));
    }
    rendered.push_str(&format!("{service:?}"));
    assert!(!rendered.contains("203.0.113"), "{rendered}");
    assert!(!rendered.contains("192.0.2"), "{rendered}");
    assert!(rendered.contains("edge-a"), "{rendered}");
    assert!(rendered.contains("64512"), "{rendered}");
}

proptest! {
    /// No call sequence can originate a prefix outside the requested set.
    ///
    /// Random sequences of fresh advertises, same-generation renewals,
    /// drains, and ambiguous apply failures over two domains must leave the
    /// fake's originated set equal to the harness-tracked expectation after
    /// every call, and every recorded apply must have originated a subset of
    /// the set the caller requested in that call.
    #[test]
    fn no_prefix_outside_the_requested_set_is_ever_originated(
        operations in prop::collection::vec(
            (0u8..2, 0u8..4, prop::collection::vec(0u8..6, 0..4)),
            1..64,
        )
    ) {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let stack = ConformanceFakeRoutingStack::new();
            let service = service(stack.clone());
            let domains = [domain(DOMAIN_A), domain(DOMAIN_B)];
            let mut generation = 0u64;
            let mut expected: [BTreeSet<HostPrefix>; 2] = [BTreeSet::new(), BTreeSet::new()];
            // Per-domain: last intent (generation, set), live epoch, and
            // whether the last apply ended ambiguously.
            let mut intents: [Option<(u64, BTreeSet<HostPrefix>)>; 2] = [None, None];
            let mut live = [false; 2];
            let mut ambiguous = [false; 2];

            for (domain_index, operation, members) in operations {
                let index = usize::from(domain_index);
                let subset: BTreeSet<HostPrefix> = members
                    .iter()
                    .map(|member| prefix(member.saturating_add(10)))
                    .collect();
                match operation {
                    // Fresh-generation advertise.
                    0 => {
                        generation += 1;
                        let report = service
                            .reconcile(domains[index], subset.clone(), Some(lease(generation)))
                            .await
                            .unwrap();
                        prop_assert_eq!(report.disposition, ReconcileDisposition::Advertised);
                        expected[index] = subset.clone();
                        intents[index] = Some((generation, subset));
                        live[index] = true;
                        ambiguous[index] = false;
                    }
                    // Drain.
                    1 => {
                        let report = service
                            .reconcile(domains[index], BTreeSet::new(), None)
                            .await
                            .unwrap();
                        prop_assert_eq!(report.disposition, ReconcileDisposition::Withdrawn);
                        expected[index] = BTreeSet::new();
                        live[index] = false;
                        ambiguous[index] = false;
                    }
                    // Same-generation renewal of the last intent.
                    2 => {
                        let Some((last_generation, last_set)) = intents[index].clone() else {
                            continue;
                        };
                        let report = service
                            .reconcile(
                                domains[index],
                                last_set,
                                Some(lease(last_generation)),
                            )
                            .await
                            .unwrap();
                        let expected_disposition = if !live[index] {
                            ReconcileDisposition::StaleRejected
                        } else if ambiguous[index] {
                            ReconcileDisposition::Advertised
                        } else {
                            ReconcileDisposition::Retained
                        };
                        prop_assert_eq!(report.disposition, expected_disposition);
                        ambiguous[index] = false;
                    }
                    // Advertise with an ambiguous apply-then-disconnect fault.
                    _ => {
                        stack.fail_next_apply(FakeApplyFailure::DisconnectAfterFullApply);
                        generation += 1;
                        let result = service
                            .reconcile(domains[index], subset.clone(), Some(lease(generation)))
                            .await;
                        prop_assert!(result.is_err());
                        // The fake applied the full set before failing.
                        expected[index] = subset.clone();
                        intents[index] = Some((generation, subset));
                        live[index] = true;
                        ambiguous[index] = true;
                    }
                }
                for (slot, expected_set) in expected.iter().enumerate() {
                    prop_assert_eq!(&stack.originated(domains[slot]), expected_set);
                }
            }

            for call in stack.apply_calls() {
                prop_assert!(call.originated_after.is_subset(&call.desired));
                prop_assert!(call.desired.len() <= 4);
            }
            for mutation in stack.mutation_log() {
                if let RecordedStackMutation::Apply { desired, .. } = mutation {
                    prop_assert!(desired.len() <= 4);
                }
            }
            Ok(())
        })?;
    }
}
