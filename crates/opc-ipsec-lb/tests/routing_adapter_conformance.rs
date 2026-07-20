//! Conformance tests for the typed prefix-advertisement tier (#309).
//!
//! Every acceptance criterion of the routing-adapter contract is proven
//! deterministically against the conformance fake: delta-exact reconcile, no
//! out-of-set origination under arbitrary call sequences, bounded lease-expiry
//! withdrawal on an injected clock, stale-generation fail-closed behavior, and
//! session-down-before-prefix-withdrawn event ordering.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use opc_session_store::TokioVirtualClock;

use opc_ipsec_lb::{
    AdvertisedPrefix, AdvertisementLease, AdvertisementSetApplyResult, ConformanceFakeRoutingStack,
    FakeApplyFailure, HostPrefix, IpAddress, IpsecLbError, LeaseGeneration, PathHealth,
    PeerIdentity, PeerObservation, PeerSessionChangeReason, PeerSessionState,
    PrefixAdvertisementState, PrefixAdvertiserConfig, PrefixAdvertiserService, PrefixApplyOutcome,
    PrefixRejectReason, PrefixWithdrawReason, ReconcileDisposition, RecordedStackMutation,
    RoutingDomainTag, RoutingEventKind, RoutingStackAdapter, MAX_ADVERTISED_PREFIXES_PER_DOMAIN,
    MAX_ADVERTISEMENT_ROUTING_DOMAINS, MAX_ROUTING_PEERS_TOTAL, MAX_ROUTING_PEER_NAME_LEN,
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
        advertised_prefixes: BTreeSet::new(),
    }
}

fn advertising_observation(
    tag: u64,
    name: &str,
    session: PeerSessionState,
    health: PathHealth,
    advertised: &[u8],
) -> PeerObservation {
    let mut observation = observation(tag, name, session, health);
    observation.advertised_prefixes = prefixes(advertised);
    observation
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
async fn reconcile_delta_is_exact_and_export_events_require_fresh_readback() {
    let stack = ConformanceFakeRoutingStack::new();
    let service = service(stack.clone());
    let mut events = service.subscribe_events();

    let report = service
        .reconcile(domain(DOMAIN_A), prefixes(&[10, 11]), Some(lease(1)))
        .await
        .unwrap();
    assert_eq!(report.disposition, ReconcileDisposition::Applied);
    assert_eq!(stack.originated(domain(DOMAIN_A)), prefixes(&[10, 11]));
    stack.set_observations(vec![advertising_observation(
        DOMAIN_A,
        "edge-a",
        PeerSessionState::Established,
        PathHealth::Up,
        &[10, 11],
    )]);
    service.observe_once().await.unwrap();

    let report = service
        .reconcile(domain(DOMAIN_A), prefixes(&[11, 12]), Some(lease(2)))
        .await
        .unwrap();
    assert_eq!(report.disposition, ReconcileDisposition::Applied);
    assert_eq!(stack.originated(domain(DOMAIN_A)), prefixes(&[11, 12]));
    stack.set_observations(vec![advertising_observation(
        DOMAIN_A,
        "edge-a",
        PeerSessionState::Established,
        PathHealth::Up,
        &[11, 12],
    )]);
    service.observe_once().await.unwrap();

    // Exactly two applies carried exactly the caller-supplied sets.
    let calls = stack.apply_calls();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].desired, prefixes(&[10, 11]));
    assert_eq!(calls[0].originated_after, prefixes(&[10, 11]));
    assert_eq!(calls[1].desired, prefixes(&[11, 12]));
    assert_eq!(calls[1].originated_after, prefixes(&[11, 12]));

    // Mutation events cover the exact delta. Peer-export truth is separately
    // reconfirmed after each complete readback; unchanged prefix 11 therefore
    // becomes unconfirmed across configure and then advertised again.
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
    let advertised: BTreeSet<AdvertisedPrefix> = events
        .iter()
        .filter_map(|event| match &event.kind {
            RoutingEventKind::PrefixAdvertised { prefix, .. } => Some(*prefix),
            _ => None,
        })
        .collect();
    assert_eq!(
        advertised,
        BTreeSet::from([
            AdvertisedPrefix::new(domain(DOMAIN_A), prefix(10)),
            AdvertisedPrefix::new(domain(DOMAIN_A), prefix(11)),
            AdvertisedPrefix::new(domain(DOMAIN_A), prefix(12)),
        ])
    );
    assert!(events.iter().any(|event| matches!(
        &event.kind,
        RoutingEventKind::PrefixUnconfirmed {
            prefix: unconfirmed,
            reason: PrefixWithdrawReason::PeerExportUnconfirmed,
        } if unconfirmed.prefix() == prefix(11)
    )));
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
    let error = service
        .reconcile(domain(DOMAIN_B), prefixes(&[10]), Some(lease(1)))
        .await
        .unwrap_err();
    assert!(matches!(error, IpsecLbError::Io { .. }));
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
    assert_eq!(report.disposition, ReconcileDisposition::Applied);
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

    let renewal_armed = Arc::new(tokio::sync::Notify::new());
    let renewal_task = tokio::spawn({
        let service = Arc::clone(&service);
        let renewal_armed = Arc::clone(&renewal_armed);
        async move {
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
            renewal_armed.notify_one();
            std::future::pending::<()>().await;
        }
    });
    renewal_armed.notified().await;
    // Model the lease-renewing/election task dying. The independently owned
    // watchdog above must remain alive and withdraw on expiry.
    renewal_task.abort();
    let _ = renewal_task.await;
    assert_eq!(stack.originated(domain(DOMAIN_A)), prefixes(&[10, 11]));

    // Before expiry, nothing is withdrawn.
    tokio::time::advance(Duration::from_secs(9)).await;
    for _ in 0..32 {
        tokio::task::yield_now().await;
    }
    assert_eq!(stack.originated(domain(DOMAIN_A)), prefixes(&[10, 11]));
    // Startup known-absence reconciliation withdrew both managed domains
    // before the first advertisement was admitted.
    assert_eq!(
        stack.withdraw_all_calls(),
        vec![domain(DOMAIN_A), domain(DOMAIN_B)]
    );

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
        vec![
            domain(DOMAIN_A),
            domain(DOMAIN_B),
            domain(DOMAIN_A),
            domain(DOMAIN_B),
        ]
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
async fn dropping_watchdog_control_drains_live_prefixes_before_run_returns() {
    let stack = ConformanceFakeRoutingStack::new();
    let service = Arc::new(service(stack.clone()));
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let runner = tokio::spawn({
        let service = Arc::clone(&service);
        async move { service.run(shutdown_rx).await }
    });

    service
        .reconcile(domain(DOMAIN_A), prefixes(&[10]), Some(lease(1)))
        .await
        .unwrap();
    assert_eq!(stack.originated(domain(DOMAIN_A)), prefixes(&[10]));

    drop(shutdown_tx);
    runner.await.unwrap();
    assert!(stack.originated(domain(DOMAIN_A)).is_empty());
    assert!(service
        .prefix_snapshot(domain(DOMAIN_A), prefix(10))
        .is_none_or(|snapshot| snapshot.state == PrefixAdvertisementState::Withdrawn));
}

#[tokio::test]
async fn session_down_is_observed_before_prefix_withdrawn_for_the_same_cause() {
    let stack = ConformanceFakeRoutingStack::new();
    stack.set_observations(vec![advertising_observation(
        DOMAIN_A,
        "edge-a",
        PeerSessionState::Established,
        PathHealth::Up,
        &[10, 11],
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
    stack.set_observations(vec![advertising_observation(
        DOMAIN_A,
        "edge-a",
        PeerSessionState::Established,
        PathHealth::Up,
        &[10],
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
    stack.set_observations(vec![advertising_observation(
        DOMAIN_A,
        "edge-a",
        PeerSessionState::Established,
        PathHealth::Up,
        &[10],
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
async fn observation_captured_before_apply_cannot_overwrite_new_export_epoch() {
    let stack = ConformanceFakeRoutingStack::new();
    stack.set_observations(vec![observation(
        DOMAIN_A,
        "edge-a",
        PeerSessionState::Established,
        PathHealth::Up,
    )]);
    let service = Arc::new(service(stack.clone()));
    service.initialize().await.unwrap();
    let mut events = service.subscribe_events();

    let gate = stack.gate_next_observation();
    let old_poll = tokio::spawn({
        let service = Arc::clone(&service);
        async move { service.observe_once().await }
    });
    gate.wait_captured().await;

    service
        .reconcile(domain(DOMAIN_A), prefixes(&[10]), Some(lease(1)))
        .await
        .unwrap();
    stack.set_observations(vec![advertising_observation(
        DOMAIN_A,
        "edge-a",
        PeerSessionState::Established,
        PathHealth::Up,
        &[10],
    )]);
    gate.release();
    old_poll.await.unwrap().unwrap();

    let pending = service
        .prefix_snapshot(domain(DOMAIN_A), prefix(10))
        .unwrap();
    assert_eq!(pending.state, PrefixAdvertisementState::Unknown);
    assert!(!collect_events(&mut events)
        .iter()
        .any(|event| matches!(&event.kind, RoutingEventKind::PrefixWithdrawn { .. })));

    service.observe_once().await.unwrap();
    let current = service
        .prefix_snapshot(domain(DOMAIN_A), prefix(10))
        .unwrap();
    assert_eq!(current.state, PrefixAdvertisementState::Advertised);
    assert_eq!(current.advertised_to.len(), 1);
}

#[tokio::test]
async fn observation_captured_after_intent_before_result_cannot_withdraw_new_export_epoch() {
    let stack = ConformanceFakeRoutingStack::new();
    let service = Arc::new(service(stack.clone()));
    service.initialize().await.unwrap();
    service
        .reconcile(domain(DOMAIN_A), prefixes(&[10]), Some(lease(1)))
        .await
        .unwrap();
    stack.set_observations(vec![advertising_observation(
        DOMAIN_A,
        "edge-a",
        PeerSessionState::Established,
        PathHealth::Up,
        &[10],
    )]);
    service.observe_once().await.unwrap();
    assert_eq!(
        service
            .prefix_snapshot(domain(DOMAIN_A), prefix(10))
            .unwrap()
            .state,
        PrefixAdvertisementState::Advertised
    );
    let mut events = service.subscribe_events();

    let apply_gate = stack.gate_next_apply();
    let apply = tokio::spawn({
        let service = Arc::clone(&service);
        async move {
            service
                .reconcile(domain(DOMAIN_A), prefixes(&[20]), Some(lease(2)))
                .await
        }
    });
    apply_gate.wait_landed().await;

    // This poll has the new intent revision but predates its authoritative
    // adapter result. Its old export view must not withdraw the new prefix.
    stack.set_observations(vec![advertising_observation(
        DOMAIN_A,
        "edge-a",
        PeerSessionState::Established,
        PathHealth::Up,
        &[10],
    )]);
    let observation_gate = stack.gate_next_observation();
    let old_poll = tokio::spawn({
        let service = Arc::clone(&service);
        async move { service.observe_once().await }
    });
    observation_gate.wait_captured().await;

    apply_gate.release();
    apply.await.unwrap().unwrap();
    observation_gate.release();
    old_poll.await.unwrap().unwrap();

    let pending = service
        .prefix_snapshot(domain(DOMAIN_A), prefix(20))
        .unwrap();
    assert_eq!(pending.state, PrefixAdvertisementState::Unknown);
    assert!(!collect_events(&mut events).iter().any(|event| {
        matches!(
            &event.kind,
            RoutingEventKind::PrefixWithdrawn { prefix: withdrawn, .. }
                if withdrawn.prefix() == prefix(20)
        )
    }));

    stack.set_observations(vec![advertising_observation(
        DOMAIN_A,
        "edge-a",
        PeerSessionState::Established,
        PathHealth::Up,
        &[20],
    )]);
    service.observe_once().await.unwrap();
    assert_eq!(
        service
            .prefix_snapshot(domain(DOMAIN_A), prefix(20))
            .unwrap()
            .state,
        PrefixAdvertisementState::Advertised
    );
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
    assert_eq!(report.disposition, ReconcileDisposition::Applied);
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
    assert_eq!(snapshot.state, PrefixAdvertisementState::Unknown);
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
    assert_eq!(report.disposition, ReconcileDisposition::Applied);
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
async fn partial_apply_disconnect_is_cleaned_and_burns_the_generation() {
    let stack = ConformanceFakeRoutingStack::new();
    stack.fail_next_apply(FakeApplyFailure::DisconnectAfterPartialApply);
    let service = service(stack.clone());

    // The apply fails ambiguously after originating only prefix 10.
    let error = service
        .reconcile(domain(DOMAIN_A), prefixes(&[10, 11]), Some(lease(1)))
        .await
        .unwrap_err();
    assert!(matches!(error, IpsecLbError::Io { .. }));
    assert!(stack.originated(domain(DOMAIN_A)).is_empty());

    // An ambiguous mutation is actively cleaned to known absence and its
    // authority epoch is burned. A retry needs a strictly newer generation.
    let report = service
        .reconcile(domain(DOMAIN_A), prefixes(&[10, 11]), Some(lease(1)))
        .await
        .unwrap();
    assert_eq!(report.disposition, ReconcileDisposition::StaleRejected);
    let report = service
        .reconcile(domain(DOMAIN_A), prefixes(&[10, 11]), Some(lease(2)))
        .await
        .unwrap();
    assert_eq!(report.disposition, ReconcileDisposition::Applied);
    assert_eq!(stack.originated(domain(DOMAIN_A)), prefixes(&[10, 11]));
    for last in [10, 11] {
        let snapshot = service
            .prefix_snapshot(domain(DOMAIN_A), prefix(last))
            .unwrap();
        assert_eq!(snapshot.state, PrefixAdvertisementState::Unknown);
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

    let mut finalized = false;
    for _ in 0..64 {
        if service
            .prefix_snapshot(domain(DOMAIN_A), prefix(10))
            .is_some_and(|snapshot| snapshot.state == PrefixAdvertisementState::Unknown)
        {
            finalized = true;
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(
        finalized,
        "driver must finalize state after caller cancellation"
    );
    assert_eq!(stack.originated(domain(DOMAIN_A)), prefixes(&[10]));
    let report = service
        .reconcile(domain(DOMAIN_A), prefixes(&[10]), Some(lease(1)))
        .await
        .unwrap();
    assert_eq!(report.disposition, ReconcileDisposition::Retained);
}

#[tokio::test]
async fn fake_apply_reports_the_same_captured_policy_outcome_that_it_applied() {
    let stack = ConformanceFakeRoutingStack::new();
    let gate = stack.gate_next_apply();
    let requested = prefixes(&[10]);
    let apply = tokio::spawn({
        let stack = stack.clone();
        let requested = requested.clone();
        async move {
            stack
                .apply_advertisement_set(domain(DOMAIN_A), &requested)
                .await
        }
    });

    gate.wait_landed().await;
    // Changing future policy while the completed side effect is waiting to
    // return must not rewrite the acknowledgement for that side effect.
    stack.reject_prefix(prefix(10));
    gate.release();

    let result = apply.await.unwrap().unwrap();
    assert_eq!(
        result.outcomes.get(&prefix(10)),
        Some(&PrefixApplyOutcome::Accepted)
    );
    assert_eq!(stack.originated(domain(DOMAIN_A)), prefixes(&[10]));
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

    // The priority scheduler queues the drain behind only the parked active
    // mutation; once that driver finishes, withdrawal is the last effect.
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

/// Two queued drivers plus a drain are totally ordered by the bounded priority
/// scheduler: the newer intent overwrites the stale one and drain wins overall.
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

    assert_eq!(report.disposition, ReconcileDisposition::Applied);
    assert_eq!(stack.originated(domain(DOMAIN_A)), prefixes(&[11]));
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
    assert_eq!(snapshot.state, PrefixAdvertisementState::Unknown);
    // The stale driver's prefix left the desired set and was converged out.
    assert!(service
        .prefix_snapshot(domain(DOMAIN_A), prefix(10))
        .is_none_or(|snapshot| snapshot.state != PrefixAdvertisementState::Advertised));
}

#[tokio::test]
async fn cancelled_drain_waiting_for_the_mutation_lock_still_finishes_last() {
    let stack = ConformanceFakeRoutingStack::new();
    let service = Arc::new(service(stack.clone()));
    service.initialize().await.unwrap();
    let gate = stack.gate_next_apply();
    let applying = tokio::spawn({
        let service = Arc::clone(&service);
        async move {
            service
                .reconcile(domain(DOMAIN_A), prefixes(&[10]), Some(lease(1)))
                .await
        }
    });
    gate.wait_landed().await;
    applying.abort();

    let drain = tokio::spawn({
        let service = Arc::clone(&service);
        async move {
            service
                .reconcile(domain(DOMAIN_A), BTreeSet::new(), None)
                .await
        }
    });
    tokio::task::yield_now().await;
    drain.abort();
    gate.release();

    for _ in 0..64 {
        if stack.originated(domain(DOMAIN_A)).is_empty() {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(stack.originated(domain(DOMAIN_A)).is_empty());
    assert!(matches!(
        stack.mutation_log().last(),
        Some(RecordedStackMutation::WithdrawAll { domain: drained })
            if *drained == domain(DOMAIN_A)
    ));
    assert!(service
        .prefix_snapshot(domain(DOMAIN_A), prefix(10))
        .is_none_or(|snapshot| snapshot.state != PrefixAdvertisementState::Advertised));
}

#[tokio::test]
async fn cancelled_drain_during_adapter_mutation_still_finishes() {
    let stack = ConformanceFakeRoutingStack::new();
    let service = Arc::new(service(stack.clone()));
    service
        .reconcile(domain(DOMAIN_A), prefixes(&[10]), Some(lease(1)))
        .await
        .unwrap();
    let gate = stack.gate_next_withdraw();
    let drain = tokio::spawn({
        let service = Arc::clone(&service);
        async move {
            service
                .reconcile(domain(DOMAIN_A), BTreeSet::new(), None)
                .await
        }
    });
    gate.wait_entered().await;
    drain.abort();
    assert_eq!(stack.originated(domain(DOMAIN_A)), prefixes(&[10]));
    gate.release();
    for _ in 0..64 {
        if stack.originated(domain(DOMAIN_A)).is_empty() {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(stack.originated(domain(DOMAIN_A)).is_empty());
}

#[tokio::test]
async fn cancelled_drain_after_unobserved_adapter_success_finalizes_belief() {
    let stack = ConformanceFakeRoutingStack::new();
    let service = Arc::new(service(stack.clone()));
    service
        .reconcile(domain(DOMAIN_A), prefixes(&[10]), Some(lease(1)))
        .await
        .unwrap();
    let gate = stack.gate_next_withdraw_after_effect();
    let drain = tokio::spawn({
        let service = Arc::clone(&service);
        async move {
            service
                .reconcile(domain(DOMAIN_A), BTreeSet::new(), None)
                .await
        }
    });
    gate.wait_entered().await;
    assert!(stack.originated(domain(DOMAIN_A)).is_empty());
    drain.abort();
    gate.release();
    for _ in 0..64 {
        if service
            .prefix_snapshot(domain(DOMAIN_A), prefix(10))
            .is_none_or(|snapshot| snapshot.state == PrefixAdvertisementState::Withdrawn)
        {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(service
        .prefix_snapshot(domain(DOMAIN_A), prefix(10))
        .is_none_or(|snapshot| snapshot.state == PrefixAdvertisementState::Withdrawn));
}

#[tokio::test(start_paused = true)]
async fn queued_apply_that_expires_before_the_mutation_boundary_never_originates() {
    let stack = ConformanceFakeRoutingStack::new();
    let clock = Arc::new(TokioVirtualClock::new());
    let service = Arc::new(
        PrefixAdvertiserService::with_clock(
            stack.clone(),
            PrefixAdvertiserConfig::default(),
            clock,
        )
        .unwrap(),
    );
    service.initialize().await.unwrap();
    let gate = stack.gate_next_apply();
    let first = tokio::spawn({
        let service = Arc::clone(&service);
        async move {
            service
                .reconcile(domain(DOMAIN_A), prefixes(&[10]), Some(short_lease(1, 60)))
                .await
        }
    });
    gate.wait_landed().await;
    let queued = tokio::spawn({
        let service = Arc::clone(&service);
        async move {
            service
                .reconcile(domain(DOMAIN_B), prefixes(&[20]), Some(short_lease(1, 1)))
                .await
        }
    });
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }
    tokio::time::advance(Duration::from_secs(2)).await;
    gate.release();
    let _ = first.await;
    assert!(queued.await.unwrap().is_err());
    assert!(stack.originated(domain(DOMAIN_B)).is_empty());
    assert!(stack
        .apply_calls()
        .iter()
        .all(|call| call.domain != domain(DOMAIN_B)));
}

#[tokio::test(start_paused = true)]
async fn lease_expiry_supersedes_an_in_flight_apply_before_state_commit() {
    let stack = ConformanceFakeRoutingStack::new();
    let clock = Arc::new(TokioVirtualClock::new());
    let service = Arc::new(
        PrefixAdvertiserService::with_clock(
            stack.clone(),
            PrefixAdvertiserConfig::default(),
            clock,
        )
        .unwrap(),
    );
    service.initialize().await.unwrap();
    let gate = stack.gate_next_apply();
    let applying = tokio::spawn({
        let service = Arc::clone(&service);
        async move {
            service
                .reconcile(domain(DOMAIN_A), prefixes(&[10]), Some(short_lease(1, 1)))
                .await
        }
    });
    gate.wait_landed().await;
    assert_eq!(stack.originated(domain(DOMAIN_A)), prefixes(&[10]));
    tokio::time::advance(Duration::from_secs(2)).await;
    let enforcing = tokio::spawn({
        let service = Arc::clone(&service);
        async move { service.enforce_lease_once().await }
    });
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }
    gate.release();

    assert!(applying.await.unwrap().is_err());
    enforcing.await.unwrap().unwrap();
    assert!(stack.originated(domain(DOMAIN_A)).is_empty());
    assert!(service
        .prefix_snapshot(domain(DOMAIN_A), prefix(10))
        .is_none_or(|snapshot| snapshot.state != PrefixAdvertisementState::Advertised));
}

#[tokio::test]
async fn missing_or_extra_adapter_outcome_keys_fail_closed_and_cleanup() {
    for malformed in [
        AdvertisementSetApplyResult::applied(Default::default()),
        AdvertisementSetApplyResult::applied(
            [
                (prefix(10), PrefixApplyOutcome::Accepted),
                (prefix(99), PrefixApplyOutcome::Accepted),
            ]
            .into_iter()
            .collect(),
        ),
    ] {
        let stack = ConformanceFakeRoutingStack::new();
        let service = service(stack.clone());
        stack.override_next_result(malformed);
        let error = service
            .reconcile(domain(DOMAIN_A), prefixes(&[10]), Some(lease(1)))
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            IpsecLbError::AdapterContractViolation {
                code: "outcome_key_set_mismatch"
            }
        ));
        assert!(stack.originated(domain(DOMAIN_A)).is_empty());
        assert!(service
            .prefix_snapshots(domain(DOMAIN_A))
            .iter()
            .all(|snapshot| snapshot.state != PrefixAdvertisementState::Advertised));
    }
}

#[tokio::test]
async fn disposition_outcome_matrix_is_complete_and_violations_clean_up() {
    let requested = prefixes(&[10]);
    let rejected = BTreeMap::from([(
        prefix(10),
        PrefixApplyOutcome::Rejected(PrefixRejectReason::ConfigureFailed),
    )]);
    let invalid = [
        AdvertisementSetApplyResult::applied(BTreeMap::from([(
            prefix(10),
            PrefixApplyOutcome::Unreachable,
        )])),
        AdvertisementSetApplyResult::refused(BTreeMap::from([(
            prefix(10),
            PrefixApplyOutcome::Accepted,
        )])),
        AdvertisementSetApplyResult::refused(BTreeMap::from([(
            prefix(10),
            PrefixApplyOutcome::Unreachable,
        )])),
        AdvertisementSetApplyResult::ambiguous(BTreeMap::from([(
            prefix(10),
            PrefixApplyOutcome::Accepted,
        )])),
        AdvertisementSetApplyResult::ambiguous(rejected.clone()),
    ];
    for result in invalid {
        let stack = ConformanceFakeRoutingStack::new();
        stack.override_next_result(result);
        let error = service(stack.clone())
            .reconcile(domain(DOMAIN_A), requested.clone(), Some(lease(1)))
            .await
            .unwrap_err();
        assert_eq!(
            error,
            IpsecLbError::adapter_contract_violation("disposition_outcome_mismatch")
        );
        assert!(stack.originated(domain(DOMAIN_A)).is_empty());
    }

    for result in [
        AdvertisementSetApplyResult::refused(rejected),
        AdvertisementSetApplyResult::ambiguous(BTreeMap::from([(
            prefix(10),
            PrefixApplyOutcome::Unreachable,
        )])),
    ] {
        let stack = ConformanceFakeRoutingStack::new();
        stack.override_next_result(result);
        let report = service(stack.clone())
            .reconcile(domain(DOMAIN_A), requested.clone(), Some(lease(1)))
            .await
            .unwrap();
        assert_eq!(report.disposition, ReconcileDisposition::PartiallyRejected);
        assert!(stack.originated(domain(DOMAIN_A)).is_empty());
    }
}

#[tokio::test]
async fn contract_error_survives_failed_cleanup_and_quarantines_complete_union() {
    let stack = ConformanceFakeRoutingStack::new();
    let service = Arc::new(service(stack.clone()));
    let gate = stack.gate_next_apply();
    stack.override_next_result(AdvertisementSetApplyResult::refused(BTreeMap::from([(
        prefix(10),
        PrefixApplyOutcome::Accepted,
    )])));
    let applying = tokio::spawn({
        let service = Arc::clone(&service);
        async move {
            service
                .reconcile(domain(DOMAIN_A), prefixes(&[10]), Some(lease(1)))
                .await
        }
    });
    gate.wait_landed().await;
    stack.set_unreachable(true);
    gate.release();
    let error = applying.await.unwrap().unwrap_err();
    assert_eq!(
        error,
        IpsecLbError::adapter_contract_violation("disposition_outcome_mismatch")
    );
    let snapshots = service.prefix_snapshots(domain(DOMAIN_A));
    assert_eq!(snapshots.len(), 1);
    assert_eq!(snapshots[0].state, PrefixAdvertisementState::Unknown);

    // A disjoint intent cannot expand the uncertainty set while quarantined.
    assert!(service
        .reconcile(domain(DOMAIN_A), prefixes(&[99]), Some(lease(2)))
        .await
        .is_err());
    let snapshots = service.prefix_snapshots(domain(DOMAIN_A));
    assert_eq!(snapshots.len(), 1);
    assert_eq!(snapshots[0].prefix.prefix(), prefix(10));

    stack.set_unreachable(false);
    service.enforce_lease_once().await.unwrap();
    assert!(service.prefix_snapshots(domain(DOMAIN_A)).is_empty());
    service
        .reconcile(domain(DOMAIN_A), prefixes(&[99]), Some(lease(3)))
        .await
        .unwrap();
    assert_eq!(stack.originated(domain(DOMAIN_A)), prefixes(&[99]));
}

#[tokio::test(start_paused = true)]
async fn simultaneous_expiry_is_one_domain_bounded_adapter_mutation() {
    const DOMAIN_COUNT: u64 = 32;
    let domains: Vec<RoutingDomainTag> = (0..DOMAIN_COUNT)
        .map(|offset| domain(DOMAIN_A + offset))
        .collect();
    let stack = ConformanceFakeRoutingStack::with_domains(domains.iter().copied());
    let clock = Arc::new(TokioVirtualClock::new());
    let service = PrefixAdvertiserService::with_clock(
        stack.clone(),
        PrefixAdvertiserConfig::default(),
        clock,
    )
    .unwrap();
    for (index, domain) in domains.iter().enumerate() {
        service
            .reconcile(
                *domain,
                prefixes(&[u8::try_from(index).unwrap()]),
                Some(short_lease(1, 1)),
            )
            .await
            .unwrap();
    }
    tokio::time::advance(Duration::from_secs(2)).await;
    service.enforce_lease_once().await.unwrap();

    let batches = stack.withdraw_batch_calls();
    assert_eq!(batches.len(), 1);
    assert_eq!(batches[0], domains.into_iter().collect());
}

#[tokio::test]
async fn malformed_observation_marks_connecting_path_unknown_before_error() {
    let stack = ConformanceFakeRoutingStack::new();
    let service = service(stack.clone());
    let mut events = service.subscribe_events();
    stack.set_observations(vec![observation(
        DOMAIN_A,
        "edge_a",
        PeerSessionState::Connecting,
        PathHealth::Up,
    )]);
    service.observe_once().await.unwrap();
    let _ = collect_events(&mut events);

    let mut malformed = Vec::new();
    for index in 0..=MAX_ROUTING_PEERS_TOTAL {
        malformed.push(PeerObservation {
            domain: domain(DOMAIN_A),
            peer: PeerIdentity::named(format!("p{index}")),
            session: PeerSessionState::Connecting,
            path_health: PathHealth::Up,
            advertised_prefixes: BTreeSet::new(),
        });
    }
    stack.set_observations(malformed);
    assert!(service.observe_once().await.is_err());
    let events = collect_events(&mut events);
    assert!(events.iter().any(|event| matches!(
        &event.kind,
        RoutingEventKind::PathHealthChanged {
            domain: event_domain,
            peer,
            health: PathHealth::Unknown,
        } if *event_domain == domain(DOMAIN_A) && peer.name() == "edge_a"
    )));
}

#[tokio::test]
async fn startup_withdraws_state_left_by_a_previous_process_before_advertising() {
    let stack = ConformanceFakeRoutingStack::new();
    stack.seed_originated(domain(DOMAIN_A), prefixes(&[42]));
    let service = service(stack.clone());

    service.initialize().await.unwrap();
    assert!(stack.originated(domain(DOMAIN_A)).is_empty());
    assert_eq!(
        stack.mutation_log().first(),
        Some(&RecordedStackMutation::WithdrawAll {
            domain: domain(DOMAIN_A),
        })
    );

    service
        .reconcile(domain(DOMAIN_A), prefixes(&[10]), Some(lease(1)))
        .await
        .unwrap();
    assert_eq!(stack.originated(domain(DOMAIN_A)), prefixes(&[10]));
}

#[tokio::test]
async fn startup_discovers_and_withdraws_stale_state_for_a_removed_domain() {
    let stack = ConformanceFakeRoutingStack::with_domains([domain(DOMAIN_A)]);
    stack.seed_originated(domain(DOMAIN_B), prefixes(&[42]));
    let service =
        PrefixAdvertiserService::new(stack.clone(), PrefixAdvertiserConfig::default()).unwrap();

    service.initialize().await.unwrap();

    assert!(stack.originated(domain(DOMAIN_B)).is_empty());
    assert_eq!(
        stack.withdraw_all_calls(),
        vec![domain(DOMAIN_A), domain(DOMAIN_B)]
    );
    service
        .reconcile(domain(DOMAIN_A), prefixes(&[10]), Some(lease(1)))
        .await
        .unwrap();
    assert_eq!(stack.originated(domain(DOMAIN_A)), prefixes(&[10]));
}

#[tokio::test]
async fn failed_startup_cleanup_blocks_advertising_and_a_later_call_retries() {
    let stack = ConformanceFakeRoutingStack::new();
    stack.seed_originated(domain(DOMAIN_A), prefixes(&[42]));
    stack.set_unreachable(true);
    let service = service(stack.clone());

    assert!(service.initialize().await.is_err());
    assert!(service
        .reconcile(domain(DOMAIN_A), prefixes(&[10]), Some(lease(1)))
        .await
        .is_err());
    assert_eq!(stack.originated(domain(DOMAIN_A)), prefixes(&[42]));

    stack.set_unreachable(false);
    service.initialize().await.unwrap();
    assert!(stack.originated(domain(DOMAIN_A)).is_empty());
    service
        .reconcile(domain(DOMAIN_A), prefixes(&[10]), Some(lease(1)))
        .await
        .unwrap();
    assert_eq!(stack.originated(domain(DOMAIN_A)), prefixes(&[10]));
}

#[test]
fn hard_prefix_configuration_ceiling_cannot_be_raised() {
    let config = PrefixAdvertiserConfig {
        max_prefixes_per_domain: MAX_ADVERTISED_PREFIXES_PER_DOMAIN + 1,
        ..PrefixAdvertiserConfig::default()
    };
    assert!(PrefixAdvertiserService::new(ConformanceFakeRoutingStack::new(), config).is_err());
}

#[test]
fn hard_domain_and_service_time_bounds_cannot_be_raised() {
    let too_many_domains =
        (1..=(MAX_ADVERTISEMENT_ROUTING_DOMAINS as u64 + 1)).map(RoutingDomainTag::new);
    assert!(PrefixAdvertiserService::new(
        ConformanceFakeRoutingStack::with_domains(too_many_domains),
        PrefixAdvertiserConfig::default(),
    )
    .is_err());

    for config in [
        PrefixAdvertiserConfig {
            poll_interval: Duration::from_secs(61),
            ..PrefixAdvertiserConfig::default()
        },
        PrefixAdvertiserConfig {
            peer_retention_secs: 86_401,
            ..PrefixAdvertiserConfig::default()
        },
    ] {
        assert!(PrefixAdvertiserService::new(ConformanceFakeRoutingStack::new(), config).is_err());
    }

    let service = service(ConformanceFakeRoutingStack::new());
    assert_eq!(
        service.lease_enforcement_bound(),
        PrefixAdvertiserConfig::default().poll_interval + Duration::from_secs(15)
    );
}

#[tokio::test]
async fn hostile_observation_snapshots_are_rejected_before_state_growth() {
    let stack = ConformanceFakeRoutingStack::new();
    let service = service(stack.clone());
    service.initialize().await.unwrap();

    stack.set_observations(vec![PeerObservation {
        domain: domain(DOMAIN_A),
        peer: PeerIdentity::named("x".repeat(MAX_ROUTING_PEER_NAME_LEN + 1)),
        session: PeerSessionState::Established,
        path_health: PathHealth::Up,
        advertised_prefixes: BTreeSet::new(),
    }]);
    assert!(service.observe_once().await.is_err());

    stack.set_observations(vec![PeerObservation {
        domain: domain(DOMAIN_A),
        peer: PeerIdentity::named("edge-a\nforged-event"),
        session: PeerSessionState::Established,
        path_health: PathHealth::Up,
        advertised_prefixes: BTreeSet::new(),
    }]);
    assert!(service.observe_once().await.is_err());

    stack.set_observations(
        (0..=MAX_ROUTING_PEERS_TOTAL)
            .map(|index| PeerObservation {
                domain: domain(DOMAIN_A),
                peer: PeerIdentity::named(format!("peer_{index}")),
                session: PeerSessionState::Established,
                path_health: PathHealth::Up,
                advertised_prefixes: BTreeSet::new(),
            })
            .collect(),
    );
    assert!(service.observe_once().await.is_err());
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
        vec![
            domain(DOMAIN_A),
            domain(DOMAIN_B),
            domain(DOMAIN_A),
            domain(DOMAIN_B),
        ]
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
async fn same_named_peer_events_preserve_their_routing_domain() {
    let stack = ConformanceFakeRoutingStack::new();
    stack.set_observations(vec![
        observation(
            DOMAIN_A,
            "shared-edge",
            PeerSessionState::Established,
            PathHealth::Down,
        ),
        observation(
            DOMAIN_B,
            "shared-edge",
            PeerSessionState::Connecting,
            PathHealth::AdminDown,
        ),
    ]);
    let service = service(stack);
    let mut receiver = service.subscribe_events();

    service.observe_once().await.unwrap();
    let events = collect_events(&mut receiver);
    let session_domains: BTreeSet<RoutingDomainTag> = events
        .iter()
        .filter_map(|event| match &event.kind {
            RoutingEventKind::PeerSessionChanged { domain, peer, .. }
                if peer.name() == "shared-edge" =>
            {
                Some(*domain)
            }
            _ => None,
        })
        .collect();
    let path_domains: BTreeSet<RoutingDomainTag> = events
        .iter()
        .filter_map(|event| match &event.kind {
            RoutingEventKind::PathHealthChanged { domain, peer, .. }
                if peer.name() == "shared-edge" =>
            {
                Some(*domain)
            }
            _ => None,
        })
        .collect();

    assert_eq!(
        session_domains,
        BTreeSet::from([domain(DOMAIN_A), domain(DOMAIN_B)])
    );
    assert_eq!(
        path_domains,
        BTreeSet::from([domain(DOMAIN_A), domain(DOMAIN_B)])
    );
}

#[tokio::test]
async fn same_peer_identity_in_another_domain_cannot_mask_session_down_reason() {
    let stack = ConformanceFakeRoutingStack::new();
    let service = service(stack.clone());
    service
        .reconcile(domain(DOMAIN_A), prefixes(&[10]), Some(lease(1)))
        .await
        .unwrap();
    service
        .reconcile(domain(DOMAIN_B), prefixes(&[11]), Some(lease(2)))
        .await
        .unwrap();
    stack.set_observations(vec![
        advertising_observation(
            DOMAIN_A,
            "shared-edge",
            PeerSessionState::Established,
            PathHealth::Up,
            &[10],
        ),
        advertising_observation(
            DOMAIN_B,
            "shared-edge",
            PeerSessionState::Established,
            PathHealth::Up,
            &[11],
        ),
    ]);
    service.observe_once().await.unwrap();
    let mut events = service.subscribe_events();

    stack.set_observations(vec![
        observation(
            DOMAIN_A,
            "shared-edge",
            PeerSessionState::Down,
            PathHealth::Down,
        ),
        advertising_observation(
            DOMAIN_B,
            "shared-edge",
            PeerSessionState::Established,
            PathHealth::Up,
            &[11],
        ),
    ]);
    service.observe_once().await.unwrap();

    assert!(collect_events(&mut events).iter().any(|event| matches!(
        event.kind,
        RoutingEventKind::PrefixWithdrawn {
            prefix: withdrawn,
            reason: PrefixWithdrawReason::PeerSessionDown,
        } if withdrawn == AdvertisedPrefix::new(domain(DOMAIN_A), prefix(10))
    )));
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
                        prop_assert_eq!(report.disposition, ReconcileDisposition::Applied);
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
                            ReconcileDisposition::Applied
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
                        // The fake applied the full set before losing its
                        // acknowledgement; the service then converged the
                        // whole domain to known absence and burned the epoch.
                        expected[index] = BTreeSet::new();
                        intents[index] = Some((generation, subset));
                        live[index] = false;
                        ambiguous[index] = false;
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
