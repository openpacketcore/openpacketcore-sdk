use super::{pool::*, wire::Class};
use opc_types::SpiffeId;
use std::{sync::Arc, time::Duration};
use tokio::time::Instant;

fn peer(name: &str) -> SpiffeId {
    SpiffeId::new(format!(
        "spiffe://example.test/tenant/example/ns/example/sa/worker/nf/smf/instance/{name}"
    ))
    .unwrap()
}

#[tokio::test(start_paused = true)]
async fn shared_worker_identity_has_an_independent_allowance_for_each_slot() {
    let pools = ProofPools::new(ProofBudgets::default()).unwrap();
    let shared = peer("fleet-worker");
    for class in [
        Class::SafetyControl,
        Class::Emergency,
        Class::EmergencyClassification,
        Class::Normal,
        Class::Maintenance,
    ] {
        for share in [
            ProofShare::Candidate,
            ProofShare::WorkerUnproven,
            ProofShare::WorkerCurrent,
            ProofShare::Controller,
        ] {
            let first = pools.reserve(class, share, &shared, [1; 32]).await.unwrap();
            let second = pools.reserve(class, share, &shared, [1; 32]).await.unwrap();
            let same_slot = pools.reserve(class, share, &shared, [1; 32]);
            tokio::pin!(same_slot);
            assert!(futures_util::poll!(&mut same_slot).is_pending());
            let another_slot = pools.reserve(class, share, &shared, [2; 32]);
            tokio::pin!(another_slot);
            let another_slot = match futures_util::poll!(&mut another_slot) {
                std::task::Poll::Ready(Ok(credit)) => credit,
                _ => panic!("one slot must not consume another slot's per-identity allowance"),
            };
            drop((another_slot, first, second));
            assert!(futures_util::poll!(&mut same_slot).is_ready());
        }
    }
    // Independent peer/slot caps remain inside the same bounded class pool.
    let mut held = Vec::new();
    for scope in 1..=4 {
        held.push(
            pools
                .reserve(
                    Class::Normal,
                    ProofShare::WorkerCurrent,
                    &shared,
                    [scope; 32],
                )
                .await
                .unwrap(),
        );
    }
    let fifth = pools.reserve(Class::Normal, ProofShare::WorkerCurrent, &shared, [5; 32]);
    tokio::pin!(fifth);
    assert!(
        futures_util::poll!(&mut fifth).is_pending(),
        "slot count cannot expand the global budget"
    );
    held.pop();
    assert!(futures_util::poll!(&mut fifth).is_ready());
}

#[tokio::test(start_paused = true)]
async fn verified_proof_retains_bounded_bytes_through_an_untimed_dispatch_queue_wait() {
    let pools = ProofPools::new(ProofBudgets::default()).unwrap();
    let credit = pools
        .reserve(
            Class::Normal,
            ProofShare::WorkerUnproven,
            &peer("worker"),
            [1; 32],
        )
        .await
        .unwrap();
    let (challenge, retained) = credit
        .verify_then_retain(
            Instant::now() + Duration::from_secs(5),
            |challenge| async move { Ok(challenge) },
        )
        .await
        .unwrap();
    assert_ne!(challenge, [0; 32]);
    tokio::time::advance(Duration::from_secs(60)).await;
    assert_eq!(
        pools.used(Class::Normal, ProofShare::WorkerUnproven),
        1,
        "consumed proof still owns its bounded request while dispatch waits"
    );
    drop(retained);
    assert_eq!(pools.used(Class::Normal, ProofShare::WorkerUnproven), 0);
}

#[tokio::test(start_paused = true)]
async fn same_svid_siblings_cannot_spend_proven_current_control_or_emergency_shares() {
    let pools = ProofPools::new(ProofBudgets::default()).unwrap();
    for class in [Class::SafetyControl, Class::Emergency] {
        let shared = peer("slot-0");
        let sibling1 = pools
            .reserve(class, ProofShare::WorkerUnproven, &peer("slot-0"), [1; 32])
            .await
            .unwrap();
        let sibling2 = pools
            .reserve(class, ProofShare::WorkerUnproven, &peer("slot-0"), [1; 32])
            .await
            .unwrap();
        let mut sibling3 =
            Box::pin(pools.reserve(class, ProofShare::WorkerUnproven, &shared, [1; 32]));
        assert!(futures_util::poll!(&mut sibling3).is_pending());
        let before = Instant::now();
        let current = tokio::time::timeout(
            Duration::from_millis(1),
            pools.reserve(class, ProofShare::WorkerCurrent, &peer("slot-0"), [1; 32]),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(Instant::now() - before < Duration::from_secs(5));
        assert_eq!(pools.used(class, ProofShare::WorkerUnproven), 2);
        assert_eq!(pools.used(class, ProofShare::WorkerCurrent), 1);
        drop((current, sibling1, sibling2));
        assert!(futures_util::poll!(&mut sibling3).is_ready());
    }
}

#[tokio::test(start_paused = true)]
async fn cancelled_and_expired_challenges_release_both_credits_and_do_not_start_early() {
    let pools = Arc::new(ProofPools::new(ProofBudgets::default()).unwrap());
    let first = pools
        .reserve(
            Class::Normal,
            ProofShare::Candidate,
            &peer("slot-0"),
            [1; 32],
        )
        .await
        .unwrap();
    let second = pools
        .reserve(
            Class::Normal,
            ProofShare::Candidate,
            &peer("slot-0"),
            [1; 32],
        )
        .await
        .unwrap();
    let pending = pools.clone();
    let task = tokio::spawn(async move {
        let credit = pending
            .reserve(
                Class::Normal,
                ProofShare::Candidate,
                &peer("slot-0"),
                [1; 32],
            )
            .await
            .unwrap();
        credit
            .with_challenge(Instant::now() + Duration::from_secs(30), |_| async {
                std::future::pending::<Result<(), ProofPoolError>>().await
            })
            .await
    });
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(20)).await;
    assert!(
        !task.is_finished(),
        "waiting for capacity has no implicit deadline"
    );
    drop(first);
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(5)).await;
    assert_eq!(task.await.unwrap().unwrap_err(), ProofPoolError::Deadline);
    assert_eq!(pools.used(Class::Normal, ProofShare::Candidate), 1);
    drop(second);
    let credit = pools
        .reserve(
            Class::Normal,
            ProofShare::Candidate,
            &peer("slot-0"),
            [1; 32],
        )
        .await
        .unwrap();
    let blocked = tokio::spawn(async move {
        credit
            .with_challenge(Instant::now() + Duration::from_secs(30), |_| async {
                std::future::pending::<Result<(), ProofPoolError>>().await
            })
            .await
    });
    tokio::task::yield_now().await;
    blocked.abort();
    let _ = blocked.await;
    assert_eq!(pools.used(Class::Normal, ProofShare::Candidate), 0);
}

#[tokio::test(start_paused = true)]
async fn role_and_class_reservations_are_independent_and_challenges_are_fresh() {
    let pools = ProofPools::new(ProofBudgets::default()).unwrap();
    let mut held = Vec::new();
    for number in 0..4 {
        for _ in 0..2 {
            held.push(
                pools
                    .reserve(
                        Class::Normal,
                        ProofShare::Controller,
                        &peer(&format!("peer-{number}")),
                        [1; 32],
                    )
                    .await
                    .unwrap(),
            );
        }
    }
    assert_eq!(pools.used(Class::Normal, ProofShare::Controller), 8);
    let candidate = pools
        .reserve(
            Class::Normal,
            ProofShare::Candidate,
            &peer("peer-0"),
            [1; 32],
        )
        .await
        .unwrap();
    let control = pools
        .reserve(
            Class::SafetyControl,
            ProofShare::Controller,
            &peer("peer-0"),
            [1; 32],
        )
        .await
        .unwrap();
    let nonce1 = candidate
        .with_challenge(
            Instant::now() + Duration::from_secs(1),
            |nonce| async move { Ok(nonce) },
        )
        .await
        .unwrap();
    let nonce2 = control
        .with_challenge(
            Instant::now() + Duration::from_secs(1),
            |nonce| async move { Ok(nonce) },
        )
        .await
        .unwrap();
    assert_ne!(nonce1, [0; 32]);
    assert_ne!(nonce1, nonce2);
}

#[test]
fn all_reserved_buckets_exist_and_fit_the_fixed_global_bound_before_activation() {
    assert_eq!(ProofBudgets::default().total().unwrap(), 120);
    let missing = ProofBudgets {
        controller: 0,
        ..ProofBudgets::default()
    };
    assert!(ProofPools::new(missing).is_err());
    let oversized = ProofBudgets {
        current_worker: 6,
        ..ProofBudgets::default()
    };
    assert!(ProofPools::new(oversized).is_err());
    let overflow = ProofBudgets {
        candidate: usize::MAX,
        ..ProofBudgets::default()
    };
    assert!(ProofPools::new(overflow).is_err());
}
