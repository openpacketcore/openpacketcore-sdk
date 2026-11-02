use super::*;
use changes::tests::{apply, time};
use key_retention_tests::{command, ephemeral_request, prune_intent};

#[test]
fn native_epoch_floor_keeps_recently_dead_key_exact() {
    let (storage, old) = key_retention_tests::retired_key_fixture();
    let observed = storage.business.observe_at(old.key(), time(2)).unwrap();
    assert!(observed.record().is_none());
    assert_eq!(observed.current_fence(), old.fence());
    assert!(storage.business.keys.contains_key(old.key()));
}

#[test]
fn native_epoch_floor_prepared_create_survives_unrelated_retirement() {
    let (mut storage, old) = key_retention_tests::acquired_fixture();
    let mut fresh = old.key().clone();
    fresh.stable_id = bytes::Bytes::from_static(b"epoch-floor-fresh")
        .try_into()
        .unwrap();
    let observed = storage.business.observe_at(&fresh, time(2)).unwrap();
    assert_eq!(observed.current_fence().get(), 0);
    let request = ephemeral_request(
        fresh.clone(),
        5,
        observed.current_fence().get(),
        storage.business.history().unwrap().active_epoch().unwrap(),
        time(2),
    );
    let released = apply(
        &mut storage,
        &[command(3, SessionMutationIntent::ReleaseLease(old))],
    );
    assert!(released.responses[0].result.is_ok());
    let prune = command(4, prune_intent(&storage));
    assert!(apply(&mut storage, &[prune]).responses[0].result.is_ok());
    let result = apply(
        &mut storage,
        &[changes::tests::command(5, &request, time(2), false)],
    );
    let Ok(SessionMutationOutcome::FencedTransition(outcome)) = &result.responses[0].result else {
        panic!(
            "an unrelated retirement must not stale a prepared create: {:?}",
            result.responses[0].result
        );
    };
    assert_eq!(outcome.lease().fence().get(), 1);
    assert_eq!(outcome.lease().key(), &fresh);
}

#[cfg(feature = "lab-memory")]
#[tokio::test(start_paused = true)]
async fn native_epoch_floor_matches_fake_through_two_real_threshold_rotations() {
    use crate::{Clock, FakeSessionBackend, SessionBackend, SessionLeaseManager};
    use changes::tests::apply_after_journal_admission as apply;
    use futures_util::StreamExt;
    use std::time::Duration;

    #[derive(Debug)]
    struct FixedClock;
    impl Clock for FixedClock {
        fn now_utc(&self) -> Timestamp {
            time(2)
        }
    }

    let (mut native, _, live) = changes::tests::fixture();
    let fake = FakeSessionBackend::in_memory_lab().with_clock(Arc::new(FixedClock));
    let initial = native.business.replication_log(1, 1, &|| Ok(())).unwrap();
    fake.replicate_entry(initial[0].clone()).await.unwrap();
    let mut watch = fake.watch(2).await.unwrap();
    let mut index = 2;
    let window = crate::key_retention::RETIRED_KEYS_PER_EPOCH;
    let mut fresh = live.lease().key().clone();
    fresh.stable_id = bytes::Bytes::from_static(b"never-created-parity-key")
        .try_into()
        .unwrap();
    let prepare_request = |name: &'static [u8], nonce| {
        let mut key = fresh.clone();
        key.stable_id = bytes::Bytes::from_static(name).try_into().unwrap();
        ephemeral_request(
            key,
            nonce,
            0,
            native.business.history().unwrap().active_epoch().unwrap(),
            time(2),
        )
    };
    let after_one = prepare_request(b"one-rotation-prepared-parity", 1_000_000);
    let after_two = prepare_request(b"two-rotation-prepared-parity", 1_000_001);
    let lab_request = |request: &FencedTransitionV2Request| {
        crate::FencedTransitionRequest::new(
            crate::FencedTransitionRequestId::new(),
            request.lease().clone(),
            request.mutation().clone(),
        )
        .unwrap()
    };
    let fake_after_one = fake
        .prepare_fenced_transition(lab_request(&after_one))
        .await
        .unwrap();
    let fake_after_two = fake
        .prepare_fenced_transition(lab_request(&after_two))
        .await
        .unwrap();
    let mut first_rotation_probed = false;
    let key = |number: u64| {
        let mut key = live.lease().key().clone();
        key.stable_id = bytes::Bytes::copy_from_slice(&number.to_be_bytes())
            .try_into()
            .unwrap();
        key
    };
    for start in (0..2 * window).step_by(256) {
        let entries = (start..start + 256)
            .map(|number| {
                command(
                    index + number - start,
                    SessionMutationIntent::AcquireLease {
                        key: key(number),
                        owner: live.lease().owner().clone(),
                        ttl: Duration::from_secs(60),
                    },
                )
            })
            .collect::<Vec<_>>();
        let acquired = apply(&mut native, &entries);
        assert_eq!(acquired.responses.len(), 256);
        assert_eq!(acquired.notifications.len(), 256);
        let mut leases = Vec::new();
        for (offset, (response, notification)) in acquired
            .responses
            .iter()
            .zip(&acquired.notifications)
            .enumerate()
        {
            let Ok(SessionMutationOutcome::Lease(lease)) = &response.result else {
                panic!("native parity acquire failed: {:?}", response.result);
            };
            let counterpart = fake
                .acquire(
                    &key(start + offset as u64),
                    live.lease().owner().clone(),
                    Duration::from_secs(60),
                )
                .await
                .unwrap();
            assert_eq!(&counterpart, lease);
            let replicated = watch.next().await.unwrap().unwrap();
            assert_eq!(replicated.op, notification.op);
            assert_eq!(replicated.sequence, notification.sequence);
            assert_eq!(replicated.timestamp, notification.timestamp);
            leases.push(lease.clone());
        }
        index += 256;
        let entries = leases
            .iter()
            .enumerate()
            .map(|(offset, lease)| {
                command(
                    index + offset as u64,
                    SessionMutationIntent::ReleaseLease(lease.clone()),
                )
            })
            .collect::<Vec<_>>();
        let released = apply(&mut native, &entries);
        assert!(released
            .responses
            .iter()
            .all(|response| response.result.is_ok()));
        assert_eq!(released.notifications.len(), 256);
        for (lease, notification) in leases.iter().zip(&released.notifications) {
            fake.release(lease.clone()).await.unwrap();
            let replicated = watch.next().await.unwrap().unwrap();
            assert_eq!(replicated.op, notification.op);
            assert_eq!(replicated.sequence, notification.sequence);
            assert_eq!(replicated.timestamp, notification.timestamp);
        }
        index += 256;
        let before = fake.key_retention_for_test().await;
        let expected = native.business.frontiers.retention.keys;
        assert_eq!(before.0, expected);
        assert_eq!(before.1, native.business.keys.len());
        assert!(before.2 <= 2 * window as usize);
        for observed_key in [&fresh, live.lease().key(), &key(0), &key(start + 255)] {
            assert_eq!(
                fake.observe_fenced_transition(observed_key).await.unwrap(),
                native.business.observe_at(observed_key, time(2)).unwrap()
            );
        }
        assert_eq!(
            fake.key_retention_for_test().await,
            before,
            "observations never rotate or tag"
        );
        if expected.epoch == 1 && !first_rotation_probed {
            assert_eq!(expected.floor_prev, 0);
            // Native pure-V2 global pruning remains a separate contract.
            // Establish the same committed cleanup cut in both backends
            // before comparing the prepared transitions themselves.
            let cleanup = apply(
                &mut native,
                &[command(
                    index,
                    SessionMutationIntent::RefreshTtl {
                        lease: live.lease().clone(),
                        ttl: Duration::from_secs(60),
                    },
                )],
            );
            index += 1;
            assert!(cleanup.responses[0].result.is_ok());
            fake.refresh_ttl(live.lease(), Duration::from_secs(60))
                .await
                .unwrap();
            let replicated = watch.next().await.unwrap().unwrap();
            assert_eq!(replicated.op, cleanup.notifications[0].op);
            assert_eq!(replicated.sequence, cleanup.notifications[0].sequence);
            let expected = native.business.frontiers.retention.keys;
            assert_eq!(fake.key_retention_for_test().await.0, expected);
            let applied = apply(
                &mut native,
                &[changes::tests::command(index, &after_one, time(2), false)],
            );
            index += 1;
            let Ok(SessionMutationOutcome::FencedTransition(outcome)) =
                &applied.responses[0].result
            else {
                panic!("native preparation survives one rotation");
            };
            assert_eq!(
                fake.fenced_transition(&fake_after_one).await.unwrap(),
                *outcome
            );
            assert_eq!(outcome.lease().fence().get(), 1);
            let replicated = watch.next().await.unwrap().unwrap();
            assert_eq!(replicated.op, applied.notifications[0].op);
            assert_eq!(replicated.sequence, applied.notifications[0].sequence);
            assert_eq!(fake.key_retention_for_test().await.0, expected);
            first_rotation_probed = true;
        }
    }
    // The final released row becomes dead at this committing boundary.
    let entry = command(
        index,
        SessionMutationIntent::RenewLease {
            lease: live.lease().clone(),
            ttl: Duration::from_secs(60),
        },
    );
    let renewed = apply(&mut native, &[entry]);
    assert!(renewed.responses[0].result.is_ok());
    fake.renew(live.lease(), Duration::from_secs(60))
        .await
        .unwrap();
    let replicated = watch.next().await.unwrap().unwrap();
    assert_eq!(replicated.op, renewed.notifications[0].op);
    let actual = fake.key_retention_for_test().await;
    assert_eq!(actual.0, native.business.frontiers.retention.keys);
    assert_eq!(actual.0.epoch, 2);
    assert_eq!(actual.0.retired_count, 0);
    assert_eq!(
        actual.0.last_rotation,
        Some(crate::key_retention::RotationReason::Threshold)
    );
    assert!(first_rotation_probed);
    assert_eq!(actual.1, window as usize + 2);
    assert_eq!(actual.2, window as usize);
    assert!(!native.business.keys.contains_key(&key(0)));
    assert!(
        2 < actual.0.floor_prev,
        "first allocated churn fence was forgotten safely"
    );
    assert_eq!(
        fake.observe_fenced_transition(&key(0))
            .await
            .unwrap()
            .current_fence()
            .get(),
        actual.0.floor_cur
    );
    assert_eq!(
        fake.observe_fenced_transition(&key(2 * window - 1))
            .await
            .unwrap(),
        native
            .business
            .observe_at(&key(2 * window - 1), time(2))
            .unwrap()
    );
    let sequence = fake.max_replication_sequence().await.unwrap();
    let rejected = apply(
        &mut native,
        &[changes::tests::command(
            index + 1,
            &after_two,
            time(2),
            false,
        )],
    );
    assert_eq!(rejected.responses[0].result, Err(StoreError::StaleFence));
    assert!(rejected.notifications.is_empty());
    assert_eq!(
        fake.fenced_transition(&fake_after_two).await,
        Err(crate::FencedTransitionExecuteError::Rejected(
            StoreError::StaleFence
        ))
    );
    assert_eq!(fake.key_retention_for_test().await, actual);
    assert_eq!(fake.max_replication_sequence().await.unwrap(), sequence);
    assert!(fake.get(after_two.lease().key()).await.unwrap().is_none());
    assert!(!native.business.keys.contains_key(after_two.lease().key()));
    let observed = fake
        .observe_fenced_transition(after_two.lease().key())
        .await
        .unwrap()
        .current_fence();
    assert_eq!(observed.get(), actual.0.floor_cur);
    let fresh_request = ephemeral_request(
        after_two.lease().key().clone(),
        1_000_002,
        observed.get(),
        native.business.history().unwrap().active_epoch().unwrap(),
        time(2),
    );
    let fake_fresh = fake
        .prepare_fenced_transition(lab_request(&fresh_request))
        .await
        .unwrap();
    let applied = apply(
        &mut native,
        &[changes::tests::command(
            index + 2,
            &fresh_request,
            time(2),
            false,
        )],
    );
    let Ok(SessionMutationOutcome::FencedTransition(outcome)) = &applied.responses[0].result else {
        panic!("native re-observed preparation succeeds");
    };
    assert_eq!(fake.fenced_transition(&fake_fresh).await.unwrap(), *outcome);
    assert_eq!(outcome.lease().fence().get(), observed.get() + 1);
    let replicated = watch.next().await.unwrap().unwrap();
    assert_eq!(replicated.op, applied.notifications[0].op);
    assert_eq!(replicated.sequence, applied.notifications[0].sequence);
    assert_eq!(
        fake.key_retention_for_test().await.0,
        native.business.frontiers.retention.keys
    );
}
