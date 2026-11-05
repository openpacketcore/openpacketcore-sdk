use super::*;
use crate::consensus::native::test_journal::journal_page_for_test_sync;
use crate::{Clock, FakeSessionBackend, SessionBackend, SessionLeaseManager};
use changes::tests::{apply, time};

#[derive(Debug)]
struct CommandClock(std::sync::Mutex<Timestamp>);
impl Clock for CommandClock {
    fn now_utc(&self) -> Timestamp {
        *self.0.lock().unwrap()
    }
}

fn new_key(template: &SessionKey, name: &'static [u8]) -> SessionKey {
    let mut key = template.clone();
    key.stable_id = bytes::Bytes::from_static(name).try_into().unwrap();
    key
}

#[tokio::test]
async fn native_v1_and_fake_retire_expired_keys_without_an_ordinary_cleanup() {
    let (mut native, _, live) = changes::tests::fixture();
    let clock = Arc::new(CommandClock(std::sync::Mutex::new(time(2))));
    let fake = FakeSessionBackend::in_memory_lab().with_clock(clock.clone());
    fake.replicate_entry(
        journal_page_for_test_sync(|| native.business.replication_log(1, 1, &|| Ok(()))).remove(0),
    )
    .await
    .unwrap();
    let history = native.business.history().unwrap().active_epoch().unwrap();
    let old_key = new_key(live.lease().key(), b"pure-v1-old");
    let next_key = new_key(live.lease().key(), b"pure-v1-next");
    for (index, key, now) in [
        (2, old_key.clone(), time(2)),
        (3, next_key.clone(), time(4)),
    ] {
        *clock.0.lock().unwrap() = now;
        let template = key_retention_tests::ephemeral_request(key, index, 0, history, now);
        let request = v1::tests::request(index as u128, &template);
        let prepared = fake
            .prepare_fenced_transition(request.clone())
            .await
            .unwrap();
        let expected = fake.fenced_transition(&prepared).await.unwrap();
        let applied = apply(
            &mut native,
            &[v1::tests::command(index, &request, now, index == 2)],
        );
        assert_eq!(
            applied.responses[0].result,
            Ok(SessionMutationOutcome::FencedTransition(expected))
        );
    }
    let actual = fake.key_retention_for_test().await;
    assert_eq!(actual.0.retired_count, 1);
    assert_eq!(native.business.frontiers.retention.keys, actual.0);
    assert_eq!(native.business.keys.len(), actual.1);
    let retired = &native.business.keys[&old_key];
    assert!(retired.record.is_none() && retired.lease.is_none());
    assert_eq!(retired.retired_epoch, Some(0));
    for key in [&old_key, &next_key] {
        assert_eq!(
            native.business.observe_at(key, time(4)).unwrap(),
            fake.observe_fenced_transition(key).await.unwrap()
        );
    }
    let replayed = FakeSessionBackend::in_memory_lab().with_clock(clock);
    for entry in journal_page_for_test_sync(|| native.business.replication_log(1, 8, &|| Ok(()))) {
        replayed.replicate_entry(entry).await.unwrap();
    }
    assert_eq!(replayed.key_retention_for_test().await, actual);
    native.validate_image().unwrap();
}

#[tokio::test]
async fn native_and_fake_cas_conflicts_publish_no_retirement_or_rotation() {
    let (mut native, _, live) = changes::tests::fixture();
    let clock = Arc::new(CommandClock(std::sync::Mutex::new(time(2))));
    let fake = FakeSessionBackend::in_memory_lab().with_clock(clock.clone());
    fake.replicate_entry(
        journal_page_for_test_sync(|| native.business.replication_log(1, 1, &|| Ok(()))).remove(0),
    )
    .await
    .unwrap();
    let old_key = new_key(live.lease().key(), b"cas-conflict-expired");
    let request = key_retention_tests::ephemeral_request(
        old_key.clone(),
        2,
        0,
        native.business.history().unwrap().active_epoch().unwrap(),
        time(2),
    );
    let created = apply(
        &mut native,
        &[changes::tests::command(2, &request, time(2), false)],
    );
    assert!(created.responses[0].result.is_ok());
    fake.replicate_entry(created.notifications[0].clone())
        .await
        .unwrap();
    let before = native.business.frontiers.retention.keys;
    let before_watch = native.business.frontiers.watch_sequence;
    let old_row = serde_json::to_vec(&**native.business.keys.get(&old_key).unwrap()).unwrap();
    *clock.0.lock().unwrap() = time(4);
    let cas = crate::CompareAndSet {
        key: live.lease().key().clone(),
        lease: live.lease().clone(),
        expected_generation: Some(crate::Generation::new(999)),
        new_record: native.business.keys[live.lease().key()]
            .record
            .as_ref()
            .unwrap()
            .clone(),
    };
    let expected = fake.compare_and_set(cas.clone()).await.unwrap();
    assert!(matches!(
        expected,
        crate::CompareAndSetResult::Conflict { .. }
    ));
    let result = apply(
        &mut native,
        &[key_retention_tests::command_at(
            3,
            SessionMutationIntent::CompareAndSet(Arc::new(cas)),
            time(4),
        )],
    );
    assert_eq!(
        result.responses[0].result,
        Ok(SessionMutationOutcome::CompareAndSet(expected))
    );
    assert!(result.notifications.is_empty());
    assert_eq!(native.business.frontiers.watch_sequence, before_watch);
    assert_eq!(fake.key_retention_for_test().await.0, before);
    assert_eq!(native.business.frontiers.retention.keys, before);
    assert_eq!(
        serde_json::to_vec(&**native.business.keys.get(&old_key).unwrap()).unwrap(),
        old_row
    );
    assert_eq!(
        native.business.keys.len(),
        fake.key_retention_for_test().await.1
    );
    native.validate_image().unwrap();
}

#[tokio::test]
async fn native_capacity_decisions_replay_and_rebuild_under_a_larger_fake_limit() {
    let (mut native, retired) = key_retention_tests::retired_key_fixture();
    let clock = Arc::new(CommandClock(std::sync::Mutex::new(time(2))));
    let fake = FakeSessionBackend::in_memory_lab().with_clock(clock.clone());
    let prefix = journal_page_for_test_sync(|| native.business.replication_log(1, 16, &|| Ok(())));
    for entry in &prefix {
        fake.replicate_entry(entry.clone()).await.unwrap();
    }
    assert_eq!(
        fake.key_retention_for_test().await.0,
        native.business.frontiers.retention.keys
    );
    assert_eq!(
        fake.observe_fenced_transition(retired.key()).await.unwrap(),
        native.business.observe_at(retired.key(), time(2)).unwrap()
    );
    let key = new_key(retired.key(), b"native-capacity-application-replay");
    let entry = key_retention_tests::command_at(
        5,
        SessionMutationIntent::AcquireLease {
            key: key.clone(),
            owner: crate::OwnerId::new("capacity-owner").unwrap(),
            ttl: std::time::Duration::from_secs(60),
        },
        time(2),
    );
    let applied = retention::with_key_capacity_limit_for_test(2, || apply(&mut native, &[entry]));
    assert!(applied.responses[0].result.is_ok());
    assert_eq!(native.business.frontiers.retention.keys.epoch, 2);
    assert_eq!(applied.notifications.len(), 1);
    fake.replicate_entry(applied.notifications[0].clone())
        .await
        .unwrap();
    assert_eq!(
        fake.observe_fenced_transition(retired.key()).await.unwrap(),
        native.business.observe_at(retired.key(), time(2)).unwrap(),
        "capacity finalization belongs to the native application entry"
    );
    assert_eq!(
        fake.key_retention_for_test().await.0,
        native.business.frontiers.retention.keys
    );
    assert!(applied.notifications[0].replay_policy.capacity_rotations == 2);
    let all = journal_page_for_test_sync(|| native.business.replication_log(1, 16, &|| Ok(())));
    let rebuilt = FakeSessionBackend::in_memory_lab().with_clock(clock);
    rebuilt
        .rebuild_replication_state(all.clone())
        .await
        .unwrap();
    assert_eq!(
        rebuilt.key_retention_for_test().await,
        fake.key_retention_for_test().await
    );
    assert_eq!(
        rebuilt.observe_fenced_transition(&key).await.unwrap(),
        fake.observe_fenced_transition(&key).await.unwrap()
    );
    let mut image = Vec::new();
    native.write_image(&mut image, [0x7A; 32], 41).unwrap();
    let cold = NativeStorage::read_image(
        &mut image.as_slice(),
        [0x7A; 32],
        41,
        native.business.identity(),
    )
    .unwrap();
    assert_eq!(
        journal_page_for_test_sync(|| cold.business.replication_log(1, 16, &|| Ok(()))),
        all
    );
    assert!(cold.business.frontiers == native.business.frontiers);
    cold.validate_image().unwrap();
}

#[test]
fn native_capacity_notification_codec_preserves_original_payload_bounds() {
    let (native, _, _) = changes::tests::fixture();
    let original =
        journal_page_for_test_sync(|| native.business.replication_log(1, 1, &|| Ok(()))).remove(0);
    let expected_payload = changes::notification_payload(&original).unwrap();
    let crate::ReplicationOp::Batch { ops } = &original.op else {
        panic!("fixture must carry both real effects");
    };
    for (effects, payload) in [(vec![ops[0].clone()], 0), (ops.clone(), expected_payload)] {
        for capacity_rotations in [1, 2] {
            let mut notification = original.clone();
            {
                notification.op = crate::ReplicationOp::Batch {
                    ops: effects.clone(),
                };
                notification.replay_policy.capacity_rotations = capacity_rotations;
            };
            notification.validate().unwrap();
            assert_eq!(
                changes::notification_payload(&notification).unwrap(),
                payload
            );
            let bytes = postcard::to_allocvec(&notification).unwrap();
            let admitted = generation::decode::inspect_notification(
                &bytes,
                notification.sequence,
                &native.business.frontiers,
                &|| Ok(()),
            )
            .unwrap();
            let owned = generation::decode::owned_notification(
                &bytes,
                admitted,
                &native.business.frontiers,
                &|| Ok(()),
            )
            .unwrap();
            assert_eq!(owned.entry(), &notification);
            for cut in 0..bytes.len() {
                assert!(generation::decode::inspect_notification(
                    &bytes[..cut],
                    notification.sequence,
                    &native.business.frontiers,
                    &|| Ok(())
                )
                .is_err());
            }
            let mut trailing = bytes;
            trailing.push(0);
            assert!(generation::decode::inspect_notification(
                &trailing,
                notification.sequence,
                &native.business.frontiers,
                &|| Ok(())
            )
            .is_err());
        }
    }
    for capacity_rotations in [3, u8::MAX] {
        let mut invalid = original.clone();
        {
            invalid.op = crate::ReplicationOp::Batch { ops: ops.clone() };
            invalid.replay_policy.capacity_rotations = capacity_rotations;
        };
        assert!(changes::notification_payload(&invalid).is_err());
        let bytes = postcard::to_allocvec(&invalid).unwrap();
        assert!(generation::decode::inspect_notification(
            &bytes,
            invalid.sequence,
            &native.business.frontiers,
            &|| Ok(())
        )
        .is_err());
    }
    for effects in [
        vec![crate::ReplicationOp::Batch { ops: ops.clone() }],
        vec![ops[0].clone(), ops[0].clone()],
        vec![ops[1].clone(), ops[0].clone()],
        vec![ops[0].clone(); 3],
    ] {
        let mut invalid = original.clone();
        {
            invalid.op = crate::ReplicationOp::Batch { ops: effects };
            invalid.replay_policy.capacity_rotations = 1;
        };
        assert!(changes::notification_payload(&invalid).is_err());
        let bytes = postcard::to_allocvec(&invalid).unwrap();
        assert!(generation::decode::inspect_notification(
            &bytes,
            invalid.sequence,
            &native.business.frontiers,
            &|| Ok(())
        )
        .is_err());
    }
}

#[tokio::test]
async fn native_and_fake_keep_command_time_after_a_no_effect_conflict() {
    let (mut native, _, live) = changes::tests::fixture();
    let clock = Arc::new(CommandClock(std::sync::Mutex::new(time(2))));
    let fake = FakeSessionBackend::in_memory_lab().with_clock(clock.clone());
    let old_key = new_key(live.lease().key(), b"no-effect-clock-expiry");
    let request = key_retention_tests::ephemeral_request(
        old_key.clone(),
        2,
        0,
        native.business.history().unwrap().active_epoch().unwrap(),
        time(2),
    );
    assert!(apply(
        &mut native,
        &[changes::tests::command(2, &request, time(2), false)]
    )
    .responses[0]
        .result
        .is_ok());
    for entry in journal_page_for_test_sync(|| native.business.replication_log(1, 8, &|| Ok(()))) {
        fake.replicate_entry(entry).await.unwrap();
    }
    let before = native.business.frontiers.retention.keys;
    let record = native.business.keys[live.lease().key()]
        .record
        .as_ref()
        .unwrap()
        .clone();
    let cas = crate::CompareAndSet {
        key: record.key.clone(),
        lease: live.lease().clone(),
        expected_generation: Some(crate::Generation::new(999)),
        new_record: record,
    };
    *clock.0.lock().unwrap() = time(4);
    assert!(matches!(
        fake.compare_and_set(cas.clone()).await.unwrap(),
        crate::CompareAndSetResult::Conflict { .. }
    ));
    assert!(apply(
        &mut native,
        &[key_retention_tests::command_at(
            3,
            SessionMutationIntent::CompareAndSet(Arc::new(cas)),
            time(4)
        )]
    )
    .notifications
    .is_empty());
    assert_eq!(fake.key_retention_for_test().await.0, before);
    assert_eq!(native.business.frontiers.retention.keys, before);
    *clock.0.lock().unwrap() = time(2);
    let key = new_key(&old_key, b"after-no-effect-clock");
    let owner = crate::OwnerId::new("clock-owner").unwrap();
    let expected = fake
        .acquire(&key, owner.clone(), std::time::Duration::from_secs(60))
        .await
        .unwrap();
    let applied = apply(
        &mut native,
        &[key_retention_tests::command_at(
            4,
            SessionMutationIntent::AcquireLease {
                key,
                owner,
                ttl: std::time::Duration::from_secs(60),
            },
            time(2),
        )],
    );
    let Ok(SessionMutationOutcome::Lease(actual)) = &applied.responses[0].result else {
        panic!("acquire must succeed");
    };
    assert_eq!(
        expected, *actual,
        "only writer samples can hold the command clock forward"
    );
    assert_eq!(
        fake.key_retention_for_test().await.0,
        native.business.frontiers.retention.keys
    );
    assert_eq!(fake.key_retention_for_test().await.0.retired_count, 1);
}

#[tokio::test]
async fn native_capacity_marker_refusal_preserves_a_smaller_fake_atomically() {
    use crate::fake::tests::{backend_data_snapshot, with_tracked_key_limit_for_test};
    use futures_util::{FutureExt, StreamExt};
    let (mut native, retired) = key_retention_tests::retired_key_fixture();
    let clock = Arc::new(CommandClock(std::sync::Mutex::new(time(2))));
    let replica = FakeSessionBackend::in_memory_lab().with_clock(clock);
    for entry in journal_page_for_test_sync(|| native.business.replication_log(1, 16, &|| Ok(()))) {
        replica.replicate_entry(entry).await.unwrap();
    }
    let key = new_key(retired.key(), b"capacity-refusal-successor");
    let entry = key_retention_tests::command_at(
        5,
        SessionMutationIntent::AcquireLease {
            key,
            owner: crate::OwnerId::new("capacity-owner").unwrap(),
            ttl: std::time::Duration::from_secs(60),
        },
        time(2),
    );
    let applied = retention::with_key_capacity_limit_for_test(2, || apply(&mut native, &[entry]));
    assert_eq!(applied.notifications.len(), 1);
    let notification = applied.notifications[0].clone();
    assert!(notification.replay_policy.capacity_rotations == 2);
    let mut watch = replica.watch(notification.sequence).await.unwrap();
    let before = backend_data_snapshot(&replica).await;
    // Preserve the admitted predecessor while reducing this clone's resource
    // allowance. The committed successor contains two live keys and cannot fit.
    let smaller = with_tracked_key_limit_for_test(&replica, 1);
    assert!(matches!(
        smaller.replicate_entry(notification.clone()).await,
        Err(StoreError::BackendUnavailable(_))
    ));
    assert_eq!(backend_data_snapshot(&smaller).await, before);
    assert!(watch.next().now_or_never().is_none());
    assert!(matches!(
        smaller
            .rebuild_replication_state(journal_page_for_test_sync(|| native
                .business
                .replication_log(1, 16, &|| Ok(()))))
            .await,
        Err(StoreError::BackendUnavailable(_))
    ));
    assert_eq!(backend_data_snapshot(&smaller).await, before);
    replica.replicate_entry(notification).await.unwrap();
    assert_eq!(
        replica.key_retention_for_test().await.0,
        native.business.frontiers.retention.keys
    );
}

#[test]
fn native_capacity_marker_belongs_only_to_its_command_in_one_apply() {
    let (mut grouped, retired) = key_retention_tests::retired_key_fixture();
    let mut separate = grouped.clone();
    let entries = [
        key_retention_tests::command(5, key_retention_tests::prune_intent(&grouped)),
        key_retention_tests::command(
            6,
            SessionMutationIntent::AcquireLease {
                key: new_key(retired.key(), b"grouped-capacity-successor"),
                owner: crate::OwnerId::new("capacity-owner").unwrap(),
                ttl: std::time::Duration::from_secs(60),
            },
        ),
    ];
    let applied = retention::with_key_capacity_limit_for_test(2, || apply(&mut grouped, &entries));
    assert!(applied
        .responses
        .iter()
        .all(|response| response.result.is_ok()));
    assert_eq!(applied.notifications.len(), 2);
    assert!(matches!(
        &applied.notifications[0].op,
        crate::ReplicationOp::RefreshTtl { .. }
    ));
    assert!(applied.notifications[1].replay_policy.capacity_rotations == 2);
    retention::with_key_capacity_limit_for_test(2, || {
        for entry in &entries {
            apply(&mut separate, std::slice::from_ref(entry));
        }
    });
    assert_eq!(
        journal_page_for_test_sync(|| grouped.business.replication_log(1, 16, &|| Ok(()))),
        journal_page_for_test_sync(|| separate.business.replication_log(1, 16, &|| Ok(())))
    );
    assert!(grouped.business.frontiers == separate.business.frontiers);
    grouped.validate_image().unwrap();
    separate.validate_image().unwrap();
}

#[tokio::test]
async fn native_capacity_rotation_without_a_mutation_notification_still_replays() {
    let (mut native, retired) = key_retention_tests::retired_key_fixture();
    let fake = FakeSessionBackend::in_memory_lab()
        .with_clock(Arc::new(CommandClock(std::sync::Mutex::new(time(2)))));
    for entry in journal_page_for_test_sync(|| native.business.replication_log(1, 16, &|| Ok(()))) {
        fake.replicate_entry(entry).await.unwrap();
    }
    let identity = native.business.identity;
    let certificate = crate::scope_authority::ScopeProfileActivation::new(
        identity,
        fenced_transition_voter_set_digest(identity, &native.business.members),
    );
    let command = key_retention_tests::command_at(
        5,
        SessionMutationIntent::Authorized {
            origin: *native.business.members.first().unwrap(),
            authority_identity: identity,
            mutation: Box::new(SessionMutationIntent::ActivateScopeProfile(Box::new(
                certificate,
            ))),
        },
        time(2),
    );
    let mut unconstrained = native.clone();
    let control = retention::with_key_capacity_limit_for_test(3, || {
        apply(&mut unconstrained, std::slice::from_ref(&command))
    });
    assert!(control.responses[0].result.is_ok());
    assert_eq!(control.notifications.len(), 1);
    assert_eq!(control.notifications[0].replay_policy.capacity_rotations, 0);
    assert!(
        matches!(&control.notifications[0].op, crate::ReplicationOp::Batch { ops } if ops.is_empty())
    );
    let applied = retention::with_key_capacity_limit_for_test(2, || apply(&mut native, &[command]));
    assert!(applied.responses[0].result.is_ok());
    assert_eq!(native.business.frontiers.retention.keys.epoch, 2);
    assert!(
        !applied.notifications.is_empty(),
        "the journal must carry the capacity decision"
    );
    for entry in applied.notifications {
        fake.replicate_entry(entry).await.unwrap();
    }
    assert_eq!(
        fake.key_retention_for_test().await.0,
        native.business.frontiers.retention.keys
    );
    assert_eq!(
        fake.observe_fenced_transition(retired.key()).await.unwrap(),
        native.business.observe_at(retired.key(), time(2)).unwrap()
    );
    native.validate_image().unwrap();
}

#[tokio::test]
async fn native_multi_create_capacity_replays_at_each_entry_boundary() {
    use crate::fake::tests::with_tracked_key_limit_for_test;
    let (mut native, old) = key_retention_tests::retired_key_fixture();
    let second = new_key(old.key(), b"second-retired-capacity-key");
    let created = apply(
        &mut native,
        &[key_retention_tests::command(
            5,
            SessionMutationIntent::AcquireLease {
                key: second,
                owner: crate::OwnerId::new("owner").unwrap(),
                ttl: std::time::Duration::from_secs(60),
            },
        )],
    );
    let Ok(SessionMutationOutcome::Lease(lease)) = &created.responses[0].result else {
        panic!("acquire succeeds")
    };
    let released = lease.clone();
    let prune = key_retention_tests::prune_intent(&native);
    apply(
        &mut native,
        &[
            key_retention_tests::command(6, SessionMutationIntent::ReleaseLease(released)),
            key_retention_tests::command(7, prune),
        ],
    );
    assert_eq!(native.business.keys.len(), 3);
    assert_eq!(native.business.frontiers.retention.keys.retired_count, 2);
    let fake = FakeSessionBackend::in_memory_lab()
        .with_clock(Arc::new(CommandClock(std::sync::Mutex::new(time(2)))));
    let fake = with_tracked_key_limit_for_test(&fake, 3);
    for entry in journal_page_for_test_sync(|| native.business.replication_log(1, 16, &|| Ok(()))) {
        fake.replicate_entry(entry).await.unwrap();
    }
    let history = native.business.history().unwrap().active_epoch().unwrap();
    let keys = [
        new_key(old.key(), b"batch-capacity-first"),
        new_key(old.key(), b"batch-capacity-second"),
    ];
    let requests = keys
        .iter()
        .enumerate()
        .map(|(i, key)| {
            key_retention_tests::ephemeral_request(key.clone(), 900 + i as u64, 0, history, time(2))
        })
        .collect::<Vec<_>>();
    let request_id =
        crate::consensus::types::fenced_transition_v2_batch_outer_request_id(&requests).unwrap();
    let mut entry =
        key_retention_tests::command(8, SessionMutationIntent::FencedTransitionV2Batch(requests));
    let EntryPayload::Normal(command) = &mut entry.payload else {
        unreachable!()
    };
    command.request_id = SessionConsensusRequestId::from_bytes(request_id);
    let applied = retention::with_key_capacity_limit_for_test(3, || apply(&mut native, &[entry]));
    let Ok(SessionMutationOutcome::FencedTransitionV2Batch(outcomes)) =
        &applied.responses[0].result
    else {
        panic!("batch succeeds")
    };
    assert!(outcomes.iter().all(Result::is_ok));
    assert_eq!(native.business.keys.len(), 3);
    assert_eq!(native.business.frontiers.retention.keys.epoch, 2);
    assert!(!applied.notifications.is_empty());
    for entry in applied.notifications {
        fake.replicate_entry(entry).await.unwrap();
        assert_eq!(
            fake.key_retention_for_test().await.0,
            native.business.frontiers.retention.keys,
            "every published entry boundary must carry the committed capacity state"
        );
    }
    for key in &keys {
        assert_eq!(
            fake.observe_fenced_transition(key).await.unwrap(),
            native.business.observe_at(key, time(2)).unwrap()
        );
    }
}

fn capacity_test_key(template: &SessionKey, group: &str, index: usize) -> SessionKey {
    let mut key = template.clone();
    key.stable_id = bytes::Bytes::from(format!("{group}-{index}"))
        .try_into()
        .unwrap();
    key
}

fn add_retired_capacity_rows(native: &mut NativeStorage, template: &SessionKey, count: usize) {
    for offset in 0..count {
        let index = native.business.frontiers.applied.unwrap().index + 1;
        let acquired = apply(
            native,
            &[key_retention_tests::command(
                index,
                SessionMutationIntent::AcquireLease {
                    key: capacity_test_key(template, "retired-capacity", offset),
                    owner: crate::OwnerId::new("capacity-owner").unwrap(),
                    ttl: std::time::Duration::from_secs(60),
                },
            )],
        );
        let Ok(SessionMutationOutcome::Lease(lease)) = &acquired.responses[0].result else {
            panic!("retirement fixture acquire succeeds")
        };
        let release = key_retention_tests::command(
            index + 1,
            SessionMutationIntent::ReleaseLease(lease.clone()),
        );
        let cleanup = native
            .business
            .keys
            .iter()
            .find_map(|(key, row)| {
                row.record
                    .as_ref()
                    .and_then(|_| native.business.retained_lease_for_test(key))
            })
            .unwrap();
        let prune = key_retention_tests::command(
            index + 2,
            SessionMutationIntent::RefreshTtl {
                lease: cleanup,
                ttl: std::time::Duration::from_secs(60),
            },
        );
        let retired = apply(native, &[release, prune]);
        assert!(retired.responses.iter().all(|r| r.result.is_ok()));
    }
}

fn capacity_scope_entry(
    native: &NativeStorage,
    intent: SessionMutationIntent,
) -> Entry<SessionRaftTypeConfig> {
    let index = native.business.frontiers.applied.unwrap().index + 1;
    let request_id = match &intent {
        SessionMutationIntent::ScopeAuthority(operation) => Some(*operation.request.request_id()),
        SessionMutationIntent::ScopeBatch(operation) => Some(*operation.request.request_id()),
        _ => None,
    };
    let mut entry = key_retention_tests::command(
        index,
        SessionMutationIntent::Authorized {
            origin: *native.business.members.first().unwrap(),
            authority_identity: native.business.identity,
            mutation: Box::new(intent),
        },
    );
    if let Some(request_id) = request_id {
        let EntryPayload::Normal(command) = &mut entry.payload else {
            unreachable!()
        };
        command.request_id = SessionConsensusRequestId::from_bytes(request_id);
    }
    entry
}

fn capacity_scope_fixture() -> (NativeStorage, LeaseGuard, crate::scope_authority::ScopeId) {
    let (mut native, old) = key_retention_tests::retired_key_fixture();
    let scope = crate::scope_authority::ScopeId::new(
        native.business.identity,
        opc_types::TenantId::from_static("capacity-scope"),
        opc_types::NetworkFunctionKind::smf(),
        [0x63; 32],
    )
    .unwrap();
    let activate = capacity_scope_entry(
        &native,
        SessionMutationIntent::ActivateScopeProfile(Box::new(
            crate::scope_authority::ScopeProfileActivation::new(
                native.business.identity,
                fenced_transition_voter_set_digest(
                    native.business.identity,
                    &native.business.members,
                ),
            ),
        )),
    );
    assert!(apply(&mut native, &[activate]).responses[0].result.is_ok());
    (native, old, scope)
}

fn capacity_scope_admit(
    native: &NativeStorage,
    scope: crate::scope_authority::ScopeId,
) -> Entry<SessionRaftTypeConfig> {
    use crate::scope_authority::{
        ScopeAuthorityCommand, ScopeAuthorityOperation, ScopeAuthorityRequest,
    };
    capacity_scope_entry(
        native,
        SessionMutationIntent::ScopeAuthority(Box::new(ScopeAuthorityCommand {
            request: ScopeAuthorityRequest::new(
                scope,
                [0x64; 16],
                0,
                ScopeAuthorityOperation::AdmitInitial {
                    execution: crate::scope_authority::tests::execution(1),
                },
            )
            .unwrap(),
        })),
    )
}

async fn assert_metadata_capacity_replays(
    native: &mut NativeStorage,
    entry: Entry<SessionRaftTypeConfig>,
) {
    let maximum = native.business.keys.len();
    let fake = FakeSessionBackend::in_memory_lab()
        .with_clock(Arc::new(CommandClock(std::sync::Mutex::new(time(2)))));
    let fake = crate::fake::tests::with_tracked_key_limit_for_test(&fake, maximum);
    let mut journal =
        journal_page_for_test_sync(|| native.business.replication_log(1, 128, &|| Ok(())));
    for row in &journal {
        fake.replicate_entry(row.clone()).await.unwrap();
    }
    let mut control = native.clone();
    let no_pressure = retention::with_key_capacity_limit_for_test(maximum + 8, || {
        apply(&mut control, std::slice::from_ref(&entry))
    });
    assert!(no_pressure.responses[0].result.is_ok());
    assert_eq!(no_pressure.notifications.len(), 1);
    assert_eq!(
        no_pressure.notifications[0]
            .replay_policy
            .capacity_rotations,
        0
    );
    assert!(
        matches!(&no_pressure.notifications[0].op, crate::ReplicationOp::Batch { ops } if ops.is_empty())
    );
    let applied = retention::with_key_capacity_limit_for_test(maximum, || apply(native, &[entry]));
    assert_eq!(applied.responses, no_pressure.responses);
    assert_eq!(native.business.frontiers.retention.keys.epoch, 2);
    assert!(
        !applied.notifications.is_empty(),
        "metadata decision must be journaled"
    );
    for row in &applied.notifications {
        fake.replicate_entry(row.clone()).await.unwrap();
    }
    assert_eq!(
        fake.key_retention_for_test().await.0,
        native.business.frontiers.retention.keys
    );
    journal.extend(applied.notifications);
    let rebuilt = FakeSessionBackend::in_memory_lab();
    rebuilt.rebuild_replication_state(journal).await.unwrap();
    assert_eq!(
        rebuilt.key_retention_for_test().await.0,
        native.business.frontiers.retention.keys
    );
    native.validate_image().unwrap();
}

#[tokio::test]
async fn native_scope_authority_capacity_without_notifications_replays() {
    let (mut native, old, scope) = capacity_scope_fixture();
    add_retired_capacity_rows(&mut native, old.key(), 2);
    let entry = capacity_scope_admit(&native, scope);
    assert_metadata_capacity_replays(&mut native, entry).await;
}

#[tokio::test]
async fn native_scope_child_batch_capacity_without_notifications_replays() {
    let (mut native, old, scope) = capacity_scope_fixture();
    let admit = capacity_scope_admit(&native, scope);
    let admitted = apply(&mut native, &[admit]);
    let Ok(SessionMutationOutcome::ScopeAuthority(Ok(checkpoint))) = &admitted.responses[0].result
    else {
        panic!("scope admission succeeds")
    };
    let permit = checkpoint.state().unwrap().view.stamp().cloned().unwrap();
    add_retired_capacity_rows(&mut native, old.key(), 2);
    let entry = capacity_scope_entry(
        &native,
        SessionMutationIntent::ScopeBatch(Box::new(crate::scope_batch::ScopeBatchCommand {
            request: crate::scope_batch::ScopeBatchRequest::new(
                &permit,
                [0x65; 16],
                0,
                vec![crate::scope_batch::tests::create(1, &[1])],
                vec![],
            )
            .unwrap(),
        })),
    );
    assert_metadata_capacity_replays(&mut native, entry).await;
}

#[tokio::test]
async fn native_maximum_create_batch_capacity_replays_every_entry_and_rebuilds_prefixes() {
    use futures_util::{FutureExt, StreamExt};
    let (mut native, old) = key_retention_tests::retired_key_fixture();
    add_retired_capacity_rows(&mut native, old.key(), 255);
    let maximum = native.business.keys.len();
    assert_eq!(maximum, 257);
    let fake = FakeSessionBackend::in_memory_lab()
        .with_clock(Arc::new(CommandClock(std::sync::Mutex::new(time(2)))));
    let fake = crate::fake::tests::with_tracked_key_limit_for_test(&fake, maximum);
    let mut journal =
        journal_page_for_test_sync(|| native.business.replication_log(1, 2048, &|| Ok(())));
    for row in &journal {
        fake.replicate_entry(row.clone()).await.unwrap();
    }
    let history = native.business.history().unwrap().active_epoch().unwrap();
    let keys = (0..256)
        .map(|i| capacity_test_key(old.key(), "maximum-create", i))
        .collect::<Vec<_>>();
    let requests = keys
        .iter()
        .enumerate()
        .map(|(i, key)| {
            key_retention_tests::ephemeral_request(
                key.clone(),
                4000 + i as u64,
                0,
                history,
                time(2),
            )
        })
        .collect::<Vec<_>>();
    let id =
        crate::consensus::types::fenced_transition_v2_batch_outer_request_id(&requests).unwrap();
    let mut entry = key_retention_tests::command(
        native.business.frontiers.applied.unwrap().index + 1,
        SessionMutationIntent::FencedTransitionV2Batch(requests),
    );
    let EntryPayload::Normal(command) = &mut entry.payload else {
        unreachable!()
    };
    command.request_id = SessionConsensusRequestId::from_bytes(id);
    let applied =
        retention::with_key_capacity_limit_for_test(maximum, || apply(&mut native, &[entry]));
    let Ok(SessionMutationOutcome::FencedTransitionV2Batch(outcomes)) =
        &applied.responses[0].result
    else {
        panic!("maximum batch succeeds")
    };
    assert_eq!(outcomes.len(), 256);
    assert!(outcomes.iter().all(Result::is_ok));
    assert_eq!(
        applied.notifications.len(),
        256,
        "preserve the original command and entry bounds"
    );
    let rebuilt = FakeSessionBackend::in_memory_lab()
        .with_clock(Arc::new(CommandClock(std::sync::Mutex::new(time(2)))));
    for (offset, row) in applied.notifications.iter().enumerate() {
        fake.replicate_entry(row.clone()).await.unwrap();
        assert_eq!(
            fake.key_retention_for_test().await.0,
            native.business.frontiers.retention.keys
        );
        let before = crate::fake::tests::backend_data_snapshot(&fake).await;
        fake.replicate_entry(row.clone()).await.unwrap();
        assert_eq!(
            crate::fake::tests::backend_data_snapshot(&fake).await,
            before,
            "duplicate does not consume a continuation"
        );
        journal.push(row.clone());
        if offset == 0 {
            rebuilt
                .rebuild_replication_state(journal.clone())
                .await
                .unwrap();
            assert_eq!(
                rebuilt.key_retention_for_test().await.0,
                native.business.frontiers.retention.keys
            );
            let mut watch = rebuilt.watch(row.sequence + 1).await.unwrap();
            let incomplete = crate::fake::tests::backend_data_snapshot(&rebuilt).await;
            assert!(rebuilt
                .acquire(
                    &capacity_test_key(old.key(), "interleaved-local", 0),
                    crate::OwnerId::new("local-owner").unwrap(),
                    std::time::Duration::from_secs(60)
                )
                .await
                .is_err());
            assert_eq!(
                crate::fake::tests::backend_data_snapshot(&rebuilt).await,
                incomplete
            );
            let mut wrong_time = applied.notifications[1].clone();
            wrong_time.timestamp = Timestamp::from_offset_datetime(
                *wrong_time.timestamp.as_offset_datetime() + time::Duration::microseconds(1),
            );
            wrong_time.validate().unwrap();
            assert!(rebuilt.replicate_entry(wrong_time).await.is_err());
            let mut interleaved = applied.notifications[1].clone();
            {
                interleaved.op = crate::ReplicationOp::Batch { ops: vec![] };
                interleaved.replay_policy.capacity_rotations = 1;
                interleaved.replay_policy.command = if 0 == 0 {
                    crate::ReplicationCommandBoundary::Single
                } else {
                    crate::ReplicationCommandBoundary::Start {
                        id: [0x52; 16],
                        following_entries: 0,
                    }
                };
                interleaved.replay_policy.async_fence_floor = 0;
                interleaved.replay_policy.prune_expired = false;
            };
            interleaved.replay_policy.command = crate::ReplicationCommandBoundary::Single;
            interleaved.validate().unwrap();
            assert!(rebuilt.replicate_entry(interleaved).await.is_err());
            let smaller = crate::fake::tests::with_tracked_key_limit_for_test(&rebuilt, 1);
            assert!(smaller
                .replicate_entry(applied.notifications[1].clone())
                .await
                .is_err());
            assert_eq!(
                crate::fake::tests::backend_data_snapshot(&rebuilt).await,
                incomplete,
                "every refused continuation preserves data, metadata, log and pending admission"
            );
            assert!(
                watch.next().now_or_never().is_none(),
                "refused continuations must not notify watchers"
            );
        } else {
            rebuilt.replicate_entry(row.clone()).await.unwrap();
        }
    }
    assert_eq!(fake.key_retention_for_test().await.1, maximum);
    assert_eq!(
        fake.key_retention_for_test().await,
        rebuilt.key_retention_for_test().await
    );
    for key in &keys {
        assert_eq!(
            fake.observe_fenced_transition(key).await.unwrap(),
            native.business.observe_at(key, time(2)).unwrap()
        );
        assert_eq!(
            rebuilt.observe_fenced_transition(key).await.unwrap(),
            native.business.observe_at(key, time(2)).unwrap()
        );
    }
    native.validate_image().unwrap();
}

#[test]
fn native_capacity_boundary_codec_preserves_original_payload_bounds() {
    let (native, _, _) = changes::tests::fixture();
    let original =
        journal_page_for_test_sync(|| native.business.replication_log(1, 1, &|| Ok(()))).remove(0);
    let expected_payload = changes::notification_payload(&original).unwrap();
    let crate::ReplicationOp::Batch { ops } = &original.op else {
        panic!("fixture must carry both real effects");
    };
    for (effects, payload) in [
        (vec![], 0),
        (vec![ops[0].clone()], 0),
        (ops.clone(), expected_payload),
    ] {
        for capacity_rotations in [1, 2] {
            let mut notification = original.clone();
            {
                notification.op = crate::ReplicationOp::Batch {
                    ops: effects.clone(),
                };
                notification.replay_policy.capacity_rotations = capacity_rotations;
                notification.replay_policy.command = if 0 == 0 {
                    crate::ReplicationCommandBoundary::Single
                } else {
                    crate::ReplicationCommandBoundary::Start {
                        id: [0x52; 16],
                        following_entries: 0,
                    }
                };
                notification.replay_policy.async_fence_floor = 0;
                notification.replay_policy.prune_expired = false;
            };
            notification.validate().unwrap();
            assert_eq!(
                changes::notification_payload(&notification).unwrap(),
                payload
            );
            let bytes = postcard::to_allocvec(&notification).unwrap();
            let admitted = generation::decode::inspect_notification(
                &bytes,
                notification.sequence,
                &native.business.frontiers,
                &|| Ok(()),
            )
            .unwrap();
            let owned = generation::decode::owned_notification(
                &bytes,
                admitted,
                &native.business.frontiers,
                &|| Ok(()),
            )
            .unwrap();
            assert_eq!(owned.entry(), &notification);
            for cut in 0..bytes.len() {
                assert!(generation::decode::inspect_notification(
                    &bytes[..cut],
                    notification.sequence,
                    &native.business.frontiers,
                    &|| Ok(())
                )
                .is_err());
            }
            let mut trailing = bytes;
            trailing.push(0);
            assert!(generation::decode::inspect_notification(
                &trailing,
                notification.sequence,
                &native.business.frontiers,
                &|| Ok(())
            )
            .is_err());
        }
    }
    for capacity_rotations in [3, u8::MAX] {
        let mut invalid = original.clone();
        {
            invalid.op = crate::ReplicationOp::Batch { ops: ops.clone() };
            invalid.replay_policy.capacity_rotations = capacity_rotations;
            invalid.replay_policy.command = if 0 == 0 {
                crate::ReplicationCommandBoundary::Single
            } else {
                crate::ReplicationCommandBoundary::Start {
                    id: [0x52; 16],
                    following_entries: 0,
                }
            };
            invalid.replay_policy.async_fence_floor = 0;
            invalid.replay_policy.prune_expired = false;
        };
        assert!(changes::notification_payload(&invalid).is_err());
        let bytes = postcard::to_allocvec(&invalid).unwrap();
        assert!(generation::decode::inspect_notification(
            &bytes,
            invalid.sequence,
            &native.business.frontiers,
            &|| Ok(())
        )
        .is_err());
    }
    for effects in [
        vec![crate::ReplicationOp::Batch { ops: ops.clone() }],
        vec![ops[0].clone(), ops[0].clone()],
        vec![ops[1].clone(), ops[0].clone()],
        vec![ops[0].clone(); 3],
    ] {
        let mut invalid = original.clone();
        {
            invalid.op = crate::ReplicationOp::Batch { ops: effects };
            invalid.replay_policy.capacity_rotations = 1;
            invalid.replay_policy.command = if 0 == 0 {
                crate::ReplicationCommandBoundary::Single
            } else {
                crate::ReplicationCommandBoundary::Start {
                    id: [0x52; 16],
                    following_entries: 0,
                }
            };
            invalid.replay_policy.async_fence_floor = 0;
            invalid.replay_policy.prune_expired = false;
        };
        assert!(changes::notification_payload(&invalid).is_err());
        let bytes = postcard::to_allocvec(&invalid).unwrap();
        assert!(generation::decode::inspect_notification(
            &bytes,
            invalid.sequence,
            &native.business.frontiers,
            &|| Ok(())
        )
        .is_err());
    }
}

#[tokio::test]
async fn native_metadata_capacity_boundary_preserves_unpruned_expired_rows() {
    let (mut native, old) = key_retention_tests::retired_key_fixture();
    let key = capacity_test_key(old.key(), "unpruned-expired", 0);
    let request = key_retention_tests::ephemeral_request(
        key.clone(),
        9000,
        0,
        native.business.history().unwrap().active_epoch().unwrap(),
        time(2),
    );
    let entry = changes::tests::command(5, &request, time(2), false);
    assert!(apply(&mut native, &[entry]).responses[0].result.is_ok());
    let prior = postcard::to_allocvec(&**native.business.keys.get(&key).unwrap()).unwrap();
    let mut entry = capacity_scope_entry(
        &native,
        SessionMutationIntent::ActivateScopeProfile(Box::new(
            crate::scope_authority::ScopeProfileActivation::new(
                native.business.identity,
                fenced_transition_voter_set_digest(
                    native.business.identity,
                    &native.business.members,
                ),
            ),
        )),
    );
    let EntryPayload::Normal(command) = &mut entry.payload else {
        unreachable!()
    };
    command.logical_time = time(4);
    let fake = FakeSessionBackend::in_memory_lab()
        .with_clock(Arc::new(CommandClock(std::sync::Mutex::new(time(4)))));
    for row in journal_page_for_test_sync(|| native.business.replication_log(1, 16, &|| Ok(()))) {
        fake.replicate_entry(row).await.unwrap();
    }
    let maximum = native.business.keys.len();
    let applied =
        retention::with_key_capacity_limit_for_test(maximum, || apply(&mut native, &[entry]));
    assert!(applied.responses[0].result.is_ok());
    assert_eq!(
        postcard::to_allocvec(&**native.business.keys.get(&key).unwrap()).unwrap(),
        prior,
        "metadata-only command must not choose an ordinary expiry finalizer"
    );
    for row in applied.notifications {
        fake.replicate_entry(row).await.unwrap();
    }
    assert_eq!(
        fake.key_retention_for_test().await.0,
        native.business.frontiers.retention.keys
    );
    assert!(
        crate::fake::tests::canonical_record_for_test(&fake, &key)
            .await
            .is_some(),
        "metadata boundary retains the physically unpruned expired payload"
    );
}

#[test]
fn native_capacity_boundary_codec_bounds_continuations_and_recovery_floor() {
    let (native, _, _) = changes::tests::fixture();
    let mut row =
        journal_page_for_test_sync(|| native.business.replication_log(1, 1, &|| Ok(()))).remove(0);
    let crate::ReplicationOp::Batch { ops } = row.op.clone() else {
        unreachable!()
    };
    for following_entries in [0, 1, 255, 256] {
        for async_fence_floor in [0, 100, COUNTER_MAX - 1] {
            {
                row.op = crate::ReplicationOp::Batch { ops: ops.clone() };
                row.replay_policy.capacity_rotations = 2;
                row.replay_policy.command = if following_entries == 0 {
                    crate::ReplicationCommandBoundary::Single
                } else {
                    crate::ReplicationCommandBoundary::Start {
                        id: [0x52; 16],
                        following_entries,
                    }
                };
                row.replay_policy.async_fence_floor = async_fence_floor;
                row.replay_policy.prune_expired = false;
            };
            let valid = following_entries <= 255 && async_fence_floor <= COUNTER_MAX - 2;
            assert_eq!(changes::notification_payload(&row).is_ok(), valid);
            let bytes = postcard::to_allocvec(&row).unwrap();
            assert_eq!(
                generation::decode::inspect_notification(
                    &bytes,
                    row.sequence,
                    &native.business.frontiers,
                    &|| Ok(())
                )
                .is_ok(),
                valid
            );
            if valid {
                assert_eq!(owned::notification(&row).unwrap(), row);
            }
        }
    }
}

async fn replay_capacity_with_later_recreation(reject_middle: bool) {
    let (mut native, old) = key_retention_tests::retired_key_fixture();
    add_retired_capacity_rows(&mut native, old.key(), 2);
    let maximum = native.business.keys.len();
    let fake = FakeSessionBackend::in_memory_lab()
        .with_clock(Arc::new(CommandClock(std::sync::Mutex::new(time(2)))));
    let fake = crate::fake::tests::with_tracked_key_limit_for_test(&fake, maximum);
    let mut journal =
        journal_page_for_test_sync(|| native.business.replication_log(1, 64, &|| Ok(())));
    for row in &journal {
        fake.replicate_entry(row.clone()).await.unwrap();
    }
    let history = native.business.history().unwrap().active_epoch().unwrap();
    let fresh = capacity_test_key(old.key(), "later-recreation", 0);
    let mut requests = vec![key_retention_tests::ephemeral_request(
        fresh.clone(),
        9100,
        0,
        history,
        time(2),
    )];
    if reject_middle {
        requests.push(key_retention_tests::ephemeral_request(
            capacity_test_key(old.key(), "rejected-middle", 0),
            9101,
            1,
            history,
            time(2),
        ));
    }
    requests.push(key_retention_tests::ephemeral_request(
        old.key().clone(),
        9102,
        old.fence().get(),
        history,
        time(2),
    ));
    let request_id =
        crate::consensus::types::fenced_transition_v2_batch_outer_request_id(&requests).unwrap();
    let mut entry = key_retention_tests::command(
        native.business.frontiers.applied.unwrap().index + 1,
        SessionMutationIntent::FencedTransitionV2Batch(requests),
    );
    let EntryPayload::Normal(command) = &mut entry.payload else {
        unreachable!()
    };
    command.request_id = SessionConsensusRequestId::from_bytes(request_id);
    let applied =
        retention::with_key_capacity_limit_for_test(maximum, || apply(&mut native, &[entry]));
    let Ok(SessionMutationOutcome::FencedTransitionV2Batch(outcomes)) =
        &applied.responses[0].result
    else {
        panic!("batch returns every child outcome")
    };
    assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 2);
    if reject_middle {
        assert_eq!(outcomes[1], Err(StoreError::StaleFence));
    }
    assert_eq!(applied.notifications.len(), 2);
    assert_eq!(native.business.frontiers.retention.keys.epoch, 2);
    for row in &applied.notifications {
        fake.replicate_entry(row.clone()).await.unwrap();
        assert_eq!(
            fake.key_retention_for_test().await.0,
            native.business.frontiers.retention.keys
        );
    }
    journal.extend(applied.notifications);
    let rebuilt = FakeSessionBackend::in_memory_lab()
        .with_clock(Arc::new(CommandClock(std::sync::Mutex::new(time(2)))));
    rebuilt.rebuild_replication_state(journal).await.unwrap();
    assert_eq!(
        rebuilt.key_retention_for_test().await,
        fake.key_retention_for_test().await
    );
    for key in [old.key(), &fresh] {
        assert_eq!(
            fake.observe_fenced_transition(key).await.unwrap(),
            native.business.observe_at(key, time(2)).unwrap()
        );
        assert_eq!(
            rebuilt.observe_fenced_transition(key).await.unwrap(),
            native.business.observe_at(key, time(2)).unwrap()
        );
    }
}

#[tokio::test]
async fn native_capacity_replays_a_retired_key_recreated_after_the_first_entry() {
    replay_capacity_with_later_recreation(false).await;
}

#[tokio::test]
async fn native_capacity_continuation_counts_effects_around_a_rejected_child() {
    replay_capacity_with_later_recreation(true).await;
}

#[tokio::test]
async fn committed_v2_entry_remains_replayable_after_released_key_capacity_rotations() {
    let (mut native, old) = key_retention_tests::retired_key_fixture();
    add_retired_capacity_rows(&mut native, old.key(), 2);
    let owner = crate::OwnerId::new("capacity-owner").unwrap();
    let ttl = std::time::Duration::from_secs(60);
    for (group, release) in [("filler", false), ("released", true)] {
        let index = native.business.frontiers.applied.unwrap().index + 1;
        let acquired = apply(
            &mut native,
            &[key_retention_tests::command(
                index,
                SessionMutationIntent::AcquireLease {
                    key: capacity_test_key(old.key(), group, 0),
                    owner: owner.clone(),
                    ttl,
                },
            )],
        );
        let Ok(SessionMutationOutcome::Lease(lease)) = &acquired.responses[0].result else {
            panic!("acquire")
        };
        if release {
            let intent = SessionMutationIntent::ReleaseLease(lease.clone());
            apply(
                &mut native,
                &[key_retention_tests::command(index + 1, intent)],
            );
        }
    }
    let fake = FakeSessionBackend::in_memory_lab()
        .with_clock(Arc::new(CommandClock(std::sync::Mutex::new(time(2)))));
    for row in journal_page_for_test_sync(|| native.business.replication_log(1, 64, &|| Ok(()))) {
        fake.replicate_entry(row).await.unwrap();
    }
    let history = native.business.history().unwrap().active_epoch().unwrap();
    let maximum = native.business.keys.len();
    let mut boundaries = Vec::new();
    for offset in 0..2 {
        let floor = native.business.frontiers.retention.keys.floor_cur;
        let request = key_retention_tests::ephemeral_request(
            capacity_test_key(old.key(), "fresh", offset),
            7800 + offset as u64,
            floor,
            history,
            time(2),
        );
        let index = native.business.frontiers.applied.unwrap().index + 1;
        let entry = changes::tests::command(index, &request, time(2), false);
        let applied =
            retention::with_key_capacity_limit_for_test(maximum, || apply(&mut native, &[entry]));
        assert!(applied.responses[0].result.is_ok());
        assert_eq!(applied.notifications.len(), 1);
        fake.replicate_entry(applied.notifications[0].clone())
            .await
            .expect("every committed entry must remain replayable at the same capacity");
        boundaries.push((
            fake.key_retention_for_test().await.0,
            native.business.frontiers.retention.keys,
        ));
    }
    for (replica, source) in boundaries {
        assert_eq!(replica, source);
    }
}

#[tokio::test]
async fn native_v2_capacity_replay_keeps_floors_after_a_release() {
    let (mut native, old) = key_retention_tests::retired_key_fixture();
    add_retired_capacity_rows(&mut native, old.key(), 2);
    let owner = crate::OwnerId::new("capacity-owner").unwrap();
    let ttl = std::time::Duration::from_secs(60);
    for (group, release) in [("filler", false), ("released", true)] {
        let index = native.business.frontiers.applied.unwrap().index + 1;
        let acquire = SessionMutationIntent::AcquireLease {
            key: capacity_test_key(old.key(), group, 0),
            owner: owner.clone(),
            ttl,
        };
        let acquired = apply(&mut native, &[key_retention_tests::command(index, acquire)]);
        let Ok(SessionMutationOutcome::Lease(lease)) = &acquired.responses[0].result else {
            panic!("acquire")
        };
        if release {
            let intent = SessionMutationIntent::ReleaseLease(lease.clone());
            apply(
                &mut native,
                &[key_retention_tests::command(index + 1, intent)],
            );
        }
    }
    let fake = FakeSessionBackend::in_memory_lab()
        .with_clock(Arc::new(CommandClock(std::sync::Mutex::new(time(2)))));
    for row in journal_page_for_test_sync(|| native.business.replication_log(1, 64, &|| Ok(()))) {
        fake.replicate_entry(row).await.unwrap();
    }
    let history = native.business.history().unwrap().active_epoch().unwrap();
    let maximum = native.business.keys.len();
    for offset in 0..2 {
        let floor = native.business.frontiers.retention.keys.floor_cur;
        let key = capacity_test_key(old.key(), "fresh", offset);
        let request = key_retention_tests::ephemeral_request(
            key,
            7800 + offset as u64,
            floor,
            history,
            time(2),
        );
        let index = native.business.frontiers.applied.unwrap().index + 1;
        let entry = changes::tests::command(index, &request, time(2), false);
        let applied =
            retention::with_key_capacity_limit_for_test(maximum, || apply(&mut native, &[entry]));
        assert!(applied.responses[0].result.is_ok());
        fake.replicate_entry(applied.notifications[0].clone())
            .await
            .unwrap();
        assert_eq!(
            fake.key_retention_for_test().await.0,
            native.business.frontiers.retention.keys
        );
    }
}

fn policy_watch_head(native: &mut NativeStorage, head: u64) {
    let original =
        journal_page_for_test_sync(|| native.business.replication_log(1, 256, &|| Ok(())))
            .pop()
            .unwrap();
    native.business.notifications.clear();
    let window = retention::NOTIFICATION_WINDOW as u64;
    for sequence in head - window + 1..=head {
        native.business.notifications.push_back(
            NotificationRow::new(NativeNotification::new(ReplicationEntry {
                sequence,
                ..original.clone()
            }))
            .unwrap(),
        );
    }
    native.business.frontiers.watch_sequence = head;
    native.business.frontiers.retention.watch_retired_through = head - window;
    native.business.admit_business().unwrap();
    native.log.admit(&native.business).unwrap();
    native.validate_image().unwrap();
}

#[test]
fn scope_authority_and_child_batch_capacity_horizons_are_atomic() {
    for child_batch in [false, true] {
        for head in [COUNTER_MAX - 1, COUNTER_MAX] {
            let (mut native, old, scope) = capacity_scope_fixture();
            let permit = if child_batch {
                let admit = capacity_scope_admit(&native, scope.clone());
                let admitted = apply(&mut native, &[admit]);
                let Ok(SessionMutationOutcome::ScopeAuthority(Ok(checkpoint))) =
                    &admitted.responses[0].result
                else {
                    panic!("admit")
                };
                Some(checkpoint.state().unwrap().view.stamp().cloned().unwrap())
            } else {
                None
            };
            add_retired_capacity_rows(&mut native, old.key(), 2);
            let entry = if let Some(permit) = permit {
                capacity_scope_entry(
                    &native,
                    SessionMutationIntent::ScopeBatch(Box::new(
                        crate::scope_batch::ScopeBatchCommand {
                            request: crate::scope_batch::ScopeBatchRequest::new(
                                &permit,
                                [0x91; 16],
                                0,
                                vec![crate::scope_batch::tests::create(1, &[1])],
                                vec![],
                            )
                            .unwrap(),
                        },
                    )),
                )
            } else {
                capacity_scope_admit(&native, scope)
            };
            policy_watch_head(&mut native, head);
            let before = native.business.frontiers.retention;
            let next_fence = native.business.frontiers.next_fence;
            let next_credential = native.business.frontiers.next_credential;
            let keys = native
                .business
                .keys
                .iter()
                .map(|(key, row)| (key.clone(), postcard::to_allocvec(&**row).unwrap()))
                .collect::<Vec<_>>();
            let maximum = native.business.keys.len();
            let result = retention::with_key_capacity_limit_for_test(maximum, || {
                apply(&mut native, &[entry])
            });
            if head == COUNTER_MAX {
                assert_eq!(
                    result.responses[0].result,
                    Err(StoreError::FencedTransitionStorageExhausted)
                );
                assert!(result.notifications.is_empty());
                assert!(native.business.frontiers.retention == before);
                assert_eq!(native.business.frontiers.next_fence, next_fence);
                assert_eq!(native.business.frontiers.next_credential, next_credential);
                assert_eq!(native.business.keys.len(), keys.len());
                for (key, bytes) in keys {
                    assert_eq!(
                        postcard::to_allocvec(&**native.business.keys.get(&key).unwrap()).unwrap(),
                        bytes
                    );
                }
            } else {
                assert!(result.responses[0].result.is_ok());
                assert_eq!(result.notifications.len(), 1);
                assert_eq!(result.notifications[0].sequence, COUNTER_MAX);
                assert_eq!(native.business.frontiers.retention.keys.epoch, 2);
            }
            native.validate_image().unwrap();
        }
    }
}
