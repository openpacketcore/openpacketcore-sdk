use super::*;
use crate::consensus::native::ordinary_retention_tests::{acquire, window_fixture};

const RETENTION_IMAGE_MAXIMUM: u64 = 128 * 1024 * 1024;

#[test]
fn native_key_retention_passes_original_lifetime_limit_and_reopens() {
    use crate::consensus::native::key_retention_tests::{command_at, ephemeral_request};
    use crate::fenced_transition::FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES;
    use std::time::Duration;

    // V2 binds real short-lived records without consuming the independent
    // ordinary-command receipt budget. Ordinary refreshes commit expiry
    // pruning. All keys, fences and receipt epochs arise from real commands.
    let started = std::time::Instant::now();
    let (mut storage, _, live) = fixture();
    let mut now = time(2);
    let mut index = 2;
    let mut created = 0_u64;
    let mut old_lease = None;
    let retained_dead = |count: u64| {
        let window = crate::key_retention::RETIRED_KEYS_PER_EPOCH;
        if count < window {
            count
        } else {
            window + count % window
        }
    };
    let mut prepared_key = live.lease().key().clone();
    prepared_key.stable_id = bytes::Bytes::from_static(b"prepared-across-rotation")
        .try_into()
        .unwrap();
    // Preparation is independent of application time. Give this encrypted
    // payload an expiry beyond both rotation probes; only the fence may reject it.
    let prepared = ephemeral_request(
        prepared_key.clone(),
        2_000_000,
        0,
        storage.business.history().unwrap().active_epoch().unwrap(),
        time(40),
    );
    let mut probed_epochs = BTreeSet::new();
    while created < 1_048_575 {
        let history = storage.business.history().unwrap();
        if history.bound_entries() == FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES {
            let entry =
                crate::consensus::native::lifecycle_tests::maintenance(&storage, index, now);
            let result = apply(&mut storage, &[entry]);
            assert!(result.responses[0].result.is_ok());
            index += 1;
            continue;
        }
        let count = 32_768
            .min(FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES - history.bound_entries())
            .min((1_048_575 - created) as usize);
        let floor = storage.business.frontiers.retention.keys.floor_cur;
        let entries = (0..count)
            .map(|offset| {
                let next = index + offset as u64;
                let mut key = live.lease().key().clone();
                key.stable_id =
                    bytes::Bytes::copy_from_slice(&(created + offset as u64 + 1).to_be_bytes())
                        .try_into()
                        .unwrap();
                let request =
                    ephemeral_request(key, next, floor, history.active_epoch().unwrap(), now);
                command(next, &request, now, false)
            })
            .collect::<Vec<_>>();
        // Preserve the checkpoint span and every operation, while delivering
        // accumulated RPC batches within the existing journal-memory budget.
        // Distinct keys own more staging memory than repeated-key notifications.
        let mut notified = 0;
        for delivery in entries.chunks(16_384) {
            let result = apply(&mut storage, delivery);
            assert_eq!(result.responses.len(), delivery.len());
            assert!(result
                .responses
                .iter()
                .all(|response| response.result.is_ok()));
            assert_eq!(result.notifications.len(), delivery.len());
            notified += result.notifications.len();
            if old_lease.is_none() {
                let Ok(SessionMutationOutcome::FencedTransition(outcome)) =
                    &result.responses[0].result
                else {
                    panic!("first short-lived record commits")
                };
                old_lease = Some(outcome.lease().clone());
            }
        }
        assert_eq!(notified, count);
        assert_eq!(
            storage.business.keys.len(),
            count + 1 + retained_dead(created) as usize
        );
        assert!(storage.business.notifications.len() <= 65_536);
        index += count as u64;
        created += count as u64;
        now = now.add_seconds(1).unwrap();
        let old_dead = storage
            .business
            .keys
            .iter()
            .filter(|(_, row)| row.retired_epoch.is_some())
            .map(|(key, row)| (key.clone(), row.fence))
            .collect::<Vec<_>>();
        let prune = command_at(
            index,
            SessionMutationIntent::RefreshTtl {
                lease: live.lease().clone(),
                ttl: Duration::from_secs(60),
            },
            now,
        );
        let result = apply(&mut storage, &[prune]);
        assert!(result.responses[0].result.is_ok());
        assert_eq!(
            storage.business.keys.len(),
            1 + retained_dead(created) as usize,
            "only the live record and the exact two-epoch window remain"
        );
        let retention = storage.business.frontiers.retention.keys;
        let window = crate::key_retention::RETIRED_KEYS_PER_EPOCH;
        assert_eq!(retention.epoch, created / window);
        assert_eq!(retention.retired_count, created % window);
        assert_eq!(
            storage
                .business
                .keys
                .values()
                .filter(|row| row.retired_epoch.is_some())
                .count(),
            retained_dead(created) as usize
        );
        assert!(retained_dead(created) <= 2 * window);
        assert!(retention.floor_cur >= floor);
        for (key, fence) in old_dead {
            if !storage.business.keys.contains_key(&key) {
                assert!(
                    fence < retention.floor_prev,
                    "every forgotten exact fence is below the previous floor"
                );
            }
        }
        index += 1;
        if matches!(retention.epoch, 1 | 2) && probed_epochs.insert(retention.epoch) {
            let mut probe = storage.clone();
            let before_fence = probe.business.frontiers.next_fence;
            let before_watch = probe.business.frontiers.watch_sequence;
            let before_revision = probe.business.frontiers.restore_revision;
            let applied = apply(&mut probe, &[command(index, &prepared, now, false)]);
            if retention.epoch == 1 {
                assert_eq!(retention.floor_prev, 0, "fresh zero survives epoch one");
                let Ok(SessionMutationOutcome::FencedTransition(outcome)) =
                    &applied.responses[0].result
                else {
                    panic!(
                        "prepared create survives one rotation: {:?}",
                        applied.responses[0].result
                    );
                };
                assert_eq!(outcome.lease().fence().get(), 1);
                assert_eq!(outcome.lease().key(), &prepared_key);
                let old = old_lease.as_ref().unwrap();
                assert_eq!(
                    probe
                        .business
                        .observe_at(old.key(), now)
                        .unwrap()
                        .current_fence(),
                    old.fence()
                );
                assert_eq!(
                    probe.business.keys.get(old.key()).unwrap().retired_epoch,
                    Some(0)
                );
                let recreate = ephemeral_request(
                    old.key().clone(),
                    2_000_001,
                    old.fence().get(),
                    probe.business.history().unwrap().active_epoch().unwrap(),
                    now,
                );
                let recreated = apply(&mut probe, &[command(index + 1, &recreate, now, false)]);
                let Ok(SessionMutationOutcome::FencedTransition(outcome)) =
                    &recreated.responses[0].result
                else {
                    panic!("recently dead exact key can be recreated");
                };
                assert!(
                    outcome.lease().fence() > old.fence(),
                    "same key/generation never reuses its AAD fence"
                );
                assert_eq!(outcome.committed_generation().get(), 1);
                assert_eq!(
                    probe.business.keys.get(old.key()).unwrap().retired_epoch,
                    None
                );
            } else {
                assert_eq!(applied.responses[0].result, Err(StoreError::StaleFence));
                assert!(!probe.business.keys.contains_key(&prepared_key));
                assert_eq!(probe.business.frontiers.next_fence, before_fence);
                assert_eq!(probe.business.frontiers.watch_sequence, before_watch);
                assert_eq!(probe.business.frontiers.restore_revision, before_revision);
                assert_eq!(probe.business.frontiers.retention.keys, retention);
                assert!(applied.notifications.is_empty());
                let old = old_lease.as_ref().unwrap();
                assert!(!probe.business.keys.contains_key(old.key()));
                assert!(old.fence().get() < retention.floor_prev);
                let stale = ephemeral_request(
                    old.key().clone(),
                    2_000_002,
                    old.fence().get(),
                    probe.business.history().unwrap().active_epoch().unwrap(),
                    now,
                );
                let rejected = apply(&mut probe, &[command(index + 1, &stale, now, false)]);
                assert_eq!(rejected.responses[0].result, Err(StoreError::StaleFence));
                assert!(rejected.notifications.is_empty());
                let observed = probe
                    .business
                    .observe_at(old.key(), now)
                    .unwrap()
                    .current_fence();
                assert_eq!(observed.get(), retention.floor_cur);
                let fresh = ephemeral_request(
                    old.key().clone(),
                    2_000_003,
                    observed.get(),
                    probe.business.history().unwrap().active_epoch().unwrap(),
                    now,
                );
                let recreated = apply(&mut probe, &[command(index + 2, &fresh, now, false)]);
                let Ok(SessionMutationOutcome::FencedTransition(outcome)) =
                    &recreated.responses[0].result
                else {
                    panic!("re-observation permits a forgotten-key create");
                };
                assert_eq!(outcome.lease().fence().get(), observed.get() + 1);
                assert!(
                    outcome.lease().fence() > old.fence(),
                    "forgotten key/generation never reuses its AAD fence"
                );
                assert_eq!(outcome.committed_generation().get(), 1);
                assert_eq!(
                    probe.business.keys.get(old.key()).unwrap().retired_epoch,
                    None
                );
            }
            assert_eq!(
                probe
                    .business
                    .observe_at(live.lease().key(), now)
                    .unwrap()
                    .current_fence(),
                live.lease().fence()
            );
        }
        let through = storage.business.applied().unwrap();
        storage
            .business
            .publish_snapshot_metadata(snapshot(&storage, through.index, "retired-keys"))
            .unwrap();
        storage
            .log
            .project(&Operation::Purge(through), &storage.business, Some(through))
            .unwrap();
        eprintln!(
            "native_key_lifetime created={created} retained={} elapsed={:?}",
            storage.business.keys.len(),
            started.elapsed()
        );
    }
    // The first fixture consumes one of the eight V2 epochs' receipt slots.
    // Two further ordinary lease keys cross the original key lifetime bound
    // without requiring a ninth receipt epoch or a synthetic state counter.
    for number in 1_048_576_u64..=1_048_577 {
        let mut key = live.lease().key().clone();
        key.stable_id = bytes::Bytes::copy_from_slice(&number.to_be_bytes())
            .try_into()
            .unwrap();
        let acquired = apply(
            &mut storage,
            &[command_at(
                index,
                SessionMutationIntent::AcquireLease {
                    key,
                    owner: live.lease().owner().clone(),
                    ttl: Duration::from_secs(60),
                },
                now,
            )],
        );
        let Ok(SessionMutationOutcome::Lease(lease)) = &acquired.responses[0].result else {
            panic!("key creation past the lifetime bound succeeds")
        };
        index += 1;
        let released = apply(
            &mut storage,
            &[command_at(
                index,
                SessionMutationIntent::ReleaseLease(lease.clone()),
                now,
            )],
        );
        assert!(released.responses[0].result.is_ok());
        index += 1;
        let pruned = apply(
            &mut storage,
            &[command_at(
                index,
                SessionMutationIntent::RefreshTtl {
                    lease: live.lease().clone(),
                    ttl: Duration::from_secs(60),
                },
                now,
            )],
        );
        assert!(pruned.responses[0].result.is_ok());
        created += 1;
        assert_eq!(
            storage.business.keys.len(),
            1 + retained_dead(created) as usize
        );
        index += 1;
    }
    assert_eq!(created, 1_048_577);
    assert_eq!(probed_epochs, BTreeSet::from([1, 2]));
    assert!(storage.business.generic_receipts.len() < 64);
    storage.validate_image().unwrap();
    let old = old_lease.unwrap();
    assert!(
        storage
            .business
            .observe_at(old.key(), now)
            .unwrap()
            .current_fence()
            > old.fence()
    );
    eprintln!(
        "native_key_lifetime opening_catalog elapsed={:?}",
        started.elapsed()
    );
    let (_files, catalog) = Files::with_maximum(&storage, 2 * 1024 * 1024 * 1024);
    let mut reopened = catalog.into_storage(&|| Ok(())).unwrap();
    reopened.validate_image().unwrap();
    assert_eq!(
        reopened.business.keys.len(),
        1 + retained_dead(created) as usize
    );
    assert!(reopened.business.frontiers == storage.business.frontiers);
    assert_eq!(
        reopened.business.observe_at(old.key(), now).unwrap(),
        storage.business.observe_at(old.key(), now).unwrap()
    );
    let stale = command_at(
        index,
        SessionMutationIntent::RenewLease {
            lease: old,
            ttl: Duration::from_secs(60),
        },
        now,
    );
    let rejected = apply(&mut reopened, &[stale]);
    assert_eq!(rejected.responses[0].result, Err(StoreError::LeaseExpired));
    eprintln!(
        "native_key_lifetime reopened elapsed={:?}",
        started.elapsed()
    );
}

#[test]
fn native_key_retention_survives_delta_reopen_and_base_rewrite() {
    use crate::consensus::native::key_retention_tests::{acquired_fixture, command, prune_intent};
    let (mut storage, old) = acquired_fixture();
    let (mut files, catalog) = Files::new(&storage);
    let mut follower = catalog.into_storage(&|| Ok(())).unwrap();
    let captured = storage.capture_snapshot().unwrap();
    storage.begin_changes().unwrap();
    let entries = [
        command(3, SessionMutationIntent::ReleaseLease(old.clone())),
        command(4, prune_intent(&storage)),
    ];
    let leader = apply(&mut storage, &entries);
    let replica = apply(&mut follower, &entries);
    assert_eq!(leader.responses, replica.responses);
    assert!(storage.business.frontiers == follower.business.frontiers);
    assert_eq!(captured.storage.business.keys.len(), 2);
    let catalog = files.append(&mut storage, 19);
    let reopened = catalog.into_storage(&|| Ok(())).unwrap();
    let (_rewritten, catalog) = Files::new(&reopened);
    let rewritten = catalog.into_storage(&|| Ok(())).unwrap();
    for mut candidate in [storage, follower, reopened, rewritten] {
        assert_eq!(candidate.business.keys.len(), 2);
        assert_eq!(
            candidate
                .business
                .observe_at(old.key(), time(2))
                .unwrap()
                .current_fence(),
            old.fence()
        );
        assert_eq!(
            candidate
                .business
                .keys
                .get(old.key())
                .unwrap()
                .retired_epoch,
            Some(0)
        );
        assert_eq!(candidate.business.frontiers.retention.keys.retired_count, 1);
        assert_eq!(candidate.business.frontiers.retention.keys.floor_cur, 0);
        let stale = command(
            5,
            SessionMutationIntent::RenewLease {
                lease: old.clone(),
                ttl: std::time::Duration::from_secs(60),
            },
        );
        let rejected = apply(&mut candidate, &[stale]);
        assert_eq!(rejected.responses[0].result, Err(StoreError::StaleFence));
    }
}

#[test]
fn native_notification_retention_passes_original_lifetime_limit_and_reopens() {
    use crate::fenced_transition::{
        FencedTransitionLease, FencedTransitionMutation, FencedTransitionV2CallerNonce,
        FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES,
    };
    use std::time::Duration;

    // V2 already has a bounded receipt lifecycle. Exercise notifying commands
    // through it so the independent ordinary-receipt lifetime cap cannot hide
    // the notification boundary under test. No state counter is synthesized.
    let started = std::time::Instant::now();
    let (mut storage, _, outcome) = fixture();
    let now = time(2);
    let mutation = FencedTransitionMutation::refresh_ttl(
        outcome.committed_generation(),
        Duration::from_secs(60),
    )
    .unwrap();
    let first = FencedTransitionV2Request::new(
        storage.business.history().unwrap().active_epoch().unwrap(),
        FencedTransitionV2CallerNonce::from_bytes(2_u128.to_be_bytes()),
        FencedTransitionLease::renew(outcome.lease().clone(), Duration::from_secs(60)).unwrap(),
        mutation.clone(),
    )
    .unwrap();
    let applied = apply(&mut storage, &[command(2, &first, now, false)]);
    let Ok(SessionMutationOutcome::FencedTransition(outcome)) = &applied.responses[0].result else {
        panic!("initial refresh commits");
    };
    let lease =
        FencedTransitionLease::renew(outcome.lease().clone(), Duration::from_secs(60)).unwrap();
    let mut key = outcome.lease().key().clone();
    key.stable_id = bytes::Bytes::from_static(b"notification-retention-limit")
        .try_into()
        .unwrap();
    let mut index = 3_u64;
    while storage.business.frontiers.watch_sequence < 1_048_576 {
        let history = storage.business.history().unwrap();
        if history.bound_entries() == FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES {
            let entry =
                crate::consensus::native::lifecycle_tests::maintenance(&storage, index, now);
            let result = apply(&mut storage, &[entry]);
            assert!(result.responses[0].result.is_ok());
            assert!(result.notifications.is_empty());
            index += 1;
            continue;
        }
        // Exercise accumulated apply deliveries. The helper appends bounded
        // RPC chunks and independently validates the complete image after
        // every apply. Grouping the delivery keeps this million-command proof
        // from repeatedly rescanning the same immutable receipt history.
        let count = 32_768.min(FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES - history.bound_entries());
        let entries = (0..count)
            .map(|offset| {
                let next = index + offset as u64;
                let request = FencedTransitionV2Request::new(
                    history.active_epoch().unwrap(),
                    FencedTransitionV2CallerNonce::from_bytes(u128::from(next).to_be_bytes()),
                    lease.clone(),
                    mutation.clone(),
                )
                .unwrap();
                command(next, &request, now, false)
            })
            .collect::<Vec<_>>();
        let result = apply(&mut storage, &entries);
        assert!(result
            .responses
            .iter()
            .all(|response| response.result.is_ok()));
        assert_eq!(result.notifications.len(), count);
        assert!(storage.business.notifications.len() <= 65_536);
        let first_sequence = storage.business.frontiers.watch_sequence - count as u64 + 1;
        for (offset, entry) in result.notifications.iter().enumerate() {
            assert_eq!(entry.sequence, first_sequence + offset as u64);
        }
        index += count as u64;
        if storage.business.history().unwrap().bound_entries()
            == FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES
        {
            eprintln!(
                "native_notification_lifetime committed={} elapsed={:?}",
                storage.business.frontiers.watch_sequence,
                started.elapsed()
            );
        }
        // Exercise the existing selected snapshot/purge contract as the log
        // grows; the independent retained-log cap is not a lifetime budget.
        if storage.log.entries.len() >= 4096 {
            let through = storage.business.applied().unwrap();
            storage
                .business
                .publish_snapshot_metadata(snapshot(&storage, through.index, "retained-window"))
                .unwrap();
            storage
                .log
                .project(&Operation::Purge(through), &storage.business, Some(through))
                .unwrap();
        }
    }
    let result = apply(&mut storage, &[acquire(index, &key)]);
    assert!(result.responses[0].result.is_ok());
    assert_eq!(result.notifications.len(), 1);
    assert_eq!(storage.business.frontiers.watch_sequence, 1_048_577);
    assert_eq!(storage.business.notifications.len(), 65_536);
    assert_eq!(
        storage.business.frontiers.retention.watch_retired_through,
        983_041
    );
    assert_eq!(
        storage
            .business
            .replication_log(983_041, 1, &|| Ok(()))
            .unwrap_err(),
        StoreError::ReplicationLogCursorCompacted {
            resume_from: 983_042
        }
    );
    storage.validate_image().unwrap();
    eprintln!(
        "native_notification_lifetime opening_catalog elapsed={:?}",
        started.elapsed()
    );
    // This proof retains eight complete V2 receipt epochs as well as the
    // notification window, so its image budget is independent of small cases.
    let (_files, catalog) = Files::with_maximum(&storage, 2 * 1024 * 1024 * 1024);
    let reopened = catalog.into_storage(&|| Ok(())).unwrap();
    reopened.validate_image().unwrap();
    assert!(reopened.business.frontiers == storage.business.frontiers);
    assert_eq!(
        reopened
            .business
            .replication_log(983_041, 1, &|| Ok(()))
            .unwrap_err(),
        StoreError::ReplicationLogCursorCompacted {
            resume_from: 983_042
        }
    );
    assert_eq!(
        reopened
            .business
            .replication_log(1_048_577, 1, &|| Ok(()))
            .unwrap()[0]
            .sequence,
        1_048_577
    );
    eprintln!(
        "native_notification_lifetime reopened elapsed={:?}",
        started.elapsed()
    );
}

#[test]
fn native_notification_retention_survives_checkpoint_reopen_and_base_rewrite() {
    let (mut storage, key) = window_fixture();
    let (mut files, catalog) = Files::with_maximum(&storage, RETENTION_IMAGE_MAXIMUM);
    let mut follower = catalog.into_storage(&|| Ok(())).unwrap();
    let before = storage.capture_snapshot().unwrap();
    storage.begin_changes().unwrap();
    for index in 3..11 {
        let entry = acquire(index, &key);
        let leader = apply(&mut storage, std::slice::from_ref(&entry));
        let replica = apply(&mut follower, &[entry]);
        assert_eq!(leader.responses, replica.responses);
        assert_eq!(leader.notifications, replica.notifications);
        assert!(storage.business.frontiers == follower.business.frontiers);
    }
    assert_eq!(
        storage.business.frontiers.retention.watch_retired_through,
        8
    );
    assert_eq!(
        before
            .storage
            .business
            .frontiers
            .retention
            .watch_retired_through,
        0
    );
    assert_eq!(
        before
            .storage
            .business
            .notifications
            .front()
            .unwrap()
            .sequence(),
        1
    );
    let catalog = files.append(&mut storage, 19);
    let reopened = catalog.into_storage(&|| Ok(())).unwrap();
    for state in [&storage.business, &follower.business, &reopened.business] {
        assert_eq!(state.notifications.len(), retention::NOTIFICATION_WINDOW);
        assert_eq!(
            state.replication_log(8, 1, &|| Ok(())).unwrap_err(),
            StoreError::ReplicationLogCursorCompacted { resume_from: 9 }
        );
        assert_eq!(
            state.replication_log(9, 1, &|| Ok(())).unwrap()[0].sequence,
            9
        );
    }
    let (_rewritten, catalog) = Files::with_maximum(&reopened, RETENTION_IMAGE_MAXIMUM);
    let rewritten = catalog.into_storage(&|| Ok(())).unwrap();
    assert!(rewritten.business.frontiers == reopened.business.frontiers);
    assert_eq!(
        rewritten
            .business
            .replication_log(8, 1, &|| Ok(()))
            .unwrap_err(),
        StoreError::ReplicationLogCursorCompacted { resume_from: 9 }
    );
}

#[test]
fn native_notification_retention_relocation_tracks_sequence_after_concurrent_pruning() {
    let (mut storage, key) = window_fixture();
    let (mut files, _) = Files::with_maximum(&storage, RETENTION_IMAGE_MAXIMUM);
    storage.begin_changes().unwrap();
    apply(&mut storage, &[acquire(3, &key)]);
    let prepared = files.prepare(&mut storage, 19);
    let (_, mut relocations) = prepared
        .append_with_relocations(&mut files.owner, &|| Ok(()))
        .unwrap();
    apply(&mut storage, &[acquire(4, &key)]);
    while !relocations.is_empty() {
        drop(relocations.publish_step(&mut storage).unwrap());
    }
    let first_new = retention::NOTIFICATION_WINDOW as u64 + 1;
    let position = storage
        .business
        .frontiers
        .notification_position(first_new)
        .unwrap();
    assert!(storage.business.notifications[position].is_selected_for_test());
    assert_eq!(
        storage.business.notifications[position].sequence(),
        first_new
    );
    assert_eq!(
        storage
            .business
            .replication_log(first_new, 2, &|| Ok(()))
            .unwrap()
            .iter()
            .map(|row| row.sequence)
            .collect::<Vec<_>>(),
        [first_new, first_new + 1]
    );
    storage.validate_image().unwrap();
}

// Verify compact-base relocation across a sparse retained notification window.
#[test]
fn native_notification_retention_compact_base_relocates_the_selected_sparse_window() {
    let (mut storage, key) = window_fixture();
    for index in 3..11 {
        apply(&mut storage, &[acquire(index, &key)]);
    }
    let floor = storage.business.frontiers.retention.watch_retired_through;
    assert_eq!(floor, 8);
    assert_eq!(storage.cold_counts_for_test()[1], 0);
    let capture = storage.capture_snapshot().unwrap();
    let (files, catalog) = Files::with_maximum(&storage, RETENTION_IMAGE_MAXIMUM);
    let mut relocations = Relocations::from_base(capture, files.owner.current()).unwrap();
    while !relocations.is_empty() {
        relocations.prepare_step(&|| Ok(())).unwrap();
        drop(relocations.publish_step(&mut storage).unwrap());
    }
    assert_eq!(
        storage.cold_counts_for_test()[1],
        retention::NOTIFICATION_WINDOW
    );
    assert!(storage
        .business
        .notifications
        .iter()
        .all(|row| row.is_selected_for_test()));
    assert_eq!(
        storage.business.notifications.front().unwrap().sequence(),
        floor + 1
    );
    assert_eq!(
        storage.business.notifications.back().unwrap().sequence(),
        storage.business.frontiers.watch_sequence
    );
    storage.validate_image().unwrap();
    let reopened = catalog.into_storage(&|| Ok(())).unwrap();
    assert_eq!(
        Version::capture(&reopened)
            .unwrap()
            .context_digest()
            .unwrap(),
        Version::capture(&storage)
            .unwrap()
            .context_digest()
            .unwrap()
    );
    assert_eq!(
        reopened
            .business
            .replication_log(floor, 1, &|| Ok(()))
            .unwrap_err(),
        StoreError::ReplicationLogCursorCompacted {
            resume_from: floor + 1
        }
    );
}

#[test]
fn native_epoch_capacity_rotation_survives_delta_reopen_and_base_rewrite() {
    use crate::consensus::native::key_retention_tests::{
        capacity_replacement, retired_key_fixture,
    };
    let (mut storage, old) = retired_key_fixture();
    let (mut files, catalog) = Files::new(&storage);
    drop(catalog);
    let mut key = old.key().clone();
    key.stable_id = bytes::Bytes::from_static(b"capacity-reopen-replacement")
        .try_into()
        .unwrap();
    storage.begin_changes().unwrap();
    let lease = capacity_replacement(&mut storage, key, 5, 2);
    let expected = storage.business.frontiers.retention.keys;
    let catalog = files.append(&mut storage, 19);
    let reopened = catalog.into_storage(&|| Ok(())).unwrap();
    let (_rewritten, catalog) = Files::new(&reopened);
    let rewritten = catalog.into_storage(&|| Ok(())).unwrap();
    for candidate in [storage, reopened, rewritten] {
        assert_eq!(candidate.business.frontiers.retention.keys, expected);
        assert_eq!(expected.epoch, 2);
        assert_eq!(
            expected.last_rotation,
            Some(crate::key_retention::RotationReason::Capacity)
        );
        assert_eq!(candidate.business.keys.len(), 2);
        assert!(!candidate.business.keys.contains_key(old.key()));
        assert_eq!(
            candidate
                .business
                .observe_at(old.key(), time(2))
                .unwrap()
                .current_fence()
                .get(),
            expected.floor_cur
        );
        assert_eq!(
            candidate
                .business
                .observe_at(lease.key(), time(2))
                .unwrap()
                .current_fence(),
            lease.fence()
        );
        candidate.validate_image().unwrap();
    }
}

#[test]
fn native_catalog_refuses_untagged_live_key_removal_below_the_previous_floor() {
    use crate::consensus::native::key_retention_tests::acquired_fixture;
    let (mut storage, lease) = acquired_fixture();
    storage.business.frontiers.retention.keys.retired_max = lease.fence().get();
    storage
        .business
        .frontiers
        .rotate_keys(crate::key_retention::RotationReason::Capacity)
        .unwrap();
    storage
        .business
        .frontiers
        .rotate_keys(crate::key_retention::RotationReason::Capacity)
        .unwrap();
    assert!(lease.fence().get() < storage.business.frontiers.retention.keys.floor_prev);
    storage.business.admit_business().unwrap();
    let (files, old) = Files::new(&storage);
    let key = lease.key();
    let predecessor = old.rows.keys[&facts::KeyId::of(key).unwrap()].row;
    assert!(predecessor.facts.credential.is_some());
    assert!(predecessor.facts.retired_epoch.is_none());
    storage.begin_changes().unwrap();
    apply(&mut storage, &[clock(3, time(2))]);
    let prepared = files.prepare(&mut storage, 19);
    let mut payload = Vec::new();
    prepared.write_payload(&mut payload, &|| Ok(())).unwrap();
    let mut wire = Wire::<Header>::read(&payload);
    assert_eq!(wire.header.changed[0], 0);
    let mut frame = vec![0];
    write_before(&mut frame, Some(predecessor.content)).unwrap();
    write_binary(&mut frame, &(key, None::<NativeKeyState>)).unwrap();
    wire.body.splice(0..0, frame);
    wire.header.changed[0] = 1;
    wire.header.after.business.counts[0] -= 1;
    replace_hash(
        &mut wire.header.after.business.content[0],
        predecessor.content,
        [0; 32],
    );
    let bytes = wire.encode(MAGIC, files.bytes());
    let mut identity = old.identity();
    identity.checkpoint_epoch += 1;
    identity.operation_sequence = 19;
    let error = reject(
        &bytes,
        rebound(&bytes, identity, &wire.header.after),
        &storage,
        wire.header.cut_binding,
    );
    assert!(error.contains("key retirement"), "{error}");
}

#[test]
fn native_key_removal_witness_survives_a_capture_from_live_authority() {
    use crate::consensus::native::key_retention_tests::{
        acquired_fixture, capacity_replacement, command as ordinary_command, prune_intent,
    };
    let (mut storage, lease) = acquired_fixture();
    let key = lease.key().clone();
    assert!(storage.business.keys[&key].lease.is_some());
    assert!(storage.business.keys[&key].retired_epoch.is_none());
    let (mut files, catalog) = Files::new(&storage);
    drop(catalog);
    storage.begin_changes().unwrap();
    let released = apply(
        &mut storage,
        &[ordinary_command(
            3,
            SessionMutationIntent::ReleaseLease(lease),
        )],
    );
    assert!(released.responses[0].result.is_ok());
    let prune = ordinary_command(4, prune_intent(&storage));
    assert!(apply(&mut storage, &[prune]).responses[0].result.is_ok());
    assert_eq!(storage.business.keys[&key].retired_epoch, Some(0));
    let mut replacement = key.clone();
    replacement.stable_id = bytes::Bytes::from_static(b"witness-live-predecessor")
        .try_into()
        .unwrap();
    capacity_replacement(&mut storage, replacement, 5, 2);
    assert!(!storage.business.keys.contains_key(&key));
    let expected = Version::capture(&storage)
        .unwrap()
        .context_digest()
        .unwrap();
    let catalog = files.append(&mut storage, 19);
    let reopened = catalog.into_storage(&|| Ok(())).unwrap();
    assert!(!reopened.business.keys.contains_key(&key));
    assert_eq!(
        Version::capture(&reopened)
            .unwrap()
            .context_digest()
            .unwrap(),
        expected
    );
    reopened.validate_image().unwrap();
    let (_rewritten, catalog) = Files::new(&reopened);
    let rewritten = catalog.into_storage(&|| Ok(())).unwrap();
    assert_eq!(
        Version::capture(&rewritten)
            .unwrap()
            .context_digest()
            .unwrap(),
        expected
    );
}

#[test]
fn native_catalog_refuses_retirement_witness_older_than_a_live_predecessor() {
    use crate::consensus::native::key_retention_tests::acquired_fixture;
    let (mut storage, lease) = acquired_fixture();
    storage.business.frontiers.retention.keys.retired_max = lease.fence().get();
    storage
        .business
        .frontiers
        .rotate_keys(crate::key_retention::RotationReason::Capacity)
        .unwrap();
    storage
        .business
        .frontiers
        .rotate_keys(crate::key_retention::RotationReason::Capacity)
        .unwrap();
    assert!(lease.fence().get() < storage.business.frontiers.retention.keys.floor_prev);
    storage.business.admit_business().unwrap();
    let (files, old) = Files::new(&storage);
    let key = lease.key();
    let predecessor = old.rows.keys[&facts::KeyId::of(key).unwrap()].row;
    assert!(predecessor.facts.credential.is_some());
    assert!(predecessor.facts.retired_epoch.is_none());
    storage.begin_changes().unwrap();
    apply(&mut storage, &[clock(3, time(2))]);
    let prepared = files.prepare(&mut storage, 19);
    let mut payload = Vec::new();
    prepared.write_payload(&mut payload, &|| Ok(())).unwrap();
    let mut wire = Wire::<Header>::read(&payload);
    assert_eq!(wire.header.changed[0], 0);
    let mut frame = vec![0];
    write_before(&mut frame, Some(predecessor.content)).unwrap();
    write_binary(&mut frame, &(key, None::<NativeKeyState>)).unwrap();
    // A live predecessor in epoch 2 cannot have retired in epoch 0.
    // Rehash the entire forged cut so rejection must come from semantics.
    write_binary(&mut frame, &(lease.fence().get(), 0_u64)).unwrap();
    wire.body.splice(0..0, frame);
    wire.header.changed[0] = 1;
    wire.header.after.business.counts[0] -= 1;
    replace_hash(
        &mut wire.header.after.business.content[0],
        predecessor.content,
        [0; 32],
    );
    let bytes = wire.encode(MAGIC, files.bytes());
    let mut identity = old.identity();
    identity.checkpoint_epoch += 1;
    identity.operation_sequence = 19;
    let error = reject(
        &bytes,
        rebound(&bytes, identity, &wire.header.after),
        &storage,
        wire.header.cut_binding,
    );
    assert!(error.contains("key retirement"), "{error}");
}

#[test]
fn native_capacity_application_marker_survives_delta_and_base_rewrite() {
    use crate::consensus::native::{key_retention_tests, retention};
    let (mut storage, retired) = key_retention_tests::retired_key_fixture();
    let (mut files, _) = Files::new(&storage);
    storage.begin_changes().unwrap();
    let mut key = retired.key().clone();
    key.stable_id = bytes::Bytes::from_static(b"cold-capacity-successor")
        .try_into()
        .unwrap();
    let entry = key_retention_tests::command_at(
        5,
        SessionMutationIntent::AcquireLease {
            key,
            owner: crate::OwnerId::new("capacity-owner").unwrap(),
            ttl: std::time::Duration::from_secs(60),
        },
        time(2),
    );
    let applied = retention::with_key_capacity_limit_for_test(2, || {
        changes::tests::apply(&mut storage, &[entry])
    });
    assert_eq!(applied.notifications.len(), 1);
    assert!(applied.notifications[0].replay_policy.capacity_rotations == 2);
    let expected_entries = storage.business.replication_log(1, 16, &|| Ok(())).unwrap();
    let expected = Version::capture(&storage)
        .unwrap()
        .context_digest()
        .unwrap();
    let cold = files
        .append(&mut storage, 31)
        .into_storage(&|| Ok(()))
        .unwrap();
    assert_eq!(
        cold.business.replication_log(1, 16, &|| Ok(())).unwrap(),
        expected_entries
    );
    assert_eq!(
        Version::capture(&cold).unwrap().context_digest().unwrap(),
        expected
    );
    cold.validate_image().unwrap();
    let (_rewritten, catalog) = Files::new(&cold);
    let rewritten = catalog.into_storage(&|| Ok(())).unwrap();
    assert_eq!(
        rewritten
            .business
            .replication_log(1, 16, &|| Ok(()))
            .unwrap(),
        expected_entries
    );
    assert_eq!(
        Version::capture(&rewritten)
            .unwrap()
            .context_digest()
            .unwrap(),
        expected
    );
    rewritten.validate_image().unwrap();
}

#[test]
fn native_capacity_boundaries_survive_full_image_and_generation_base_rewrite() {
    let (mut storage, old) = crate::consensus::native::key_retention_tests::retired_key_fixture();
    let (mut delta_files, _) = Files::new(&storage);
    storage.begin_changes().unwrap();
    crate::consensus::native::key_retention_tests::apply_capacity_boundary_commands(
        &mut storage,
        &old,
    );
    let expected_entries = storage.business.replication_log(1, 32, &|| Ok(())).unwrap();
    let expected = Version::capture(&storage)
        .unwrap()
        .context_digest()
        .unwrap();
    let delta = delta_files
        .append(&mut storage, 31)
        .into_storage(&|| Ok(()))
        .unwrap();
    delta.validate_image().unwrap();
    assert_eq!(
        delta.business.replication_log(1, 32, &|| Ok(())).unwrap(),
        expected_entries
    );
    assert_eq!(
        Version::capture(&delta).unwrap().context_digest().unwrap(),
        expected
    );
    let mut bytes = Vec::new();
    storage.write_image(&mut bytes, [0x39; 32], 27).unwrap();
    let cold = NativeStorage::read_image(
        &mut bytes.as_slice(),
        [0x39; 32],
        27,
        storage.business.identity,
    )
    .unwrap();
    assert_eq!(
        cold.business.replication_log(1, 32, &|| Ok(())).unwrap(),
        expected_entries
    );
    assert_eq!(
        Version::capture(&cold).unwrap().context_digest().unwrap(),
        expected
    );
    let (_files, catalog) = Files::new(&cold);
    let rewritten = catalog.into_storage(&|| Ok(())).unwrap();
    rewritten.validate_image().unwrap();
    assert_eq!(
        rewritten
            .business
            .replication_log(1, 32, &|| Ok(()))
            .unwrap(),
        expected_entries
    );
    assert_eq!(
        Version::capture(&rewritten)
            .unwrap()
            .context_digest()
            .unwrap(),
        expected
    );
}
