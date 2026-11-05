use super::*;
use crate::consensus::native::test_journal::journal_page_for_test_sync;
use changes::tests::{clock, fixture, time};
use std::time::Duration;

pub(in crate::consensus::native) fn command(
    index: u64,
    intent: SessionMutationIntent,
) -> Entry<SessionRaftTypeConfig> {
    command_at(index, intent, time(2))
}

pub(in crate::consensus::native) fn command_at(
    index: u64,
    intent: SessionMutationIntent,
    now: Timestamp,
) -> Entry<SessionRaftTypeConfig> {
    let mut entry = clock(index, now);
    let EntryPayload::Normal(command) = &mut entry.payload else {
        unreachable!()
    };
    command.intent = intent;
    entry
}

pub(in crate::consensus::native) fn ephemeral_request(
    key: SessionKey,
    nonce: u64,
    floor: u64,
    epoch: crate::FencedTransitionV2HistoryEpoch,
    now: Timestamp,
) -> FencedTransitionV2Request {
    use crate::fenced_transition::{
        FencedTransitionLease, FencedTransitionMutation, FencedTransitionV2CallerNonce,
    };
    use crate::{EncryptedSessionPayload, FenceToken, Generation, OwnerId, StateClass, StateType};
    let owner = OwnerId::new("key-retention-owner").unwrap();
    let lease = FencedTransitionLease::acquire(
        key.clone(),
        owner.clone(),
        FenceToken::new(floor),
        Duration::from_secs(1),
    )
    .unwrap();
    let mut record = StoredSessionRecord {
        key,
        generation: Generation::new(1),
        owner,
        fence: FenceToken::new(floor + 1),
        state_class: StateClass::EphemeralProcedure,
        state_type: StateType::from_static("key-retention-test"),
        expires_at: Some(now.add_seconds(1).unwrap()),
        payload: EncryptedSessionPayload::new([]),
    };
    let handle = opc_key::KeyHandle::new(
        opc_key::KeyId::new("key-retention-vector").unwrap(),
        opc_key::KeyPurpose::Session,
        record.key.tenant.clone(),
        opc_key::Zeroizing::new([0xAE; opc_key::AES_256_GCM_SIV_KEY_LEN]),
    );
    let aad =
        crate::record::build_session_envelope_aad(&record, "key-retention-test", &handle).unwrap();
    let mut iv = [0; opc_key::AES_256_GCM_SIV_NONCE_LEN];
    iv[4..].copy_from_slice(&nonce.to_be_bytes());
    let encoded = opc_crypto::encrypt_envelope_with_handle_and_nonce(
        &handle,
        &aad,
        b"key retention vector",
        iv,
    )
    .unwrap();
    assert_eq!(
        opc_crypto::decrypt_envelope_with_handle(&handle, &aad, &encoded)
            .unwrap()
            .as_slice(),
        b"key retention vector"
    );
    record.payload = EncryptedSessionPayload::try_envelope(encoded).unwrap();
    FencedTransitionV2Request::new(
        epoch,
        FencedTransitionV2CallerNonce::from_bytes(u128::from(nonce).to_be_bytes()),
        lease,
        FencedTransitionMutation::create(record),
    )
    .unwrap()
}

pub(crate) fn acquired_fixture() -> (NativeStorage, LeaseGuard) {
    let (mut storage, _, live) = fixture();
    let mut key = live.lease().key().clone();
    key.stable_id = bytes::Bytes::from_static(b"retired-key")
        .try_into()
        .unwrap();
    let applied = changes::tests::apply(
        &mut storage,
        &[command(
            2,
            SessionMutationIntent::AcquireLease {
                key,
                owner: crate::OwnerId::new("retention-owner").unwrap(),
                ttl: Duration::from_secs(60),
            },
        )],
    );
    let Ok(SessionMutationOutcome::Lease(lease)) = &applied.responses[0].result else {
        panic!("acquire must succeed")
    };
    (storage, lease.clone())
}

pub(in crate::consensus::native) fn prune_intent(storage: &NativeStorage) -> SessionMutationIntent {
    let (key, _) = storage
        .business
        .keys
        .iter()
        .find(|(_, row)| row.record.is_some())
        .unwrap();
    SessionMutationIntent::RefreshTtl {
        lease: storage.business.retained_lease_for_test(key).unwrap(),
        ttl: Duration::from_secs(60),
    }
}

pub(crate) fn retired_key_fixture() -> (NativeStorage, LeaseGuard) {
    let (mut storage, lease) = acquired_fixture();
    let result = changes::tests::apply(
        &mut storage,
        &[command(
            3,
            SessionMutationIntent::ReleaseLease(lease.clone()),
        )],
    );
    assert!(result.responses[0].result.is_ok());
    let prune = command(4, prune_intent(&storage));
    let result = changes::tests::apply(&mut storage, &[prune]);
    assert!(result.responses[0].result.is_ok());
    (storage, lease)
}

#[test]
fn native_key_retention_is_independent_of_delivery_batches() {
    let (mut leader, old) = acquired_fixture();
    let mut follower = leader.clone();
    let intents = [
        SessionMutationIntent::ReleaseLease(old.clone()),
        prune_intent(&leader),
        SessionMutationIntent::AcquireLease {
            key: old.key().clone(),
            owner: old.owner().clone(),
            ttl: Duration::from_secs(60),
        },
        SessionMutationIntent::RenewLease {
            lease: old.clone(),
            ttl: Duration::from_secs(60),
        },
    ];
    let entries: Vec<_> = intents
        .into_iter()
        .enumerate()
        .map(|(offset, intent)| command(3 + offset as u64, intent))
        .collect();
    let mut responses = Vec::new();
    for entry in &entries {
        responses.extend(changes::tests::apply(&mut leader, std::slice::from_ref(entry)).responses);
    }
    let combined = changes::tests::apply(&mut follower, &entries);
    assert_eq!(responses, combined.responses);
    assert!(leader.business.frontiers == follower.business.frontiers);
    assert_eq!(
        leader.business.observe_at(old.key(), time(2)).unwrap(),
        follower.business.observe_at(old.key(), time(2)).unwrap()
    );
    assert_eq!(leader.business.keys.len(), follower.business.keys.len());
}

#[test]
fn native_key_retention_retires_dead_keys_without_reviving_stale_credentials() {
    let (mut storage, _, live) = fixture();
    let mut key = live.lease().key().clone();
    key.stable_id = bytes::Bytes::from_static(b"retired-key")
        .try_into()
        .unwrap();
    let acquire = |index| {
        command(
            index,
            SessionMutationIntent::AcquireLease {
                key: key.clone(),
                owner: crate::OwnerId::new("retention-owner").unwrap(),
                ttl: Duration::from_secs(60),
            },
        )
    };
    let applied = changes::tests::apply(&mut storage, &[acquire(2)]);
    let Ok(SessionMutationOutcome::Lease(old)) = &applied.responses[0].result else {
        panic!("acquire must succeed")
    };
    let released = changes::tests::apply(
        &mut storage,
        &[command(3, SessionMutationIntent::ReleaseLease(old.clone()))],
    );
    assert!(released.responses[0].result.is_ok());
    let prune = command(4, prune_intent(&storage));
    let pruned = changes::tests::apply(&mut storage, &[prune]);
    assert!(pruned.responses[0].result.is_ok());
    assert_eq!(
        storage.business.keys.len(),
        2,
        "live and recently dead keys remain exact"
    );
    let observation = storage.business.observe_at(&key, time(2)).unwrap();
    assert!(observation.record().is_none());
    assert_eq!(observation.current_fence(), old.fence());
    let stale = |index| {
        command(
            index,
            SessionMutationIntent::RenewLease {
                lease: old.clone(),
                ttl: Duration::from_secs(60),
            },
        )
    };
    let rejected = changes::tests::apply(&mut storage, &[stale(5)]);
    assert_eq!(rejected.responses[0].result, Err(StoreError::StaleFence));
    let recreated = changes::tests::apply(&mut storage, &[acquire(6)]);
    let Ok(SessionMutationOutcome::Lease(new)) = &recreated.responses[0].result else {
        panic!("recreation must succeed")
    };
    assert!(new.fence() > observation.current_fence());
    let rejected = changes::tests::apply(&mut storage, &[stale(7)]);
    assert_eq!(rejected.responses[0].result, Err(StoreError::StaleFence));
    let renewed = changes::tests::apply(
        &mut storage,
        &[command(
            8,
            SessionMutationIntent::RenewLease {
                lease: live.lease().clone(),
                ttl: Duration::from_secs(60),
            },
        )],
    );
    assert!(
        renewed.responses[0].result.is_ok(),
        "live authority survives"
    );
}

pub(in crate::consensus::native) fn capacity_replacement(
    storage: &mut NativeStorage,
    key: SessionKey,
    index: u64,
    maximum: usize,
) -> LeaseGuard {
    use crate::sqlite::consensus::wal::Operation;
    let entry = command(
        index,
        SessionMutationIntent::AcquireLease {
            key,
            owner: crate::OwnerId::new("retention-capacity-owner").unwrap(),
            ttl: Duration::from_secs(60),
        },
    );
    storage
        .log
        .project(
            &Operation::Append(vec![serde_json::to_vec(&entry).unwrap().into()]),
            &storage.business,
            None,
        )
        .unwrap();
    storage
        .log
        .project(
            &Operation::Committed(Some(entry.log_id)),
            &storage.business,
            None,
        )
        .unwrap();
    let mut delta = storage.business.prepare(&[entry]).unwrap();
    // Exercise the production finalizer inside the same unpublished command.
    // Production uses MAX_ITEMS; this unit test uses a two-row resident cap.
    delta.rotate_key_capacity_at(maximum).unwrap();
    let applied = changes::Publication::prepare(delta)
        .unwrap()
        .publish(&mut storage.business)
        .unwrap();
    storage.validate_image().unwrap();
    let Ok(SessionMutationOutcome::Lease(lease)) = &applied.responses[0].result else {
        panic!("capacity replacement must commit");
    };
    lease.clone()
}

#[test]
fn native_epoch_capacity_reclaims_dead_history_and_preserves_live_exact_fences() {
    let (mut storage, old) = retired_key_fixture();
    let mut replacement = old.key().clone();
    replacement.stable_id = bytes::Bytes::from_static(b"native-capacity-replacement")
        .try_into()
        .unwrap();
    let lease = capacity_replacement(&mut storage, replacement, 5, 2);
    let retention = storage.business.frontiers.retention.keys;
    assert_eq!(retention.epoch, 2);
    assert_eq!(retention.floor_prev, old.fence().get() + 1);
    assert_eq!(retention.floor_cur, old.fence().get() + 2);
    assert_eq!(retention.retired_count, 0);
    assert_eq!(retention.retired_max, 0);
    assert_eq!(
        retention.last_rotation,
        Some(crate::key_retention::RotationReason::Capacity)
    );
    assert_eq!(storage.business.keys.len(), 2);
    assert!(!storage.business.keys.contains_key(old.key()));
    assert!(old.fence().get() < retention.floor_prev);
    assert_eq!(
        storage
            .business
            .observe_at(old.key(), time(2))
            .unwrap()
            .current_fence()
            .get(),
        retention.floor_cur
    );
    assert!(lease.fence().get() < retention.floor_cur);
    assert_eq!(
        storage
            .business
            .observe_at(lease.key(), time(2))
            .unwrap()
            .current_fence(),
        lease.fence()
    );
    let (live_key, live) = storage
        .business
        .keys
        .iter()
        .find(|(_, row)| row.record.is_some())
        .unwrap();
    assert_eq!(
        storage
            .business
            .observe_at(live_key, time(2))
            .unwrap()
            .current_fence()
            .get(),
        live.fence
    );
    let mut fresh = old.key().clone();
    fresh.stable_id = bytes::Bytes::from_static(b"native-capacity-old-preparation")
        .try_into()
        .unwrap();
    let request = ephemeral_request(
        fresh.clone(),
        6,
        0,
        storage.business.history().unwrap().active_epoch().unwrap(),
        time(2),
    );
    let next_fence = storage.business.frontiers.next_fence;
    let watch_sequence = storage.business.frontiers.watch_sequence;
    let applied = changes::tests::apply(
        &mut storage,
        &[changes::tests::command(6, &request, time(2), false)],
    );
    assert_eq!(applied.responses[0].result, Err(StoreError::StaleFence));
    assert!(applied.notifications.is_empty());
    assert_eq!(storage.business.frontiers.retention.keys, retention);
    assert_eq!(storage.business.frontiers.next_fence, next_fence);
    assert_eq!(storage.business.frontiers.watch_sequence, watch_sequence);
    assert_eq!(storage.business.keys.len(), 2);
    assert!(!storage.business.keys.contains_key(&fresh));
}

#[test]
fn native_key_removal_requires_an_old_retirement_tag_even_below_the_floor() {
    let (storage, lease) = acquired_fixture();
    let live = storage.business.keys.get(lease.key()).unwrap();
    assert!(live.lease.is_some());
    assert!(live.retired_epoch.is_none());
    let mut frontiers = storage.business.frontiers.clone();
    frontiers.retention.keys.retired_max = lease.fence().get();
    frontiers
        .rotate_keys(crate::key_retention::RotationReason::Capacity)
        .unwrap();
    frontiers
        .rotate_keys(crate::key_retention::RotationReason::Capacity)
        .unwrap();
    assert!(lease.fence().get() < frontiers.retention.keys.floor_prev);
    assert!(
        frontiers
            .retention
            .validate_key_removal(lease.key(), Some(live))
            .is_err(),
        "live authority below the namespace floor still requires its exact row"
    );
    let mut dead = NativeKeyState {
        fence: lease.fence().get(),
        ..Default::default()
    };
    assert!(
        frontiers
            .retention
            .validate_key_removal(lease.key(), Some(&dead))
            .is_err(),
        "untagged dead rows have not completed their retention window"
    );
    for epoch in [1, 2, 3] {
        dead.retired_epoch = Some(epoch);
        assert!(
            frontiers
                .retention
                .validate_key_removal(lease.key(), Some(&dead))
                .is_err(),
            "current, previous and future tags cannot authorize removal: {epoch}"
        );
    }
    dead.retired_epoch = Some(0);
    frontiers
        .retention
        .validate_key_removal(lease.key(), Some(&dead))
        .unwrap();
}

/// Capacity fixture that runs the actual entry finalizer, including its journal decision.
pub(crate) fn rotated_application_fixture() -> (NativeStorage, LeaseGuard) {
    let (mut storage, old) = retired_key_fixture();
    let mut key = old.key().clone();
    key.stable_id = bytes::Bytes::from_static(b"portable-capacity-successor")
        .try_into()
        .unwrap();
    let entry = command(
        5,
        SessionMutationIntent::AcquireLease {
            key,
            owner: crate::OwnerId::new("retention-capacity-owner").unwrap(),
            ttl: Duration::from_secs(60),
        },
    );
    let applied = retention::with_key_capacity_limit_for_test(2, || {
        changes::tests::apply(&mut storage, &[entry])
    });
    assert!(applied.responses[0].result.is_ok());
    (storage, old)
}

/// A real zero-effect capacity boundary followed by a two-effect command boundary.
pub(crate) fn capacity_boundary_application_fixture() -> NativeStorage {
    let (mut storage, old) = retired_key_fixture();
    apply_capacity_boundary_commands(&mut storage, &old);
    storage
}

pub(in crate::consensus::native) fn apply_capacity_boundary_commands(
    storage: &mut NativeStorage,
    old: &LeaseGuard,
) {
    let identity = storage.business.identity;
    let cleanup_lease = storage
        .business
        .keys
        .iter()
        .find_map(|(key, row)| {
            row.record
                .as_ref()
                .and_then(|_| storage.business.retained_lease_for_test(key))
        })
        .unwrap();
    let activation = command(
        5,
        SessionMutationIntent::Authorized {
            origin: *storage.business.members.first().unwrap(),
            authority_identity: identity,
            mutation: Box::new(SessionMutationIntent::ActivateScopeProfile(Box::new(
                crate::scope_authority::ScopeProfileActivation::new(
                    identity,
                    fenced_transition_voter_set_digest(identity, &storage.business.members),
                ),
            ))),
        },
    );
    let result = retention::with_key_capacity_limit_for_test(2, || {
        changes::tests::apply(storage, std::slice::from_ref(&activation))
    });
    assert!(result.responses[0].result.is_ok());
    assert!(
        matches!(&result.notifications[0].op, crate::ReplicationOp::Batch { ops } if ops.is_empty())
            && result.notifications[0].replay_policy.command
                == crate::ReplicationCommandBoundary::Single
    );
    for offset in 0..2 {
        let index = storage.business.frontiers.applied.unwrap().index + 1;
        let mut key = old.key().clone();
        key.stable_id = bytes::Bytes::from(format!("boundary-retired-{offset}"))
            .try_into()
            .unwrap();
        let result = changes::tests::apply(
            storage,
            &[command(
                index,
                SessionMutationIntent::AcquireLease {
                    key,
                    owner: crate::OwnerId::new("boundary-owner").unwrap(),
                    ttl: Duration::from_secs(60),
                },
            )],
        );
        let Ok(SessionMutationOutcome::Lease(lease)) = &result.responses[0].result else {
            panic!("acquire")
        };
        let release = command(
            index + 1,
            SessionMutationIntent::ReleaseLease(lease.clone()),
        );
        let prune = command(
            index + 2,
            SessionMutationIntent::RefreshTtl {
                lease: cleanup_lease.clone(),
                ttl: Duration::from_secs(60),
            },
        );
        assert!(changes::tests::apply(storage, &[release, prune])
            .responses
            .iter()
            .all(|r| r.result.is_ok()));
    }
    let history = storage.business.history().unwrap().active_epoch().unwrap();
    let floor = storage.business.frontiers.retention.keys.floor_cur;
    let requests = (0..2)
        .map(|offset| {
            let mut key = old.key().clone();
            key.stable_id = bytes::Bytes::from(format!("boundary-created-{offset}"))
                .try_into()
                .unwrap();
            ephemeral_request(key, 8000 + offset, floor, history, time(2))
        })
        .collect::<Vec<_>>();
    let request_id =
        crate::consensus::types::fenced_transition_v2_batch_outer_request_id(&requests).unwrap();
    let mut entry = command(
        storage.business.frontiers.applied.unwrap().index + 1,
        SessionMutationIntent::FencedTransitionV2Batch(requests),
    );
    let EntryPayload::Normal(command) = &mut entry.payload else {
        unreachable!()
    };
    command.request_id = SessionConsensusRequestId::from_bytes(request_id);
    let maximum = storage.business.keys.len();
    let result = retention::with_key_capacity_limit_for_test(maximum, || {
        changes::tests::apply(storage, &[entry])
    });
    let Ok(SessionMutationOutcome::FencedTransitionV2Batch(outcomes)) = &result.responses[0].result
    else {
        panic!("batch succeeds")
    };
    assert!(outcomes.iter().all(Result::is_ok));
    assert!(matches!(
        result.notifications[0].replay_policy.command,
        crate::ReplicationCommandBoundary::Start {
            following_entries: 1,
            ..
        }
    ));
    storage.validate_image().unwrap();
}

#[test]
fn native_metadata_capacity_reserves_its_watch_counter_before_key_publication() {
    for head in [COUNTER_MAX - 1, COUNTER_MAX] {
        let (mut storage, old) = retired_key_fixture();
        // An admitted bounded window isolates the signed counter horizon;
        // retirement still uses its original threshold and actual dead row.
        let original =
            journal_page_for_test_sync(|| storage.business.replication_log(1, 16, &|| Ok(())))
                .pop()
                .unwrap();
        storage.business.notifications.clear();
        let window = retention::NOTIFICATION_WINDOW as u64;
        for sequence in head - window + 1..=head {
            storage.business.notifications.push_back(
                NotificationRow::new(NativeNotification::new(ReplicationEntry {
                    sequence,
                    ..original.clone()
                }))
                .unwrap(),
            );
        }
        storage.business.frontiers.watch_sequence = head;
        storage.business.frontiers.retention.watch_retired_through = head - window;
        storage.business.admit_business().unwrap();
        storage.log.admit(&storage.business).unwrap();
        storage.validate_image().unwrap();
        let before = storage.business.frontiers.retention.keys;
        let next_fence = storage.business.frontiers.next_fence;
        let next_credential = storage.business.frontiers.next_credential;
        let rows = storage
            .business
            .keys
            .iter()
            .map(|(key, row)| (key.clone(), postcard::to_allocvec(&**row).unwrap()))
            .collect::<Vec<_>>();
        let identity = storage.business.identity;
        let entry = command(
            5,
            SessionMutationIntent::Authorized {
                origin: *storage.business.members.first().unwrap(),
                authority_identity: identity,
                mutation: Box::new(SessionMutationIntent::ActivateScopeProfile(Box::new(
                    crate::scope_authority::ScopeProfileActivation::new(
                        identity,
                        fenced_transition_voter_set_digest(identity, &storage.business.members),
                    ),
                ))),
            },
        );
        let applied = retention::with_key_capacity_limit_for_test(2, || {
            changes::tests::apply(&mut storage, &[entry])
        });
        if head == COUNTER_MAX {
            assert_eq!(
                applied.responses[0].result,
                Err(StoreError::FencedTransitionStorageExhausted)
            );
            assert!(applied.notifications.is_empty());
            assert_eq!(storage.business.frontiers.watch_sequence, head);
            assert_eq!(storage.business.frontiers.retention.keys, before);
            assert_eq!(storage.business.frontiers.next_fence, next_fence);
            assert_eq!(storage.business.frontiers.next_credential, next_credential);
            assert_eq!(storage.business.keys.len(), rows.len());
            for (key, bytes) in rows {
                assert_eq!(
                    postcard::to_allocvec(&**storage.business.keys.get(&key).unwrap()).unwrap(),
                    bytes
                );
            }
        } else {
            assert!(applied.responses[0].result.is_ok());
            assert_eq!(applied.notifications.len(), 1);
            assert_eq!(applied.notifications[0].sequence, COUNTER_MAX);
            assert_eq!(storage.business.frontiers.retention.keys.epoch, 2);
            assert!(!storage.business.keys.contains_key(old.key()));
        }
        storage.validate_image().unwrap();
    }
}

#[test]
fn native_new_internal_capacity_requires_a_journal_position_even_without_key_pressure() {
    let (mut storage, _) = retired_key_fixture();
    let original =
        journal_page_for_test_sync(|| storage.business.replication_log(1, 16, &|| Ok(())))
            .pop()
            .unwrap();
    storage.business.notifications.clear();
    let window = retention::NOTIFICATION_WINDOW as u64;
    for sequence in COUNTER_MAX - window + 1..=COUNTER_MAX {
        storage.business.notifications.push_back(
            NotificationRow::new(NativeNotification::new(ReplicationEntry {
                sequence,
                ..original.clone()
            }))
            .unwrap(),
        );
    }
    storage.business.frontiers.watch_sequence = COUNTER_MAX;
    storage.business.frontiers.retention.watch_retired_through = COUNTER_MAX - window;
    storage.business.admit_business().unwrap();
    storage.log.admit(&storage.business).unwrap();
    storage.validate_image().unwrap();
    let before = storage.business.frontiers.retention;
    let identity = storage.business.identity;
    let entry = command(
        5,
        SessionMutationIntent::Authorized {
            origin: *storage.business.members.first().unwrap(),
            authority_identity: identity,
            mutation: Box::new(SessionMutationIntent::ActivateScopeProfile(Box::new(
                crate::scope_authority::ScopeProfileActivation::new(
                    identity,
                    fenced_transition_voter_set_digest(identity, &storage.business.members),
                ),
            ))),
        },
    );
    let applied = retention::with_key_capacity_limit_for_test(3, || {
        changes::tests::apply(&mut storage, &[entry])
    });
    assert_eq!(
        applied.responses[0].result,
        Err(StoreError::FencedTransitionStorageExhausted),
        "new internal resident capacity must be journaled before publication"
    );
    assert!(applied.notifications.is_empty());
    assert!(storage.business.frontiers.retention == before);
    assert_eq!(storage.business.keys.len(), 2);
    storage.validate_image().unwrap();
}

/// Real command fixture covering every replay-policy dimension in portable images.
pub(crate) fn explicit_replay_policy_fixture() -> NativeStorage {
    let (mut storage, old) = retired_key_fixture();
    let new_key = |suffix: &'static [u8]| {
        let mut key = old.key().clone();
        key.stable_id = bytes::Bytes::from_static(suffix).try_into().unwrap();
        key
    };
    let history = storage
        .business
        .history_state()
        .unwrap()
        .active_epoch()
        .unwrap();
    let first = ephemeral_request(
        new_key(b"policy-expired-before-control"),
        50_001,
        0,
        history,
        time(2),
    );
    let entry = changes::tests::command(5, &first, time(2), false);
    assert!(changes::tests::apply(&mut storage, &[entry]).responses[0]
        .result
        .is_ok());
    let identity = storage.business.identity;
    let control = command_at(
        6,
        SessionMutationIntent::Authorized {
            origin: *storage.business.members.first().unwrap(),
            authority_identity: identity,
            mutation: Box::new(SessionMutationIntent::ActivateScopeProfile(Box::new(
                crate::scope_authority::ScopeProfileActivation::new(
                    identity,
                    fenced_transition_voter_set_digest(identity, &storage.business.members),
                ),
            ))),
        },
        time(4),
    );
    let maximum = storage.business.keys.len();
    let controlled = retention::with_key_capacity_limit_for_test(maximum, || {
        changes::tests::apply(&mut storage, &[control])
    });
    assert_eq!(controlled.notifications.len(), 1);
    assert_eq!(
        controlled.notifications[0].replay_policy.capacity_rotations,
        2
    );
    assert!(!controlled.notifications[0].replay_policy.prune_expired);
    let floor = crate::sqlite::consensus::wal::async_authority::Reservation::from_era(2)
        .unwrap()
        .retired_through();
    let mut boundary = command_at(
        7,
        SessionMutationIntent::AsyncRecoveryBoundary {
            era: 2,
            plan: [0x95; 32],
            protected: None,
        },
        time(4),
    );
    boundary.log_id.leader_id = opc_consensus::engine::CommittedLeaderId::new(
        floor + 2,
        *storage.business.members.first().unwrap(),
    );
    let recovered = changes::tests::apply(&mut storage, &[boundary]);
    assert!(recovered.responses[0].result.is_ok());
    assert_eq!(recovered.notifications[0].sequence, floor + 1);
    let history = storage
        .business
        .history_state()
        .unwrap()
        .active_epoch()
        .unwrap();
    let request = ephemeral_request(
        new_key(b"policy-plain-after-recovery"),
        50_002,
        floor,
        history,
        time(4),
    );
    let mut entry = changes::tests::command(8, &request, time(4), false);
    entry.log_id.leader_id = storage.business.applied().unwrap().leader_id;
    let plain = changes::tests::apply(&mut storage, &[entry]);
    assert_eq!(plain.notifications.len(), 1);
    assert_eq!(
        plain.notifications[0].replay_policy.async_fence_floor,
        floor
    );
    assert_eq!(plain.notifications[0].replay_policy.capacity_rotations, 0);
    assert!(!plain.notifications[0].replay_policy.prune_expired);
    let requests = [
        b"policy-batch-first".as_slice(),
        b"policy-batch-second".as_slice(),
    ]
    .into_iter()
    .enumerate()
    .map(|(index, suffix)| {
        ephemeral_request(
            new_key(suffix),
            50_003 + index as u64,
            floor,
            history,
            time(6),
        )
    })
    .collect::<Vec<_>>();
    let id =
        crate::consensus::types::fenced_transition_v2_batch_outer_request_id(&requests).unwrap();
    let mut batch = command_at(
        9,
        SessionMutationIntent::FencedTransitionV2Batch(requests),
        time(6),
    );
    batch.log_id.leader_id = storage.business.applied().unwrap().leader_id;
    let EntryPayload::Normal(command) = &mut batch.payload else {
        unreachable!()
    };
    command.request_id = SessionConsensusRequestId::from_bytes(id);
    let effects = changes::tests::apply(&mut storage, &[batch]);
    assert_eq!(effects.notifications.len(), 2);
    assert!(matches!(
        effects.notifications[0].replay_policy.command,
        crate::ReplicationCommandBoundary::Start {
            following_entries: 1,
            ..
        }
    ));
    assert!(matches!(
        effects.notifications[1].replay_policy.command,
        crate::ReplicationCommandBoundary::Continue {
            remaining_entries: 0,
            ..
        }
    ));
    let mut ordinary = command_at(
        10,
        SessionMutationIntent::AcquireLease {
            key: new_key(b"policy-ordinary-after-recovery"),
            owner: crate::OwnerId::new("policy-owner").unwrap(),
            ttl: Duration::from_secs(60),
        },
        time(7),
    );
    ordinary.log_id.leader_id = storage.business.applied().unwrap().leader_id;
    let maximum = storage.business.keys.len();
    let final_cut = retention::with_key_capacity_limit_for_test(maximum, || {
        changes::tests::apply(&mut storage, &[ordinary])
    });
    assert!(final_cut.responses[0].result.is_ok());
    assert_eq!(final_cut.notifications.len(), 1);
    assert_eq!(
        final_cut.notifications[0].replay_policy.capacity_rotations,
        2
    );
    assert_eq!(
        final_cut.notifications[0].replay_policy.async_fence_floor,
        floor
    );
    assert!(final_cut.notifications[0].replay_policy.prune_expired);
    assert!(final_cut.notifications[0].replay_policy.retire_dead_keys);
    storage.validate_image().unwrap();
    storage
}

#[test]
fn round6_internal_count_includes_reserved_rows_with_nonzero_fences() {
    let (_, _, live) = fixture();
    let key = live.lease().key().clone();
    let mut index = expiry::ExpiryIndex::default();
    let reserved = NativeKeyState {
        fence: 100,
        reserved: true,
        ..NativeKeyState::default()
    };
    index.replace(&key, None, Some(&reserved));
    assert_eq!(
        index.internal_key_count().unwrap(),
        1,
        "a reserved carrier retains the current nonzero floor"
    );
    let mut occupied = reserved.clone();
    occupied.lease = Some(NativeLease::from_guard(live.lease()).unwrap());
    index.replace(&key, Some(&reserved), Some(&occupied));
    assert_eq!(
        index.internal_key_count().unwrap(),
        0,
        "a key already represented by its lease must not be counted twice"
    );
    index.replace(&key, Some(&occupied), None);
    assert_eq!(index.internal_key_count().unwrap(), 0);
}
