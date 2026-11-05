use crate::test_process::witness::{JoinExt, ReceiverExt};

use super::*;
use crate::fake::tests::{
    replay_key_id_for_test, replay_state_for_test, ReplayRowForTest, ReplayStateForTest,
};
use crate::{Clock, FakeSessionBackend, SessionBackend};
use changes::tests::{apply, time};
use std::time::Duration;

#[derive(Debug)]
struct ReplayClock(std::sync::Mutex<Timestamp>);
impl Clock for ReplayClock {
    fn now_utc(&self) -> Timestamp {
        *self.0.lock().unwrap()
    }
}

fn key(template: &SessionKey, id: u64) -> SessionKey {
    let mut result = template.clone();
    result.stable_id = bytes::Bytes::from(format!("replay-policy-{id}"))
        .try_into()
        .unwrap();
    result
}

fn opaque_source_row(key: &SessionKey, row: &NativeKeyState) -> bool {
    // Independent raw-state oracle, not the producer's derived expiry index.
    crate::scope_storage::is_scope_record_key(key)
        || (row.record.is_none() && row.lease.is_none() && row.retired_epoch.is_none())
}

fn native_state(native: &NativeStorage) -> ReplayStateForTest {
    ReplayStateForTest {
        async_fence_floor: native.business.frontiers.async_fence_floor(),
        internal_key_count: native
            .business
            .keys
            .iter()
            .filter(|(key, row)| opaque_source_row(key, row))
            .count()
            .try_into()
            .unwrap(),
        retention: native.business.frontiers.retention.keys,
        retired_index: native
            .business
            .keys
            .iter()
            .filter_map(|(key, row)| {
                row.retired_epoch
                    .map(|epoch| (epoch, replay_key_id_for_test(key)))
            })
            .collect(),
        keys: native
            .business
            .keys
            .iter()
            .filter(|(key, row)| !opaque_source_row(key, row))
            .map(|(key, row)| {
                let lease = row.lease.as_ref().map(|lease| {
                    (
                        lease.active,
                        lease.owner.clone(),
                        lease.fence,
                        lease.credential_id,
                        lease.acquired_at,
                        lease.expires_at_unix_ms,
                        lease.guard_expires_at,
                    )
                });
                (
                    replay_key_id_for_test(key),
                    ReplayRowForTest {
                        fence: row.fence,
                        record: row.record.clone(),
                        lease,
                        retired_epoch: row.retired_epoch,
                    },
                )
            })
            .collect(),
        next_fence: native.business.frontiers.next_fence,
        next_credential: native.business.frontiers.next_credential,
    }
}

use super::test_journal::{journal_page_for_test, journal_page_for_test_sync};

async fn replay_prefix(native: &NativeStorage, clock: Arc<ReplayClock>) -> FakeSessionBackend {
    let fake = FakeSessionBackend::new().with_clock(clock);
    for row in journal_page_for_test(native, 1, 1024).await {
        fake.replicate_entry(row).await.unwrap();
    }
    assert_eq!(native_state(native), replay_state_for_test(&fake).await);
    fake
}

fn batch_entry(
    native: &NativeStorage,
    requests: Vec<FencedTransitionV2Request>,
    now: Timestamp,
) -> Entry<SessionRaftTypeConfig> {
    let request_id =
        crate::consensus::types::fenced_transition_v2_batch_outer_request_id(&requests).unwrap();
    let mut entry = key_retention_tests::command_at(
        native.business.frontiers.applied.unwrap().index + 1,
        SessionMutationIntent::FencedTransitionV2Batch(requests),
        now,
    );
    let EntryPayload::Normal(command) = &mut entry.payload else {
        unreachable!()
    };
    command.request_id = SessionConsensusRequestId::from_bytes(request_id);
    entry
}

async fn single_effect_expiry_case(rotating: bool, batch: bool, cached_and_failed: bool) {
    let (mut native, old) = key_retention_tests::retired_key_fixture();
    let expired = key(old.key(), 900);
    let history = native.business.history().unwrap().active_epoch().unwrap();
    let cached = key_retention_tests::ephemeral_request(expired, 900, 0, history, time(2));
    let first = changes::tests::command(5, &cached, time(2), false);
    assert!(apply(&mut native, &[first]).responses[0].result.is_ok());
    let clock = Arc::new(ReplayClock(std::sync::Mutex::new(time(4))));
    let fake = replay_prefix(&native, clock.clone()).await;
    let fresh =
        key_retention_tests::ephemeral_request(key(old.key(), 901), 901, 0, history, time(4));
    let entry = if batch {
        let mut requests = Vec::new();
        if cached_and_failed {
            requests.push(cached);
            requests.push(key_retention_tests::ephemeral_request(
                key(old.key(), 902),
                902,
                1,
                history,
                time(4),
            ));
        }
        requests.push(fresh);
        batch_entry(&native, requests, time(4))
    } else {
        changes::tests::command(6, &fresh, time(4), false)
    };
    let maximum = if rotating {
        native.business.keys.len()
    } else {
        64
    };
    let result =
        retention::with_key_capacity_limit_for_test(maximum, || apply(&mut native, &[entry]));
    assert!(result.responses[0].result.is_ok());
    assert_eq!(result.notifications.len(), 1);
    assert_eq!(
        native.business.frontiers.retention.keys.epoch,
        if rotating { 2 } else { 0 }
    );
    for row in result.notifications {
        fake.replicate_entry(row).await.unwrap();
    }
    let expected = native_state(&native);
    assert_eq!(
        expected,
        replay_state_for_test(&fake).await,
        "a V2 effect must retain unrelated expired rows and exact fences"
    );
    let rebuilt = FakeSessionBackend::new().with_clock(clock);
    rebuilt
        .rebuild_replication_state(fake.get_replication_log(1, 1024).await.unwrap())
        .await
        .unwrap();
    assert_eq!(expected, replay_state_for_test(&rebuilt).await);
}

#[tokio::test]
async fn single_v2_rotation_preserves_unpruned_expired_state() {
    single_effect_expiry_case(true, false, false).await;
}
#[tokio::test]
async fn one_effect_v2_batch_rotation_preserves_unpruned_expired_state() {
    single_effect_expiry_case(true, true, false).await;
}
#[tokio::test]
async fn cached_and_failed_v2_batch_children_preserve_single_effect_policy() {
    single_effect_expiry_case(true, true, true).await;
}
#[tokio::test]
async fn nonrotating_v2_preserves_unpruned_expired_state() {
    single_effect_expiry_case(false, false, false).await;
}

#[tokio::test]
async fn async_recovery_floor_and_following_capacity_replay_match_native() {
    use crate::sqlite::consensus::wal::async_authority::Reservation;
    let (mut native, old) = key_retention_tests::retired_key_fixture();
    let clock = Arc::new(ReplayClock(std::sync::Mutex::new(time(3))));
    let fake = replay_prefix(&native, clock).await;
    let floor = Reservation::from_era(2).unwrap().retired_through();
    let mut boundary = key_retention_tests::command_at(
        5,
        SessionMutationIntent::AsyncRecoveryBoundary {
            era: 2,
            plan: [0xD5; 32],
            protected: None,
        },
        time(3),
    );
    boundary.log_id.leader_id = opc_consensus::engine::CommittedLeaderId::new(
        floor + 2,
        *native.business.members.first().unwrap(),
    );
    let result = apply(&mut native, &[boundary]);
    assert!(result.responses[0].result.is_ok());
    for row in result.notifications {
        fake.replicate_entry(row).await.unwrap();
    }
    assert_eq!(
        native_state(&native),
        replay_state_for_test(&fake).await,
        "the committed recovery floor must travel to the application replica"
    );
    let mut create = key_retention_tests::command_at(
        6,
        SessionMutationIntent::AcquireLease {
            key: key(old.key(), 903),
            owner: crate::OwnerId::new("recovery-owner").unwrap(),
            ttl: Duration::from_secs(60),
        },
        time(3),
    );
    create.log_id.leader_id = native.business.frontiers.applied.unwrap().leader_id;
    let result = retention::with_key_capacity_limit_for_test(2, || apply(&mut native, &[create]));
    assert!(result.responses[0].result.is_ok());
    for row in result.notifications {
        fake.replicate_entry(row).await.unwrap();
    }
    assert_eq!(native_state(&native), replay_state_for_test(&fake).await);
    assert_eq!(
        native.business.frontiers.retention.keys.floor_prev,
        floor + 1
    );
    assert_eq!(
        native.business.frontiers.retention.keys.floor_cur,
        floor + 2
    );
}

async fn incomplete_batch_case(conflict: bool) {
    let (mut native, old) = key_retention_tests::retired_key_fixture();
    let extra = key(old.key(), 910);
    let result = apply(
        &mut native,
        &[key_retention_tests::command(
            5,
            SessionMutationIntent::AcquireLease {
                key: extra,
                owner: crate::OwnerId::new("prefix-owner").unwrap(),
                ttl: Duration::from_secs(60),
            },
        )],
    );
    let Ok(SessionMutationOutcome::Lease(extra)) = &result.responses[0].result else {
        panic!("acquire")
    };
    let prune = key_retention_tests::prune_intent(&native);
    apply(
        &mut native,
        &[
            key_retention_tests::command(6, SessionMutationIntent::ReleaseLease(extra.clone())),
            key_retention_tests::command(7, prune),
        ],
    );
    let fake = replay_prefix(
        &native,
        Arc::new(ReplayClock(std::sync::Mutex::new(time(2)))),
    )
    .await;
    let history = native.business.history().unwrap().active_epoch().unwrap();
    let first_key = key(old.key(), 911);
    let requests = [first_key.clone(), key(old.key(), 912)]
        .into_iter()
        .enumerate()
        .map(|(i, key)| {
            key_retention_tests::ephemeral_request(key, 911 + i as u64, 0, history, time(2))
        })
        .collect();
    let entry = batch_entry(&native, requests, time(2));
    let result = retention::with_key_capacity_limit_for_test(3, || apply(&mut native, &[entry]));
    assert!(result.responses[0].result.is_ok());
    assert_eq!(result.notifications.len(), 2);
    fake.replicate_entry(result.notifications[0].clone())
        .await
        .unwrap();
    let before = crate::fake::tests::backend_data_snapshot(&fake).await;
    let operation = if conflict {
        let mut record = native.business.keys[&first_key].record.clone().unwrap();
        record.generation = crate::Generation::new(778);
        crate::SessionOp::CompareAndSet(crate::CompareAndSet {
            key: first_key.clone(),
            expected_generation: Some(crate::Generation::new(777)),
            new_record: record,
            lease: native.business.retained_lease_for_test(&first_key).unwrap(),
        })
    } else {
        crate::SessionOp::RefreshTtl {
            lease: old,
            ttl: Duration::from_secs(60),
        }
    };
    let result = fake.batch(vec![operation]).await;
    assert!(
        matches!(result, Err(StoreError::BackendUnavailable(_))),
        "an incomplete replay command must refuse every local write batch: {result:?}"
    );
    assert_eq!(
        before,
        crate::fake::tests::backend_data_snapshot(&fake).await
    );
}

#[tokio::test]
async fn incomplete_replay_refuses_all_conflict_write_batches() {
    incomplete_batch_case(true).await;
}
#[tokio::test]
async fn incomplete_replay_refuses_all_failing_write_batches() {
    incomplete_batch_case(false).await;
}

// Fixed-seed command selection is intentionally independent of entry encoding.
// Assertions compare canonical rows, leases, exact fences, epoch tags and both
// allocators after every committed native command and complete replay group.
async fn randomized_policy_parity(seed: u64, capacity_pressure: bool) {
    let (mut native, old) = key_retention_tests::retired_key_fixture();
    let clock = Arc::new(ReplayClock(std::sync::Mutex::new(time(2))));
    let fake = replay_prefix(&native, clock.clone()).await;
    let mut random = seed;
    let mut trace = Vec::new();
    let mut cached = Vec::new();
    let mut seconds = 2_u64;
    for step in 0..64_u64 {
        random ^= random << 13;
        random ^= random >> 7;
        random ^= random << 17;
        seconds += 1 + random % 3;
        let now = time(0).add_seconds(seconds as i64).unwrap();
        *clock.0.lock().unwrap() = now;
        let slot = (random >> 8) % 12;
        let target = key(old.key(), slot);
        let index = native.business.frontiers.applied.unwrap().index + 1;
        let kind = (random >> 24) % 6;
        let mut entry = match kind {
            0 => key_retention_tests::command_at(
                index,
                SessionMutationIntent::AcquireLease {
                    key: target,
                    owner: crate::OwnerId::new("random-owner").unwrap(),
                    ttl: Duration::from_secs(2 + (random >> 32) % 5),
                },
                now,
            ),
            1..=3 => {
                let floor = native
                    .business
                    .observe_at(&target, now)
                    .unwrap()
                    .current_fence()
                    .get();
                let history = native
                    .business
                    .history_state()
                    .unwrap()
                    .active_epoch()
                    .unwrap();
                let request = key_retention_tests::ephemeral_request(
                    target,
                    10000 + step,
                    floor,
                    history,
                    now,
                );
                cached.push(request.clone());
                if kind == 2 {
                    batch_entry(&native, vec![request], now)
                } else if kind == 3 {
                    let mut children = cached.last().cloned().into_iter().collect::<Vec<_>>();
                    children.push(key_retention_tests::ephemeral_request(
                        key(old.key(), 1000 + step),
                        20000 + step,
                        1,
                        history,
                        now,
                    ));
                    batch_entry(&native, children, now)
                } else {
                    changes::tests::command(index, &request, now, false)
                }
            }
            4 => key_retention_tests::command_at(
                index,
                SessionMutationIntent::ReleaseLease(old.clone()),
                now,
            ),
            _ => key_retention_tests::command_at(
                index,
                SessionMutationIntent::AdvanceLogicalTime,
                now,
            ),
        };
        entry.log_id.leader_id = native.business.frontiers.applied.unwrap().leader_id;
        let inserts =
            (1..=3).contains(&kind) && !native.business.keys.contains_key(&key(old.key(), slot));
        let maximum = if capacity_pressure
            && step != 0
            && inserts
            && native
                .business
                .keys
                .values()
                .any(|row| row.retired_epoch.is_some())
        {
            native.business.keys.len()
        } else {
            validation::MAX_ITEMS
        };
        trace.push((step, seconds, kind, slot, maximum));
        let epoch = native.business.frontiers.retention.keys.epoch;
        let result =
            retention::with_key_capacity_limit_for_test(maximum, || apply(&mut native, &[entry]));
        eprintln!("replay_seed={seed:#x} pressure={capacity_pressure} step={step} kind={kind} rotations={} entries={}",
            native.business.frontiers.retention.keys.epoch - epoch, result.notifications.len());
        for row in result.notifications {
            fake.replicate_entry(row).await.unwrap();
        }
        assert_eq!(
            native_state(&native),
            replay_state_for_test(&fake).await,
            "seed={seed:#x}, pressure={capacity_pressure}, trace={trace:?}"
        );
    }
}

macro_rules! parity_seed {
    ($name:ident, $seed:expr, $pressure:expr) => {
        #[tokio::test]
        async fn $name() {
            randomized_policy_parity($seed, $pressure).await;
        }
    };
}
parity_seed!(
    randomized_replay_policy_seed_01,
    0x9E37_79B9_7F4A_7C15,
    false
);
parity_seed!(
    randomized_replay_policy_seed_02,
    0xD1B5_4A32_D192_ED03,
    false
);
parity_seed!(
    randomized_replay_policy_seed_03,
    0x94D0_49BB_1331_11EB,
    false
);
parity_seed!(
    randomized_replay_policy_seed_04,
    0x8538_EA91_9F4A_7C15,
    false
);
parity_seed!(
    randomized_capacity_policy_seed_01,
    0x9E37_79B9_7F4A_7C15,
    true
);
parity_seed!(
    randomized_capacity_policy_seed_02,
    0xD1B5_4A32_D192_ED03,
    true
);
parity_seed!(
    randomized_capacity_policy_seed_03,
    0x94D0_49BB_1331_11EB,
    true
);
parity_seed!(
    randomized_capacity_policy_seed_04,
    0x8538_EA91_9F4A_7C15,
    true
);

fn mixed_time(seconds: u64) -> Timestamp {
    time(0).add_seconds(seconds.try_into().unwrap()).unwrap()
}

fn mixed_guard(native: &NativeStorage, random: u64, now: Timestamp) -> LeaseGuard {
    let mut guards = native
        .business
        .keys
        .iter()
        .filter_map(|(key, row)| {
            let lease = row.lease.as_ref()?;
            (lease.active
                && lease.guard_expires_at > now
                && lease.fence.get() > native.business.frontiers.async_fence_floor()
                && !crate::scope_storage::is_scope_record_key(key))
            .then(|| {
                LeaseGuard::new(
                    key.clone(),
                    lease.owner.clone(),
                    lease.fence,
                    lease.acquired_at.unwrap(),
                    lease.guard_expires_at,
                    lease.credential_id,
                )
            })
        })
        .collect::<Vec<_>>();
    guards.sort_by_key(|guard| replay_key_id_for_test(guard.key()));
    if guards.is_empty() {
        let template = native
            .business
            .keys
            .keys()
            .filter(|key| !crate::scope_storage::is_scope_record_key(key))
            .min_by_key(|key| replay_key_id_for_test(key))
            .cloned()
            .unwrap_or_else(|| SessionKey {
                tenant: opc_types::TenantId::from_static("mixed-replay"),
                nf_kind: opc_types::NetworkFunctionKind::smf(),
                key_type: crate::SessionKeyType::PduSession,
                stable_id: bytes::Bytes::from_static(b"expired-mixed")
                    .try_into()
                    .unwrap(),
            });
        LeaseGuard::new(
            template,
            crate::OwnerId::new("expired-mixed-owner").unwrap(),
            crate::FenceToken::new(1),
            time(0),
            time(1),
            1,
        )
    } else {
        guards[random as usize % guards.len()].clone()
    }
}

fn mixed_record(
    guard: &LeaseGuard,
    generation: crate::Generation,
    nonce: u64,
    now: Timestamp,
) -> StoredSessionRecord {
    let mut record = StoredSessionRecord {
        key: guard.key().clone(),
        owner: guard.owner().clone(),
        fence: guard.fence(),
        generation,
        state_class: crate::StateClass::EphemeralProcedure,
        state_type: crate::StateType::from_static("mixed-replay"),
        expires_at: Some(now.add_seconds(2 + (nonce % 5) as i64).unwrap()),
        payload: crate::EncryptedSessionPayload::new([]),
    };
    let handle = opc_key::KeyHandle::new(
        opc_key::KeyId::new("mixed-replay-key").unwrap(),
        opc_key::KeyPurpose::Session,
        record.key.tenant.clone(),
        opc_key::Zeroizing::new([0xDA; opc_key::AES_256_GCM_SIV_KEY_LEN]),
    );
    let aad = crate::record::build_session_envelope_aad(&record, "mixed-replay", &handle).unwrap();
    let mut iv = [0; opc_key::AES_256_GCM_SIV_NONCE_LEN];
    iv[4..].copy_from_slice(&nonce.to_be_bytes());
    let encoded =
        opc_crypto::encrypt_envelope_with_handle_and_nonce(&handle, &aad, b"mixed replay", iv)
            .unwrap();
    assert_eq!(
        opc_crypto::decrypt_envelope_with_handle(&handle, &aad, &encoded)
            .unwrap()
            .as_slice(),
        b"mixed replay"
    );
    record.payload = crate::EncryptedSessionPayload::try_envelope(encoded).unwrap();
    record
}

fn mixed_scope_entry(
    native: &NativeStorage,
    intent: SessionMutationIntent,
    now: Timestamp,
) -> Entry<SessionRaftTypeConfig> {
    let request_id = match &intent {
        SessionMutationIntent::ScopeAuthority(command) => Some(*command.request.request_id()),
        SessionMutationIntent::ScopeBatch(command) => Some(*command.request.request_id()),
        SessionMutationIntent::ScopeBatchCancel(command) => Some(command.proposal_id().unwrap()),
        _ => None,
    };
    let mut entry = key_retention_tests::command_at(
        native.business.applied().unwrap().index + 1,
        SessionMutationIntent::Authorized {
            origin: *native.business.members.first().unwrap(),
            authority_identity: native.business.identity,
            mutation: Box::new(intent),
        },
        now,
    );
    if let Some(id) = request_id {
        let EntryPayload::Normal(command) = &mut entry.payload else {
            unreachable!()
        };
        command.request_id = SessionConsensusRequestId::from_bytes(id);
    }
    entry
}

fn mixed_v2_request(
    native: &NativeStorage,
    template: &SessionKey,
    nonce: u64,
    random: u64,
    now: Timestamp,
) -> FencedTransitionV2Request {
    let history = native
        .business
        .history_state()
        .unwrap()
        .active_epoch()
        .unwrap();
    if random & 3 == 0 {
        let guard = mixed_guard(native, random, now);
        if let Some(record) = native
            .business
            .keys
            .get(guard.key())
            .and_then(|row| row.record.as_ref())
        {
            let mutation = match (random >> 8) % 3 {
                0 => crate::FencedTransitionMutation::delete(record.generation),
                1 => crate::FencedTransitionMutation::refresh_ttl(
                    record.generation,
                    Duration::from_secs(3),
                )
                .unwrap(),
                _ => crate::FencedTransitionMutation::update(
                    record.generation,
                    mixed_record(&guard, record.generation.next().unwrap(), nonce, now),
                ),
            };
            return FencedTransitionV2Request::new(
                history,
                crate::FencedTransitionV2CallerNonce::from_bytes(u128::from(nonce).to_be_bytes()),
                crate::FencedTransitionLease::renew(guard, Duration::from_secs(4)).unwrap(),
                mutation,
            )
            .unwrap();
        }
    }
    let target = key(template, (random >> 8) % 24);
    let floor = native
        .business
        .observe_at(&target, now)
        .unwrap()
        .current_fence()
        .get();
    key_retention_tests::ephemeral_request(target, nonce, floor, history, now)
}

// The selection space covers all native session mutation families, their
// activation variants and the controls which can affect replay. Unsupported
// topology administrative intents are outside this state-machine profile.
async fn mixed_command_profile_parity(
    seed: u64,
    pressure: bool,
    profile: crate::FencedTransitionV2Profile,
) {
    static MIXED_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    let _serial = MIXED_TEST_LOCK.lock().await;
    use crate::fake::tests::{pending_replay_entries_for_test, with_tracked_key_limit_for_test};
    use crate::scope_authority::{
        ScopeAuthorityCommand, ScopeAuthorityOperation, ScopeAuthorityRequest,
    };
    let (mut native, first, _) = changes::tests::fixture_with_profile(profile);
    let template = first.lease().key().clone();
    let clock = Arc::new(ReplayClock(std::sync::Mutex::new(time(2))));
    let fake = replay_prefix(&native, clock.clone()).await;
    let mut journal = journal_page_for_test(&native, 1, 4096).await;
    let scope = crate::scope_authority::ScopeId::new(
        native.business.identity,
        opc_types::TenantId::from_static("mixed-replay"),
        opc_types::NetworkFunctionKind::smf(),
        [0x83; 32],
    )
    .unwrap();
    let mut random = seed;
    let mut schedule = (0..23).collect::<Vec<_>>();
    let mut shuffle = seed;
    for index in (1..schedule.len()).rev() {
        shuffle ^= shuffle << 13;
        shuffle ^= shuffle >> 7;
        shuffle ^= shuffle << 17;
        schedule.swap(index, shuffle as usize % (index + 1));
    }
    let mut seconds = 2;
    let mut cached = vec![first];
    let mut coverage = [0_u64; 23];
    let mut rotating = 0;
    let mut multi_entries = 0;
    let mut metadata_rotating = 0;
    let mut cached_children = 0;
    let mut refused_children = 0;
    let mut cancelled = 0;
    let mut trace = Vec::new();
    for step in 0..256_u64 {
        random ^= random << 13;
        random ^= random >> 7;
        random ^= random << 17;
        seconds += 1 + random % 3;
        let now = mixed_time(seconds);
        *clock.0.lock().unwrap() = now;
        let kind = if step < 23 {
            schedule[step as usize]
        } else {
            (random as usize >> 24) % 23
        };
        coverage[kind] += 1;
        let index = native.business.applied().unwrap().index + 1;
        let nonce = 100_000 + step * 8;
        let guard = mixed_guard(&native, random, now);
        let ttl = Duration::from_secs(3 + (random >> 16) % 7);
        let request = mixed_v2_request(&native, &template, nonce, random, now);
        let history = native
            .business
            .history_state()
            .unwrap()
            .active_epoch()
            .unwrap();
        let mut entry = match kind {
            0 => key_retention_tests::command_at(
                index,
                SessionMutationIntent::AcquireLease {
                    key: key(&template, (random >> 8) % 24),
                    owner: crate::OwnerId::new("mixed-owner").unwrap(),
                    ttl,
                },
                now,
            ),
            1 => key_retention_tests::command_at(
                index,
                SessionMutationIntent::RenewLease {
                    lease: guard.clone(),
                    ttl,
                },
                now,
            ),
            2 => key_retention_tests::command_at(
                index,
                SessionMutationIntent::ReleaseLease(guard.clone()),
                now,
            ),
            3 => {
                let prior = native
                    .business
                    .keys
                    .get(guard.key())
                    .and_then(|row| row.record.as_ref())
                    .map(|row| row.generation);
                let expected = if random & 1 == 0 {
                    prior
                } else {
                    Some(crate::Generation::new(999))
                };
                key_retention_tests::command_at(
                    index,
                    SessionMutationIntent::CompareAndSet(Arc::new(crate::CompareAndSet {
                        key: guard.key().clone(),
                        lease: guard.clone(),
                        expected_generation: expected,
                        new_record: mixed_record(
                            &guard,
                            prior.map_or(crate::Generation::new(1), |generation| {
                                generation.next().unwrap()
                            }),
                            nonce,
                            now,
                        ),
                    })),
                    now,
                )
            }
            4 => key_retention_tests::command_at(
                index,
                SessionMutationIntent::DeleteFenced(guard.clone()),
                now,
            ),
            5 => key_retention_tests::command_at(
                index,
                SessionMutationIntent::RefreshTtl {
                    lease: guard.clone(),
                    ttl,
                },
                now,
            ),
            6 | 7 => {
                let v1_request = v1::tests::request(u128::from(nonce), &request);
                v1::tests::command(
                    index,
                    &v1_request,
                    now,
                    kind == 7 || native.business.frontiers.v1_activation.is_none(),
                )
            }
            8 | 9 => {
                let mut entry = changes::tests::command(index, &request, now, kind == 9);
                if let EntryPayload::Normal(command) = &mut entry.payload {
                    if let SessionMutationIntent::ActivateFencedTransitionV2 {
                        profile_digest,
                        ..
                    } = &mut command.intent
                    {
                        *profile_digest =
                            native.business.frontiers.fenced_transition_profile.digest();
                    }
                }
                entry
            }
            10 | 11 => {
                let wrong_key = key(&template, 10_000 + step);
                let wrong_floor = native
                    .business
                    .observe_at(&wrong_key, now)
                    .unwrap()
                    .current_fence()
                    .get()
                    + 99;
                let failed = key_retention_tests::ephemeral_request(
                    wrong_key,
                    nonce + 1,
                    wrong_floor,
                    history,
                    now,
                );
                refused_children += 1;
                let mut children = vec![failed];
                if kind == 10 {
                    children.push(request.clone());
                    children.push(key_retention_tests::ephemeral_request(
                        key(&template, 20_000 + step),
                        nonce + 2,
                        native
                            .business
                            .frontiers
                            .retention
                            .keys
                            .floor_cur
                            .max(native.business.frontiers.async_fence_floor()),
                        history,
                        now,
                    ));
                    let same_epoch = cached
                        .iter()
                        .filter(|request| request.request_id().epoch() == history)
                        .collect::<Vec<_>>();
                    if !same_epoch.is_empty() {
                        children
                            .push(same_epoch[(random >> 12) as usize % same_epoch.len()].clone());
                        cached_children += 1;
                    }
                }
                batch_entry(&native, children, now)
            }
            12 | 13 => {
                let mut entry = changes::tests::void_command(index, &request, now, kind == 13);
                if let EntryPayload::Normal(command) = &mut entry.payload {
                    if let SessionMutationIntent::ActivateVoidFencedTransitionV2 {
                        profile_digest,
                        ..
                    } = &mut command.intent
                    {
                        *profile_digest =
                            native.business.frontiers.fenced_transition_profile.digest();
                    }
                }
                entry
            }
            14 => key_retention_tests::command_at(
                index,
                SessionMutationIntent::AdvanceLogicalTime,
                now,
            ),
            15 => key_retention_tests::command_at(
                index,
                SessionMutationIntent::BindConsumerRequest {
                    request_commitment: [step as u8; 32],
                },
                now,
            ),
            16 => key_retention_tests::command_at(
                index,
                SessionMutationIntent::ReadConsumerRecord {
                    key: key(&template, random % 24),
                },
                now,
            ),
            17 => lifecycle_tests::maintenance(&native, index, now),
            18 => mixed_scope_entry(
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
                now,
            ),
            19 => mixed_scope_entry(
                &native,
                SessionMutationIntent::ScopeAuthority(Box::new(ScopeAuthorityCommand {
                    request: ScopeAuthorityRequest::new(
                        scope.clone(),
                        u128::from(nonce).to_be_bytes(),
                        0,
                        ScopeAuthorityOperation::AdmitInitial {
                            execution: crate::scope_authority::tests::execution(1),
                        },
                    )
                    .unwrap(),
                })),
                now,
            ),
            20 | 22 => {
                let checkpoint = native
                    .business
                    .keys
                    .get(&scope.key().unwrap())
                    .and_then(|row| row.record.as_ref())
                    .map(crate::scope_authority::ScopeAuthorityCheckpoint::from_record)
                    .transpose()
                    .unwrap();
                let permit = checkpoint
                    .as_ref()
                    .and_then(|checkpoint| checkpoint.state().unwrap().view.stamp().cloned());
                let fallback = crate::scope_authority::ScopeState::empty(scope.clone())
                    .transition(
                        &ScopeAuthorityRequest::new(
                            scope.clone(),
                            [0x92; 16],
                            0,
                            ScopeAuthorityOperation::AdmitInitial {
                                execution: crate::scope_authority::tests::execution(1),
                            },
                        )
                        .unwrap(),
                    )
                    .unwrap();
                let permit = permit
                    .as_ref()
                    .unwrap_or_else(|| fallback.view.stamp().unwrap());
                let revision = native
                    .business
                    .keys
                    .get(&crate::scope_storage::batch_key(&scope).unwrap())
                    .and_then(|row| row.record.as_ref())
                    .map(crate::scope_storage::ScopeRow::from_record)
                    .transpose()
                    .unwrap()
                    .map_or(0, |row| match row {
                        crate::scope_storage::ScopeRow::Batch(row) => row.revision,
                        _ => panic!("batch key contains a batch checkpoint"),
                    });
                let request = crate::scope_batch::ScopeBatchRequest::new(
                    permit,
                    u128::from(nonce).to_be_bytes(),
                    revision,
                    vec![crate::scope_batch::tests::create(
                        (step % 240 + 1) as u8,
                        &[],
                    )],
                    vec![],
                )
                .unwrap();
                let intent = if kind == 22 {
                    SessionMutationIntent::ScopeBatchCancel(Box::new(
                        crate::scope_batch::ScopeBatchCancelCommand {
                            attempt: request.attempt().unwrap(),
                        },
                    ))
                } else {
                    SessionMutationIntent::ScopeBatch(Box::new(
                        crate::scope_batch::ScopeBatchCommand { request },
                    ))
                };
                mixed_scope_entry(&native, intent, now)
            }
            21 => {
                use crate::sqlite::consensus::wal::async_authority::Reservation;
                let era = native
                    .business
                    .frontiers
                    .async_recovery
                    .as_ref()
                    .map_or(2, |boundary| boundary.era + 1);
                let floor = Reservation::from_era(era).unwrap().retired_through();
                let mut entry = key_retention_tests::command_at(
                    index,
                    SessionMutationIntent::AsyncRecoveryBoundary {
                        era,
                        plan: [(step as u8).wrapping_add(1); 32],
                        protected: None,
                    },
                    now,
                );
                entry.log_id.leader_id = opc_consensus::engine::CommittedLeaderId::new(
                    floor + 2,
                    *native.business.members.first().unwrap(),
                );
                entry
            }
            _ => unreachable!(),
        };
        if kind != 21 {
            entry.log_id.leader_id = native.business.applied().unwrap().leader_id;
        }
        if matches!(kind, 12 | 13) && !profile.permits_void() {
            // This profile refuses voids before they can enter the committed
            // log. Exercise that admission boundary without fabricating an
            // already-committed command which the profile cannot produce.
            assert!(log::NativeLog::validate_entry(&entry, &native.business).is_err());
            assert_eq!(native_state(&native), replay_state_for_test(&fake).await);
            continue;
        }
        // Leave room for the maximum effects of this command while forcing a
        // real finalizer decision whenever exact dead history can make room.
        let new_keys = match kind {
            10 => 2,
            1..=5 | 11..=17 | 21 => 0,
            18 => 1,
            19 => 2,
            20 | 22 => 4,
            _ => 1,
        };
        let retired = native
            .business
            .keys
            .values()
            .filter(|row| row.retired_epoch.is_some())
            .count();
        let maximum = if pressure && retired != 0 {
            let reclaim = 1 + (random >> 48) as usize % retired.min(2);
            (native.business.keys.len() + new_keys)
                .saturating_sub(reclaim)
                .max(1)
        } else {
            validation::MAX_ITEMS
        };
        let prior_epoch = native.business.frontiers.retention.keys.epoch;
        trace.push((step, seconds, kind, maximum));
        let result =
            retention::with_key_capacity_limit_for_test(maximum, || apply(&mut native, &[entry]));
        cancelled += u64::from(matches!(
            result.responses[0].result,
            Ok(SessionMutationOutcome::ScopeBatchCancel(Ok(_)))
        ));
        rotating += u64::from(native.business.frontiers.retention.keys.epoch != prior_epoch);
        multi_entries += u64::from(result.notifications.len() > 1);
        if native.business.frontiers.retention.keys.epoch != prior_epoch
            && (11..=21).contains(&kind)
        {
            assert_eq!(
                result.notifications.len(),
                1,
                "control capacity decision has one explicit entry"
            );
            metadata_rotating += 1;
        }
        let replica = with_tracked_key_limit_for_test(&fake, maximum);
        for (position, row) in result.notifications.iter().enumerate() {
            replica.replicate_entry(row.clone()).await.unwrap_or_else(|error|
                panic!("committed replay refused: {error:?}; seed={seed:#x} pressure={pressure} trace={trace:?}"));
            let prefix = replay_state_for_test(&replica).await;
            assert_eq!(
                prefix.retention, native.business.frontiers.retention.keys,
                "seed={seed:#x} trace={trace:?}"
            );
            assert!(prefix.keys.len() + prefix.internal_key_count as usize <= maximum);
            let remaining = result.notifications.len() - position - 1;
            assert_eq!(
                pending_replay_entries_for_test(&replica).await,
                (remaining != 0).then_some(remaining as u16)
            );
            let before_duplicate = crate::fake::tests::backend_data_snapshot(&replica).await;
            replica.replicate_entry(row.clone()).await.unwrap();
            assert_eq!(
                crate::fake::tests::backend_data_snapshot(&replica).await,
                before_duplicate
            );
            journal.push(row.clone());
            if remaining != 0 {
                let rebuilt = FakeSessionBackend::new().with_clock(clock.clone());
                rebuilt
                    .rebuild_replication_state(journal.clone())
                    .await
                    .unwrap();
                assert_eq!(replay_state_for_test(&rebuilt).await, prefix);
                assert_eq!(
                    pending_replay_entries_for_test(&rebuilt).await,
                    Some(remaining as u16)
                );
            }
        }
        assert_eq!(
            native_state(&native),
            replay_state_for_test(&fake).await,
            "seed={seed:#x} pressure={pressure} trace={trace:?}"
        );
        if matches!(
            result.responses[0].result,
            Ok(SessionMutationOutcome::FencedTransition(_))
        ) && matches!(kind, 8 | 9)
        {
            cached.push(request);
        }
        if step % 31 == 0 || step == 255 {
            let rebuilt = FakeSessionBackend::new().with_clock(clock.clone());
            rebuilt
                .rebuild_replication_state(journal.clone())
                .await
                .unwrap();
            assert_eq!(replay_state_for_test(&rebuilt).await, native_state(&native));
            let mut image = Vec::new();
            native.write_image(&mut image, [0x85; 32], 71).unwrap();
            let reopened = NativeStorage::read_image(
                &mut image.as_slice(),
                [0x85; 32],
                71,
                native.business.identity,
            )
            .unwrap();
            assert_eq!(native_state(&reopened), native_state(&native));
        }
    }
    assert!(
        cancelled > 0,
        "seed={seed:#x} profile={profile:?} must exercise successful cancellation"
    );
    assert!(coverage.iter().all(|count| *count != 0));
    assert!(cached_children > 0 && refused_children > 0 && multi_entries > 0);
    if pressure {
        assert!(rotating > 0 && metadata_rotating > 0);
    }
    eprintln!("mixed_seed={seed:#x} profile={profile:?} cancelled={cancelled} pressure={pressure} coverage={coverage:?} rotating={rotating} multi={multi_entries} metadata_rotating={metadata_rotating} cached={cached_children} failed={refused_children}");
}

async fn mixed_command_parity(seed: u64, pressure: bool) {
    for profile in [
        crate::FencedTransitionV2Profile::V2,
        crate::FencedTransitionV2Profile::V2WithLeaseDeferral,
    ] {
        mixed_command_profile_parity(seed, pressure, profile).await;
    }
}

macro_rules! mixed_seed {
    ($name:ident, $pressure:ident, $seed:expr) => {
        #[tokio::test]
        async fn $name() {
            mixed_command_parity($seed, false).await;
        }
        #[tokio::test]
        async fn $pressure() {
            mixed_command_parity($seed, true).await;
        }
    };
}
mixed_seed!(
    mixed_command_parity_seed_01,
    mixed_capacity_parity_seed_01,
    0x9E37_79B9_7F4A_7C15
);
mixed_seed!(
    mixed_command_parity_seed_02,
    mixed_capacity_parity_seed_02,
    0xD1B5_4A32_D192_ED03
);
mixed_seed!(
    mixed_command_parity_seed_03,
    mixed_capacity_parity_seed_03,
    0x94D0_49BB_1331_11EB
);
mixed_seed!(
    mixed_command_parity_seed_04,
    mixed_capacity_parity_seed_04,
    0x8538_EA91_9F4A_7C15
);

#[tokio::test]
async fn released_lease_replay_preserves_physical_expiry_and_guard_deadline() {
    let (mut native, _, live) = changes::tests::fixture();
    let clock = Arc::new(ReplayClock(std::sync::Mutex::new(time(2))));
    let fake = replay_prefix(&native, clock).await;
    let renewed = apply(
        &mut native,
        &[key_retention_tests::command_at(
            2,
            SessionMutationIntent::RenewLease {
                lease: live.lease().clone(),
                ttl: Duration::from_secs(5),
            },
            time(2),
        )],
    );
    let Ok(SessionMutationOutcome::Lease(guard)) = &renewed.responses[0].result else {
        panic!("renew")
    };
    for entry in renewed.notifications {
        fake.replicate_entry(entry).await.unwrap();
    }
    assert_eq!(native_state(&native), replay_state_for_test(&fake).await);
    let released = apply(
        &mut native,
        &[key_retention_tests::command_at(
            3,
            SessionMutationIntent::ReleaseLease(guard.clone()),
            time(3),
        )],
    );
    for entry in released.notifications {
        fake.replicate_entry(entry).await.unwrap();
    }
    assert_eq!(native_state(&native), replay_state_for_test(&fake).await);
}

#[tokio::test]
async fn explicit_policy_watch_rebuild_and_application_restore_round_trip() {
    if crate::test_process::run_completion_parent(std::time::Duration::from_secs(300)) {
        return;
    }
    use crate::test_process::CommandExt as _;
    const CHILD: &str = "OPC_REPLAY_POLICY_ROUND_TRIP_CHILD";
    const TEST: &str = "consensus::native::replay_policy_parity_tests::explicit_policy_watch_rebuild_and_application_restore_round_trip";
    if std::env::var_os(CHILD).is_none() {
        // Restore admission reserves its original fixed verification budget.
        // A checked child keeps unrelated parallel fixtures from consuming it.
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--test-threads=1", "--nocapture"])
            .env(CHILD, "1")
            .test_output_with_deadline(std::time::Duration::from_secs(1800))
            .unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap();
        let stderr = String::from_utf8(output.stderr).unwrap();
        println!(
            "replay_policy_round_trip_child={}",
            serde_json::json!({
                "exit_code": output.status.code(), "stdout": stdout, "stderr": stderr,
            })
        );
        assert!(
            output.status.success(),
            "the complete replay and restore round trip must succeed"
        );
        assert!(
            stdout.contains(&format!("test {TEST} ... ok"))
                && stdout.contains("test result: ok. 1 passed; 0 failed; 0 ignored;"),
            "the exact non-ignored round-trip test must execute"
        );
        return;
    }
    use futures_util::{FutureExt, StreamExt};
    let mut native = key_retention_tests::explicit_replay_policy_fixture();
    let mut journal = Vec::new();
    NativeNotification::visit_export(
        &native.business.notifications,
        &native.business.frontiers,
        &|| Ok(()),
        &mut |entry| {
            journal.push(owned::notification(entry)?);
            Ok(())
        },
    )
    .unwrap();
    let mut offset = 0;
    for entry in &mut journal {
        if matches!(
            entry.replay_policy.recovery,
            crate::ReplicationRecoveryBoundary::Recover { .. }
        ) {
            offset = entry.replay_policy.async_fence_floor + 1 - entry.sequence;
        }
        entry.sequence += offset;
    }
    crate::backend::validate_replication_prefix(&journal).unwrap();
    let clock = Arc::new(ReplayClock(std::sync::Mutex::new(time(7))));
    let replica = FakeSessionBackend::new().with_clock(clock.clone());
    let stream = replica.watch(1).await.unwrap();
    let mut stream = crate::backend::enforce_replication_watch_cursor(stream, 1);
    for entry in &journal {
        replica.replicate_entry(entry.clone()).await.unwrap();
    }
    for entry in &journal {
        assert_eq!(
            stream
                .next()
                .now_or_never()
                .expect("committed watch entry ready")
                .unwrap()
                .unwrap(),
            *entry
        );
    }
    assert_eq!(native_state(&native), replay_state_for_test(&replica).await);
    let rebuilt = FakeSessionBackend::new().with_clock(clock);
    rebuilt.rebuild_replication_state(journal).await.unwrap();
    assert_eq!(native_state(&native), replay_state_for_test(&rebuilt).await);
    native
        .business
        .set_local_restore_incarnation(crate::sqlite::ops::RestoreScanIncarnation::new().unwrap());
    let mut request = crate::RestoreScanRequest::all(64);
    request.scope.tenant = Some(opc_types::TenantId::from_static("native-change-tenant"));
    let source = native
        .business
        .scan_restore_records(request.clone(), time(7), &|| Ok(()))
        .unwrap();
    for backend in [&replica, &rebuilt] {
        let page = backend.scan_restore_records(request.clone()).await.unwrap();
        assert!(page.complete && source.complete);
        assert_eq!(page.records, source.records);
        assert_eq!(page.loaded_count, source.loaded_count);
    }
}

async fn plain_v2_before_capacity_boundary_case(boundary: u8) {
    let (mut native, old) = key_retention_tests::retired_key_fixture();
    for (suffix, release) in [(3100, false), (3101, true)] {
        let index = native.business.applied().unwrap().index + 1;
        let acquired = apply(
            &mut native,
            &[key_retention_tests::command_at(
                index,
                SessionMutationIntent::AcquireLease {
                    key: key(old.key(), suffix),
                    owner: crate::OwnerId::new("plain-policy-owner").unwrap(),
                    ttl: Duration::from_secs(60),
                },
                time(2),
            )],
        );
        let Ok(SessionMutationOutcome::Lease(guard)) = &acquired.responses[0].result else {
            panic!("acquire")
        };
        if release {
            let entry = key_retention_tests::command_at(
                index + 1,
                SessionMutationIntent::ReleaseLease(guard.clone()),
                time(2),
            );
            apply(&mut native, &[entry]);
        }
    }
    let fake =
        FakeSessionBackend::new().with_clock(Arc::new(ReplayClock(std::sync::Mutex::new(time(2)))));
    for entry in journal_page_for_test(&native, 1, 64).await {
        fake.replicate_entry(entry).await.unwrap();
    }
    // Lease storage timestamps have their own regression; start this probe
    // only after proving that both retention views have the same predecessor.
    assert_eq!(
        native_state(&native).retention,
        replay_state_for_test(&fake).await.retention
    );
    let history = native
        .business
        .history_state()
        .unwrap()
        .active_epoch()
        .unwrap();
    let plain =
        key_retention_tests::ephemeral_request(key(old.key(), 3102), 60_001, 0, history, time(2));
    let index = native.business.applied().unwrap().index + 1;
    let result = apply(
        &mut native,
        &[changes::tests::command(index, &plain, time(2), false)],
    );
    assert_eq!(result.notifications.len(), 1);
    for entry in result.notifications {
        fake.replicate_entry(entry).await.unwrap();
    }
    let first_source = native_state(&native);
    let first_replica = replay_state_for_test(&fake).await;
    if boundary != 0 {
        let entry = if boundary == 1 {
            batch_entry(
                &native,
                [3103, 3104]
                    .into_iter()
                    .enumerate()
                    .map(|(offset, id)| {
                        key_retention_tests::ephemeral_request(
                            key(old.key(), id),
                            60_002 + offset as u64,
                            0,
                            history,
                            time(2),
                        )
                    })
                    .collect(),
                time(2),
            )
        } else {
            let identity = native.business.identity;
            key_retention_tests::command_at(
                native.business.applied().unwrap().index + 1,
                SessionMutationIntent::Authorized {
                    origin: *native.business.members.first().unwrap(),
                    authority_identity: identity,
                    mutation: Box::new(SessionMutationIntent::ActivateScopeProfile(Box::new(
                        crate::scope_authority::ScopeProfileActivation::new(
                            identity,
                            fenced_transition_voter_set_digest(identity, &native.business.members),
                        ),
                    ))),
                },
                time(2),
            )
        };
        let maximum = native.business.keys.len() + usize::from(boundary == 1);
        let result =
            retention::with_key_capacity_limit_for_test(maximum, || apply(&mut native, &[entry]));
        assert!(result.responses[0].result.is_ok());
        assert_eq!(native.business.frontiers.retention.keys.epoch, 2);
        for entry in result.notifications {
            fake.replicate_entry(entry).await.unwrap();
        }
    }
    assert_eq!(
        first_source.retention, first_replica.retention,
        "a plain nonrotating V2 entry cannot retire the earlier released key"
    );
    assert_eq!(
        native_state(&native).retention,
        replay_state_for_test(&fake).await.retention
    );
    assert_eq!(first_source, first_replica);
    assert_eq!(native_state(&native), replay_state_for_test(&fake).await);
}

#[tokio::test]
async fn nonrotating_v2_preserves_released_key_before_any_boundary() {
    plain_v2_before_capacity_boundary_case(0).await;
}
#[tokio::test]
async fn nonrotating_v2_before_multi_entry_capacity_preserves_released_key() {
    plain_v2_before_capacity_boundary_case(1).await;
}
#[tokio::test]
async fn nonrotating_v2_before_control_capacity_preserves_released_key() {
    plain_v2_before_capacity_boundary_case(2).await;
}

#[tokio::test]
async fn recovery_boundary_carries_its_own_capacity_decision() {
    let (mut native, _) = key_retention_tests::retired_key_fixture();
    let clock = Arc::new(ReplayClock(std::sync::Mutex::new(time(3))));
    let fake = replay_prefix(&native, clock).await;
    let floor = crate::sqlite::consensus::wal::async_authority::Reservation::from_era(2)
        .unwrap()
        .retired_through();
    let mut entry = key_retention_tests::command_at(
        5,
        SessionMutationIntent::AsyncRecoveryBoundary {
            era: 2,
            plan: [0x96; 32],
            protected: None,
        },
        time(3),
    );
    entry.log_id.leader_id = opc_consensus::engine::CommittedLeaderId::new(
        floor + 2,
        *native.business.members.first().unwrap(),
    );
    let result = retention::with_key_capacity_limit_for_test(1, || apply(&mut native, &[entry]));
    assert!(result.responses[0].result.is_ok());
    assert_eq!(result.notifications.len(), 1);
    assert_eq!(native.business.frontiers.retention.keys.epoch, 2);
    for entry in result.notifications {
        fake.replicate_entry(entry).await.unwrap();
    }
    assert_eq!(native_state(&native), replay_state_for_test(&fake).await);
}

#[path = "round6_replay_tests.rs"]
mod round6_replay_tests;

#[path = "round6_roster_parity.rs"]
mod round6_roster_parity;

#[tokio::test]
async fn parity_fixture_tolerates_transient_journal_page_admission_refusal() {
    if crate::test_process::run_completion_parent(std::time::Duration::from_secs(300)) {
        return;
    }
    const CHILD: &str = "OPC_PARITY_PAGE_REFUSAL_CHILD";
    const TEST: &str = "consensus::native::replay_policy_parity_tests::parity_fixture_tolerates_transient_journal_page_admission_refusal";
    if std::env::var_os(CHILD).is_none() {
        use crate::test_process::CommandExt as _;
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--test-threads=1", "--nocapture"])
            .env(CHILD, "1")
            .test_output_with_deadline(std::time::Duration::from_secs(1800))
            .unwrap();
        assert!(
            output.status.success(),
            "isolated optional-page probe failed: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed; 0 ignored"));
        return;
    }
    use futures_util::FutureExt;
    let (native, _, _) = changes::tests::fixture();
    let occupied =
        crate::consensus::verified_snapshot::JournalPageMemory::reserve(32 * 1024 * 1024).unwrap();
    let release = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(50));
        drop(occupied);
    });
    let result = std::panic::AssertUnwindSafe(replay_prefix(
        &native,
        Arc::new(ReplayClock(std::sync::Mutex::new(time(3)))),
    ))
    .catch_unwind()
    .await;
    release.test_join().unwrap();
    assert!(
        result.is_ok(),
        "an optional page refusal must not fail a valid parity fixture"
    );
    // Unrelated availability reasons and typed errors are never retried.
    for error in [
        StoreError::BackendUnavailable("different refusal".to_owned()),
        StoreError::ReplicationLogCursorCompacted { resume_from: 123 },
    ] {
        let attempts = std::cell::Cell::new(0);
        let error = std::cell::RefCell::new(Some(error));
        let result = super::test_journal::journal_page_result_for_test::<()>(|| {
            attempts.set(attempts.get() + 1);
            Err(error
                .borrow_mut()
                .take()
                .expect("no retry for another error"))
        });
        assert!(result.is_err());
        assert_eq!(attempts.get(), 1);
    }
    // The synchronous fixture must also outlive a page refusal. Release is
    // triggered by the observed refusal, so no schedule chooses the outcome.
    std::thread::scope(|scope| {
        let occupied =
            crate::consensus::verified_snapshot::JournalPageMemory::reserve(32 * 1024 * 1024)
                .unwrap();
        let (released, release) = std::sync::mpsc::sync_channel(1);
        let holder = scope.spawn(move || {
            release.test_recv().unwrap();
            drop(occupied);
        });
        let attempts = std::cell::Cell::new(0);
        let read = || {
            attempts.set(attempts.get() + 1);
            let result = native.business.replication_log(1, 1024, &|| Ok(()));
            if attempts.get() == 1 {
                assert!(
                    matches!(&result, Err(StoreError::BackendUnavailable(reason))
                    if reason == "native committed state unavailable")
                );
                released.send(()).unwrap();
            }
            result
        };
        let rows = journal_page_for_test_sync(read);
        holder.test_join().unwrap();
        assert!(!rows.is_empty());
        assert!(
            attempts.get() >= 2,
            "the fixture must retry after admission is released"
        );
    });
}
