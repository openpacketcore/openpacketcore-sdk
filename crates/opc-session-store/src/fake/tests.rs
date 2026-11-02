use super::*;
use crate::model::{Generation, StateClass};
use bytes::Bytes;
use futures_util::StreamExt;
use opc_types::{NetworkFunctionKind, TenantId};
use std::collections::{BTreeMap, HashMap};

#[path = "replay_time_tests.rs"]
mod replay_time;

#[path = "clock_isolation_tests.rs"]
mod clock_isolation;

#[path = "commit_tests.rs"]
mod commit;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FakeBackendDataSnapshot {
    records: BTreeMap<FakeMapKey, StoredSessionRecord>,
    leases: HashMap<FakeMapKey, LeaseEntry>,
    key_fences: HashMap<FakeMapKey, FenceToken>,
    key_retention: crate::key_retention::KeyRetention,
    async_fence_floor: u64,
    internal_key_count: u32,
    pending_replay_command: Option<PendingReplayCommand>,
    retired_keys: HashMap<FakeMapKey, u64>,
    retired_index: std::collections::BTreeSet<(u64, FakeMapKey)>,
    retirement_candidates: std::collections::BTreeSet<FakeMapKey>,
    committed_time: Option<Timestamp>,
    next_fence: u64,
    next_credential_id: u64,
    compacted_replication_sequence: u64,
    last_replication_sequence: u64,
    replication_log: Vec<ReplicationEntry>,
    watcher_count: usize,
}

fn data_snapshot(state: &FakeBackendState) -> FakeBackendDataSnapshot {
    FakeBackendDataSnapshot {
        records: state
            .records
            .iter()
            .map(|(key, row)| (key.clone(), row.clone()))
            .collect(),
        leases: state
            .leases
            .iter()
            .map(|(key, row)| (key.clone(), row.clone()))
            .collect(),
        key_fences: state
            .key_fences
            .iter()
            .map(|(key, fence)| (key.clone(), *fence))
            .collect(),
        key_retention: state.key_retention,
        async_fence_floor: state.async_fence_floor,
        internal_key_count: state.internal_key_count,
        pending_replay_command: state.pending_replay_command.clone(),
        retired_keys: state
            .retired_keys
            .iter()
            .map(|(key, epoch)| (key.clone(), *epoch))
            .collect(),
        retired_index: state.retired_index.iter().cloned().collect(),
        retirement_candidates: state.retirement_candidates.iter().cloned().collect(),
        committed_time: state.committed_time,
        next_fence: state.next_fence,
        next_credential_id: state.next_credential_id,
        compacted_replication_sequence: state.compacted_replication_sequence,
        last_replication_sequence: state.last_replication_sequence,
        replication_log: state.replication_log.iter().cloned().collect(),
        watcher_count: state.watchers.len(),
    }
}

pub(crate) async fn backend_data_snapshot(backend: &FakeSessionBackend) -> FakeBackendDataSnapshot {
    let state = backend.inner.lock().await;
    data_snapshot(&state)
}

pub(crate) type ReplayKeyIdForTest = (String, String, String, Vec<u8>);
pub(crate) type ReplayLeaseForTest = (
    bool,
    OwnerId,
    FenceToken,
    u64,
    Option<Timestamp>,
    i64,
    Timestamp,
);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReplayRowForTest {
    pub(crate) fence: u64,
    pub(crate) record: Option<StoredSessionRecord>,
    pub(crate) lease: Option<ReplayLeaseForTest>,
    pub(crate) retired_epoch: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReplayStateForTest {
    pub(crate) async_fence_floor: u64,
    pub(crate) internal_key_count: u32,
    pub(crate) retention: crate::key_retention::KeyRetention,
    pub(crate) retired_index: std::collections::BTreeSet<(u64, ReplayKeyIdForTest)>,
    pub(crate) keys: BTreeMap<ReplayKeyIdForTest, ReplayRowForTest>,
    pub(crate) next_fence: u64,
    pub(crate) next_credential: u64,
}

pub(crate) fn replay_key_id_for_test(key: &SessionKey) -> ReplayKeyIdForTest {
    (
        key.tenant.as_str().to_owned(),
        key.nf_kind.as_str().to_owned(),
        key.key_type.as_str().to_owned(),
        key.stable_id.as_bytes().to_vec(),
    )
}

pub(crate) async fn replay_state_for_test(backend: &FakeSessionBackend) -> ReplayStateForTest {
    let state = backend.inner.lock().await;
    ReplayStateForTest {
        async_fence_floor: state.async_fence_floor,
        internal_key_count: state.internal_key_count,
        retention: state.key_retention,
        retired_index: state
            .retired_index
            .iter()
            .map(|(epoch, key)| {
                (
                    *epoch,
                    (
                        key.tenant.clone(),
                        key.nf_kind.clone(),
                        key.key_type.as_str().to_owned(),
                        key.stable_id.as_bytes().to_vec(),
                    ),
                )
            })
            .collect(),
        keys: state
            .key_fences
            .iter()
            .map(|(key, fence)| {
                let id = (
                    key.tenant.clone(),
                    key.nf_kind.clone(),
                    key.key_type.as_str().to_owned(),
                    key.stable_id.as_bytes().to_vec(),
                );
                let lease = state.leases.get(key).map(|lease| {
                    (
                        lease.active,
                        lease.owner.clone(),
                        lease.fence,
                        lease.credential_id,
                        Some(lease.acquired_at),
                        crate::sqlite::ops::timestamp_unix_millis(lease.expires_at).unwrap(),
                        lease.guard_expires_at,
                    )
                });
                (
                    id,
                    ReplayRowForTest {
                        fence: fence.get(),
                        record: state.records.get(key).cloned(),
                        lease,
                        retired_epoch: state.retired_keys.get(key).copied(),
                    },
                )
            })
            .collect(),
        next_fence: state.next_fence,
        next_credential: state.next_credential_id,
    }
}

pub(crate) async fn pending_replay_entries_for_test(backend: &FakeSessionBackend) -> Option<u16> {
    backend
        .inner
        .lock()
        .await
        .pending_replay_command
        .as_ref()
        .map(|pending| pending.remaining)
}

fn replication_entry(
    sequence: u64,
    tx_id: &str,
    timestamp: Timestamp,
    op: ReplicationOp,
) -> ReplicationEntry {
    ReplicationEntry {
        replay_policy: crate::ReplicationReplayPolicy::prune_and_retire(),
        sequence,
        tx_id: tx_id.try_into().expect("valid transaction ID"),
        op,
        timestamp,
    }
}

fn test_key(tenant: &str, stable_id: &[u8]) -> SessionKey {
    SessionKey {
        tenant: TenantId::new(tenant).unwrap(),
        nf_kind: NetworkFunctionKind::from_static("smf"),
        key_type: crate::model::SessionKeyType::PduSession,
        stable_id: Bytes::copy_from_slice(stable_id)
            .try_into()
            .expect("valid stable ID"),
    }
}

fn test_record(key: SessionKey, generation: u64, fence: u64, owner: &str) -> StoredSessionRecord {
    StoredSessionRecord {
        key,
        generation: Generation::new(generation),
        owner: OwnerId::new(owner).unwrap(),
        fence: FenceToken::new(fence),
        state_class: StateClass::AuthoritativeSession,
        state_type: crate::model::StateType::new("test").unwrap(),
        expires_at: None,
        payload: crate::record::EncryptedSessionPayload::new(Bytes::from_static(b"payload")),
    }
}

#[cfg(feature = "lab-memory")]
#[tokio::test]
async fn fake_key_retention_retires_dead_keys_without_reviving_stale_credentials() {
    let backend = FakeSessionBackend::in_memory_lab();
    let live_key = test_key("retention", b"live");
    let key = test_key("retention", b"retired");
    let owner = OwnerId::new("retention-owner").unwrap();
    let live = backend
        .acquire(&live_key, owner.clone(), Duration::from_secs(60))
        .await
        .unwrap();
    let old = backend
        .acquire(&key, owner.clone(), Duration::from_secs(60))
        .await
        .unwrap();
    backend.release(old.clone()).await.unwrap();
    assert_eq!(
        backend.inner.lock().await.key_fences.len(),
        2,
        "live and recently dead keys remain exact"
    );
    let observation = backend.observe_fenced_transition(&key).await.unwrap();
    assert!(observation.record().is_none());
    assert_eq!(observation.current_fence(), old.fence());
    assert_eq!(
        backend
            .renew(&old, Duration::from_secs(60))
            .await
            .unwrap_err(),
        LeaseError::StaleFence
    );
    let new = backend
        .acquire(&key, owner, Duration::from_secs(60))
        .await
        .unwrap();
    assert!(new.fence() > observation.current_fence());
    assert_eq!(
        backend.release(old).await.unwrap_err(),
        LeaseError::StaleFence
    );
    assert!(backend.renew(&live, Duration::from_secs(60)).await.is_ok());
}

#[tokio::test(start_paused = true)]
async fn expired_retired_lease_mutations_preserve_the_expiry_answer() {
    let backend = FakeSessionBackend::new();
    let key = test_key("retention", b"expired-owned-lease");
    let lease = backend
        .acquire(
            &key,
            OwnerId::new("expiry-owner").unwrap(),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
    tokio::time::advance(Duration::from_secs(6)).await;
    // Commit expiry cleanup before testing mutations against a retired key.
    // Reads filter expiry without publishing retirement.
    let maintenance = backend
        .acquire(
            &test_key("retention", b"expiry-maintenance"),
            OwnerId::new("maintenance-owner").unwrap(),
            Duration::from_secs(60),
        )
        .await
        .unwrap();
    backend.release(maintenance).await.unwrap();
    assert!(backend.get(&key).await.unwrap().is_none());
    assert_eq!(
        backend
            .inner
            .lock()
            .await
            .key_fences
            .get(&FakeSessionBackend::map_key(&key)),
        Some(&lease.fence())
    );
    let before = backend_data_snapshot(&backend).await;
    assert_eq!(
        backend
            .compare_and_set(cas_for_lease(key.clone(), &lease, None, 1))
            .await,
        Err(StoreError::LeaseExpired)
    );
    assert_eq!(
        backend.delete_fenced(&lease).await,
        Err(StoreError::LeaseExpired)
    );
    assert_eq!(
        backend.refresh_ttl(&lease, Duration::from_secs(60)).await,
        Err(StoreError::LeaseExpired)
    );
    assert_eq!(backend_data_snapshot(&backend).await, before);
}

#[cfg(feature = "lab-memory")]
#[tokio::test(start_paused = true)]
async fn fake_key_retention_passes_original_distinct_key_limit() {
    let backend = FakeSessionBackend::in_memory_lab();
    let owner = OwnerId::new("retention-owner").unwrap();
    let live_key = test_key("retention", b"live");
    let live = backend
        .acquire(&live_key, owner.clone(), Duration::from_secs(60))
        .await
        .unwrap();
    let mut first = None;
    for number in 0_u64..100_001 {
        let key = test_key("retention", &number.to_be_bytes());
        let lease = backend
            .acquire(&key, owner.clone(), Duration::from_secs(60))
            .await
            .unwrap();
        assert_eq!(
            backend
                .compare_and_set(cas_for_lease(key.clone(), &lease, None, 1))
                .await
                .unwrap(),
            CompareAndSetResult::Success
        );
        assert!(backend.get(&key).await.unwrap().is_some());
        backend.delete_fenced(&lease).await.unwrap();
        backend.release(lease.clone()).await.unwrap();
        if first.is_none() {
            first = Some(lease);
        }
        let state = backend.inner.lock().await;
        // The preceding released key is retired by the next committing
        // acquire; this iteration retains its own inactive lease until then.
        let window = crate::key_retention::RETIRED_KEYS_PER_EPOCH;
        let retained = if number < window {
            number
        } else {
            window + number % window
        };
        assert_eq!(state.key_fences.len(), 2 + retained as usize);
        assert_eq!(state.retired_keys.len(), retained as usize);
        assert!(state.retired_keys.len() <= 2 * window as usize);
        assert_eq!(state.key_retention.epoch, number / window);
        assert_eq!(state.key_retention.retired_count, number % window);
        assert_eq!(state.leases.len(), 2);
        assert!(state.records.is_empty());
        assert!(state.replication_log.len() <= 65_536);
        assert!(state.lab_transitions.is_empty());
    }
    let first = first.unwrap();
    let observation = backend
        .observe_fenced_transition(first.key())
        .await
        .unwrap();
    assert!(observation.current_fence() > first.fence());
    assert!(observation.record().is_none());
    assert_eq!(
        backend
            .renew(&first, Duration::from_secs(60))
            .await
            .unwrap_err(),
        LeaseError::StaleFence
    );
    let recreated = backend
        .acquire(first.key(), owner, Duration::from_secs(60))
        .await
        .unwrap();
    assert!(recreated.fence() > observation.current_fence());
    assert_eq!(
        backend.release(first).await.unwrap_err(),
        LeaseError::StaleFence
    );
    assert_eq!(
        backend
            .renew(&live, Duration::from_secs(60))
            .await
            .unwrap()
            .fence(),
        live.fence()
    );
    assert!(matches!(
        backend.get_replication_log(1, 1).await,
        Err(StoreError::ReplicationLogCursorCompacted { .. })
    ));
}

#[tokio::test(start_paused = true)]
async fn fake_key_retention_replays_and_rebuilds_the_same_absent_floor() {
    let clock: Arc<dyn Clock> = Arc::new(TokioVirtualClock::new());
    let limits = FakeBackendLimits {
        max_tracked_keys: 2,
        max_replication_entries: 64,
    };
    let source = FakeSessionBackend::with_limits(limits).with_clock(Arc::clone(&clock));
    let replica = FakeSessionBackend::with_limits(limits).with_clock(Arc::clone(&clock));
    let rebuilt = FakeSessionBackend::with_limits(limits).with_clock(clock);
    let live_key = test_key("retention", b"live");
    let live = acquire_test_lease(&source, &live_key, "owner").await;
    let mut first = None;
    for number in 0_u64..10 {
        let key = test_key("retention", &number.to_be_bytes());
        let lease = acquire_test_lease(&source, &key, "owner").await;
        source
            .compare_and_set(cas_for_lease(key, &lease, None, 1))
            .await
            .unwrap();
        source.delete_fenced(&lease).await.unwrap();
        source.release(lease.clone()).await.unwrap();
        first.get_or_insert(lease);
    }
    let entries = source.get_replication_log(1, 64).await.unwrap();
    for entry in &entries {
        replica.replicate_entry(entry.clone()).await.unwrap();
    }
    rebuilt.rebuild_replication_state(entries).await.unwrap();
    let source_snapshot = backend_data_snapshot(&source).await;
    assert_eq!(source_snapshot.key_fences.len(), 2);
    assert!(source_snapshot.key_retention.floor_cur > first.as_ref().unwrap().fence().get());
    assert_eq!(backend_data_snapshot(&replica).await, source_snapshot);
    assert_eq!(backend_data_snapshot(&rebuilt).await, source_snapshot);
    for backend in [&replica, &rebuilt] {
        assert_eq!(
            backend
                .renew(first.as_ref().unwrap(), Duration::from_secs(60))
                .await
                .unwrap_err(),
            LeaseError::StaleFence
        );
        assert_eq!(
            backend
                .renew(&live, Duration::from_secs(60))
                .await
                .unwrap()
                .fence(),
            live.fence()
        );
    }
}

#[tokio::test(start_paused = true)]
async fn fake_key_retention_reclaims_imported_delete_floors() {
    let backend = FakeSessionBackend::with_limits(FakeBackendLimits {
        max_tracked_keys: 1,
        max_replication_entries: 8,
    });
    let now = backend.clock.now_utc();
    for sequence in 1_u64..=3 {
        let before = backend_data_snapshot(&backend).await;
        assert_eq!(
            backend
                .replicate_entry(replication_entry(
                    1,
                    &format!("retired-{sequence}"),
                    now,
                    ReplicationOp::DeleteFenced {
                        key: test_key("retention", &sequence.to_be_bytes()),
                        owner: OwnerId::new("owner").unwrap(),
                        fence: FenceToken::new(sequence),
                    },
                ))
                .await,
            Err(StoreError::StaleFence)
        );
        assert_eq!(backend_data_snapshot(&backend).await, before);
        let state = backend.inner.lock().await;
        assert!(state.key_fences.is_empty());
        assert_eq!(state.key_retention.floor_cur, 0);
        assert_eq!(state.next_fence, 1);
    }
}

#[tokio::test(start_paused = true)]
async fn fake_key_retention_keeps_counter_horizon_fences() {
    let backend = FakeSessionBackend::new();
    let key = test_key("retention", b"horizon");
    let mk = FakeSessionBackend::map_key(&key);
    let mut state = backend.inner.lock().await;
    state.next_fence = u64::MAX;
    state
        .key_fences
        .insert(mk.clone(), FenceToken::new(u64::MAX - 1));
    FakeSessionBackend::prune_state(&mut state, backend.clock.now_utc());
    assert_eq!(
        state.key_fences.get(&mk),
        Some(&FenceToken::new(u64::MAX - 1))
    );
    assert_eq!(state.next_fence, u64::MAX);
    assert_eq!(state.key_retention.floor_cur, 0);
}

fn test_record_with_state_class(
    key: SessionKey,
    generation: u64,
    fence: u64,
    owner: &str,
    state_class: StateClass,
) -> StoredSessionRecord {
    StoredSessionRecord {
        state_class,
        ..test_record(key, generation, fence, owner)
    }
}

fn protected_roster_established_create(key: SessionKey, timestamp: Timestamp) -> ReplicationOp {
    let record = test_record(key.clone(), 1, 1, "owner-v2");
    ReplicationOp::ProtectedRosterEstablishedCreate {
        key,
        record,
        owner: OwnerId::new("owner-v2").expect("owner"),
        fence: FenceToken::new(1),
        credential_id: 1,
        guard_acquired_at: timestamp,
        guard_expires_at: timestamp,
    }
}

async fn acquire_test_lease(
    backend: &FakeSessionBackend,
    key: &SessionKey,
    owner: &str,
) -> LeaseGuard {
    backend
        .acquire(key, OwnerId::new(owner).unwrap(), Duration::from_secs(60))
        .await
        .unwrap()
}

fn test_record_for_lease(
    key: SessionKey,
    generation: u64,
    lease: &LeaseGuard,
) -> StoredSessionRecord {
    test_record(key, generation, lease.fence().get(), lease.owner().as_str())
}

fn test_record_for_lease_with_state_class(
    key: SessionKey,
    generation: u64,
    lease: &LeaseGuard,
    state_class: StateClass,
) -> StoredSessionRecord {
    test_record_with_state_class(
        key,
        generation,
        lease.fence().get(),
        lease.owner().as_str(),
        state_class,
    )
}

fn cas_for_lease(
    key: SessionKey,
    lease: &LeaseGuard,
    expected_generation: Option<Generation>,
    generation: u64,
) -> CompareAndSet {
    CompareAndSet {
        key: key.clone(),
        lease: lease.clone(),
        expected_generation,
        new_record: test_record_for_lease(key, generation, lease),
    }
}

fn cas_for_lease_with_state_class(
    key: SessionKey,
    lease: &LeaseGuard,
    expected_generation: Option<Generation>,
    generation: u64,
    state_class: StateClass,
) -> CompareAndSet {
    CompareAndSet {
        key: key.clone(),
        lease: lease.clone(),
        expected_generation,
        new_record: test_record_for_lease_with_state_class(key, generation, lease, state_class),
    }
}

async fn next_replication_entry<S>(stream: &mut S) -> ReplicationEntry
where
    S: futures_util::Stream<Item = Result<ReplicationEntry, StoreError>> + Unpin,
{
    tokio::time::timeout(Duration::from_secs(1), stream.next())
        .await
        .expect("watch should receive replication entry")
        .expect("watch stream should remain open")
        .expect("replication entry should be ok")
}

async fn assert_no_replication_entry<S>(stream: &mut S)
where
    S: futures_util::Stream<Item = Result<ReplicationEntry, StoreError>> + Unpin,
{
    assert!(
        tokio::time::timeout(Duration::from_millis(25), stream.next())
            .await
            .is_err(),
        "watch must remain open without receiving an entry"
    );
}

#[tokio::test]
async fn failed_replication_preserves_expired_internal_state_and_watchers() {
    let backend = FakeSessionBackend::new();
    let key = test_key("t1", b"expired-before-rejection");
    let map_key = FakeSessionBackend::map_key(&key);
    let owner = OwnerId::new("owner-a").expect("owner");
    let fence = FenceToken::new(7);
    let now = backend.clock.now_utc();
    let expired_at =
        Timestamp::from_offset_datetime(*now.as_offset_datetime() - time::Duration::seconds(1));
    let acquired_at =
        Timestamp::from_offset_datetime(*now.as_offset_datetime() - time::Duration::seconds(2));
    let existing_entry =
        replication_entry(1, "existing", now, ReplicationOp::Batch { ops: Vec::new() });

    {
        let mut state = backend.inner.lock().await;
        let mut expired_record = test_record(key.clone(), 1, fence.get(), owner.as_str());
        expired_record.expires_at = Some(expired_at);
        state.records.insert(map_key.clone(), expired_record);
        state.leases.insert(
            map_key.clone(),
            LeaseEntry {
                active: true,
                credential_id: 8,
                owner,
                fence,
                acquired_at,
                expires_at: expired_at,
                guard_expires_at: expired_at,
            },
        );
        state.key_fences.insert(map_key, fence);
        state.next_fence = 8;
        state.next_credential_id = 9;
        state.last_replication_sequence = 1;
        state.replication_log.push_back(existing_entry);
    }
    let mut watch = backend.watch(2).await.expect("watch rejected append");
    let before = backend_data_snapshot(&backend).await;

    let error = backend
        .replicate_entry(replication_entry(
            1,
            "divergent",
            now,
            ReplicationOp::Batch { ops: Vec::new() },
        ))
        .await
        .expect_err("divergent duplicate must reject");
    assert_eq!(
        error,
        StoreError::BackendUnavailable("divergent replication entry sequence".into())
    );

    assert_eq!(backend_data_snapshot(&backend).await, before);
    assert_no_replication_entry(&mut watch).await;
}

#[tokio::test]
async fn protected_roster_v2_create_replication_is_rejected_without_state_change() {
    let backend = FakeSessionBackend::new();
    let now = backend.clock.now_utc();
    let mut watch = backend.watch(1).await.expect("watch create rejection");
    let before = backend_data_snapshot(&backend).await;
    let rejected = replication_entry(
        1,
        "v2-create",
        now,
        protected_roster_established_create(test_key("t1", b"v2-create"), now),
    );

    assert_eq!(
        backend
            .replicate_entry(rejected)
            .await
            .expect_err("fake backend must reject Profile V2 create replay"),
        StoreError::CapabilityNotSupported(
            FakeSessionBackend::PROTECTED_ROSTER_PROFILE_V2_CAPABILITY.into()
        )
    );
    assert_eq!(backend_data_snapshot(&backend).await, before);
    assert_no_replication_entry(&mut watch).await;
}

#[tokio::test]
async fn nested_protected_roster_v2_create_replication_is_rejected_atomically() {
    let backend = FakeSessionBackend::new();
    let now = backend.clock.now_utc();
    let mut watch = backend
        .watch(1)
        .await
        .expect("watch nested create rejection");
    let before = backend_data_snapshot(&backend).await;
    let rejected = replication_entry(
        1,
        "nested-v2-create",
        now,
        ReplicationOp::Batch {
            ops: vec![
                ReplicationOp::DeleteFenced {
                    key: test_key("t1", b"would-mutate-first"),
                    owner: OwnerId::new("owner-a").expect("owner"),
                    fence: FenceToken::new(1),
                },
                ReplicationOp::Batch {
                    ops: vec![protected_roster_established_create(
                        test_key("t1", b"nested-v2-create"),
                        now,
                    )],
                },
            ],
        },
    );

    assert_eq!(
        backend
            .replicate_entry(rejected)
            .await
            .expect_err("fake backend must reject a nested Profile V2 create before replay"),
        StoreError::CapabilityNotSupported(
            FakeSessionBackend::PROTECTED_ROSTER_PROFILE_V2_CAPABILITY.into()
        )
    );
    assert_eq!(backend_data_snapshot(&backend).await, before);
    assert_no_replication_entry(&mut watch).await;
}

#[tokio::test]
async fn protected_roster_v2_create_rebuild_is_rejected_without_state_change() {
    let backend = FakeSessionBackend::new();
    let original_key = test_key("t1", b"rebuild-original");
    let lease = acquire_test_lease(&backend, &original_key, "owner-a").await;
    backend
        .compare_and_set(cas_for_lease(original_key, &lease, None, 1))
        .await
        .expect("seed fake state");
    let watch_start = backend.max_replication_sequence().await.expect("head") + 1;
    let mut watch = backend
        .watch(watch_start)
        .await
        .expect("watch rebuild rejection");
    let before = backend_data_snapshot(&backend).await;
    let now = backend.clock.now_utc();
    let rejected = vec![
        replication_entry(
            1,
            "rebuild-would-mutate-first",
            now,
            ReplicationOp::DeleteFenced {
                key: test_key("t1", b"rebuild-would-mutate-first"),
                owner: OwnerId::new("owner-a").expect("owner"),
                fence: FenceToken::new(1),
            },
        ),
        replication_entry(
            2,
            "rebuild-v2-create",
            now,
            protected_roster_established_create(test_key("t1", b"rebuild-v2-create"), now),
        ),
    ];

    assert_eq!(
        backend
            .rebuild_replication_state(rejected)
            .await
            .expect_err("fake backend must reject a Profile V2 create during rebuild"),
        StoreError::CapabilityNotSupported(
            FakeSessionBackend::PROTECTED_ROSTER_PROFILE_V2_CAPABILITY.into()
        )
    );
    assert_eq!(backend_data_snapshot(&backend).await, before);
    assert_no_replication_entry(&mut watch).await;
}

#[tokio::test]
async fn late_capacity_failure_after_dead_child_rolls_back_batch_and_preserves_watcher() {
    let backend = FakeSessionBackend::with_limits(FakeBackendLimits {
        max_tracked_keys: 1,
        max_replication_entries: 8,
    });
    let key_a = test_key("t1", b"capacity-a");
    let key_b = test_key("t1", b"capacity-b");
    let owner = OwnerId::new("owner-a").expect("owner");
    let now = backend.clock.now_utc();
    let expires_at = checked_session_deadline(now, Duration::from_secs(60)).unwrap();
    let acquire = ReplicationOp::AcquireLease {
        key: key_a.clone(),
        owner: owner.clone(),
        fence: FenceToken::new(1),
        credential_id: 1,
        ttl: Duration::from_secs(60),
        expires_at,
    };
    let release = ReplicationOp::ReleaseLease {
        key: key_a.clone(),
        owner: owner.clone(),
        fence: FenceToken::new(1),
        credential_id: 1,
    };
    let mut watch = backend.watch(1).await.expect("watch rejected batch");
    let before = backend_data_snapshot(&backend).await;
    let rejected = replication_entry(
        1,
        "capacity-rejected",
        now,
        ReplicationOp::Batch {
            ops: vec![
                acquire.clone(),
                release.clone(),
                // The first key has no record or active authority. Its
                // inactive lease must not be pruned between Batch children.
                ReplicationOp::AcquireLease {
                    key: key_b,
                    owner: owner.clone(),
                    fence: FenceToken::new(2),
                    credential_id: 2,
                    ttl: Duration::from_secs(60),
                    expires_at,
                },
            ],
        },
    );

    assert_eq!(
        backend
            .replicate_entry(rejected)
            .await
            .expect_err("the final child must exceed the key limit"),
        StoreError::BackendUnavailable("fake backend tracked-key limit reached".into())
    );
    assert_eq!(backend_data_snapshot(&backend).await, before);
    assert_no_replication_entry(&mut watch).await;

    let accepted = replication_entry(
        1,
        "capacity-accepted",
        now,
        ReplicationOp::Batch {
            ops: vec![acquire, release],
        },
    );
    backend
        .replicate_entry(accepted.clone())
        .await
        .expect("a valid entry must remain appendable");
    assert_eq!(next_replication_entry(&mut watch).await, accepted);
    assert_no_replication_entry(&mut watch).await;
    assert_eq!(backend.inner.lock().await.watchers.len(), 1);
    let state = backend.inner.lock().await;
    assert!(
        !state
            .leases
            .get(&FakeSessionBackend::map_key(&key_a))
            .unwrap()
            .active
    );
    assert_eq!(state.key_retention.epoch, 0);
}

#[tokio::test]
async fn late_capacity_failure_rolls_back_batch_and_preserves_watcher() {
    let backend = FakeSessionBackend::with_limits(FakeBackendLimits {
        max_tracked_keys: 1,
        max_replication_entries: 8,
    });
    let key_a = test_key("t1", b"capacity-a");
    let key_b = test_key("t1", b"capacity-b");
    let owner = OwnerId::new("owner-a").expect("owner");
    let now = backend.clock.now_utc();
    let lease_expires_at = checked_session_deadline(now, Duration::from_secs(60))
        .expect("capacity fixture lease expiry");
    let mut watch = backend.watch(1).await.expect("watch rejected batch");
    let before = backend_data_snapshot(&backend).await;
    // A late refusal must roll back a live first child as well as the dead
    // first child covered above. Cleanup never runs between batch children.
    let rejected = replication_entry(
        1,
        "capacity-rejected",
        now,
        ReplicationOp::Batch {
            ops: vec![
                ReplicationOp::AcquireLease {
                    key: key_a.clone(),
                    owner: owner.clone(),
                    fence: FenceToken::new(1),
                    credential_id: 1,
                    ttl: Duration::from_secs(60),
                    expires_at: lease_expires_at,
                },
                ReplicationOp::AcquireLease {
                    key: key_b.clone(),
                    owner: owner.clone(),
                    fence: FenceToken::new(2),
                    credential_id: 2,
                    ttl: Duration::from_secs(60),
                    expires_at: lease_expires_at,
                },
            ],
        },
    );

    assert_eq!(
        backend
            .replicate_entry(rejected)
            .await
            .expect_err("the final child must exceed the key limit"),
        StoreError::BackendUnavailable("fake backend tracked-key limit reached".into())
    );
    assert_eq!(backend_data_snapshot(&backend).await, before);
    assert_no_replication_entry(&mut watch).await;

    let accepted = replication_entry(
        1,
        "capacity-accepted",
        now,
        ReplicationOp::AcquireLease {
            key: key_a,
            owner,
            fence: FenceToken::new(1),
            credential_id: 1,
            ttl: Duration::from_secs(60),
            expires_at: lease_expires_at,
        },
    );
    backend
        .replicate_entry(accepted.clone())
        .await
        .expect("a valid entry must remain appendable");
    assert_eq!(next_replication_entry(&mut watch).await, accepted);
    assert_no_replication_entry(&mut watch).await;
    assert_eq!(backend.inner.lock().await.watchers.len(), 1);
}

#[tokio::test]
async fn failed_rebuild_preserves_every_internal_state_dimension() {
    let backend = FakeSessionBackend::new();
    let original_key = test_key("t1", b"rebuild-original");
    let lease = acquire_test_lease(&backend, &original_key, "owner-a").await;
    backend
        .compare_and_set(cas_for_lease(original_key, &lease, None, 1))
        .await
        .expect("seed record");
    let watch_start = backend.max_replication_sequence().await.expect("head") + 1;
    let mut watch = backend.watch(watch_start).await.expect("watch rebuild");
    let before = backend_data_snapshot(&backend).await;

    let owner = OwnerId::new("owner-b").expect("owner");
    let replacement_key = test_key("t1", b"rebuild-replacement");
    let missing_key = test_key("t1", b"rebuild-missing");
    let now = backend.clock.now_utc();
    let ttl = Duration::from_secs(60);
    let expires_at =
        Timestamp::from_offset_datetime(*now.as_offset_datetime() + time::Duration::seconds(60));
    let replacement = vec![
        replication_entry(
            1,
            "replacement-first",
            now,
            ReplicationOp::AcquireLease {
                key: replacement_key,
                owner: owner.clone(),
                fence: FenceToken::new(20),
                credential_id: 20,
                ttl,
                expires_at,
            },
        ),
        replication_entry(
            2,
            "replacement-failure",
            now,
            ReplicationOp::Batch {
                ops: vec![
                    ReplicationOp::AcquireLease {
                        key: missing_key.clone(),
                        owner: owner.clone(),
                        fence: FenceToken::new(21),
                        credential_id: 21,
                        ttl,
                        expires_at,
                    },
                    ReplicationOp::RefreshTtl {
                        key: missing_key,
                        owner,
                        fence: FenceToken::new(21),
                        ttl,
                        expires_at,
                    },
                ],
            },
        ),
    ];

    assert_eq!(
        backend
            .rebuild_replication_state(replacement)
            .await
            .expect_err("the final rebuild entry must reject"),
        StoreError::NotFound
    );
    assert_eq!(backend_data_snapshot(&backend).await, before);
    assert_no_replication_entry(&mut watch).await;
}

#[tokio::test]
async fn staging_preserves_and_advances_nonzero_compaction_state() {
    let backend = FakeSessionBackend::with_limits(FakeBackendLimits {
        max_tracked_keys: 8,
        max_replication_entries: 1,
    });
    let owner = OwnerId::new("owner-a").expect("owner");
    let first_key = test_key("t1", b"compacted-first");
    let second_key = test_key("t1", b"retained-second");
    let third_key = test_key("t1", b"next-third");
    let missing_key = test_key("t1", b"missing-final");
    let now = backend.clock.now_utc();
    let expires_at = checked_session_deadline(now, Duration::from_secs(60)).unwrap();
    let first = replication_entry(
        1,
        "compacted-first",
        now,
        ReplicationOp::AcquireLease {
            key: first_key,
            owner: owner.clone(),
            fence: FenceToken::new(1),
            credential_id: 1,
            ttl: Duration::from_secs(60),
            expires_at,
        },
    );
    let second = replication_entry(
        2,
        "retained-second",
        now,
        ReplicationOp::AcquireLease {
            key: second_key,
            owner: owner.clone(),
            fence: FenceToken::new(2),
            credential_id: 2,
            ttl: Duration::from_secs(60),
            expires_at,
        },
    );
    backend
        .replicate_entry(first.clone())
        .await
        .expect("append first entry");
    backend
        .replicate_entry(second.clone())
        .await
        .expect("append second entry");
    let mut watch = backend.watch(3).await.expect("watch after compaction");
    let compacted = backend_data_snapshot(&backend).await;
    assert_eq!(compacted.compacted_replication_sequence, 1);
    assert_eq!(compacted.last_replication_sequence, 2);
    assert_eq!(compacted.replication_log, vec![second]);

    let rejected_ops = vec![
        ReplicationOp::AcquireLease {
            key: third_key.clone(),
            owner: owner.clone(),
            fence: FenceToken::new(3),
            credential_id: 3,
            ttl: Duration::from_secs(60),
            expires_at,
        },
        ReplicationOp::Batch {
            ops: vec![
                ReplicationOp::AcquireLease {
                    key: missing_key.clone(),
                    owner: owner.clone(),
                    fence: FenceToken::new(4),
                    credential_id: 4,
                    ttl: Duration::from_secs(60),
                    expires_at,
                },
                ReplicationOp::RefreshTtl {
                    key: missing_key,
                    owner: owner.clone(),
                    fence: FenceToken::new(4),
                    ttl: Duration::from_secs(60),
                    expires_at,
                },
            ],
        },
    ];
    let rejected_append = replication_entry(
        3,
        "rejected-after-compaction",
        now,
        ReplicationOp::Batch {
            ops: rejected_ops.clone(),
        },
    );
    assert_eq!(
        backend
            .replicate_entry(rejected_append)
            .await
            .expect_err("late append child must reject"),
        StoreError::NotFound
    );
    assert_eq!(backend_data_snapshot(&backend).await, compacted);
    assert_no_replication_entry(&mut watch).await;

    let rejected_rebuild = vec![
        replication_entry(1, "rebuild-first", now, rejected_ops[0].clone()),
        replication_entry(2, "rebuild-final", now, rejected_ops[1].clone()),
    ];
    assert_eq!(
        backend
            .rebuild_replication_state(rejected_rebuild)
            .await
            .expect_err("late rebuild entry must reject"),
        StoreError::NotFound
    );
    assert_eq!(backend_data_snapshot(&backend).await, compacted);
    assert_no_replication_entry(&mut watch).await;

    backend
        .replicate_entry(first)
        .await
        .expect("an already-compacted duplicate is idempotent");
    assert_eq!(backend_data_snapshot(&backend).await, compacted);
    assert_no_replication_entry(&mut watch).await;

    let third = replication_entry(
        3,
        "accepted-after-compaction",
        now,
        ReplicationOp::AcquireLease {
            key: third_key,
            owner,
            fence: FenceToken::new(3),
            credential_id: 3,
            ttl: Duration::from_secs(60),
            expires_at,
        },
    );
    backend
        .replicate_entry(third.clone())
        .await
        .expect("next entry remains appendable");
    assert_eq!(next_replication_entry(&mut watch).await, third.clone());
    assert_no_replication_entry(&mut watch).await;

    let advanced = backend_data_snapshot(&backend).await;
    assert_eq!(advanced.compacted_replication_sequence, 2);
    assert_eq!(advanced.last_replication_sequence, 3);
    assert_eq!(advanced.replication_log, vec![third]);
    assert_eq!(advanced.watcher_count, 1);
}

#[tokio::test]
async fn fake_backend_get_miss() {
    let backend = FakeSessionBackend::new();
    let key = test_key("t1", b"id1");
    let result = backend.get(&key).await.unwrap();
    assert!(result.is_none());
}

#[tokio::test]
async fn exhausted_direct_replication_sequence_rejects_before_lease_mutation() {
    let backend = FakeSessionBackend::new();
    {
        let mut state = backend.inner.lock().await;
        state.last_replication_sequence = u64::MAX;
    }
    let key = test_key("t1", b"sequence-exhausted");

    let error = backend
        .acquire(
            &key,
            OwnerId::new("owner-a").expect("owner"),
            Duration::from_secs(60),
        )
        .await
        .expect_err("an exhausted direct log must reject before mutation");

    assert_eq!(
        error,
        LeaseError::Backend("backend unavailable: replication sequence exhausted".to_string())
    );
    let state = backend.inner.lock().await;
    assert!(!state
        .leases
        .contains_key(&FakeSessionBackend::map_key(&key)));
    assert!(state.replication_log.is_empty());
    assert_eq!(state.next_fence, 1);
    assert_eq!(state.next_credential_id, 1);
}

#[tokio::test]
async fn direct_successful_cas_emits_ordered_replication_entry_and_watch_event() {
    let backend = FakeSessionBackend::new();
    let key = test_key("t1", b"direct-cas");
    let lease = acquire_test_lease(&backend, &key, "owner-a").await;
    let start_sequence = backend.max_replication_sequence().await.unwrap() + 1;
    let mut watch = backend.watch(start_sequence).await.unwrap();

    let result = backend
        .compare_and_set(cas_for_lease(key.clone(), &lease, None, 1))
        .await
        .unwrap();
    assert_eq!(result, CompareAndSetResult::Success);

    let watched = next_replication_entry(&mut watch).await;
    assert_eq!(watched.sequence, start_sequence);
    match &watched.op {
        ReplicationOp::CompareAndSet {
            key: logged_key,
            expected_generation,
            credential_id,
            guard_expires_at,
            new_record,
        } => {
            assert_eq!(logged_key, &key);
            assert_eq!(expected_generation, &None);
            assert_eq!(*credential_id, lease.credential_id());
            assert_eq!(*guard_expires_at, lease.expires_at());
            assert_eq!(new_record.generation, Generation::new(1));
        }
        other => panic!("expected direct CAS replication op, got {other:?}"),
    }

    assert_eq!(
        backend.max_replication_sequence().await.unwrap(),
        start_sequence
    );
    let log = backend.get_replication_log(1, 16).await.unwrap();
    assert!(log.iter().any(|entry| entry == &watched));
}

#[tokio::test]
async fn direct_conflicting_cas_does_not_advance_replication_sequence() {
    let backend = FakeSessionBackend::new();
    let key = test_key("t1", b"direct-cas-conflict");
    let lease = acquire_test_lease(&backend, &key, "owner-a").await;

    let result = backend
        .compare_and_set(cas_for_lease(key.clone(), &lease, None, 1))
        .await
        .unwrap();
    assert_eq!(result, CompareAndSetResult::Success);
    let before_conflict = backend.max_replication_sequence().await.unwrap();

    let result = backend
        .compare_and_set(cas_for_lease(key, &lease, None, 2))
        .await
        .unwrap();
    assert!(matches!(result, CompareAndSetResult::Conflict { .. }));
    assert_eq!(
        backend.max_replication_sequence().await.unwrap(),
        before_conflict
    );
}

#[tokio::test]
async fn direct_delete_and_ttl_refresh_emit_matching_replication_ops() {
    let backend = FakeSessionBackend::new();
    let key = test_key("t1", b"direct-delete-refresh");
    let lease = acquire_test_lease(&backend, &key, "owner-a").await;

    let result = backend
        .compare_and_set(cas_for_lease(key.clone(), &lease, None, 1))
        .await
        .unwrap();
    assert_eq!(result, CompareAndSetResult::Success);

    let refresh_sequence = backend.max_replication_sequence().await.unwrap() + 1;
    let mut refresh_watch = backend.watch(refresh_sequence).await.unwrap();
    backend
        .refresh_ttl(&lease, Duration::from_secs(30))
        .await
        .unwrap();
    let refresh_entry = next_replication_entry(&mut refresh_watch).await;
    assert_eq!(refresh_entry.sequence, refresh_sequence);
    assert!(matches!(
        refresh_entry.op,
        ReplicationOp::RefreshTtl {
            key: ref logged_key,
            owner: ref logged_owner,
            fence,
            ttl,
            expires_at,
        } if logged_key == &key
            && logged_owner == lease.owner()
            && fence == lease.fence()
            && ttl == Duration::from_secs(30)
            && expires_at > lease.acquired_at()
    ));

    let delete_sequence = backend.max_replication_sequence().await.unwrap() + 1;
    let mut delete_watch = backend.watch(delete_sequence).await.unwrap();
    backend.delete_fenced(&lease).await.unwrap();
    let delete_entry = next_replication_entry(&mut delete_watch).await;
    assert_eq!(delete_entry.sequence, delete_sequence);
    assert!(matches!(
        delete_entry.op,
        ReplicationOp::DeleteFenced {
            key: ref logged_key,
            owner: ref logged_owner,
            fence,
        } if logged_key == &key && logged_owner == lease.owner() && fence == lease.fence()
    ));
}

#[tokio::test]
async fn direct_lease_mutations_emit_matching_replication_ops() {
    let backend = FakeSessionBackend::new();
    let key = test_key("t1", b"direct-lease-log");
    let owner = OwnerId::new("owner-a").unwrap();
    let mut watch = backend.watch(1).await.unwrap();

    let lease = backend
        .acquire(&key, owner.clone(), Duration::from_secs(60))
        .await
        .unwrap();
    let acquired = next_replication_entry(&mut watch).await;
    assert!(matches!(
        acquired.op,
        ReplicationOp::AcquireLease {
            key: ref logged_key,
            owner: ref logged_owner,
            fence,
            credential_id,
            ttl,
            expires_at,
        } if logged_key == &key
            && logged_owner == &owner
            && fence == lease.fence()
            && credential_id == lease.credential_id()
            && ttl == Duration::from_secs(60)
            && expires_at == lease.expires_at()
    ));

    let renewed = backend
        .renew(&lease, Duration::from_secs(90))
        .await
        .unwrap();
    let renewed_entry = next_replication_entry(&mut watch).await;
    assert!(matches!(
        renewed_entry.op,
        ReplicationOp::RenewLease {
            key: ref logged_key,
            owner: ref logged_owner,
            fence,
            credential_id,
            ttl,
            expires_at,
        } if logged_key == &key
            && logged_owner == &owner
            && fence == renewed.fence()
            && credential_id == renewed.credential_id()
            && ttl == Duration::from_secs(90)
            && expires_at == renewed.expires_at()
    ));

    let released_fence = renewed.fence();
    let released_credential_id = renewed.credential_id();
    backend.release(renewed).await.unwrap();
    let released_entry = next_replication_entry(&mut watch).await;
    assert!(matches!(
        released_entry.op,
        ReplicationOp::ReleaseLease {
            key: ref logged_key,
            owner: ref logged_owner,
            fence,
            credential_id,
        } if logged_key == &key
            && logged_owner == &owner
            && fence == released_fence
            && credential_id == released_credential_id
    ));
}

#[tokio::test]
async fn slow_watch_receiver_is_dropped_when_buffer_fills() {
    use futures_util::StreamExt;

    let backend = FakeSessionBackend::new();
    let mut watch = backend.watch(1).await.unwrap();
    let owner = OwnerId::new("owner-a").unwrap();
    let capacity = crate::backend::WATCH_CHANNEL_CAPACITY;

    for idx in 0..=capacity {
        let key = test_key("t1", format!("slow-watch-{idx}").as_bytes());
        backend
            .acquire(&key, owner.clone(), Duration::from_secs(60))
            .await
            .unwrap();
    }

    for _ in 0..capacity {
        assert!(watch.next().await.unwrap().is_ok());
    }
    let end = tokio::time::timeout(Duration::from_millis(100), watch.next())
        .await
        .expect("bounded watcher should close after overflow");
    assert!(end.is_none(), "slow watcher should be dropped on overflow");
}

#[tokio::test]
async fn fake_backend_bounds_tracked_keys_and_replication_log() {
    let backend = FakeSessionBackend::with_limits(FakeBackendLimits {
        max_tracked_keys: 2,
        max_replication_entries: 3,
    });
    let owner = OwnerId::new("owner-a").unwrap();
    let key_a = test_key("t1", b"bounded-a");
    let key_b = test_key("t1", b"bounded-b");
    let key_c = test_key("t1", b"bounded-c");

    backend
        .acquire(&key_a, owner.clone(), Duration::from_secs(60))
        .await
        .unwrap();
    backend
        .acquire(&key_b, owner.clone(), Duration::from_secs(60))
        .await
        .unwrap();

    let err = backend
        .acquire(&key_c, owner.clone(), Duration::from_secs(60))
        .await
        .unwrap_err();
    assert_eq!(
        err,
        LeaseError::Backend("fake backend tracked-key limit reached".into())
    );

    for _ in 0..5 {
        backend
            .acquire(&key_a, owner.clone(), Duration::from_secs(60))
            .await
            .unwrap();
    }

    let max_sequence = backend.max_replication_sequence().await.unwrap();
    assert_eq!(max_sequence, 7);
    let retained = backend
        .get_replication_log(max_sequence - 2, 16)
        .await
        .unwrap();
    assert_eq!(retained.len(), 3);
    assert_eq!(retained.first().unwrap().sequence, max_sequence - 2);
    assert_eq!(retained.last().unwrap().sequence, max_sequence);

    let compacted = backend.get_replication_log(1, 16).await.unwrap_err();
    assert_eq!(
        compacted,
        StoreError::ReplicationLogCursorCompacted {
            resume_from: max_sequence - 2,
        }
    );

    let state = backend.inner.lock().await;
    assert_eq!(state.key_fences.len(), 2);
    assert!(state.leases.len() <= 2);
    assert!(state.records.len() <= 2);
    assert_eq!(state.replication_log.len(), 3);
}

#[tokio::test]
async fn direct_cas_succeeds_when_replication_log_and_watch_are_disabled() {
    let mut caps = BackendCapabilities::all_enabled();
    caps.ordered_replication_log = false;
    caps.watch = false;
    let backend = FakeSessionBackend::with_capabilities(caps);
    let key = test_key("t1", b"log-watch-disabled");
    let lease = acquire_test_lease(&backend, &key, "owner-a").await;

    let result = backend
        .compare_and_set(cas_for_lease(key.clone(), &lease, None, 1))
        .await
        .unwrap();
    assert_eq!(result, CompareAndSetResult::Success);
    assert!(backend.get(&key).await.unwrap().is_some());
    assert_eq!(backend.max_replication_sequence().await.unwrap(), 0);
}

#[tokio::test]
async fn cas_success_create() {
    let backend = FakeSessionBackend::new();
    let key = test_key("t1", b"id1");
    let lease = acquire_test_lease(&backend, &key, "owner-a").await;
    let record = test_record_for_lease(key.clone(), 1, &lease);

    let op = CompareAndSet {
        key: key.clone(),
        lease: lease.clone(),
        expected_generation: None,
        new_record: record.clone(),
    };

    let result = backend.compare_and_set(op).await.unwrap();
    assert_eq!(result, CompareAndSetResult::Success);

    let got = backend.get(&key).await.unwrap().unwrap();
    assert_eq!(got.generation, Generation::new(1));
}

#[tokio::test]
async fn cas_conflict_wrong_generation() {
    let backend = FakeSessionBackend::new();
    let key = test_key("t1", b"id1");
    let lease = acquire_test_lease(&backend, &key, "owner-a").await;
    let record = test_record_for_lease(key.clone(), 1, &lease);

    backend
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: None,
            new_record: record.clone(),
        })
        .await
        .unwrap();

    let op = CompareAndSet {
        key: key.clone(),
        lease: lease.clone(),
        expected_generation: Some(Generation::new(99)),
        new_record: test_record_for_lease(key.clone(), 2, &lease),
    };

    let result = backend.compare_and_set(op).await.unwrap();
    assert_eq!(
        result,
        CompareAndSetResult::Conflict {
            current: Some(test_record_for_lease(key.clone(), 1, &lease)),
        }
    );
}

#[tokio::test]
async fn cas_conflict_same_generation_for_authoritative_state() {
    let backend = FakeSessionBackend::new();
    let key = test_key("t1", b"id1");
    let lease = acquire_test_lease(&backend, &key, "owner-a").await;
    let current = test_record_for_lease(key.clone(), 7, &lease);

    backend
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: None,
            new_record: current.clone(),
        })
        .await
        .unwrap();

    let result = backend
        .compare_and_set(cas_for_lease(
            key.clone(),
            &lease,
            Some(Generation::new(7)),
            7,
        ))
        .await
        .unwrap();

    assert_eq!(
        result,
        CompareAndSetResult::Conflict {
            current: Some(current),
        }
    );
}

#[tokio::test]
async fn cas_conflict_decrementing_generation_for_authoritative_state() {
    let backend = FakeSessionBackend::new();
    let key = test_key("t1", b"id1");
    let lease = acquire_test_lease(&backend, &key, "owner-a").await;
    let current = test_record_for_lease(key.clone(), 7, &lease);

    backend
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: None,
            new_record: current.clone(),
        })
        .await
        .unwrap();

    let result = backend
        .compare_and_set(cas_for_lease(
            key.clone(),
            &lease,
            Some(Generation::new(7)),
            3,
        ))
        .await
        .unwrap();

    assert_eq!(
        result,
        CompareAndSetResult::Conflict {
            current: Some(current),
        }
    );
}

#[tokio::test]
async fn cas_allows_non_monotonic_generation_for_telemetry_state() {
    let backend = FakeSessionBackend::new();
    let key = test_key("t1", b"id1");
    let lease = acquire_test_lease(&backend, &key, "owner-a").await;

    backend
        .compare_and_set(cas_for_lease_with_state_class(
            key.clone(),
            &lease,
            None,
            7,
            StateClass::TelemetryDerived,
        ))
        .await
        .unwrap();

    let result = backend
        .compare_and_set(cas_for_lease_with_state_class(
            key.clone(),
            &lease,
            Some(Generation::new(7)),
            3,
            StateClass::TelemetryDerived,
        ))
        .await
        .unwrap();

    assert_eq!(result, CompareAndSetResult::Success);
}

#[tokio::test]
async fn cas_rejects_mismatched_record_key_on_create() {
    let backend = FakeSessionBackend::new();
    let key_a = test_key("t1", b"id1");
    let key_b = test_key("t2", b"id2");
    let lease_a = acquire_test_lease(&backend, &key_a, "owner-a").await;

    let err = backend
        .compare_and_set(CompareAndSet {
            key: key_a.clone(),
            lease: lease_a,
            expected_generation: None,
            new_record: test_record(key_b, 1, 1, "owner-a"),
        })
        .await
        .unwrap_err();

    assert_eq!(
        err,
        StoreError::InvalidKey("compare-and-set key does not match record key".into())
    );
    assert!(backend.get(&key_a).await.unwrap().is_none());
}

#[tokio::test]
async fn cas_rejects_mismatched_record_key_on_update() {
    let backend = FakeSessionBackend::new();
    let key_a = test_key("t1", b"id1");
    let key_b = test_key("t2", b"id2");
    let lease_a = acquire_test_lease(&backend, &key_a, "owner-a").await;

    backend
        .compare_and_set(CompareAndSet {
            key: key_a.clone(),
            lease: lease_a.clone(),
            expected_generation: None,
            new_record: test_record_for_lease(key_a.clone(), 1, &lease_a),
        })
        .await
        .unwrap();

    let err = backend
        .compare_and_set(CompareAndSet {
            key: key_a.clone(),
            lease: lease_a,
            expected_generation: Some(Generation::new(1)),
            new_record: test_record(key_b, 2, 2, "owner-a"),
        })
        .await
        .unwrap_err();

    assert_eq!(
        err,
        StoreError::InvalidKey("compare-and-set key does not match record key".into())
    );
    assert_eq!(backend.get(&key_a).await.unwrap().unwrap().key, key_a);
}

#[tokio::test]
async fn stale_fence_rejected() {
    let backend = FakeSessionBackend::new();
    let key = test_key("t1", b"id1");

    // Owner A acquires lease with fence 1.
    let lease_a = backend
        .acquire(
            &key,
            OwnerId::new("owner-a").unwrap(),
            Duration::from_secs(60),
        )
        .await
        .unwrap();
    assert_eq!(lease_a.fence(), FenceToken::new(1));

    // Owner A writes with fence 1.
    backend
        .compare_and_set(cas_for_lease(key.clone(), &lease_a, None, 1))
        .await
        .unwrap();

    // Owner A releases lease.
    let stale_lease_a = lease_a.clone();
    backend.release(lease_a).await.unwrap();

    // Owner B acquires lease with fence 2.
    let lease_b = backend
        .acquire(
            &key,
            OwnerId::new("owner-b").unwrap(),
            Duration::from_secs(60),
        )
        .await
        .unwrap();
    assert_eq!(lease_b.fence(), FenceToken::new(2));

    // Owner A tries to write again with old fence 1.
    let err = backend
        .compare_and_set(cas_for_lease(
            key.clone(),
            &stale_lease_a,
            Some(Generation::new(1)),
            2,
        ))
        .await
        .unwrap_err();

    assert_eq!(err, StoreError::StaleFence);
}

#[tokio::test(start_paused = true)]
async fn stale_fence_after_lease_expiry() {
    let backend = FakeSessionBackend::new();
    let key = test_key("t1", b"id1");

    // Owner A acquires a very short lease.
    let lease_a = backend
        .acquire(
            &key,
            OwnerId::new("owner-a").unwrap(),
            Duration::from_millis(50),
        )
        .await
        .unwrap();

    // Owner A writes.
    backend
        .compare_and_set(cas_for_lease(key.clone(), &lease_a, None, 1))
        .await
        .unwrap();

    // Advance time past lease expiry.
    tokio::time::advance(Duration::from_millis(100)).await;

    // Owner B acquires new lease with higher fence.
    let lease_b = backend
        .acquire(
            &key,
            OwnerId::new("owner-b").unwrap(),
            Duration::from_secs(60),
        )
        .await
        .unwrap();
    assert!(lease_b.fence() > lease_a.fence());

    // Owner A tries to write with old fence.
    let err = backend
        .compare_and_set(cas_for_lease(
            key.clone(),
            &lease_a,
            Some(Generation::new(1)),
            2,
        ))
        .await
        .unwrap_err();

    assert_eq!(err, StoreError::StaleFence);
}

#[tokio::test(start_paused = true)]
async fn expired_lease_cas_is_rejected_without_reacquire() {
    let backend = FakeSessionBackend::new();
    let key = test_key("t1", b"id1");

    let lease = backend
        .acquire(
            &key,
            OwnerId::new("owner-a").unwrap(),
            Duration::from_millis(50),
        )
        .await
        .unwrap();

    backend
        .compare_and_set(cas_for_lease(key.clone(), &lease, None, 1))
        .await
        .unwrap();

    tokio::time::advance(Duration::from_millis(100)).await;

    let err = backend
        .compare_and_set(cas_for_lease(
            key.clone(),
            &lease,
            Some(Generation::new(1)),
            2,
        ))
        .await
        .unwrap_err();

    assert_eq!(err, StoreError::LeaseExpired);
}

#[tokio::test]
async fn forged_higher_fence_cas_is_rejected_while_other_owner_holds_lease() {
    let backend = FakeSessionBackend::new();
    let key = test_key("t1", b"id1");

    let lease_a = backend
        .acquire(
            &key,
            OwnerId::new("owner-a").unwrap(),
            Duration::from_secs(60),
        )
        .await
        .unwrap();

    backend
        .compare_and_set(cas_for_lease(key.clone(), &lease_a, None, 1))
        .await
        .unwrap();

    let err = backend
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease_a,
            expected_generation: Some(Generation::new(1)),
            new_record: test_record(key.clone(), 2, 999, "owner-b"),
        })
        .await
        .unwrap_err();

    assert_eq!(err, StoreError::StaleFence);
}

#[tokio::test]
async fn released_lease_same_fence_cas_is_rejected_until_reacquire() {
    let backend = FakeSessionBackend::new();
    let key = test_key("t1", b"id1");

    let lease = backend
        .acquire(
            &key,
            OwnerId::new("owner-a").unwrap(),
            Duration::from_secs(60),
        )
        .await
        .unwrap();

    backend
        .compare_and_set(cas_for_lease(key.clone(), &lease, None, 1))
        .await
        .unwrap();

    let stale_lease = lease.clone();
    backend.release(lease).await.unwrap();

    let err = backend
        .compare_and_set(cas_for_lease(
            key.clone(),
            &stale_lease,
            Some(Generation::new(1)),
            2,
        ))
        .await
        .unwrap_err();

    assert_eq!(err, StoreError::StaleFence);
}

#[tokio::test]
async fn released_lease_forged_higher_fence_cas_is_rejected_until_reacquire() {
    let backend = FakeSessionBackend::new();
    let key = test_key("t1", b"id1");

    let lease = backend
        .acquire(
            &key,
            OwnerId::new("owner-a").unwrap(),
            Duration::from_secs(60),
        )
        .await
        .unwrap();

    backend
        .compare_and_set(cas_for_lease(key.clone(), &lease, None, 1))
        .await
        .unwrap();

    let stale_lease = lease.clone();
    backend.release(lease).await.unwrap();

    let err = backend
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: stale_lease,
            expected_generation: Some(Generation::new(1)),
            new_record: test_record(key.clone(), 2, 999, "owner-b"),
        })
        .await
        .unwrap_err();

    assert_eq!(err, StoreError::StaleFence);
}

#[tokio::test]
async fn stale_reader_cannot_replay_get_output_into_compare_and_set() {
    let backend = FakeSessionBackend::new();
    let key = test_key("t1", b"id1");

    let lease_a = acquire_test_lease(&backend, &key, "owner-a").await;
    backend
        .compare_and_set(cas_for_lease(key.clone(), &lease_a, None, 1))
        .await
        .unwrap();

    let snapshot = backend.get(&key).await.unwrap().unwrap();
    let stale_lease = lease_a.clone();
    backend.release(lease_a).await.unwrap();
    let _lease_b = acquire_test_lease(&backend, &key, "owner-b").await;

    let err = backend
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: stale_lease,
            expected_generation: Some(snapshot.generation),
            new_record: StoredSessionRecord {
                key,
                generation: Generation::new(2),
                ..snapshot
            },
        })
        .await
        .unwrap_err();

    assert_eq!(err, StoreError::StaleFence);
}

#[tokio::test]
async fn stale_reader_cannot_replay_get_output_into_delete_fenced() {
    let backend = FakeSessionBackend::new();
    let key = test_key("t1", b"id1");

    let lease = acquire_test_lease(&backend, &key, "owner-a").await;
    backend
        .compare_and_set(cas_for_lease(key.clone(), &lease, None, 1))
        .await
        .unwrap();

    let _snapshot = backend.get(&key).await.unwrap().unwrap();
    let stale_lease = lease.clone();
    backend.release(lease).await.unwrap();

    let err = backend.delete_fenced(&stale_lease).await.unwrap_err();

    assert_eq!(err, StoreError::StaleFence);
}

#[tokio::test]
async fn stale_reader_cannot_replay_get_output_into_refresh_ttl() {
    let backend = FakeSessionBackend::new();
    let key = test_key("t1", b"id1");

    let lease = acquire_test_lease(&backend, &key, "owner-a").await;
    backend
        .compare_and_set(cas_for_lease(key.clone(), &lease, None, 1))
        .await
        .unwrap();

    let _snapshot = backend.get(&key).await.unwrap().unwrap();
    let stale_lease = lease.clone();
    backend.release(lease).await.unwrap();

    let err = backend
        .refresh_ttl(&stale_lease, Duration::from_secs(10))
        .await
        .unwrap_err();

    assert_eq!(err, StoreError::StaleFence);
}

#[tokio::test]
async fn matching_fence_but_wrong_owner_cas_is_rejected() {
    let backend = FakeSessionBackend::new();
    let key = test_key("t1", b"id1");

    let lease_a = backend
        .acquire(
            &key,
            OwnerId::new("owner-a").unwrap(),
            Duration::from_secs(60),
        )
        .await
        .unwrap();

    backend
        .compare_and_set(cas_for_lease(key.clone(), &lease_a, None, 1))
        .await
        .unwrap();

    let err = backend
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease_a,
            expected_generation: Some(Generation::new(1)),
            new_record: test_record(key.clone(), 2, FenceToken::new(1).get(), "owner-b"),
        })
        .await
        .unwrap_err();

    assert_eq!(err, StoreError::StaleFence);
}

#[tokio::test]
async fn acquire_fence_advances_past_recorded_key_fence() {
    let backend = FakeSessionBackend::new();
    let key = test_key("t1", b"id1");
    let mk = FakeSessionBackend::map_key(&key);
    {
        let mut state = backend.inner.lock().await;
        state.key_fences.insert(mk, FenceToken::new(10));
        state.next_fence = 1;
    }

    let lease = backend
        .acquire(
            &key,
            OwnerId::new("owner-b").unwrap(),
            Duration::from_secs(60),
        )
        .await
        .unwrap();
    assert_eq!(lease.fence(), FenceToken::new(11));

    let err = backend
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease,
            expected_generation: Some(Generation::new(1)),
            new_record: test_record(key.clone(), 2, 10, "owner-a"),
        })
        .await
        .unwrap_err();
    assert_eq!(err, StoreError::StaleFence);
}

#[tokio::test]
async fn lease_acquire_renew_release() {
    let backend = FakeSessionBackend::new();
    let key = test_key("t1", b"id1");

    // Acquire.
    let lease = backend
        .acquire(
            &key,
            OwnerId::new("owner-a").unwrap(),
            Duration::from_secs(60),
        )
        .await
        .unwrap();
    assert_eq!(lease.owner().as_str(), "owner-a");
    assert_eq!(lease.fence(), FenceToken::new(1));

    // Renew.
    let renewed = backend
        .renew(&lease, Duration::from_secs(120))
        .await
        .unwrap();
    assert_eq!(renewed.fence(), lease.fence());
    assert_eq!(renewed.owner(), lease.owner());

    // Release.
    backend.release(renewed).await.unwrap();

    // After release, another owner can acquire.
    let lease2 = backend
        .acquire(
            &key,
            OwnerId::new("owner-b").unwrap(),
            Duration::from_secs(60),
        )
        .await
        .unwrap();
    assert_eq!(lease2.owner().as_str(), "owner-b");
    // Fence must be higher than previous.
    assert!(lease2.fence() > lease.fence());
}

#[tokio::test]
async fn stale_guard_release_after_renew_is_rejected() {
    let backend = FakeSessionBackend::new();
    let key = test_key("t1", b"id1");

    let lease = backend
        .acquire(
            &key,
            OwnerId::new("owner-a").unwrap(),
            Duration::from_secs(60),
        )
        .await
        .unwrap();
    let renewed = backend
        .renew(&lease, Duration::from_secs(120))
        .await
        .unwrap();

    let err = backend.release(lease).await.unwrap_err();
    assert_eq!(err, LeaseError::StaleFence);

    backend.release(renewed).await.unwrap();
}

#[tokio::test]
async fn stale_guard_renew_after_renew_is_rejected() {
    let backend = FakeSessionBackend::new();
    let key = test_key("t1", b"id1");

    let lease = backend
        .acquire(
            &key,
            OwnerId::new("owner-a").unwrap(),
            Duration::from_secs(60),
        )
        .await
        .unwrap();
    let renewed = backend
        .renew(&lease, Duration::from_secs(120))
        .await
        .unwrap();

    let err = backend
        .renew(&lease, Duration::from_secs(180))
        .await
        .unwrap_err();
    assert_eq!(err, LeaseError::StaleFence);

    backend.release(renewed).await.unwrap();
}

#[tokio::test]
async fn stale_guard_release_after_same_owner_reacquire_is_rejected() {
    let backend = FakeSessionBackend::new();
    let key = test_key("t1", b"id1");

    let first = backend
        .acquire(
            &key,
            OwnerId::new("owner-a").unwrap(),
            Duration::from_secs(60),
        )
        .await
        .unwrap();
    let second = backend
        .acquire(
            &key,
            OwnerId::new("owner-a").unwrap(),
            Duration::from_secs(60),
        )
        .await
        .unwrap();

    assert!(second.fence() > first.fence());

    let err = backend.release(first).await.unwrap_err();
    assert_eq!(err, LeaseError::StaleFence);

    backend.release(second).await.unwrap();
}

#[tokio::test]
async fn stale_guard_renew_after_same_owner_reacquire_is_rejected() {
    let backend = FakeSessionBackend::new();
    let key = test_key("t1", b"id1");

    let first = backend
        .acquire(
            &key,
            OwnerId::new("owner-a").unwrap(),
            Duration::from_secs(60),
        )
        .await
        .unwrap();
    let second = backend
        .acquire(
            &key,
            OwnerId::new("owner-a").unwrap(),
            Duration::from_secs(60),
        )
        .await
        .unwrap();

    assert!(second.fence() > first.fence());

    let err = backend
        .renew(&first, Duration::from_secs(60))
        .await
        .unwrap_err();
    assert_eq!(err, LeaseError::StaleFence);

    backend.release(second).await.unwrap();
}

#[tokio::test]
async fn lease_held_by_other_blocks_acquire() {
    let backend = FakeSessionBackend::new();
    let key = test_key("t1", b"id1");

    backend
        .acquire(
            &key,
            OwnerId::new("owner-a").unwrap(),
            Duration::from_secs(60),
        )
        .await
        .unwrap();

    let err = backend
        .acquire(
            &key,
            OwnerId::new("owner-b").unwrap(),
            Duration::from_secs(60),
        )
        .await
        .unwrap_err();

    assert_eq!(err, LeaseError::AlreadyHeld);
}

#[tokio::test]
async fn tenant_scoped_key_digesting() {
    let key_a = test_key("tenant-a", b"same-id");
    let key_b = test_key("tenant-b", b"same-id");

    let digest_a = key_a.digest();
    let digest_b = key_b.digest();

    assert_ne!(digest_a, digest_b);

    // Also verify HMAC-style digests differ.
    let hmac_a = key_a.digest_with_key(b"privacy-key");
    let hmac_b = key_b.digest_with_key(b"privacy-key");
    assert_ne!(hmac_a, hmac_b);
    assert_ne!(hmac_a, digest_a);
}

#[tokio::test]
async fn capability_enforcement_cas_disabled() {
    let mut caps = BackendCapabilities::all_enabled();
    caps.atomic_compare_and_set = false;
    let backend = FakeSessionBackend::with_capabilities(caps);
    let key = test_key("t1", b"id1");
    let lease = acquire_test_lease(&backend, &key, "owner-a").await;

    let err = backend
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease,
            expected_generation: None,
            new_record: test_record(key.clone(), 1, 1, "owner-a"),
        })
        .await
        .unwrap_err();

    assert_eq!(
        err,
        StoreError::CapabilityNotSupported("atomic_compare_and_set".into())
    );
}

#[tokio::test]
async fn capability_enforcement_fence_disabled() {
    let mut caps = BackendCapabilities::all_enabled();
    caps.monotonic_fencing_token = false;
    let backend = FakeSessionBackend::with_capabilities(caps);
    let key = test_key("t1", b"id1");
    let lease = acquire_test_lease(&backend, &key, "owner-a").await;

    let err = backend.delete_fenced(&lease).await.unwrap_err();

    assert_eq!(
        err,
        StoreError::CapabilityNotSupported("monotonic_fencing_token".into())
    );
}

#[tokio::test]
async fn capability_enforcement_ttl_disabled() {
    let mut caps = BackendCapabilities::all_enabled();
    caps.per_key_ttl = false;
    let backend = FakeSessionBackend::with_capabilities(caps);
    let key = test_key("t1", b"id1");
    let lease = acquire_test_lease(&backend, &key, "owner-a").await;

    let err = backend
        .refresh_ttl(&lease, Duration::from_secs(10))
        .await
        .unwrap_err();

    assert_eq!(
        err,
        StoreError::CapabilityNotSupported("per_key_ttl".into())
    );
}

#[tokio::test]
async fn capability_enforcement_max_value_bytes() {
    let mut caps = BackendCapabilities::all_enabled();
    caps.max_value_bytes = 4;
    let backend = FakeSessionBackend::with_capabilities(caps);
    let key = test_key("t1", b"id1");
    let lease = acquire_test_lease(&backend, &key, "owner-a").await;

    let err = backend
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease,
            expected_generation: None,
            new_record: test_record(key, 1, 1, "owner-a"),
        })
        .await
        .unwrap_err();

    assert_eq!(err, StoreError::PayloadTooLarge { actual: 7, max: 4 });
}

#[tokio::test]
async fn batch_mixed_ops() {
    let backend = FakeSessionBackend::new();
    let key1 = test_key("t1", b"id1");
    let key2 = test_key("t1", b"id2");
    let lease1 = acquire_test_lease(&backend, &key1, "owner-a").await;

    let ops = vec![
        SessionOp::CompareAndSet(cas_for_lease(key1.clone(), &lease1, None, 1)),
        SessionOp::Get { key: key1.clone() },
        SessionOp::Get { key: key2.clone() },
    ];

    let results = backend.batch(ops).await.unwrap();
    assert_eq!(results.len(), 3);

    assert_eq!(
        results[0],
        SessionOpResult::CompareAndSet(Ok(CompareAndSetResult::Success))
    );
    assert!(
        matches!(&results[1], SessionOpResult::Get(Ok(Some(r))) if r.generation == Generation::new(1))
    );
    assert_eq!(results[2], SessionOpResult::Get(Ok(None)));
}

#[tokio::test]
async fn capability_enforcement_batch_disabled() {
    let mut caps = BackendCapabilities::all_enabled();
    caps.batch_write = false;
    let backend = FakeSessionBackend::with_capabilities(caps);

    let err = backend.batch(vec![]).await.unwrap_err();

    assert_eq!(
        err,
        StoreError::CapabilityNotSupported("batch_write".into())
    );
}

#[tokio::test]
async fn delete_fenced_success_and_stale() {
    let backend = FakeSessionBackend::new();
    let key = test_key("t1", b"id1");
    let lease = acquire_test_lease(&backend, &key, "owner-a").await;

    backend
        .compare_and_set(cas_for_lease(key.clone(), &lease, None, 1))
        .await
        .unwrap();

    // Stale released guard.
    let stale_lease = lease.clone();
    backend.release(lease).await.unwrap();
    let err = backend.delete_fenced(&stale_lease).await.unwrap_err();
    assert_eq!(err, StoreError::StaleFence);

    // Valid active lease.
    let active_lease = acquire_test_lease(&backend, &key, "owner-b").await;
    backend.delete_fenced(&active_lease).await.unwrap();
    assert!(backend.get(&key).await.unwrap().is_none());
}

#[tokio::test]
async fn refresh_ttl_success_and_stale() {
    let backend = FakeSessionBackend::new();
    let key = test_key("t1", b"id1");
    let lease = acquire_test_lease(&backend, &key, "owner-a").await;

    backend
        .compare_and_set(cas_for_lease(key.clone(), &lease, None, 1))
        .await
        .unwrap();

    // Stale released guard.
    let stale_lease = lease.clone();
    backend.release(lease).await.unwrap();
    let err = backend
        .refresh_ttl(&stale_lease, Duration::from_secs(10))
        .await
        .unwrap_err();
    assert_eq!(err, StoreError::StaleFence);

    // Valid active lease.
    let active_lease = acquire_test_lease(&backend, &key, "owner-b").await;
    backend
        .refresh_ttl(&active_lease, Duration::from_secs(10))
        .await
        .unwrap();

    let got = backend.get(&key).await.unwrap().unwrap();
    assert!(got.expires_at.is_some());
}

#[tokio::test]
async fn test_ttl_expiration_fake_backend() {
    let backend = FakeSessionBackend::new();
    let key = test_key("t1", b"id1");
    let lease = acquire_test_lease(&backend, &key, "owner-a").await;
    let mut record = test_record_for_lease(key.clone(), 1, &lease);

    // Set expires_at in the past
    let now = Timestamp::now_utc();
    let past = *now.as_offset_datetime() - time::Duration::seconds(10);
    record.expires_at = Some(Timestamp::from_offset_datetime(past));

    // Verify is_expired() directly on the record
    assert!(record.is_expired());

    // Perform CAS to write the expired record.
    backend
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: None,
            new_record: record.clone(),
        })
        .await
        .unwrap();

    // 1. Reading it (get) must return None.
    let got = backend.get(&key).await.unwrap();
    assert!(got.is_none(), "expired record should return None on get");

    // 2. CAS checks: if it's expired, it acts as absent/None.
    // A CAS expecting None (create) should succeed and overwrite/update the expired record.
    let new_record = test_record_for_lease(key.clone(), 2, &lease);
    let res = backend
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: None,
            new_record: new_record.clone(),
        })
        .await
        .unwrap();
    assert_eq!(
        res,
        CompareAndSetResult::Success,
        "CAS expecting None should succeed on expired record"
    );

    // Now the record is generation 2 and NOT expired (expires_at is None).
    let got = backend.get(&key).await.unwrap().unwrap();
    assert_eq!(got.generation, Generation::new(2));

    // Make it expired again by setting expires_at to past and update via CAS.
    let mut expired_v3 = test_record_for_lease(key.clone(), 3, &lease);
    expired_v3.expires_at = Some(Timestamp::from_offset_datetime(past));
    let res = backend
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: Some(Generation::new(2)),
            new_record: expired_v3,
        })
        .await
        .unwrap();
    assert_eq!(res, CompareAndSetResult::Success);

    // Now record is expired again. Attempting to CAS it expecting generation 3 should fail as absent.
    let v4 = test_record_for_lease(key.clone(), 4, &lease);
    let res = backend
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: Some(Generation::new(3)),
            new_record: v4,
        })
        .await
        .unwrap();
    assert_eq!(
        res,
        CompareAndSetResult::Conflict { current: None },
        "CAS expecting generation should conflict with None if expired"
    );

    // 3. TTL refreshes: if record is expired, refreshing TTL must return StoreError::NotFound.
    let err = backend
        .refresh_ttl(&lease, Duration::from_secs(10))
        .await
        .unwrap_err();
    assert_eq!(
        err,
        StoreError::NotFound,
        "refreshing TTL of expired record must return NotFound"
    );
}

#[tokio::test]
async fn repeated_idle_watch_disconnects_do_not_accumulate_in_fake_backend() {
    let backend = FakeSessionBackend::new();
    for _ in 0..128 {
        let stream = backend.watch(1).await.expect("register idle watch");
        drop(stream);
    }

    let live = backend.watch(1).await.expect("register live watch");
    assert_eq!(backend.inner.lock().await.watchers.len(), 1);
    drop(live);
}

#[path = "capacity_replay_tests.rs"]
mod capacity_replay;

#[path = "command_clock_regression_tests.rs"]
mod command_clock_regressions;

pub(crate) fn with_tracked_key_limit_for_test(
    source: &FakeSessionBackend,
    maximum: usize,
) -> FakeSessionBackend {
    assert!(maximum > 0);
    let mut backend = source.clone();
    backend.limits.max_tracked_keys = maximum;
    backend
}

#[path = "literal_renewal_tests.rs"]
mod literal_renewal;

#[cfg(feature = "lab-memory")]
pub(crate) async fn canonical_record_for_test(
    backend: &FakeSessionBackend,
    key: &SessionKey,
) -> Option<StoredSessionRecord> {
    backend
        .inner
        .lock()
        .await
        .records
        .get(&FakeSessionBackend::map_key(key))
        .cloned()
}

pub(crate) async fn retained_record_count_for_test(backend: &FakeSessionBackend) -> usize {
    backend.inner.lock().await.records.len()
}

#[tokio::test]
async fn round6_non_journal_batch_keeps_its_original_write_exemption() {
    let mut caps = BackendCapabilities::all_enabled();
    caps.ordered_replication_log = false;
    caps.watch = false;
    let backend = FakeSessionBackend::with_capabilities(caps);
    let key = test_key("batch-bound", b"non-journal");
    let lease = acquire_test_lease(&backend, &key, "batch-owner").await;
    backend
        .compare_and_set(cas_for_lease(key.clone(), &lease, None, 1))
        .await
        .unwrap();
    let ops = (0..256)
        .map(|_| SessionOp::RefreshTtl {
            lease: lease.clone(),
            ttl: Duration::from_secs(60),
        })
        .collect();
    let results = backend
        .batch(ops)
        .await
        .expect("no serialized journal entry exists to exceed its node limit");
    assert_eq!(results.len(), 256);
    assert!(results
        .iter()
        .all(|r| matches!(r, SessionOpResult::RefreshTtl(Ok(())))));
    assert_eq!(backend.max_replication_sequence().await.unwrap(), 0);
}
