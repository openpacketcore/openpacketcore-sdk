use std::time::Duration;

use bytes::Bytes;
use futures_util::{stream::BoxStream, StreamExt};
use opc_session_store::{
    EncryptedSessionPayload, FakeSessionBackend, FenceToken, Generation, OwnerId, ReplicationEntry,
    ReplicationOp, SessionKey, SessionKeyType, SessionStoreBackend, SqliteSessionBackend,
    StateClass, StateType, StoreError, StoredSessionRecord,
};
use opc_types::{NetworkFunctionKind, TenantId, Timestamp};

fn key(stable_id: &'static [u8]) -> SessionKey {
    SessionKey {
        tenant: TenantId::new("replication-atomicity").expect("tenant"),
        nf_kind: NetworkFunctionKind::from_static("smf"),
        key_type: SessionKeyType::PduSession,
        stable_id: Bytes::from_static(stable_id)
            .try_into()
            .expect("valid stable ID"),
    }
}

fn timestamp() -> Timestamp {
    Timestamp::from_offset_datetime(time::OffsetDateTime::now_utc())
}

fn deadline(timestamp: Timestamp) -> Timestamp {
    Timestamp::from_offset_datetime(*timestamp.as_offset_datetime() + time::Duration::hours(1))
}

fn record(
    key: SessionKey,
    generation: u64,
    owner: &OwnerId,
    fence: FenceToken,
) -> StoredSessionRecord {
    StoredSessionRecord {
        key,
        generation: Generation::new(generation),
        owner: owner.clone(),
        fence,
        state_class: StateClass::AuthoritativeSession,
        state_type: StateType::new("replication-atomicity").expect("state type"),
        expires_at: None,
        payload: EncryptedSessionPayload::new(Bytes::from_static(b"ciphertext")),
    }
}

fn acquire(
    key: SessionKey,
    owner: &OwnerId,
    fence: u64,
    credential_id: u64,
    timestamp: Timestamp,
) -> ReplicationOp {
    ReplicationOp::AcquireLease {
        key,
        owner: owner.clone(),
        fence: FenceToken::new(fence),
        credential_id,
        ttl: Duration::from_secs(60 * 60),
        expires_at: deadline(timestamp),
    }
}

fn compare_and_set(
    key: SessionKey,
    owner: &OwnerId,
    fence: u64,
    credential_id: u64,
    generation: u64,
    expected_generation: Option<Generation>,
    timestamp: Timestamp,
) -> ReplicationOp {
    ReplicationOp::CompareAndSet {
        key: key.clone(),
        expected_generation,
        credential_id,
        guard_expires_at: deadline(timestamp),
        new_record: record(key, generation, owner, FenceToken::new(fence)),
    }
}

fn entry(
    sequence: u64,
    tx_id: impl Into<String>,
    timestamp: Timestamp,
    op: ReplicationOp,
) -> ReplicationEntry {
    ReplicationEntry {
        sequence,
        tx_id: tx_id.into().try_into().expect("valid transaction ID"),
        op,
        timestamp,
    }
}

fn lease_and_record_entry(
    sequence: u64,
    tx_id: &'static str,
    key: SessionKey,
    owner: &OwnerId,
    fence: u64,
    credential_id: u64,
    timestamp: Timestamp,
) -> ReplicationEntry {
    entry(
        sequence,
        tx_id,
        timestamp,
        ReplicationOp::Batch {
            ops: vec![
                acquire(key.clone(), owner, fence, credential_id, timestamp),
                compare_and_set(key, owner, fence, credential_id, 1, None, timestamp),
            ],
        },
    )
}

async fn replication_snapshot<B>(backend: &B) -> (u64, Vec<ReplicationEntry>, (u64, u64))
where
    B: SessionStoreBackend,
{
    (
        backend
            .max_replication_sequence()
            .await
            .expect("read replication head"),
        backend
            .get_replication_log(1, 32)
            .await
            .expect("read replication log"),
        backend
            .next_lease_info()
            .await
            .expect("read lease counters"),
    )
}

async fn next_watch_entry(
    watch: &mut BoxStream<'static, Result<ReplicationEntry, StoreError>>,
) -> ReplicationEntry {
    tokio::time::timeout(Duration::from_secs(1), watch.next())
        .await
        .expect("watch entry deadline")
        .expect("watch remains open")
        .expect("watch entry")
}

async fn assert_no_watch_entry(
    watch: &mut BoxStream<'static, Result<ReplicationEntry, StoreError>>,
) {
    match tokio::time::timeout(Duration::from_millis(25), watch.next()).await {
        Err(_) => {}
        Ok(item) => panic!("watch unexpectedly yielded {item:?}"),
    }
}

async fn assert_failed_compound_append_is_atomic<B>(backend: B)
where
    B: SessionStoreBackend,
{
    let owner = OwnerId::new("owner-a").expect("owner");
    let original_key = key(b"original");
    let staged_key = key(b"staged");
    let missing_lease_key = key(b"missing-lease");
    let first_timestamp = timestamp();
    let original = lease_and_record_entry(
        1,
        "original",
        original_key.clone(),
        &owner,
        1,
        1,
        first_timestamp,
    );
    backend
        .replicate_entry(original.clone())
        .await
        .expect("seed original state");
    let before = replication_snapshot(&backend).await;
    let original_record = backend
        .get(&original_key)
        .await
        .expect("read original")
        .expect("original record");
    let mut watch = backend.watch(2).await.expect("watch failed append");

    let second_timestamp = timestamp();
    let rejected = entry(
        2,
        "late-child-failure",
        second_timestamp,
        ReplicationOp::Batch {
            ops: vec![
                acquire(staged_key.clone(), &owner, 10, 10, second_timestamp),
                compare_and_set(
                    staged_key.clone(),
                    &owner,
                    10,
                    10,
                    1,
                    None,
                    second_timestamp,
                ),
                compare_and_set(
                    missing_lease_key.clone(),
                    &owner,
                    11,
                    11,
                    1,
                    None,
                    second_timestamp,
                ),
            ],
        },
    );

    assert_eq!(
        backend
            .replicate_entry(rejected)
            .await
            .expect_err("the final child must reject"),
        StoreError::StaleFence
    );
    assert_eq!(replication_snapshot(&backend).await, before);
    assert_eq!(
        backend.get(&original_key).await.expect("read original"),
        Some(original_record)
    );
    assert!(backend
        .get(&staged_key)
        .await
        .expect("read staged")
        .is_none());
    assert!(backend
        .get(&missing_lease_key)
        .await
        .expect("read missing lease key")
        .is_none());
    assert_no_watch_entry(&mut watch).await;
}

async fn assert_failed_rebuild_is_atomic<B>(backend: B)
where
    B: SessionStoreBackend,
{
    let owner = OwnerId::new("owner-a").expect("owner");
    let original_key = key(b"rebuild-original");
    let replacement_key = key(b"rebuild-replacement");
    let missing_lease_key = key(b"rebuild-missing-lease");
    let original_timestamp = timestamp();
    let original = lease_and_record_entry(
        1,
        "rebuild-original",
        original_key.clone(),
        &owner,
        3,
        4,
        original_timestamp,
    );
    backend
        .replicate_entry(original.clone())
        .await
        .expect("seed original state");
    let before = replication_snapshot(&backend).await;
    let original_record = backend
        .get(&original_key)
        .await
        .expect("read original")
        .expect("original record");
    let mut watch = backend.watch(2).await.expect("watch failed rebuild");

    let replacement_timestamp = timestamp();
    let replacement = lease_and_record_entry(
        1,
        "replacement",
        replacement_key.clone(),
        &owner,
        20,
        21,
        replacement_timestamp,
    );
    let rejected = entry(
        2,
        "rebuild-late-failure",
        timestamp(),
        compare_and_set(
            missing_lease_key.clone(),
            &owner,
            22,
            22,
            1,
            None,
            timestamp(),
        ),
    );

    assert_eq!(
        backend
            .rebuild_replication_state(vec![replacement, rejected])
            .await
            .expect_err("the final rebuild entry must reject"),
        StoreError::StaleFence
    );
    assert_eq!(replication_snapshot(&backend).await, before);
    assert_eq!(
        backend.get(&original_key).await.expect("read original"),
        Some(original_record)
    );
    assert!(backend
        .get(&replacement_key)
        .await
        .expect("read replacement")
        .is_none());
    assert!(backend
        .get(&missing_lease_key)
        .await
        .expect("read missing lease key")
        .is_none());
    assert_no_watch_entry(&mut watch).await;
}

async fn assert_successful_compound_append_is_ordered_and_single_event<B>(backend: B)
where
    B: SessionStoreBackend,
{
    let owner = OwnerId::new("owner-a").expect("owner");
    let key = key(b"successful-compound");
    let submitted = lease_and_record_entry(1, "compound", key.clone(), &owner, 7, 8, timestamp());
    let mut watch = backend.watch(1).await.expect("watch compound append");

    backend
        .replicate_entry(submitted.clone())
        .await
        .expect("ordered compound append");
    assert_eq!(next_watch_entry(&mut watch).await, submitted);
    assert_no_watch_entry(&mut watch).await;
    assert!(backend
        .get(&key)
        .await
        .expect("read compound record")
        .is_some());
    assert_eq!(
        backend
            .get_replication_log(1, 8)
            .await
            .expect("read compound log"),
        vec![submitted.clone()]
    );

    backend
        .replicate_entry(submitted)
        .await
        .expect("exact duplicate is idempotent");
    assert_no_watch_entry(&mut watch).await;
}

async fn assert_successful_rebuild_preserves_watch_subscription<B>(backend: B)
where
    B: SessionStoreBackend,
{
    let owner = OwnerId::new("owner-a").expect("owner");
    let key = key(b"successful-rebuild");
    let first = lease_and_record_entry(1, "first", key.clone(), &owner, 30, 31, timestamp());
    backend
        .replicate_entry(first.clone())
        .await
        .expect("seed rebuild state");
    let mut watch = backend.watch(2).await.expect("watch across rebuild");

    backend
        .rebuild_replication_state(vec![first])
        .await
        .expect("successful rebuild");
    assert_no_watch_entry(&mut watch).await;

    let second_timestamp = timestamp();
    let second = entry(
        2,
        "after-rebuild",
        second_timestamp,
        ReplicationOp::RenewLease {
            key,
            owner,
            fence: FenceToken::new(30),
            credential_id: 31,
            ttl: Duration::from_secs(60 * 60),
            expires_at: deadline(second_timestamp),
        },
    );
    backend
        .replicate_entry(second.clone())
        .await
        .expect("append after rebuild");
    assert_eq!(next_watch_entry(&mut watch).await, second);
    assert_no_watch_entry(&mut watch).await;
}

#[tokio::test]
async fn fake_failed_compound_append_is_atomic() {
    assert_failed_compound_append_is_atomic(FakeSessionBackend::new()).await;
}

#[tokio::test]
async fn sqlite_failed_compound_append_is_atomic() {
    assert_failed_compound_append_is_atomic(
        SqliteSessionBackend::in_memory().expect("SQLite backend"),
    )
    .await;
}

#[tokio::test]
async fn fake_failed_rebuild_is_atomic() {
    assert_failed_rebuild_is_atomic(FakeSessionBackend::new()).await;
}

#[tokio::test]
async fn sqlite_failed_rebuild_is_atomic() {
    assert_failed_rebuild_is_atomic(SqliteSessionBackend::in_memory().expect("SQLite backend"))
        .await;
}

#[tokio::test]
async fn fake_successful_compound_append_is_ordered_and_single_event() {
    assert_successful_compound_append_is_ordered_and_single_event(FakeSessionBackend::new()).await;
}

#[tokio::test]
async fn sqlite_successful_compound_append_is_ordered_and_single_event() {
    assert_successful_compound_append_is_ordered_and_single_event(
        SqliteSessionBackend::in_memory().expect("SQLite backend"),
    )
    .await;
}

#[tokio::test]
async fn fake_successful_rebuild_preserves_watch_subscription() {
    assert_successful_rebuild_preserves_watch_subscription(FakeSessionBackend::new()).await;
}

#[tokio::test]
async fn sqlite_successful_rebuild_preserves_watch_subscription() {
    assert_successful_rebuild_preserves_watch_subscription(
        SqliteSessionBackend::in_memory().expect("SQLite backend"),
    )
    .await;
}
