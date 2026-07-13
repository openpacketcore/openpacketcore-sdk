use std::{sync::Arc, thread, time::Duration};

use bytes::Bytes;
use futures_util::{FutureExt, StreamExt};
use opc_session_store::{
    checked_session_deadline, validate_replication_page_owned, validate_replication_prefix_owned,
    Clock, EncryptedSessionPayload, FakeSessionBackend, FenceToken, Generation, OwnerId,
    ReplicationEntry, ReplicationOp, SessionKey, SessionKeyType, SessionStoreBackend,
    SqliteSessionBackend, StateClass, StateType, StoreError, StoredSessionRecord,
    MAX_REPLICATION_OPERATIONS_PER_ENTRY, MAX_REPLICATION_OPERATION_DEPTH,
};
use opc_types::{NetworkFunctionKind, TenantId, Timestamp};

const DEEP_REJECTION_DEPTH: usize = 10_000;
const SMALL_STACK_BYTES: usize = 128 * 1024;

#[derive(Debug, Clone, Copy)]
enum BackendKind {
    Fake,
    Sqlite,
}

#[derive(Debug)]
struct FixedClock(Timestamp);

impl Clock for FixedClock {
    fn now_utc(&self) -> Timestamp {
        self.0
    }
}

fn timestamp() -> Timestamp {
    Timestamp::from_offset_datetime(
        time::OffsetDateTime::from_unix_timestamp(1_900_000_000)
            .expect("fixed test timestamp is representable"),
    )
}

fn key(stable_id: &[u8]) -> SessionKey {
    SessionKey {
        tenant: TenantId::new("structure-bounds").expect("tenant"),
        nf_kind: NetworkFunctionKind::from_static("smf"),
        key_type: SessionKeyType::PduSession,
        stable_id: Bytes::copy_from_slice(stable_id)
            .try_into()
            .expect("valid stable ID"),
    }
}

fn owner(value: &str) -> OwnerId {
    OwnerId::new(value).expect("owner")
}

fn leaf_for(key: SessionKey) -> ReplicationOp {
    ReplicationOp::DeleteFenced {
        key,
        owner: owner("structure-owner"),
        fence: FenceToken::new(1),
    }
}

fn nested_at_depth(depth: usize, leaf: ReplicationOp) -> ReplicationOp {
    assert!(depth > 0, "the root operation has depth one");
    let mut op = leaf;
    for _ in 1..depth {
        op = ReplicationOp::Batch { ops: vec![op] };
    }
    op
}

fn mixed_tree_with_nodes(node_count: usize) -> ReplicationOp {
    assert!(
        node_count >= 3,
        "mixed trees contain a root, batch, and leaf"
    );
    let mut ops = Vec::with_capacity(node_count - 1);
    ops.push(ReplicationOp::Batch { ops: Vec::new() });
    for index in 0..(node_count - 2) {
        ops.push(leaf_for(key(format!("node-{index}").as_bytes())));
    }
    ReplicationOp::Batch { ops }
}

fn entry(sequence: u64, tx_id: &str, op: ReplicationOp) -> ReplicationEntry {
    ReplicationEntry {
        sequence,
        tx_id: tx_id.try_into().expect("valid transaction ID"),
        op,
        timestamp: timestamp(),
    }
}

fn operation_shape(root: &ReplicationOp) -> (usize, usize) {
    let mut pending = vec![(root, 1_usize)];
    let mut nodes = 0;
    let mut max_depth = 0;
    while let Some((op, depth)) = pending.pop() {
        nodes += 1;
        max_depth = max_depth.max(depth);
        if let ReplicationOp::Batch { ops } = op {
            pending.extend(ops.iter().map(|child| (child, depth + 1)));
        }
    }
    (nodes, max_depth)
}

fn discard_op_iteratively(root: ReplicationOp) {
    let mut pending = vec![vec![root].into_iter()];
    while let Some(current) = pending.last_mut() {
        match current.next() {
            Some(ReplicationOp::Batch { ops }) => pending.push(ops.into_iter()),
            Some(_) => {}
            None => {
                pending.pop();
            }
        }
    }
}

fn discard_entry_iteratively(entry: ReplicationEntry) {
    let ReplicationEntry { op, .. } = entry;
    discard_op_iteratively(op);
}

fn discard_entries_iteratively(entries: Vec<ReplicationEntry>) {
    for entry in entries {
        discard_entry_iteratively(entry);
    }
}

fn assert_limit_error(error: StoreError) {
    assert_eq!(error, StoreError::ReplicationOperationLimitExceeded);
    assert_eq!(error.to_string(), "replication operation limit exceeded");
    assert_eq!(format!("{error:?}"), "ReplicationOperationLimitExceeded");
}

#[test]
fn public_limits_count_the_root_every_batch_and_every_leaf() {
    assert_eq!(MAX_REPLICATION_OPERATION_DEPTH, 16);
    assert_eq!(MAX_REPLICATION_OPERATIONS_PER_ENTRY, 256);

    let root_leaf = leaf_for(key(b"root-leaf"));
    assert_eq!(operation_shape(&root_leaf), (1, 1));
    root_leaf
        .validate_structure()
        .expect("a root leaf is one valid operation");
    discard_op_iteratively(root_leaf);

    let root_batch = ReplicationOp::Batch { ops: Vec::new() };
    assert_eq!(operation_shape(&root_batch), (1, 1));
    root_batch
        .validate_structure()
        .expect("an empty root batch is one valid operation");
    discard_op_iteratively(root_batch);

    let mixed = mixed_tree_with_nodes(3);
    assert_eq!(operation_shape(&mixed), (3, 2));
    mixed
        .validate_structure()
        .expect("the root batch, nested batch, and leaf each count once");
    discard_op_iteratively(mixed);
}

#[test]
fn exact_depth_limit_is_accepted_and_next_depth_is_rejected() {
    let accepted = entry(
        1,
        "depth-at-limit",
        nested_at_depth(
            MAX_REPLICATION_OPERATION_DEPTH,
            leaf_for(key(b"depth-at-limit")),
        ),
    )
    .into_validated()
    .expect("the exact public depth limit must be accepted");
    assert_eq!(
        operation_shape(&accepted.op),
        (
            MAX_REPLICATION_OPERATION_DEPTH,
            MAX_REPLICATION_OPERATION_DEPTH
        )
    );
    discard_entry_iteratively(accepted);

    let error = entry(
        1,
        "depth-over-limit",
        nested_at_depth(
            MAX_REPLICATION_OPERATION_DEPTH + 1,
            leaf_for(key(b"depth-over-limit")),
        ),
    )
    .into_validated()
    .expect_err("one node beyond the depth limit must be rejected");
    assert_limit_error(error);
}

#[test]
fn exact_node_limit_is_accepted_and_next_node_is_rejected() {
    let accepted = entry(
        1,
        "nodes-at-limit",
        mixed_tree_with_nodes(MAX_REPLICATION_OPERATIONS_PER_ENTRY),
    )
    .into_validated()
    .expect("the exact public operation-count limit must be accepted");
    assert_eq!(
        operation_shape(&accepted.op),
        (MAX_REPLICATION_OPERATIONS_PER_ENTRY, 2)
    );
    discard_entry_iteratively(accepted);

    let error = entry(
        1,
        "nodes-over-limit",
        mixed_tree_with_nodes(MAX_REPLICATION_OPERATIONS_PER_ENTRY + 1),
    )
    .into_validated()
    .expect_err("one node beyond the operation-count limit must be rejected");
    assert_limit_error(error);
}

#[test]
fn limit_error_is_fieldless_serialized_and_redaction_safe() {
    const TX_CANARY: &str = "TX_CANARY_47f7d63d";
    const OWNER_CANARY: &str = "OWNER_CANARY_6d6556b4";
    const KEY_CANARY: &[u8] = b"KEY_CANARY_a10bf2ee";

    let error = entry(
        1,
        TX_CANARY,
        nested_at_depth(
            MAX_REPLICATION_OPERATION_DEPTH + 1,
            ReplicationOp::DeleteFenced {
                key: key(KEY_CANARY),
                owner: owner(OWNER_CANARY),
                fence: FenceToken::new(1),
            },
        ),
    )
    .into_validated()
    .expect_err("the canary-bearing tree must exceed the depth limit");

    let display = error.to_string();
    let debug = format!("{error:?}");
    let serialized = serde_json::to_string(&error).expect("serialize fieldless error");
    assert_eq!(display, "replication operation limit exceeded");
    assert_eq!(debug, "ReplicationOperationLimitExceeded");
    assert_eq!(serialized, r#""ReplicationOperationLimitExceeded""#);

    let combined = format!("{display}\n{debug}\n{serialized}");
    for canary in [TX_CANARY, OWNER_CANARY, "KEY_CANARY_a10bf2ee"] {
        assert!(!combined.contains(canary), "error exposed canary {canary}");
    }

    let decoded: StoreError = serde_json::from_str(&serialized).expect("deserialize error");
    assert_eq!(decoded, StoreError::ReplicationOperationLimitExceeded);
}

fn assert_owned_rejection(result: Result<Vec<ReplicationEntry>, StoreError>) {
    match result {
        Err(error) => assert_eq!(error, StoreError::InvalidReplicationSequence),
        Ok(entries) => {
            discard_entries_iteratively(entries);
            panic!("invalid shallow first entry was unexpectedly accepted");
        }
    }
}

#[test]
fn owned_prefix_and_page_drain_unvisited_deep_entries_on_a_small_stack() {
    thread::Builder::new()
        .name("replication-owned-drain".to_owned())
        .stack_size(SMALL_STACK_BYTES)
        .spawn(|| {
            let prefix = vec![
                entry(0, "invalid-prefix-first", leaf_for(key(b"prefix-first"))),
                entry(
                    2,
                    "deep-prefix-later",
                    nested_at_depth(DEEP_REJECTION_DEPTH, leaf_for(key(b"deep-prefix-later"))),
                ),
            ];
            assert_owned_rejection(validate_replication_prefix_owned(prefix));

            let page = vec![
                entry(0, "invalid-page-first", leaf_for(key(b"page-first"))),
                entry(
                    1,
                    "deep-page-later",
                    nested_at_depth(DEEP_REJECTION_DEPTH, leaf_for(key(b"deep-page-later"))),
                ),
            ];
            assert_owned_rejection(validate_replication_page_owned(page));
        })
        .expect("spawn small-stack validation thread")
        .join()
        .expect("small-stack validation thread completed");
}

fn backend(kind: BackendKind, clock: Arc<FixedClock>) -> Arc<dyn SessionStoreBackend> {
    match kind {
        BackendKind::Fake => Arc::new(FakeSessionBackend::new().with_clock(clock)),
        BackendKind::Sqlite => Arc::new(
            SqliteSessionBackend::in_memory()
                .expect("in-memory SQLite backend")
                .with_clock(clock),
        ),
    }
}

fn replicated_record(key: SessionKey) -> StoredSessionRecord {
    StoredSessionRecord {
        key,
        generation: Generation::new(1),
        owner: owner("seed-owner"),
        fence: FenceToken::new(1),
        state_class: StateClass::AuthoritativeSession,
        state_type: StateType::from_static("structure-bounds-record"),
        expires_at: None,
        payload: EncryptedSessionPayload::new(Bytes::from_static(b"seed-payload")),
    }
}

fn seed_prefix(now: Timestamp, key: &SessionKey) -> Vec<ReplicationEntry> {
    let ttl = Duration::from_secs(600);
    let expires_at = checked_session_deadline(now, ttl).expect("seed deadline");
    vec![
        ReplicationEntry {
            sequence: 1,
            tx_id: "seed-lease".try_into().expect("valid transaction ID"),
            op: ReplicationOp::AcquireLease {
                key: key.clone(),
                owner: owner("seed-owner"),
                fence: FenceToken::new(1),
                credential_id: 1,
                ttl,
                expires_at,
            },
            timestamp: now,
        },
        ReplicationEntry {
            sequence: 2,
            tx_id: "seed-record".try_into().expect("valid transaction ID"),
            op: ReplicationOp::CompareAndSet {
                key: key.clone(),
                expected_generation: None,
                credential_id: 1,
                guard_expires_at: expires_at,
                new_record: replicated_record(key.clone()),
            },
            timestamp: now,
        },
    ]
}

async fn replication_log(backend: &dyn SessionStoreBackend) -> Vec<ReplicationEntry> {
    backend
        .get_replication_log(1, usize::MAX)
        .await
        .expect("replication log")
}

async fn assert_backend_rejects_structure_before_state_change(kind: BackendKind) {
    let now = timestamp();
    let backend = backend(kind, Arc::new(FixedClock(now)));
    let seed_key = key(b"preserved-record");
    let original = seed_prefix(now, &seed_key);
    backend
        .rebuild_replication_state(original.clone())
        .await
        .expect("seed original state");

    let before_record = backend.get(&seed_key).await.expect("seed record");
    let before_log = replication_log(backend.as_ref()).await;
    let before_head = backend.max_replication_sequence().await.expect("seed head");
    let before_lease_info = backend.next_lease_info().await.expect("seed lease info");
    let mut watch = backend.watch(3).await.expect("watch before rejection");

    let replicate_error = backend
        .replicate_entry(entry(
            3,
            "over-depth-replicate",
            nested_at_depth(
                MAX_REPLICATION_OPERATION_DEPTH + 1,
                leaf_for(seed_key.clone()),
            ),
        ))
        .await
        .expect_err("over-depth replicate must fail");
    assert_limit_error(replicate_error);
    assert_eq!(backend.get(&seed_key).await.expect("record"), before_record);
    assert_eq!(replication_log(backend.as_ref()).await, before_log);
    assert_eq!(
        backend.max_replication_sequence().await.expect("head"),
        before_head
    );
    assert_eq!(
        backend.next_lease_info().await.expect("lease info"),
        before_lease_info
    );
    assert!(
        watch.next().now_or_never().is_none(),
        "{kind:?} rejected replicate notified a watcher"
    );

    let malformed_replacement = vec![
        entry(1, "replacement-would-delete", leaf_for(seed_key.clone())),
        entry(
            2,
            "over-depth-rebuild",
            nested_at_depth(
                MAX_REPLICATION_OPERATION_DEPTH + 1,
                leaf_for(seed_key.clone()),
            ),
        ),
    ];
    let rebuild_error = backend
        .rebuild_replication_state(malformed_replacement)
        .await
        .expect_err("entire over-depth replacement must fail before rebuilding");
    assert_limit_error(rebuild_error);
    assert_eq!(backend.get(&seed_key).await.expect("record"), before_record);
    assert_eq!(replication_log(backend.as_ref()).await, before_log);
    assert_eq!(
        backend.max_replication_sequence().await.expect("head"),
        before_head
    );
    assert_eq!(
        backend.next_lease_info().await.expect("lease info"),
        before_lease_info
    );
    assert!(
        watch.next().now_or_never().is_none(),
        "{kind:?} rejected rebuild notified a watcher"
    );

    discard_entries_iteratively(original);
}

#[tokio::test]
async fn fake_rejects_over_limit_replicate_and_rebuild_atomically() {
    assert_backend_rejects_structure_before_state_change(BackendKind::Fake).await;
}

#[tokio::test]
async fn sqlite_rejects_over_limit_replicate_and_rebuild_atomically() {
    assert_backend_rejects_structure_before_state_change(BackendKind::Sqlite).await;
}
