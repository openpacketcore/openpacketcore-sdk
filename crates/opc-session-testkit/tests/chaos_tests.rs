use opc_session_store::{
    BackendCapabilities, CompareAndSet, CompareAndSetResult, FakeSessionBackend,
    FencedSessionReplica, Generation, OwnerId, QuorumReplicaDescriptor, QuorumReplicaMember,
    QuorumSessionStore, QuorumTopologyConfig, ReplicaBackingIdentity, ReplicaEndpoint,
    ReplicaFailureDomain, ReplicaId, ReplicaTlsIdentity, SessionBackend, SessionKey,
    SessionLeaseManager, SessionOp, SessionOpResult, StateClass, StateType, StoreError,
    StoredSessionRecord, ValidatedQuorumTopology,
};
use opc_session_testkit::ChaosTestkit;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

fn validated_quorum(replicas: Vec<FencedSessionReplica>) -> QuorumSessionStore {
    let members = replicas
        .into_iter()
        .map(|replica| {
            let index = replica.id;
            QuorumReplicaMember::new(
                QuorumReplicaDescriptor::new(
                    ReplicaId::new(format!("direct-chaos-replica-{index}"))
                        .expect("test replica ID"),
                    ReplicaEndpoint::new(format!("direct-chaos-replica-{index}.invalid"), 7443)
                        .expect("test endpoint"),
                    ReplicaTlsIdentity::new(format!("spiffe://test/direct-chaos/replica/{index}"))
                        .expect("test TLS identity"),
                    ReplicaFailureDomain::new(format!("direct-chaos-failure-domain-{index}"))
                        .expect("test failure domain"),
                    ReplicaBackingIdentity::new(format!("direct-chaos-backing-{index}"))
                        .expect("test backing identity"),
                ),
                replica,
            )
        })
        .collect();
    let topology = ValidatedQuorumTopology::try_from(QuorumTopologyConfig::new(
        ReplicaId::new("direct-chaos-replica-0").expect("test local ID"),
        members,
    ))
    .expect("valid direct chaos topology");
    QuorumSessionStore::from_validated_topology(topology)
}

fn test_session_key() -> SessionKey {
    SessionKey {
        tenant: opc_types::TenantId::new("test-tenant").unwrap(),
        nf_kind: opc_types::NetworkFunctionKind::new("amf").unwrap(),
        key_type: opc_session_store::SessionKeyType::SubscriberContext,
        stable_id: bytes::Bytes::copy_from_slice(&[0xAA; 16]),
    }
}

fn make_record(
    key: &SessionKey,
    generation: u64,
    lease: &opc_session_store::LeaseGuard,
) -> StoredSessionRecord {
    make_record_with_payload(key, generation, lease, b"session data")
}

fn make_record_with_payload(
    key: &SessionKey,
    generation: u64,
    lease: &opc_session_store::LeaseGuard,
    payload: &[u8],
) -> StoredSessionRecord {
    StoredSessionRecord {
        key: key.clone(),
        generation: Generation::new(generation),
        owner: lease.owner().clone(),
        fence: lease.fence(),
        state_class: StateClass::AuthoritativeSession,
        state_type: StateType::from_str("amf-state").unwrap(),
        expires_at: None,
        payload: opc_session_store::EncryptedSessionPayload::new_zeroizing(
            zeroize::Zeroizing::new(payload.to_vec()),
        ),
    }
}

#[tokio::test]
async fn test_split_brain_partition_and_healing() {
    let testkit = ChaosTestkit::new(3);

    // Coordinator A reaches Node 0 and Node 1 (Majority)
    let coord_a = testkit
        .build_coordinator(0, &[0, 1])
        .expect("valid coordinator A topology");
    // Coordinator B reaches Node 2 (Minority)
    let coord_b = testkit
        .build_coordinator(2, &[2])
        .expect("valid coordinator B topology");

    let key = test_session_key();
    let owner_a = OwnerId::from_str("owner-a").unwrap();
    let owner_b = OwnerId::from_str("owner-b").unwrap();

    // Coordinator A should be able to acquire lease
    let lease_a = coord_a
        .acquire(&key, owner_a, Duration::from_secs(10))
        .await
        .unwrap();

    // Coordinator B should fail because it cannot reach a quorum
    let err_b = coord_b
        .acquire(&key, owner_b, Duration::from_secs(10))
        .await
        .unwrap_err();
    assert!(err_b.to_string().contains("quorum not reached"));

    // Coordinator A writes successfully
    let record_a = make_record(&key, 1, &lease_a);
    let op = CompareAndSet {
        key: key.clone(),
        lease: lease_a.clone(),
        expected_generation: None,
        new_record: record_a.clone(),
    };
    let cas_res = coord_a.compare_and_set(op).await.unwrap();
    assert_eq!(cas_res, CompareAndSetResult::Success);

    // Heal partition: Coordinator B can now reach all nodes
    let coord_healed = testkit
        .build_coordinator(0, &[0, 1, 2])
        .expect("valid healed topology");
    let loaded = coord_healed.get(&key).await.unwrap().unwrap();
    assert_eq!(loaded.generation.get(), 1);
}

#[tokio::test]
async fn test_stale_leader_and_multi_writer_rejection() {
    let testkit = ChaosTestkit::new(3);
    let coord = testkit
        .build_coordinator(0, &[0, 1, 2])
        .expect("valid chaos topology");

    let key = test_session_key();
    let owner_1 = OwnerId::from_str("owner-1").unwrap();
    let owner_2 = OwnerId::from_str("owner-2").unwrap();

    // Client 1 acquires lease
    let lease_1 = coord
        .acquire(&key, owner_1, Duration::from_secs(10))
        .await
        .unwrap();

    // Advance clocks by 11 seconds to expire Client 1's lease so Client 2 can acquire it
    for i in 0..3 {
        testkit.set_clock_skew(i, Duration::from_secs(11), false);
    }

    // Client 2 acquires lease (monotonically higher fence)
    let lease_2 = coord
        .acquire(&key, owner_2, Duration::from_secs(10))
        .await
        .unwrap();
    assert!(lease_2.fence().get() > lease_1.fence().get());

    // Client 1 (stale leader) tries to write: should be rejected
    let record_1 = make_record(&key, 1, &lease_1);
    let op = CompareAndSet {
        key: key.clone(),
        lease: lease_1.clone(),
        expected_generation: None,
        new_record: record_1,
    };
    let err = coord.compare_and_set(op).await.unwrap_err();
    // Replicas reject the stale fence token
    assert!(err.to_string().contains("StaleFence") || err.to_string().contains("fence"));
}

#[tokio::test]
async fn test_clock_skew_ttl_behavior() {
    let testkit = ChaosTestkit::new(3);
    let coord = testkit
        .build_coordinator(0, &[0, 1, 2])
        .expect("valid chaos topology");

    let key = test_session_key();
    let owner = OwnerId::from_str("owner").unwrap();

    // Acquire lease
    let lease = coord
        .acquire(&key, owner, Duration::from_secs(10))
        .await
        .unwrap();

    // Skew clock of Node 0 forward by 20 seconds (simulating local expiry)
    testkit.set_clock_skew(0, Duration::from_secs(20), false);

    // A write should still succeed because Node 1 and Node 2 are not skewed, meaning
    // a quorum (2 out of 3) still considers the lease valid.
    let record = make_record(&key, 1, &lease);
    let op = CompareAndSet {
        key: key.clone(),
        lease: lease.clone(),
        expected_generation: None,
        new_record: record,
    };
    let cas_res = coord.compare_and_set(op).await.unwrap();
    assert_eq!(cas_res, CompareAndSetResult::Success);

    // Now skew Node 1 forward by 20 seconds as well (meaning majority of nodes agree lease is expired)
    testkit.set_clock_skew(1, Duration::from_secs(20), false);

    // Write should now fail because quorum considers lease expired
    let record_2 = make_record(&key, 2, &lease);
    let op_2 = CompareAndSet {
        key: key.clone(),
        lease: lease.clone(),
        expected_generation: Some(Generation::new(1)),
        new_record: record_2,
    };
    let err = coord.compare_and_set(op_2).await.unwrap_err();
    assert!(
        matches!(err, StoreError::StaleFence | StoreError::LeaseExpired),
        "expected lease authority rejection, got {err:?}"
    );
}

#[tokio::test]
async fn test_restart_rejoin_monotonicity() {
    let testkit = ChaosTestkit::new(3);
    let coord = testkit
        .build_coordinator(0, &[0, 1, 2])
        .expect("valid chaos topology");

    let key = test_session_key();
    let owner = OwnerId::from_str("owner").unwrap();

    let lease = coord
        .acquire(&key, owner, Duration::from_secs(10))
        .await
        .unwrap();

    // Node 1 goes offline (simulating crash)
    testkit.set_online(1, false).await;

    // Renew lease (should succeed on majority: Node 0 and Node 2)
    let renewed_lease = coord.renew(&lease, Duration::from_secs(10)).await.unwrap();
    assert_eq!(renewed_lease.fence(), lease.fence());

    // Node 1 restarts (comes online)
    testkit.set_online(1, true).await;

    // Client performs CAS write
    let record = make_record(&key, 1, &renewed_lease);
    let op = CompareAndSet {
        key: key.clone(),
        lease: renewed_lease,
        expected_generation: None,
        new_record: record,
    };
    let cas_res = coord.compare_and_set(op).await.unwrap();
    assert_eq!(cas_res, CompareAndSetResult::Success);
}

#[tokio::test]
async fn test_replication_lag() {
    let testkit = ChaosTestkit::new(3);
    let coord = testkit
        .build_coordinator(0, &[0, 1, 2])
        .expect("valid chaos topology");

    // Set 50ms lag on Node 0 and Node 1
    testkit.set_lag(0, Some(Duration::from_millis(50))).await;
    testkit.set_lag(1, Some(Duration::from_millis(50))).await;

    let key = test_session_key();
    let owner = OwnerId::from_str("owner").unwrap();

    let start = std::time::Instant::now();
    let _lease = coord
        .acquire(&key, owner, Duration::from_secs(10))
        .await
        .unwrap();
    let duration = start.elapsed();

    // Should take at least 50ms due to simulated replication lag
    assert!(duration >= Duration::from_millis(50));
}

#[tokio::test]
async fn test_divergent_read_fails_closed_without_record_quorum() {
    let mut caps = BackendCapabilities::all_enabled();
    caps.ordered_replication_log = false;
    caps.watch = false;
    let replicas: Vec<FencedSessionReplica> = (0..3)
        .map(|id| {
            FencedSessionReplica::new(id, Arc::new(FakeSessionBackend::with_capabilities(caps)))
        })
        .collect();
    let key = test_session_key();

    for (replica_id, generation) in [(0, 1), (1, 2), (2, 3)] {
        let owner = OwnerId::from_str(&format!("owner-{replica_id}")).unwrap();
        let lease = replicas[replica_id]
            .inner
            .acquire(&key, owner, Duration::from_secs(10))
            .await
            .unwrap();
        let record = make_record(&key, generation, &lease);
        let op = CompareAndSet {
            key: key.clone(),
            lease,
            expected_generation: None,
            new_record: record,
        };

        assert_eq!(
            replicas[replica_id]
                .inner
                .compare_and_set(op)
                .await
                .unwrap(),
            CompareAndSetResult::Success
        );
    }

    let coord = validated_quorum(replicas);
    let err = coord.get(&key).await.unwrap_err();

    assert!(matches!(
        err,
        StoreError::BackendUnavailable(reason)
            if reason.contains("no quorum consensus for session record")
    ));
}

#[tokio::test]
async fn test_advertised_capabilities() {
    let testkit = ChaosTestkit::new(3);
    let coord = testkit
        .build_coordinator(0, &[0, 1, 2])
        .expect("valid chaos topology");

    let caps = coord.capabilities().await;
    assert!(caps.atomic_compare_and_set);
    assert!(caps.monotonic_fencing_token);
    assert!(caps.per_key_ttl);
    assert!(caps.server_side_lease_expiry);
    assert!(caps.ordered_replication_log);
    assert!(caps.batch_write);
    assert!(caps.watch);
}

#[tokio::test]
async fn test_capabilities_intersect_wrapped_replica_capabilities() {
    let mut limited_caps = BackendCapabilities::all_enabled();
    limited_caps.per_key_ttl = false;
    limited_caps.batch_write = false;
    limited_caps.max_value_bytes = 128;

    let replicas = vec![
        FencedSessionReplica::new(0, Arc::new(FakeSessionBackend::new())),
        FencedSessionReplica::new(
            1,
            Arc::new(FakeSessionBackend::with_capabilities(limited_caps)),
        ),
        FencedSessionReplica::new(2, Arc::new(FakeSessionBackend::new())),
    ];
    let coord = validated_quorum(replicas);

    let caps = coord.capabilities().await;

    assert!(caps.atomic_compare_and_set);
    assert!(caps.monotonic_fencing_token);
    assert!(!caps.per_key_ttl);
    assert!(caps.server_side_lease_expiry);
    assert!(caps.ordered_replication_log);
    assert!(!caps.batch_write);
    assert!(caps.watch);
    assert_eq!(caps.max_value_bytes, 128);
}

#[tokio::test]
async fn test_duplicate_replication_entry_idempotency() {
    let testkit = ChaosTestkit::new(3);
    let coord = testkit
        .build_coordinator(0, &[0, 1, 2])
        .expect("valid chaos topology");

    let key = test_session_key();
    let owner = OwnerId::from_str("dup-owner").unwrap();
    let lease = coord
        .acquire(&key, owner, Duration::from_secs(10))
        .await
        .unwrap();

    let max_seq = testkit.replicas[0]
        .inner
        .max_replication_sequence()
        .await
        .unwrap();
    let next_seq = max_seq + 1;

    // Replicate an entry twice on Node 0 directly
    let record = make_record(&key, 1, &lease);
    let op = opc_session_store::ReplicationOp::CompareAndSet {
        key: key.clone(),
        expected_generation: None,
        credential_id: 1,
        guard_expires_at: lease.expires_at(),
        new_record: record,
    };
    let entry = opc_session_store::ReplicationEntry {
        sequence: next_seq,
        tx_id: "tx-unique-123".into(),
        op,
        timestamp: opc_types::Timestamp::now_utc(),
    };

    // First call: succeeds
    testkit.replicas[0]
        .inner
        .replicate_entry(entry.clone())
        .await
        .unwrap();

    // Second call (duplicate delivery): succeeds idempotently
    testkit.replicas[0]
        .inner
        .replicate_entry(entry)
        .await
        .unwrap();
}

#[tokio::test]
async fn test_partial_write_recovery_and_catch_up() {
    let testkit = ChaosTestkit::new(3);

    let key = test_session_key();
    let owner = OwnerId::from_str("partial-owner").unwrap();

    let coord_majority = testkit
        .build_coordinator(0, &[0, 1, 2])
        .expect("valid majority topology");

    // Acquire lease on majority coordinator (replicates AcquireLease to all 3)
    let lease = coord_majority
        .acquire(&key, owner.clone(), Duration::from_secs(10))
        .await
        .unwrap();

    // Replicate a CompareAndSet (sequence 2) directly to Node 0 only. This is
    // an uncommitted partial write and must not become the future source of
    // truth just because it has the highest visible sequence.
    let record = make_record_with_payload(&key, 1, &lease, b"uncommitted partial write");
    let op = opc_session_store::ReplicationOp::CompareAndSet {
        key: key.clone(),
        expected_generation: None,
        credential_id: 1,
        guard_expires_at: lease.expires_at(),
        new_record: record,
    };
    let entry = opc_session_store::ReplicationEntry {
        sequence: 2,
        tx_id: "partial-tx-123".into(),
        op,
        timestamp: opc_types::Timestamp::now_utc(),
    };
    testkit.replicas[0]
        .inner
        .replicate_entry(entry)
        .await
        .unwrap();

    // Node 0 should have the record
    let node0_fetched = testkit.replicas[0].inner.get(&key).await.unwrap().unwrap();
    assert_eq!(node0_fetched.generation.get(), 1);

    // Replicas 1 and 2 do NOT have it yet (they are at sequence 1)
    assert!(testkit.replicas[1].inner.get(&key).await.unwrap().is_none());

    // Write a clean record through the quorum coordinator. The coordinator must
    // repair Node 0 back to the committed prefix, discard the uncommitted tail,
    // and then commit this clean entry at sequence 2.
    let record2 = make_record_with_payload(&key, 1, &lease, b"committed clean write");
    let op2 = CompareAndSet {
        key: key.clone(),
        lease,
        expected_generation: None,
        new_record: record2.clone(),
    };
    coord_majority.compare_and_set(op2).await.unwrap();

    // Verify all replicas are caught up and have the committed clean entry, not
    // the uncommitted partial write from Node 0.
    let fetched = coord_majority.get(&key).await.unwrap().unwrap();
    assert_eq!(fetched, record2);

    let node1_fetched = testkit.replicas[1].inner.get(&key).await.unwrap().unwrap();
    assert_eq!(node1_fetched, record2);
    let node0_fetched = testkit.replicas[0].inner.get(&key).await.unwrap().unwrap();
    assert_eq!(node0_fetched, record2);
}

#[tokio::test]
async fn test_replicated_batch_does_not_reapply_writes_for_results() {
    let testkit = ChaosTestkit::new(3);
    let coord = testkit
        .build_coordinator(0, &[0, 1, 2])
        .expect("valid chaos topology");

    let key = test_session_key();
    let owner = OwnerId::from_str("batch-owner").unwrap();
    let lease = coord
        .acquire(&key, owner, Duration::from_secs(10))
        .await
        .unwrap();

    let record = make_record(&key, 1, &lease);
    let cas = CompareAndSet {
        key: key.clone(),
        lease,
        expected_generation: None,
        new_record: record.clone(),
    };

    let results = coord
        .batch(vec![
            SessionOp::Get { key: key.clone() },
            SessionOp::CompareAndSet(cas),
            SessionOp::Get { key: key.clone() },
        ])
        .await
        .unwrap();

    assert!(matches!(&results[0], SessionOpResult::Get(Ok(None))));
    assert!(matches!(
        &results[1],
        SessionOpResult::CompareAndSet(Ok(CompareAndSetResult::Success))
    ));
    assert!(matches!(
        &results[2],
        SessionOpResult::Get(Ok(Some(current))) if current == &record
    ));
    assert_eq!(coord.get(&key).await.unwrap(), Some(record));
}

#[tokio::test]
async fn test_replica_restart_rejoin_catch_up_sqlite() {
    // Create 3 SQLite in-memory databases as replicas
    let mut replicas = Vec::new();
    for i in 0..3 {
        let raw_backend = opc_session_store::SqliteSessionBackend::in_memory().unwrap();
        replicas.push(FencedSessionReplica::new(i, Arc::new(raw_backend)));
    }

    // Coord reaches Node 0, Node 1, Node 2
    let coord = validated_quorum(replicas.clone());

    let key = test_session_key();
    let owner = OwnerId::from_str("sqlite-owner").unwrap();

    // 1. Acquire lease
    let lease = coord
        .acquire(&key, owner.clone(), Duration::from_secs(10))
        .await
        .unwrap();

    // 2. Perform write
    let record = make_record(&key, 1, &lease);
    let op = CompareAndSet {
        key: key.clone(),
        lease: lease.clone(),
        expected_generation: None,
        new_record: record.clone(),
    };
    coord.compare_and_set(op).await.unwrap();

    // 3. Mark Node 1 client offline (simulated partition)
    *replicas[1].client_online.lock().await = false;

    // 4. Perform second write (succeeds on Node 0 and Node 2 - majority)
    let mut record2 = make_record(&key, 2, &lease);
    record2.payload = opc_session_store::EncryptedSessionPayload::new_zeroizing(
        zeroize::Zeroizing::new(b"sqlite update".to_vec()),
    );
    let op2 = CompareAndSet {
        key: key.clone(),
        lease: lease.clone(),
        expected_generation: Some(Generation::new(1)),
        new_record: record2.clone(),
    };
    coord.compare_and_set(op2).await.unwrap();

    // 5. Node 1 comes back online
    *replicas[1].client_online.lock().await = true;

    // 6. Get record (should catch up Node 1 and return generation 2)
    let fetched = coord.get(&key).await.unwrap().unwrap();
    assert_eq!(fetched.generation.get(), 2);

    // 7. Verify Node 1 actually has the caught-up generation 2 record
    let node1_fetched = replicas[1].inner.get(&key).await.unwrap().unwrap();
    assert_eq!(node1_fetched.generation.get(), 2);
}

#[tokio::test]
async fn test_watch_change_stream_resume() {
    let testkit = ChaosTestkit::new(3);
    let coord = testkit
        .build_coordinator(0, &[0, 1, 2])
        .expect("valid chaos topology");

    let key = test_session_key();
    let owner = OwnerId::from_str("watch-owner").unwrap();

    let lease = coord
        .acquire(&key, owner.clone(), Duration::from_secs(10))
        .await
        .unwrap();

    // Write record
    let record1 = make_record(&key, 1, &lease);
    let op = CompareAndSet {
        key: key.clone(),
        lease: lease.clone(),
        expected_generation: None,
        new_record: record1,
    };
    coord.compare_and_set(op).await.unwrap();

    // Start watching from sequence 1
    use futures_util::StreamExt;
    let mut watch_stream = coord.watch(1).await.unwrap();

    // Write another record to generate more sequences
    let mut record2 = make_record(&key, 2, &lease);
    record2.payload = opc_session_store::EncryptedSessionPayload::new_zeroizing(
        zeroize::Zeroizing::new(b"new session data".to_vec()),
    );
    let op2 = CompareAndSet {
        key: key.clone(),
        lease: lease.clone(),
        expected_generation: Some(Generation::new(1)),
        new_record: record2,
    };
    coord.compare_and_set(op2).await.unwrap();

    // Read entries from watch stream
    let entry1 = watch_stream.next().await.unwrap().unwrap();
    let entry2 = watch_stream.next().await.unwrap().unwrap();

    assert!(entry1.sequence >= 1);
    assert!(entry2.sequence > entry1.sequence);

    // Stop watch stream, and resume watching from entry2's sequence + 1
    let mut resume_stream = coord.watch(entry2.sequence + 1).await.unwrap();

    // Write a third record
    let mut record3 = make_record(&key, 3, &lease);
    record3.payload = opc_session_store::EncryptedSessionPayload::new_zeroizing(
        zeroize::Zeroizing::new(b"even newer data".to_vec()),
    );
    let op3 = CompareAndSet {
        key: key.clone(),
        lease: lease.clone(),
        expected_generation: Some(Generation::new(2)),
        new_record: record3,
    };
    coord.compare_and_set(op3).await.unwrap();

    // The resume stream should receive the third entry immediately
    let entry3 = resume_stream.next().await.unwrap().unwrap();
    assert_eq!(entry3.sequence, entry2.sequence + 1);
}
