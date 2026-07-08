use opc_persist::{
    AuditKey, AuditOpType, AuditRecord, ClusterMembership, CommitRecord, CommitSource, ConfigStore,
    ConsensusClock, ConsensusConfigStore, InstallSnapshotRequest, Role, RollbackTarget,
    SqliteBackend, StoredConfig,
};
use opc_types::{ConfigVersion, SchemaDigest, Timestamp, TxId};
use std::sync::Arc;
use tempfile::TempDir;

const TEST_AUDIT_KEY_BYTES: [u8; 32] = [0xA5; 32];

fn test_audit_key() -> AuditKey {
    AuditKey::new(TEST_AUDIT_KEY_BYTES).unwrap()
}

fn make_commit_record(tx_id: TxId, version: u64) -> CommitRecord {
    CommitRecord {
        tx_id,
        parent_tx_id: None,
        version: ConfigVersion::new(version),
        committed_at: Timestamp::now_utc(),
        principal: "spiffe://test/trust-domain/tenant/test/ns/default/sa/svc/nf/test/instance/1"
            .to_string(),
        source: CommitSource::LocalOperator,
        schema_digest: SchemaDigest::from_bytes([0u8; 32]),
        plaintext_digest: vec![],
        encrypted_blob: b"encrypted payload".to_vec(),
        rollback_point: false,
        confirmed_deadline: None,
    }
}

fn make_audit_record(tx_id: TxId, sequence: u32, path: &str) -> AuditRecord {
    let mut record = AuditRecord {
        tx_id,
        sequence,
        yang_path: path.to_string(),
        op_type: AuditOpType::Create,
        previous_value: None,
        new_value: Some(r#""value""#.to_string()),
        redaction_applied: false,
        previous_hash: [0u8; 32],
        entry_hmac: [0u8; 32],
    };
    record.entry_hmac = record.calculate_hmac_with_audit_count(&test_audit_key(), "test", 1);
    record
}

async fn setup_consensus_group(temp_dir: &TempDir) -> Vec<Arc<ConsensusConfigStore>> {
    let mut backends = Vec::new();
    for i in 0..3 {
        let db_path = temp_dir.path().join(format!("consensus_{i}.db"));
        let backend = SqliteBackend::open_with_audit_key(&db_path, true, 0, test_audit_key())
            .await
            .expect("open backend");
        backends.push(Arc::new(backend));
    }

    let mut stores = Vec::new();
    for (i, backend) in backends.iter().enumerate() {
        let membership = ClusterMembership {
            cluster_id: "test-cluster".to_string(),
            node_id: i,
            voting_members: vec![0, 1, 2],
            non_voting_members: vec![],
            old_voting_members: None,
            removed_members: vec![],
            epoch: 1,
        };
        let clock = ConsensusClock {
            election_timeout_min: std::time::Duration::from_millis(150),
            election_timeout_max: std::time::Duration::from_millis(300),
            heartbeat_interval: std::time::Duration::from_millis(50),
            enable_timers: false,
        };
        let store = ConsensusConfigStore::new(i, backend.clone(), Some(membership), Some(clock))
            .await
            .expect("create consensus store");
        stores.push(Arc::new(store));
    }

    // Connect peers
    for i in 0..3 {
        for j in 0..3 {
            if i != j {
                stores[i].add_peer(j, stores[j].clone()).await;
            }
        }
    }

    stores
}

#[tokio::test]
async fn test_consensus_happy_path_commit_persists_on_majority_and_reads_after_restart() {
    let temp_dir = TempDir::new().unwrap();
    let group = setup_consensus_group(&temp_dir).await;

    // Campaign node 0 to leader
    group[0].campaign().await.unwrap();
    assert_eq!(group[0].get_role().await, Role::Leader);

    let tx_id = TxId::new();
    let record = make_commit_record(tx_id, 1);
    let audit = vec![make_audit_record(tx_id, 0, "/a")];

    // Write should succeed
    group[0].append_commit(record, audit).await.unwrap();

    // Latest should be returned from leader
    let follower_log_before_read = group[1].inner.consensus_get_last_log().await.unwrap();
    let loaded = group[0].load_latest().await.unwrap().unwrap();
    assert_eq!(loaded.record.tx_id, tx_id);
    let follower_log_after_read = group[1].inner.consensus_get_last_log().await.unwrap();
    assert_eq!(follower_log_after_read, follower_log_before_read);
    assert_eq!(follower_log_after_read.0, 2);

    // Verify audit chain verification passes
    loaded.verify_audit_chain(&test_audit_key()).unwrap();

    // Restart replicas 1 and 2
    let db_path_1 = temp_dir.path().join("consensus_1.db");
    let backend_1 = SqliteBackend::open_with_audit_key(&db_path_1, true, 0, test_audit_key())
        .await
        .unwrap();
    let clock = ConsensusClock {
        election_timeout_min: std::time::Duration::from_millis(150),
        election_timeout_max: std::time::Duration::from_millis(300),
        heartbeat_interval: std::time::Duration::from_millis(50),
        enable_timers: false,
    };
    let new_store_1 = Arc::new(
        ConsensusConfigStore::new(1, Arc::new(backend_1), None, Some(clock.clone()))
            .await
            .unwrap(),
    );

    let db_path_2 = temp_dir.path().join("consensus_2.db");
    let backend_2 = SqliteBackend::open_with_audit_key(&db_path_2, true, 0, test_audit_key())
        .await
        .unwrap();
    let new_store_2 = Arc::new(
        ConsensusConfigStore::new(2, Arc::new(backend_2), None, Some(clock))
            .await
            .unwrap(),
    );

    // Re-wire peers
    group[0].add_peer(1, new_store_1.clone()).await;
    group[0].add_peer(2, new_store_2.clone()).await;

    new_store_1.add_peer(0, group[0].clone()).await;
    new_store_1.add_peer(2, new_store_2.clone()).await;

    new_store_2.add_peer(0, group[0].clone()).await;
    new_store_2.add_peer(1, new_store_1.clone()).await;

    // Send a sync/heartbeat to inform followers of the leader
    group[0].sync().await.unwrap();

    // Verify read from follower works and gets redirect to leader
    let loaded_fol = new_store_1.load_latest().await.unwrap().unwrap();
    assert_eq!(loaded_fol.record.tx_id, tx_id);
}

#[tokio::test]
async fn test_consensus_stale_leader_write_rejected() {
    let temp_dir = TempDir::new().unwrap();
    let group = setup_consensus_group(&temp_dir).await;

    // Campaign node 0 to leader in term 1
    group[0].campaign().await.unwrap();
    assert_eq!(group[0].get_role().await, Role::Leader);

    // Campaign node 1 to leader in term 2 (deposing node 0)
    group[1].campaign().await.unwrap();
    assert_eq!(group[1].get_role().await, Role::Leader);

    // Now node 0 attempts a write with its stale leadership (term 1)
    let tx_id = TxId::new();
    let record = make_commit_record(tx_id, 1);
    let audit = vec![make_audit_record(tx_id, 0, "/a")];

    let err = group[0].append_commit(record, audit).await.unwrap_err();
    assert!(
        err.to_string().contains("stale leader")
            || err.to_string().contains("term/role changed")
            || err.to_string().contains("failed to become leader")
    );
}

#[tokio::test]
async fn test_consensus_partition_split_brain() {
    let temp_dir = TempDir::new().unwrap();
    let group = setup_consensus_group(&temp_dir).await;

    // Partition: node 2 is offline
    group[2].set_online(false).await;

    // Node 0 campaigns, should succeed (0 and 1 online -> majority)
    group[0].campaign().await.unwrap();
    assert_eq!(group[0].get_role().await, Role::Leader);

    let tx_id = TxId::new();
    let record = make_commit_record(tx_id, 1);
    let audit = vec![make_audit_record(tx_id, 0, "/a")];

    // Write should succeed
    group[0].append_commit(record, audit).await.unwrap();

    // Now partition worsens: node 1 goes offline, only node 0 is online
    group[1].set_online(false).await;

    let tx_id_2 = TxId::new();
    let record_2 = make_commit_record(tx_id_2, 2);
    let audit_2 = vec![make_audit_record(tx_id_2, 0, "/b")];

    // Write should fail
    let err_write = group[0].append_commit(record_2, audit_2).await.unwrap_err();
    assert!(err_write.to_string().contains("quorum not reached"));

    // Read should fail (quorum loss fails closed)
    let err_read = group[0].load_latest().await.unwrap_err();
    assert!(
        err_read.to_string().contains("lost leader quorum")
            || err_read.to_string().contains("quorum")
    );
}

#[tokio::test]
async fn test_consensus_partition_heal_catches_stale_replica_up() {
    let temp_dir = TempDir::new().unwrap();
    let group = setup_consensus_group(&temp_dir).await;

    // Partition: node 2 is offline
    group[2].set_online(false).await;

    group[0].campaign().await.unwrap();

    let tx_id = TxId::new();
    let record = make_commit_record(tx_id, 1);
    let audit = vec![make_audit_record(tx_id, 0, "/a")];
    group[0].append_commit(record, audit).await.unwrap();

    // Verify node 2 has applied index = 0 (doesn't have the entry)
    let applied_2 = group[2].inner.consensus_get_applied_index().await.unwrap();
    assert_eq!(applied_2, 0);

    // Heal partition: node 2 back online
    group[2].set_online(true).await;

    // Trigger sync/catch-up
    group[0].sync().await.unwrap();

    // Verify node 2 caught up to applied index = 2
    let applied_2_healed = group[2].inner.consensus_get_applied_index().await.unwrap();
    assert_eq!(applied_2_healed, 2);

    // Verify reading from node 2 now returns the entry
    let loaded = group[2].load_latest().await.unwrap().unwrap();
    assert_eq!(loaded.record.tx_id, tx_id);
}

#[tokio::test]
async fn test_consensus_stale_snapshot_install_does_not_regress_follower_state() {
    let temp_dir = TempDir::new().unwrap();
    let group = setup_consensus_group(&temp_dir).await;

    group[0].campaign().await.unwrap();

    let tx_1 = TxId::new();
    let record_1 = make_commit_record(tx_1, 1);
    let audit_1 = vec![make_audit_record(tx_1, 0, "/first")];
    group[0]
        .append_commit(record_1.clone(), audit_1.clone())
        .await
        .unwrap();

    let tx_2 = TxId::new();
    let record_2 = make_commit_record(tx_2, 2);
    group[0]
        .append_commit(record_2, vec![make_audit_record(tx_2, 0, "/second")])
        .await
        .unwrap();
    group[0].sync().await.unwrap();

    let applied_before = group[1].inner.consensus_get_applied_index().await.unwrap();
    assert!(applied_before > 1);
    let latest_before = group[1].inner.load_latest().await.unwrap().unwrap();
    assert_eq!(latest_before.record.tx_id, tx_2);

    let stale_index = applied_before - 1;
    let stale_term = group[0]
        .inner
        .consensus_get_log_term(stale_index)
        .await
        .unwrap()
        .unwrap_or(group[0].get_term().await);
    let stale_snapshot = StoredConfig {
        record: record_1,
        audit: audit_1,
    };
    let snapshot_bytes = serde_json::to_vec(&stale_snapshot).unwrap();

    let response = group[1]
        .handle_install_snapshot(InstallSnapshotRequest {
            term: group[0].get_term().await,
            leader_id: 0,
            last_included_index: stale_index,
            last_included_term: stale_term,
            data: snapshot_bytes,
        })
        .await
        .unwrap();

    assert!(response.success);
    assert_eq!(
        group[1].inner.consensus_get_applied_index().await.unwrap(),
        applied_before
    );
    let latest_after = group[1].inner.load_latest().await.unwrap().unwrap();
    assert_eq!(latest_after.record.tx_id, tx_2);
}

#[tokio::test]
async fn test_consensus_compaction_requires_applied_index_and_allows_future_writes() {
    let temp_dir = TempDir::new().unwrap();
    let group = setup_consensus_group(&temp_dir).await;

    group[0].campaign().await.unwrap();

    let tx_1 = TxId::new();
    let rec_1 = make_commit_record(tx_1, 1);
    group[0]
        .append_commit(rec_1, vec![make_audit_record(tx_1, 0, "/first")])
        .await
        .unwrap();

    let tx_2 = TxId::new();
    let rec_2 = make_commit_record(tx_2, 2);
    group[0]
        .append_commit(rec_2, vec![make_audit_record(tx_2, 0, "/second")])
        .await
        .unwrap();

    let applied = group[0].inner.consensus_get_applied_index().await.unwrap();
    assert!(applied > 1);

    let err = group[0].compact_logs(applied - 1).await.unwrap_err();
    assert!(err
        .to_string()
        .contains("snapshot index must match applied consensus state"));

    group[0].compact_logs(applied).await.unwrap();
    let snapshot = group[0]
        .inner
        .consensus_get_snapshot()
        .await
        .unwrap()
        .unwrap();
    assert_eq!(snapshot.0, applied);
    assert_eq!(
        group[0].inner.consensus_get_last_log().await.unwrap().0,
        applied
    );

    let tx_3 = TxId::new();
    let rec_3 = make_commit_record(tx_3, 3);
    group[0]
        .append_commit(rec_3, vec![make_audit_record(tx_3, 0, "/third")])
        .await
        .unwrap();

    let latest = group[0].load_latest().await.unwrap().unwrap();
    assert_eq!(latest.record.tx_id, tx_3);
}

#[tokio::test]
async fn test_consensus_membership_change_preserves_local_node_identity() {
    let temp_dir = TempDir::new().unwrap();
    let group = setup_consensus_group(&temp_dir).await;

    group[0].campaign().await.unwrap();
    group[0].add_node_as_non_voter(3).await.unwrap();
    group[0].sync().await.unwrap();

    let follower_membership = group[1]
        .inner
        .consensus_get_membership()
        .await
        .unwrap()
        .unwrap();
    assert_eq!(follower_membership.node_id, 1);
    assert!(follower_membership.non_voting_members.contains(&3));

    let db_path_1 = temp_dir.path().join("consensus_1.db");
    let backend_1 = SqliteBackend::open_with_audit_key(&db_path_1, true, 0, test_audit_key())
        .await
        .unwrap();
    let restarted = ConsensusConfigStore::new(1, Arc::new(backend_1), None, None).await;
    assert!(
        restarted.is_ok(),
        "restart should accept follower node_id after replicated membership change"
    );
}

#[tokio::test]
async fn test_consensus_crashed_replica_cannot_overwrite_newer_data() {
    let temp_dir = TempDir::new().unwrap();
    let group = setup_consensus_group(&temp_dir).await;

    // Node 0 campaigns and writes commit 1 (replicated to 0 and 1, term 1)
    group[2].set_online(false).await;
    group[0].campaign().await.unwrap();

    let tx_id_1 = TxId::new();
    let record_1 = make_commit_record(tx_id_1, 1);
    group[0]
        .append_commit(record_1, vec![make_audit_record(tx_id_1, 0, "/a")])
        .await
        .unwrap();

    // Node 2 is offline and has NO entries.
    // Bring Node 2 online, Node 2 campaigns (deposing Node 0) but it has stale log
    group[2].set_online(true).await;

    // Node 2 campaign should fail or be rejected because its log is not up-to-date
    let err_campaign = group[2].campaign().await.unwrap_err();
    assert!(
        err_campaign.to_string().contains("did not reach quorum")
            || err_campaign.to_string().contains("peer has newer term")
    );

    // Sync from actual leader node 0 should catch node 2 up
    group[0].campaign().await.unwrap(); // node 0 regains leadership
    group[0].sync().await.unwrap();

    let applied_2 = group[2].inner.consensus_get_applied_index().await.unwrap();
    assert_eq!(applied_2, 3);
}

#[tokio::test]
async fn test_consensus_commit_confirmed_pending_config_survives_failover() {
    let temp_dir = TempDir::new().unwrap();
    let group = setup_consensus_group(&temp_dir).await;

    group[0].campaign().await.unwrap();

    let tx_id = TxId::new();
    let mut record = make_commit_record(tx_id, 1);

    // Set a pending confirmed deadline
    let dt = time::OffsetDateTime::now_utc() + time::Duration::seconds(60);
    record.confirmed_deadline = Some(Timestamp::from(dt));

    let audit = vec![make_audit_record(tx_id, 0, "/a")];
    group[0].append_commit(record, audit).await.unwrap();

    // Crash leader (node 0)
    group[0].set_online(false).await;

    // Campaign node 1
    group[1].campaign().await.unwrap();
    assert_eq!(group[1].get_role().await, Role::Leader);

    // Sync to commit the NoOp entry and apply logs
    group[1].sync().await.unwrap();

    // Verify pending commit survived failover and is loaded by node 1
    let loaded = group[1].load_latest().await.unwrap().unwrap();
    assert_eq!(loaded.record.tx_id, tx_id);
    assert!(loaded.record.confirmed_deadline.is_some());
}

#[tokio::test]
async fn test_consensus_rollback_target_selection_rejects_uncommitted_state() {
    let temp_dir = TempDir::new().unwrap();
    let group = setup_consensus_group(&temp_dir).await;

    // Write a stable commit 1
    group[0].campaign().await.unwrap();
    let tx_1 = TxId::new();
    let rec_1 = make_commit_record(tx_1, 1);
    group[0]
        .append_commit(rec_1, vec![make_audit_record(tx_1, 0, "/x")])
        .await
        .unwrap();

    // Replicas 1 and 2 offline
    group[1].set_online(false).await;
    group[2].set_online(false).await;

    // Try writing commit 2, which should fail due to lack of quorum
    let tx_2 = TxId::new();
    let rec_2 = make_commit_record(tx_2, 2);
    let err_write = group[0]
        .append_commit(rec_2, vec![make_audit_record(tx_2, 0, "/y")])
        .await
        .unwrap_err();
    assert!(err_write.to_string().contains("consensus"));

    // Now restore replicas 1 and 2
    group[1].set_online(true).await;
    group[2].set_online(true).await;

    // Try reading rollback target or latest: should not see the uncommitted commit 2
    let latest = group[0].load_latest().await.unwrap().unwrap();
    assert_eq!(latest.record.tx_id, tx_1); // Still tx_1!
}

#[tokio::test]
async fn test_consensus_failed_no_quorum_write_is_not_resurrected() {
    let temp_dir = TempDir::new().unwrap();
    let group = setup_consensus_group(&temp_dir).await;

    group[0].campaign().await.unwrap();

    let tx_1 = TxId::new();
    let rec_1 = make_commit_record(tx_1, 1);
    group[0]
        .append_commit(rec_1, vec![make_audit_record(tx_1, 0, "/stable")])
        .await
        .unwrap();

    group[1].set_online(false).await;
    group[2].set_online(false).await;

    let failed_tx = TxId::new();
    let failed_record = make_commit_record(failed_tx, 2);
    let err = group[0]
        .append_commit(
            failed_record,
            vec![make_audit_record(failed_tx, 0, "/failed")],
        )
        .await
        .unwrap_err();
    assert!(err.to_string().contains("quorum not reached"));

    group[1].set_online(true).await;
    group[2].set_online(true).await;

    group[0].campaign().await.unwrap();
    group[0].sync().await.unwrap();

    let missing_failed = group[0]
        .inner
        .load_rollback(RollbackTarget::ByTxId(failed_tx))
        .await
        .unwrap_err();
    assert!(missing_failed
        .to_string()
        .contains("rollback target not found"));

    let tx_2 = TxId::new();
    let rec_2 = make_commit_record(tx_2, 2);
    group[0]
        .append_commit(rec_2, vec![make_audit_record(tx_2, 0, "/replacement")])
        .await
        .unwrap();

    let latest = group[0].load_latest().await.unwrap().unwrap();
    assert_eq!(latest.record.tx_id, tx_2);

    let still_missing_failed = group[0]
        .inner
        .load_rollback(RollbackTarget::ByTxId(failed_tx))
        .await
        .unwrap_err();
    assert!(still_missing_failed
        .to_string()
        .contains("rollback target not found"));
}

#[tokio::test]
async fn test_consensus_duplicate_replayed_log_entries_idempotent() {
    let temp_dir = TempDir::new().unwrap();
    let group = setup_consensus_group(&temp_dir).await;

    group[0].campaign().await.unwrap();

    let tx_id = TxId::new();
    let record = make_commit_record(tx_id, 1);
    let audit = vec![make_audit_record(tx_id, 0, "/a")];

    // Replay log insertion explicitly
    let entry = opc_persist::LogEntry {
        index: 1,
        term: 1,
        op: opc_persist::ConsensusOp::AppendCommit {
            record: record.clone(),
            audit: audit.clone(),
        },
    };

    // Append once
    group[0]
        .inner
        .consensus_append_logs(0, vec![entry.clone()])
        .await
        .unwrap();
    // Append duplicate
    group[0]
        .inner
        .consensus_append_logs(0, vec![entry.clone()])
        .await
        .unwrap();

    // Apply
    group[0].inner.consensus_apply_entries(1).await.unwrap();
    // Apply again (idempotent)
    group[0].inner.consensus_apply_entries(1).await.unwrap();

    let latest = group[0].inner.load_latest().await.unwrap().unwrap();
    assert_eq!(latest.record.tx_id, tx_id);
}

#[tokio::test]
async fn test_consensus_double_majority_quorum() {
    let temp_dir = TempDir::new().unwrap();
    let mut backends = Vec::new();
    for i in 0..4 {
        let db_path = temp_dir.path().join(format!("consensus_four_{i}.db"));
        let backend = SqliteBackend::open_with_audit_key(&db_path, true, 0, test_audit_key())
            .await
            .expect("open backend");
        backends.push(Arc::new(backend));
    }

    let mut group = Vec::new();
    for (i, backend) in backends.iter().enumerate() {
        let membership = ClusterMembership {
            cluster_id: "test-cluster".to_string(),
            node_id: i,
            voting_members: vec![0, 1, 2],
            non_voting_members: vec![3],
            old_voting_members: None,
            removed_members: vec![],
            epoch: 1,
        };
        let clock = ConsensusClock {
            election_timeout_min: std::time::Duration::from_millis(250),
            election_timeout_max: std::time::Duration::from_millis(500),
            heartbeat_interval: std::time::Duration::from_millis(50),
            enable_timers: true,
        };
        let store = ConsensusConfigStore::new(i, backend.clone(), Some(membership), Some(clock))
            .await
            .expect("create consensus store");
        group.push(Arc::new(store));
    }

    // Connect peers
    for i in 0..4 {
        for j in 0..4 {
            if i != j {
                group[i].add_peer(j, group[j].clone()).await;
            }
        }
    }

    // Campaign node 0 to leader
    group[0].campaign().await.unwrap();
    assert_eq!(group[0].get_role().await, Role::Leader);

    // Sync to ensure all nodes (including non-voter node 3) match indices
    let tx_id = TxId::new();
    let record = make_commit_record(tx_id, 1);
    let audit = vec![make_audit_record(tx_id, 0, "/init")];
    group[0].append_commit(record, audit).await.unwrap();
    group[0].sync().await.unwrap();

    // Verify node 3 is caught up
    let last_log = group[0].inner.consensus_get_last_log().await.unwrap().0;
    let node3_match = group[0]
        .state
        .lock()
        .await
        .match_index
        .get(&3)
        .cloned()
        .unwrap_or(0);
    assert_eq!(node3_match, last_log);

    // Partition node 2 and node 3 (offline)
    group[2].set_online(false).await;
    group[3].set_online(false).await;

    // Attempting to promote node 3 should fail because:
    // - Old configuration [0, 1, 2] needs 2/3 (online: 0, 1) -> met (committed joint config)
    // - New configuration [0, 1, 2, 3] needs 3/4 (online: 0, 1) -> NOT met (failed final config commit)
    let res = group[0].promote_node(3).await;
    assert!(res.is_err());
    let err_msg = res.unwrap_err().to_string();
    assert!(
        err_msg.contains("quorum") || err_msg.contains("consensus") || err_msg.contains("offline")
    );

    // Verify the database is reverted to C_old
    let joint_m = group[0]
        .inner
        .consensus_get_membership()
        .await
        .unwrap()
        .unwrap();
    assert_eq!(joint_m.old_voting_members, None);
    assert_eq!(joint_m.voting_members, vec![0, 1, 2]);

    // Heal node 3 partition (bring online)
    group[3].set_online(true).await;

    // Promote node 3 again, which should succeed now that node 3 is online
    group[0].promote_node(3).await.unwrap();

    // Sync node 3
    group[0].sync().await.unwrap();

    // Since node 3 is online and enable_timers: true, the background task
    // should automatically propose and commit the final configuration.
    let start = std::time::Instant::now();
    let mut finalized = false;
    while start.elapsed() < std::time::Duration::from_secs(3) {
        let current_m = group[0]
            .inner
            .consensus_get_membership()
            .await
            .unwrap()
            .unwrap();
        if current_m.old_voting_members.is_none() && current_m.epoch > 2 {
            finalized = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    assert!(
        finalized,
        "transition was not automatically finalized to old_voting_members = None"
    );
}

#[tokio::test]
async fn test_consensus_epoch_monotonicity_enforcement() {
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("epoch.db");
    let backend = SqliteBackend::open_with_audit_key(&db_path, true, 0, test_audit_key())
        .await
        .unwrap();

    let initial_membership = ClusterMembership {
        cluster_id: "test-cluster".to_string(),
        node_id: 1,
        voting_members: vec![1],
        non_voting_members: vec![],
        old_voting_members: None,
        removed_members: vec![],
        epoch: 5,
    };
    backend
        .consensus_set_membership(&initial_membership)
        .await
        .unwrap();

    let stale_membership = ClusterMembership {
        cluster_id: "test-cluster".to_string(),
        node_id: 1,
        voting_members: vec![1],
        non_voting_members: vec![],
        old_voting_members: None,
        removed_members: vec![],
        epoch: 5,
    };

    let entry = opc_persist::LogEntry {
        index: 1,
        term: 1,
        op: opc_persist::ConsensusOp::ChangeMembership {
            membership: stale_membership,
        },
    };

    backend.consensus_append_logs(0, vec![entry]).await.unwrap();

    let res = backend.consensus_apply_entries(1).await;
    assert!(res.is_err());
    assert!(res.unwrap_err().to_string().contains("stale epoch"));
}

#[tokio::test]
async fn test_consensus_apply_tolerates_missing_tx_id() {
    // A committed MarkConfirmed / CreateRollbackPoint whose target tx_id is not
    // present on this node (compacted away, or restored from an older snapshot)
    // must apply as a deterministic no-op. Returning an error here would abort
    // the apply transaction and freeze applied_index, wedging the node forever.
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("missing_tx.db");
    let backend = SqliteBackend::open_with_audit_key(&db_path, true, 0, test_audit_key())
        .await
        .unwrap();

    let entries = vec![
        opc_persist::LogEntry {
            index: 1,
            term: 1,
            op: opc_persist::ConsensusOp::MarkConfirmed { tx_id: TxId::new() },
        },
        opc_persist::LogEntry {
            index: 2,
            term: 1,
            op: opc_persist::ConsensusOp::CreateRollbackPoint {
                tx_id: TxId::new(),
                label: Some("orphan".to_string()),
            },
        },
    ];
    backend.consensus_append_logs(0, entries).await.unwrap();

    // Apply must succeed (previously returned rollback_not_found and wedged).
    backend.consensus_apply_entries(2).await.unwrap();

    // applied_index advanced past both entries: the state machine made progress.
    assert_eq!(backend.consensus_get_applied_index().await.unwrap(), 2);
}

#[tokio::test]
async fn test_consensus_leadership_transfer() {
    let temp_dir = TempDir::new().unwrap();
    let group = setup_consensus_group(&temp_dir).await;

    // Campaign node 0 to leader
    group[0].campaign().await.unwrap();
    assert_eq!(group[0].get_role().await, Role::Leader);

    // Sync to ensure everyone is caught up
    let tx_id = TxId::new();
    let record = make_commit_record(tx_id, 1);
    let audit = vec![make_audit_record(tx_id, 0, "/transfer")];
    group[0].append_commit(record, audit).await.unwrap();
    group[0].sync().await.unwrap();

    // Transfer leadership to node 1
    group[0].transfer_leadership(1).await.unwrap();

    // Check that node 0 stepped down to follower
    assert_eq!(group[0].get_role().await, Role::Follower);

    // Wait for node 1 to become leader via TimeoutNow campaign
    let start = std::time::Instant::now();
    let mut success = false;
    while start.elapsed() < std::time::Duration::from_secs(2) {
        if group[1].get_role().await == Role::Leader {
            success = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(success, "node 1 did not become leader");
}

#[tokio::test]
async fn test_consensus_automatic_transition_finalization() {
    let temp_dir = TempDir::new().unwrap();
    let mut backends = Vec::new();
    for i in 0..3 {
        let db_path = temp_dir.path().join(format!("final_consensus_{i}.db"));
        let backend = SqliteBackend::open_with_audit_key(&db_path, true, 0, test_audit_key())
            .await
            .unwrap();
        backends.push(Arc::new(backend));
    }

    let mut stores = Vec::new();
    for (i, backend) in backends.iter().enumerate() {
        let membership = ClusterMembership {
            cluster_id: "test-cluster".to_string(),
            node_id: i,
            voting_members: vec![0, 1, 2],
            non_voting_members: vec![],
            old_voting_members: None,
            removed_members: vec![],
            epoch: 1,
        };
        let clock = ConsensusClock {
            // Timers loose enough to survive CI scheduler jitter under load;
            // the test asserts that membership finalizes (logic), not how fast.
            election_timeout_min: std::time::Duration::from_millis(250),
            election_timeout_max: std::time::Duration::from_millis(500),
            heartbeat_interval: std::time::Duration::from_millis(50),
            enable_timers: true,
        };
        let store = ConsensusConfigStore::new(i, backend.clone(), Some(membership), Some(clock))
            .await
            .unwrap();
        stores.push(Arc::new(store));
    }

    // Connect peers
    for i in 0..3 {
        for j in 0..3 {
            if i != j {
                stores[i].add_peer(j, stores[j].clone()).await;
            }
        }
    }

    // Campaign node 0
    stores[0].campaign().await.unwrap();
    assert_eq!(stores[0].get_role().await, Role::Leader);

    // Prepare a joint configuration ChangeMembership op
    let joint_membership = ClusterMembership {
        cluster_id: "test-cluster".to_string(),
        node_id: 0,
        voting_members: vec![0, 1, 2],
        non_voting_members: vec![],
        old_voting_members: Some(vec![0, 1, 2]),
        removed_members: vec![],
        epoch: 2,
    };

    // Replicate and commit the joint config
    stores[0]
        .replicate_and_commit(opc_persist::ConsensusOp::ChangeMembership {
            membership: joint_membership,
        })
        .await
        .unwrap();

    // Wait for the background loop to automatically propose and commit the final config
    let start = std::time::Instant::now();
    let mut finalized = false;
    while start.elapsed() < std::time::Duration::from_secs(10) {
        let current_m = stores[0]
            .inner
            .consensus_get_membership()
            .await
            .unwrap()
            .unwrap();
        if current_m.old_voting_members.is_none() && current_m.epoch > 2 {
            finalized = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    assert!(
        finalized,
        "transition was not automatically finalized to old_voting_members = None"
    );
}

#[tokio::test]
#[allow(clippy::needless_range_loop)]
async fn test_consensus_snapshot_membership_bug() {
    let temp_dir = TempDir::new().unwrap();

    // 1. Create a 3-node group: 0, 1, 2
    let mut backends = Vec::new();
    for i in 0..4 {
        let db_path = temp_dir.path().join(format!("snap_bug_{i}.db"));
        let backend = SqliteBackend::open_with_audit_key(&db_path, true, 0, test_audit_key())
            .await
            .expect("open backend");
        backends.push(Arc::new(backend));
    }

    let mut stores = Vec::new();
    for i in 0..3 {
        let membership = ClusterMembership {
            cluster_id: "test-cluster".to_string(),
            node_id: i,
            voting_members: vec![0, 1, 2],
            non_voting_members: vec![],
            old_voting_members: None,
            removed_members: vec![],
            epoch: 1,
        };
        let clock = ConsensusClock {
            election_timeout_min: std::time::Duration::from_millis(150),
            election_timeout_max: std::time::Duration::from_millis(300),
            heartbeat_interval: std::time::Duration::from_millis(50),
            enable_timers: false,
        };
        let store =
            ConsensusConfigStore::new(i, backends[i].clone(), Some(membership), Some(clock))
                .await
                .expect("create store");
        stores.push(Arc::new(store));
    }

    // Connect stores 0, 1, 2
    for i in 0..3 {
        for j in 0..3 {
            if i != j {
                stores[i].add_peer(j, stores[j].clone()).await;
            }
        }
    }

    // Campaign node 0 to leader
    stores[0].campaign().await.unwrap();
    assert_eq!(stores[0].get_role().await, Role::Leader);

    // Replicate first log entry
    let tx_id = TxId::new();
    let record = make_commit_record(tx_id, 1);
    let audit = vec![make_audit_record(tx_id, 0, "/a")];
    stores[0].append_commit(record, audit).await.unwrap();
    stores[0].sync().await.unwrap();

    // Now, compact logs up to the current applied index on leader (node 0)
    let applied = stores[0].inner.consensus_get_applied_index().await.unwrap();
    stores[0].compact_logs(applied).await.unwrap();

    // Setup node 3 (new follower catching up from scratch)
    // Its initial membership table has only [3]
    let initial_membership_3 = ClusterMembership {
        cluster_id: "test-cluster".to_string(),
        node_id: 3,
        voting_members: vec![3],
        non_voting_members: vec![],
        old_voting_members: None,
        removed_members: vec![],
        epoch: 1,
    };
    let clock = ConsensusClock {
        election_timeout_min: std::time::Duration::from_millis(150),
        election_timeout_max: std::time::Duration::from_millis(300),
        heartbeat_interval: std::time::Duration::from_millis(50),
        enable_timers: false,
    };
    let store_3 = Arc::new(
        ConsensusConfigStore::new(
            3,
            backends[3].clone(),
            Some(initial_membership_3),
            Some(clock),
        )
        .await
        .unwrap(),
    );

    // Connect node 0 and node 3
    stores[0].add_peer(3, store_3.clone()).await;
    store_3.add_peer(0, stores[0].clone()).await;

    // Trigger sync from leader to replicate to node 3
    // Since leader's logs are compacted, leader should send snapshot to node 3.
    stores[0].sync().await.unwrap();

    // Check if node 3's applied index matches the snapshot's index
    let applied_3 = store_3.inner.consensus_get_applied_index().await.unwrap();
    assert_eq!(applied_3, applied);

    // Check node 3's membership configuration
    let membership_3 = store_3
        .inner
        .consensus_get_membership()
        .await
        .unwrap()
        .unwrap();

    // Check if the membership was updated to the cluster's membership [0, 1, 2]
    // If there is a bug, node 3's membership will still be the initial [3]!
    println!("Node 3 membership: {membership_3:?}");
    assert_eq!(
        membership_3.voting_members,
        vec![0, 1, 2],
        "Membership should be reconciled from snapshot!"
    );
}

#[tokio::test]
async fn test_consensus_add_removed_node_bug() {
    let temp_dir = TempDir::new().unwrap();
    let group = setup_consensus_group(&temp_dir).await;

    // Campaign node 0 to leader
    group[0].campaign().await.unwrap();

    // Replicate initial commit
    let tx_id = TxId::new();
    let record = make_commit_record(tx_id, 1);
    let audit = vec![make_audit_record(tx_id, 0, "/init")];
    group[0].append_commit(record, audit).await.unwrap();
    group[0].sync().await.unwrap();

    // Remove node 2
    group[0].remove_node(2).await.unwrap();
    group[0].sync().await.unwrap();

    // Now try to add node 2 back using add_node_as_non_voter
    // If there is a bug, this will succeed even though node 2 is tombstoned/removed!
    let res = group[0].add_node_as_non_voter(2).await;
    assert!(
        res.is_err(),
        "Should not allow adding a removed/tombstoned member!"
    );
}

#[tokio::test]
#[allow(clippy::needless_range_loop)]
async fn test_consensus_non_voter_becomes_leader_bug() {
    let temp_dir = TempDir::new().unwrap();

    // Create 4 backends
    let mut backends = Vec::new();
    for i in 0..4 {
        let db_path = temp_dir.path().join(format!("non_voter_leader_{i}.db"));
        let backend = SqliteBackend::open_with_audit_key(&db_path, true, 0, test_audit_key())
            .await
            .expect("open backend");
        backends.push(Arc::new(backend));
    }

    let mut stores = Vec::new();
    for i in 0..4 {
        let membership = ClusterMembership {
            cluster_id: "test-cluster".to_string(),
            node_id: i,
            voting_members: vec![0, 1, 2],
            non_voting_members: vec![3],
            old_voting_members: None,
            removed_members: vec![],
            epoch: 1,
        };
        let clock = ConsensusClock {
            election_timeout_min: std::time::Duration::from_millis(150),
            election_timeout_max: std::time::Duration::from_millis(300),
            heartbeat_interval: std::time::Duration::from_millis(50),
            enable_timers: false,
        };
        let store =
            ConsensusConfigStore::new(i, backends[i].clone(), Some(membership), Some(clock))
                .await
                .expect("create store");
        stores.push(Arc::new(store));
    }

    // Connect all peers
    for i in 0..4 {
        for j in 0..4 {
            if i != j {
                stores[i].add_peer(j, stores[j].clone()).await;
            }
        }
    }

    // Node 3 is a non-voting member. Let's make node 3 campaign!
    // If there is a bug, this will succeed and node 3 will become leader!
    let _ = stores[3].campaign().await;
    assert_ne!(
        stores[3].get_role().await,
        Role::Leader,
        "Non-voting member should not be allowed to become leader!"
    );
}
