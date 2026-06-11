use opc_persist::{
    AuditOpType, AuditRecord, CommitRecord, CommitSource, ConfigStore, FencedReplica,
    QuorumConfigStore, RollbackTarget, SqliteBackend,
};
use opc_types::{ConfigVersion, SchemaDigest, Timestamp, TxId};
use std::sync::Arc;
use tempfile::TempDir;

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
    AuditRecord {
        tx_id,
        sequence,
        yang_path: path.to_string(),
        op_type: AuditOpType::Create,
        previous_value: None,
        new_value: Some(r#""value""#.to_string()),
        redaction_applied: false,
        previous_hash: [0u8; 32],
        entry_hmac: [0u8; 32],
    }
}

async fn setup_replicas(temp_dir: &TempDir) -> Vec<FencedReplica> {
    let mut replicas = Vec::new();
    for i in 0..3 {
        let db_path = temp_dir.path().join(format!("replica_{}.db", i));
        let backend = SqliteBackend::open(&db_path, true, 0)
            .await
            .expect("open backend");
        replicas.push(FencedReplica::new(i, Arc::new(backend)));
    }
    replicas
}

#[tokio::test]
async fn test_quorum_writes_and_reads() {
    let temp_dir = TempDir::new().unwrap();
    let replicas = setup_replicas(&temp_dir).await;
    let quorum_store = QuorumConfigStore::new(replicas.clone(), 1);

    // Initial load should be None
    let loaded = quorum_store.load_latest().await.unwrap();
    assert!(loaded.is_none());

    // Successful write with epoch 1
    let tx_id = TxId::new();
    let record = make_commit_record(tx_id, 1);
    let audit = vec![make_audit_record(tx_id, 0, "/a")];

    quorum_store.append_commit(record, audit).await.unwrap();

    // Latest should be returned
    let loaded = quorum_store.load_latest().await.unwrap().unwrap();
    assert_eq!(loaded.record.tx_id, tx_id);
}

#[tokio::test]
async fn test_fencing_prevents_stale_leader_writes() {
    let temp_dir = TempDir::new().unwrap();
    let replicas = setup_replicas(&temp_dir).await;

    // Leader 1 uses epoch 1
    let store_1 = QuorumConfigStore::new(replicas.clone(), 1);
    // Leader 2 uses epoch 2
    let store_2 = QuorumConfigStore::new(replicas.clone(), 2);

    // Leader 2 registers epoch 2 (fencing off Leader 1)
    let tx_id_2 = TxId::new();
    let record_2 = make_commit_record(tx_id_2, 1);
    store_2
        .append_commit(record_2, vec![make_audit_record(tx_id_2, 0, "/b")])
        .await
        .unwrap();

    // Now Leader 1 (epoch 1) attempts a write, which should be rejected
    let tx_id_1 = TxId::new();
    let record_1 = make_commit_record(tx_id_1, 2);
    let err = store_1
        .append_commit(record_1, vec![make_audit_record(tx_id_1, 0, "/a")])
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("leader epoch quorum not reached")
            || err.to_string().contains("Fenced")
    );
}

#[tokio::test]
async fn test_linearizability_with_partition_split_brain() {
    let temp_dir = TempDir::new().unwrap();
    let replicas = setup_replicas(&temp_dir).await;
    let store = QuorumConfigStore::new(replicas.clone(), 1);

    // Partition: Replica 0 and 1 are online, Replica 2 is offline
    replicas[2].set_online(false).await;

    // Write should succeed because we have a majority (2 out of 3) online
    let tx_id_1 = TxId::new();
    let record_1 = make_commit_record(tx_id_1, 1);
    store
        .append_commit(record_1, vec![make_audit_record(tx_id_1, 0, "/a")])
        .await
        .unwrap();

    // Load latest should also succeed
    let loaded = store.load_latest().await.unwrap().unwrap();
    assert_eq!(loaded.record.tx_id, tx_id_1);

    // Now partition worsens: Replica 1 goes offline, only Replica 0 remains online (minority)
    replicas[1].set_online(false).await;

    // Write should fail
    let tx_id_2 = TxId::new();
    let record_2 = make_commit_record(tx_id_2, 2);
    let err_write = store
        .append_commit(record_2, vec![make_audit_record(tx_id_2, 0, "/b")])
        .await
        .unwrap_err();
    assert!(
        err_write.to_string().contains("quorum not reached")
            || err_write.to_string().contains("offline")
    );

    // Read latest should also fail due to lack of quorum responses
    let err_read = store.load_latest().await.unwrap_err();
    assert!(
        err_read.to_string().contains("unavailable") || err_read.to_string().contains("consensus")
    );
}

#[tokio::test]
async fn test_rollback_does_not_select_pending_or_divergent_commit() {
    let temp_dir = TempDir::new().unwrap();
    let replicas = setup_replicas(&temp_dir).await;
    let store = QuorumConfigStore::new(replicas.clone(), 1);

    // 1. Write a stable confirmed config (version 1)
    let tx_1 = TxId::new();
    let rec_1 = make_commit_record(tx_1, 1);
    store
        .append_commit(rec_1, vec![make_audit_record(tx_1, 0, "/x")])
        .await
        .unwrap();

    // 2. Write a second stable confirmed config (version 2) with parent = tx_1
    let tx_2 = TxId::new();
    let mut rec_2 = make_commit_record(tx_2, 2);
    rec_2.parent_tx_id = Some(tx_1);
    store
        .append_commit(rec_2, vec![make_audit_record(tx_2, 0, "/y")])
        .await
        .unwrap();

    // 3. Write a commit-confirmed config (version 3) with a pending deadline and parent = tx_2
    let tx_3 = TxId::new();
    let mut rec_3 = make_commit_record(tx_3, 3);
    rec_3.parent_tx_id = Some(tx_2);
    let dt = time::OffsetDateTime::now_utc() + time::Duration::seconds(60);
    rec_3.confirmed_deadline = Some(Timestamp::from(dt));

    store
        .append_commit(rec_3, vec![make_audit_record(tx_3, 0, "/z")])
        .await
        .unwrap();

    // At this point, latest loaded config includes the pending one (version 3)
    let latest = store.load_latest().await.unwrap().unwrap();
    assert_eq!(latest.record.tx_id, tx_3);

    // Rollback to Previous should select version 1 (which is parent of the latest confirmed commit, version 2),
    // NOT version 2 (which is parent of version 3, since version 3 is pending and ignored).
    let rolled = store.load_rollback(RollbackTarget::Previous).await.unwrap();
    assert_eq!(rolled.record.tx_id, tx_1);

    // Rollback target for ByTxId of the pending commit should be rejected
    let err = store
        .load_rollback(RollbackTarget::ByTxId(tx_3))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("rollback target not found"));
}

#[tokio::test]
async fn test_restart_rejoin_monotonicity() {
    let temp_dir = TempDir::new().unwrap();

    // 1. Initial run: create 3 replicas
    let db_paths: Vec<_> = (0..3)
        .map(|i| temp_dir.path().join(format!("replica_{}.db", i)))
        .collect();
    let mut replicas = Vec::new();
    for (i, path) in db_paths.iter().enumerate() {
        let backend = SqliteBackend::open(path, true, 0).await.unwrap();
        replicas.push(FencedReplica::new(i, Arc::new(backend)));
    }

    // Set leader epoch to 10
    let store = QuorumConfigStore::new(replicas.clone(), 10);

    let tx_1 = TxId::new();
    let rec_1 = make_commit_record(tx_1, 1);
    store
        .append_commit(rec_1, vec![make_audit_record(tx_1, 0, "/a")])
        .await
        .unwrap();

    // Save max epochs to simulate persistent node memory or external lease manager
    let mut max_epochs = Vec::new();
    for r in &replicas {
        max_epochs.push(r.get_max_epoch().await);
    }
    assert_eq!(max_epochs, vec![10, 10, 10]);

    // 2. Simulate node restart of replica 1
    // We recreate replica 1 SqliteBackend on the same path, and restore its max_epoch
    let restarted_backend = SqliteBackend::open(&db_paths[1], true, 0).await.unwrap();
    let restarted_replica = FencedReplica::new(1, Arc::new(restarted_backend));
    restarted_replica.set_max_epoch(max_epochs[1]).await;

    // Assemble new replica list
    let mut new_replicas = replicas.clone();
    new_replicas[1] = restarted_replica;

    let store_after_restart = QuorumConfigStore::new(new_replicas, 10);

    // Verify loading works across restart
    let latest = store_after_restart.load_latest().await.unwrap().unwrap();
    assert_eq!(latest.record.tx_id, tx_1);

    // Older leader with epoch 9 should still be fenced out
    store_after_restart.set_leader_epoch(9).await;
    let tx_2 = TxId::new();
    let rec_2 = make_commit_record(tx_2, 2);
    let err = store_after_restart
        .append_commit(rec_2, vec![make_audit_record(tx_2, 0, "/b")])
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("leader epoch quorum not reached")
            || err.to_string().contains("Fenced")
    );
}
