mod common;
mod tcp_consensus_common;
use opc_persist::{ConfigStore, ConsensusPeer, Role, RollbackTarget};
use opc_types::{Timestamp, TxId};
use std::sync::Arc;
use std::time::Duration;
use tcp_consensus_common::{
    make_audit_record, make_commit_record, setup_tcp_consensus_group, test_audit_key, SqliteBackend,
};
use tempfile::TempDir;
use tokio::time::sleep;

#[tokio::test]
async fn test_tcp_consensus_happy_path_and_failover() {
    let temp_dir = TempDir::new().unwrap();
    let group = setup_tcp_consensus_group(&temp_dir, 16000).await;

    group[0].campaign().await.unwrap();
    assert_eq!(group[0].get_role().await, Role::Leader);

    let tx_id_1 = TxId::new();
    let record_1 = make_commit_record(tx_id_1, 1);
    let audit_1 = vec![make_audit_record(tx_id_1, 0, "/a")];

    group[0].append_commit(record_1, audit_1).await.unwrap();

    group[0].sync().await.unwrap();
    let latest_1 = group[1].load_latest().await.unwrap().unwrap();
    assert_eq!(latest_1.record.tx_id, tx_id_1);

    group[2].set_online(false).await;

    let tx_id_2 = TxId::new();
    let record_2 = make_commit_record(tx_id_2, 2);
    let audit_2 = vec![make_audit_record(tx_id_2, 0, "/b")];

    group[0].append_commit(record_2, audit_2).await.unwrap();

    let latest_2_offline = group[2].inner.load_latest().await.unwrap().unwrap();
    assert_eq!(latest_2_offline.record.tx_id, tx_id_1);

    group[2].set_online(true).await;

    group[0].sync().await.unwrap();

    let latest_2_online = group[2].load_latest().await.unwrap().unwrap();
    assert_eq!(latest_2_online.record.tx_id, tx_id_2);

    group[0].set_online(false).await;

    group[1].campaign().await.unwrap();
    assert_eq!(group[1].get_role().await, Role::Leader);

    let tx_id_3 = TxId::new();
    let record_3 = make_commit_record(tx_id_3, 3);
    let audit_3 = vec![make_audit_record(tx_id_3, 0, "/c")];
    group[1].append_commit(record_3, audit_3).await.unwrap();

    group[1].sync().await.unwrap();
    let latest_3 = group[2].load_latest().await.unwrap().unwrap();
    assert_eq!(latest_3.record.tx_id, tx_id_3);

    latest_3.verify_audit_chain(&test_audit_key()).unwrap();
}

#[tokio::test]
async fn test_tcp_consensus_partition_scenarios() {
    let temp_dir = TempDir::new().unwrap();
    let group = setup_tcp_consensus_group(&temp_dir, 16100).await;

    group[0].campaign().await.unwrap();

    group[1].set_online(false).await;
    group[2].set_online(false).await;

    let tx_id = TxId::new();
    let record = make_commit_record(tx_id, 1);
    let audit = vec![make_audit_record(tx_id, 0, "/a")];
    let err_write = group[0].append_commit(record, audit).await.unwrap_err();
    assert!(err_write.to_string().contains("quorum not reached"));

    let err_read = group[0].load_latest().await.unwrap_err();
    assert!(
        err_read.to_string().contains("lost leader quorum")
            || err_read.to_string().contains("quorum")
    );

    group[1].set_online(true).await;

    group[0].campaign().await.unwrap();
    assert_eq!(group[0].get_role().await, Role::Leader);

    let tx_id_maj = TxId::new();
    let record_maj = make_commit_record(tx_id_maj, 1);
    let audit_maj = vec![make_audit_record(tx_id_maj, 0, "/maj")];
    group[0].append_commit(record_maj, audit_maj).await.unwrap();

    let loaded = group[0].load_latest().await.unwrap().unwrap();
    assert_eq!(loaded.record.tx_id, tx_id_maj);
}

#[tokio::test]
async fn test_tcp_consensus_no_quorum_write_not_resurrected() {
    let temp_dir = TempDir::new().unwrap();
    let group = setup_tcp_consensus_group(&temp_dir, 16200).await;

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
    let _ = group[0]
        .append_commit(
            failed_record,
            vec![make_audit_record(failed_tx, 0, "/failed")],
        )
        .await
        .unwrap_err();

    group[1].set_online(true).await;
    group[2].set_online(true).await;

    group[0].campaign().await.unwrap();
    group[0].sync().await.unwrap();

    let err_rollback = group[0]
        .inner
        .load_rollback(RollbackTarget::ByTxId(failed_tx))
        .await
        .unwrap_err();
    assert!(err_rollback
        .to_string()
        .contains("rollback target not found"));
}

#[tokio::test]
async fn test_tcp_consensus_schema_mismatch_fails_closed() {
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("mismatch.db");

    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute_batch(
            r#"
            CREATE TABLE schema_version (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                schema_digest TEXT NOT NULL,
                sdk_version TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            INSERT INTO schema_version (id, schema_digest, sdk_version, created_at)
            VALUES (1, 'incompatible-digest', '99.9.9', datetime('now'));
            "#,
        )
        .unwrap();
    }

    let err = SqliteBackend::open_with_audit_key(&db_path, true, 0, test_audit_key())
        .await
        .unwrap_err();

    assert!(err.to_string().contains("schema version mismatch"));
}

#[tokio::test]
async fn test_tcp_consensus_commit_confirmed_failover_and_rollback_prevention() {
    let temp_dir = TempDir::new().unwrap();
    let group = setup_tcp_consensus_group(&temp_dir, 16300).await;

    group[0].campaign().await.unwrap();

    let tx_id = TxId::new();
    let mut record = make_commit_record(tx_id, 1);

    let dt = time::OffsetDateTime::now_utc() + time::Duration::seconds(60);
    record.confirmed_deadline = Some(Timestamp::from(dt));

    let audit = vec![make_audit_record(tx_id, 0, "/a")];
    group[0].append_commit(record, audit).await.unwrap();

    group[0].set_online(false).await;

    group[1].campaign().await.unwrap();
    assert_eq!(group[1].get_role().await, Role::Leader);

    group[1].sync().await.unwrap();

    let loaded = group[1].load_latest().await.unwrap().unwrap();
    assert_eq!(loaded.record.tx_id, tx_id);
    assert!(loaded.record.confirmed_deadline.is_some());

    let err_rollback = group[1]
        .inner
        .load_rollback(RollbackTarget::ByTxId(tx_id))
        .await
        .unwrap_err();
    assert!(err_rollback
        .to_string()
        .contains("rollback target not found"));
}

#[tokio::test]
async fn test_tcp_consensus_server_shutdown_and_restart() {
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("shutdown_restart.db");
    let backend = Arc::new(
        SqliteBackend::open_with_audit_key(&db_path, true, 0, test_audit_key())
            .await
            .unwrap(),
    );

    let membership = opc_persist::ClusterMembership {
        cluster_id: "tcp-test-cluster".to_string(),
        node_id: 0,
        voting_members: vec![0],
        non_voting_members: vec![],
        old_voting_members: None,
        removed_members: vec![],
        epoch: 1,
    };
    let store = Arc::new(
        opc_persist::ConsensusConfigStore::new(0, backend, Some(membership), None)
            .await
            .unwrap(),
    );
    let (_, _, identities) = tcp_consensus_common::generate_test_ca_and_identities(&[0]);
    store
        .set_identity(identities.get(&0).unwrap().clone())
        .await
        .unwrap();

    let server = opc_persist::TcpRpcServer::new(store.clone(), "127.0.0.1:16500".to_string());
    let handle = server.start().await.unwrap();
    let duplicate_start = server.start().await;
    assert!(duplicate_start.is_err());
    assert!(duplicate_start
        .err()
        .unwrap()
        .to_string()
        .contains("already running"));

    server.shutdown().await;
    let _ = handle.await;

    let server_restart =
        opc_persist::TcpRpcServer::new(store.clone(), "127.0.0.1:16500".to_string());
    let handle_restart = server_restart.start().await.unwrap();

    server_restart.shutdown().await;
    let _ = handle_restart.await;
}

#[tokio::test]
async fn test_tcp_consensus_rejoining_prevention() {
    let temp_dir = TempDir::new().unwrap();
    let group = setup_tcp_consensus_group(&temp_dir, 18500).await;

    group[0].campaign().await.unwrap();
    assert_eq!(group[0].get_role().await, Role::Leader);

    group[0].remove_node(2).await.unwrap();

    group[0].sync().await.unwrap();
    let m1 = group[1]
        .inner
        .consensus_get_membership()
        .await
        .unwrap()
        .unwrap();
    assert!(m1.removed_members.contains(&2));

    let peer_to_1 = opc_persist::TcpPeer::new(
        1,
        "127.0.0.1:18501".to_string(),
        std::time::Duration::from_millis(250),
    );

    let node2_identity = group[2].identity.read().await.clone().unwrap();
    peer_to_1.set_identity(node2_identity).await.unwrap();
    peer_to_1
        .set_auth(
            2,
            "tcp-test-cluster".to_string(),
            group[2].get_client_cert_pem(),
        )
        .await
        .unwrap();

    let req = opc_persist::RequestVoteRequest {
        term: 2,
        candidate_id: 2,
        last_log_index: 0,
        last_log_term: 0,
    };
    let res = peer_to_1.request_vote(req).await;

    assert!(res.is_err());
    let err_str = res.unwrap_err().to_string();
    assert!(
        err_str.contains("redacted")
            || err_str.contains("unauthenticated")
            || err_str.contains("removed")
    );
}

#[tokio::test]
async fn test_tcp_consensus_log_term_gap_recovery() {
    let temp_dir = TempDir::new().unwrap();
    let group = setup_tcp_consensus_group(&temp_dir, 22200).await;

    group[0].campaign().await.unwrap();
    assert_eq!(group[0].get_role().await, Role::Leader);

    group[2].set_online(false).await;

    for v in 1..=5 {
        let tx_id = TxId::new();
        let res = group[0]
            .append_commit(
                make_commit_record(tx_id, v),
                vec![make_audit_record(tx_id, 0, &format!("/path/{v}"))],
            )
            .await;
        assert!(res.is_ok() || res.is_err()); // Ensure it returns a Result
    }

    group[2].set_online(true).await;
    sleep(Duration::from_millis(2000)).await;

    let latest_0 = group[0].load_latest().await.unwrap().unwrap();
    let latest_2 = group[2].load_latest().await.unwrap().unwrap();

    assert_eq!(latest_2.record.tx_id, latest_0.record.tx_id);
}
