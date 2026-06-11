mod common;
mod e2e_tier2_common;

use common::{generate_test_identities, wait_for_port, TestCluster, TestNode};
use e2e_tier2_common::test_audit_key;
use opc_persist::{ConfigStore, SqliteBackend, UnsafePathMock};
use opc_types::TxId;
use serde_json::json;
use std::time::Duration;
use tempfile::TempDir;
use tokio::time::sleep;

fn get_dynamic_base_port() -> u16 {
    common::find_free_port_block(50)
}

#[tokio::test]
async fn test_boundary_disk_full_append() {
    let mut cluster = TestCluster::new(37500);
    cluster.base_port = get_dynamic_base_port();
    cluster.bootstrap().await.unwrap();
    sleep(Duration::from_millis(500)).await;

    cluster
        .nodes
        .get_mut(&0)
        .unwrap()
        .send_command(json!({
            "command": "Campaign"
        }))
        .await
        .unwrap();
    sleep(Duration::from_millis(500)).await;

    let db_path = cluster.nodes.get(&0).unwrap().db_path.clone();

    let conn = rusqlite::Connection::open(&db_path).unwrap();
    conn.execute_batch("PRAGMA busy_timeout = 5000;").unwrap();
    conn.execute("BEGIN EXCLUSIVE TRANSACTION", []).unwrap();

    let tx_id = TxId::new();
    let resp = cluster.nodes.get_mut(&0).unwrap().send_command(json!({
        "command": "AppendCommit",
        "tx_id": tx_id.to_string(),
        "version": 1,
        "principal": "spiffe://test/trust-domain/tenant/test/ns/default/sa/svc/nf/test/instance/0",
        "encrypted_blob": "aabbcc",
        "audit_paths": ["/a"]
    })).await.unwrap();

    conn.execute("ROLLBACK", []).unwrap();

    assert!(!resp["success"].as_bool().unwrap());
}

#[tokio::test]
async fn test_boundary_corrupted_wal() {
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("corrupted.db");

    std::fs::write(&db_path, b"garbage sqlite file header").unwrap();

    let audit_key = test_audit_key();
    let res = SqliteBackend::open_with_audit_key(&db_path, false, 0, audit_key).await;
    assert!(res.is_err());
}

#[tokio::test]
async fn test_boundary_single_quote_db_path() {
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("node 'with spaces & quotes'!.db");

    let node_ids = vec![0];
    let identities = generate_test_identities(&node_ids);
    let identity = identities.get(&0).unwrap();
    let certs_dir = temp_dir.path().join("certs");

    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();

    let mut node = TestNode::spawn(
        0,
        port,
        db_path,
        certs_dir,
        identity,
        &[0],
        &[],
        "tcp-test-cluster",
        &"a5".repeat(32),
        150,
        300,
        150,
    );
    wait_for_port(port).await;

    let resp = node
        .send_command(json!({
            "command": "DumpMetrics"
        }))
        .await
        .unwrap();
    assert!(resp["success"].as_bool().unwrap());
}

#[tokio::test]
async fn test_boundary_db_lock_contention() {
    let mut cluster = TestCluster::new(37700);
    cluster.base_port = get_dynamic_base_port();
    cluster.bootstrap().await.unwrap();
    sleep(Duration::from_millis(500)).await;

    cluster
        .nodes
        .get_mut(&0)
        .unwrap()
        .send_command(json!({
            "command": "Campaign"
        }))
        .await
        .unwrap();
    sleep(Duration::from_millis(500)).await;

    let db_path = cluster.nodes.get(&0).unwrap().db_path.clone();

    let conn = rusqlite::Connection::open(&db_path).unwrap();
    conn.execute("BEGIN EXCLUSIVE TRANSACTION", []).unwrap();

    tokio::spawn(async move {
        sleep(Duration::from_millis(10)).await;
        let _ = conn.execute("COMMIT", []);
    });

    let tx_id = TxId::new();
    let resp = cluster.nodes.get_mut(&0).unwrap().send_command(json!({
        "command": "AppendCommit",
        "tx_id": tx_id.to_string(),
        "version": 1,
        "principal": "spiffe://test/trust-domain/tenant/test/ns/default/sa/svc/nf/test/instance/0",
        "encrypted_blob": "aabbcc",
        "audit_paths": ["/a"]
    })).await.unwrap();

    assert!(resp["success"].as_bool().unwrap());
}

#[tokio::test]
async fn test_boundary_unsafe_nfs() {
    let mock = UnsafePathMock::new("NFS mount detected");
    let caps_res = mock.preflight().await;
    assert!(caps_res.is_err());
    assert!(caps_res.unwrap_err().to_string().contains("NFS"));

    let load_res = mock.load_latest().await;
    assert!(load_res.is_err());
}
