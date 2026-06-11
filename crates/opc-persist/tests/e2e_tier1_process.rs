mod common;

use common::TestCluster;
use opc_types::TxId;
use serde_json::json;
use std::time::Duration;
use tokio::time::sleep;

fn get_dynamic_base_port() -> u16 {
    common::find_free_port_block(50)
}

#[tokio::test]
async fn test_process_control_graceful_stop_restart() {
    let mut cluster = TestCluster::new(20000);
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

    cluster.graceful_stop_node(1).await;
    sleep(Duration::from_millis(300)).await;

    let send_res = cluster
        .nodes
        .get_mut(&1)
        .unwrap()
        .send_command(json!({
            "command": "DumpMetrics"
        }))
        .await;
    assert!(send_res.is_err());

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

    cluster.restart_node(1).await;
    let mut success = false;
    let mut resp_latest = serde_json::Value::Null;
    for _ in 0..15 {
        if let Ok(resp) = cluster
            .nodes
            .get_mut(&1)
            .unwrap()
            .send_command(json!({
                "command": "LoadLatest"
            }))
            .await
        {
            resp_latest = resp;
            if resp_latest["success"].as_bool().unwrap_or(false)
                && resp_latest["data"]["record"]["version"].as_u64() == Some(1)
            {
                success = true;
                break;
            }
        }
        sleep(Duration::from_millis(500)).await;
    }
    assert!(
        success,
        "Node 1 failed to load latest config after restart. resp = {:?}",
        resp_latest
    );
}

#[tokio::test]
async fn test_process_control_hard_kill_failover() {
    let mut cluster = TestCluster::new(20000);
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

    cluster.kill_node(0).await;
    let mut new_leader = None;
    for _attempt in 0..35 {
        for &node_id in &[1, 2] {
            if let Ok(resp) = cluster
                .nodes
                .get_mut(&node_id)
                .unwrap()
                .send_command(json!({
                    "command": "DumpMetrics"
                }))
                .await
            {
                if resp["success"].as_bool().unwrap_or(false)
                    && resp["data"]["role"].as_str() == Some("Leader")
                {
                    new_leader = Some(node_id);
                    break;
                }
            }
        }
        if new_leader.is_some() {
            break;
        }
        sleep(Duration::from_millis(200)).await;
    }
    let leader_id = new_leader.expect("A new leader should be elected");

    let tx_id = TxId::new();
    let resp = cluster.nodes.get_mut(&leader_id).unwrap().send_command(json!({
        "command": "AppendCommit",
        "tx_id": tx_id.to_string(),
        "version": 1,
        "principal": "spiffe://test/trust-domain/tenant/test/ns/default/sa/svc/nf/test/instance/0",
        "encrypted_blob": "aabbcc",
        "audit_paths": ["/a"]
    })).await.unwrap();
    assert!(resp["success"].as_bool().unwrap());

    let other_node = if leader_id == 1 { 2 } else { 1 };
    let mut success = false;
    let mut resp_latest = serde_json::Value::Null;
    for _ in 0..10 {
        resp_latest = cluster
            .nodes
            .get_mut(&other_node)
            .unwrap()
            .send_command(json!({
                "command": "LoadLatest"
            }))
            .await
            .unwrap();
        if resp_latest["success"].as_bool().unwrap_or(false)
            && resp_latest["data"]["record"]["version"].as_u64() == Some(1)
        {
            success = true;
            break;
        }
        sleep(Duration::from_millis(500)).await;
    }
    assert!(
        success,
        "Follower failed to catch up / load latest. resp = {:?}",
        resp_latest
    );
}

#[tokio::test]
async fn test_process_control_disk_state_preservation() {
    let mut cluster = TestCluster::new(20000);
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

    cluster.kill_node(2).await;
    sleep(Duration::from_millis(200)).await;

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

    cluster.restart_node(2).await;
    sleep(Duration::from_millis(800)).await;

    let resp_latest = cluster
        .nodes
        .get_mut(&2)
        .unwrap()
        .send_command(json!({
            "command": "LoadLatest"
        }))
        .await
        .unwrap();
    assert!(resp_latest["success"].as_bool().unwrap());
    assert_eq!(resp_latest["data"]["record"]["version"].as_u64(), Some(1));
}

#[tokio::test]
async fn test_process_control_network_isolation_and_heal() {
    let mut cluster = TestCluster::new(20000);
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

    let m_init = cluster
        .nodes
        .get_mut(&2)
        .unwrap()
        .send_command(json!({
            "command": "DumpMetrics"
        }))
        .await
        .unwrap();
    let initial_idx = m_init["data"]["last_log_index"].as_u64().unwrap();

    cluster.partition(0, 2);
    cluster.partition(1, 2);
    sleep(Duration::from_millis(200)).await;

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

    sleep(Duration::from_millis(500)).await;

    let m_isolated = cluster
        .nodes
        .get_mut(&2)
        .unwrap()
        .send_command(json!({
            "command": "DumpMetrics"
        }))
        .await
        .unwrap();
    let isolated_idx = m_isolated["data"]["last_log_index"].as_u64().unwrap();
    assert_eq!(isolated_idx, initial_idx);

    cluster.heal(0, 2);
    cluster.heal(1, 2);
    sleep(Duration::from_millis(500)).await;

    let mut success = false;
    for _attempt in 0..5 {
        let _ = cluster
            .nodes
            .get_mut(&0)
            .unwrap()
            .send_command(json!({
                "command": "Campaign"
            }))
            .await;
        sleep(Duration::from_millis(500)).await;

        let m0 = cluster
            .nodes
            .get_mut(&0)
            .unwrap()
            .send_command(json!({"command": "DumpMetrics"}))
            .await;
        if let Ok(m) = m0 {
            if m["data"]["role"].as_str() == Some("Leader") {
                success = true;
                break;
            }
        }
    }
    assert!(
        success,
        "Node 0 failed to become leader after healing partition"
    );

    sleep(Duration::from_millis(500)).await;

    let resp_latest2 = cluster
        .nodes
        .get_mut(&2)
        .unwrap()
        .send_command(json!({
            "command": "LoadLatest"
        }))
        .await
        .unwrap();
    assert!(resp_latest2["success"].as_bool().unwrap());
    assert_eq!(resp_latest2["data"]["record"]["version"].as_u64(), Some(1));
}

#[tokio::test]
async fn test_process_control_cascading_shutdown() {
    let mut cluster = TestCluster::new(20000);
    cluster.base_port = get_dynamic_base_port();
    cluster.bootstrap().await.unwrap();
    sleep(Duration::from_millis(500)).await;

    for i in 0..3 {
        cluster.graceful_stop_node(i).await;
    }
    sleep(Duration::from_millis(500)).await;

    for i in 0..3 {
        cluster.restart_node(i).await;
    }
    sleep(Duration::from_millis(800)).await;

    let mut leader_id = None;
    for attempt in 0..20 {
        for node_id in 0..3 {
            if let Ok(metrics) = cluster
                .nodes
                .get_mut(&node_id)
                .unwrap()
                .send_command(json!({
                    "command": "DumpMetrics"
                }))
                .await
            {
                if metrics["success"].as_bool().unwrap_or(false)
                    && metrics["data"]["role"].as_str() == Some("Leader")
                {
                    leader_id = Some(node_id);
                    break;
                }
            }
        }
        if leader_id.is_some() {
            break;
        }

        let candidate = attempt % 3;
        let _ = cluster
            .nodes
            .get_mut(&candidate)
            .unwrap()
            .send_command(json!({
                "command": "Campaign"
            }))
            .await;
        sleep(Duration::from_millis(300)).await;
    }
    let leader_id = leader_id.expect("No leader elected after cascading restart");
    sleep(Duration::from_millis(500)).await;

    let tx_id = TxId::new();
    let resp = cluster.nodes.get_mut(&leader_id).unwrap().send_command(json!({
        "command": "AppendCommit",
        "tx_id": tx_id.to_string(),
        "version": 1,
        "principal": "spiffe://test/trust-domain/tenant/test/ns/default/sa/svc/nf/test/instance/0",
        "encrypted_blob": "aabbcc",
        "audit_paths": ["/a"]
    })).await.unwrap();
    assert!(resp["success"].as_bool().unwrap());

    sleep(Duration::from_millis(500)).await;
    let mut resp_latest = None;
    for _ in 0..20 {
        let resp = cluster
            .nodes
            .get_mut(&1)
            .unwrap()
            .send_command(json!({
                "command": "LoadLatest"
            }))
            .await
            .unwrap();
        if resp["success"].as_bool().unwrap_or(false)
            && resp["data"]["record"]["version"].as_u64() == Some(1)
        {
            resp_latest = Some(resp);
            break;
        }
        sleep(Duration::from_millis(500)).await;
    }
    assert!(resp_latest.is_some());
}

#[tokio::test]
async fn test_process_control_pending_commit_failover() {
    let mut cluster = TestCluster::new(20000);
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

    let tx_id = TxId::new();
    let append_resp = cluster
        .nodes
        .get_mut(&0)
        .unwrap()
        .send_command(json!({
            "command": "AppendCommit",
            "tx_id": tx_id.to_string(),
            "version": 1,
            "principal": "spiffe://test/trust-domain/tenant/test/ns/default/sa/svc/nf/test/instance/0",
            "encrypted_blob": "aabbcc",
            "audit_paths": ["/a"],
            "confirmed_deadline": 60
        }))
        .await
        .unwrap();
    assert!(append_resp["success"].as_bool().unwrap());
    sleep(Duration::from_millis(500)).await;

    cluster.kill_node(0).await;
    sleep(Duration::from_millis(1500)).await;

    cluster
        .nodes
        .get_mut(&1)
        .unwrap()
        .send_command(json!({
            "command": "Campaign"
        }))
        .await
        .unwrap();

    let start_poll = std::time::Instant::now();
    let mut load_resp = serde_json::Value::Null;
    while start_poll.elapsed() < Duration::from_secs(10) {
        if let Ok(resp) = cluster
            .nodes
            .get_mut(&1)
            .unwrap()
            .send_command(json!({
                "command": "LoadLatest"
            }))
            .await
        {
            if resp["success"].as_bool().unwrap_or(false) {
                load_resp = resp;
                break;
            }
        }
        sleep(Duration::from_millis(100)).await;
    }
    assert!(load_resp["success"].as_bool().unwrap());
    assert_eq!(
        load_resp["data"]["record"]["tx_id"].as_str(),
        Some(tx_id.to_string().as_str())
    );

    let rollback_resp = cluster
        .nodes
        .get_mut(&1)
        .unwrap()
        .send_command(json!({
            "command": "LoadRollback",
            "tx_id": tx_id.to_string()
        }))
        .await
        .unwrap();
    assert!(!rollback_resp["success"].as_bool().unwrap());

    let confirm_resp = cluster
        .nodes
        .get_mut(&1)
        .unwrap()
        .send_command(json!({
            "command": "MarkConfirmed",
            "tx_id": tx_id.to_string()
        }))
        .await
        .unwrap();
    assert!(
        confirm_resp["success"].as_bool().unwrap(),
        "MarkConfirmed failed after failover: {confirm_resp}"
    );

    let rollback_resp2 = cluster
        .nodes
        .get_mut(&1)
        .unwrap()
        .send_command(json!({
            "command": "LoadRollback",
            "tx_id": tx_id.to_string()
        }))
        .await
        .unwrap();
    assert!(rollback_resp2["success"].as_bool().unwrap());
}
