mod common;

use common::{
    bootstrap_4_nodes, connect_raw_tls, wait_for_automatic_leader, AuthenticatedRequest,
    TestCluster, TestNode,
};
use opc_persist::{AppendEntriesRequest, ClusterMembership, ConsensusOp, LogEntry};
use opc_types::TxId;
use serde_json::json;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::sleep;

fn get_dynamic_base_port() -> u16 {
    common::find_free_port_block(50)
}

#[tokio::test]
async fn test_election_single_node() {
    let temp_dir = tempfile::TempDir::new().unwrap();
    let certs_dir = temp_dir.path().join("certs");
    let identities = common::generate_test_identities(&[0]);
    let identity = identities.get(&0).unwrap();

    let port = get_dynamic_base_port();

    let peers: Vec<(usize, u16)> = Vec::new();
    let mut node = TestNode::spawn(
        0,
        port,
        temp_dir.path().join("node_0.db"),
        certs_dir.clone(),
        identity,
        &[0],
        &peers,
        "single-node-cluster",
        &"a5".repeat(32),
        150,
        300,
        150,
    );
    let addr = format!("127.0.0.1:{port}");
    let mut success = false;
    for _ in 0..300 {
        if let Ok(stream) = tokio::net::TcpStream::connect(&addr).await {
            drop(stream);
            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
            success = true;
            break;
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
    }
    if !success {
        let err_path = certs_dir.join("node_0.err");
        if let Ok(err_content) = std::fs::read_to_string(&err_path) {
            println!("--- NODE 0 STDERR --- \n{err_content}");
        } else {
            println!("--- NODE 0 STDERR (not found/unread) ---");
        }
        panic!("Port {port} did not become available in time");
    }

    let resp = node
        .send_command(json!({
            "command": "Campaign"
        }))
        .await
        .unwrap();
    assert!(resp["success"].as_bool().unwrap());

    sleep(Duration::from_millis(500)).await;

    let resp_metrics = node
        .send_command(json!({
            "command": "DumpMetrics"
        }))
        .await
        .unwrap();
    assert!(resp_metrics["success"].as_bool().unwrap());
    assert_eq!(resp_metrics["data"]["role"].as_str(), Some("Leader"));
}

#[tokio::test]
async fn test_election_campaign_monotonic_term() {
    let mut cluster = TestCluster::new(20000);
    cluster.base_port = get_dynamic_base_port();
    cluster.bootstrap().await.unwrap();
    sleep(Duration::from_millis(500)).await;

    let resp = cluster
        .nodes
        .get_mut(&0)
        .unwrap()
        .send_command(json!({
            "command": "Campaign"
        }))
        .await
        .unwrap();
    assert!(resp["success"].as_bool().unwrap());
    sleep(Duration::from_millis(200)).await;

    let m1 = cluster
        .nodes
        .get_mut(&0)
        .unwrap()
        .send_command(json!({
            "command": "DumpMetrics"
        }))
        .await
        .unwrap();
    let term1 = m1["data"]["term"].as_u64().unwrap();

    let resp2 = cluster
        .nodes
        .get_mut(&0)
        .unwrap()
        .send_command(json!({
            "command": "Campaign"
        }))
        .await
        .unwrap();
    assert!(resp2["success"].as_bool().unwrap());
    sleep(Duration::from_millis(200)).await;

    let m2 = cluster
        .nodes
        .get_mut(&0)
        .unwrap()
        .send_command(json!({
            "command": "DumpMetrics"
        }))
        .await
        .unwrap();
    let term2 = m2["data"]["term"].as_u64().unwrap();

    assert!(term2 > term1);
}

#[tokio::test]
async fn test_election_heartbeat_prevents_campaign() {
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

    let m1_1 = cluster
        .nodes
        .get_mut(&1)
        .unwrap()
        .send_command(json!({
            "command": "DumpMetrics"
        }))
        .await
        .unwrap();
    let ec1_1 = m1_1["data"]["election_count"].as_u64().unwrap();

    let m2_1 = cluster
        .nodes
        .get_mut(&2)
        .unwrap()
        .send_command(json!({
            "command": "DumpMetrics"
        }))
        .await
        .unwrap();
    let ec2_1 = m2_1["data"]["election_count"].as_u64().unwrap();

    sleep(Duration::from_millis(1000)).await;

    let m1_2 = cluster
        .nodes
        .get_mut(&1)
        .unwrap()
        .send_command(json!({
            "command": "DumpMetrics"
        }))
        .await
        .unwrap();
    let ec1_2 = m1_2["data"]["election_count"].as_u64().unwrap();

    let m2_2 = cluster
        .nodes
        .get_mut(&2)
        .unwrap()
        .send_command(json!({
            "command": "DumpMetrics"
        }))
        .await
        .unwrap();
    let ec2_2 = m2_2["data"]["election_count"].as_u64().unwrap();

    assert_eq!(ec1_1, ec1_2);
    assert_eq!(ec2_1, ec2_2);
}

#[tokio::test]
async fn test_election_split_vote_resolution() {
    let mut cluster = TestCluster::new(20000);
    cluster.base_port = get_dynamic_base_port();
    cluster.bootstrap().await.unwrap();
    sleep(Duration::from_millis(500)).await;

    cluster.partition(0, 1);
    cluster.partition(0, 2);
    cluster.partition(1, 2);
    sleep(Duration::from_millis(200)).await;

    let _ = cluster
        .nodes
        .get_mut(&0)
        .unwrap()
        .send_command(json!({
            "command": "Campaign"
        }))
        .await;
    let _ = cluster
        .nodes
        .get_mut(&1)
        .unwrap()
        .send_command(json!({
            "command": "Campaign"
        }))
        .await;

    sleep(Duration::from_millis(300)).await;

    cluster.heal(0, 1);
    cluster.heal(0, 2);
    cluster.heal(1, 2);

    wait_for_automatic_leader(
        &mut cluster,
        &[0, 1, 2],
        "split-vote resolution after healing the cluster",
    )
    .await;
}

#[tokio::test]
async fn test_election_stale_term_rejected() {
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
    sleep(Duration::from_millis(300)).await;

    let node_0_port = cluster.base_port;
    let identity = cluster.identities.get(&1).unwrap().clone();
    let mut tls_stream = connect_raw_tls(&format!("127.0.0.1:{node_0_port}"), &identity)
        .await
        .unwrap();

    let req = json!({
        "RequestVote": {
            "term": 0,
            "candidate_id": 1,
            "last_log_index": 0,
            "last_log_term": 0
        }
    });
    let auth_req = AuthenticatedRequest {
        sender_node_id: 1,
        target_node_id: 0,
        cluster_id: "tcp-test-cluster".to_string(),
        spiffe_id: None,
        client_cert_pem: None,
        request: req,
    };
    let bytes = serde_json::to_vec(&auth_req).unwrap();
    let mut payload = (bytes.len() as u32).to_be_bytes().to_vec();
    payload.extend_from_slice(&bytes);

    tls_stream.write_all(&payload).await.unwrap();

    let mut len_buf = [0u8; 4];
    tls_stream.read_exact(&mut len_buf).await.unwrap();
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut resp_buf = vec![0u8; len];
    tls_stream.read_exact(&mut resp_buf).await.unwrap();

    let resp: serde_json::Value = serde_json::from_slice(&resp_buf).unwrap();
    let vote_granted = resp["response"]["RequestVote"]["Ok"]["vote_granted"]
        .as_bool()
        .unwrap_or(true);
    assert!(!vote_granted);
}

#[tokio::test]
async fn test_membership_add_non_voter() {
    let mut cluster = bootstrap_4_nodes(get_dynamic_base_port()).await.unwrap();
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

    let add_resp = cluster
        .nodes
        .get_mut(&0)
        .unwrap()
        .send_command(json!({
            "command": "AddNodeAsNonVoter",
            "peer_id": 3
        }))
        .await
        .unwrap();
    assert!(add_resp["success"].as_bool().unwrap());
    sleep(Duration::from_millis(300)).await;

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

    sleep(Duration::from_millis(800)).await;
    let resp_latest = cluster
        .nodes
        .get_mut(&3)
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
async fn test_membership_promote_non_voter_success() {
    let mut cluster = bootstrap_4_nodes(get_dynamic_base_port()).await.unwrap();
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

    cluster
        .nodes
        .get_mut(&0)
        .unwrap()
        .send_command(json!({
            "command": "AddNodeAsNonVoter",
            "peer_id": 3
        }))
        .await
        .unwrap();
    sleep(Duration::from_millis(300)).await;

    let tx_id = TxId::new();
    cluster.nodes.get_mut(&0).unwrap().send_command(json!({
        "command": "AppendCommit",
        "tx_id": tx_id.to_string(),
        "version": 1,
        "principal": "spiffe://test/trust-domain/tenant/test/ns/default/sa/svc/nf/test/instance/0",
        "encrypted_blob": "aabbcc",
        "audit_paths": ["/a"]
    })).await.unwrap();
    sleep(Duration::from_millis(500)).await;

    let prom_resp = cluster
        .nodes
        .get_mut(&0)
        .unwrap()
        .send_command(json!({
            "command": "PromoteNode",
            "peer_id": 3
        }))
        .await
        .unwrap();
    assert!(prom_resp["success"].as_bool().unwrap());
    sleep(Duration::from_millis(500)).await;

    cluster.partition(0, 2);
    cluster.partition(1, 2);
    cluster.partition(0, 3);
    cluster.partition(1, 3);
    cluster.partition(2, 3);
    cluster.partition(3, 2);
    sleep(Duration::from_millis(200)).await;

    let tx_id2 = TxId::new();
    let resp = cluster.nodes.get_mut(&0).unwrap().send_command(json!({
        "command": "AppendCommit",
        "tx_id": tx_id2.to_string(),
        "version": 2,
        "principal": "spiffe://test/trust-domain/tenant/test/ns/default/sa/svc/nf/test/instance/0",
        "encrypted_blob": "aabbcc",
        "audit_paths": ["/a"]
    })).await.unwrap();
    assert!(!resp["success"].as_bool().unwrap());

    cluster.heal(0, 2);
    cluster.heal(1, 2);
    sleep(Duration::from_millis(500)).await;

    let mut leader_id = None;
    for attempt in 0..10 {
        for i in 0..4 {
            if let Some(node) = cluster.nodes.get_mut(&i) {
                if let Ok(m) = node.send_command(json!({"command": "DumpMetrics"})).await {
                    if m["data"]["role"].as_str() == Some("Leader") {
                        leader_id = Some(i);
                        break;
                    }
                }
            }
        }
        if leader_id.is_some() {
            break;
        }
        if attempt % 2 == 0 {
            let _ = cluster
                .nodes
                .get_mut(&0)
                .unwrap()
                .send_command(json!({
                    "command": "Campaign"
                }))
                .await;
        }
        sleep(Duration::from_millis(500)).await;
    }
    let lid = leader_id.expect("No leader elected in the cluster after healing");

    let resp2 = cluster.nodes.get_mut(&lid).unwrap().send_command(json!({
        "command": "AppendCommit",
        "tx_id": tx_id2.to_string(),
        "version": 2,
        "principal": "spiffe://test/trust-domain/tenant/test/ns/default/sa/svc/nf/test/instance/0",
        "encrypted_blob": "aabbcc",
        "audit_paths": ["/a"]
    })).await.unwrap();
    assert!(
        resp2["success"].as_bool().unwrap(),
        "resp2 failed: {resp2:?}"
    );
}

#[tokio::test]
async fn test_membership_promote_non_voter_not_caught_up() {
    let mut cluster = bootstrap_4_nodes(get_dynamic_base_port()).await.unwrap();
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

    cluster
        .nodes
        .get_mut(&0)
        .unwrap()
        .send_command(json!({
            "command": "AddNodeAsNonVoter",
            "peer_id": 3
        }))
        .await
        .unwrap();
    sleep(Duration::from_millis(200)).await;

    cluster.partition(0, 3);
    cluster.partition(1, 3);
    cluster.partition(2, 3);
    sleep(Duration::from_millis(200)).await;

    let tx_id = TxId::new();
    cluster.nodes.get_mut(&0).unwrap().send_command(json!({
        "command": "AppendCommit",
        "tx_id": tx_id.to_string(),
        "version": 1,
        "principal": "spiffe://test/trust-domain/tenant/test/ns/default/sa/svc/nf/test/instance/0",
        "encrypted_blob": "aabbcc",
        "audit_paths": ["/a"]
    })).await.unwrap();
    sleep(Duration::from_millis(300)).await;

    let prom_resp = cluster
        .nodes
        .get_mut(&0)
        .unwrap()
        .send_command(json!({
            "command": "PromoteNode",
            "peer_id": 3
        }))
        .await
        .unwrap();
    assert!(!prom_resp["success"].as_bool().unwrap());
}

#[tokio::test]
async fn test_membership_remove_voter() {
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

    let rem_resp = cluster
        .nodes
        .get_mut(&0)
        .unwrap()
        .send_command(json!({
            "command": "RemoveNode",
            "peer_id": 2
        }))
        .await
        .unwrap();
    assert!(rem_resp["success"].as_bool().unwrap());

    cluster.kill_node(2).await;
    sleep(Duration::from_millis(500)).await;

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
async fn test_membership_epoch_monotonicity() {
    let mut cluster = TestCluster::new(20000);
    cluster.base_port = get_dynamic_base_port();
    cluster.bootstrap().await.unwrap();
    sleep(Duration::from_millis(500)).await;

    let node_0_port = cluster.base_port;
    let identity = cluster.identities.get(&1).unwrap().clone();
    let mut tls_stream = match connect_raw_tls(&format!("127.0.0.1:{node_0_port}"), &identity).await
    {
        Ok(s) => s,
        Err(e) => {
            for nid in 0..3 {
                let err_path = cluster.certs_dir.join(format!("node_{nid}.err"));
                if let Ok(err_content) = std::fs::read_to_string(&err_path) {
                    println!("--- NODE {nid} STDERR --- \n{err_content}");
                } else {
                    println!("--- NODE {nid} STDERR (not found/unread) ---");
                }
            }
            panic!("failed to connect to 127.0.0.1:{node_0_port}: {e}");
        }
    };

    let stale_membership = ClusterMembership {
        cluster_id: "tcp-test-cluster".to_string(),
        node_id: 0,
        voting_members: vec![0, 1, 2],
        non_voting_members: vec![],
        old_voting_members: None,
        removed_members: vec![],
        epoch: 0,
    };
    let op = ConsensusOp::ChangeMembership {
        membership: stale_membership,
    };
    let entry = LogEntry {
        index: 1,
        term: 1,
        op,
    };
    let req = AppendEntriesRequest {
        term: 1,
        leader_id: 0,
        prev_log_index: 0,
        prev_log_term: 0,
        entries: vec![entry],
        leader_commit: 1,
    };
    let auth_req = AuthenticatedRequest {
        sender_node_id: 1,
        target_node_id: 0,
        cluster_id: "tcp-test-cluster".to_string(),
        spiffe_id: None,
        client_cert_pem: None,
        request: json!({ "AppendEntries": req }),
    };

    let bytes = serde_json::to_vec(&auth_req).unwrap();
    let mut payload = (bytes.len() as u32).to_be_bytes().to_vec();
    payload.extend_from_slice(&bytes);

    tls_stream.write_all(&payload).await.unwrap();

    let mut len_buf = [0u8; 4];
    tls_stream.read_exact(&mut len_buf).await.unwrap();
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut resp_buf = vec![0u8; len];
    tls_stream.read_exact(&mut resp_buf).await.unwrap();

    let resp: serde_json::Value = serde_json::from_slice(&resp_buf).unwrap();
    let err_str = resp["response"]["AppendEntries"].to_string();
    assert!(
        err_str.contains("stale epoch") || err_str.contains("Err") || err_str.contains("redacted")
    );
}
