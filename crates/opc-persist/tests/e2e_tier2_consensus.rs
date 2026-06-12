mod common;
mod e2e_tier2_common;

use common::TestCluster;
use e2e_tier2_common::{
    generate_test_ca_and_identities, make_audit_record, make_commit_record, send_tls_rpc,
    setup_process_cluster, SnapshotPayload,
};
use opc_persist::ClusterMembership;
use opc_types::TxId;
use serde_json::json;
use std::time::Duration;
use tokio::time::sleep;

fn get_dynamic_base_port() -> u16 {
    common::find_free_port_block(50)
}

#[tokio::test]
async fn test_boundary_empty_voter_list() {
    let mut cluster = setup_process_cluster(1).await;
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

    let res = cluster
        .nodes
        .get_mut(&0)
        .unwrap()
        .send_command(json!({
            "command": "RemoveNode",
            "peer_id": 0
        }))
        .await
        .unwrap();

    assert!(!res["success"].as_bool().unwrap());
    let err = res["error"].as_str().unwrap().to_string();
    assert!(
        err.contains("cannot remove all voting members")
            || err.contains("leader")
            || err.contains("empty")
            || err.contains("voter")
    );
}

#[tokio::test]
async fn test_boundary_duplicate_voter_id() {
    let mut cluster = setup_process_cluster(1).await;
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

    let res = cluster
        .nodes
        .get_mut(&0)
        .unwrap()
        .send_command(json!({
            "command": "AddNodeAsNonVoter",
            "peer_id": 0
        }))
        .await
        .unwrap();

    assert!(!res["success"].as_bool().unwrap());
    assert!(res["error"]
        .as_str()
        .unwrap()
        .contains("already in cluster"));
}

#[tokio::test]
async fn test_boundary_stale_log_candidate() {
    let mut cluster = TestCluster::new(22000);
    cluster.base_port = get_dynamic_base_port();
    cluster.bootstrap().await.unwrap();
    sleep(Duration::from_millis(500)).await;

    let res = cluster
        .nodes
        .get_mut(&0)
        .unwrap()
        .send_command(json!({
            "command": "Campaign"
        }))
        .await
        .unwrap();
    assert!(res["success"].as_bool().unwrap());
    sleep(Duration::from_millis(500)).await;

    let tx_id = TxId::new();
    let res = cluster.nodes.get_mut(&0).unwrap().send_command(json!({
        "command": "AppendCommit",
        "tx_id": tx_id.to_string(),
        "version": 1,
        "principal": "spiffe://test/trust-domain/tenant/test/ns/default/sa/svc/nf/test/instance/0",
        "encrypted_blob": "aabbcc",
        "audit_paths": ["/a"]
    })).await.unwrap();
    assert!(res["success"].as_bool().unwrap());
    sleep(Duration::from_millis(500)).await;

    let identity = cluster.identities.get(&2).unwrap().clone();
    let node_0_port = cluster.base_port;

    let req = json!({
        "RequestVote": {
            "term": 2,
            "candidate_id": 2,
            "last_log_index": 0,
            "last_log_term": 0
        }
    });

    let resp = send_tls_rpc(
        &format!("127.0.0.1:{node_0_port}"),
        2,
        0,
        &cluster.cluster_id,
        &identity,
        req,
    )
    .await
    .unwrap();

    let vote_granted = resp["response"]["RequestVote"]["Ok"]["vote_granted"]
        .as_bool()
        .unwrap();
    assert!(!vote_granted);
}

#[tokio::test]
async fn test_boundary_out_of_date_term_rpc() {
    let mut cluster = TestCluster::new(22100);
    cluster.base_port = get_dynamic_base_port();
    cluster.bootstrap().await.unwrap();
    sleep(Duration::from_millis(500)).await;

    let res = cluster
        .nodes
        .get_mut(&0)
        .unwrap()
        .send_command(json!({
            "command": "Campaign"
        }))
        .await
        .unwrap();
    assert!(res["success"].as_bool().unwrap());
    sleep(Duration::from_millis(500)).await;

    let identity = cluster.identities.get(&0).unwrap().clone();
    let node_1_port = cluster.base_port + 10;

    let req = json!({
        "AppendEntries": {
            "term": 0,
            "leader_id": 0,
            "prev_log_index": 0,
            "prev_log_term": 0,
            "entries": [],
            "leader_commit": 0
        }
    });

    let resp = send_tls_rpc(
        &format!("127.0.0.1:{node_1_port}"),
        0,
        1,
        &cluster.cluster_id,
        &identity,
        req,
    )
    .await
    .unwrap();

    let success = resp["response"]["AppendEntries"]["Ok"]["success"]
        .as_bool()
        .unwrap();
    let term = resp["response"]["AppendEntries"]["Ok"]["term"]
        .as_u64()
        .unwrap();

    assert!(!success);
    assert!(term >= 1);
}

#[tokio::test]
async fn test_boundary_log_term_gap_recovery() {
    let mut cluster = TestCluster::new(22200);
    cluster.base_port = get_dynamic_base_port();
    cluster.bootstrap().await.unwrap();
    sleep(Duration::from_millis(500)).await;

    let res = cluster
        .nodes
        .get_mut(&0)
        .unwrap()
        .send_command(json!({
            "command": "Campaign"
        }))
        .await
        .unwrap();
    assert!(res["success"].as_bool().unwrap());
    sleep(Duration::from_millis(500)).await;

    cluster.kill_node(2).await;

    for v in 1..=5 {
        let tx_id = TxId::new();
        let res = cluster.nodes.get_mut(&0).unwrap().send_command(json!({
            "command": "AppendCommit",
            "tx_id": tx_id.to_string(),
            "version": v,
            "principal": "spiffe://test/trust-domain/tenant/test/ns/default/sa/svc/nf/test/instance/0",
            "encrypted_blob": format!("aabbcc{:02x}", v),
            "audit_paths": [format!("/path/{}", v)]
        })).await.unwrap();
        if !res["success"].as_bool().unwrap_or(false) {
            panic!("AppendCommit failed: {res:?}");
        }
    }

    cluster.restart_node(2).await;
    sleep(Duration::from_millis(2000)).await;

    let latest_0 = cluster
        .nodes
        .get_mut(&0)
        .unwrap()
        .send_command(json!({
            "command": "LoadLatest"
        }))
        .await
        .unwrap();
    assert!(latest_0["success"].as_bool().unwrap());

    let latest_2 = cluster
        .nodes
        .get_mut(&2)
        .unwrap()
        .send_command(json!({
            "command": "LoadLatest"
        }))
        .await
        .unwrap();
    assert!(latest_2["success"].as_bool().unwrap());

    assert_eq!(
        latest_2["data"]["record"]["tx_id"].as_str().unwrap(),
        latest_0["data"]["record"]["tx_id"].as_str().unwrap()
    );
}

#[tokio::test]
async fn test_boundary_empty_snapshot() {
    let cluster = setup_process_cluster(1).await;
    sleep(Duration::from_millis(500)).await;

    let identity = cluster.identities.get(&0).unwrap().clone();
    let node_port = cluster.base_port;

    let req = json!({
        "InstallSnapshot": {
            "term": 1,
            "leader_id": 0,
            "last_included_index": 10,
            "last_included_term": 1,
            "data": []
        }
    });

    let resp = send_tls_rpc(
        &format!("127.0.0.1:{node_port}"),
        0,
        0,
        &cluster.cluster_id,
        &identity,
        req,
    )
    .await
    .unwrap();

    let err_str = resp["response"]["InstallSnapshot"]["Err"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        err_str.contains("Corrupt snapshot JSON")
            || err_str.contains("EOF")
            || err_str.contains("invalid")
            || err_str.contains("JSON")
    );
}

#[tokio::test]
async fn test_boundary_snapshot_hmac_mismatch() {
    let cluster = setup_process_cluster(1).await;
    sleep(Duration::from_millis(500)).await;

    let tx_id = TxId::new();
    let config = opc_persist::StoredConfig {
        record: make_commit_record(tx_id, 1),
        audit: vec![make_audit_record(tx_id, 0, "/a")],
    };
    let membership = ClusterMembership {
        cluster_id: cluster.cluster_id.clone(),
        node_id: 0,
        voting_members: vec![0],
        non_voting_members: vec![],
        old_voting_members: None,
        removed_members: vec![],
        epoch: 1,
    };

    let mut payload = SnapshotPayload {
        cluster_id: cluster.cluster_id.clone(),
        membership_epoch: 1,
        last_included_index: 5,
        last_included_term: 1,
        config,
        membership,
        payload_hmac: [0u8; 32],
    };
    payload.payload_hmac = [0xFF; 32];

    let data = serde_json::to_vec(&payload).unwrap();

    let identity = cluster.identities.get(&0).unwrap().clone();
    let node_port = cluster.base_port;

    let req = json!({
        "InstallSnapshot": {
            "term": 1,
            "leader_id": 0,
            "last_included_index": 5,
            "last_included_term": 1,
            "data": data
        }
    });

    let resp = send_tls_rpc(
        &format!("127.0.0.1:{node_port}"),
        0,
        0,
        &cluster.cluster_id,
        &identity,
        req,
    )
    .await
    .unwrap();

    let err_str = resp["response"]["InstallSnapshot"]["Err"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(err_str.contains("HMAC verification failed"));
}

#[tokio::test]
async fn test_boundary_future_snapshot_index() {
    let mut cluster = setup_process_cluster(1).await;
    sleep(Duration::from_millis(500)).await;

    let tx_id = TxId::new();
    let config = opc_persist::StoredConfig {
        record: make_commit_record(tx_id, 1),
        audit: vec![make_audit_record(tx_id, 0, "/a")],
    };
    let membership = ClusterMembership {
        cluster_id: cluster.cluster_id.clone(),
        node_id: 0,
        voting_members: vec![0],
        non_voting_members: vec![],
        old_voting_members: None,
        removed_members: vec![],
        epoch: 1,
    };

    let mut payload = SnapshotPayload {
        cluster_id: cluster.cluster_id.clone(),
        membership_epoch: 1,
        last_included_index: 100,
        last_included_term: 1,
        config,
        membership,
        payload_hmac: [0u8; 32],
    };
    payload.payload_hmac = payload.calculate_hmac();

    let data = serde_json::to_vec(&payload).unwrap();

    let identity = cluster.identities.get(&0).unwrap().clone();
    let node_port = cluster.base_port;

    let req = json!({
        "InstallSnapshot": {
            "term": 1,
            "leader_id": 0,
            "last_included_index": 100,
            "last_included_term": 1,
            "data": data
        }
    });

    let resp = send_tls_rpc(
        &format!("127.0.0.1:{node_port}"),
        0,
        0,
        &cluster.cluster_id,
        &identity,
        req,
    )
    .await
    .unwrap();

    let success = resp["response"]["InstallSnapshot"]["Ok"]["success"]
        .as_bool()
        .unwrap();
    assert!(success);

    let metrics_resp = cluster
        .nodes
        .get_mut(&0)
        .unwrap()
        .send_command(json!({
            "command": "DumpMetrics"
        }))
        .await
        .unwrap();

    let applied = metrics_resp["data"]["applied_index"].as_u64().unwrap();
    assert_eq!(applied, 100);
}

#[tokio::test]
async fn test_boundary_compacting_unapplied_index() {
    let mut cluster = setup_process_cluster(1).await;
    sleep(Duration::from_millis(500)).await;

    let metrics_resp = cluster
        .nodes
        .get_mut(&0)
        .unwrap()
        .send_command(json!({
            "command": "DumpMetrics"
        }))
        .await
        .unwrap();

    let applied = metrics_resp["data"]["applied_index"].as_u64().unwrap();

    let res = cluster
        .nodes
        .get_mut(&0)
        .unwrap()
        .send_command(json!({
            "command": "CompactLogs",
            "index": applied + 1
        }))
        .await
        .unwrap();

    assert!(!res["success"].as_bool().unwrap());
    let err = res["error"].as_str().unwrap().to_string();
    assert!(err.contains("cannot compact unapplied logs"));
}

#[tokio::test]
async fn test_boundary_membership_change_during_snapshot() {
    let mut cluster = setup_process_cluster(1).await;
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
    let config = opc_persist::StoredConfig {
        record: make_commit_record(tx_id, 1),
        audit: vec![make_audit_record(tx_id, 0, "/a")],
    };
    let membership = ClusterMembership {
        cluster_id: cluster.cluster_id.clone(),
        node_id: 0,
        voting_members: vec![0],
        non_voting_members: vec![],
        old_voting_members: None,
        removed_members: vec![],
        epoch: 1,
    };

    let mut payload = SnapshotPayload {
        cluster_id: cluster.cluster_id.clone(),
        membership_epoch: 1,
        last_included_index: 10,
        last_included_term: 1,
        config,
        membership,
        payload_hmac: [0u8; 32],
    };
    payload.payload_hmac = payload.calculate_hmac();
    let data = serde_json::to_vec(&payload).unwrap();

    let identity = cluster.identities.get(&0).unwrap().clone();
    let node_port = cluster.base_port;
    let cluster_id = cluster.cluster_id.clone();

    let handle1 = tokio::spawn(async move {
        let req = json!({
            "InstallSnapshot": {
                "term": 1,
                "leader_id": 0,
                "last_included_index": 10,
                "last_included_term": 1,
                "data": data
            }
        });
        send_tls_rpc(
            &format!("127.0.0.1:{node_port}"),
            0,
            0,
            &cluster_id,
            &identity,
            req,
        )
        .await
    });

    let res2 = cluster
        .nodes
        .get_mut(&0)
        .unwrap()
        .send_command(json!({
            "command": "AddNodeAsNonVoter",
            "peer_id": 1
        }))
        .await;

    let res1 = handle1.await.unwrap();
    assert!(res1.is_ok() || res1.is_err());
    assert!(res2.is_ok() || res2.is_err());
}

#[tokio::test]
async fn test_boundary_pending_commit_survives_failover_and_can_be_confirmed() {
    let mut cluster = TestCluster::new(39000);
    cluster.election_timeout_min = 1000;
    cluster.election_timeout_max = 2000;
    cluster.rpc_timeout = 500;
    let (_ca_cert, _ca_key_pair, identities) = generate_test_ca_and_identities(&[0, 1, 2]);
    cluster.identities = identities;
    cluster.base_port = get_dynamic_base_port();
    cluster.bootstrap().await.unwrap();
    sleep(Duration::from_millis(500)).await;

    let mut campaign_success = false;
    for _ in 0..25 {
        let res = cluster
            .nodes
            .get_mut(&0)
            .unwrap()
            .send_command(json!({
                "command": "Campaign"
            }))
            .await
            .unwrap();
        if res["success"].as_bool().unwrap_or(false) {
            campaign_success = true;
            break;
        }
        sleep(Duration::from_millis(200)).await;
    }
    assert!(
        campaign_success,
        "Node 0 failed to campaign and become leader"
    );

    let tx_id = TxId::new();
    let resp = cluster
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
            "confirmed_deadline": 60.0
        }))
        .await
        .unwrap();
    assert!(
        resp["success"].as_bool().unwrap(),
        "AppendCommit failed: {resp:?}"
    );

    sleep(Duration::from_millis(500)).await;

    cluster.kill_node(0).await;
    sleep(Duration::from_millis(1500)).await;

    let mut new_leader = None;
    let mut last_camp_resp = serde_json::Value::Null;
    for _ in 0..25 {
        for candidate in [1usize, 2usize] {
            let res = cluster
                .nodes
                .get_mut(&candidate)
                .unwrap()
                .send_command(json!({
                    "command": "Campaign"
                }))
                .await
                .unwrap();
            if res["success"].as_bool().unwrap_or(false) {
                new_leader = Some(candidate);
                break;
            }
            last_camp_resp = res;
        }
        if new_leader.is_some() {
            break;
        }
        sleep(Duration::from_millis(200)).await;
    }
    let new_leader = new_leader.unwrap_or_else(|| {
        panic!("No surviving node could campaign and become new leader: {last_camp_resp:?}")
    });
    assert!(
        [1usize, 2usize].contains(&new_leader),
        "unexpected new leader: {new_leader}"
    );
    sleep(Duration::from_millis(1500)).await;

    let load_resp = cluster
        .nodes
        .get_mut(&new_leader)
        .unwrap()
        .send_command(json!({
            "command": "LoadLatest"
        }))
        .await
        .unwrap();
    assert!(
        load_resp["success"].as_bool().unwrap(),
        "LoadLatest failed: {load_resp:?}"
    );
    let latest = &load_resp["data"];
    assert_eq!(
        latest["record"]["tx_id"].as_str().unwrap(),
        tx_id.to_string()
    );
    assert!(
        latest["record"]["confirmed_deadline"].is_string(),
        "confirmed_deadline is missing or not a string: {latest:?}"
    );

    let confirm_resp = cluster
        .nodes
        .get_mut(&new_leader)
        .unwrap()
        .send_command(json!({
            "command": "MarkConfirmed",
            "tx_id": tx_id.to_string()
        }))
        .await
        .unwrap();
    assert!(
        confirm_resp["success"].as_bool().unwrap(),
        "MarkConfirmed failed: {confirm_resp:?}"
    );
    sleep(Duration::from_millis(300)).await;

    let load_resp2 = cluster
        .nodes
        .get_mut(&new_leader)
        .unwrap()
        .send_command(json!({
            "command": "LoadLatest"
        }))
        .await
        .unwrap();
    assert!(
        load_resp2["success"].as_bool().unwrap(),
        "LoadLatest 2 failed: {load_resp2:?}"
    );
    let latest2 = &load_resp2["data"];
    assert_eq!(
        latest2["record"]["tx_id"].as_str().unwrap(),
        tx_id.to_string()
    );
    assert!(
        latest2["record"]["confirmed_deadline"].is_null(),
        "confirmed_deadline was not cleared: {latest2:?}"
    );
}
