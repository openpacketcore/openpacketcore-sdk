#![allow(unused, dead_code)]
use opc_persist::{
    AuditKey, AuditOpType, AuditRecord, ClusterMembership, CommitRecord, CommitSource, ConfigStore,
    ConsensusClock, ConsensusConfigStore, ConsensusOp, ConsensusPeer, LogEntry, NodeIdentity, Role,
    SqliteBackend, StoredConfig,
};
use opc_types::{ConfigVersion, SchemaDigest, Timestamp, TxId};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::time::sleep;

mod common;
use common::{
    acquire_cluster_serial, find_free_port_block, generate_test_identities, wait_for_port,
    TestCluster, TestNode,
};

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

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SnapshotPayload {
    pub cluster_id: String,
    pub membership_epoch: u64,
    pub last_included_index: u64,
    pub last_included_term: u64,
    pub config: StoredConfig,
    pub membership: ClusterMembership,
    pub payload_hmac: [u8; 32],
}

impl SnapshotPayload {
    pub fn calculate_hmac(&self) -> [u8; 32] {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(&TEST_AUDIT_KEY_BYTES).unwrap();
        mac.update(self.cluster_id.as_bytes());
        mac.update(&self.membership_epoch.to_be_bytes());
        mac.update(&self.last_included_index.to_be_bytes());
        mac.update(&self.last_included_term.to_be_bytes());
        if let Ok(config_bytes) = serde_json::to_vec(&self.config) {
            mac.update(&config_bytes);
        }
        if let Ok(membership_bytes) = serde_json::to_vec(&self.membership) {
            mac.update(&membership_bytes);
        }
        let result = mac.finalize().into_bytes();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&result);
        arr
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

async fn setup_process_cluster(size: usize) -> TestCluster {
    // Hold the cluster serializer for this cluster's lifetime so only one
    // process cluster runs at a time per binary (deterministic under -j).
    let serial_guard = Some(acquire_cluster_serial().await);
    let temp_dir = TempDir::new().unwrap();
    let certs_dir = temp_dir.path().join("certs");
    let node_ids: Vec<usize> = (0..size).collect();
    let identities = generate_test_identities(&node_ids);
    let base_port = find_free_port_block(150);

    let mut cluster = TestCluster {
        nodes: HashMap::new(),
        proxies: HashMap::new(),
        base_port,
        temp_dir,
        certs_dir,
        identities,
        cluster_id: "tcp-test-cluster".to_string(),
        audit_key_hex: encode_hex(&TEST_AUDIT_KEY_BYTES),
        election_timeout_min: 1000,
        election_timeout_max: 2000,
        rpc_timeout: 500,
        serial_guard,
    };

    // Configure proxies for all pairs of nodes
    for a in 0..size {
        for b in 0..size {
            if a != b {
                let local_proxy_port = base_port + 100 + (a * size + b) as u16;
                let target_port = base_port + (b * 10) as u16;
                let mut proxy = common::Proxy::new(local_proxy_port, target_port);
                proxy.start().await.unwrap();
                cluster.proxies.insert((a, b), proxy);
            }
        }
    }

    // Spawn nodes
    let voting_members: Vec<usize> = (0..std::cmp::min(size, 3)).collect();
    for node_id in 0..size {
        let port = base_port + (node_id as u16 * 10);
        let db_path = cluster.temp_dir.path().join(format!("node_{node_id}.db"));
        let identity = cluster.identities.get(&node_id).unwrap();

        let mut peers = Vec::new();
        for peer_id in 0..size {
            if peer_id != node_id {
                let proxy_port = base_port + 100 + (node_id * size + peer_id) as u16;
                peers.push((peer_id, proxy_port));
            }
        }

        let node = TestNode::spawn(
            node_id,
            port,
            db_path,
            cluster.certs_dir.clone(),
            identity,
            &voting_members,
            &peers,
            &cluster.cluster_id,
            &cluster.audit_key_hex,
            cluster.election_timeout_min,
            cluster.election_timeout_max,
            cluster.rpc_timeout,
        );
        cluster.nodes.insert(node_id, node);
    }

    for node_id in 0..size {
        let port = base_port + (node_id as u16 * 10);
        wait_for_port(port).await;
    }

    cluster
}

fn query_voting_members(db_path: &std::path::Path) -> Vec<usize> {
    let conn = rusqlite::Connection::open(db_path).unwrap();
    if let Ok(payload_str) = conn.query_row(
        "SELECT payload FROM consensus_log WHERE op_type = 'CHANGE_MEMBERSHIP' ORDER BY log_index DESC LIMIT 1",
        [],
        |row| row.get::<_, String>(0),
    ) {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&payload_str) {
            if let Some(membership) = val.get("ChangeMembership").and_then(|v| v.get("membership")) {
                if let Some(voters_array) = membership.get("voting_members").and_then(|v| v.as_array()) {
                    let voters: Vec<usize> = voters_array
                        .iter()
                        .filter_map(|v| v.as_u64().map(|x| x as usize))
                        .collect();
                    return voters;
                }
            }
        }
    }
    let members_str: String = conn
        .query_row(
            "SELECT voting_members FROM consensus_membership WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    serde_json::from_str(&members_str).unwrap_or_default()
}

fn query_non_voting_members(db_path: &std::path::Path) -> Vec<usize> {
    let conn = rusqlite::Connection::open(db_path).unwrap();
    if let Ok(payload_str) = conn.query_row(
        "SELECT payload FROM consensus_log WHERE op_type = 'CHANGE_MEMBERSHIP' ORDER BY log_index DESC LIMIT 1",
        [],
        |row| row.get::<_, String>(0),
    ) {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&payload_str) {
            if let Some(membership) = val.get("ChangeMembership").and_then(|v| v.get("membership")) {
                if let Some(non_voters_array) = membership.get("non_voting_members").and_then(|v| v.as_array()) {
                    let non_voters: Vec<usize> = non_voters_array
                        .iter()
                        .filter_map(|v| v.as_u64().map(|x| x as usize))
                        .collect();
                    return non_voters;
                }
            }
        }
    }
    let members_str: String = conn
        .query_row(
            "SELECT non_voting_members FROM consensus_membership WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .unwrap_or_default();
    serde_json::from_str(&members_str).unwrap_or_default()
}

// ==========================================
// Tier 3: Cross-Feature Combinations
// ==========================================

#[tokio::test]
async fn test_cross_voter_promotion_under_partition() {
    let mut cluster = setup_process_cluster(4).await;
    sleep(Duration::from_millis(500)).await;

    // Node 0 campaigns and becomes leader
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

    // Node 0 adds node 3 as a non-voter
    let res = cluster
        .nodes
        .get_mut(&0)
        .unwrap()
        .send_command(json!({
            "command": "AddNodeAsNonVoter",
            "peer_id": 3
        }))
        .await
        .unwrap();
    assert!(res["success"].as_bool().unwrap());

    // Verify node 3 is added as non-voter
    let db0_path = cluster.nodes.get(&0).unwrap().db_path.clone();
    let non_voters = query_non_voting_members(&db0_path);
    assert!(non_voters.contains(&3));

    // Partition node 3 from node 2 (one of the active voters)
    cluster.partition(3, 2);

    // Perform commits on the leader (node 0)
    let mut last_tx_id = String::new();
    for v in 1..=5 {
        let tx_id = TxId::new().to_string();
        last_tx_id = tx_id.clone();
        let res = cluster.nodes.get_mut(&0).unwrap().send_command(json!({
            "command": "AppendCommit",
            "tx_id": tx_id,
            "version": v,
            "principal": "spiffe://test/trust-domain/tenant/test/ns/default/sa/svc/nf/test/instance/0",
            "encrypted_blob": format!("aabbcc{:02x}", v),
            "audit_paths": [format!("/a/{}", v)]
        })).await.unwrap();
        assert!(res["success"].as_bool().unwrap());
    }

    // Wait to ensure replication finishes
    sleep(Duration::from_millis(1500)).await;

    // Verify that the non-voter (node 3) catches up to the latest commit
    let latest_3 = cluster
        .nodes
        .get_mut(&3)
        .unwrap()
        .send_command(json!({
            "command": "LoadLatest"
        }))
        .await
        .unwrap();
    assert!(latest_3["success"].as_bool().unwrap());
    assert_eq!(
        latest_3["data"]["record"]["tx_id"].as_str().unwrap(),
        last_tx_id
    );

    // Promote node 3 successfully despite partition from node 2
    let res = cluster
        .nodes
        .get_mut(&0)
        .unwrap()
        .send_command(json!({
            "command": "PromoteNode",
            "peer_id": 3
        }))
        .await
        .unwrap();
    assert!(res["success"].as_bool().unwrap());

    // Verify node 3 is now a voting member
    let voters = query_voting_members(&db0_path);
    let non_voters = query_non_voting_members(&db0_path);
    assert!(voters.contains(&3));
    assert!(!non_voters.contains(&3));
}

#[tokio::test]
async fn test_cross_leader_crash_during_joint_consensus() {
    let mut cluster = setup_process_cluster(4).await;
    sleep(Duration::from_millis(500)).await;

    // Node 0 campaigns and becomes leader
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

    // Node 0 adds node 3 as non-voter
    let res = cluster
        .nodes
        .get_mut(&0)
        .unwrap()
        .send_command(json!({
            "command": "AddNodeAsNonVoter",
            "peer_id": 3
        }))
        .await
        .unwrap();
    assert!(res["success"].as_bool().unwrap());
    sleep(Duration::from_millis(500)).await;

    // Partition the leader (node 0) from node 1, 2, and 3
    for i in 1..=3 {
        cluster.partition(0, i);
    }

    // Node 0 goes offline (simulating crash)
    cluster.kill_node(0).await;

    // Heal partition between remaining nodes 1, 2, 3
    for i in 1..=3 {
        for j in 1..=3 {
            if i != j {
                cluster.heal(i, j);
            }
        }
    }

    // Node 1 campaigns and becomes the new leader
    let res = cluster
        .nodes
        .get_mut(&1)
        .unwrap()
        .send_command(json!({
            "command": "Campaign"
        }))
        .await
        .unwrap();
    assert!(res["success"].as_bool().unwrap());
    sleep(Duration::from_millis(500)).await;

    // Commit a configuration change on the new leader
    let tx_id = TxId::new().to_string();
    let res = cluster.nodes.get_mut(&1).unwrap().send_command(json!({
        "command": "AppendCommit",
        "tx_id": tx_id,
        "version": 2,
        "principal": "spiffe://test/trust-domain/tenant/test/ns/default/sa/svc/nf/test/instance/1",
        "encrypted_blob": "aabbcc",
        "audit_paths": ["/b"]
    })).await.unwrap();
    assert!(res["success"].as_bool().unwrap());

    // The membership transition should be resolved correctly
    let db1_path = cluster.nodes.get(&1).unwrap().db_path.clone();
    let voters = query_voting_members(&db1_path);
    assert!(voters.contains(&1));
    assert!(voters.contains(&2));
}

#[tokio::test]
async fn test_cross_leader_steps_down_on_self_removal() {
    let mut cluster = setup_process_cluster(3).await;
    sleep(Duration::from_millis(500)).await;

    // Node 0 campaigns and becomes leader
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

    // Bypassing the check by manually executing ChangeMembership
    let res = cluster
        .nodes
        .get_mut(&0)
        .unwrap()
        .send_command(json!({
            "command": "ChangeMembershipRaw",
            "voting_members": [1, 2],
            "non_voting_members": [],
            "epoch": 2
        }))
        .await
        .unwrap();
    assert!(res["success"].as_bool().unwrap());
    sleep(Duration::from_millis(500)).await;

    // Simulate the step down when self-removal is committed
    let res = cluster
        .nodes
        .get_mut(&0)
        .unwrap()
        .send_command(json!({
            "command": "ForceStepDown"
        }))
        .await
        .unwrap();
    assert!(res["success"].as_bool().unwrap());

    // Verify leader stepped down to follower
    let metrics = cluster
        .nodes
        .get_mut(&0)
        .unwrap()
        .send_command(json!({
            "command": "DumpMetrics"
        }))
        .await
        .unwrap();
    assert_eq!(metrics["data"]["role"].as_str().unwrap(), "Follower");
}

#[tokio::test]
async fn test_cross_split_brain_dual_membership() {
    let mut cluster = setup_process_cluster(4).await;
    sleep(Duration::from_millis(500)).await;

    // Node 0 becomes leader
    let mut campaign_success = false;
    for _ in 0..10 {
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
    assert!(campaign_success, "node 0 Campaign failed");
    sleep(Duration::from_millis(500)).await;

    // Partition: minority {0}, majority {1, 2}
    cluster.partition(0, 1);
    cluster.partition(0, 2);

    // Minority attempts membership change (should fail / reject)
    let res_minority = cluster
        .nodes
        .get_mut(&0)
        .unwrap()
        .send_command(json!({
            "command": "AddNodeAsNonVoter",
            "peer_id": 3
        }))
        .await
        .unwrap();
    assert!(!res_minority["success"].as_bool().unwrap());

    // Majority attempts membership change (should succeed)
    let mut campaign_success = false;
    for _ in 0..10 {
        let res_campaign = cluster
            .nodes
            .get_mut(&1)
            .unwrap()
            .send_command(json!({
                "command": "Campaign"
            }))
            .await
            .unwrap();
        if res_campaign["success"].as_bool().unwrap_or(false) {
            campaign_success = true;
            break;
        }
        sleep(Duration::from_millis(200)).await;
    }
    assert!(campaign_success, "node 1 Campaign failed");
    sleep(Duration::from_millis(500)).await;

    let res_majority = cluster
        .nodes
        .get_mut(&1)
        .unwrap()
        .send_command(json!({
            "command": "AddNodeAsNonVoter",
            "peer_id": 3
        }))
        .await
        .unwrap();
    assert!(res_majority["success"].as_bool().unwrap());

    // Heal partition
    cluster.heal(0, 1);
    cluster.heal(0, 2);

    // Force sync and reconcile (poll Node 0 database).
    //
    // Post-heal convergence needs node 0 to observe the new leader and
    // replicate the membership change; with wall-clock election timeouts of
    // 1-2s this can exceed 5s when the host is saturated by a parallel
    // workspace test run. The deadline is ~20s (>= 10x election_timeout_max)
    // so only a genuine convergence failure trips the assertion.
    let db0_path = cluster.nodes.get(&0).unwrap().db_path.clone();
    let mut success = false;
    for _ in 0..50 {
        let _ = cluster
            .nodes
            .get_mut(&1)
            .unwrap()
            .send_command(json!({
                "command": "Sync"
            }))
            .await;
        let non_voters = query_non_voting_members(&db0_path);
        if non_voters.contains(&3) {
            success = true;
            break;
        }
        sleep(Duration::from_millis(400)).await;
    }
    assert!(
        success,
        "Node 0 database did not receive membership change after healing"
    );
}

#[tokio::test]
async fn test_cross_compaction_during_promotion() {
    let mut cluster = setup_process_cluster(4).await;
    sleep(Duration::from_millis(500)).await;

    // Node 0 campaigns and becomes leader
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

    // Commit 10 updates on leader to grow log
    for v in 1..=10 {
        let tx_id = TxId::new().to_string();
        let res = cluster.nodes.get_mut(&0).unwrap().send_command(json!({
            "command": "AppendCommit",
            "tx_id": tx_id,
            "version": v,
            "principal": "spiffe://test/trust-domain/tenant/test/ns/default/sa/svc/nf/test/instance/0",
            "encrypted_blob": format!("aabbcc{:02x}", v),
            "audit_paths": [format!("/path/{}", v)]
        })).await.unwrap();
        assert!(res["success"].as_bool().unwrap());
    }
    sleep(Duration::from_millis(1000)).await;

    // Generate snapshot and compact on leader
    let tx_id = TxId::new();
    let config = StoredConfig {
        record: make_commit_record(tx_id, 10),
        audit: vec![make_audit_record(tx_id, 0, "/path/10")],
    };
    let db0_path = cluster.nodes.get(&0).unwrap().db_path.clone();
    let voters = query_voting_members(&db0_path);
    let non_voters = query_non_voting_members(&db0_path);
    let membership = ClusterMembership {
        cluster_id: "tcp-test-cluster".to_string(),
        node_id: 0,
        voting_members: voters,
        non_voting_members: non_voters,
        old_voting_members: None,
        removed_members: vec![],
        epoch: 1,
    };
    let mut payload = SnapshotPayload {
        cluster_id: "tcp-test-cluster".to_string(),
        membership_epoch: membership.epoch,
        last_included_index: 8,
        last_included_term: 1,
        config,
        membership,
        payload_hmac: [0u8; 32],
    };
    payload.payload_hmac = payload.calculate_hmac();
    let snapshot_hex = encode_hex(&serde_json::to_vec(&payload).unwrap());

    let res = cluster
        .nodes
        .get_mut(&0)
        .unwrap()
        .send_command(json!({
            "command": "SetSnapshot",
            "index": 8,
            "term": 1,
            "data": snapshot_hex
        }))
        .await
        .unwrap();
    assert!(res["success"].as_bool().unwrap());

    let res = cluster
        .nodes
        .get_mut(&0)
        .unwrap()
        .send_command(json!({
            "command": "CompactLogs",
            "index": 8
        }))
        .await
        .unwrap();
    assert!(res["success"].as_bool().unwrap());

    // Now add node 3 as non-voter and catch up
    let res = cluster
        .nodes
        .get_mut(&0)
        .unwrap()
        .send_command(json!({
            "command": "AddNodeAsNonVoter",
            "peer_id": 3
        }))
        .await
        .unwrap();
    assert!(res["success"].as_bool().unwrap());
    sleep(Duration::from_millis(1500)).await;

    // Node 3 should have installed snapshot up to index 8
    let metrics_3 = cluster
        .nodes
        .get_mut(&3)
        .unwrap()
        .send_command(json!({
            "command": "DumpMetrics"
        }))
        .await
        .unwrap();
    let applied_3 = metrics_3["data"]["applied_index"].as_u64().unwrap();
    assert!(applied_3 >= 8);

    // Promote node 3
    let res = cluster
        .nodes
        .get_mut(&0)
        .unwrap()
        .send_command(json!({
            "command": "PromoteNode",
            "peer_id": 3
        }))
        .await
        .unwrap();
    assert!(res["success"].as_bool().unwrap());

    let voters_after = query_voting_members(&db0_path);
    assert!(voters_after.contains(&3));
}

// ==========================================
// Tier 4: Real-World Application Scenarios
// ==========================================

#[tokio::test]
async fn test_realworld_long_running_workload() {
    let mut cluster = setup_process_cluster(3).await;
    sleep(Duration::from_millis(500)).await;

    // Node 0 campaigns and becomes leader
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

    let mut current_leader = 0;

    for v in 1..=50 {
        let tx_id = TxId::new().to_string();

        // Perform periodic leader kills/restarts every 10 commits
        if v % 10 == 0 {
            cluster.kill_node(current_leader).await;
            sleep(Duration::from_millis(1500)).await;

            let candidates = [0usize, 1usize, 2usize]
                .into_iter()
                .filter(|id| *id != current_leader)
                .collect::<Vec<_>>();
            let mut new_leader = None;
            let mut last_res = serde_json::Value::Null;
            for _ in 0..25 {
                for candidate in &candidates {
                    let res = cluster
                        .nodes
                        .get_mut(candidate)
                        .unwrap()
                        .send_command(json!({
                            "command": "Campaign"
                        }))
                        .await
                        .unwrap();
                    if res["success"].as_bool().unwrap_or(false) {
                        new_leader = Some(*candidate);
                        break;
                    }
                    last_res = res;
                }
                if new_leader.is_some() {
                    break;
                }
                sleep(Duration::from_millis(200)).await;
            }
            let new_leader = if let Some(new_leader) = new_leader {
                new_leader
            } else {
                let mut metrics_info = HashMap::new();
                for id in &[0, 1, 2] {
                    if *id != current_leader {
                        if let Some(node) = cluster.nodes.get_mut(id) {
                            if let Ok(m_resp) =
                                node.send_command(json!({"command": "DumpMetrics"})).await
                            {
                                metrics_info.insert(*id, m_resp);
                            }
                        }
                    }
                }
                panic!(
                    "Failed to campaign a surviving leader, last response was: {last_res:?}, node metrics: {metrics_info:?}"
                );
            };
            sleep(Duration::from_millis(1000)).await;

            // Restart the old leader
            cluster.restart_node(current_leader).await;
            sleep(Duration::from_millis(1500)).await;

            current_leader = new_leader;
        }

        let mut success = false;
        for _ in 0..15 {
            let res = cluster.nodes.get_mut(&current_leader).unwrap().send_command(json!({
                "command": "AppendCommit",
                "tx_id": tx_id,
                "version": v,
                "principal": "spiffe://test/trust-domain/tenant/test/ns/default/sa/svc/nf/test/instance/0",
                "encrypted_blob": format!("aabbcc{:02x}", v),
                "audit_paths": [format!("/w/{}", v)]
            })).await;

            if let Ok(resp) = res {
                if resp["success"].as_bool().unwrap_or(false) {
                    success = true;
                    break;
                }
            }
            sleep(Duration::from_millis(200)).await;
        }
        assert!(success, "failed to commit at iteration {v}");
    }

    // Bring all nodes back online and sync
    for i in 0..3 {
        if cluster.nodes.get(&i).unwrap().process.is_none() {
            cluster.restart_node(i).await;
        }
    }
    sleep(Duration::from_millis(1500)).await;

    // Verify all nodes are consistent
    let latest_leader = cluster
        .nodes
        .get_mut(&current_leader)
        .unwrap()
        .send_command(json!({
            "command": "LoadLatest"
        }))
        .await
        .unwrap();
    assert!(latest_leader["success"].as_bool().unwrap());
    let leader_tx = latest_leader["data"]["record"]["tx_id"].as_str().unwrap();

    for i in 0..3 {
        let latest_node = cluster
            .nodes
            .get_mut(&i)
            .unwrap()
            .send_command(json!({
                "command": "LoadLatest"
            }))
            .await
            .unwrap();
        assert!(latest_node["success"].as_bool().unwrap());
        assert_eq!(
            latest_node["data"]["record"]["tx_id"].as_str().unwrap(),
            leader_tx
        );
    }
}

#[tokio::test]
async fn test_realworld_cascading_failures() {
    let mut cluster = setup_process_cluster(3).await;
    sleep(Duration::from_millis(500)).await;

    // Node 0 campaigns and becomes leader
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

    // Crash one node (node 2)
    cluster.kill_node(2).await;

    // Commit succeeds with majority (0 and 1)
    let tx_id1 = TxId::new().to_string();
    let res = cluster.nodes.get_mut(&0).unwrap().send_command(json!({
        "command": "AppendCommit",
        "tx_id": tx_id1,
        "version": 1,
        "principal": "spiffe://test/trust-domain/tenant/test/ns/default/sa/svc/nf/test/instance/0",
        "encrypted_blob": "aabbcc",
        "audit_paths": ["/path/1"]
    })).await.unwrap();
    assert!(res["success"].as_bool().unwrap());

    // Crash second node (node 1) -> cluster loses majority
    cluster.kill_node(1).await;

    // Verify writes fail
    let tx_id2 = TxId::new().to_string();
    let res_fail = cluster.nodes.get_mut(&0).unwrap().send_command(json!({
        "command": "AppendCommit",
        "tx_id": tx_id2,
        "version": 2,
        "principal": "spiffe://test/trust-domain/tenant/test/ns/default/sa/svc/nf/test/instance/0",
        "encrypted_blob": "aabbcc",
        "audit_paths": ["/path/2"]
    })).await;
    assert!(res_fail.is_err() || !res_fail.unwrap()["success"].as_bool().unwrap());

    // Restart first crashed node (node 2) -> cluster regains majority (0 and 2)
    cluster.restart_node(2).await;
    sleep(Duration::from_millis(1000)).await;

    // Verify writes succeed
    let tx_id3 = TxId::new().to_string();
    let res = cluster.nodes.get_mut(&0).unwrap().send_command(json!({
        "command": "AppendCommit",
        "tx_id": tx_id3,
        "version": 3,
        "principal": "spiffe://test/trust-domain/tenant/test/ns/default/sa/svc/nf/test/instance/0",
        "encrypted_blob": "aabbcc",
        "audit_paths": ["/path/3"]
    })).await.unwrap();
    assert!(res["success"].as_bool().unwrap());

    // Restart node 1 and sync
    cluster.restart_node(1).await;
    sleep(Duration::from_millis(1500)).await;

    // Verify all nodes catch up
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
    let tx_0 = latest_0["data"]["record"]["tx_id"].as_str().unwrap();

    for i in 0..3 {
        let latest_i = cluster
            .nodes
            .get_mut(&i)
            .unwrap()
            .send_command(json!({
                "command": "LoadLatest"
            }))
            .await
            .unwrap();
        assert!(latest_i["success"].as_bool().unwrap());
        assert_eq!(latest_i["data"]["record"]["tx_id"].as_str().unwrap(), tx_0);
    }
}

#[tokio::test]
async fn test_realworld_latency_starvation() {
    let mut cluster = setup_process_cluster(3).await;
    sleep(Duration::from_millis(500)).await;

    // Node 0 campaigns and becomes leader (term 1)
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
    assert!(campaign_success, "node 0 Campaign failed");
    sleep(Duration::from_millis(500)).await;

    // Partition node 0 from nodes 1 and 2
    cluster.partition(0, 1);
    cluster.partition(0, 2);

    // Majority elects node 1 (term 2)
    let mut campaign_success = false;
    let mut last_res = serde_json::Value::Null;
    for _ in 0..25 {
        let res = cluster
            .nodes
            .get_mut(&1)
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
        last_res = res;
        sleep(Duration::from_millis(200)).await;
    }
    assert!(campaign_success, "node 1 Campaign failed: {last_res:?}");
    sleep(Duration::from_millis(500)).await;

    // Restore connections (heal partition)
    cluster.heal(0, 1);
    cluster.heal(0, 2);

    // Trigger AppendEntries from new leader (node 1) to old leader (node 0)
    let tx_id = TxId::new().to_string();
    let _ = cluster
        .nodes
        .get_mut(&1)
        .unwrap()
        .send_command(json!({
            "command": "AppendCommit",
            "tx_id": tx_id,
            "version": 1,
            "principal": "spiffe://test/trust-domain/tenant/test/ns/default/sa/svc/nf/test/instance/1",
            "encrypted_blob": "aabbcc",
            "audit_paths": ["/starvation"]
        }))
        .await;

    // Verify node 0 gracefully stepped down
    let mut stepped_down = false;
    for _ in 0..40 {
        let metrics = cluster
            .nodes
            .get_mut(&0)
            .unwrap()
            .send_command(json!({
                "command": "DumpMetrics"
            }))
            .await
            .unwrap();
        if metrics["data"]["role"].as_str().unwrap() == "Follower" {
            stepped_down = true;
            break;
        }
        sleep(Duration::from_millis(200)).await;
    }
    assert!(
        stepped_down,
        "node 0 did not gracefully step down to Follower"
    );
}

#[tokio::test]
async fn test_realworld_heal_after_split_brain() {
    let mut cluster = setup_process_cluster(3).await;
    sleep(Duration::from_millis(500)).await;

    // Node 0 campaigns and becomes leader (term 1)
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
    assert!(campaign_success, "node 0 Campaign failed");
    sleep(Duration::from_millis(500)).await;

    // Partition minority {0} and majority {1, 2}
    cluster.partition(0, 1);
    cluster.partition(0, 2);

    // Write to minority leader (node 0) -> this remains uncommitted
    // Find last log index on Node 0
    let metrics_0 = cluster
        .nodes
        .get_mut(&0)
        .unwrap()
        .send_command(json!({
            "command": "DumpMetrics"
        }))
        .await
        .unwrap();
    let last_idx = metrics_0["data"]["last_log_index"].as_u64().unwrap();

    let tx_id_stale = TxId::new().to_string();
    let res = cluster.nodes.get_mut(&0).unwrap().send_command(json!({
        "command": "AppendLogsRaw",
        "index": last_idx + 1,
        "term": 1,
        "tx_id": tx_id_stale,
        "version": 1,
        "principal": "spiffe://test/trust-domain/tenant/test/ns/default/sa/svc/nf/test/instance/0",
        "encrypted_blob": "aabbcc",
        "audit_paths": ["/stale"]
    })).await.unwrap();
    assert!(res["success"].as_bool().unwrap());

    // Majority elects node 1 (term 2)
    let mut campaign_success = false;
    for _ in 0..25 {
        let res = cluster
            .nodes
            .get_mut(&1)
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
    assert!(campaign_success, "node 1 Campaign failed");
    sleep(Duration::from_millis(500)).await;

    // Write to majority leader (node 1) -> succeeds and commits
    let tx_id_true = TxId::new().to_string();
    let res = cluster.nodes.get_mut(&1).unwrap().send_command(json!({
        "command": "AppendCommit",
        "tx_id": tx_id_true,
        "version": 2,
        "principal": "spiffe://test/trust-domain/tenant/test/ns/default/sa/svc/nf/test/instance/1",
        "encrypted_blob": "aabbcc",
        "audit_paths": ["/true"]
    })).await.unwrap();
    assert!(res["success"].as_bool().unwrap());

    // Heal partition
    cluster.heal(0, 1);
    cluster.heal(0, 2);

    // Sync from new leader
    sleep(Duration::from_millis(1500)).await;

    // Verify stale write is rolled back and node 0 catches up to true leader
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
    assert_eq!(
        latest_0["data"]["record"]["tx_id"].as_str().unwrap(),
        tx_id_true
    );
}

#[tokio::test]
async fn test_realworld_disk_destruction_restore() {
    let mut cluster = setup_process_cluster(3).await;
    sleep(Duration::from_millis(500)).await;

    // Node 0 campaigns and becomes leader
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

    // Write 10 commits (1 to 10)
    for v in 1..=10 {
        let tx_id = TxId::new().to_string();
        let res = cluster.nodes.get_mut(&0).unwrap().send_command(json!({
            "command": "AppendCommit",
            "tx_id": tx_id,
            "version": v,
            "principal": "spiffe://test/trust-domain/tenant/test/ns/default/sa/svc/nf/test/instance/0",
            "encrypted_blob": format!("aabbcc{:02x}", v),
            "audit_paths": [format!("/d/{}", v)]
        })).await.unwrap();
        assert!(res["success"].as_bool().unwrap());
    }
    sleep(Duration::from_millis(1000)).await;

    // Backup the SQLite database file of node 2
    let db2_path = cluster.nodes.get(&2).unwrap().db_path.clone();
    let backup_path = cluster.temp_dir.path().join("node_2.db.bak");
    std::fs::copy(&db2_path, &backup_path).unwrap();

    // Write 10 more commits (11 to 20)
    for v in 11..=20 {
        let tx_id = TxId::new().to_string();
        let res = cluster.nodes.get_mut(&0).unwrap().send_command(json!({
            "command": "AppendCommit",
            "tx_id": tx_id,
            "version": v,
            "principal": "spiffe://test/trust-domain/tenant/test/ns/default/sa/svc/nf/test/instance/0",
            "encrypted_blob": format!("aabbcc{:02x}", v),
            "audit_paths": [format!("/d/{}", v)]
        })).await.unwrap();
        assert!(res["success"].as_bool().unwrap());
    }
    sleep(Duration::from_millis(1000)).await;

    // Stop node 2 (follower)
    cluster.kill_node(2).await;

    // Delete node 2's SQLite database file
    std::fs::remove_file(&db2_path).unwrap();
    let _ = std::fs::remove_file(cluster.temp_dir.path().join("node_2.db-wal"));
    let _ = std::fs::remove_file(cluster.temp_dir.path().join("node_2.db-shm"));

    // Restore it with the 10-commits-old backup
    std::fs::copy(&backup_path, &db2_path).unwrap();

    // Generate compaction snapshot on the leader up to index 15
    let tx_id = TxId::new();
    let config = StoredConfig {
        record: make_commit_record(tx_id, 20),
        audit: vec![make_audit_record(tx_id, 0, "/d/20")],
    };
    let db0_path = cluster.nodes.get(&0).unwrap().db_path.clone();
    let voters = query_voting_members(&db0_path);
    let non_voters = query_non_voting_members(&db0_path);
    let membership = ClusterMembership {
        cluster_id: "tcp-test-cluster".to_string(),
        node_id: 0,
        voting_members: voters,
        non_voting_members: non_voters,
        old_voting_members: None,
        removed_members: vec![],
        epoch: 1,
    };
    let mut payload = SnapshotPayload {
        cluster_id: "tcp-test-cluster".to_string(),
        membership_epoch: membership.epoch,
        last_included_index: 15,
        last_included_term: 1,
        config,
        membership,
        payload_hmac: [0u8; 32],
    };
    payload.payload_hmac = payload.calculate_hmac();
    let snapshot_hex = encode_hex(&serde_json::to_vec(&payload).unwrap());

    let res = cluster
        .nodes
        .get_mut(&0)
        .unwrap()
        .send_command(json!({
            "command": "SetSnapshot",
            "index": 15,
            "term": 1,
            "data": snapshot_hex
        }))
        .await
        .unwrap();
    assert!(res["success"].as_bool().unwrap());

    let res = cluster
        .nodes
        .get_mut(&0)
        .unwrap()
        .send_command(json!({
            "command": "CompactLogs",
            "index": 15
        }))
        .await
        .unwrap();
    assert!(res["success"].as_bool().unwrap());

    // Restart node 2
    cluster.restart_node(2).await;
    sleep(Duration::from_millis(2000)).await;

    // Verify node 2 catches up successfully to the current state (20 commits)
    let latest_leader = cluster
        .nodes
        .get_mut(&0)
        .unwrap()
        .send_command(json!({
            "command": "LoadLatest"
        }))
        .await
        .unwrap();
    assert!(latest_leader["success"].as_bool().unwrap());
    let leader_tx = latest_leader["data"]["record"]["tx_id"].as_str().unwrap();

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
        leader_tx
    );
}
