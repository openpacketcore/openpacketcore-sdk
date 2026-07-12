mod common;

use common::{
    connect_raw_tls, generate_custom_identity, generate_test_ca_and_identities,
    wait_for_automatic_leader, AuthenticatedRequest, NodeMetricsDiagnostic, TestCluster,
};
use opc_types::TxId;
use serde_json::json;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::sleep;

fn get_dynamic_base_port() -> u16 {
    common::find_free_port_block(50)
}

#[test]
fn metrics_diagnostic_rejects_success_missing_required_fields() {
    let mut diagnostic = NodeMetricsDiagnostic::new(1);
    diagnostic.observe_response(&json!({
        "success": true,
        "data": {
            "role": "Follower",
            "term": 6,
            "election_count": 1,
            "leader_changes": 0
        }
    }));
    diagnostic.observe_response(&json!({
        "success": true,
        "data": {
            "role": "Leader",
            "term": 7,
            "election_count": 2
        }
    }));

    assert_eq!(diagnostic.role.as_deref(), Some("Follower"));
    assert_eq!(diagnostic.term, Some(6));
    assert_eq!(diagnostic.election_count, Some(1));
    assert_eq!(diagnostic.leader_changes, Some(0));
    assert_eq!(
        diagnostic.command_error.as_deref(),
        Some("DumpMetrics success response is missing required field(s): leader_changes")
    );
}

#[tokio::test]
async fn test_metrics_roles_and_terms() {
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

    let m0 = cluster
        .nodes
        .get_mut(&0)
        .unwrap()
        .send_command(json!({
            "command": "DumpMetrics"
        }))
        .await
        .unwrap();
    assert_eq!(m0["data"]["role"].as_str(), Some("Leader"));
    assert!(m0["data"]["term"].as_u64().unwrap() >= 1);

    let m1 = cluster
        .nodes
        .get_mut(&1)
        .unwrap()
        .send_command(json!({
            "command": "DumpMetrics"
        }))
        .await
        .unwrap();
    assert_eq!(m1["data"]["role"].as_str(), Some("Follower"));
}

#[tokio::test]
async fn test_metrics_election_count() {
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
    let observation = wait_for_automatic_leader(
        &mut cluster,
        &[1, 2],
        "leader failover after terminating node 0",
    )
    .await;
    let leader_id = observation.leader_id;
    let survivor_diagnostics = observation.diagnostics;
    let leader_metrics = survivor_diagnostics
        .iter()
        .find(|diagnostic| diagnostic.node_id == leader_id)
        .expect("elected leader should have a metrics diagnostic");
    let election_count = leader_metrics.election_count.unwrap_or(0);
    let leader_changes = leader_metrics.leader_changes.unwrap_or(0);
    assert!(
        election_count >= 1,
        "new leader should report at least one election; survivor diagnostics: {survivor_diagnostics:#?}"
    );
    assert!(
        leader_changes >= 1,
        "new leader should report at least one leader change; survivor diagnostics: {survivor_diagnostics:#?}"
    );
}

#[tokio::test]
async fn test_metrics_rpc_status_counters() {
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

    cluster.partition(0, 2);
    sleep(Duration::from_millis(200)).await;

    let tx_id = TxId::new();
    let _ = cluster.nodes.get_mut(&0).unwrap().send_command(json!({
        "command": "AppendCommit",
        "tx_id": tx_id.to_string(),
        "version": 1,
        "principal": "spiffe://test/trust-domain/tenant/test/ns/default/sa/svc/nf/test/instance/0",
        "encrypted_blob": "aabbcc",
        "audit_paths": ["/a"]
    })).await;

    sleep(Duration::from_millis(500)).await;

    let m = cluster
        .nodes
        .get_mut(&0)
        .unwrap()
        .send_command(json!({
            "command": "DumpMetrics"
        }))
        .await
        .unwrap();
    let rpc_failures = m["data"]["rpc_failures"].as_u64().unwrap();
    assert!(rpc_failures >= 1);
    for family in [
        "request_vote",
        "append_entries",
        "install_snapshot",
        "load_latest",
        "load_rollback",
        "timeout_now",
    ] {
        assert!(m["data"]["rpc_timeouts_by_family"][family].is_u64());
    }
    for stage in [
        "deadline_setup",
        "authentication_setup",
        "request_serialization",
        "tls_configuration",
        "tcp_connect",
        "tls_handshake",
        "request_write",
        "response_length",
        "response_body",
        "response_decode",
        "retry_backoff",
    ] {
        assert!(m["data"]["rpc_timeouts_by_stage"][stage].is_u64());
    }
}

#[tokio::test]
async fn test_metrics_label_hygiene() {
    let mut cluster = TestCluster::new(20000);
    cluster.base_port = get_dynamic_base_port();
    cluster.bootstrap().await.unwrap();
    sleep(Duration::from_millis(500)).await;

    for i in 0..3 {
        let m = cluster
            .nodes
            .get_mut(&i)
            .unwrap()
            .send_command(json!({
                "command": "DumpMetrics"
            }))
            .await
            .unwrap();
        let serialized = serde_json::to_string(&m).unwrap();
        assert!(!serialized.contains("spiffe://"));
        assert!(!serialized.contains("-----BEGIN"));
        assert!(!serialized.contains('/'));
        assert!(!serialized.contains('\\'));
    }
}

#[tokio::test]
async fn test_metrics_error_redaction() {
    let mut cluster = TestCluster::new(20000);
    cluster.base_port = get_dynamic_base_port();
    let (ca_cert, ca_key_pair, identities) = generate_test_ca_and_identities(&[0, 1, 2]);
    cluster.identities = identities;
    cluster.bootstrap().await.unwrap();
    sleep(Duration::from_millis(500)).await;

    let spiffe = "spiffe://test/trust-domain/tenant/test/ns/default/sa/svc/nf/test/instance/1";
    let expired_identity = generate_custom_identity(&ca_cert, &ca_key_pair, spiffe, true);

    let node_0_port = cluster.base_port;
    let conn_res = connect_raw_tls(&format!("127.0.0.1:{node_0_port}"), &expired_identity).await;

    if let Ok(mut tls_stream) = conn_res {
        let req = json!({
            "RequestVote": {
                "term": 2,
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

        let write_res = tls_stream.write_all(&payload).await;
        if write_res.is_ok() {
            let mut len_buf = [0u8; 4];
            let read_res = tls_stream.read_exact(&mut len_buf).await;
            if read_res.is_ok() {
                let len = u32::from_be_bytes(len_buf) as usize;
                let mut resp_buf = vec![0u8; len];
                let payload_res = tls_stream.read_exact(&mut resp_buf).await;
                if payload_res.is_ok() {
                    let resp: serde_json::Value = serde_json::from_slice(&resp_buf).unwrap();
                    let err_str = resp["response"].to_string();
                    assert!(err_str.contains("redacted safety error"));
                }
            }
        }
    }
}
