mod common;
mod e2e_tier2_common;

use common::TestCluster;
use e2e_tier2_common::{connect_raw_tls, generate_test_ca_and_identities, AuthenticatedRequest};
use serde_json::json;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::sleep;

fn get_dynamic_base_port() -> u16 {
    common::find_free_port_block(50)
}

#[tokio::test]
async fn test_boundary_duplicate_rpc_frame() {
    let mut cluster = TestCluster::new(37000);
    let (_ca_cert, _ca_key_pair, identities) = generate_test_ca_and_identities(&[0, 1, 2]);
    cluster.identities = identities;
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

    let req = json!({
        "RequestVote": {
            "term": 2,
            "candidate_id": 0,
            "last_log_index": 0,
            "last_log_term": 0
        }
    });
    let auth_req = AuthenticatedRequest {
        sender_node_id: 0,
        target_node_id: 1,
        cluster_id: "tcp-test-cluster".to_string(),
        spiffe_id: None,
        client_cert_pem: None,
        request: req,
    };
    let bytes = serde_json::to_vec(&auth_req).unwrap();
    let mut payload = (bytes.len() as u32).to_be_bytes().to_vec();
    payload.extend_from_slice(&bytes);

    let node_1_port = cluster.base_port + 10;
    let identity = cluster.identities.get(&0).unwrap().clone();
    let mut tls_stream = connect_raw_tls(&format!("127.0.0.1:{node_1_port}"), &identity)
        .await
        .unwrap();

    tls_stream.write_all(&payload).await.unwrap();
    let mut len_buf = [0u8; 4];
    tls_stream.read_exact(&mut len_buf).await.unwrap();
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut resp_buf = vec![0u8; len];
    tls_stream.read_exact(&mut resp_buf).await.unwrap();

    let _ = tls_stream.write_all(&payload).await;
    sleep(Duration::from_millis(100)).await;
    let resp = cluster
        .nodes
        .get_mut(&1)
        .unwrap()
        .send_command(json!({
            "command": "DumpMetrics"
        }))
        .await
        .unwrap();
    assert!(resp["success"].as_bool().unwrap());
}

#[tokio::test]
async fn test_boundary_connection_drop_mid_rpc() {
    let mut cluster = TestCluster::new(37100);
    cluster.base_port = get_dynamic_base_port();
    cluster.bootstrap().await.unwrap();
    sleep(Duration::from_millis(500)).await;

    let node_1_port = cluster.base_port + 10;
    let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{node_1_port}"))
        .await
        .unwrap();

    stream.write_all(&(1000u32).to_be_bytes()).await.unwrap();
    stream.write_all(b"incomplete").await.unwrap();
    drop(stream);

    sleep(Duration::from_millis(100)).await;
    let resp = cluster
        .nodes
        .get_mut(&1)
        .unwrap()
        .send_command(json!({
            "command": "DumpMetrics"
        }))
        .await
        .unwrap();
    assert!(resp["success"].as_bool().unwrap());
}

#[tokio::test]
async fn test_boundary_slow_connection() {
    let mut cluster = TestCluster::new(37200);
    let (_ca_cert, _ca_key_pair, identities) = generate_test_ca_and_identities(&[0, 1, 2]);
    cluster.identities = identities;
    cluster.base_port = get_dynamic_base_port();
    cluster.bootstrap().await.unwrap();
    sleep(Duration::from_millis(500)).await;

    let req = json!({
        "RequestVote": {
            "term": 2,
            "candidate_id": 0,
            "last_log_index": 0,
            "last_log_term": 0
        }
    });
    let auth_req = AuthenticatedRequest {
        sender_node_id: 0,
        target_node_id: 1,
        cluster_id: "tcp-test-cluster".to_string(),
        spiffe_id: None,
        client_cert_pem: None,
        request: req,
    };
    let bytes = serde_json::to_vec(&auth_req).unwrap();
    let mut payload = (bytes.len() as u32).to_be_bytes().to_vec();
    payload.extend_from_slice(&bytes);

    let node_1_port = cluster.base_port + 10;
    let identity = cluster.identities.get(&0).unwrap().clone();
    let mut tls_stream = connect_raw_tls(&format!("127.0.0.1:{node_1_port}"), &identity)
        .await
        .unwrap();

    for byte in payload {
        if tls_stream.write_all(&[byte]).await.is_err() {
            break;
        }
        sleep(Duration::from_millis(15)).await;
    }

    let mut len_buf = [0u8; 4];
    let res = tls_stream.read_exact(&mut len_buf).await;
    let _ = res;
}

#[tokio::test]
async fn test_boundary_zero_byte_rpc() {
    let mut cluster = TestCluster::new(37300);
    let (_ca_cert, _ca_key_pair, identities) = generate_test_ca_and_identities(&[0, 1, 2]);
    cluster.identities = identities;
    cluster.base_port = get_dynamic_base_port();
    cluster.bootstrap().await.unwrap();
    sleep(Duration::from_millis(500)).await;

    let node_1_port = cluster.base_port + 10;
    let identity = cluster.identities.get(&0).unwrap().clone();
    let tls_stream = connect_raw_tls(&format!("127.0.0.1:{node_1_port}"), &identity)
        .await
        .unwrap();
    drop(tls_stream);

    sleep(Duration::from_millis(100)).await;
    let resp = cluster
        .nodes
        .get_mut(&1)
        .unwrap()
        .send_command(json!({
            "command": "DumpMetrics"
        }))
        .await
        .unwrap();
    assert!(resp["success"].as_bool().unwrap());
}

#[tokio::test]
async fn test_boundary_frame_size_exhaustion() {
    let mut cluster = TestCluster::new(37400);
    let (_ca_cert, _ca_key_pair, identities) = generate_test_ca_and_identities(&[0, 1, 2]);
    cluster.identities = identities;
    cluster.base_port = get_dynamic_base_port();
    cluster.bootstrap().await.unwrap();
    sleep(Duration::from_millis(500)).await;

    let node_1_port = cluster.base_port + 10;
    let identity = cluster.identities.get(&0).unwrap().clone();
    let mut tls_stream = connect_raw_tls(&format!("127.0.0.1:{node_1_port}"), &identity)
        .await
        .unwrap();

    let bad_len = (17 * 1024 * 1024_u32).to_be_bytes();
    tls_stream.write_all(&bad_len).await.unwrap();

    let mut buf = [0u8; 10];
    let read_res = tls_stream.read(&mut buf).await;
    match read_res {
        Ok(0) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {}
        other => panic!("Expected connection closed (EOF or UnexpectedEof), got {other:?}"),
    }
}
