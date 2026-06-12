mod common;

use common::{
    connect_raw_tls, generate_custom_identity, generate_test_ca_and_identities,
    AuthenticatedRequest, TestCluster,
};
use opc_types::TxId;
use serde_json::json;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::sleep;

fn get_dynamic_base_port() -> u16 {
    common::find_free_port_block(50)
}

#[tokio::test]
async fn test_mtls_valid_rpc() {
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

    for node_id in 1..3 {
        let resp = cluster
            .nodes
            .get_mut(&node_id)
            .unwrap()
            .send_command(json!({
                "command": "LoadLatest"
            }))
            .await
            .unwrap();
        assert!(resp["success"].as_bool().unwrap());
        let val = &resp["data"];
        assert_eq!(val["record"]["version"].as_u64(), Some(1));
    }
}

#[tokio::test]
async fn test_mtls_plain_tcp_rejected() {
    let mut cluster = TestCluster::new(20000);
    cluster.base_port = get_dynamic_base_port();
    cluster.bootstrap().await.unwrap();
    sleep(Duration::from_millis(500)).await;

    let node_1_port = cluster.base_port + 10;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{node_1_port}"))
        .await
        .unwrap();
    let _ = stream.write_all(b"plain tcp text request").await;

    let mut buf = [0u8; 1000];
    let mut total_read = 0;
    loop {
        match stream.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => {
                total_read += n;
                if total_read > 10000 {
                    panic!("Read too many bytes without connection closure");
                }
            }
            Err(_) => break,
        }
    }
}

#[tokio::test]
async fn test_mtls_untrusted_ca_rejected() {
    let mut cluster = TestCluster::new(20000);
    cluster.base_port = get_dynamic_base_port();
    let (_ca_cert, _ca_key_pair, identities) = generate_test_ca_and_identities(&[0, 1, 2]);
    cluster.identities = identities;
    cluster.bootstrap().await.unwrap();
    sleep(Duration::from_millis(500)).await;

    let untrusted_ca_key_pair = rcgen::KeyPair::generate().unwrap();
    let mut untrusted_ca_params = rcgen::CertificateParams::default();
    untrusted_ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let untrusted_ca_cert = untrusted_ca_params
        .self_signed(&untrusted_ca_key_pair)
        .unwrap();

    let spiffe = "spiffe://test/trust-domain/tenant/test/ns/default/sa/svc/nf/test/instance/1";
    let untrusted_identity =
        generate_custom_identity(&untrusted_ca_cert, &untrusted_ca_key_pair, spiffe, false);

    let node_0_port = cluster.base_port;
    let conn_res = connect_raw_tls(&format!("127.0.0.1:{node_0_port}"), &untrusted_identity).await;
    assert!(conn_res.is_err());
}

#[tokio::test]
async fn test_mtls_expired_cert_rejected() {
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
                    assert!(
                        err_str.contains("redacted")
                            || err_str.contains("safety error")
                            || err_str.contains("unauthenticated")
                            || err_str.contains("Err")
                    );
                }
            }
        }
    }
}

#[tokio::test]
async fn test_mtls_spiffe_id_mismatch_rejected() {
    let mut cluster = TestCluster::new(20000);
    cluster.base_port = get_dynamic_base_port();
    let (ca_cert, ca_key_pair, identities) = generate_test_ca_and_identities(&[0, 1, 2]);
    cluster.identities = identities;
    cluster.bootstrap().await.unwrap();
    sleep(Duration::from_millis(500)).await;

    let spiffe = "spiffe://test/trust-domain/tenant/test/ns/default/sa/svc/nf/test/instance/5";
    let custom_identity = generate_custom_identity(&ca_cert, &ca_key_pair, spiffe, false);

    let node_0_port = cluster.base_port;
    let mut tls_stream = connect_raw_tls(&format!("127.0.0.1:{node_0_port}"), &custom_identity)
        .await
        .unwrap();

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

    tls_stream.write_all(&payload).await.unwrap();

    let mut len_buf = [0u8; 4];
    tls_stream.read_exact(&mut len_buf).await.unwrap();
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut resp_buf = vec![0u8; len];
    tls_stream.read_exact(&mut resp_buf).await.unwrap();

    let resp: serde_json::Value = serde_json::from_slice(&resp_buf).unwrap();
    let err_str = resp["response"].to_string();
    assert!(
        err_str.contains("redacted")
            || err_str.contains("safety error")
            || err_str.contains("unauthenticated")
            || err_str.contains("Err")
    );
}
