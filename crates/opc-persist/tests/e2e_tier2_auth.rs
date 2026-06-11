mod common;
mod e2e_tier2_common;

use common::TestCluster;
use e2e_tier2_common::{
    connect_raw_tls, generate_custom_identity, generate_malformed_san_identity,
    generate_test_ca_and_identities, send_tls_rpc, AuthenticatedRequest, AuthenticatedResponse,
};
use serde_json::json;
use std::collections::HashMap;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::sleep;

fn get_dynamic_base_port() -> u16 {
    common::find_free_port_block(50)
}

#[tokio::test]
async fn test_boundary_expired_client_cert() {
    let mut cluster = TestCluster::new(37800);
    let (ca_cert, ca_key_pair, identities) = generate_test_ca_and_identities(&[0, 1, 2]);
    cluster.identities = identities;
    cluster.base_port = get_dynamic_base_port();
    cluster.bootstrap().await.unwrap();
    sleep(Duration::from_millis(500)).await;

    let spiffe = "spiffe://test/trust-domain/tenant/test/ns/default/sa/svc/nf/test/instance/1";
    let expired_identity = generate_custom_identity(&ca_cert, &ca_key_pair, spiffe, true);

    let node_0_port = cluster.base_port;
    let conn_res = connect_raw_tls(&format!("127.0.0.1:{}", node_0_port), &expired_identity).await;

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
                    let resp: AuthenticatedResponse = serde_json::from_slice(&resp_buf).unwrap();
                    let err_str = resp.response.to_string();
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
async fn test_boundary_untrusted_ca() {
    let mut cluster = TestCluster::new(37900);
    let (_ca_cert, _ca_key_pair, identities) = generate_test_ca_and_identities(&[0, 1, 2]);
    cluster.identities = identities;
    cluster.base_port = get_dynamic_base_port();
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
    let conn_res =
        connect_raw_tls(&format!("127.0.0.1:{}", node_0_port), &untrusted_identity).await;
    assert!(conn_res.is_err());
}

#[tokio::test]
async fn test_boundary_malformed_san_uri() {
    let mut cluster = TestCluster::new(38000);
    let (ca_cert, ca_key_pair, identities) = generate_test_ca_and_identities(&[0, 1, 2]);
    cluster.identities = identities;
    cluster.base_port = get_dynamic_base_port();
    cluster.bootstrap().await.unwrap();
    sleep(Duration::from_millis(500)).await;

    let malformed_san = "spiffe://test/invalid/uri/format";
    let malformed_identity = generate_malformed_san_identity(&ca_cert, &ca_key_pair, malformed_san);

    let node_0_port = cluster.base_port;
    let conn_res =
        connect_raw_tls(&format!("127.0.0.1:{}", node_0_port), &malformed_identity).await;

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

        if tls_stream.write_all(&payload).await.is_ok() {
            let mut len_buf = [0u8; 4];
            if tls_stream.read_exact(&mut len_buf).await.is_ok() {
                let len = u32::from_be_bytes(len_buf) as usize;
                let mut resp_buf = vec![0u8; len];
                if tls_stream.read_exact(&mut resp_buf).await.is_ok() {
                    let resp: AuthenticatedResponse = serde_json::from_slice(&resp_buf).unwrap();
                    let err_str = resp.response.to_string();
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
async fn test_boundary_spiffe_node_id_mismatch() {
    let mut cluster = TestCluster::new(38100);
    let (ca_cert, ca_key_pair, identities) = generate_test_ca_and_identities(&[0, 1, 2]);
    cluster.identities = identities;
    cluster.base_port = get_dynamic_base_port();
    cluster.bootstrap().await.unwrap();
    sleep(Duration::from_millis(500)).await;

    let spiffe = "spiffe://test/trust-domain/tenant/test/ns/default/sa/svc/nf/test/instance/5";
    let custom_identity = generate_custom_identity(&ca_cert, &ca_key_pair, spiffe, false);

    let node_0_port = cluster.base_port;
    let mut tls_stream = connect_raw_tls(&format!("127.0.0.1:{}", node_0_port), &custom_identity)
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

    let resp: AuthenticatedResponse = serde_json::from_slice(&resp_buf).unwrap();
    let err_str = resp.response.to_string();
    assert!(
        err_str.contains("redacted")
            || err_str.contains("safety error")
            || err_str.contains("unauthenticated")
            || err_str.contains("Err")
    );
}

#[tokio::test]
async fn test_boundary_cluster_id_mismatch() {
    let mut cluster = TestCluster::new(38200);
    let (_ca_cert, _ca_key_pair, identities) = generate_test_ca_and_identities(&[0, 1, 2]);
    cluster.identities = identities;
    cluster.base_port = get_dynamic_base_port();
    cluster.bootstrap().await.unwrap();
    sleep(Duration::from_millis(500)).await;

    let node_0_port = cluster.base_port;
    let identity = cluster.identities.get(&1).unwrap().clone();
    let mut tls_stream = connect_raw_tls(&format!("127.0.0.1:{}", node_0_port), &identity)
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
        cluster_id: "mismatched-cluster-id".to_string(),
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

    let resp: AuthenticatedResponse = serde_json::from_slice(&resp_buf).unwrap();
    let err_str = resp.response.to_string();
    assert!(
        err_str.contains("redacted")
            || err_str.contains("safety error")
            || err_str.contains("unauthenticated")
            || err_str.contains("Err")
    );
}

#[tokio::test]
async fn test_boundary_non_test_spiffe_profile_is_accepted() {
    let mut cluster = TestCluster::new(38250);
    let (ca_cert, ca_key_pair, _) = generate_test_ca_and_identities(&[]);
    let mut identities = HashMap::new();
    for node_id in 0..3 {
        let spiffe = format!(
            "spiffe://prod.example.org/tenant/carrier/ns/core/sa/opc-consensus/nf/amf/instance/{}",
            node_id
        );
        identities.insert(
            node_id,
            generate_custom_identity(&ca_cert, &ca_key_pair, &spiffe, false),
        );
    }
    cluster.identities = identities;
    cluster.base_port = get_dynamic_base_port();
    cluster.bootstrap().await.unwrap();
    sleep(Duration::from_millis(500)).await;

    let req = json!({
        "RequestVote": {
            "term": 2,
            "candidate_id": 1,
            "last_log_index": 0,
            "last_log_term": 0
        }
    });
    let node_0_addr = format!("127.0.0.1:{}", cluster.base_port);
    let identity = cluster.identities.get(&1).unwrap();
    let resp = send_tls_rpc(&node_0_addr, 1, 0, "tcp-test-cluster", identity, req)
        .await
        .unwrap();
    let resp_str = resp.to_string();

    assert!(resp_str.contains("RequestVote"));
    assert!(!resp_str.contains("unauthenticated"));
    assert!(!resp_str.contains("redacted safety error"));
}
