#![allow(dead_code, unused_imports)]
use crate::common::{
    acquire_cluster_serial, find_free_port_block, generate_test_identities, wait_for_port, Proxy,
    TestCluster, TestNode,
};
use opc_persist::{
    AuditKey, AuditOpType, AuditRecord, ClusterMembership, CommitRecord, CommitSource,
    ConsensusClock, ConsensusConfigStore, NodeIdentity, SqliteBackend, StoredConfig,
    UnsafePathMock,
};
use opc_types::{ConfigVersion, SchemaDigest, Timestamp, TxId};
use rustls::pki_types::{pem::PemObject, ServerName};
use std::collections::HashMap;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsConnector;

pub const TEST_AUDIT_KEY_BYTES: [u8; 32] = [0xA5; 32];

pub fn test_audit_key() -> AuditKey {
    AuditKey::new(TEST_AUDIT_KEY_BYTES).unwrap()
}

pub fn make_commit_record(tx_id: TxId, version: u64) -> CommitRecord {
    CommitRecord {
        tx_id,
        parent_tx_id: None,
        version: ConfigVersion::new(version),
        committed_at: Timestamp::now_utc(),
        principal: "spiffe://test-trust-domain/tenant/test/ns/default/sa/svc/nf/test/instance/1"
            .to_string(),
        source: CommitSource::LocalOperator,
        schema_digest: SchemaDigest::from_bytes([0u8; 32]),
        plaintext_digest: vec![],
        encrypted_blob: b"encrypted payload".to_vec(),
        rollback_point: false,
        confirmed_deadline: None,
    }
}

pub fn make_audit_record(tx_id: TxId, sequence: u32, path: &str) -> AuditRecord {
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

pub async fn setup_consensus_group(temp_dir: &TempDir) -> Vec<Arc<ConsensusConfigStore>> {
    let mut backends = Vec::new();
    for i in 0..3 {
        let db_path = temp_dir.path().join(format!("consensus_{i}.db"));
        let backend = SqliteBackend::open_with_audit_key(&db_path, true, 0, test_audit_key())
            .await
            .expect("open backend");
        backends.push(Arc::new(backend));
    }

    let mut stores = Vec::new();
    for (i, backend) in backends.iter().enumerate() {
        let membership = ClusterMembership {
            cluster_id: "tcp-test-cluster".to_string(),
            node_id: i,
            voting_members: vec![0, 1, 2],
            non_voting_members: vec![],
            old_voting_members: None,
            removed_members: vec![],
            epoch: 1,
        };
        let clock = ConsensusClock {
            election_timeout_min: std::time::Duration::from_millis(150),
            election_timeout_max: std::time::Duration::from_millis(300),
            heartbeat_interval: std::time::Duration::from_millis(50),
            enable_timers: false,
        };
        let store = ConsensusConfigStore::new(i, backend.clone(), Some(membership), Some(clock))
            .await
            .expect("create consensus store");
        stores.push(Arc::new(store));
    }

    for i in 0..3 {
        for j in 0..3 {
            if i != j {
                stores[i].add_peer(j, stores[j].clone()).await;
            }
        }
    }

    stores
}

pub fn generate_test_ca_and_identities(
    node_ids: &[usize],
) -> (
    rcgen::Certificate,
    rcgen::KeyPair,
    HashMap<usize, NodeIdentity>,
) {
    let ca_key_pair = rcgen::KeyPair::generate().unwrap();
    let mut ca_params = rcgen::CertificateParams::default();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_key_pair).unwrap();
    let ca_cert_pem = ca_cert.pem();

    let mut identities = HashMap::new();

    for &node_id in node_ids {
        let node_key_pair = rcgen::KeyPair::generate().unwrap();
        let mut node_params = rcgen::CertificateParams::default();
        node_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "localhost");

        let spiffe = format!(
            "spiffe://test/trust-domain/tenant/test/ns/default/sa/svc/nf/test/instance/{node_id}"
        );

        node_params.subject_alt_names = vec![
            rcgen::SanType::DnsName(rcgen::Ia5String::try_from("localhost").unwrap()),
            rcgen::SanType::IpAddress("127.0.0.1".parse().unwrap()),
            rcgen::SanType::URI(rcgen::Ia5String::try_from(spiffe).unwrap()),
        ];

        node_params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(1);
        node_params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(10);

        let node_cert = node_params
            .signed_by(&node_key_pair, &ca_cert, &ca_key_pair)
            .unwrap();
        let node_cert_pem = node_cert.pem();
        let node_private_key_pem = node_key_pair.serialize_pem();

        identities.insert(
            node_id,
            NodeIdentity {
                cert_chain_pem: node_cert_pem,
                private_key_pem: node_private_key_pem,
                ca_cert_pem: ca_cert_pem.clone(),
            },
        );
    }

    (ca_cert, ca_key_pair, identities)
}

pub fn generate_custom_identity(
    ca_cert: &rcgen::Certificate,
    ca_key_pair: &rcgen::KeyPair,
    spiffe_id: &str,
    expired: bool,
) -> NodeIdentity {
    let node_key_pair = rcgen::KeyPair::generate().unwrap();
    let mut node_params = rcgen::CertificateParams::default();
    node_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "localhost");
    node_params.subject_alt_names = vec![
        rcgen::SanType::DnsName(rcgen::Ia5String::try_from("localhost").unwrap()),
        rcgen::SanType::IpAddress("127.0.0.1".parse().unwrap()),
        rcgen::SanType::URI(rcgen::Ia5String::try_from(spiffe_id).unwrap()),
    ];

    if expired {
        node_params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(10);
        node_params.not_after = time::OffsetDateTime::now_utc() - time::Duration::days(1);
    } else {
        node_params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(1);
        node_params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(10);
    }

    let node_cert = node_params
        .signed_by(&node_key_pair, ca_cert, ca_key_pair)
        .unwrap();
    let node_cert_pem = node_cert.pem();
    let node_private_key_pem = node_key_pair.serialize_pem();

    NodeIdentity {
        cert_chain_pem: node_cert_pem,
        private_key_pem: node_private_key_pem,
        ca_cert_pem: ca_cert.pem(),
    }
}

pub fn generate_malformed_san_identity(
    ca_cert: &rcgen::Certificate,
    ca_key_pair: &rcgen::KeyPair,
    malformed_san: &str,
) -> NodeIdentity {
    let node_key_pair = rcgen::KeyPair::generate().unwrap();
    let mut node_params = rcgen::CertificateParams::default();
    node_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "localhost");
    node_params.subject_alt_names = vec![
        rcgen::SanType::DnsName(rcgen::Ia5String::try_from("localhost").unwrap()),
        rcgen::SanType::IpAddress("127.0.0.1".parse().unwrap()),
        rcgen::SanType::URI(rcgen::Ia5String::try_from(malformed_san).unwrap()),
    ];

    node_params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(1);
    node_params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(10);

    let node_cert = node_params
        .signed_by(&node_key_pair, ca_cert, ca_key_pair)
        .unwrap();
    let node_cert_pem = node_cert.pem();
    let node_private_key_pem = node_key_pair.serialize_pem();

    NodeIdentity {
        cert_chain_pem: node_cert_pem,
        private_key_pem: node_private_key_pem,
        ca_cert_pem: ca_cert.pem(),
    }
}

pub fn load_certs_from_pem(
    pem: &str,
) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, std::io::Error> {
    rustls::pki_types::CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
}

pub fn load_private_key_from_pem(
    pem: &str,
) -> Result<rustls::pki_types::PrivateKeyDer<'static>, std::io::Error> {
    rustls::pki_types::PrivateKeyDer::from_pem_slice(pem.as_bytes())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
}

pub async fn build_client_connector(identity: &NodeIdentity) -> TlsConnector {
    let mut root_store = rustls::RootCertStore::empty();
    let ca_certs = load_certs_from_pem(&identity.ca_cert_pem).unwrap();
    for ca_cert in ca_certs {
        root_store.add(ca_cert).unwrap();
    }
    let client_certs = load_certs_from_pem(&identity.cert_chain_pem).unwrap();
    let private_key = load_private_key_from_pem(&identity.private_key_pem).unwrap();

    static INIT_CRYPTO: std::sync::Once = std::sync::Once::new();
    INIT_CRYPTO.call_once(|| {
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();
    });

    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(client_certs, private_key)
        .unwrap();
    TlsConnector::from(std::sync::Arc::new(client_config))
}

pub async fn connect_raw_tls(
    addr: &str,
    identity: &NodeIdentity,
) -> Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>, std::io::Error> {
    let tcp = tokio::net::TcpStream::connect(addr).await?;
    let connector = build_client_connector(identity).await;
    let host = addr.split(':').next().unwrap_or("127.0.0.1");
    let server_name = ServerName::try_from(host).unwrap().to_owned();
    connector.connect(server_name, tcp).await
}

#[derive(serde::Serialize)]
pub struct AuthenticatedRequest {
    pub sender_node_id: usize,
    pub target_node_id: usize,
    pub cluster_id: String,
    pub spiffe_id: Option<String>,
    pub client_cert_pem: Option<String>,
    pub request: serde_json::Value,
}

#[derive(serde::Deserialize)]
pub struct AuthenticatedResponse {
    pub response: serde_json::Value,
}

pub async fn send_tls_rpc(
    addr: &str,
    sender_id: usize,
    target_id: usize,
    cluster_id: &str,
    client_identity: &NodeIdentity,
    req: serde_json::Value,
) -> Result<serde_json::Value, String> {
    let mut tls_stream = connect_raw_tls(addr, client_identity)
        .await
        .map_err(|e| format!("Failed to connect: {e}"))?;
    let auth_req = AuthenticatedRequest {
        sender_node_id: sender_id,
        target_node_id: target_id,
        cluster_id: cluster_id.to_string(),
        spiffe_id: None,
        client_cert_pem: None,
        request: req,
    };
    let bytes = serde_json::to_vec(&auth_req).unwrap();
    let mut payload = (bytes.len() as u32).to_be_bytes().to_vec();
    payload.extend_from_slice(&bytes);

    tls_stream
        .write_all(&payload)
        .await
        .map_err(|e| format!("Failed to write: {e}"))?;

    let mut len_buf = [0u8; 4];
    tls_stream
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| format!("Failed to read length: {e}"))?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut resp_buf = vec![0u8; len];
    tls_stream
        .read_exact(&mut resp_buf)
        .await
        .map_err(|e| format!("Failed to read body: {e}"))?;
    let resp: serde_json::Value =
        serde_json::from_slice(&resp_buf).map_err(|e| format!("Failed to parse response: {e}"))?;
    Ok(resp)
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

pub fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub async fn setup_process_cluster(size: usize) -> TestCluster {
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

    for a in 0..size {
        for b in 0..size {
            if a != b {
                let local_proxy_port = base_port + 100 + (a * size + b) as u16;
                let target_port = base_port + (b * 10) as u16;
                let mut proxy = Proxy::new(local_proxy_port, target_port);
                proxy.start().await.unwrap();
                cluster.proxies.insert((a, b), proxy);
            }
        }
    }

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
