#![allow(dead_code, unused_imports)]
pub use opc_persist::SqliteBackend;
use opc_persist::{
    AuditKey, AuditOpType, AuditRecord, ClusterMembership, CommitRecord, CommitSource,
    ConsensusClock, ConsensusConfigStore, NodeIdentity, TcpPeer, TcpRpcServer,
};
use opc_types::{ConfigVersion, SchemaDigest, Timestamp, TxId};
use std::sync::Arc;
use tempfile::TempDir;

pub const TEST_AUDIT_KEY_BYTES: [u8; 32] = [0xA5; 32];

pub fn generate_test_ca_and_identities(
    node_ids: &[usize],
) -> (
    rcgen::Certificate,
    rcgen::KeyPair,
    std::collections::HashMap<usize, NodeIdentity>,
) {
    let ca_key_pair = rcgen::KeyPair::generate().unwrap();
    let mut ca_params = rcgen::CertificateParams::default();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_key_pair).unwrap();
    let ca_cert_pem = ca_cert.pem();

    let mut identities = std::collections::HashMap::new();

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

pub fn test_audit_key() -> AuditKey {
    AuditKey::new(TEST_AUDIT_KEY_BYTES).unwrap()
}

pub fn make_commit_record(tx_id: TxId, version: u64) -> CommitRecord {
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

pub fn get_free_ports(count: usize) -> Vec<u16> {
    let listeners: Vec<_> = (0..count)
        .map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    listeners
        .iter()
        .map(|l| l.local_addr().unwrap().port())
        .collect()
}

pub async fn setup_tcp_consensus_group(
    temp_dir: &TempDir,
    _base_port: u16,
) -> Vec<Arc<ConsensusConfigStore>> {
    let (_, _, identities) = generate_test_ca_and_identities(&[0, 1, 2]);

    let mut backends = Vec::new();
    for i in 0..3 {
        let db_path = temp_dir.path().join(format!("tcp_consensus_{i}.db"));
        let backend = SqliteBackend::open_with_audit_key(&db_path, true, 0, test_audit_key())
            .await
            .expect("open backend");
        backends.push(Arc::new(backend));
    }

    let mut stores = Vec::new();
    let free_ports = get_free_ports(3);
    let mut addrs = Vec::new();
    for port in free_ports {
        addrs.push(format!("127.0.0.1:{port}"));
    }

    for i in 0..3 {
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
        let store =
            ConsensusConfigStore::new(i, backends[i].clone(), Some(membership), Some(clock))
                .await
                .expect("create store");
        let store_arc = Arc::new(store);

        let identity = identities.get(&i).cloned().expect("identity");
        store_arc
            .set_identity(identity)
            .await
            .expect("set identity");

        stores.push(store_arc.clone());

        let server = TcpRpcServer::new(store_arc, addrs[i].clone());
        std::mem::drop(server.start().await.expect("start server"));
    }

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    for (i, store) in stores.iter().enumerate() {
        for (j, addr) in addrs.iter().enumerate() {
            if i != j {
                let peer = TcpPeer::new(j, addr.clone(), std::time::Duration::from_millis(150));
                store.add_peer(j, Arc::new(peer)).await;
            }
        }
    }

    stores
}
