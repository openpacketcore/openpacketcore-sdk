use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;

use opc_alarm::{AffectedObject, AlarmDetails, AlarmType, ProbableCause, RedactedText, Severity};
use opc_amf_lite::{AmfConfig, AmfLite};
use opc_config_model::{CommitMode, CommitStatus, TrustedPrincipal, WorkloadIdentity};
use opc_nacm::{ModuleRegistry, NacmAction, NacmPolicy, NacmRule, PolicyVersion};
use opc_persist::{
    AuditKey, ClusterMembership, ConfigStore, ConsensusClock, ConsensusConfigStore, NodeIdentity,
    SqliteBackend, TcpPeer, TcpRpcServer,
};
use opc_security_testkit::{FakeKms, KmsBehavior};
use opc_session_store::{
    CompareAndSet, OwnerId, SessionBackend, SessionKey, SessionKeyType, SessionLeaseManager,
    StateClass, StateType, StoreError, StoredSessionRecord,
};
use opc_session_testkit::ChaosTestkit;
use opc_types::{NetworkFunctionKind, TenantId, Timestamp};

const TEST_AUDIT_KEY_BYTES: [u8; 32] = [0xA5; 32];
fn test_audit_key() -> AuditKey {
    AuditKey::new(TEST_AUDIT_KEY_BYTES).unwrap()
}

fn get_free_ports(count: usize) -> Vec<u16> {
    let listeners: Vec<_> = (0..count)
        .map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    listeners
        .iter()
        .map(|l| l.local_addr().unwrap().port())
        .collect()
}

async fn wait_for_shutdown(amf: &AmfLite) {
    amf.shutdown().await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while amf.phase().await != opc_runtime::RuntimePhase::Stopped
        && tokio::time::Instant::now() < deadline
    {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn query_admin(addr: SocketAddr, path: &str, token: Option<&str>) -> (u16, String) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let mut stream = loop {
        match tokio::net::TcpStream::connect(addr).await {
            Ok(stream) => break stream,
            Err(err) if tokio::time::Instant::now() < deadline => {
                eprintln!("admin probe connect to {addr} failed, retrying: {err}");
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            Err(err) => panic!("admin probe connect to {addr} failed: {err}"),
        }
    };
    let req = if let Some(t) = token {
        format!(
            "GET {path} HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer {t}\r\nConnection: close\r\n\r\n"
        )
    } else {
        format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n")
    };
    stream.write_all(req.as_bytes()).await.unwrap();
    stream.flush().await.unwrap();
    let mut resp = String::new();
    stream.read_to_string(&mut resp).await.unwrap();

    let first_line = resp.lines().next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    let status: u16 = if parts.len() >= 2 {
        parts[1].parse().unwrap_or(500)
    } else {
        500
    };
    (status, resp)
}

fn generate_test_ca_and_identities(
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

#[allow(dead_code)]
fn generate_custom_identity(
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

async fn setup_tcp_consensus_group(
    temp_dir: &TempDir,
) -> (Vec<Arc<ConsensusConfigStore>>, Vec<String>) {
    let (_, _, identities) = generate_test_ca_and_identities(&[0, 1, 2]);

    let mut backends = Vec::new();
    for i in 0..3 {
        let db_path = temp_dir.path().join(format!("tcp_consensus_{i}.db"));
        let backend = SqliteBackend::open_with_audit_key(&db_path, true, 0, test_audit_key())
            .await
            .expect("open backend");
        backends.push(Arc::new(backend));
    }

    let free_ports = get_free_ports(3);
    let mut addrs = Vec::new();
    for port in free_ports {
        addrs.push(format!("127.0.0.1:{port}"));
    }

    let mut stores = Vec::new();
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

    (stores, addrs)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_amf_lite_e2e_happy_path() {
    println!("[E2E] Starting test_amf_lite_e2e_happy_path");
    let temp_dir = TempDir::new().unwrap();

    // 1. KMS Setup
    println!("[E2E] Setting up FakeKms (Unix)");
    let kms_path = temp_dir.path().join("kms.sock");
    let kms = FakeKms::new_unix(&kms_path, KmsBehavior::default())
        .await
        .unwrap();
    let kms_endpoint = kms.endpoint().to_string();
    println!("[E2E] FakeKms endpoint: {kms_endpoint}");

    let key_config = [1u8; 32];
    kms.insert_key("key-config-1", "config", "system", key_config);
    kms.set_active_key("config", "system", "key-config-1");

    let key_session = [2u8; 32];
    kms.insert_key("key-session-1", "session", "system", key_session);
    kms.set_active_key("session", "system", "key-session-1");

    // 2. Config Store (single replica Sqlite for happy path)
    println!("[E2E] Opening SqliteBackend");
    let db_path = temp_dir.path().join("amf_config.db");
    let backend = SqliteBackend::open_with_audit_key(&db_path, true, 0, test_audit_key())
        .await
        .unwrap();
    let config_store = Arc::new(backend);

    // 3. Quorum Session Store Setup
    println!("[E2E] Setting up ChaosTestkit");
    let chaos = ChaosTestkit::new(3);

    // 4. NACM setup
    println!("[E2E] Setting up NACM module and policy");
    let mut modules = ModuleRegistry::new();
    modules
        .register_module("openpacketcore-amf", "amf")
        .unwrap();
    let rule_update = NacmRule::allow(
        NacmAction::Update,
        opc_nacm::YangPathPattern::parse("/amf:amf/**", &modules).unwrap(),
    );
    let rule_replace = NacmRule::allow(
        NacmAction::Replace,
        opc_nacm::YangPathPattern::parse("/amf:amf/**", &modules).unwrap(),
    );
    let policy = Arc::new(
        NacmPolicy::builder(PolicyVersion::new(1))
            .add_rule(rule_update)
            .add_rule(rule_replace)
            .build(),
    );
    let nacm_modules = Arc::new(modules);

    // 5. Admin server port allocation
    let admin_ports = get_free_ports(1);
    let admin_addr: SocketAddr = format!("127.0.0.1:{}", admin_ports[0]).parse().unwrap();
    let auth_token = "secure-amf-token".to_string();
    println!("[E2E] Allocated admin server port: {admin_addr}");

    // 6. Launch AMF-lite
    println!("[E2E] Starting AMF-lite...");
    let amf = AmfLite::start(
        AmfConfig::default(),
        config_store,
        chaos.replicas.clone(),
        kms_endpoint,
        Some(auth_token.clone()),
        admin_addr,
        policy,
        nacm_modules,
    )
    .await
    .expect("AMF-lite starts successfully");

    println!("[E2E] AMF-lite started! Checking runtime phase...");
    assert_eq!(amf.phase().await, opc_runtime::RuntimePhase::Ready);

    // 7. Test Admin/readiness endpoints
    println!("[E2E] Querying admin /livez");
    let (status_live, _) = query_admin(admin_addr, "/livez", Some(&auth_token)).await;
    assert_eq!(status_live, 200);

    println!("[E2E] Querying admin /readyz");
    let (status_ready, _) = query_admin(admin_addr, "/readyz", Some(&auth_token)).await;
    assert_eq!(status_ready, 200);

    println!("[E2E] Querying admin /startupz");
    let (status_startup, _) = query_admin(admin_addr, "/startupz", Some(&auth_token)).await;
    assert_eq!(status_startup, 200);

    // Test unauthorized access
    println!("[E2E] Querying admin /readyz (unauthorized)");
    let (status_unauth, _) = query_admin(admin_addr, "/readyz", None).await;
    assert_eq!(status_unauth, 401);

    // 8. Config update commit
    println!("[E2E] Committing new config via northbound principal");
    let new_config = AmfConfig {
        hostname: "amf-prod-1".to_string(),
        nrf_endpoint: "http://nrf.openpacketcore.internal".to_string(),
        plmn_id: "20896".to_string(),
        capacity: 5000,
    };
    let principal = TrustedPrincipal::new(
        WorkloadIdentity::Internal("admin".to_string()),
        TenantId::new("system").unwrap(),
    )
    .with_roles(vec!["admin"]);

    let commit_res = amf
        .commit_config(new_config.clone(), principal.clone())
        .await
        .expect("E2E commit_config must succeed");
    assert_eq!(commit_res.status, CommitStatus::Committed);

    // Verify config change is applied and observable
    let snapshot = amf.config_bus().current_snapshot();
    assert_eq!(snapshot.config.hostname, "amf-prod-1");
    assert_eq!(snapshot.config.capacity, 5000);

    // 9. UE Registration & state mutation (Fenced CAS)
    println!("[E2E] Registering UE IMSI context");
    let imsi = "208960000000001";
    amf.register_ue(imsi, 101, Duration::from_secs(10))
        .await
        .unwrap();

    // Verify state registered
    let key = SessionKey {
        tenant: TenantId::new("system").unwrap(),
        nf_kind: NetworkFunctionKind::new("amf").unwrap(),
        key_type: SessionKeyType::SubscriberContext,
        stable_id: bytes::Bytes::copy_from_slice(imsi.as_bytes()),
    };
    let retrieved = amf.session_store().get(&key).await.unwrap().unwrap();
    let plaintext_payload = retrieved.payload.as_bytes();
    let ctx: opc_amf_lite::UeSessionContext = serde_json::from_slice(plaintext_payload).unwrap();
    assert_eq!(ctx.state, "REGISTERED");
    assert_eq!(ctx.amf_ue_ngap_id, 101);

    // Update state to CONNECTED
    println!("[E2E] Updating UE session state to CONNECTED");
    amf.update_ue_session(imsi, "CONNECTED").await.unwrap();
    let retrieved_updated = amf.session_store().get(&key).await.unwrap().unwrap();
    let ctx_updated: opc_amf_lite::UeSessionContext =
        serde_json::from_slice(retrieved_updated.payload.as_bytes()).unwrap();
    assert_eq!(ctx_updated.state, "CONNECTED");

    // 10. Test Alarms & health degradation
    println!("[E2E] Raising critical alarm");
    amf.alarms().raise(
        AlarmType::new("amf-lite.test.degraded"),
        Severity::Critical,
        ProbableCause::ConfigApplyFailed,
        AffectedObject::NfInstance {
            kind: "amf-lite".to_string(),
            instance: "1".to_string(),
        },
        Some("system".to_string()),
        None,
        None,
        RedactedText::new("Simulated alarm for testing"),
        AlarmDetails::empty(),
    );

    // Verify readiness-blocking status for critical alarms.
    let health = amf.health().await.unwrap();
    assert_eq!(health.status, "not_ok");
    assert_eq!(health.reason, Some("active_critical_alarm"));

    let (status_degraded, _) = query_admin(admin_addr, "/readyz", Some(&auth_token)).await;
    assert_eq!(status_degraded, 503);

    // Clear alarm
    println!("[E2E] Clearing critical alarm");
    amf.alarms().clear(
        &AlarmType::new("amf-lite.test.degraded"),
        ProbableCause::ConfigApplyFailed,
        &AffectedObject::NfInstance {
            kind: "amf-lite".to_string(),
            instance: "1".to_string(),
        },
        Some("system"),
        None,
        None,
    );

    let health_recovered = amf.health().await.unwrap();
    assert_eq!(health_recovered.status, "ok");

    // 11. Graceful shutdown
    println!("[E2E] Shuting down AMF-lite...");
    wait_for_shutdown(&amf).await;
    assert_eq!(amf.phase().await, opc_runtime::RuntimePhase::Stopped);
    println!("[E2E] Test test_amf_lite_e2e_happy_path passed successfully!");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_amf_lite_ha_failover_and_recovery() {
    println!("[HA] Starting test_amf_lite_ha_failover_and_recovery");
    let temp_dir = TempDir::new().unwrap();

    // 1. KMS Setup
    println!("[HA] Setting up FakeKms (Unix)");
    let kms_path = temp_dir.path().join("kms.sock");
    let kms = FakeKms::new_unix(&kms_path, KmsBehavior::default())
        .await
        .unwrap();
    let kms_endpoint = kms.endpoint().to_string();

    let key_config = [1u8; 32];
    kms.insert_key("key-config-1", "config", "system", key_config);
    kms.set_active_key("config", "system", "key-config-1");

    let key_session = [2u8; 32];
    kms.insert_key("key-session-1", "session", "system", key_session);
    kms.set_active_key("session", "system", "key-session-1");

    // 2. Consensus Config Store Group Setup (3 nodes)
    println!("[HA] Building 3-node consensus config group");
    let (group, _addrs) = setup_tcp_consensus_group(&temp_dir).await;

    // Campaign node 0 to be leader
    println!("[HA] Campaigning node 0 to Leader");
    group[0].campaign().await.unwrap();
    assert_eq!(group[0].get_role().await, opc_persist::Role::Leader);

    // 3. Quorum Session Store Setup (3 nodes)
    println!("[HA] Initializing ChaosTestkit");
    let chaos = ChaosTestkit::new(3);

    // 4. NACM setup
    let mut modules = ModuleRegistry::new();
    modules
        .register_module("openpacketcore-amf", "amf")
        .unwrap();
    let rule_update = NacmRule::allow(
        NacmAction::Update,
        opc_nacm::YangPathPattern::parse("/amf:amf/**", &modules).unwrap(),
    );
    let rule_replace = NacmRule::allow(
        NacmAction::Replace,
        opc_nacm::YangPathPattern::parse("/amf:amf/**", &modules).unwrap(),
    );
    let policy = Arc::new(
        NacmPolicy::builder(PolicyVersion::new(1))
            .add_rule(rule_update)
            .add_rule(rule_replace)
            .build(),
    );
    let nacm_modules = Arc::new(modules);

    // 5. Admin server port allocation
    let admin_ports = get_free_ports(1);
    let admin_addr: SocketAddr = format!("127.0.0.1:{}", admin_ports[0]).parse().unwrap();
    let auth_token = "secure-amf-token".to_string();

    // 6. Start AMF on Node 0 config store
    println!("[HA] Starting AMF node 0 on consensus node 0 store");
    let amf_0 = AmfLite::start(
        AmfConfig::default(),
        group[0].clone(),
        chaos.replicas.clone(),
        kms_endpoint.clone(),
        Some(auth_token.clone()),
        admin_addr,
        policy.clone(),
        nacm_modules.clone(),
    )
    .await
    .unwrap();

    // Commit a config to leader node 0
    println!("[HA] Submitting commit-confirmed config to leader node 0");
    let candidate = AmfConfig {
        hostname: "amf-ha-node0".to_string(),
        nrf_endpoint: "http://nrf.openpacketcore.internal".to_string(),
        plmn_id: "20896".to_string(),
        capacity: 4000,
    };
    let principal = TrustedPrincipal::new(
        WorkloadIdentity::Internal("admin".to_string()),
        TenantId::new("system").unwrap(),
    )
    .with_roles(vec!["admin"]);

    let res = amf_0
        .commit_config_with_mode(
            candidate.clone(),
            principal.clone(),
            CommitMode::CommitConfirmed {
                timeout: Duration::from_secs(10),
            },
        )
        .await
        .expect("HA commit-confirmed config must succeed");
    assert_eq!(res.status, CommitStatus::CommitConfirmedPending);

    // Sync other consensus nodes so they replicate the commit
    println!("[HA] Syncing consensus group to replicate commit-confirmed");
    group[0].sync().await.unwrap();

    // Confirm it on leader node 0
    println!("[HA] Submitting standard commit to confirm config on leader node 0");
    let confirmed = amf_0
        .commit_config_with_mode(candidate.clone(), principal.clone(), CommitMode::Commit)
        .await
        .expect("HA confirm commit must succeed");
    assert_eq!(confirmed.status, CommitStatus::Committed);
    group[0].sync().await.unwrap();

    // 7. Make session replica 2 offline (simulate network issue)
    println!("[HA] Simulating network drop for session replica 2");
    chaos.set_online(2, false).await;

    // Register a UE context (writes to replica 0 and 1, forming quorum)
    let imsi = "208960000000002";
    println!("[HA] Registering UE IMSI context with session replica 2 offline");
    amf_0
        .register_ue(imsi, 202, Duration::from_secs(10))
        .await
        .unwrap();

    // Verify state in session replica 0 and 1
    let key = SessionKey {
        tenant: TenantId::new("system").unwrap(),
        nf_kind: NetworkFunctionKind::new("amf").unwrap(),
        key_type: SessionKeyType::SubscriberContext,
        stable_id: bytes::Bytes::copy_from_slice(imsi.as_bytes()),
    };

    // 8. Simulate AMF Node 0 crash & Consensus leader failover
    println!("[HA] Shutting down AMF node 0 and taking consensus node 0 offline");
    wait_for_shutdown(&amf_0).await;
    group[0].set_online(false).await;

    // Campaign node 1 of the consensus group to be the new leader
    println!("[HA] Campaigning consensus node 1 to new Leader");
    group[1].campaign().await.unwrap();
    assert_eq!(group[1].get_role().await, opc_persist::Role::Leader);

    // Rejoin session replica 2
    println!("[HA] Bringing session replica 2 back online");
    chaos.set_online(2, true).await;

    // Start a new AMF-lite instance targeting the new consensus leader
    let admin_ports_new = get_free_ports(1);
    let admin_addr_new: SocketAddr = format!("127.0.0.1:{}", admin_ports_new[0]).parse().unwrap();

    println!(
        "[HA] Direct query on group[1] load_latest: {:?}",
        group[1].load_latest().await
    );
    println!("[HA] Launching new AMF node 1 on consensus node 1 store");
    let amf_1 = AmfLite::start(
        AmfConfig::default(),
        group[1].clone(),
        chaos.replicas.clone(),
        kms_endpoint.clone(),
        Some(auth_token.clone()),
        admin_addr_new,
        policy.clone(),
        nacm_modules.clone(),
    )
    .await
    .unwrap();

    // Verify recovery: the new instance recovered the last committed config from node 1!
    println!("[HA] Verifying recovered config hostname on node 1");
    let recovered_snap = amf_1.config_bus().current_snapshot();
    println!(
        "[HA] Recovered snapshot: version={:?} config={:?}",
        recovered_snap.version, recovered_snap.config
    );
    assert_eq!(recovered_snap.config.hostname, "amf-ha-node0");
    assert_eq!(recovered_snap.config.capacity, 4000);

    // Read UE state from the new AMF-lite coordinator.
    // This will trigger read-repair on replica 2!
    println!("[HA] Querying UE state from new AMF node 1 (triggering read-repair)");
    let retrieved = amf_1.session_store().get(&key).await.unwrap().unwrap();
    let ctx: opc_amf_lite::UeSessionContext =
        serde_json::from_slice(retrieved.payload.as_bytes()).unwrap();
    assert_eq!(ctx.amf_ue_ngap_id, 202);

    // Verify session replica 2 got read-repaired
    println!("[HA] Verifying session replica 2 was read-repaired");
    let rep2 = &chaos.replicas[2];
    let kms_provider = Arc::new(opc_key::KmsKeyProvider::new(
        kms_endpoint.clone(),
        None,
        Duration::from_secs(2),
    ));
    let decrypted_backend = opc_session_store::EncryptingSessionBackend::new(
        rep2.inner.clone(),
        kms_provider,
        "amf-sessions",
    );
    let rep2_record = decrypted_backend.get(&key).await.unwrap().unwrap();
    let rep2_ctx: opc_amf_lite::UeSessionContext =
        serde_json::from_slice(rep2_record.payload.as_bytes()).unwrap();
    assert_eq!(rep2_ctx.amf_ue_ngap_id, 202);

    // 9. Stale fence / session replay rejection
    // Let's create a client write with a stale lease/fence token
    println!("[HA] Verifying stale fence write rejection");
    let owner = OwnerId::new("amf-lite-1").unwrap();
    let old_lease = amf_1
        .session_store()
        .acquire(&key, owner.clone(), Duration::from_secs(5))
        .await
        .unwrap();

    // Re-acquire to increment the fence term
    let _newer_lease = amf_1
        .session_store()
        .acquire(&key, owner.clone(), Duration::from_secs(5))
        .await
        .unwrap();

    // A write using the old lease must be rejected!
    let stale_record = StoredSessionRecord {
        key: key.clone(),
        generation: retrieved.generation.next().unwrap(),
        owner: owner.clone(),
        fence: old_lease.fence(),
        state_class: StateClass::AuthoritativeSession,
        state_type: StateType::new("subscriber-context").unwrap(),
        expires_at: Some(opc_amf_lite::add_duration(
            Timestamp::now_utc(),
            Duration::from_secs(5),
        )),
        payload: retrieved.payload.clone(),
    };

    let stale_cas = CompareAndSet {
        key: key.clone(),
        lease: old_lease,
        expected_generation: Some(retrieved.generation),
        new_record: stale_record,
    };

    let stale_res = amf_1.session_store().compare_and_set(stale_cas).await;
    println!("[HA] stale_res was: {stale_res:?}");
    assert!(matches!(
        stale_res,
        Err(StoreError::StaleFence) | Err(StoreError::LeaseExpired)
    ));

    // Clean up
    wait_for_shutdown(&amf_1).await;
    println!("[HA] Test test_amf_lite_ha_failover_and_recovery passed successfully!");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_amf_lite_security_and_redaction() {
    println!("[Security] Starting test_amf_lite_security_and_redaction");
    let temp_dir = TempDir::new().unwrap();

    // 1. KMS Setup
    println!("[Security] Setting up FakeKms (Unix)");
    let kms_path = temp_dir.path().join("kms.sock");
    let kms = FakeKms::new_unix(&kms_path, KmsBehavior::default())
        .await
        .unwrap();
    let kms_endpoint = kms.endpoint().to_string();

    let key_config = [1u8; 32];
    kms.insert_key("key-config-1", "config", "system", key_config);
    kms.set_active_key("config", "system", "key-config-1");

    let key_session = [2u8; 32];
    kms.insert_key("key-session-1", "session", "system", key_session);
    kms.set_active_key("session", "system", "key-session-1");

    // 2. Config Store
    println!("[Security] Opening SqliteBackend");
    let db_path = temp_dir.path().join("amf_security.db");
    let backend = SqliteBackend::open_with_audit_key(&db_path, true, 0, test_audit_key())
        .await
        .unwrap();
    let config_store = Arc::new(backend);

    // 3. Quorum Session Store Setup
    let chaos = ChaosTestkit::new(3);

    // 4. NACM setup
    println!("[Security] Setting up NACM module and policy");
    let mut modules = ModuleRegistry::new();
    modules
        .register_module("openpacketcore-amf", "amf")
        .unwrap();
    let rule_update = NacmRule::allow(
        NacmAction::Update,
        opc_nacm::YangPathPattern::parse("/amf:amf/**", &modules).unwrap(),
    );
    let rule_replace = NacmRule::allow(
        NacmAction::Replace,
        opc_nacm::YangPathPattern::parse("/amf:amf/**", &modules).unwrap(),
    );
    let policy = Arc::new(
        NacmPolicy::builder(PolicyVersion::new(1))
            .add_rule(rule_update)
            .add_rule(rule_replace)
            .build(),
    );
    let nacm_modules = Arc::new(modules);

    // 5. Admin server port allocation
    let admin_ports = get_free_ports(1);
    let admin_addr: SocketAddr = format!("127.0.0.1:{}", admin_ports[0]).parse().unwrap();
    let auth_token = "secure-amf-token".to_string();

    // 6. Launch AMF-lite
    println!("[Security] Starting AMF-lite");
    let amf = AmfLite::start(
        AmfConfig::default(),
        config_store,
        chaos.replicas.clone(),
        kms_endpoint.clone(),
        Some(auth_token.clone()),
        admin_addr,
        policy,
        nacm_modules,
    )
    .await
    .unwrap();

    // 7. NACM block guest role
    println!("[Security] Verifying guest role is blocked by NACM");
    let candidate = AmfConfig {
        hostname: "amf-unauthorized".to_string(),
        nrf_endpoint: "http://nrf.openpacketcore.internal".to_string(),
        plmn_id: "20896".to_string(),
        capacity: 3000,
    };
    let guest_principal = TrustedPrincipal::new(
        WorkloadIdentity::Internal("guest-user".to_string()),
        TenantId::new("system").unwrap(),
    )
    .with_roles(vec!["guest"]);

    let commit_err = amf.commit_config(candidate.clone(), guest_principal).await;
    let commit_err = commit_err.unwrap_err();
    assert!(commit_err.to_string().contains("authorization denied"));

    // Verify audit log has the attempt or that NACM denied metric is incremented
    let deny_count = opc_redaction::metrics::METRICS
        .nacm_eval_deny
        .load(std::sync::atomic::Ordering::Relaxed);
    assert!(deny_count >= 1);

    // 8. KMS Unavailable / Timeout fails closed without secret leakage
    println!("[Security] Setting KMS to unavailable and verifying it fails closed");
    kms.set_behavior(KmsBehavior {
        unavailable: true,
        delay: None,
        simulate_error: false,
    });

    let admin_principal = TrustedPrincipal::new(
        WorkloadIdentity::Internal("admin".to_string()),
        TenantId::new("system").unwrap(),
    )
    .with_roles(vec!["admin"]);

    let kms_err = amf.commit_config(candidate.clone(), admin_principal).await;
    assert!(kms_err.is_err());

    // Restore KMS
    kms.set_behavior(KmsBehavior::default());

    // 9. Redaction verification
    // Register a UE context with IMSI
    println!("[Security] Verifying IMSI is redacted and redaction-safe in metrics");
    let imsi = "208960000000003";
    amf.register_ue(imsi, 303, Duration::from_secs(10))
        .await
        .unwrap();

    // Fetch metrics via admin server and verify IMSI is not present (redacted/redaction-safe)
    let (_, metrics_resp) = query_admin(admin_addr, "/metrics", Some(&auth_token)).await;
    assert!(!metrics_resp.contains(imsi));

    // Clean up
    wait_for_shutdown(&amf).await;
    println!("[Security] Test test_amf_lite_security_and_redaction passed successfully!");
}
