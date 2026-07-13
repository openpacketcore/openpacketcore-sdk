use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;

use opc_alarm::{AffectedObject, AlarmDetails, AlarmType, ProbableCause, RedactedText, Severity};
use opc_amf_lite::{AmfConfig, AmfLite};
use opc_config_model::{CommitMode, CommitStatus, TrustedPrincipal, WorkloadIdentity};
use opc_nacm::{ModuleRegistry, NacmAction, NacmPolicy, NacmRule, PolicyVersion};
use opc_persist::{AuditKey, ConfigStore, SqliteBackend};
use opc_security_testkit::{short_unix_socket_path, FakeKms, KmsBehavior};
use opc_session_store::{
    CompareAndSet, OwnerId, SessionBackend, SessionLeaseManager, StateClass, StateType, StoreError,
    StoredSessionRecord,
};
use opc_session_testkit::ConsensusTestCluster;
use opc_testbed::VirtualClock;
use opc_types::{TenantId, Timestamp};

mod config_consensus_common;
use config_consensus_common::ConfigCluster;

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

async fn wait_for_amf_readiness(amf: &AmfLite, expected: opc_runtime::Readiness) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        if amf.readiness().await == expected {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for AMF readiness {expected:?}"
        );
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_amf_lite_e2e_happy_path() {
    println!("[E2E] Starting test_amf_lite_e2e_happy_path");
    let temp_dir = TempDir::new().unwrap();

    // 1. KMS Setup
    println!("[E2E] Setting up FakeKms (Unix)");
    let kms_path = short_unix_socket_path("kms");
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

    // 3. Real three-member Openraft Session Store Setup.
    println!("[E2E] Starting Openraft session fleet");
    let session_cluster = ConsensusTestCluster::start(3).await;

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
    let mut virtual_clock = VirtualClock::new(Timestamp::now_utc());
    virtual_clock.advance(time::Duration::seconds(42));
    let expected_session_time = virtual_clock.now();
    let amf = AmfLite::start_with_clock(
        AmfConfig::default(),
        config_store,
        session_cluster.store(0),
        kms_endpoint,
        Some(auth_token.clone()),
        admin_addr,
        policy,
        nacm_modules,
        Arc::new(virtual_clock),
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

    println!("[E2E] Removing the durable session-store quorum");
    session_cluster.set_node_online(1, false);
    session_cluster.set_node_online(2, false);
    wait_for_amf_readiness(&amf, opc_runtime::Readiness::NotReady).await;
    let (status_no_quorum, _) = query_admin(admin_addr, "/readyz", Some(&auth_token)).await;
    assert_eq!(status_no_quorum, 503);

    println!("[E2E] Restoring the durable session-store quorum");
    session_cluster.set_node_online(1, true);
    session_cluster.set_node_online(2, true);
    wait_for_amf_readiness(&amf, opc_runtime::Readiness::Ready).await;
    let (status_quorum_restored, _) = query_admin(admin_addr, "/readyz", Some(&auth_token)).await;
    assert_eq!(status_quorum_restored, 200);

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
    let key = amf.session_key_for_subscriber(imsi).await.unwrap();
    assert!(
        !key.stable_id
            .as_ref()
            .windows(imsi.len())
            .any(|window| window == imsi.as_bytes()),
        "session stable_id must not contain the raw IMSI"
    );
    let retrieved = amf.session_store().get(&key).await.unwrap().unwrap();
    let plaintext_payload = retrieved.payload.as_bytes();
    let payload_json = std::str::from_utf8(plaintext_payload).unwrap();
    assert!(
        !payload_json.contains(imsi),
        "session payload must not contain the raw IMSI"
    );
    let ctx: opc_amf_lite::UeSessionContext = serde_json::from_slice(plaintext_payload).unwrap();
    assert_eq!(
        key.stable_id.len(),
        opc_session_store::STABLE_ID_HMAC_SHA256_BYTES
    );
    assert_ne!(ctx.subscriber_pseudonym.as_bytes(), key.stable_id.as_ref());
    assert!(!ctx.subscriber_pseudonym.contains(imsi));
    assert_eq!(ctx.subscriber_identity, "<subscriber-id>");
    assert_eq!(ctx.state, "REGISTERED");
    assert_eq!(ctx.amf_ue_ngap_id, 101);
    assert_eq!(ctx.last_updated, expected_session_time);
    assert_eq!(
        retrieved.expires_at,
        Some(opc_amf_lite::add_duration(
            expected_session_time,
            Duration::from_secs(10)
        ))
    );

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
async fn test_amf_lite_config_ha_failover_and_session_recovery() {
    println!("[HA] Starting test_amf_lite_config_ha_failover_and_session_recovery");
    let temp_dir = TempDir::new().unwrap();

    // 1. KMS Setup
    println!("[HA] Setting up FakeKms (Unix)");
    let kms_path = short_unix_socket_path("kms");
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

    // 2. Three-member Openraft config group. The SDK-facing store forwards
    // writes to the current leader, so the AMF does not own election logic.
    println!("[HA] Building 3-node Openraft config group");
    let config_cluster = ConfigCluster::start(temp_dir.path()).await;
    let original_leader = config_cluster.leader();

    // 3. Real three-member Openraft session fleet.
    println!("[HA] Starting Openraft session fleet");
    let session_cluster = ConsensusTestCluster::start(3).await;

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

    // 6. Start AMF on the current config leader.
    println!("[HA] Starting AMF node 0 on the current Openraft config leader");
    let amf_0 = AmfLite::start(
        AmfConfig::default(),
        Arc::new(config_cluster.stores[original_leader].clone()),
        session_cluster.store(0),
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

    // Confirm it on leader node 0
    println!("[HA] Submitting standard commit to confirm config on leader node 0");
    let confirmed = amf_0
        .commit_config_with_mode(candidate.clone(), principal.clone(), CommitMode::Commit)
        .await
        .expect("HA confirm commit must succeed");
    assert_eq!(confirmed.status, CommitStatus::Committed);

    // 7. Commit through one member of the Openraft session fleet.
    let imsi = "208960000000002";
    println!("[HA] Registering UE context through Openraft session member 0");
    amf_0
        .register_ue(imsi, 202, Duration::from_secs(10))
        .await
        .unwrap();

    // Verify the persisted key does not expose the subscriber identity.
    let key = amf_0.session_key_for_subscriber(imsi).await.unwrap();
    assert!(
        !key.stable_id
            .as_ref()
            .windows(imsi.len())
            .any(|window| window == imsi.as_bytes()),
        "session stable_id must not contain the raw IMSI"
    );

    // 8. Simulate AMF Node 0 crash & Consensus leader failover
    println!("[HA] Shutting down AMF node 0 and isolating its config leader");
    wait_for_shutdown(&amf_0).await;
    config_cluster.isolate(original_leader);
    let survivor_leader = config_cluster
        .wait_for_survivor_leader(original_leader)
        .await;

    // Start a new AMF-lite instance targeting the new consensus leader
    let admin_ports_new = get_free_ports(1);
    let admin_addr_new: SocketAddr = format!("127.0.0.1:{}", admin_ports_new[0]).parse().unwrap();

    assert!(config_cluster.stores[survivor_leader]
        .load_latest()
        .await
        .expect("survivor config read")
        .is_some());
    println!("[HA] Launching new AMF node 1 on the survivor config leader");
    let recovered_session_store = session_cluster.store(1);
    let amf_1 = AmfLite::start(
        AmfConfig::default(),
        Arc::new(config_cluster.stores[survivor_leader].clone()),
        recovered_session_store,
        kms_endpoint.clone(),
        Some(auth_token.clone()),
        admin_addr_new,
        policy.clone(),
        nacm_modules.clone(),
    )
    .await
    .expect("AMF node 1 starts on the recovered config authority");

    // Verify recovery: the new instance recovered the last committed config from node 1!
    println!("[HA] Verifying recovered config hostname on node 1");
    let recovered_snap = amf_1.config_bus().current_snapshot();
    println!(
        "[HA] Recovered snapshot: version={:?} config={:?}",
        recovered_snap.version, recovered_snap.config
    );
    assert_eq!(recovered_snap.config.hostname, "amf-ha-node0");
    assert_eq!(recovered_snap.config.capacity, 4000);

    // Read the encrypted UE state through the newly started AMF process.
    println!("[HA] Querying UE state from new AMF node 1");
    let retrieved = amf_1.session_store().get(&key).await.unwrap().unwrap();
    let ctx: opc_amf_lite::UeSessionContext =
        serde_json::from_slice(retrieved.payload.as_bytes()).unwrap();
    assert!(!ctx.subscriber_pseudonym.contains(imsi));
    assert_eq!(ctx.amf_ue_ngap_id, 202);

    // An independent follower serves the same committed encrypted record
    // through a linearizable read after its state machine catches up.
    println!("[HA] Verifying session follower 2 serves committed state");
    let kms_provider = Arc::new(opc_key::KmsKeyProvider::new(
        kms_endpoint.clone(),
        None,
        Duration::from_secs(2),
    ));
    let follower_backend = opc_session_store::EncryptingSessionBackend::new(
        Arc::new(session_cluster.store(2)),
        kms_provider,
        "amf-sessions",
    );
    let follower_record = follower_backend.get(&key).await.unwrap().unwrap();
    let follower_ctx: opc_amf_lite::UeSessionContext =
        serde_json::from_slice(follower_record.payload.as_bytes()).unwrap();
    assert_eq!(follower_ctx.amf_ue_ngap_id, 202);

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
    config_cluster.shutdown().await;
    println!(
        "[HA] Test test_amf_lite_config_ha_failover_and_session_recovery passed successfully!"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_amf_lite_security_and_redaction() {
    println!("[Security] Starting test_amf_lite_security_and_redaction");
    let temp_dir = TempDir::new().unwrap();

    // 1. KMS Setup
    println!("[Security] Setting up FakeKms (Unix)");
    let kms_path = short_unix_socket_path("kms");
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

    // 3. Openraft Session Store Setup
    let session_cluster = ConsensusTestCluster::start(1).await;

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
        session_cluster.store(0),
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
        ..KmsBehavior::default()
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
