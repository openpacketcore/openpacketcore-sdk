use hmac::Mac;
use std::sync::Arc;
use tempfile::tempdir;
use tokio::sync::Mutex as TokioMutex;

use opc_alarm::SharedAlarmManager;
use opc_key::{KeyId, KeyPurpose, MemoryKeyProvider, Zeroizing};
use opc_nacm::{ModuleRegistry, NacmAction, NacmPolicy, NacmRule, PolicyVersion, YangPathPattern};
use opc_persist::{
    AuditKey, BreakGlassAlarmNotifier, BreakGlassRequest, BreakGlassService, BreakGlassStatus,
    SecurityPolicyService, SqliteBackend, SqliteSecurityPolicyService,
};
use opc_types::TenantId;

static TEST_MUTEX: TokioMutex<()> = TokioMutex::const_new(());

fn get_admin_principal(name: &str) -> String {
    format!(
        "spiffe://test-domain/tenant/test-tenant/ns/default/sa/security-admin/nf/amf/instance/{}",
        name
    )
}

fn make_break_glass_policy(
    version: u64,
    allow_request: bool,
    allow_approve: bool,
    allow_activate: bool,
    allow_revoke: bool,
) -> NacmPolicy {
    let mut registry = ModuleRegistry::new();
    registry.register_module("security", "security").unwrap();
    let path_pattern = YangPathPattern::parse("/security:break-glass", &registry).unwrap();

    let mut builder = NacmPolicy::builder(PolicyVersion::new(version));

    if allow_request {
        builder = builder.add_rule(NacmRule::allow(NacmAction::Request, path_pattern.clone()));
    } else {
        builder = builder.add_rule(NacmRule::deny(NacmAction::Request, path_pattern.clone()));
    }

    if allow_approve {
        builder = builder.add_rule(NacmRule::allow(NacmAction::Approve, path_pattern.clone()));
    } else {
        builder = builder.add_rule(NacmRule::deny(NacmAction::Approve, path_pattern.clone()));
    }

    if allow_activate {
        builder = builder.add_rule(NacmRule::allow(NacmAction::Activate, path_pattern.clone()));
    } else {
        builder = builder.add_rule(NacmRule::deny(NacmAction::Activate, path_pattern.clone()));
    }

    if allow_revoke {
        builder = builder.add_rule(NacmRule::allow(NacmAction::Revoke, path_pattern.clone()));
    } else {
        builder = builder.add_rule(NacmRule::deny(NacmAction::Revoke, path_pattern.clone()));
    }

    let policy_path = YangPathPattern::parse("/security:policy", &registry).unwrap();
    builder = builder.add_rule(NacmRule::allow(NacmAction::SecurityAdmin, policy_path));

    builder.build()
}

pub struct TestAlarmNotifier {
    pub manager: SharedAlarmManager,
}

#[async_trait::async_trait]
impl BreakGlassAlarmNotifier for TestAlarmNotifier {
    async fn raise_alarm(&self, tenant: &str, session_id: &str) -> Result<(), String> {
        let text = format!(
            "Active break-glass session {} for tenant {}",
            session_id, tenant
        );
        let _ = self.manager.raise(
            opc_alarm::AlarmType::new("security.break-glass"),
            opc_alarm::Severity::Warning,
            opc_alarm::ProbableCause::SecurityBreakGlass,
            opc_alarm::AffectedObject::Slice {
                snssai: session_id.to_string(),
            },
            Some(tenant.to_string()),
            Some(session_id.to_string()),
            None,
            opc_alarm::RedactedText::new(text),
            opc_alarm::AlarmDetails::empty(),
        );
        Ok(())
    }

    async fn resolve_alarm(&self, tenant: &str, session_id: &str) -> Result<(), String> {
        let _ = self.manager.clear(
            &opc_alarm::AlarmType::new("security.break-glass"),
            opc_alarm::ProbableCause::SecurityBreakGlass,
            &opc_alarm::AffectedObject::Slice {
                snssai: session_id.to_string(),
            },
            Some(tenant),
            Some(session_id),
            None,
        );
        Ok(())
    }
}

async fn setup_break_glass_service() -> (
    SqliteSecurityPolicyService<MemoryKeyProvider>,
    SharedAlarmManager,
    tempfile::TempDir,
) {
    let temp_dir = tempdir().unwrap();
    let db_path = temp_dir.path().join("test_break_glass_stress.db");

    let backend =
        SqliteBackend::open_with_audit_key(&db_path, true, 0, AuditKey::new([0x42; 32]).unwrap())
            .await
            .unwrap();

    let key_provider = Arc::new(MemoryKeyProvider::new());
    let tenant_id = TenantId::new("test-tenant").unwrap();
    key_provider
        .insert_active_key(
            KeyId::new("key-1").unwrap(),
            KeyPurpose::ShadowSecurity,
            tenant_id,
            Zeroizing::new([0x99; 32]),
        )
        .unwrap();

    let alarm_manager = SharedAlarmManager::in_memory();
    let alarm_notifier = Arc::new(TestAlarmNotifier {
        manager: alarm_manager.clone(),
    });

    let service =
        SqliteSecurityPolicyService::new_with_notifier(backend, key_provider, alarm_notifier);
    (service, alarm_manager, temp_dir)
}

fn verify_break_glass_audit_chain(
    db_path: &std::path::Path,
    audit_key: &AuditKey,
    tenant: &str,
) -> Result<(), String> {
    // 1. Open SQLite database connection directly
    let conn = rusqlite::Connection::open(db_path).map_err(|e| e.to_string())?;

    // 2. Fetch all entries from break_glass_audit ordered by id ASC
    let mut stmt = conn.prepare(
        "SELECT tenant, timestamp, principal, action, details, previous_hash, entry_hmac FROM break_glass_audit WHERE tenant = ?1 ORDER BY id ASC"
    ).map_err(|e| e.to_string())?;

    struct AuditEntry {
        tenant: String,
        timestamp: String,
        principal: String,
        action: String,
        details: String,
        previous_hash: Vec<u8>,
        entry_hmac: Vec<u8>,
    }

    let rows = stmt
        .query_map([tenant], |row| {
            Ok(AuditEntry {
                tenant: row.get(0)?,
                timestamp: row.get(1)?,
                principal: row.get(2)?,
                action: row.get(3)?,
                details: row.get(4)?,
                previous_hash: row.get(5)?,
                entry_hmac: row.get(6)?,
            })
        })
        .map_err(|e| e.to_string())?;

    let mut prev_hash = vec![0u8; 32];

    for row_res in rows {
        let entry = row_res.map_err(|e| e.to_string())?;

        // Check previous hash links
        if entry.previous_hash != prev_hash {
            return Err("Previous hash link broken".to_string());
        }

        // Recalculate HMAC
        let mut mac_input = Vec::new();
        mac_input.extend_from_slice(&(entry.tenant.len() as u32).to_be_bytes());
        mac_input.extend_from_slice(entry.tenant.as_bytes());

        mac_input.extend_from_slice(&(entry.timestamp.len() as u32).to_be_bytes());
        mac_input.extend_from_slice(entry.timestamp.as_bytes());

        mac_input.extend_from_slice(&(entry.principal.len() as u32).to_be_bytes());
        mac_input.extend_from_slice(entry.principal.as_bytes());

        mac_input.extend_from_slice(&(entry.action.len() as u32).to_be_bytes());
        mac_input.extend_from_slice(entry.action.as_bytes());

        mac_input.extend_from_slice(&(entry.details.len() as u32).to_be_bytes());
        mac_input.extend_from_slice(entry.details.as_bytes());

        mac_input.extend_from_slice(&entry.previous_hash);

        type HmacSha256 = hmac::Hmac<sha2::Sha256>;
        let mut mac =
            HmacSha256::new_from_slice(audit_key.as_bytes()).map_err(|e| e.to_string())?;
        mac.update(&mac_input);
        let expected_hmac: [u8; 32] = mac.finalize().into_bytes().into();

        if entry.entry_hmac != expected_hmac {
            return Err("HMAC verification failed".to_string());
        }

        prev_hash = entry.entry_hmac.clone();
    }

    Ok(())
}

#[tokio::test]
async fn test_duration_boundaries() {
    let _guard = TEST_MUTEX.lock().await;
    let (service, _, _temp_dir) = setup_break_glass_service().await;
    let tenant = "test-tenant";
    let requester = get_admin_principal("requester");

    // Bootstrap policy
    let policy = make_break_glass_policy(1, true, true, true, true);
    service
        .stage_policy(tenant, &requester, policy)
        .await
        .unwrap();
    service.apply_policy(tenant, &requester).await.unwrap();

    // 1. Duration just below 900: 899 seconds (should succeed)
    let request_899 = BreakGlassRequest {
        principal: requester.clone(),
        tenant: tenant.to_string(),
        reason: "Boundary check 899".to_string(),
        scope: "/security:break-glass".to_string(),
        requested_duration: 899,
        evidence_id: "TICKET-899".to_string(),
    };
    let session_899 = service
        .request_break_glass(tenant, &requester, request_899)
        .await;
    assert!(session_899.is_ok());

    // 2. Duration exactly 900 seconds (should succeed)
    let request_900 = BreakGlassRequest {
        principal: requester.clone(),
        tenant: tenant.to_string(),
        reason: "Boundary check 900".to_string(),
        scope: "/security:break-glass".to_string(),
        requested_duration: 900,
        evidence_id: "TICKET-900".to_string(),
    };
    let session_900 = service
        .request_break_glass(tenant, &requester, request_900)
        .await;
    assert!(session_900.is_ok());

    // 3. Duration just above 900: 901 seconds (should fail)
    let request_901 = BreakGlassRequest {
        principal: requester.clone(),
        tenant: tenant.to_string(),
        reason: "Boundary check 901".to_string(),
        scope: "/security:break-glass".to_string(),
        requested_duration: 901,
        evidence_id: "TICKET-901".to_string(),
    };
    let session_901 = service
        .request_break_glass(tenant, &requester, request_901)
        .await;
    assert!(session_901.is_err());
    let err_msg = format!("{:?}", session_901.err().unwrap());
    assert!(err_msg.contains("Requested duration must be between 1 and 900 seconds"));

    // 4. Duration exactly 0 seconds (should fail)
    let request_0 = BreakGlassRequest {
        principal: requester.clone(),
        tenant: tenant.to_string(),
        reason: "Boundary check 0".to_string(),
        scope: "/security:break-glass".to_string(),
        requested_duration: 0,
        evidence_id: "TICKET-0".to_string(),
    };
    let session_0 = service
        .request_break_glass(tenant, &requester, request_0)
        .await;
    assert!(session_0.is_err());
}

#[tokio::test]
async fn test_concurrency_transitions() {
    let _guard = TEST_MUTEX.lock().await;
    let (service, _, _temp_dir) = setup_break_glass_service().await;
    let service = Arc::new(service);
    let tenant = "test-tenant";
    let requester = get_admin_principal("requester");

    // Bootstrap policy
    let policy = make_break_glass_policy(1, true, true, true, true);
    service
        .stage_policy(tenant, &requester, policy)
        .await
        .unwrap();
    service.apply_policy(tenant, &requester).await.unwrap();

    let mut tasks = vec![];
    let num_concurrent = 20;

    for i in 0..num_concurrent {
        let service_clone = Arc::clone(&service);
        let requester_clone = requester.clone();
        let approver = get_admin_principal(&format!("approver-{}", i));

        let t = tokio::spawn(async move {
            let request = BreakGlassRequest {
                principal: requester_clone.clone(),
                tenant: "test-tenant".to_string(),
                reason: format!("Concurrency test {}", i),
                scope: "/security:break-glass".to_string(),
                requested_duration: 60,
                evidence_id: format!("CONC-{}", i),
            };

            // 1. Request
            let session = service_clone
                .request_break_glass("test-tenant", &requester_clone, request)
                .await
                .unwrap();

            // 2. Approve
            let session = service_clone
                .approve_break_glass("test-tenant", &approver, &session.id)
                .await
                .unwrap();

            // 3. Activate
            let session = service_clone
                .activate_break_glass("test-tenant", &requester_clone, &session.id)
                .await
                .unwrap();

            assert_eq!(session.status, BreakGlassStatus::Active);
        });
        tasks.push(t);
    }

    for t in tasks {
        t.await.unwrap();
    }
}

#[tokio::test]
async fn test_survival_across_restart() {
    let _guard = TEST_MUTEX.lock().await;
    let temp_dir = tempdir().unwrap();
    let db_path = temp_dir.path().join("restart_survival.db");
    let tenant = "test-tenant";

    // Keep a helper scope to drop the first service instance
    let session_id_active = {
        let backend = SqliteBackend::open_with_audit_key(
            &db_path,
            true,
            0,
            AuditKey::new([0x42; 32]).unwrap(),
        )
        .await
        .unwrap();

        let key_provider = Arc::new(MemoryKeyProvider::new());
        let tenant_id = TenantId::new(tenant).unwrap();
        key_provider
            .insert_active_key(
                KeyId::new("key-1").unwrap(),
                KeyPurpose::ShadowSecurity,
                tenant_id,
                Zeroizing::new([0x99; 32]),
            )
            .unwrap();

        let alarm_manager = SharedAlarmManager::in_memory();
        let alarm_notifier = Arc::new(TestAlarmNotifier {
            manager: alarm_manager.clone(),
        });

        let service =
            SqliteSecurityPolicyService::new_with_notifier(backend, key_provider, alarm_notifier);

        let requester = get_admin_principal("requester");
        let approver = get_admin_principal("approver");

        // Bootstrap policy
        let policy = make_break_glass_policy(1, true, true, true, true);
        service
            .stage_policy(tenant, &requester, policy)
            .await
            .unwrap();
        service.apply_policy(tenant, &requester).await.unwrap();

        // Create session A (should survive as active)
        let request_a = BreakGlassRequest {
            principal: requester.clone(),
            tenant: tenant.to_string(),
            reason: "Session A (active)".to_string(),
            scope: "/security:break-glass".to_string(),
            requested_duration: 100,
            evidence_id: "RESTART-A".to_string(),
        };
        let session_a = service
            .request_break_glass(tenant, &requester, request_a)
            .await
            .unwrap();
        let session_a = service
            .approve_break_glass(tenant, &approver, &session_a.id)
            .await
            .unwrap();
        let session_a = service
            .activate_break_glass(tenant, &requester, &session_a.id)
            .await
            .unwrap();
        assert_eq!(session_a.status, BreakGlassStatus::Active);

        // Create session B (should expire during downtime)
        let request_b = BreakGlassRequest {
            principal: requester.clone(),
            tenant: tenant.to_string(),
            reason: "Session B (expired)".to_string(),
            scope: "/security:break-glass".to_string(),
            requested_duration: 1, // 1 second duration
            evidence_id: "RESTART-B".to_string(),
        };
        let session_b = service
            .request_break_glass(tenant, &requester, request_b)
            .await
            .unwrap();
        let session_b = service
            .approve_break_glass(tenant, &approver, &session_b.id)
            .await
            .unwrap();
        let session_b = service
            .activate_break_glass(tenant, &requester, &session_b.id)
            .await
            .unwrap();
        assert_eq!(session_b.status, BreakGlassStatus::Active);

        // Let session B expire
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        (session_a.id, session_b.id)
    };

    // Now, simulate the reload/restart. The original service has been dropped.
    // Create a new instance pointing to the same DB file.
    {
        let backend = SqliteBackend::open_with_audit_key(
            &db_path,
            true,
            0,
            AuditKey::new([0x42; 32]).unwrap(),
        )
        .await
        .unwrap();

        let key_provider = Arc::new(MemoryKeyProvider::new());
        let tenant_id = TenantId::new(tenant).unwrap();
        key_provider
            .insert_active_key(
                KeyId::new("key-1").unwrap(),
                KeyPurpose::ShadowSecurity,
                tenant_id,
                Zeroizing::new([0x99; 32]),
            )
            .unwrap();

        let alarm_manager = SharedAlarmManager::in_memory();
        let alarm_notifier = Arc::new(TestAlarmNotifier {
            manager: alarm_manager.clone(),
        });

        let service =
            SqliteSecurityPolicyService::new_with_notifier(backend, key_provider, alarm_notifier);

        // Verify that before cleaning, both are still in database in their original states
        let session_a_db = service
            .get_session(tenant, &session_id_active.0)
            .await
            .unwrap();
        let session_b_db = service
            .get_session(tenant, &session_id_active.1)
            .await
            .unwrap();

        assert_eq!(session_a_db.status, BreakGlassStatus::Active);
        assert_eq!(session_b_db.status, BreakGlassStatus::Active);

        // Trigger clean_expired explicitly
        service.clean_expired(tenant).await.unwrap();

        // Verify that B transitioned to Expired, while A remains Active
        let session_a_after = service
            .get_session(tenant, &session_id_active.0)
            .await
            .unwrap();
        let session_b_after = service
            .get_session(tenant, &session_id_active.1)
            .await
            .unwrap();

        assert_eq!(session_a_after.status, BreakGlassStatus::Active);
        assert_eq!(session_b_after.status, BreakGlassStatus::Expired);
    }
}

#[tokio::test]
async fn test_revocation_and_expiry_under_stress() {
    let _guard = TEST_MUTEX.lock().await;
    let (service, alarm_manager, _temp_dir) = setup_break_glass_service().await;
    let service = Arc::new(service);
    let tenant = "test-tenant";
    let requester = get_admin_principal("requester");

    // Bootstrap policy
    let policy = make_break_glass_policy(1, true, true, true, true);
    service
        .stage_policy(tenant, &requester, policy)
        .await
        .unwrap();
    service.apply_policy(tenant, &requester).await.unwrap();

    let mut session_ids_to_revoke = vec![];
    let mut session_ids_to_expire = vec![];

    // Request, approve and activate 10 sessions to revoke and 10 to expire
    for i in 0..10 {
        let approver = get_admin_principal(&format!("approver-{}", i));

        // Revoke target
        let req_rev = BreakGlassRequest {
            principal: requester.clone(),
            tenant: tenant.to_string(),
            reason: format!("Revoke target {}", i),
            scope: "/security:break-glass".to_string(),
            requested_duration: 100,
            evidence_id: format!("REV-{}", i),
        };
        let s_rev = service
            .request_break_glass(tenant, &requester, req_rev)
            .await
            .unwrap();
        let s_rev = service
            .approve_break_glass(tenant, &approver, &s_rev.id)
            .await
            .unwrap();
        let s_rev = service
            .activate_break_glass(tenant, &requester, &s_rev.id)
            .await
            .unwrap();
        session_ids_to_revoke.push(s_rev.id);

        // Expire target
        let req_exp = BreakGlassRequest {
            principal: requester.clone(),
            tenant: tenant.to_string(),
            reason: format!("Expire target {}", i),
            scope: "/security:break-glass".to_string(),
            requested_duration: 1, // 1 second
            evidence_id: format!("EXP-{}", i),
        };
        let s_exp = service
            .request_break_glass(tenant, &requester, req_exp)
            .await
            .unwrap();
        let s_exp = service
            .approve_break_glass(tenant, &approver, &s_exp.id)
            .await
            .unwrap();
        let s_exp = service
            .activate_break_glass(tenant, &requester, &s_exp.id)
            .await
            .unwrap();
        session_ids_to_expire.push(s_exp.id);
    }

    // Alarm count should be 20, because alarms are unique by session_id (slice)
    assert_eq!(alarm_manager.active_count(), 20);

    // Concurrently revoke the 10 revoke targets, and let the 10 expire targets time out.
    let mut revoke_tasks = vec![];
    for id in session_ids_to_revoke.clone() {
        let service_clone = Arc::clone(&service);
        let requester_clone = requester.clone();
        let t = tokio::spawn(async move {
            service_clone
                .revoke_break_glass("test-tenant", &requester_clone, &id)
                .await
                .unwrap();
        });
        revoke_tasks.push(t);
    }

    for t in revoke_tasks {
        t.await.unwrap();
    }

    // Wait for the 10 expire targets to expire
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    // Call clean_expired
    service.clean_expired(tenant).await.unwrap();

    // Verify all states
    for id in session_ids_to_revoke {
        let s = service.get_session(tenant, &id).await.unwrap();
        assert_eq!(s.status, BreakGlassStatus::Revoked);
    }
    for id in session_ids_to_expire {
        let s = service.get_session(tenant, &id).await.unwrap();
        assert_eq!(s.status, BreakGlassStatus::Expired);
    }

    // All alarms should be cleared
    assert_eq!(alarm_manager.active_count(), 0);
}

#[tokio::test]
async fn test_tampering_checks() {
    let _guard = TEST_MUTEX.lock().await;
    let temp_dir = tempdir().unwrap();
    let db_path = temp_dir.path().join("tampering_check.db");
    let tenant = "test-tenant";
    let audit_key = AuditKey::new([0x42; 32]).unwrap();

    // Setup service with our DB file
    let backend = SqliteBackend::open_with_audit_key(&db_path, true, 0, audit_key.clone())
        .await
        .unwrap();

    let key_provider = Arc::new(MemoryKeyProvider::new());
    let tenant_id = TenantId::new(tenant).unwrap();
    key_provider
        .insert_active_key(
            KeyId::new("key-1").unwrap(),
            KeyPurpose::ShadowSecurity,
            tenant_id,
            Zeroizing::new([0x99; 32]),
        )
        .unwrap();

    let alarm_manager = SharedAlarmManager::in_memory();
    let alarm_notifier = Arc::new(TestAlarmNotifier {
        manager: alarm_manager.clone(),
    });

    let service =
        SqliteSecurityPolicyService::new_with_notifier(backend, key_provider, alarm_notifier);

    let requester = get_admin_principal("requester");
    let approver = get_admin_principal("approver");

    // Bootstrap policy
    let policy = make_break_glass_policy(1, true, true, true, true);
    service
        .stage_policy(tenant, &requester, policy)
        .await
        .unwrap();
    service.apply_policy(tenant, &requester).await.unwrap();

    // 1. Generate some audit entries
    let request = BreakGlassRequest {
        principal: requester.clone(),
        tenant: tenant.to_string(),
        reason: "Tampering check entry".to_string(),
        scope: "/security:break-glass".to_string(),
        requested_duration: 100,
        evidence_id: "TICKET-TAMPER".to_string(),
    };
    let session = service
        .request_break_glass(tenant, &requester, request)
        .await
        .unwrap();
    let session = service
        .approve_break_glass(tenant, &approver, &session.id)
        .await
        .unwrap();
    let _session = service
        .activate_break_glass(tenant, &requester, &session.id)
        .await
        .unwrap();

    // Verify valid audit chain passes
    let verify_res = verify_break_glass_audit_chain(&db_path, &audit_key, tenant);
    assert!(
        verify_res.is_ok(),
        "Expected valid audit chain to pass verification"
    );

    // 2. Tamper check: Modify fields directly in SQLite (e.g. principal field)
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        // Modify principal in the first audit log entry
        conn.execute(
            "UPDATE break_glass_audit SET principal = ?1 WHERE id = 1",
            ["spiffe://test-domain/tenant/test-tenant/ns/default/sa/tampered-principal/nf/amf/instance/0"],
        )
        .unwrap();
    }

    // Verify verification fails now
    let verify_res = verify_break_glass_audit_chain(&db_path, &audit_key, tenant);
    assert!(
        verify_res.is_err(),
        "Expected verification to fail after modifying entry field"
    );

    // Restore principal, verify it passes again
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute(
            "UPDATE break_glass_audit SET principal = ?1 WHERE id = 1",
            [&requester],
        )
        .unwrap();
    }
    assert!(
        verify_break_glass_audit_chain(&db_path, &audit_key, tenant).is_ok(),
        "Expected verification to pass after restoration"
    );

    // 3. Tamper check: Modify HMAC directly in SQLite
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute(
            "UPDATE break_glass_audit SET entry_hmac = ?1 WHERE id = 1",
            [vec![0u8; 32]],
        )
        .unwrap();
    }
    let verify_res = verify_break_glass_audit_chain(&db_path, &audit_key, tenant);
    assert!(
        verify_res.is_err(),
        "Expected verification to fail after modifying entry HMAC"
    );
}
