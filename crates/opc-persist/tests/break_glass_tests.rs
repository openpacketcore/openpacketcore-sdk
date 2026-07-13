use std::sync::Arc;
use tempfile::tempdir;
use tokio::sync::{Barrier, Mutex as TokioMutex};

mod common;
use common::wait_until_async;

use opc_alarm::{Severity, SharedAlarmManager};
use opc_key::{KeyId, KeyPurpose, MemoryKeyProvider, Zeroizing};
use opc_nacm::{ModuleRegistry, NacmAction, NacmPolicy, NacmRule, PolicyVersion, YangPathPattern};
use opc_persist::{
    AuditKey, BreakGlassAlarmNotifier, BreakGlassRequest, BreakGlassService, BreakGlassStatus,
    SecurityPolicyError, SecurityPolicyService, SqliteBackend, SqliteSecurityPolicyService,
};
use opc_types::TenantId;

static TEST_MUTEX: TokioMutex<()> = TokioMutex::const_new(());

fn get_admin_principal(name: &str) -> String {
    format!(
        "spiffe://test-domain/tenant/test-tenant/ns/default/sa/security-admin/nf/amf/instance/{name}"
    )
}

fn get_non_admin_principal() -> String {
    "spiffe://test-domain/tenant/test-tenant/ns/default/sa/normal-user/nf/amf/instance/0"
        .to_string()
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
        let text = format!("Active break-glass session {session_id} for tenant {tenant}");
        let _ = self.manager.raise(
            opc_alarm::AlarmType::new("security.break-glass"),
            opc_alarm::Severity::Warning,
            opc_alarm::ProbableCause::SecurityBreakGlass,
            opc_alarm::AffectedObject::Tenant {
                tenant: tenant.to_string(),
            },
            Some(tenant.to_string()),
            None,
            None,
            opc_alarm::RedactedText::new(text),
            opc_alarm::AlarmDetails::empty(),
        );
        Ok(())
    }

    async fn resolve_alarm(&self, tenant: &str, _session_id: &str) -> Result<(), String> {
        let _ = self.manager.clear(
            &opc_alarm::AlarmType::new("security.break-glass"),
            opc_alarm::ProbableCause::SecurityBreakGlass,
            &opc_alarm::AffectedObject::Tenant {
                tenant: tenant.to_string(),
            },
            Some(tenant),
            None,
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
    let db_path = temp_dir.path().join("test_break_glass.db");

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

fn make_test_break_glass_request(
    tenant: &str,
    principal: &str,
    evidence_id: &str,
) -> BreakGlassRequest {
    BreakGlassRequest {
        principal: principal.to_string(),
        tenant: tenant.to_string(),
        reason: format!("Investigate incident {evidence_id}"),
        scope: "/security:break-glass".to_string(),
        requested_duration: 60,
        evidence_id: evidence_id.to_string(),
    }
}

async fn install_break_glass_policy(
    service: &SqliteSecurityPolicyService<MemoryKeyProvider>,
    tenant: &str,
    principal: &str,
) {
    service
        .stage_policy(
            tenant,
            principal,
            make_break_glass_policy(1, true, true, true, true),
        )
        .await
        .unwrap();
    service.apply_policy(tenant, principal).await.unwrap();
}

async fn seed_break_glass_audit(
    service: &SqliteSecurityPolicyService<MemoryKeyProvider>,
    tenant: &str,
    requester: &str,
    approver: &str,
) {
    install_break_glass_policy(service, tenant, requester).await;
    let session = service
        .request_break_glass(
            tenant,
            requester,
            make_test_break_glass_request(tenant, requester, "AUDIT-SEED"),
        )
        .await
        .unwrap();
    service
        .approve_break_glass(tenant, approver, &session.id)
        .await
        .unwrap();
    service
        .revoke_break_glass(tenant, requester, &session.id)
        .await
        .unwrap();
}

#[tokio::test]
async fn test_break_glass_happy_path_lifecycle() {
    let _guard = TEST_MUTEX.lock().await;
    let (service, alarm_manager, _temp_dir) = setup_break_glass_service().await;
    let tenant = "test-tenant";
    let requester = get_admin_principal("requester");
    let approver = get_admin_principal("approver");

    // Bootstrap policy allowing break glass transitions
    let policy = make_break_glass_policy(1, true, true, true, true);
    service
        .stage_policy(tenant, &requester, policy)
        .await
        .unwrap();
    service.apply_policy(tenant, &requester).await.unwrap();

    // 1. Request
    let request = BreakGlassRequest {
        principal: requester.clone(),
        tenant: tenant.to_string(),
        reason: "Emergency database repair".to_string(),
        scope: "/security:break-glass".to_string(),
        requested_duration: 300,
        evidence_id: "TICKET-1234".to_string(),
    };

    let session = service
        .request_break_glass(tenant, &requester, request)
        .await
        .unwrap();
    assert_eq!(session.status, BreakGlassStatus::Requested);
    assert_eq!(session.request.reason, "Emergency database repair");

    // 2. Approve
    let session = service
        .approve_break_glass(tenant, &approver, &session.id)
        .await
        .unwrap();
    assert_eq!(session.status, BreakGlassStatus::Approved);
    assert_eq!(session.approver, Some(approver.clone()));

    // Verify alarm is not yet active
    assert_eq!(alarm_manager.active_count(), 0);

    // 3. Activate
    let session = service
        .activate_break_glass(tenant, &requester, &session.id)
        .await
        .unwrap();
    assert_eq!(session.status, BreakGlassStatus::Active);
    assert!(session.expires_at.is_some());

    // Verify warning alarm raised
    assert_eq!(alarm_manager.active_count(), 1);
    let alarms = alarm_manager.active_alarms();
    assert_eq!(alarms[0].alarm_type.as_str(), "security.break-glass");
    assert_eq!(alarms[0].severity, Severity::Warning);

    // 4. Revoke
    let session = service
        .revoke_break_glass(tenant, &requester, &session.id)
        .await
        .unwrap();
    assert_eq!(session.status, BreakGlassStatus::Revoked);

    // Verify alarm resolved
    assert_eq!(alarm_manager.active_count(), 0);
}

#[tokio::test]
async fn test_break_glass_excessive_duration_rejected() {
    let _guard = TEST_MUTEX.lock().await;
    let (service, _, _temp_dir) = setup_break_glass_service().await;
    let tenant = "test-tenant";
    let requester = get_admin_principal("requester");

    let request = BreakGlassRequest {
        principal: requester.clone(),
        tenant: tenant.to_string(),
        reason: "Emergency repair".to_string(),
        scope: "/security:break-glass".to_string(),
        requested_duration: 901, // exceeds 900 limit
        evidence_id: "TICKET-123".to_string(),
    };

    let res = service
        .request_break_glass(tenant, &requester, request)
        .await;
    assert!(res.is_err());
    let err = res.err().unwrap();
    assert!(format!("{err:?}").contains("duration"));
}

#[tokio::test]
async fn test_break_glass_missing_reason_rejected() {
    let _guard = TEST_MUTEX.lock().await;
    let (service, _, _temp_dir) = setup_break_glass_service().await;
    let tenant = "test-tenant";
    let requester = get_admin_principal("requester");

    let request = BreakGlassRequest {
        principal: requester.clone(),
        tenant: tenant.to_string(),
        reason: "   ".to_string(), // empty
        scope: "/security:break-glass".to_string(),
        requested_duration: 60,
        evidence_id: "TICKET-123".to_string(),
    };

    let res = service
        .request_break_glass(tenant, &requester, request)
        .await;
    assert!(res.is_err());
}

#[tokio::test]
async fn test_break_glass_two_person_approval_requester_cannot_approve() {
    let _guard = TEST_MUTEX.lock().await;
    let (service, _, _temp_dir) = setup_break_glass_service().await;
    let tenant = "test-tenant";
    let requester = get_admin_principal("requester");

    let request = BreakGlassRequest {
        principal: requester.clone(),
        tenant: tenant.to_string(),
        reason: "Repair".to_string(),
        scope: "/security:break-glass".to_string(),
        requested_duration: 60,
        evidence_id: "TICKET-123".to_string(),
    };

    let session = service
        .request_break_glass(tenant, &requester, request)
        .await
        .unwrap();

    // Requester attempts to approve their own request
    let res = service
        .approve_break_glass(tenant, &requester, &session.id)
        .await;
    assert!(res.is_err());
    let err = res.err().unwrap();
    assert!(format!("{err:?}").contains("different principal"));
}

#[tokio::test]
async fn test_break_glass_unauthorized_approver_role_rejected() {
    let _guard = TEST_MUTEX.lock().await;
    let (service, _, _temp_dir) = setup_break_glass_service().await;
    let tenant = "test-tenant";
    let requester = get_admin_principal("requester");
    let normal_user = get_non_admin_principal();

    let request = BreakGlassRequest {
        principal: requester.clone(),
        tenant: tenant.to_string(),
        reason: "Repair".to_string(),
        scope: "/security:break-glass".to_string(),
        requested_duration: 60,
        evidence_id: "TICKET-123".to_string(),
    };

    let session = service
        .request_break_glass(tenant, &requester, request)
        .await
        .unwrap();

    // Normal user (non-admin) tries to approve
    let res = service
        .approve_break_glass(tenant, &normal_user, &session.id)
        .await;
    assert!(res.is_err());
    let err = res.err().unwrap();
    assert!(format!("{err:?}").contains("lacks 'security-admin' role"));
}

#[tokio::test]
async fn test_break_glass_unauthorized_action_by_policy() {
    let _guard = TEST_MUTEX.lock().await;
    let (service, _, _temp_dir) = setup_break_glass_service().await;
    let tenant = "test-tenant";
    let requester = get_admin_principal("requester");
    let approver = get_admin_principal("approver");

    // Policy denying Approve action
    let policy = make_break_glass_policy(1, true, false, true, true);
    service
        .stage_policy(tenant, &requester, policy)
        .await
        .unwrap();
    service.apply_policy(tenant, &requester).await.unwrap();

    let request = BreakGlassRequest {
        principal: requester.clone(),
        tenant: tenant.to_string(),
        reason: "Repair".to_string(),
        scope: "/security:break-glass".to_string(),
        requested_duration: 60,
        evidence_id: "TICKET-123".to_string(),
    };

    let session = service
        .request_break_glass(tenant, &requester, request)
        .await
        .unwrap();

    // Approver has security-admin role, but policy explicitly denies approve action
    let res = service
        .approve_break_glass(tenant, &approver, &session.id)
        .await;
    assert!(res.is_err());
    let err = res.err().unwrap();
    let err_msg = format!("{err:?}");
    assert!(err_msg.contains("lacks permission") || err_msg.contains("Access denied"));
}

#[tokio::test]
async fn test_break_glass_audit_corruption_fails_closed() {
    let _guard = TEST_MUTEX.lock().await;
    let temp_dir = tempdir().unwrap();
    let db_path = temp_dir.path().join("test_break_glass_audit_corrupt.db");

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
        manager: alarm_manager,
    });
    let service = SqliteSecurityPolicyService::new_with_notifier(
        backend.clone(),
        key_provider,
        alarm_notifier,
    );

    let tenant = "test-tenant";
    let requester = get_admin_principal("requester");
    let approver = get_admin_principal("approver");

    let policy = make_break_glass_policy(1, true, true, true, true);
    service
        .stage_policy(tenant, &requester, policy)
        .await
        .unwrap();
    service.apply_policy(tenant, &requester).await.unwrap();

    let request = BreakGlassRequest {
        principal: requester.clone(),
        tenant: tenant.to_string(),
        reason: "Investigate active incident".to_string(),
        scope: "/security:break-glass".to_string(),
        requested_duration: 60,
        evidence_id: "TICKET-456".to_string(),
    };

    let session = service
        .request_break_glass(tenant, &requester, request)
        .await
        .unwrap();

    {
        let db = rusqlite::Connection::open(&db_path).unwrap();
        db.execute(
            "UPDATE break_glass_audit SET entry_hmac = ?1 WHERE tenant = ?2",
            rusqlite::params![vec![0x01_u8, 0x02, 0x03], tenant],
        )
        .unwrap();
    }

    let res = service
        .approve_break_glass(tenant, &approver, &session.id)
        .await;
    assert!(
        matches!(res, Err(opc_persist::SecurityPolicyError::Internal)),
        "corrupt audit HMAC length must fail closed, got: {res:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_break_glass_audit_concurrent_appends_remain_linear() {
    let _guard = TEST_MUTEX.lock().await;
    let (service, _, temp_dir) = setup_break_glass_service().await;
    let tenant = "test-tenant";
    let principal_a = get_admin_principal("requester-a");
    let principal_b = get_admin_principal("requester-b");
    install_break_glass_policy(&service, tenant, &principal_a).await;
    let request_a = make_test_break_glass_request(tenant, &principal_a, "CONCURRENT-A");
    let request_b = make_test_break_glass_request(tenant, &principal_b, "CONCURRENT-B");
    let service = Arc::new(service);
    let barrier = Arc::new(Barrier::new(3));

    let first = {
        let service = Arc::clone(&service);
        let barrier = Arc::clone(&barrier);
        tokio::spawn(async move {
            barrier.wait().await;
            service
                .request_break_glass(tenant, &principal_a, request_a)
                .await
        })
    };
    let second = {
        let service = Arc::clone(&service);
        let barrier = Arc::clone(&barrier);
        tokio::spawn(async move {
            barrier.wait().await;
            service
                .request_break_glass(tenant, &principal_b, request_b)
                .await
        })
    };

    barrier.wait().await;
    first.await.unwrap().unwrap();
    second.await.unwrap().unwrap();

    let db_path = temp_dir.path().join("test_break_glass.db");
    let conn = rusqlite::Connection::open(db_path).unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT previous_hash, entry_hmac FROM break_glass_audit WHERE tenant = ?1 ORDER BY id ASC",
        )
        .unwrap();
    let rows = stmt
        .query_map([tenant], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
        })
        .unwrap();

    let mut prev_hash = vec![0u8; 32];
    let mut row_count = 0;
    for row in rows {
        let (previous_hash, entry_hmac) = row.unwrap();
        assert_eq!(
            previous_hash, prev_hash,
            "audit chain forked at row {row_count}"
        );
        prev_hash = entry_hmac;
        row_count += 1;
    }
    assert_eq!(row_count, 2);
}

#[tokio::test]
async fn test_break_glass_audit_verifier_rejects_detail_tamper() {
    let _guard = TEST_MUTEX.lock().await;
    let (service, _, temp_dir) = setup_break_glass_service().await;
    let tenant = "test-tenant";
    let requester = get_admin_principal("requester");
    let approver = get_admin_principal("approver");
    seed_break_glass_audit(&service, tenant, &requester, &approver).await;

    let db_path = temp_dir.path().join("test_break_glass.db");
    let conn = rusqlite::Connection::open(db_path).unwrap();
    conn.execute(
        "UPDATE break_glass_audit SET details = 'tampered' WHERE tenant = ?1 AND id = (
            SELECT id FROM break_glass_audit WHERE tenant = ?1 ORDER BY id ASC LIMIT 1 OFFSET 1
        )",
        [tenant],
    )
    .unwrap();

    let res = service.verify_break_glass_audit_chain(tenant).await;
    assert!(
        matches!(res, Err(SecurityPolicyError::Internal)),
        "tampered break-glass audit details must fail verification, got: {res:?}"
    );
}

#[tokio::test]
async fn test_break_glass_audit_verifier_rejects_tail_delete() {
    let _guard = TEST_MUTEX.lock().await;
    let (service, _, temp_dir) = setup_break_glass_service().await;
    let tenant = "test-tenant";
    let requester = get_admin_principal("requester");
    let approver = get_admin_principal("approver");
    seed_break_glass_audit(&service, tenant, &requester, &approver).await;

    let db_path = temp_dir.path().join("test_break_glass.db");
    let conn = rusqlite::Connection::open(db_path).unwrap();
    conn.execute(
        "DELETE FROM break_glass_audit WHERE tenant = ?1 AND id = (
            SELECT id FROM break_glass_audit WHERE tenant = ?1 ORDER BY id DESC LIMIT 1
        )",
        [tenant],
    )
    .unwrap();

    let res = service.verify_break_glass_audit_chain(tenant).await;
    assert!(
        matches!(res, Err(SecurityPolicyError::Internal)),
        "deleted break-glass audit tail must fail verification, got: {res:?}"
    );
}

#[tokio::test]
async fn test_break_glass_expiry() {
    let _guard = TEST_MUTEX.lock().await;
    let (service, alarm_manager, _temp_dir) = setup_break_glass_service().await;
    let tenant = "test-tenant";
    let requester = get_admin_principal("requester");
    let approver = get_admin_principal("approver");

    let request = BreakGlassRequest {
        principal: requester.clone(),
        tenant: tenant.to_string(),
        reason: "Quick test".to_string(),
        scope: "/security:break-glass".to_string(),
        requested_duration: 1, // 1 second duration
        evidence_id: "TICKET-999".to_string(),
    };

    let session = service
        .request_break_glass(tenant, &requester, request)
        .await
        .unwrap();
    let session = service
        .approve_break_glass(tenant, &approver, &session.id)
        .await
        .unwrap();
    let session = service
        .activate_break_glass(tenant, &requester, &session.id)
        .await
        .unwrap();
    assert_eq!(session.status, BreakGlassStatus::Active);
    assert_eq!(alarm_manager.active_count(), 1);

    wait_until_async(
        "break-glass session to expire and resolve alarm",
        std::time::Duration::from_secs(10),
        || {
            let service = &service;
            let alarm_manager = alarm_manager.clone();
            let session_id = session.id.clone();
            async move {
                if service.clean_expired(tenant).await.is_err() {
                    return false;
                }
                match service.get_session(tenant, &session_id).await {
                    Ok(session) => {
                        session.status == BreakGlassStatus::Expired
                            && alarm_manager.active_count() == 0
                    }
                    Err(_) => false,
                }
            }
        },
    )
    .await;

    // Trigger access, which should clean expired sessions
    let _session_status = service.get_session(tenant, &session.id).await.unwrap();
    // Wait, the clean_expired is called in request/approve/activate/deny/revoke, but get_session doesn't call it.
    // Let's call clean_expired explicitly or call get_session which shows updated or let's check clean_expired.
    service.clean_expired(tenant).await.unwrap();

    let session_status_after = service.get_session(tenant, &session.id).await.unwrap();
    assert_eq!(session_status_after.status, BreakGlassStatus::Expired);

    // Verify alarm resolved automatically
    assert_eq!(alarm_manager.active_count(), 0);
}

#[test]
fn test_break_glass_telemetry_redaction() {
    // Principal contains SPIFFE ID which is sensitive and must be redacted in metrics labels
    let principal =
        "spiffe://test-domain/tenant/test-tenant/ns/default/sa/security-admin/nf/amf/instance/0";
    let safe_label = opc_redaction::metrics::metrics_label_safe(principal);
    assert_eq!(safe_label, "redacted");

    // Check that reasons containing sensitive digit runs or IP addresses are redacted
    let reason_with_ip = "Connecting from 192.168.1.50 for database recovery";
    let mut val_opt = Some(serde_json::to_string(&reason_with_ip).unwrap());
    let mut applied = false;
    opc_persist::redact_entry("reason", &mut val_opt, &mut applied);
    assert!(applied);
    assert!(val_opt.unwrap().contains("<redacted>"));
}
