use std::sync::atomic::Ordering;
use std::sync::Arc;
use tempfile::tempdir;
use tokio::sync::Mutex;

use opc_key::{KeyId, KeyPurpose, MemoryKeyProvider, Zeroizing};
use opc_nacm::{ModuleRegistry, NacmAction, NacmPolicy, NacmRule, PolicyVersion, YangPathPattern};
use opc_persist::{
    AuditKey, RollbackTarget, SecurityPolicyError, SecurityPolicyService, SqliteBackend,
    SqliteSecurityPolicyService, TEST_COMMIT_FAIL,
};
use opc_types::TenantId;

static TEST_MUTEX: Mutex<()> = Mutex::const_new(());

fn get_admin_principal() -> String {
    "spiffe://test-domain/tenant/test-tenant/ns/default/sa/security-admin/nf/amf/instance/0"
        .to_string()
}

fn get_non_admin_principal() -> String {
    "spiffe://test-domain/tenant/test-tenant/ns/default/sa/normal-user/nf/amf/instance/0"
        .to_string()
}

fn get_mismatched_tenant_principal() -> String {
    "spiffe://test-domain/tenant/other-tenant/ns/default/sa/security-admin/nf/amf/instance/0"
        .to_string()
}

fn make_valid_policy(version: u64) -> NacmPolicy {
    let mut registry = ModuleRegistry::new();
    registry.register_module("security", "security").unwrap();
    let path_pattern = YangPathPattern::parse("/security:policy", &registry).unwrap();
    let rule = NacmRule::allow(NacmAction::SecurityAdmin, path_pattern);
    NacmPolicy::builder(PolicyVersion::new(version))
        .add_rule(rule)
        .build()
}

fn make_invalid_policy(version: u64) -> NacmPolicy {
    // An empty policy will deny all actions by default (lockout check fails)
    NacmPolicy::empty(PolicyVersion::new(version))
}

async fn setup_service() -> (
    SqliteSecurityPolicyService<MemoryKeyProvider>,
    tempfile::TempDir,
) {
    let temp_dir = tempdir().unwrap();
    let db_path = temp_dir.path().join("test_security.db");

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

    let service = SqliteSecurityPolicyService::new(backend, key_provider);
    (service, temp_dir)
}

#[tokio::test]
async fn test_bootstrap_and_stage_policy() {
    let _guard = TEST_MUTEX.lock().await;
    let (service, _temp_dir) = setup_service().await;
    let tenant = "test-tenant";
    let principal = get_admin_principal();

    let policy = make_valid_policy(1);
    let res = service.stage_policy(tenant, &principal, policy).await;
    assert!(
        res.is_ok(),
        "Staging policy should succeed during bootstrap: {:?}",
        res
    );
}

#[tokio::test]
async fn test_lockout_validation_fails_for_empty_policy() {
    let _guard = TEST_MUTEX.lock().await;
    let (service, _temp_dir) = setup_service().await;
    let tenant = "test-tenant";
    let principal = get_admin_principal();

    let policy = make_invalid_policy(1);
    service
        .stage_policy(tenant, &principal, policy)
        .await
        .unwrap();

    let res = service.validate_policy(tenant, &principal).await;
    assert!(
        matches!(res, Err(SecurityPolicyError::ValidationFailed(_))),
        "Validation must fail lockout check for policy that denies access: {:?}",
        res
    );
}

#[tokio::test]
async fn test_apply_policy_success_and_cache_invalidation() {
    let _guard = TEST_MUTEX.lock().await;
    let (service, _temp_dir) = setup_service().await;
    let tenant = "test-tenant";
    let principal = get_admin_principal();

    // Stage version 1
    let policy1 = make_valid_policy(1);
    service
        .stage_policy(tenant, &principal, policy1)
        .await
        .unwrap();
    service.apply_policy(tenant, &principal).await.unwrap();

    let metadata = service
        .inspect_active_policy(tenant, &principal)
        .await
        .unwrap();
    assert_eq!(metadata.version, 1);

    // Staged candidate version must be strictly greater than active version
    let policy2 = make_valid_policy(2);
    service
        .stage_policy(tenant, &principal, policy2)
        .await
        .unwrap();
    service.apply_policy(tenant, &principal).await.unwrap();

    let metadata2 = service
        .inspect_active_policy(tenant, &principal)
        .await
        .unwrap();
    assert_eq!(metadata2.version, 2);

    let active_policy = service.get_active_policy_compiled(tenant).await.unwrap();
    assert_eq!(active_policy.version().get(), 2);
}

#[tokio::test]
async fn test_apply_policy_rejects_stale_or_equal_version() {
    let _guard = TEST_MUTEX.lock().await;
    let (service, _temp_dir) = setup_service().await;
    let tenant = "test-tenant";
    let principal = get_admin_principal();

    // Apply version 2
    let policy = make_valid_policy(2);
    service
        .stage_policy(tenant, &principal, policy)
        .await
        .unwrap();
    service.apply_policy(tenant, &principal).await.unwrap();

    // Staging and applying version 1 or 2 should fail
    let policy_stale = make_valid_policy(1);
    service
        .stage_policy(tenant, &principal, policy_stale)
        .await
        .unwrap();
    let res = service.apply_policy(tenant, &principal).await;
    assert!(
        matches!(res, Err(SecurityPolicyError::StaleVersion(_))),
        "Apply must reject older version: {:?}",
        res
    );

    let policy_equal = make_valid_policy(2);
    service
        .stage_policy(tenant, &principal, policy_equal)
        .await
        .unwrap();
    let res2 = service.apply_policy(tenant, &principal).await;
    assert!(
        matches!(res2, Err(SecurityPolicyError::StaleVersion(_))),
        "Apply must reject equal version: {:?}",
        res2
    );
}

#[tokio::test]
async fn test_dry_run_policy() {
    let _guard = TEST_MUTEX.lock().await;
    let (service, _temp_dir) = setup_service().await;
    let tenant = "test-tenant";
    let principal = get_admin_principal();

    // Stage a policy with a read allow rule for interfaces
    let mut registry = ModuleRegistry::new();
    registry
        .register_module("ietf-interfaces", "ietf-interfaces")
        .unwrap();
    registry.register_module("security", "security").unwrap();
    let path_pattern =
        YangPathPattern::parse("/ietf-interfaces:interfaces/interface", &registry).unwrap();
    let rule = NacmRule::allow(NacmAction::Read, path_pattern);

    // Also include rule to satisfy lockout check
    let path_pattern_sec = YangPathPattern::parse("/security:policy", &registry).unwrap();
    let rule_sec = NacmRule::allow(NacmAction::SecurityAdmin, path_pattern_sec);

    let policy = NacmPolicy::builder(PolicyVersion::new(1))
        .add_rule(rule)
        .add_rule(rule_sec)
        .build();

    service
        .stage_policy(tenant, &principal, policy)
        .await
        .unwrap();

    // Dry run on staged candidate
    let decision = service
        .dry_run_policy(
            tenant,
            &principal,
            "/ietf-interfaces:interfaces/interface",
            NacmAction::Read,
        )
        .await
        .unwrap();
    assert!(decision.is_allowed());

    // Dry run for action that is not allowed
    let decision_deny = service
        .dry_run_policy(
            tenant,
            &principal,
            "/ietf-interfaces:interfaces/interface",
            NacmAction::Update,
        )
        .await
        .unwrap();
    assert!(!decision_deny.is_allowed());
}

#[tokio::test]
async fn test_rollback_policy() {
    let _guard = TEST_MUTEX.lock().await;
    let (service, _temp_dir) = setup_service().await;
    let tenant = "test-tenant";
    let principal = get_admin_principal();

    // Apply version 1
    let policy1 = make_valid_policy(1);
    service
        .stage_policy(tenant, &principal, policy1)
        .await
        .unwrap();
    service.apply_policy(tenant, &principal).await.unwrap();

    // Apply version 2
    let policy2 = make_valid_policy(2);
    service
        .stage_policy(tenant, &principal, policy2)
        .await
        .unwrap();
    service.apply_policy(tenant, &principal).await.unwrap();

    let history = service
        .list_policy_history(tenant, &principal)
        .await
        .unwrap();
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].version, 2);
    assert_eq!(history[1].version, 1);

    // Rollback to previous (version 1)
    service
        .rollback_policy(tenant, &principal, RollbackTarget::Previous)
        .await
        .unwrap();

    let active_metadata = service
        .inspect_active_policy(tenant, &principal)
        .await
        .unwrap();
    assert_eq!(active_metadata.version, 1);

    // Rollback to version 2 specifically
    service
        .rollback_policy(
            tenant,
            &principal,
            RollbackTarget::ByVersion(opc_types::ConfigVersion::new(2)),
        )
        .await
        .unwrap();

    let active_metadata2 = service
        .inspect_active_policy(tenant, &principal)
        .await
        .unwrap();
    assert_eq!(active_metadata2.version, 2);
}

#[tokio::test]
async fn test_tenant_and_role_authorization_enforced() {
    let _guard = TEST_MUTEX.lock().await;
    let (service, _temp_dir) = setup_service().await;
    let tenant = "test-tenant";

    let policy = make_valid_policy(1);

    // Mismatched tenant must be rejected
    let mismatched_principal = get_mismatched_tenant_principal();
    let res_mismatch = service
        .stage_policy(tenant, &mismatched_principal, policy.clone())
        .await;
    assert!(
        matches!(res_mismatch, Err(SecurityPolicyError::Unauthorized(_))),
        "Stage policy must reject tenant mismatch: {:?}",
        res_mismatch
    );

    // Principal lacking role must be rejected
    let normal_principal = get_non_admin_principal();
    let res_unauth = service
        .stage_policy(tenant, &normal_principal, policy.clone())
        .await;
    assert!(
        matches!(res_unauth, Err(SecurityPolicyError::Unauthorized(_))),
        "Stage policy must reject non-security-admin principal: {:?}",
        res_unauth
    );

    // inspect_active_policy and list_policy_history must enforce tenant scope and roles
    let res_inspect_mismatch = service
        .inspect_active_policy(tenant, &mismatched_principal)
        .await;
    assert!(
        matches!(
            res_inspect_mismatch,
            Err(SecurityPolicyError::Unauthorized(_))
        ),
        "inspect_active_policy must reject tenant mismatch: {:?}",
        res_inspect_mismatch
    );

    let res_history_mismatch = service
        .list_policy_history(tenant, &mismatched_principal)
        .await;
    assert!(
        matches!(
            res_history_mismatch,
            Err(SecurityPolicyError::Unauthorized(_))
        ),
        "list_policy_history must reject tenant mismatch: {:?}",
        res_history_mismatch
    );

    let res_inspect_unauth = service
        .inspect_active_policy(tenant, &normal_principal)
        .await;
    assert!(
        matches!(
            res_inspect_unauth,
            Err(SecurityPolicyError::Unauthorized(_))
        ),
        "inspect_active_policy must reject non-security-admin principal: {:?}",
        res_inspect_unauth
    );

    let res_history_unauth = service.list_policy_history(tenant, &normal_principal).await;
    assert!(
        matches!(
            res_history_unauth,
            Err(SecurityPolicyError::Unauthorized(_))
        ),
        "list_policy_history must reject non-security-admin principal: {:?}",
        res_history_unauth
    );
}

#[tokio::test]
async fn test_failed_apply_leaves_previous_policy_active() {
    let _guard = TEST_MUTEX.lock().await;
    let (service, _temp_dir) = setup_service().await;
    let tenant = "test-tenant";
    let principal = get_admin_principal();

    // 1. Apply version 1 successfully
    let policy1 = make_valid_policy(1);
    service
        .stage_policy(tenant, &principal, policy1)
        .await
        .unwrap();
    service.apply_policy(tenant, &principal).await.unwrap();

    let metadata = service
        .inspect_active_policy(tenant, &principal)
        .await
        .unwrap();
    assert_eq!(metadata.version, 1);

    // 2. Stage version 2
    let policy2 = make_valid_policy(2);
    service
        .stage_policy(tenant, &principal, policy2)
        .await
        .unwrap();

    // 3. Enable simulated commit failure (fault injection)
    TEST_COMMIT_FAIL.store(true, Ordering::Relaxed);

    // 4. Try to apply, should fail
    let res = service.apply_policy(tenant, &principal).await;
    assert!(
        res.is_err(),
        "Apply must fail when commit fail is simulated"
    );

    // Disable fault injection
    TEST_COMMIT_FAIL.store(false, Ordering::Relaxed);

    // 5. Verify that active policy is still version 1
    let active_metadata = service
        .inspect_active_policy(tenant, &principal)
        .await
        .unwrap();
    assert_eq!(active_metadata.version, 1);

    let active_policy = service.get_active_policy_compiled(tenant).await.unwrap();
    assert_eq!(active_policy.version().get(), 1);
}

#[tokio::test]
async fn test_additional_security_policy_verifications() {
    let _guard = TEST_MUTEX.lock().await;

    // Setup backend & service, keeping a clone of backend to query database directly.
    let temp_dir = tempdir().unwrap();
    let db_path = temp_dir.path().join("test_security_extra.db");

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

    let service = SqliteSecurityPolicyService::new(backend.clone(), key_provider);
    let tenant = "test-tenant";

    // 1. Verify fallback role parsing isolates roles and rejects admin-read-only
    let admin_read_only =
        "spiffe://test-domain/tenant/test-tenant/ns/default/sa/admin-read-only/nf/amf/instance/0";
    let policy = make_valid_policy(1);

    // Staging with admin-read-only should fail with Unauthorized
    let res_stage = service
        .stage_policy(tenant, admin_read_only, policy.clone())
        .await;
    assert!(
        matches!(res_stage, Err(SecurityPolicyError::Unauthorized(_))),
        "Expected admin-read-only to be unauthorized to stage policy, got: {:?}",
        res_stage
    );

    // Other service accounts with similar names but not exactly "admin" or "security-admin"
    let security_admin_lite = "spiffe://test-domain/tenant/test-tenant/ns/default/sa/security-admin-lite/nf/amf/instance/0";
    let res_stage_lite = service
        .stage_policy(tenant, security_admin_lite, policy.clone())
        .await;
    assert!(
        matches!(res_stage_lite, Err(SecurityPolicyError::Unauthorized(_))),
        "Expected security-admin-lite to be unauthorized, got: {:?}",
        res_stage_lite
    );

    // 2. Verify proper tenant isolation on read-only metadata endpoints
    // Setup a valid admin principal for test-tenant
    let admin_principal = get_admin_principal();
    // Stage and apply policy so there is something to query
    service
        .stage_policy(tenant, &admin_principal, policy)
        .await
        .unwrap();
    service
        .apply_policy(tenant, &admin_principal)
        .await
        .unwrap();

    // Verification of inspect_active_policy and list_policy_history for mismatching tenant
    let mismatched_tenant_principal = get_mismatched_tenant_principal();
    let res_inspect = service
        .inspect_active_policy(tenant, &mismatched_tenant_principal)
        .await;
    assert!(
        matches!(res_inspect, Err(SecurityPolicyError::Unauthorized(_))),
        "Expected inspect_active_policy to reject tenant mismatch, got: {:?}",
        res_inspect
    );

    let res_history = service
        .list_policy_history(tenant, &mismatched_tenant_principal)
        .await;
    assert!(
        matches!(res_history, Err(SecurityPolicyError::Unauthorized(_))),
        "Expected list_policy_history to reject tenant mismatch, got: {:?}",
        res_history
    );

    // 3. Database transaction commit failures correctly trigger audit events
    // Let's stage version 2 first
    let policy2 = make_valid_policy(2);
    service
        .stage_policy(tenant, &admin_principal, policy2)
        .await
        .unwrap();

    // Enable simulated commit failure
    TEST_COMMIT_FAIL.store(true, Ordering::Relaxed);
    let res_apply = service.apply_policy(tenant, &admin_principal).await;
    assert!(
        res_apply.is_err(),
        "Expected apply_policy to fail due to simulated commit failure"
    );
    TEST_COMMIT_FAIL.store(false, Ordering::Relaxed);

    // Verify the database has the APPLY_FAILURE audit event
    let conn = backend.conn();
    {
        let db = conn.lock().await;
        let mut stmt = db
            .prepare(
                "SELECT action, details FROM security_policy_audit WHERE action = 'APPLY_FAILURE'",
            )
            .unwrap();
        let mut rows = stmt.query([]).unwrap();
        let mut found = false;
        while let Some(row) = rows.next().unwrap() {
            let action: String = row.get(0).unwrap();
            let details: String = row.get(1).unwrap();
            assert_eq!(action, "APPLY_FAILURE");
            assert!(details.contains("simulated commit failure") || details.contains("failed"));
            found = true;
        }
        assert!(found, "Expected to find APPLY_FAILURE in audit table");
    }

    // Now let's trigger a ROLLBACK_FAILURE
    // First, stage and apply version 2 successfully to have a history of v1 and v2
    let policy2 = make_valid_policy(2);
    service
        .stage_policy(tenant, &admin_principal, policy2)
        .await
        .unwrap();
    service
        .apply_policy(tenant, &admin_principal)
        .await
        .unwrap();

    // To force rollback to fail, we will drop the security_policy_active table
    {
        let db = conn.lock().await;
        db.execute("DROP TABLE security_policy_active", []).unwrap();
    }

    // Now calling rollback should fail
    let res_rollback = service
        .rollback_policy(tenant, &admin_principal, RollbackTarget::Previous)
        .await;
    assert!(
        res_rollback.is_err(),
        "Expected rollback_policy to fail because table was dropped"
    );

    // Verify that ROLLBACK_FAILURE is in the audit table
    {
        let db = conn.lock().await;
        let mut stmt = db.prepare("SELECT action, details FROM security_policy_audit WHERE action = 'ROLLBACK_FAILURE'").unwrap();
        let mut rows = stmt.query([]).unwrap();
        let mut found = false;
        while let Some(row) = rows.next().unwrap() {
            let action: String = row.get(0).unwrap();
            let details: String = row.get(1).unwrap();
            assert_eq!(action, "ROLLBACK_FAILURE");
            assert!(
                details.contains("Rollback transaction failed")
                    || details.contains("no such table")
                    || details.contains("failed")
            );
            found = true;
        }
        assert!(found, "Expected to find ROLLBACK_FAILURE in audit table");
    }
}

#[tokio::test]
async fn test_security_policy_audit_corruption_fails_closed() {
    let _guard = TEST_MUTEX.lock().await;
    let temp_dir = tempdir().unwrap();
    let db_path = temp_dir.path().join("test_security_audit_corrupt.db");

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

    let service = SqliteSecurityPolicyService::new(backend.clone(), key_provider);
    let tenant = "test-tenant";
    let principal = get_admin_principal();

    service
        .stage_policy(tenant, &principal, make_valid_policy(1))
        .await
        .unwrap();

    {
        let conn = backend.conn();
        let db = conn.lock().await;
        db.execute(
            "UPDATE security_policy_audit SET entry_hmac = ?1 WHERE tenant = ?2",
            rusqlite::params![vec![0x01_u8, 0x02, 0x03], tenant],
        )
        .unwrap();
    }

    let res = service
        .stage_policy(tenant, &principal, make_valid_policy(2))
        .await;
    assert!(
        matches!(res, Err(SecurityPolicyError::Internal)),
        "corrupt audit HMAC length must fail closed, got: {:?}",
        res
    );
}
