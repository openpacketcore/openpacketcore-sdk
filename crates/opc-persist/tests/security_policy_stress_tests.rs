#[cfg(feature = "dangerous-test-hooks")]
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tempfile::tempdir;
use tokio::sync::Barrier;

use opc_key::{KeyId, KeyPurpose, MemoryKeyProvider, Zeroizing};
use opc_nacm::{ModuleRegistry, NacmAction, NacmPolicy, NacmRule, PolicyVersion, YangPathPattern};
#[cfg(feature = "dangerous-test-hooks")]
use opc_persist::TEST_COMMIT_FAIL;
use opc_persist::{
    AuditKey, RollbackTarget, SecurityPolicyError, SecurityPolicyService, SqliteBackend,
    SqliteSecurityPolicyService,
};
use opc_types::TenantId;

static TEST_MUTEX: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn get_tenant_admin_principal(tenant: &str) -> String {
    format!("spiffe://test-domain/tenant/{tenant}/ns/default/sa/security-admin/nf/amf/instance/0")
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

fn make_lockout_deny_policy(version: u64) -> NacmPolicy {
    let mut registry = ModuleRegistry::new();
    registry.register_module("security", "security").unwrap();
    let path_pattern = YangPathPattern::parse("/security:policy", &registry).unwrap();
    let rule = NacmRule::deny(NacmAction::SecurityAdmin, path_pattern);
    NacmPolicy::builder(PolicyVersion::new(version))
        .add_rule(rule)
        .build()
}

fn make_lockout_wildcard_deny_policy(version: u64) -> NacmPolicy {
    let mut registry = ModuleRegistry::new();
    registry.register_module("security", "security").unwrap();
    let path_pattern = YangPathPattern::parse("/security:*", &registry).unwrap();
    let rule = NacmRule::deny(NacmAction::SecurityAdmin, path_pattern);
    NacmPolicy::builder(PolicyVersion::new(version))
        .add_rule(rule)
        .build()
}

async fn setup_stress_service() -> (
    SqliteSecurityPolicyService<MemoryKeyProvider>,
    tempfile::TempDir,
    SqliteBackend,
) {
    let temp_dir = tempdir().unwrap();
    let db_path = temp_dir.path().join("stress_security.db");

    let backend =
        SqliteBackend::open_with_audit_key(&db_path, true, 0, AuditKey::new([0x42; 32]).unwrap())
            .await
            .unwrap();

    let key_provider = Arc::new(MemoryKeyProvider::new());

    // Setup keys for tenant-a
    let tenant_a = TenantId::new("tenant-a").unwrap();
    key_provider
        .insert_active_key(
            KeyId::new("key-tenant-a").unwrap(),
            KeyPurpose::ShadowSecurity,
            tenant_a,
            Zeroizing::new([0xaa; 32]),
        )
        .unwrap();

    // Setup keys for tenant-b
    let tenant_b = TenantId::new("tenant-b").unwrap();
    key_provider
        .insert_active_key(
            KeyId::new("key-tenant-b").unwrap(),
            KeyPurpose::ShadowSecurity,
            tenant_b,
            Zeroizing::new([0xbb; 32]),
        )
        .unwrap();

    let service = SqliteSecurityPolicyService::new(backend.clone(), key_provider);
    (service, temp_dir, backend)
}

#[tokio::test]
async fn test_tenant_separation_strictness() {
    let _guard = TEST_MUTEX.lock().await;
    let (service, _temp_dir, _backend) = setup_stress_service().await;

    let policy_a = make_valid_policy(1);
    let principal_a = get_tenant_admin_principal("tenant-a");
    let principal_b = get_tenant_admin_principal("tenant-b");

    // 1. Stage: principal B cannot stage policy for tenant A
    let res = service
        .stage_policy("tenant-a", &principal_b, policy_a.clone())
        .await;
    assert!(
        matches!(res, Err(SecurityPolicyError::Unauthorized(_))),
        "Tenant B principal must be unauthorized to stage for Tenant A: {res:?}"
    );

    // Stage successfully with principal A
    service
        .stage_policy("tenant-a", &principal_a, policy_a.clone())
        .await
        .unwrap();

    // 2. Validate: principal B cannot validate policy for tenant A
    let res = service.validate_policy("tenant-a", &principal_b).await;
    assert!(
        matches!(res, Err(SecurityPolicyError::Unauthorized(_))),
        "Tenant B principal must be unauthorized to validate for Tenant A: {res:?}"
    );

    // 3. Apply: principal B cannot apply policy for tenant A
    let res = service.apply_policy("tenant-a", &principal_b).await;
    assert!(
        matches!(res, Err(SecurityPolicyError::Unauthorized(_))),
        "Tenant B principal must be unauthorized to apply for Tenant A: {res:?}"
    );

    // Apply successfully with principal A
    service
        .apply_policy("tenant-a", &principal_a)
        .await
        .unwrap();

    // 4. Dry run: principal B cannot dry run policy for tenant A
    let res = service
        .dry_run_policy(
            "tenant-a",
            &principal_b,
            "/security:policy",
            NacmAction::SecurityAdmin,
        )
        .await;
    assert!(
        matches!(res, Err(SecurityPolicyError::Unauthorized(_))),
        "Tenant B principal must be unauthorized to dry run for Tenant A: {res:?}"
    );

    // 5. Rollback: principal B cannot rollback policy for tenant A
    let res = service
        .rollback_policy("tenant-a", &principal_b, RollbackTarget::Previous)
        .await;
    assert!(
        matches!(res, Err(SecurityPolicyError::Unauthorized(_))),
        "Tenant B principal must be unauthorized to rollback for Tenant A: {res:?}"
    );
}

#[tokio::test]
async fn test_key_lane_separation_enforced() {
    let _guard = TEST_MUTEX.lock().await;
    let (service, _temp_dir, _backend) = setup_stress_service().await;

    // Create a policy for tenant-a, stage and apply it
    let policy_a = make_valid_policy(1);
    let principal_a = get_tenant_admin_principal("tenant-a");
    service
        .stage_policy("tenant-a", &principal_a, policy_a)
        .await
        .unwrap();
    service
        .apply_policy("tenant-a", &principal_a)
        .await
        .unwrap();

    // Let's verify that inspecting/loading compiles and decrypts fine for tenant-a
    let active_a = service
        .get_active_policy_compiled("tenant-a")
        .await
        .unwrap();
    assert_eq!(active_a.version().get(), 1);

    // Now let's try to load/decrypt tenant-a's active policy but by tricking the system
    let res_b = service.get_active_policy_compiled("tenant-b").await;
    assert!(
        matches!(res_b, Err(SecurityPolicyError::StaleVersion(_))),
        "Tenant B has no active policy, should return StaleVersion: {res_b:?}"
    );
}

#[tokio::test]
async fn test_lockout_rules_enforcement() {
    let _guard = TEST_MUTEX.lock().await;
    let (service, _temp_dir, _backend) = setup_stress_service().await;
    let tenant = "tenant-a";
    let principal = get_tenant_admin_principal(tenant);

    // 1. Rejects empty policy
    let empty_policy = NacmPolicy::empty(PolicyVersion::new(1));
    service
        .stage_policy(tenant, &principal, empty_policy)
        .await
        .unwrap();
    let res_val = service.validate_policy(tenant, &principal).await;
    assert!(
        matches!(res_val, Err(SecurityPolicyError::ValidationFailed(_))),
        "Empty policy must fail validation check: {res_val:?}"
    );

    // 2. Rejects policy denying security-admin access to /security:policy
    let deny_policy = make_lockout_deny_policy(2);
    service
        .stage_policy(tenant, &principal, deny_policy)
        .await
        .unwrap();
    let res_val2 = service.validate_policy(tenant, &principal).await;
    assert!(
        matches!(res_val2, Err(SecurityPolicyError::ValidationFailed(_))),
        "Policy denying SecurityAdmin access to /security:policy must fail: {res_val2:?}"
    );

    // 3. Rejects policy denying security-admin access via wildcard /security:*
    let wildcard_deny_policy = make_lockout_wildcard_deny_policy(3);
    service
        .stage_policy(tenant, &principal, wildcard_deny_policy)
        .await
        .unwrap();
    let res_val3 = service.validate_policy(tenant, &principal).await;
    assert!(
        matches!(res_val3, Err(SecurityPolicyError::ValidationFailed(_))),
        "Policy denying SecurityAdmin access via wildcard must fail: {res_val3:?}"
    );
}

#[tokio::test]
async fn test_stale_version_prevention() {
    let _guard = TEST_MUTEX.lock().await;
    let (service, _temp_dir, _backend) = setup_stress_service().await;
    let tenant = "tenant-a";
    let principal = get_tenant_admin_principal(tenant);

    // Apply version 10
    let policy10 = make_valid_policy(10);
    service
        .stage_policy(tenant, &principal, policy10)
        .await
        .unwrap();
    service.apply_policy(tenant, &principal).await.unwrap();

    // Stage version 9 (older than active 10)
    let policy9 = make_valid_policy(9);
    service
        .stage_policy(tenant, &principal, policy9)
        .await
        .unwrap();

    // Apply version 9 must fail
    let res_apply9 = service.apply_policy(tenant, &principal).await;
    assert!(
        matches!(res_apply9, Err(SecurityPolicyError::StaleVersion(_))),
        "Apply must reject older version (9 < 10): {res_apply9:?}"
    );

    // Stage version 10 (equal to active 10)
    let policy10_dup = make_valid_policy(10);
    service
        .stage_policy(tenant, &principal, policy10_dup)
        .await
        .unwrap();

    // Apply version 10 must fail
    let res_apply10 = service.apply_policy(tenant, &principal).await;
    assert!(
        matches!(res_apply10, Err(SecurityPolicyError::StaleVersion(_))),
        "Apply must reject equal version (10 == 10): {res_apply10:?}"
    );

    // Stage version 11 (newer than active 10)
    let policy11 = make_valid_policy(11);
    service
        .stage_policy(tenant, &principal, policy11)
        .await
        .unwrap();
    // Apply must succeed
    service.apply_policy(tenant, &principal).await.unwrap();

    let metadata = service
        .inspect_active_policy(tenant, &principal)
        .await
        .unwrap();
    assert_eq!(metadata.version, 11);
}

#[cfg(feature = "dangerous-test-hooks")]
#[tokio::test]
async fn test_failed_apply_rollback_and_cache_consistency() {
    let _guard = TEST_MUTEX.lock().await;
    let (service, _temp_dir, _backend) = setup_stress_service().await;
    let tenant = "tenant-a";
    let principal = get_tenant_admin_principal(tenant);

    // 1. Apply version 1 successfully
    let policy1 = make_valid_policy(1);
    service
        .stage_policy(tenant, &principal, policy1)
        .await
        .unwrap();
    service.apply_policy(tenant, &principal).await.unwrap();

    let active_policy1 = service.get_active_policy_compiled(tenant).await.unwrap();
    assert_eq!(active_policy1.version().get(), 1);

    // 2. Stage version 2
    let policy2 = make_valid_policy(2);
    service
        .stage_policy(tenant, &principal, policy2)
        .await
        .unwrap();

    // 3. Trigger commit fail
    TEST_COMMIT_FAIL.store(true, Ordering::Relaxed);

    // 4. Try applying version 2, which fails
    let res = service.apply_policy(tenant, &principal).await;
    assert!(res.is_err(), "Apply must fail when TEST_COMMIT_FAIL is set");

    // Disable commit fail
    TEST_COMMIT_FAIL.store(false, Ordering::Relaxed);

    // 5. Verify database and in-memory cache are still consistent at version 1!
    let active_policy_after_fail = service.get_active_policy_compiled(tenant).await.unwrap();
    assert_eq!(
        active_policy_after_fail.version().get(),
        1,
        "Cache must remain at version 1"
    );

    let metadata = service
        .inspect_active_policy(tenant, &principal)
        .await
        .unwrap();
    assert_eq!(
        metadata.version, 1,
        "Database metadata must remain at version 1"
    );

    // 6. Now apply without fail should succeed and update both
    service.apply_policy(tenant, &principal).await.unwrap();
    let active_policy_final = service.get_active_policy_compiled(tenant).await.unwrap();
    assert_eq!(active_policy_final.version().get(), 2);
}

#[tokio::test]
async fn test_concurrency_stage_and_apply_stress() {
    let _guard = TEST_MUTEX.lock().await;
    let (service, _temp_dir, _backend) = setup_stress_service().await;
    let service = Arc::new(service);
    let tenant = "tenant-a";
    let principal = get_tenant_admin_principal(tenant);

    // Stage version 1 and apply to bootstrap
    let policy1 = make_valid_policy(1);
    service
        .stage_policy(tenant, &principal, policy1)
        .await
        .unwrap();
    service.apply_policy(tenant, &principal).await.unwrap();

    let num_tasks = 20;
    let barrier = Arc::new(Barrier::new(num_tasks));
    let mut handles = Vec::new();

    for i in 0..num_tasks {
        let service = service.clone();
        let barrier = barrier.clone();
        let principal = principal.clone();
        let version = (i + 2) as u64; // version 2 to 21

        handles.push(tokio::spawn(async move {
            // Wait for all tasks to be spawned
            barrier.wait().await;

            let policy = make_valid_policy(version);

            // Try staging
            let stage_res = service.stage_policy("tenant-a", &principal, policy).await;

            // Try applying (it might succeed or fail depending on ordering and version checks)
            let apply_res = service.apply_policy("tenant-a", &principal).await;

            (stage_res, apply_res)
        }));
    }

    let mut results = Vec::new();
    for h in handles {
        results.push(h.await.unwrap());
    }

    // Since multiple threads staged concurrently and applied, the active version should be one of 2..=21.
    // Let's verify database state is still healthy and consistent.
    let metadata = service
        .inspect_active_policy(tenant, &principal)
        .await
        .unwrap();
    let active_policy = service.get_active_policy_compiled(tenant).await.unwrap();

    assert_eq!(
        metadata.version,
        active_policy.version().get(),
        "DB version and cache version must be consistent"
    );
    assert!(
        metadata.version >= 2 && metadata.version <= 21,
        "Active version must be within valid range: {}",
        metadata.version
    );
}

#[tokio::test]
async fn test_adversarial_aad_injection_mismatched_tenant() {
    let _guard = TEST_MUTEX.lock().await;
    let (service, temp_dir, _backend) = setup_stress_service().await;

    // 1. Stage a policy for tenant-a
    let policy_a = make_valid_policy(1);
    let principal_a = get_tenant_admin_principal("tenant-a");
    service
        .stage_policy("tenant-a", &principal_a, policy_a)
        .await
        .unwrap();

    // Fetch tenant-a's staged entry directly from the DB
    let conn = rusqlite::Connection::open(temp_dir.path().join("stress_security.db")).unwrap();
    let (version, encrypted_blob): (u64, Vec<u8>) = conn
        .query_row(
            "SELECT version, encrypted_blob FROM staged_security_policy WHERE tenant = 'tenant-a'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();

    // 2. Perform injection: write tenant-a's encrypted_blob into tenant-b's staged row
    conn.execute(
            "INSERT INTO staged_security_policy (tenant, version, staged_at, principal, encrypted_blob) \
             VALUES ('tenant-b', ?1, '2026-06-08T22:00:00Z', 'spiffe://test-domain/tenant/tenant-b/ns/default/sa/security-admin/nf/amf/instance/0', ?2)",
            rusqlite::params![version, encrypted_blob],
        )
        .unwrap();
    drop(conn);

    // 3. Attempt validation on tenant-b using tenant-b's admin principal
    let principal_b = get_tenant_admin_principal("tenant-b");
    let res = service.validate_policy("tenant-b", &principal_b).await;

    // The validation must fail with Internal error because decryption fails due to mismatched tenant key and AAD context.
    assert!(
        matches!(res, Err(SecurityPolicyError::Internal)),
        "Decryption of Tenant A's blob using Tenant B's expected AAD must fail closed with Internal: {res:?}"
    );
}

#[tokio::test]
async fn test_adversarial_version_mismatched_tampering() {
    let _guard = TEST_MUTEX.lock().await;
    let (service, temp_dir, _backend) = setup_stress_service().await;

    // 1. Stage a policy for tenant-a with version 2
    let policy_a = make_valid_policy(2);
    let principal_a = get_tenant_admin_principal("tenant-a");
    service
        .stage_policy("tenant-a", &principal_a, policy_a)
        .await
        .unwrap();

    // 2. Tamper with version: update the metadata column 'version' to 1 (while the blob has version 2 bound in AAD)
    {
        let conn = rusqlite::Connection::open(temp_dir.path().join("stress_security.db")).unwrap();
        conn.execute(
            "UPDATE staged_security_policy SET version = 1 WHERE tenant = 'tenant-a'",
            [],
        )
        .unwrap();
    }

    // 3. Attempt validation on tenant-a
    let res = service.validate_policy("tenant-a", &principal_a).await;

    // The validation must fail with Internal error because decryption fails due to mismatched version.
    assert!(
        matches!(res, Err(SecurityPolicyError::Internal)),
        "Decryption of version-tampered metadata must fail closed with Internal: {res:?}"
    );
}
