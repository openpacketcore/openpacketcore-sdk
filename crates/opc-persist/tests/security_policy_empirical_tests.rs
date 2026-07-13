use std::collections::HashSet;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tempfile::tempdir;
use tokio::sync::Mutex;

use opc_key::{EnvelopeAad, KeyId, KeyProvider, KeyPurpose, MemoryKeyProvider, Zeroizing};
use opc_nacm::{ModuleRegistry, NacmAction, NacmPolicy, NacmRule, PolicyVersion, YangPathPattern};
#[cfg(feature = "dangerous-test-hooks")]
use opc_persist::TEST_COMMIT_FAIL;
use opc_persist::{
    AuditKey, RollbackTarget, SecurityPolicyError, SecurityPolicyService, SqliteBackend,
    SqliteSecurityPolicyService,
};
use opc_types::TenantId;

static EMPIRICAL_TEST_MUTEX: Mutex<()> = Mutex::const_new(());

fn get_tenant_principal(tenant: &str, role: &str) -> String {
    format!("spiffe://test-domain/tenant/{tenant}/ns/default/sa/{role}/nf/amf/instance/0")
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

fn make_lockout_policy_deny(version: u64) -> NacmPolicy {
    let mut registry = ModuleRegistry::new();
    registry.register_module("security", "security").unwrap();
    let path_pattern = YangPathPattern::parse("/security:policy", &registry).unwrap();
    let rule = NacmRule::deny(NacmAction::SecurityAdmin, path_pattern);
    NacmPolicy::builder(PolicyVersion::new(version))
        .add_rule(rule)
        .build()
}

fn make_empty_policy(version: u64) -> NacmPolicy {
    NacmPolicy::empty(PolicyVersion::new(version))
}

async fn setup_stress_service(
    tenants: &[&str],
) -> (
    SqliteSecurityPolicyService<MemoryKeyProvider>,
    SqliteBackend,
    Arc<MemoryKeyProvider>,
    tempfile::TempDir,
) {
    let temp_dir = tempdir().unwrap();
    let db_path = temp_dir.path().join("stress_security.db");

    let backend =
        SqliteBackend::open_with_audit_key(&db_path, true, 0, AuditKey::new([0x42; 32]).unwrap())
            .await
            .unwrap();

    let key_provider = Arc::new(MemoryKeyProvider::new());
    for &tenant in tenants {
        let tenant_id = TenantId::new(tenant).unwrap();
        key_provider
            .insert_active_key(
                KeyId::new(format!("key-{tenant}")).unwrap(),
                KeyPurpose::ShadowSecurity,
                tenant_id,
                Zeroizing::new([0x99; 32]),
            )
            .unwrap();
    }

    let service = SqliteSecurityPolicyService::new(backend.clone(), key_provider.clone());
    (service, backend, key_provider, temp_dir)
}

#[tokio::test]
async fn test_tenant_separation_empirical() {
    let _guard = EMPIRICAL_TEST_MUTEX.lock().await;
    let (service, _backend, _kp, _temp_dir) = setup_stress_service(&["tenant-a", "tenant-b"]).await;

    let policy_a = make_valid_policy(1);
    let policy_b = make_valid_policy(1);

    let admin_a = get_tenant_principal("tenant-a", "security-admin");
    let admin_b = get_tenant_principal("tenant-b", "security-admin");

    // 1. Tenant A stages policy for Tenant A -> Success
    let res = service
        .stage_policy("tenant-a", &admin_a, policy_a.clone())
        .await;
    assert!(res.is_ok());

    // 2. Tenant B stages policy for Tenant B -> Success
    let res = service
        .stage_policy("tenant-b", &admin_b, policy_b.clone())
        .await;
    assert!(res.is_ok());

    // 3. Tenant A tries to stage policy for Tenant B -> Failure (Unauthorized)
    let res = service
        .stage_policy("tenant-b", &admin_a, policy_b.clone())
        .await;
    assert!(matches!(res, Err(SecurityPolicyError::Unauthorized(_))));

    // 4. Tenant B tries to stage policy for Tenant A -> Failure (Unauthorized)
    let res = service
        .stage_policy("tenant-a", &admin_b, policy_a.clone())
        .await;
    assert!(matches!(res, Err(SecurityPolicyError::Unauthorized(_))));

    // 5. Tenant A applies for Tenant A -> Success
    let res = service.apply_policy("tenant-a", &admin_a).await;
    assert!(res.is_ok());

    // 6. Tenant B applies for Tenant B -> Success
    let res = service.apply_policy("tenant-b", &admin_b).await;
    assert!(res.is_ok());

    // 7. Tenant A tries to apply for Tenant B -> Failure (Unauthorized)
    let res = service.apply_policy("tenant-b", &admin_a).await;
    assert!(matches!(res, Err(SecurityPolicyError::Unauthorized(_))));

    // 8. Tenant A tries to validate Tenant B -> Failure (Unauthorized)
    let res = service.validate_policy("tenant-b", &admin_a).await;
    assert!(matches!(res, Err(SecurityPolicyError::Unauthorized(_))));

    // 9. Tenant A tries to dry run Tenant B -> Failure (Unauthorized)
    let res = service
        .dry_run_policy(
            "tenant-b",
            &admin_a,
            "/security:policy",
            NacmAction::SecurityAdmin,
        )
        .await;
    assert!(matches!(res, Err(SecurityPolicyError::Unauthorized(_))));

    // 10. Tenant A tries to rollback Tenant B -> Failure (Unauthorized)
    let res = service
        .rollback_policy("tenant-b", &admin_a, RollbackTarget::Previous)
        .await;
    assert!(matches!(res, Err(SecurityPolicyError::Unauthorized(_))));
}

#[tokio::test]
async fn test_key_lane_separation_empirical() {
    let _guard = EMPIRICAL_TEST_MUTEX.lock().await;
    let (service, _backend, key_provider, temp_dir) =
        setup_stress_service(&["tenant-a", "tenant-b"]).await;

    let admin_a = get_tenant_principal("tenant-a", "security-admin");
    let policy_a = make_valid_policy(1);

    // Stage and apply policy for Tenant A
    service
        .stage_policy("tenant-a", &admin_a, policy_a)
        .await
        .unwrap();
    service.apply_policy("tenant-a", &admin_a).await.unwrap();

    // Fetch the encrypted blob from the database for Tenant A
    let conn = rusqlite::Connection::open(temp_dir.path().join("stress_security.db")).unwrap();
    let (version, encrypted_blob): (u64, Vec<u8>) = conn
        .query_row(
            "SELECT version, encrypted_blob FROM security_policy_active WHERE tenant = ?1",
            ["tenant-a"],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    drop(conn);

    // Decrypt envelope using Tenant A's key provider credentials -> should succeed
    let tenant_id_a = TenantId::new("tenant-a").unwrap();
    let aad_a = EnvelopeAad::shadow_security(
        tenant_id_a.clone(),
        version,
        opc_key::ShadowSecurityAad::new(version),
    );

    let decrypted_ok =
        opc_crypto::decrypt_envelope(key_provider.as_ref(), &aad_a, &encrypted_blob).await;
    assert!(decrypted_ok.is_ok());

    // Decrypt envelope using Tenant B's AAD (different tenant) -> should fail
    let tenant_id_b = TenantId::new("tenant-b").unwrap();
    let aad_b = EnvelopeAad::shadow_security(
        tenant_id_b,
        version,
        opc_key::ShadowSecurityAad::new(version),
    );
    let decrypted_fail_tenant =
        opc_crypto::decrypt_envelope(key_provider.as_ref(), &aad_b, &encrypted_blob).await;
    assert!(decrypted_fail_tenant.is_err());

    // Decrypt envelope using a different version in AAD -> should fail
    let aad_bad_version = EnvelopeAad::shadow_security(
        tenant_id_a,
        version + 1,
        opc_key::ShadowSecurityAad::new(version + 1),
    );
    let decrypted_fail_version =
        opc_crypto::decrypt_envelope(key_provider.as_ref(), &aad_bad_version, &encrypted_blob)
            .await;
    assert!(decrypted_fail_version.is_err());
}

#[tokio::test]
async fn test_concurrent_mutations_stress() {
    let _guard = EMPIRICAL_TEST_MUTEX.lock().await;
    let (service, _backend, _kp, _temp_dir) = setup_stress_service(&["tenant-a"]).await;
    let service = Arc::new(service);

    let admin = get_tenant_principal("tenant-a", "security-admin");

    // Spawn 20 concurrent tasks, each trying to stage and apply a policy with a unique version.
    let mut join_handles = Vec::new();
    for i in 1..=20 {
        let service_clone = service.clone();
        let admin_clone = admin.clone();
        join_handles.push(tokio::spawn(async move {
            let policy = make_valid_policy(i);
            let stage_res = service_clone
                .stage_policy("tenant-a", &admin_clone, policy)
                .await;
            if let Err(ref e) = stage_res {
                panic!("Stage policy failed unexpectedly: {e:?}");
            }

            let apply_res = service_clone.apply_policy("tenant-a", &admin_clone).await;
            match apply_res {
                Ok(_) => {}
                Err(SecurityPolicyError::StaleVersion(_)) => {}
                Err(e) => {
                    panic!("Apply policy failed with unexpected error: {e:?}");
                }
            }
        }));
    }

    for handle in join_handles {
        handle.await.unwrap();
    }

    // Verify cache and database are fully in sync
    let db_active = service
        .inspect_active_policy("tenant-a", &admin)
        .await
        .unwrap();
    let cache_active = service
        .get_active_policy_compiled("tenant-a")
        .await
        .unwrap();
    assert_eq!(db_active.version, cache_active.version().get());

    // Check history integrity
    let history = service
        .list_policy_history("tenant-a", &admin)
        .await
        .unwrap();
    let mut versions = Vec::new();
    for entry in &history {
        versions.push(entry.version);
    }
    let unique_versions: HashSet<_> = versions.iter().collect();
    assert_eq!(versions.len(), unique_versions.len());
    for w in versions.windows(2) {
        assert!(w[0] > w[1]);
    }
}

#[cfg(feature = "dangerous-test-hooks")]
#[tokio::test]
async fn test_failed_apply_rollback_empirical() {
    let _guard = EMPIRICAL_TEST_MUTEX.lock().await;
    let (service, _backend, _kp, _temp_dir) = setup_stress_service(&["tenant-a"]).await;

    let admin = get_tenant_principal("tenant-a", "security-admin");

    // 1. Apply version 1 successfully
    let policy1 = make_valid_policy(1);
    service
        .stage_policy("tenant-a", &admin, policy1)
        .await
        .unwrap();
    service.apply_policy("tenant-a", &admin).await.unwrap();

    let cached = service
        .get_active_policy_compiled("tenant-a")
        .await
        .unwrap();
    assert_eq!(cached.version().get(), 1);

    // 2. Stage version 2
    let policy2 = make_valid_policy(2);
    service
        .stage_policy("tenant-a", &admin, policy2)
        .await
        .unwrap();

    // 3. Enable simulated commit failure
    TEST_COMMIT_FAIL.store(true, Ordering::Relaxed);

    // 4. Try to apply, should fail
    let res = service.apply_policy("tenant-a", &admin).await;
    assert!(
        res.is_err(),
        "Apply must fail when commit fail is simulated"
    );

    // Disable simulated commit failure
    TEST_COMMIT_FAIL.store(false, Ordering::Relaxed);

    // 5. Verify database active version is still 1
    let db_active = service
        .inspect_active_policy("tenant-a", &admin)
        .await
        .unwrap();
    assert_eq!(db_active.version, 1);

    // 6. Verify in-memory evaluator cache STILL returns version 1
    let cached_after_fail = service
        .get_active_policy_compiled("tenant-a")
        .await
        .unwrap();
    assert_eq!(cached_after_fail.version().get(), 1);
}

#[tokio::test]
async fn test_lockout_rules_empirical() {
    let _guard = EMPIRICAL_TEST_MUTEX.lock().await;
    let (service, _backend, _kp, _temp_dir) = setup_stress_service(&["tenant-a"]).await;

    let admin = get_tenant_principal("tenant-a", "security-admin");

    // 1. Empty policy lockout
    let empty_policy = make_empty_policy(1);
    service
        .stage_policy("tenant-a", &admin, empty_policy)
        .await
        .unwrap();
    let res_empty = service.validate_policy("tenant-a", &admin).await;
    assert!(
        matches!(res_empty, Err(SecurityPolicyError::ValidationFailed(_))),
        "Empty policy must fail validation"
    );

    // 2. Explicit deny lockout
    let deny_policy = make_lockout_policy_deny(2);
    service
        .stage_policy("tenant-a", &admin, deny_policy)
        .await
        .unwrap();
    let res_deny = service.validate_policy("tenant-a", &admin).await;
    assert!(
        matches!(res_deny, Err(SecurityPolicyError::ValidationFailed(_))),
        "Explicit deny admin policy must fail validation"
    );
}

#[tokio::test]
async fn test_stale_version_prevention_empirical() {
    let _guard = EMPIRICAL_TEST_MUTEX.lock().await;
    let (service, _backend, _kp, _temp_dir) = setup_stress_service(&["tenant-a"]).await;

    let admin = get_tenant_principal("tenant-a", "security-admin");

    // 1. Stage and apply version 10
    let policy_10 = make_valid_policy(10);
    service
        .stage_policy("tenant-a", &admin, policy_10)
        .await
        .unwrap();
    service.apply_policy("tenant-a", &admin).await.unwrap();

    // 2. Stage older version 9 -> Stage succeeds, apply must reject
    let policy_9 = make_valid_policy(9);
    service
        .stage_policy("tenant-a", &admin, policy_9)
        .await
        .unwrap();
    let res_apply_9 = service.apply_policy("tenant-a", &admin).await;
    assert!(
        matches!(res_apply_9, Err(SecurityPolicyError::StaleVersion(_))),
        "Apply must reject older version"
    );

    // 3. Stage equal version 10 -> Stage succeeds, apply must reject
    let policy_10_dup = make_valid_policy(10);
    service
        .stage_policy("tenant-a", &admin, policy_10_dup)
        .await
        .unwrap();
    let res_apply_10 = service.apply_policy("tenant-a", &admin).await;
    assert!(
        matches!(res_apply_10, Err(SecurityPolicyError::StaleVersion(_))),
        "Apply must reject equal version"
    );

    // 4. Stage and apply version 11 -> Success
    let policy_11 = make_valid_policy(11);
    service
        .stage_policy("tenant-a", &admin, policy_11)
        .await
        .unwrap();
    let res_apply_11 = service.apply_policy("tenant-a", &admin).await;
    assert!(res_apply_11.is_ok());
}

struct DelayingKeyProvider {
    inner: Arc<MemoryKeyProvider>,
    delay_key_id: String,
    delay: std::time::Duration,
    should_delay: std::sync::atomic::AtomicBool,
}

#[async_trait::async_trait]
impl KeyProvider for DelayingKeyProvider {
    async fn get_active_key(
        &self,
        purpose: KeyPurpose,
        tenant: &TenantId,
    ) -> Result<opc_key::KeyHandle, opc_key::KeyError> {
        self.inner.get_active_key(purpose, tenant).await
    }

    async fn get_key_by_id(&self, key_id: &KeyId) -> Result<opc_key::KeyHandle, opc_key::KeyError> {
        println!("[delay] get_key_by_id called for key: {}", key_id.as_str());
        if key_id.as_str() == self.delay_key_id
            && self
                .should_delay
                .compare_exchange(true, false, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            println!("[delay] get_key_by_id sleeping for 200ms");
            tokio::time::sleep(self.delay).await;
            println!("[delay] get_key_by_id waking up");
        }
        self.inner.get_key_by_id(key_id).await
    }

    async fn rotate_key(
        &self,
        purpose: KeyPurpose,
        tenant: &TenantId,
    ) -> Result<KeyId, opc_key::KeyError> {
        self.inner.rotate_key(purpose, tenant).await
    }
}

#[tokio::test]
async fn test_cache_desync_race_condition() {
    let _guard = EMPIRICAL_TEST_MUTEX.lock().await;

    let temp_dir = tempdir().unwrap();
    let db_path = temp_dir.path().join("desync_security.db");

    let backend =
        SqliteBackend::open_with_audit_key(&db_path, true, 0, AuditKey::new([0x42; 32]).unwrap())
            .await
            .unwrap();

    let memory_kp = Arc::new(MemoryKeyProvider::new());
    let tenant_id = TenantId::new("tenant-a").unwrap();

    // Key for version 1
    memory_kp
        .insert_active_key(
            KeyId::new("key-1").unwrap(),
            KeyPurpose::ShadowSecurity,
            tenant_id.clone(),
            Zeroizing::new([0x11; 32]),
        )
        .unwrap();

    let key_provider = Arc::new(DelayingKeyProvider {
        inner: memory_kp.clone(),
        delay_key_id: "key-1".to_string(),
        delay: std::time::Duration::from_millis(200),
        should_delay: std::sync::atomic::AtomicBool::new(false),
    });

    let service = SqliteSecurityPolicyService::new(backend.clone(), key_provider.clone());
    let admin = get_tenant_principal("tenant-a", "security-admin");

    // 1. Stage and Apply version 1 (uses key-1)
    let policy1 = make_valid_policy(1);
    service
        .stage_policy("tenant-a", &admin, policy1)
        .await
        .unwrap();
    service.apply_policy("tenant-a", &admin).await.unwrap();

    // Enable delay for key-1 decryption
    key_provider.should_delay.store(true, Ordering::Relaxed);

    // Now insert Key for version 2 (will become active key)
    memory_kp
        .insert_active_key(
            KeyId::new("key-2").unwrap(),
            KeyPurpose::ShadowSecurity,
            tenant_id.clone(),
            Zeroizing::new([0x22; 32]),
        )
        .unwrap();

    // 2. Create reader service instance sharing the same DB and key provider (starts with empty cache)
    let service_reader = SqliteSecurityPolicyService::new(backend.clone(), key_provider.clone());

    // 3. Stage version 2 (will use key-2 since it is active)
    let policy2 = make_valid_policy(2);
    service
        .stage_policy("tenant-a", &admin, policy2)
        .await
        .unwrap();

    let service_reader_arc = Arc::new(service_reader);
    let service_reader_clone = service_reader_arc.clone();

    // Spawn reader task
    let reader_handle = tokio::spawn(async move {
        service_reader_clone
            .get_active_policy_compiled("tenant-a")
            .await
    });

    // Let reader start and hit the get_key_by_id("key-1") delay
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Apply version 2 on the service (will write to DB and update cache to version 2)
    service_reader_arc
        .apply_policy("tenant-a", &admin)
        .await
        .unwrap();

    // Wait for the reader thread to finish
    let reader_res = reader_handle.await.unwrap().unwrap();
    assert_eq!(reader_res.version().get(), 2);

    // Inspect final state of the cache vs DB
    let cache_after = service_reader_arc
        .get_active_policy_compiled("tenant-a")
        .await
        .unwrap();
    let db_active = service_reader_arc
        .inspect_active_policy("tenant-a", &admin)
        .await
        .unwrap();

    println!(
        "DB active version: {}, Cache active version: {}",
        db_active.version,
        cache_after.version().get()
    );

    assert_eq!(
        cache_after.version().get(),
        db_active.version,
        "Cache desynchronization detected! Cache has version {}, but database has version {}",
        cache_after.version().get(),
        db_active.version
    );
}
