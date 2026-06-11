use async_trait::async_trait;
use hmac::Mac;
use std::sync::atomic::Ordering;

use opc_key::KeyProvider;
use opc_nacm::{
    AuthorizationDecision, ModuleRegistry, NacmAction, NacmEvaluator, NacmPolicy, YangPath,
};

use super::crypto::{
    compile_serializable_policy, decrypt_policy, encrypt_policy, to_serializable_policy,
    validate_principal_tenant_and_roles,
};
#[cfg(any(test, feature = "dangerous-test-hooks"))]
use super::TEST_COMMIT_FAIL;
use super::{
    ActivePolicyMetadata, PolicyHistoryEntry, SecurityPolicyError, SecurityPolicyService,
    SqliteSecurityPolicyService,
};
use crate::types::RollbackTarget;

impl<P: KeyProvider + 'static> SqliteSecurityPolicyService<P> {
    pub async fn get_active_policy_compiled(
        &self,
        tenant: &str,
    ) -> Result<NacmPolicy, SecurityPolicyError> {
        self.get_active_policy_compiled_recursive(tenant).await
    }

    fn get_active_policy_compiled_recursive<'a>(
        &'a self,
        tenant: &'a str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<NacmPolicy, SecurityPolicyError>> + Send + 'a>,
    > {
        Box::pin(async move {
            {
                let cache = self.active_policies.read().await;
                if let Some(policy) = cache.get(tenant) {
                    return Ok(policy.clone());
                }
            }

            let start_epoch = self.write_epoch.load(Ordering::Relaxed);
            let compiled = self.get_active_policy_compiled_no_cache(tenant).await?;
            let mut cache = self.active_policies.write().await;
            if self.write_epoch.load(Ordering::Relaxed) != start_epoch {
                drop(cache);
                return self.get_active_policy_compiled_recursive(tenant).await;
            }

            if let Some(cached_policy) = cache.get(tenant) {
                if compiled.version().get() > cached_policy.version().get() {
                    cache.insert(tenant.to_string(), compiled.clone());
                    Ok(compiled)
                } else {
                    Ok(cached_policy.clone())
                }
            } else {
                cache.insert(tenant.to_string(), compiled.clone());
                Ok(compiled)
            }
        })
    }

    pub(crate) async fn get_active_policy_compiled_no_cache(
        &self,
        tenant: &str,
    ) -> Result<NacmPolicy, SecurityPolicyError> {
        let conn_mutex = self.backend.conn();
        let conn = conn_mutex.lock().await;
        let row: Result<(u64, Vec<u8>), _> = conn.query_row(
            "SELECT version, encrypted_blob FROM security_policy_active WHERE tenant = ?1",
            [tenant],
            |row| Ok((row.get::<_, u64>(0)?, row.get::<_, Vec<u8>>(1)?)),
        );

        match row {
            Ok((version, encrypted_blob)) => {
                drop(conn);
                let serializable =
                    decrypt_policy(self.key_provider.as_ref(), tenant, version, &encrypted_blob)
                        .await?;

                compile_serializable_policy(&serializable)
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Err(SecurityPolicyError::StaleVersion(
                "No active policy found".to_string(),
            )),
            Err(e) => {
                tracing::error!(err = ?e, "Failed to load active policy from database");
                Err(SecurityPolicyError::Internal)
            }
        }
    }

    async fn check_authorization(
        &self,
        tenant: &str,
        principal: &str,
    ) -> Result<String, SecurityPolicyError> {
        let (validated_spiffe, roles) = validate_principal_tenant_and_roles(principal, tenant)?;

        if !roles.iter().any(|r| r == "security-admin") {
            return Err(SecurityPolicyError::Unauthorized(format!(
                "Principal '{}' lacks 'security-admin' role",
                validated_spiffe
            )));
        }

        let active_policy = match self.get_active_policy_compiled(tenant).await {
            Ok(p) => p,
            Err(SecurityPolicyError::StaleVersion(_)) => return Ok(validated_spiffe),
            Err(e) => return Err(e),
        };

        let mut registry = ModuleRegistry::new();
        let _ = registry.register_module("security", "security");
        for rule in active_policy.rules() {
            for segment in rule.path().to_string().split('/') {
                if let Some((prefix, _)) = segment.split_once(':') {
                    if !prefix.is_empty() && prefix != "*" {
                        let _ = registry.register_module(prefix, prefix);
                    }
                }
            }
        }

        let path = YangPath::parse("/security:policy", &registry).map_err(|e| {
            tracing::error!(err = ?e, "Failed to parse YangPath /security:policy");
            SecurityPolicyError::Internal
        })?;

        let mut evaluator = NacmEvaluator::new();
        let decision = evaluator.evaluate(&active_policy, &path, NacmAction::SecurityAdmin);

        if !decision.is_allowed() {
            let _ = self
                .audit_event(
                    tenant,
                    &validated_spiffe,
                    "EVALUATE_DENY",
                    "NACM check denied security-admin access to /security:policy",
                )
                .await;

            return Err(SecurityPolicyError::Unauthorized(
                "Access denied by active security policy".to_string(),
            ));
        }

        let _ = self
            .audit_event(
                tenant,
                &validated_spiffe,
                "EVALUATE_ALLOW",
                "NACM check allowed security-admin access to /security:policy",
            )
            .await;

        Ok(validated_spiffe)
    }

    async fn audit_event(
        &self,
        tenant: &str,
        principal: &str,
        action: &str,
        details: &str,
    ) -> Result<(), SecurityPolicyError> {
        let conn_mutex = self.backend.conn();
        let (previous_hash, timestamp) = {
            let conn = conn_mutex.lock().await;

            let prev_hash_row: Result<Vec<u8>, _> = conn.query_row(
                "SELECT entry_hmac FROM security_policy_audit WHERE tenant = ?1 ORDER BY id DESC LIMIT 1",
                [tenant],
                |row| row.get(0),
            );

            let previous_hash: [u8; 32] = match prev_hash_row {
                Ok(bytes) => {
                    if bytes.len() != 32 {
                        tracing::error!(
                            len = bytes.len(),
                            "Invalid previous security policy audit HMAC length"
                        );
                        return Err(SecurityPolicyError::Internal);
                    }
                    let mut h = [0u8; 32];
                    h.copy_from_slice(&bytes);
                    h
                }
                Err(rusqlite::Error::QueryReturnedNoRows) => [0u8; 32],
                Err(e) => {
                    tracing::error!(err = ?e, "Failed to fetch previous audit hash");
                    return Err(SecurityPolicyError::Internal);
                }
            };

            let timestamp = opc_types::Timestamp::now_utc().to_string();
            (previous_hash, timestamp)
        };

        let mut mac_input = Vec::new();
        mac_input.extend_from_slice(&(tenant.len() as u32).to_be_bytes());
        mac_input.extend_from_slice(tenant.as_bytes());

        mac_input.extend_from_slice(&(timestamp.len() as u32).to_be_bytes());
        mac_input.extend_from_slice(timestamp.as_bytes());

        mac_input.extend_from_slice(&(principal.len() as u32).to_be_bytes());
        mac_input.extend_from_slice(principal.as_bytes());

        mac_input.extend_from_slice(&(action.len() as u32).to_be_bytes());
        mac_input.extend_from_slice(action.as_bytes());

        mac_input.extend_from_slice(&(details.len() as u32).to_be_bytes());
        mac_input.extend_from_slice(details.as_bytes());

        mac_input.extend_from_slice(&previous_hash);

        type HmacSha256 = hmac::Hmac<sha2::Sha256>;
        let mut mac =
            HmacSha256::new_from_slice(self.backend.audit_key().as_bytes()).map_err(|e| {
                tracing::error!(err = ?e, "Failed to create HMAC provider");
                SecurityPolicyError::Internal
            })?;
        mac.update(&mac_input);
        let entry_hmac: [u8; 32] = mac.finalize().into_bytes().into();

        {
            let conn = conn_mutex.lock().await;
            let insert_res = conn.execute(
                "INSERT INTO security_policy_audit (tenant, timestamp, principal, action, details, previous_hash, entry_hmac) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                rusqlite::params![
                    tenant,
                    timestamp,
                    principal,
                    action,
                    details,
                    previous_hash.to_vec(),
                    entry_hmac.to_vec(),
                ],
            );

            if let Err(e) = insert_res {
                tracing::error!(err = ?e, "Failed to insert security policy audit entry");
                return Err(SecurityPolicyError::Internal);
            }
        }

        tracing::info!(
            target: "security_policy_audit",
            tenant = %tenant,
            principal = %principal,
            action = %action,
            details = %details,
            "Security policy audit log"
        );

        Ok(())
    }
}

#[async_trait]
impl<P: KeyProvider + 'static> SecurityPolicyService for SqliteSecurityPolicyService<P> {
    async fn stage_policy(
        &self,
        tenant: &str,
        principal: &str,
        policy: NacmPolicy,
    ) -> Result<(), SecurityPolicyError> {
        let validated_spiffe = self.check_authorization(tenant, principal).await?;

        let serializable = to_serializable_policy(&policy);
        let version = serializable.version;
        let encrypted_blob =
            encrypt_policy(self.key_provider.as_ref(), tenant, version, &serializable).await?;

        {
            let conn_mutex = self.backend.conn();
            let conn = conn_mutex.lock().await;
            let staged_at = opc_types::Timestamp::now_utc().to_string();

            let tx = conn.unchecked_transaction().map_err(|e| {
                tracing::error!(err = ?e, "Failed to start transaction for stage_policy");
                SecurityPolicyError::Internal
            })?;

            tx.execute(
                "DELETE FROM staged_security_policy WHERE tenant = ?1",
                [tenant],
            )
            .map_err(|e| {
                tracing::error!(err = ?e, "Failed to delete old staged policy");
                SecurityPolicyError::Internal
            })?;

            tx.execute(
                "INSERT INTO staged_security_policy (tenant, version, staged_at, principal, encrypted_blob) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    tenant,
                    version,
                    staged_at,
                    validated_spiffe,
                    encrypted_blob,
                ],
            ).map_err(|e| {
                tracing::error!(err = ?e, "Failed to insert staged policy");
                SecurityPolicyError::Internal
            })?;

            tx.commit().map_err(|e| {
                tracing::error!(err = ?e, "Failed to commit staged policy transaction");
                SecurityPolicyError::Internal
            })?;
        }

        let details = format!("Staged policy version {}", version);
        self.audit_event(tenant, &validated_spiffe, "STAGE", &details)
            .await?;

        Ok(())
    }

    async fn validate_policy(
        &self,
        tenant: &str,
        principal: &str,
    ) -> Result<(), SecurityPolicyError> {
        let validated_spiffe = validate_principal_tenant_and_roles(principal, tenant)?.0;

        let conn_mutex = self.backend.conn();
        let row = {
            let conn = conn_mutex.lock().await;
            let row_res: Result<(u64, Vec<u8>), _> = conn.query_row(
                "SELECT version, encrypted_blob FROM staged_security_policy WHERE tenant = ?1",
                [tenant],
                |r| Ok((r.get::<_, u64>(0)?, r.get::<_, Vec<u8>>(1)?)),
            );
            row_res
        };

        let (version, encrypted_blob) = match row {
            Ok(res) => res,
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                return Err(SecurityPolicyError::ValidationFailed(
                    "No policy staged for this tenant".to_string(),
                ));
            }
            Err(e) => {
                tracing::error!(err = ?e, "Failed to fetch staged policy for validation");
                return Err(SecurityPolicyError::Internal);
            }
        };

        let serializable =
            decrypt_policy(self.key_provider.as_ref(), tenant, version, &encrypted_blob).await?;

        let candidate_policy = compile_serializable_policy(&serializable)?;

        let mut registry = ModuleRegistry::new();
        let _ = registry.register_module("security", "security");
        for rule in candidate_policy.rules() {
            for segment in rule.path().to_string().split('/') {
                if let Some((prefix, _)) = segment.split_once(':') {
                    if !prefix.is_empty() && prefix != "*" {
                        let _ = registry.register_module(prefix, prefix);
                    }
                }
            }
        }

        let path = YangPath::parse("/security:policy", &registry).map_err(|e| {
            tracing::error!(err = ?e, "Failed to parse path /security:policy for validation");
            SecurityPolicyError::Internal
        })?;

        let mut evaluator = NacmEvaluator::new();
        let decision = evaluator.evaluate(&candidate_policy, &path, NacmAction::SecurityAdmin);

        if !decision.is_allowed() {
            let reason = "Validation failed: lockout check failed, candidate policy denies security-admin role access to /security:policy".to_string();
            let _ = self
                .audit_event(tenant, &validated_spiffe, "VALIDATE_FAILURE", &reason)
                .await;
            return Err(SecurityPolicyError::ValidationFailed(reason));
        }

        Ok(())
    }

    async fn apply_policy(&self, tenant: &str, principal: &str) -> Result<(), SecurityPolicyError> {
        let validated_spiffe = self.check_authorization(tenant, principal).await?;

        let conn_mutex = self.backend.conn();
        let row = {
            let conn = conn_mutex.lock().await;
            let row_res: Result<(u64, Vec<u8>), _> = conn.query_row(
                "SELECT version, encrypted_blob FROM staged_security_policy WHERE tenant = ?1",
                [tenant],
                |r| Ok((r.get::<_, u64>(0)?, r.get::<_, Vec<u8>>(1)?)),
            );
            row_res
        };

        let (version, encrypted_blob) = match row {
            Ok(res) => res,
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                let _ = self
                    .audit_event(
                        tenant,
                        &validated_spiffe,
                        "APPLY_FAILURE",
                        "No staged policy to apply",
                    )
                    .await;
                return Err(SecurityPolicyError::StaleVersion(
                    "No staged policy to apply".to_string(),
                ));
            }
            Err(e) => {
                tracing::error!(err = ?e, "Failed to load staged policy for apply");
                return Err(SecurityPolicyError::Internal);
            }
        };

        let active_version_res = {
            let conn = conn_mutex.lock().await;
            let active_res: Result<u64, _> = conn.query_row(
                "SELECT version FROM security_policy_active WHERE tenant = ?1",
                [tenant],
                |r| r.get(0),
            );
            active_res
        };

        if let Ok(active_version) = active_version_res {
            if version <= active_version {
                let reason = format!(
                    "Apply rejected: candidate version {} is not newer than active version {}",
                    version, active_version
                );
                let _ = self
                    .audit_event(tenant, &validated_spiffe, "APPLY_FAILURE", &reason)
                    .await;
                return Err(SecurityPolicyError::StaleVersion(reason));
            }
        }

        if let Err(e) = self.validate_policy(tenant, &validated_spiffe).await {
            let _ = self
                .audit_event(
                    tenant,
                    &validated_spiffe,
                    "APPLY_FAILURE",
                    &format!("Validation failed: {}", e),
                )
                .await;
            return Err(e);
        }

        #[cfg(any(test, feature = "dangerous-test-hooks"))]
        let mut failed_simulated = false;
        #[cfg(not(any(test, feature = "dangerous-test-hooks")))]
        let failed_simulated = false;

        let tx_result = async {
            let conn_guard = conn_mutex.lock().await;
            let tx = conn_guard.unchecked_transaction().map_err(|e| {
                tracing::error!(err = ?e, "Failed to start transaction for apply_policy");
                SecurityPolicyError::Internal
            })?;

            let applied_at = opc_types::Timestamp::now_utc().to_string();

            tx.execute(
                "INSERT OR REPLACE INTO security_policy_active (tenant, version, applied_at, principal, encrypted_blob) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    tenant,
                    version,
                    applied_at,
                    validated_spiffe,
                    encrypted_blob,
                ],
            ).map_err(|e| {
                tracing::error!(err = ?e, "Failed to upsert active policy");
                SecurityPolicyError::Internal
            })?;

            tx.execute(
                "INSERT INTO security_policy_history (tenant, version, applied_at, principal, encrypted_blob, tx_id, label) \
                 VALUES (?1, ?2, ?3, ?4, ?5, NULL, NULL)",
                rusqlite::params![
                    tenant,
                    version,
                    applied_at,
                    validated_spiffe,
                    encrypted_blob,
                ],
            ).map_err(|e| {
                tracing::error!(err = ?e, "Failed to insert policy history");
                SecurityPolicyError::Internal
            })?;

            tx.execute(
                "DELETE FROM staged_security_policy WHERE tenant = ?1",
                [tenant],
            )
            .map_err(|e| {
                tracing::error!(err = ?e, "Failed to clear staged policy after apply");
                SecurityPolicyError::Internal
            })?;

            #[cfg(any(test, feature = "dangerous-test-hooks"))]
            let mut run_commit = true;
            #[cfg(not(any(test, feature = "dangerous-test-hooks")))]
            let run_commit = true;

            #[cfg(any(test, feature = "dangerous-test-hooks"))]
            if TEST_COMMIT_FAIL.load(std::sync::atomic::Ordering::Relaxed) {
                run_commit = false;
            }

            if run_commit {
                tx.commit().map_err(|e| {
                    tracing::error!(err = ?e, "Failed to commit apply transaction");
                    SecurityPolicyError::Internal
                })?;
                self.write_epoch.fetch_add(1, Ordering::Relaxed);
            }

            Ok::<(), SecurityPolicyError>(())
        }.await;

        #[cfg(any(test, feature = "dangerous-test-hooks"))]
        if TEST_COMMIT_FAIL.load(std::sync::atomic::Ordering::Relaxed) {
            failed_simulated = true;
        }

        if let Err(e) = tx_result {
            let reason = format!("Apply transaction failed: {:?}", e);
            let _ = self
                .audit_event(tenant, &validated_spiffe, "APPLY_FAILURE", &reason)
                .await;
            return Err(e);
        }

        if failed_simulated {
            let reason = "Apply transaction aborted due to simulated commit failure".to_string();
            let _ = self
                .audit_event(tenant, &validated_spiffe, "APPLY_FAILURE", &reason)
                .await;
            return Err(SecurityPolicyError::Internal);
        }

        if let Ok(compiled) = self.get_active_policy_compiled_no_cache(tenant).await {
            let mut cache = self.active_policies.write().await;
            cache.insert(tenant.to_string(), compiled);
        }

        let details = format!("Successfully applied policy version {}", version);
        self.audit_event(tenant, &validated_spiffe, "APPLY_SUCCESS", &details)
            .await?;

        Ok(())
    }

    async fn dry_run_policy(
        &self,
        tenant: &str,
        principal: &str,
        path: &str,
        action: NacmAction,
    ) -> Result<AuthorizationDecision, SecurityPolicyError> {
        let validated_spiffe = self.check_authorization(tenant, principal).await?;

        let conn_mutex = self.backend.conn();
        let row = {
            let conn = conn_mutex.lock().await;
            let row_res: Result<(u64, Vec<u8>), _> = conn.query_row(
                "SELECT version, encrypted_blob FROM staged_security_policy WHERE tenant = ?1",
                [tenant],
                |r| Ok((r.get::<_, u64>(0)?, r.get::<_, Vec<u8>>(1)?)),
            );
            row_res
        };

        let (version, encrypted_blob) = match row {
            Ok(res) => res,
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                return Err(SecurityPolicyError::ValidationFailed(
                    "No policy staged for dry run".to_string(),
                ));
            }
            Err(e) => {
                tracing::error!(err = ?e, "Failed to fetch staged policy for dry run");
                return Err(SecurityPolicyError::Internal);
            }
        };

        let serializable =
            decrypt_policy(self.key_provider.as_ref(), tenant, version, &encrypted_blob).await?;

        let candidate_policy = compile_serializable_policy(&serializable)?;

        let mut registry = ModuleRegistry::new();
        for rule in candidate_policy.rules() {
            for segment in rule.path().to_string().split('/') {
                if let Some((prefix, _)) = segment.split_once(':') {
                    if !prefix.is_empty() && prefix != "*" {
                        let _ = registry.register_module(prefix, prefix);
                    }
                }
            }
        }
        for segment in path.split('/') {
            if let Some((prefix, _)) = segment.split_once(':') {
                if !prefix.is_empty() && prefix != "*" {
                    let _ = registry.register_module(prefix, prefix);
                }
            }
        }

        let yang_path = YangPath::parse(path, &registry).map_err(|e| {
            SecurityPolicyError::ValidationFailed(format!(
                "Invalid path for dry run: {}",
                e.message()
            ))
        })?;

        let mut evaluator = NacmEvaluator::new();
        let decision = evaluator.evaluate(&candidate_policy, &yang_path, action);

        let details = format!(
            "Dry run evaluation on path {} action {} outcome {:?}",
            path,
            action,
            decision.effect()
        );
        let audit_action = if decision.is_allowed() {
            "EVALUATE_ALLOW"
        } else {
            "EVALUATE_DENY"
        };
        self.audit_event(tenant, &validated_spiffe, audit_action, &details)
            .await?;

        Ok(decision)
    }

    async fn rollback_policy(
        &self,
        tenant: &str,
        principal: &str,
        target: RollbackTarget,
    ) -> Result<(), SecurityPolicyError> {
        let validated_spiffe = self.check_authorization(tenant, principal).await?;

        let conn_mutex = self.backend.conn();

        let prepare_result = async {
            let conn_guard = conn_mutex.lock().await;

            let row_res: Result<(u64, Vec<u8>), SecurityPolicyError> = match target {
                RollbackTarget::Previous => {
                    let mut stmt = conn_guard.prepare(
                        "SELECT version, encrypted_blob FROM security_policy_history WHERE tenant = ?1 ORDER BY version DESC LIMIT 2",
                    ).map_err(|e| {
                        tracing::error!(err = ?e, "Failed to prepare previous target query");
                        SecurityPolicyError::Internal
                    })?;
                    let mut rows = stmt.query([tenant]).map_err(|e| {
                        tracing::error!(err = ?e, "Failed to execute previous target query");
                        SecurityPolicyError::Internal
                    })?;
                    let _current = rows.next().map_err(|e| {
                        tracing::error!(err = ?e, "Failed to fetch current version");
                        SecurityPolicyError::Internal
                    })?;
                    let previous = rows.next().map_err(|e| {
                        tracing::error!(err = ?e, "Failed to fetch previous version");
                        SecurityPolicyError::Internal
                    })?;
                    if let Some(prev_row) = previous {
                        let version: u64 = prev_row.get(0).map_err(|e| {
                            tracing::error!(err = ?e, "Failed to read previous policy version");
                            SecurityPolicyError::Internal
                        })?;
                        let encrypted_blob: Vec<u8> = prev_row.get(1).map_err(|e| {
                            tracing::error!(err = ?e, "Failed to read previous policy blob");
                            SecurityPolicyError::Internal
                        })?;
                        Ok((version, encrypted_blob))
                    } else {
                        Err(SecurityPolicyError::StaleVersion(
                            "No previous policy history exists for rollback".to_string(),
                        ))
                    }
                }
                RollbackTarget::ByVersion(config_version) => {
                    let version_val = config_version.get();
                    let res: Result<(u64, Vec<u8>), _> = conn_guard.query_row(
                        "SELECT version, encrypted_blob FROM security_policy_history WHERE tenant = ?1 AND version = ?2",
                        rusqlite::params![tenant, version_val],
                        |r| Ok((r.get::<_, u64>(0)?, r.get::<_, Vec<u8>>(1)?)),
                    );
                    res.map_err(|e| {
                        if matches!(e, rusqlite::Error::QueryReturnedNoRows) {
                            SecurityPolicyError::StaleVersion(format!(
                                "No history found for version {}",
                                version_val
                            ))
                        } else {
                            tracing::error!(err = ?e, "Failed to query policy history by version");
                            SecurityPolicyError::Internal
                        }
                    })
                }
                RollbackTarget::ByTxId(tx_id) => {
                    let tx_id_bytes = tx_id.as_uuid().as_bytes().to_vec();
                    let res: Result<(u64, Vec<u8>), _> = conn_guard.query_row(
                        "SELECT version, encrypted_blob FROM security_policy_history WHERE tenant = ?1 AND tx_id = ?2",
                        rusqlite::params![tenant, tx_id_bytes],
                        |r| Ok((r.get::<_, u64>(0)?, r.get::<_, Vec<u8>>(1)?)),
                    );
                    res.map_err(|e| {
                        if matches!(e, rusqlite::Error::QueryReturnedNoRows) {
                            SecurityPolicyError::StaleVersion(format!(
                                "No history found for tx_id {:?}",
                                tx_id
                            ))
                        } else {
                            tracing::error!(err = ?e, "Failed to query policy history by tx_id");
                            SecurityPolicyError::Internal
                        }
                    })
                }
                RollbackTarget::ByLabel(label) => {
                    let res: Result<(u64, Vec<u8>), _> = conn_guard.query_row(
                        "SELECT version, encrypted_blob FROM security_policy_history WHERE tenant = ?1 AND label = ?2",
                        rusqlite::params![tenant, label],
                        |r| Ok((r.get::<_, u64>(0)?, r.get::<_, Vec<u8>>(1)?)),
                    );
                    res.map_err(|e| {
                        if matches!(e, rusqlite::Error::QueryReturnedNoRows) {
                            SecurityPolicyError::StaleVersion(format!(
                                "No history found for label {}",
                                label
                            ))
                        } else {
                            tracing::error!(err = ?e, "Failed to query policy history by label");
                            SecurityPolicyError::Internal
                        }
                    })
                }
            };
            let (version, encrypted_blob) = row_res?;

            let serializable =
                decrypt_policy(self.key_provider.as_ref(), tenant, version, &encrypted_blob).await?;
            let candidate_policy = compile_serializable_policy(&serializable)?;
            let mut registry = ModuleRegistry::new();
            let _ = registry.register_module("security", "security");
            for rule in candidate_policy.rules() {
                for segment in rule.path().to_string().split('/') {
                    if let Some((prefix, _)) = segment.split_once(':') {
                        if !prefix.is_empty() && prefix != "*" {
                            let _ = registry.register_module(prefix, prefix);
                        }
                    }
                }
            }
            let path = YangPath::parse("/security:policy", &registry).map_err(|e| {
                tracing::error!(err = ?e, "Failed to parse path /security:policy for rollback validation");
                SecurityPolicyError::Internal
            })?;
            let mut evaluator = NacmEvaluator::new();
            let decision = evaluator.evaluate(&candidate_policy, &path, NacmAction::SecurityAdmin);
            if !decision.is_allowed() {
                let reason = format!("Rollback rejected: target policy version {} denies security-admin role access to /security:policy", version);
                return Err(SecurityPolicyError::ValidationFailed(reason));
            }

            Ok::<_, SecurityPolicyError>((version, encrypted_blob))
        }.await;

        let (version, encrypted_blob) = match prepare_result {
            Ok(res) => res,
            Err(e) => {
                let reason = format!("{}", e);
                let _ = self
                    .audit_event(tenant, &validated_spiffe, "ROLLBACK_FAILURE", &reason)
                    .await;
                return Err(e);
            }
        };

        let tx_result = async {
            let conn_guard = conn_mutex.lock().await;
            let tx = conn_guard.unchecked_transaction().map_err(|e| {
                tracing::error!(err = ?e, "Failed to start transaction for rollback");
                SecurityPolicyError::Internal
            })?;

            let applied_at = opc_types::Timestamp::now_utc().to_string();

            tx.execute(
                "INSERT OR REPLACE INTO security_policy_active (tenant, version, applied_at, principal, encrypted_blob) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    tenant,
                    version,
                    applied_at,
                    validated_spiffe,
                    encrypted_blob,
                ],
            ).map_err(|e| {
                tracing::error!(err = ?e, "Failed to restore active policy in rollback");
                SecurityPolicyError::Internal
            })?;

            tx.commit().map_err(|e| {
                tracing::error!(err = ?e, "Failed to commit rollback transaction");
                SecurityPolicyError::Internal
            })?;
            self.write_epoch.fetch_add(1, Ordering::Relaxed);

            Ok::<(), SecurityPolicyError>(())
        }.await;

        if let Err(e) = tx_result {
            let reason = format!("Rollback transaction failed: {:?}", e);
            let _ = self
                .audit_event(tenant, &validated_spiffe, "ROLLBACK_FAILURE", &reason)
                .await;
            return Err(e);
        }

        if let Ok(compiled) = self.get_active_policy_compiled_no_cache(tenant).await {
            let mut cache = self.active_policies.write().await;
            cache.insert(tenant.to_string(), compiled);
        }

        let details = format!("Rolled back active policy to version {}", version);
        self.audit_event(tenant, &validated_spiffe, "ROLLBACK", &details)
            .await?;

        Ok(())
    }

    async fn inspect_active_policy(
        &self,
        tenant: &str,
        principal: &str,
    ) -> Result<ActivePolicyMetadata, SecurityPolicyError> {
        let _validated_spiffe = self.check_authorization(tenant, principal).await?;
        let conn_mutex = self.backend.conn();
        let conn = conn_mutex.lock().await;
        let row: Result<(u64, String, String), _> = conn.query_row(
            "SELECT version, applied_at, principal FROM security_policy_active WHERE tenant = ?1",
            [tenant],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        );

        match row {
            Ok((version, applied_at, principal)) => Ok(ActivePolicyMetadata {
                version,
                applied_at,
                principal,
            }),
            Err(rusqlite::Error::QueryReturnedNoRows) => Err(SecurityPolicyError::StaleVersion(
                "No active policy found".to_string(),
            )),
            Err(e) => {
                tracing::error!(err = ?e, "Failed to inspect active policy");
                Err(SecurityPolicyError::Internal)
            }
        }
    }

    async fn list_policy_history(
        &self,
        tenant: &str,
        principal: &str,
    ) -> Result<Vec<PolicyHistoryEntry>, SecurityPolicyError> {
        let _validated_spiffe = self.check_authorization(tenant, principal).await?;
        let conn_mutex = self.backend.conn();
        let conn = conn_mutex.lock().await;
        let mut stmt = conn.prepare(
            "SELECT version, applied_at, principal FROM security_policy_history WHERE tenant = ?1 ORDER BY version DESC",
        ).map_err(|e| {
            tracing::error!(err = ?e, "Failed to prepare history query");
            SecurityPolicyError::Internal
        })?;

        let rows = stmt.query_map([tenant], |r| {
            Ok(PolicyHistoryEntry {
                version: r.get(0)?,
                applied_at: r.get(1)?,
                principal: r.get(2)?,
            })
        });

        match rows {
            Ok(mapped_rows) => {
                let mut history = Vec::new();
                for entry in mapped_rows {
                    history.push(entry.map_err(|e| {
                        tracing::error!(err = ?e, "Failed to decode policy history row");
                        SecurityPolicyError::Internal
                    })?);
                }
                Ok(history)
            }
            Err(e) => {
                tracing::error!(err = ?e, "Failed to query policy history list");
                Err(SecurityPolicyError::Internal)
            }
        }
    }
}
