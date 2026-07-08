use async_trait::async_trait;
use hmac::Mac;
use std::sync::Arc;

use opc_key::KeyProvider;
use opc_nacm::{ModuleRegistry, NacmAction, NacmEvaluator, YangPath};
use opc_types::Timestamp;

use crate::break_glass::{
    BreakGlassRequest, BreakGlassService, BreakGlassSession, BreakGlassStatus,
};

use super::crypto::validate_principal_tenant_and_roles;
use super::{SecurityPolicyError, SqliteSecurityPolicyService};

impl<P: KeyProvider + 'static> SqliteSecurityPolicyService<P> {
    pub async fn clean_expired_all_tenants(&self) -> Result<(), SecurityPolicyError> {
        let tenants = {
            let conn_mutex = self.backend.conn();
            let conn = conn_mutex.lock().await;
            let mut stmt = conn
                .prepare("SELECT DISTINCT tenant FROM break_glass_sessions")
                .map_err(|e| {
                    tracing::error!(err = ?e, "Failed to prepare distinct tenants query");
                    SecurityPolicyError::Internal
                })?;
            let rows = stmt.query_map([], |r| r.get::<_, String>(0)).map_err(|e| {
                tracing::error!(err = ?e, "Failed to execute distinct tenants query");
                SecurityPolicyError::Internal
            })?;
            let mut t_list = Vec::new();
            for r in rows {
                t_list.push(r.map_err(|e| {
                    tracing::error!(err = ?e, "Failed to map tenant row");
                    SecurityPolicyError::Internal
                })?);
            }
            t_list
        };

        for tenant in tenants {
            let _ = self.clean_expired(&tenant).await;
        }

        Ok(())
    }

    pub fn start_periodic_cleanup(self: Arc<Self>, interval: std::time::Duration) {
        tokio::spawn(async move {
            if let Err(e) = self.clean_expired_all_tenants().await {
                tracing::error!(err = ?e, "Startup break glass cleanup failed");
            }
            loop {
                tokio::time::sleep(interval).await;
                if let Err(e) = self.clean_expired_all_tenants().await {
                    tracing::error!(err = ?e, "Periodic break glass cleanup failed");
                }
            }
        });
    }

    async fn break_glass_audit_event(
        &self,
        tenant: &str,
        principal: &str,
        action: &str,
        details: &str,
    ) -> Result<(), SecurityPolicyError> {
        let conn_mutex = self.backend.conn();
        let timestamp = Timestamp::now_utc().to_string();

        {
            let conn = conn_mutex.lock().await;
            let tx = conn.unchecked_transaction().map_err(|e| {
                tracing::error!(err = ?e, "Failed to start break-glass audit transaction");
                SecurityPolicyError::Internal
            })?;

            let prev_hash_row: Result<Vec<u8>, _> = tx.query_row(
                "SELECT entry_hmac FROM break_glass_audit WHERE tenant = ?1 ORDER BY id DESC LIMIT 1",
                [tenant],
                |row| row.get(0),
            );

            let previous_hash: [u8; 32] = match prev_hash_row {
                Ok(bytes) => {
                    if bytes.len() != 32 {
                        tracing::error!(
                            len = bytes.len(),
                            "Invalid previous break-glass audit HMAC length"
                        );
                        return Err(SecurityPolicyError::Internal);
                    }
                    let mut h = [0u8; 32];
                    h.copy_from_slice(&bytes);
                    h
                }
                Err(rusqlite::Error::QueryReturnedNoRows) => [0u8; 32],
                Err(e) => {
                    tracing::error!(err = ?e, "Failed to fetch previous break-glass audit hash");
                    return Err(SecurityPolicyError::Internal);
                }
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

            let insert_res = tx.execute(
                "INSERT INTO break_glass_audit (tenant, timestamp, principal, action, details, previous_hash, entry_hmac) \
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
                tracing::error!(err = ?e, "Failed to insert break glass audit entry");
                return Err(SecurityPolicyError::Internal);
            }

            tx.commit().map_err(|e| {
                tracing::error!(err = ?e, "Failed to commit break-glass audit transaction");
                SecurityPolicyError::Internal
            })?;
        }

        tracing::info!(
            target: "break_glass_audit",
            tenant = %tenant,
            principal = %principal,
            action = %action,
            details = %details,
            "Break glass audit log"
        );

        Ok(())
    }

    #[cfg(any(test, feature = "dangerous-test-hooks"))]
    pub async fn break_glass_audit_event_for_test(
        &self,
        tenant: &str,
        principal: &str,
        action: &str,
        details: &str,
    ) -> Result<(), SecurityPolicyError> {
        self.break_glass_audit_event(tenant, principal, action, details)
            .await
    }

    async fn check_break_glass_permission(
        &self,
        tenant: &str,
        principal: &str,
        action: NacmAction,
    ) -> Result<String, SecurityPolicyError> {
        let (validated_spiffe, _, groups) = validate_principal_tenant_and_roles(principal, tenant)?;

        let active_policy = match self.get_active_policy_compiled(tenant).await {
            Ok(p) => p,
            Err(SecurityPolicyError::StaleVersion(_)) => return Ok(validated_spiffe),
            Err(e) => return Err(e),
        };

        let mut registry = ModuleRegistry::new();
        let _ = registry.register_module("security", "security");
        let path = YangPath::parse("/security:break-glass", &registry).map_err(|e| {
            tracing::error!(err = ?e, "Failed to parse YangPath /security:break-glass");
            SecurityPolicyError::Internal
        })?;

        let mut evaluator = NacmEvaluator::new();
        let decision = evaluator.evaluate_for_groups(&active_policy, &path, action, &groups);

        if !decision.is_allowed() {
            let details = format!("NACM check denied break-glass access for action {action:?}");
            let _ = self
                .break_glass_audit_event(tenant, &validated_spiffe, "EVALUATE_DENY", &details)
                .await;

            return Err(SecurityPolicyError::Unauthorized(format!(
                "Access denied by active security policy for action: {action:?}"
            )));
        }

        Ok(validated_spiffe)
    }
}

fn map_row_to_session(row: &rusqlite::Row<'_>) -> rusqlite::Result<BreakGlassSession> {
    let status_str: String = row.get(7)?;
    let status = match status_str.as_str() {
        "requested" => BreakGlassStatus::Requested,
        "approved" => BreakGlassStatus::Approved,
        "active" => BreakGlassStatus::Active,
        "denied" => BreakGlassStatus::Denied,
        "expired" => BreakGlassStatus::Expired,
        "revoked" => BreakGlassStatus::Revoked,
        _ => BreakGlassStatus::Requested,
    };

    Ok(BreakGlassSession {
        id: row.get(0)?,
        request: BreakGlassRequest {
            principal: row.get(1)?,
            tenant: row.get(2)?,
            reason: row.get(3)?,
            scope: row.get(4)?,
            requested_duration: row.get(5)?,
            evidence_id: row.get(6)?,
        },
        status,
        requested_at: row.get(8)?,
        approved_at: row.get(9)?,
        approver: row.get(10)?,
        activated_at: row.get(11)?,
        expires_at: row.get(12)?,
        denied_at: row.get(13)?,
        revoked_at: row.get(14)?,
        revoker: row.get(15)?,
    })
}

#[async_trait]
impl<P: KeyProvider + 'static> BreakGlassService for SqliteSecurityPolicyService<P> {
    async fn request_break_glass(
        &self,
        tenant: &str,
        principal: &str,
        req: BreakGlassRequest,
    ) -> Result<BreakGlassSession, SecurityPolicyError> {
        if req.requested_duration == 0 || req.requested_duration > 900 {
            return Err(SecurityPolicyError::ValidationFailed(
                "Requested duration must be between 1 and 900 seconds (15 minutes)".to_string(),
            ));
        }
        if req.reason.trim().is_empty() {
            return Err(SecurityPolicyError::ValidationFailed(
                "Reason/justification must not be empty".to_string(),
            ));
        }
        if req.evidence_id.trim().is_empty() {
            return Err(SecurityPolicyError::ValidationFailed(
                "Evidence ID/ticket ID must not be empty".to_string(),
            ));
        }
        if req.tenant != tenant {
            return Err(SecurityPolicyError::ValidationFailed(
                "Tenant mismatch in request".to_string(),
            ));
        }

        let _ = self.clean_expired(tenant).await;

        let validated_spiffe = self
            .check_break_glass_permission(tenant, principal, NacmAction::Request)
            .await?;

        let session_id = uuid::Uuid::new_v4().to_string();
        let requested_at = Timestamp::now_utc().to_string();

        let session = BreakGlassSession {
            id: session_id.clone(),
            request: req.clone(),
            status: BreakGlassStatus::Requested,
            requested_at: requested_at.clone(),
            approved_at: None,
            approver: None,
            activated_at: None,
            expires_at: None,
            denied_at: None,
            revoked_at: None,
            revoker: None,
        };

        {
            let conn_mutex = self.backend.conn();
            let conn = conn_mutex.lock().await;
            conn.execute(
                "INSERT INTO break_glass_sessions (id, principal, tenant, reason, scope, requested_duration, evidence_id, status, requested_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                rusqlite::params![
                    session.id,
                    session.request.principal,
                    session.request.tenant,
                    session.request.reason,
                    session.request.scope,
                    session.request.requested_duration,
                    session.request.evidence_id,
                    "requested",
                    session.requested_at,
                ],
            ).map_err(|e| {
                tracing::error!(err = ?e, "Failed to insert break glass session");
                SecurityPolicyError::Internal
            })?;
        }

        let details = format!(
            "Break glass request created: session_id={}, evidence_id={}, duration={}s",
            session_id, req.evidence_id, req.requested_duration
        );
        self.break_glass_audit_event(tenant, &validated_spiffe, "REQUEST", &details)
            .await?;

        Ok(session)
    }

    async fn approve_break_glass(
        &self,
        tenant: &str,
        approver: &str,
        session_id: &str,
    ) -> Result<BreakGlassSession, SecurityPolicyError> {
        let (validated_approver, _, _) = validate_principal_tenant_and_roles(approver, tenant)?;

        let _ = self.clean_expired(tenant).await;

        let active_policy = self.get_active_policy_compiled(tenant).await.ok();

        let session = self.get_session(tenant, session_id).await?;
        if session.status != BreakGlassStatus::Requested {
            return Err(SecurityPolicyError::ValidationFailed(
                "Only sessions in 'requested' status can be approved".to_string(),
            ));
        }

        self.approval_service
            .check_approval(
                tenant,
                &session.request.principal,
                approver,
                active_policy.as_ref(),
            )
            .await?;

        let _ = self
            .check_break_glass_permission(tenant, approver, NacmAction::Approve)
            .await?;

        let approved_at = Timestamp::now_utc().to_string();

        {
            let conn_mutex = self.backend.conn();
            let conn = conn_mutex.lock().await;
            conn.execute(
                "UPDATE break_glass_sessions SET status = ?1, approved_at = ?2, approver = ?3 WHERE id = ?4",
                rusqlite::params!["approved", approved_at, validated_approver, session_id],
            ).map_err(|e| {
                tracing::error!(err = ?e, "Failed to approve break glass session");
                SecurityPolicyError::Internal
            })?;
        }

        let details = format!(
            "Break glass request approved: session_id={session_id}, approver={validated_approver}"
        );
        self.break_glass_audit_event(tenant, &validated_approver, "APPROVE", &details)
            .await?;

        self.get_session(tenant, session_id).await
    }

    async fn activate_break_glass(
        &self,
        tenant: &str,
        principal: &str,
        session_id: &str,
    ) -> Result<BreakGlassSession, SecurityPolicyError> {
        let _ = self.clean_expired(tenant).await;

        let validated_spiffe = self
            .check_break_glass_permission(tenant, principal, NacmAction::Activate)
            .await?;

        let session = self.get_session(tenant, session_id).await?;
        if session.status != BreakGlassStatus::Approved {
            return Err(SecurityPolicyError::ValidationFailed(
                "Only sessions in 'approved' status can be activated".to_string(),
            ));
        }

        let (parsed_spiffe, _, _) = validate_principal_tenant_and_roles(principal, tenant)?;
        let (req_spiffe, _, _) =
            validate_principal_tenant_and_roles(&session.request.principal, tenant)?;
        if parsed_spiffe != req_spiffe {
            return Err(SecurityPolicyError::Unauthorized(
                "Only the original requester can activate their break-glass session".to_string(),
            ));
        }

        let activated_at = Timestamp::now_utc();
        let dt: time::OffsetDateTime = activated_at.into();
        let expires_dt = dt + time::Duration::seconds(session.request.requested_duration as i64);
        let expires_at = Timestamp::from_offset_datetime(expires_dt);

        let activated_at_str = activated_at.to_string();
        let expires_at_str = expires_at.to_string();

        {
            let conn_mutex = self.backend.conn();
            let conn = conn_mutex.lock().await;
            conn.execute(
                "UPDATE break_glass_sessions SET status = ?1, activated_at = ?2, expires_at = ?3 WHERE id = ?4",
                rusqlite::params!["active", activated_at_str, expires_at_str, session_id],
            ).map_err(|e| {
                tracing::error!(err = ?e, "Failed to activate break glass session");
                SecurityPolicyError::Internal
            })?;
        }

        opc_redaction::metrics::METRICS
            .break_glass_sessions_active
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let _ = self.alarm_notifier.raise_alarm(tenant, session_id).await;

        let details = format!(
            "Break glass session activated: session_id={session_id}, expires_at={expires_at_str}"
        );
        self.break_glass_audit_event(tenant, &validated_spiffe, "ACTIVATE", &details)
            .await?;

        self.get_session(tenant, session_id).await
    }

    async fn deny_break_glass(
        &self,
        tenant: &str,
        principal: &str,
        session_id: &str,
    ) -> Result<BreakGlassSession, SecurityPolicyError> {
        let _ = self.clean_expired(tenant).await;

        let validated_spiffe = self
            .check_break_glass_permission(tenant, principal, NacmAction::Approve)
            .await?;

        let session = self.get_session(tenant, session_id).await?;
        if session.status != BreakGlassStatus::Requested {
            return Err(SecurityPolicyError::ValidationFailed(
                "Only sessions in 'requested' status can be denied".to_string(),
            ));
        }

        let denied_at = Timestamp::now_utc().to_string();

        {
            let conn_mutex = self.backend.conn();
            let conn = conn_mutex.lock().await;
            conn.execute(
                "UPDATE break_glass_sessions SET status = ?1, denied_at = ?2 WHERE id = ?3",
                rusqlite::params!["denied", denied_at, session_id],
            )
            .map_err(|e| {
                tracing::error!(err = ?e, "Failed to deny break glass session");
                SecurityPolicyError::Internal
            })?;
        }

        let details =
            format!("Break glass request denied: session_id={session_id}, by={validated_spiffe}");
        self.break_glass_audit_event(tenant, &validated_spiffe, "DENY", &details)
            .await?;

        self.get_session(tenant, session_id).await
    }

    async fn revoke_break_glass(
        &self,
        tenant: &str,
        principal: &str,
        session_id: &str,
    ) -> Result<BreakGlassSession, SecurityPolicyError> {
        let _ = self.clean_expired(tenant).await;

        let validated_spiffe = self
            .check_break_glass_permission(tenant, principal, NacmAction::Revoke)
            .await?;

        let session = self.get_session(tenant, session_id).await?;
        if session.status != BreakGlassStatus::Active
            && session.status != BreakGlassStatus::Approved
        {
            return Err(SecurityPolicyError::ValidationFailed(
                "Only 'approved' or 'active' sessions can be revoked".to_string(),
            ));
        }

        let revoked_at = Timestamp::now_utc().to_string();
        let was_active = session.status == BreakGlassStatus::Active;

        {
            let conn_mutex = self.backend.conn();
            let conn = conn_mutex.lock().await;
            conn.execute(
                "UPDATE break_glass_sessions SET status = ?1, revoked_at = ?2, revoker = ?3 WHERE id = ?4",
                rusqlite::params!["revoked", revoked_at, validated_spiffe, session_id],
            ).map_err(|e| {
                tracing::error!(err = ?e, "Failed to revoke break glass session");
                SecurityPolicyError::Internal
            })?;
        }

        if was_active {
            opc_redaction::metrics::METRICS
                .break_glass_sessions_active
                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            let _ = self.alarm_notifier.resolve_alarm(tenant, session_id).await;
        }

        let details =
            format!("Break glass session revoked: session_id={session_id}, by={validated_spiffe}");
        self.break_glass_audit_event(tenant, &validated_spiffe, "REVOKE", &details)
            .await?;

        self.get_session(tenant, session_id).await
    }

    async fn get_session(
        &self,
        tenant: &str,
        session_id: &str,
    ) -> Result<BreakGlassSession, SecurityPolicyError> {
        let conn_mutex = self.backend.conn();
        let conn = conn_mutex.lock().await;
        let row: Result<BreakGlassSession, _> = conn.query_row(
            "SELECT id, principal, tenant, reason, scope, requested_duration, evidence_id, status, requested_at, \
                    approved_at, approver, activated_at, expires_at, denied_at, revoked_at, revoker \
             FROM break_glass_sessions WHERE tenant = ?1 AND id = ?2",
            [tenant, session_id],
            map_row_to_session,
        );

        match row {
            Ok(s) => Ok(s),
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                Err(SecurityPolicyError::ValidationFailed(format!(
                    "Break glass session not found: {session_id}"
                )))
            }
            Err(e) => {
                tracing::error!(err = ?e, "Failed to query break glass session");
                Err(SecurityPolicyError::Internal)
            }
        }
    }

    async fn list_sessions(
        &self,
        tenant: &str,
    ) -> Result<Vec<BreakGlassSession>, SecurityPolicyError> {
        let conn_mutex = self.backend.conn();
        let conn = conn_mutex.lock().await;
        let mut stmt = conn.prepare(
            "SELECT id, principal, tenant, reason, scope, requested_duration, evidence_id, status, requested_at, \
                    approved_at, approver, activated_at, expires_at, denied_at, revoked_at, revoker \
             FROM break_glass_sessions WHERE tenant = ?1 ORDER BY requested_at DESC",
        ).map_err(|e| {
            tracing::error!(err = ?e, "Failed to prepare list break glass sessions query");
            SecurityPolicyError::Internal
        })?;

        let rows = stmt.query_map([tenant], map_row_to_session).map_err(|e| {
            tracing::error!(err = ?e, "Failed to query list break glass sessions");
            SecurityPolicyError::Internal
        })?;

        let mut list = Vec::new();
        for r in rows {
            list.push(r.map_err(|e| {
                tracing::error!(err = ?e, "Failed to map break glass session row");
                SecurityPolicyError::Internal
            })?);
        }

        Ok(list)
    }

    async fn clean_expired(&self, tenant: &str) -> Result<(), SecurityPolicyError> {
        let active_sessions = {
            let conn_mutex = self.backend.conn();
            let conn = conn_mutex.lock().await;
            let mut stmt = conn.prepare(
                "SELECT id, principal, tenant, reason, scope, requested_duration, evidence_id, status, requested_at, \
                        approved_at, approver, activated_at, expires_at, denied_at, revoked_at, revoker \
                 FROM break_glass_sessions WHERE tenant = ?1 AND status = 'active'",
            ).map_err(|e| {
                tracing::error!(err = ?e, "Failed to prepare active break glass query for clean");
                SecurityPolicyError::Internal
            })?;

            let rows = stmt.query_map([tenant], map_row_to_session).map_err(|e| {
                tracing::error!(err = ?e, "Failed to execute active break glass query for clean");
                SecurityPolicyError::Internal
            })?;

            let mut active = Vec::new();
            for r in rows {
                active.push(r.map_err(|e| {
                    tracing::error!(err = ?e, "Failed to map active break glass row for clean");
                    SecurityPolicyError::Internal
                })?);
            }
            active
        };

        let now_str = Timestamp::now_utc().to_string();

        for session in active_sessions {
            if let Some(ref expires_at_str) = session.expires_at {
                if now_str >= *expires_at_str {
                    {
                        let conn_mutex = self.backend.conn();
                        let conn = conn_mutex.lock().await;
                        conn.execute(
                            "UPDATE break_glass_sessions SET status = 'expired' WHERE id = ?1",
                            [&session.id],
                        ).map_err(|e| {
                            tracing::error!(err = ?e, "Failed to update expired break glass session");
                            SecurityPolicyError::Internal
                        })?;
                    }

                    opc_redaction::metrics::METRICS
                        .break_glass_sessions_active
                        .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                    let _ = self.alarm_notifier.resolve_alarm(tenant, &session.id).await;

                    let details = format!(
                        "Break glass session expired automatically: session_id={}",
                        session.id
                    );
                    self.break_glass_audit_event(tenant, "system", "EXPIRE", &details)
                        .await?;
                }
            }
        }

        Ok(())
    }
}
