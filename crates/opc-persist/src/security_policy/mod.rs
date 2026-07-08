use async_trait::async_trait;
use hmac::Mac;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use tokio::sync::RwLock;

use opc_key::KeyProvider;
use opc_nacm::{AuthorizationDecision, NacmAction, NacmPolicy};

use crate::break_glass::{
    BreakGlassAlarmNotifier, BreakGlassApprovalTrait, DefaultBreakGlassApproval,
    NoopBreakGlassAlarmNotifier,
};
use crate::types::RollbackTarget;
use crate::{AuditKey, SqliteBackend};

mod break_glass;
mod crypto;
mod service;

pub(crate) use crypto::validate_principal_tenant_and_roles;

#[cfg(any(test, feature = "dangerous-test-hooks"))]
pub static TEST_COMMIT_FAIL: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[derive(Debug, Clone, thiserror::Error, Serialize, Deserialize, PartialEq, Eq)]
pub enum SecurityPolicyError {
    #[error("unauthorized mismatch or lack of role: {0}")]
    Unauthorized(String),
    #[error("validation failure: {0}")]
    ValidationFailed(String),
    #[error("stale version or invalid transaction: {0}")]
    StaleVersion(String),
    #[error("security policy internal error")]
    Internal,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivePolicyMetadata {
    pub version: u64,
    pub applied_at: String,
    pub principal: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyHistoryEntry {
    pub version: u64,
    pub applied_at: String,
    pub principal: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializableRule {
    pub action: String,
    pub effect: String,
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializableRuleList {
    pub name: String,
    pub groups: Vec<String>,
    pub rules: Vec<SerializableRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializablePolicy {
    pub version: u64,
    pub rules: Vec<SerializableRule>,
    #[serde(default)]
    pub rule_lists: Vec<SerializableRuleList>,
}

#[async_trait]
pub trait SecurityPolicyService: Send + Sync {
    async fn stage_policy(
        &self,
        tenant: &str,
        principal: &str,
        policy: NacmPolicy,
    ) -> Result<(), SecurityPolicyError>;
    async fn validate_policy(
        &self,
        tenant: &str,
        principal: &str,
    ) -> Result<(), SecurityPolicyError>;
    async fn apply_policy(&self, tenant: &str, principal: &str) -> Result<(), SecurityPolicyError>;
    async fn dry_run_policy(
        &self,
        tenant: &str,
        principal: &str,
        path: &str,
        action: NacmAction,
    ) -> Result<AuthorizationDecision, SecurityPolicyError>;
    async fn rollback_policy(
        &self,
        tenant: &str,
        principal: &str,
        target: RollbackTarget,
    ) -> Result<(), SecurityPolicyError>;
    async fn inspect_active_policy(
        &self,
        tenant: &str,
        principal: &str,
    ) -> Result<ActivePolicyMetadata, SecurityPolicyError>;
    async fn list_policy_history(
        &self,
        tenant: &str,
        principal: &str,
    ) -> Result<Vec<PolicyHistoryEntry>, SecurityPolicyError>;
}

pub struct SqliteSecurityPolicyService<P: KeyProvider + 'static> {
    backend: SqliteBackend,
    key_provider: Arc<P>,
    active_policies: Arc<RwLock<HashMap<String, NacmPolicy>>>,
    write_epoch: Arc<AtomicU64>,
    alarm_notifier: Arc<dyn BreakGlassAlarmNotifier>,
    approval_service: Arc<dyn BreakGlassApprovalTrait>,
}

#[derive(Clone, Copy)]
enum AuditChainKind {
    SecurityPolicy,
    BreakGlass,
}

impl AuditChainKind {
    fn audit_table(self) -> &'static str {
        match self {
            Self::SecurityPolicy => "security_policy_audit",
            Self::BreakGlass => "break_glass_audit",
        }
    }

    fn anchor_table(self) -> &'static str {
        match self {
            Self::SecurityPolicy => "security_policy_audit_anchor",
            Self::BreakGlass => "break_glass_audit_anchor",
        }
    }
}

pub(super) fn audit_hash_from_blob(
    bytes: Vec<u8>,
    context: &'static str,
) -> Result<[u8; 32], SecurityPolicyError> {
    if bytes.len() != 32 {
        tracing::error!(len = bytes.len(), context, "Invalid audit HMAC length");
        return Err(SecurityPolicyError::Internal);
    }
    let mut h = [0u8; 32];
    h.copy_from_slice(&bytes);
    Ok(h)
}

pub(super) fn calculate_audit_event_hmac(
    audit_key: &AuditKey,
    tenant: &str,
    timestamp: &str,
    principal: &str,
    action: &str,
    details: &str,
    previous_hash: &[u8; 32],
) -> Result<[u8; 32], SecurityPolicyError> {
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

    mac_input.extend_from_slice(previous_hash);

    type HmacSha256 = hmac::Hmac<sha2::Sha256>;
    let mut mac = HmacSha256::new_from_slice(audit_key.as_bytes()).map_err(|e| {
        tracing::error!(err = ?e, "Failed to create HMAC provider");
        SecurityPolicyError::Internal
    })?;
    mac.update(&mac_input);
    Ok(mac.finalize().into_bytes().into())
}

impl<P: KeyProvider + 'static> SqliteSecurityPolicyService<P> {
    pub fn new(backend: SqliteBackend, key_provider: Arc<P>) -> Self {
        Self {
            backend,
            key_provider,
            active_policies: Arc::new(RwLock::new(HashMap::new())),
            write_epoch: Arc::new(AtomicU64::new(1)),
            alarm_notifier: Arc::new(NoopBreakGlassAlarmNotifier),
            approval_service: Arc::new(DefaultBreakGlassApproval),
        }
    }

    pub fn new_with_notifier(
        backend: SqliteBackend,
        key_provider: Arc<P>,
        alarm_notifier: Arc<dyn BreakGlassAlarmNotifier>,
    ) -> Self {
        Self {
            backend,
            key_provider,
            active_policies: Arc::new(RwLock::new(HashMap::new())),
            write_epoch: Arc::new(AtomicU64::new(1)),
            alarm_notifier,
            approval_service: Arc::new(DefaultBreakGlassApproval),
        }
    }

    pub fn new_with_notifier_and_approval(
        backend: SqliteBackend,
        key_provider: Arc<P>,
        alarm_notifier: Arc<dyn BreakGlassAlarmNotifier>,
        approval_service: Arc<dyn BreakGlassApprovalTrait>,
    ) -> Self {
        Self {
            backend,
            key_provider,
            active_policies: Arc::new(RwLock::new(HashMap::new())),
            write_epoch: Arc::new(AtomicU64::new(1)),
            alarm_notifier,
            approval_service,
        }
    }

    pub async fn verify_security_policy_audit_chain(
        &self,
        tenant: &str,
    ) -> Result<(), SecurityPolicyError> {
        self.verify_audit_chain(tenant, AuditChainKind::SecurityPolicy)
            .await
    }

    pub async fn verify_break_glass_audit_chain(
        &self,
        tenant: &str,
    ) -> Result<(), SecurityPolicyError> {
        self.verify_audit_chain(tenant, AuditChainKind::BreakGlass)
            .await
    }

    async fn verify_audit_chain(
        &self,
        tenant: &str,
        kind: AuditChainKind,
    ) -> Result<(), SecurityPolicyError> {
        let conn_mutex = self.backend.conn();
        let conn = conn_mutex.lock().await;
        let audit_table = kind.audit_table();
        let anchor_table = kind.anchor_table();

        let anchor = match conn.query_row(
            &format!(
                "SELECT audit_count, audit_terminal_hash FROM {anchor_table} WHERE tenant = ?1"
            ),
            [tenant],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)),
        ) {
            Ok((count, terminal_hash)) => Some((count, terminal_hash)),
            Err(rusqlite::Error::QueryReturnedNoRows) => None,
            Err(e) => {
                tracing::error!(err = ?e, tenant, "Failed to load audit anchor");
                return Err(SecurityPolicyError::Internal);
            }
        };

        let mut stmt = conn
            .prepare(&format!(
                "SELECT timestamp, principal, action, details, previous_hash, entry_hmac \
                 FROM {audit_table} WHERE tenant = ?1 ORDER BY id ASC"
            ))
            .map_err(|e| {
                tracing::error!(err = ?e, tenant, "Failed to prepare audit verification query");
                SecurityPolicyError::Internal
            })?;
        let rows = stmt
            .query_map([tenant], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                ))
            })
            .map_err(|e| {
                tracing::error!(err = ?e, tenant, "Failed to query audit rows for verification");
                SecurityPolicyError::Internal
            })?;

        let mut prev_hash = [0u8; 32];
        let mut row_count: i64 = 0;
        for row in rows {
            let (timestamp, principal, action, details, previous_hash, entry_hmac) =
                row.map_err(|e| {
                    tracing::error!(err = ?e, tenant, "Failed to read audit row for verification");
                    SecurityPolicyError::Internal
                })?;
            let previous_hash = audit_hash_from_blob(previous_hash, "audit row previous_hash")?;
            let entry_hmac = audit_hash_from_blob(entry_hmac, "audit row entry_hmac")?;

            if previous_hash != prev_hash {
                tracing::error!(tenant, audit_table, "Audit chain previous_hash mismatch");
                return Err(SecurityPolicyError::Internal);
            }

            let expected_hmac = calculate_audit_event_hmac(
                self.backend.audit_key(),
                tenant,
                &timestamp,
                &principal,
                &action,
                &details,
                &previous_hash,
            )?;
            if entry_hmac != expected_hmac {
                tracing::error!(tenant, audit_table, "Audit chain HMAC mismatch");
                return Err(SecurityPolicyError::Internal);
            }

            prev_hash = entry_hmac;
            row_count += 1;
        }

        match anchor {
            Some((audit_count, terminal_hash)) => {
                if audit_count != row_count {
                    tracing::error!(
                        tenant,
                        audit_table,
                        expected = audit_count,
                        actual = row_count,
                        "Audit anchor count mismatch"
                    );
                    return Err(SecurityPolicyError::Internal);
                }
                let terminal_hash =
                    audit_hash_from_blob(terminal_hash, "audit anchor terminal hash")?;
                if terminal_hash != prev_hash {
                    tracing::error!(tenant, audit_table, "Audit anchor terminal hash mismatch");
                    return Err(SecurityPolicyError::Internal);
                }
            }
            None if row_count == 0 => {}
            None => {
                tracing::error!(tenant, audit_table, "Audit rows exist without an anchor");
                return Err(SecurityPolicyError::Internal);
            }
        }

        Ok(())
    }
}
