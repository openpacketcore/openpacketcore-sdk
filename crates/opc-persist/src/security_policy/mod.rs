use async_trait::async_trait;
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
use crate::SqliteBackend;

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
}
