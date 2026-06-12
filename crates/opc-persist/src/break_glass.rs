use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use opc_nacm::{ModuleRegistry, NacmAction, NacmEvaluator, NacmPolicy, YangPath};

use crate::security_policy::{validate_principal_tenant_and_roles, SecurityPolicyError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BreakGlassStatus {
    Requested,
    Approved,
    Active,
    Denied,
    Expired,
    Revoked,
}

impl std::fmt::Display for BreakGlassStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Requested => "requested",
            Self::Approved => "approved",
            Self::Active => "active",
            Self::Denied => "denied",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        };
        f.write_str(s)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BreakGlassRequest {
    pub principal: String,
    pub tenant: String,
    pub reason: String,
    pub scope: String,
    pub requested_duration: u32, // hard limit of 900 seconds
    pub evidence_id: String,     // ticket ID / evidence ID
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BreakGlassSession {
    pub id: String,
    pub request: BreakGlassRequest,
    pub status: BreakGlassStatus,
    pub requested_at: String,
    pub approved_at: Option<String>,
    pub approver: Option<String>,
    pub activated_at: Option<String>,
    pub expires_at: Option<String>,
    pub denied_at: Option<String>,
    pub revoked_at: Option<String>,
    pub revoker: Option<String>,
}

#[async_trait]
pub trait BreakGlassAlarmNotifier: Send + Sync {
    async fn raise_alarm(&self, tenant: &str, session_id: &str) -> Result<(), String>;
    async fn resolve_alarm(&self, tenant: &str, session_id: &str) -> Result<(), String>;
}

pub struct NoopBreakGlassAlarmNotifier;

#[async_trait]
impl BreakGlassAlarmNotifier for NoopBreakGlassAlarmNotifier {
    async fn raise_alarm(&self, _tenant: &str, _session_id: &str) -> Result<(), String> {
        Ok(())
    }
    async fn resolve_alarm(&self, _tenant: &str, _session_id: &str) -> Result<(), String> {
        Ok(())
    }
}

#[async_trait]
pub trait BreakGlassApprovalTrait: Send + Sync {
    async fn check_approval(
        &self,
        tenant: &str,
        requester: &str,
        approver: &str,
        policy: Option<&NacmPolicy>,
    ) -> Result<(), SecurityPolicyError>;
}

pub struct DefaultBreakGlassApproval;

#[async_trait]
impl BreakGlassApprovalTrait for DefaultBreakGlassApproval {
    async fn check_approval(
        &self,
        tenant: &str,
        requester: &str,
        approver: &str,
        policy: Option<&NacmPolicy>,
    ) -> Result<(), SecurityPolicyError> {
        let (req_spiffe, _) = validate_principal_tenant_and_roles(requester, tenant)?;
        let (app_spiffe, app_roles) = validate_principal_tenant_and_roles(approver, tenant)?;

        if req_spiffe == app_spiffe {
            return Err(SecurityPolicyError::Unauthorized(
                "Approver must be a different principal from the requester".to_string(),
            ));
        }

        if !app_roles.iter().any(|r| r == "security-admin") {
            return Err(SecurityPolicyError::Unauthorized(format!(
                "Approver '{app_spiffe}' lacks 'security-admin' role"
            )));
        }

        if let Some(active_policy) = policy {
            let mut registry = ModuleRegistry::new();
            let _ = registry.register_module("security", "security");
            let path = YangPath::parse("/security:break-glass", &registry).map_err(|e| {
                tracing::error!(err = ?e, "Failed to parse /security:break-glass");
                SecurityPolicyError::Internal
            })?;

            let mut evaluator = NacmEvaluator::new();
            let decision = evaluator.evaluate(active_policy, &path, NacmAction::Approve);

            if !decision.is_allowed() {
                return Err(SecurityPolicyError::Unauthorized(
                    "Approver lacks permission to approve break-glass access under the active policy".to_string(),
                ));
            }
        }

        Ok(())
    }
}

#[async_trait]
pub trait BreakGlassService: Send + Sync {
    async fn request_break_glass(
        &self,
        tenant: &str,
        principal: &str,
        req: BreakGlassRequest,
    ) -> Result<BreakGlassSession, SecurityPolicyError>;

    async fn approve_break_glass(
        &self,
        tenant: &str,
        approver: &str,
        session_id: &str,
    ) -> Result<BreakGlassSession, SecurityPolicyError>;

    async fn activate_break_glass(
        &self,
        tenant: &str,
        principal: &str,
        session_id: &str,
    ) -> Result<BreakGlassSession, SecurityPolicyError>;

    async fn deny_break_glass(
        &self,
        tenant: &str,
        principal: &str,
        session_id: &str,
    ) -> Result<BreakGlassSession, SecurityPolicyError>;

    async fn revoke_break_glass(
        &self,
        tenant: &str,
        principal: &str,
        session_id: &str,
    ) -> Result<BreakGlassSession, SecurityPolicyError>;

    async fn get_session(
        &self,
        tenant: &str,
        session_id: &str,
    ) -> Result<BreakGlassSession, SecurityPolicyError>;

    async fn list_sessions(
        &self,
        tenant: &str,
    ) -> Result<Vec<BreakGlassSession>, SecurityPolicyError>;

    async fn clean_expired(&self, tenant: &str) -> Result<(), SecurityPolicyError>;
}
