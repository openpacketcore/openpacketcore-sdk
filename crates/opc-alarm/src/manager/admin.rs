use crate::model::AlarmId;
use time::OffsetDateTime;

/// Authorization check result for suppression/acknowledgement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuppressionAuth {
    pub authorized: bool,
    pub reason: Option<String>,
}

/// Administrative alarm action protected by policy and audit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlarmAction {
    Acknowledge,
    Suppress,
}

/// Scope asserted by an administrative alarm action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AlarmActionScope {
    Alarm { alarm_id: AlarmId },
    Tenant { tenant: String },
    Global,
}

/// Structured context required for production alarm acknowledgement/suppression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlarmActionContext {
    pub principal: String,
    pub tenant: Option<String>,
    pub reason: String,
    pub scope: AlarmActionScope,
    pub expires_at: Option<OffsetDateTime>,
    pub correlation_id: Option<String>,
}

impl AlarmActionContext {
    pub fn new(
        principal: impl Into<String>,
        reason: impl Into<String>,
        scope: AlarmActionScope,
    ) -> Self {
        Self {
            principal: principal.into(),
            tenant: None,
            reason: reason.into(),
            scope,
            expires_at: None,
            correlation_id: None,
        }
    }

    pub fn with_tenant(mut self, tenant: impl Into<String>) -> Self {
        self.tenant = Some(tenant.into());
        self
    }

    pub fn with_expiry(mut self, expires_at: OffsetDateTime) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    pub fn with_correlation_id(mut self, correlation_id: impl Into<String>) -> Self {
        self.correlation_id = Some(correlation_id.into());
        self
    }
}

/// Authorization denial returned by authorizers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlarmActionDenied {
    pub message: String,
}

impl AlarmActionDenied {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}
