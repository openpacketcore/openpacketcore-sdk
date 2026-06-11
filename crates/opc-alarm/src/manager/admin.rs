//! Administrative alarm action types: acknowledgement/suppression requests,
//! the scope they assert, the operator context they carry, and the denial
//! result authorizers return. Suppression and acknowledgement require
//! authorization and audit per RFC 013 §10.

use crate::model::AlarmId;
use time::OffsetDateTime;

/// Authorization check result for suppression/acknowledgement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuppressionAuth {
    /// Caller-asserted authorization outcome. The simple `acknowledge` /
    /// `suppress` manager paths trust this flag as-is (no audit, no
    /// security-critical policy check) and return `Unauthorized` when it is
    /// `false`; the `*_with_policy` paths evaluate a real authorizer instead.
    pub authorized: bool,
    /// Optional reason recorded by the caller for why the check passed or
    /// failed; informational only, never interpreted by the manager.
    pub reason: Option<String>,
}

/// Administrative alarm action protected by policy and audit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlarmAction {
    /// Mark an active alarm as seen by an operator. Does not clear the fault
    /// (RFC 013 §8) and survives subsequent raises of the same dedup key.
    Acknowledge,
    /// Hide an active alarm from normal presentation (maintenance window,
    /// known outage, test mode). History is preserved, and security-critical
    /// alarms additionally require an explicit policy override (RFC 013 §10).
    Suppress,
}

/// Scope asserted by an administrative alarm action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AlarmActionScope {
    /// The action targets exactly one alarm; authorizers reject the action if
    /// this id differs from the alarm actually being acted on.
    Alarm {
        /// Identifier of the single alarm the action is allowed to touch.
        alarm_id: AlarmId,
    },
    /// The action covers alarms belonging to one tenant; authorizers reject
    /// it for alarms scoped to a different tenant or to no tenant.
    Tenant {
        /// Tenant whose alarms the action may touch.
        tenant: String,
    },
    /// The action may target any alarm. The broadest scope, intended for
    /// platform-level operators; still subject to authorization and audit.
    Global,
}

/// Structured context required for production alarm acknowledgement/suppression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlarmActionContext {
    /// Authenticated operator identity performing the action. Authorizers
    /// reject blank principals, and the value is written verbatim into audit
    /// records — map it from real authenticated identity, and keep it free of
    /// raw subscriber identifiers per RFC 010.
    pub principal: String,
    /// Optional tenant assertion. A tenant-scoped context may only act on
    /// alarms of that same tenant; it cannot touch global (tenant-less)
    /// alarms or another tenant's alarms.
    pub tenant: Option<String>,
    /// Free-text justification recorded in the audit trail. MUST be redacted
    /// per RFC 010 before being supplied; persistence-side sinks additionally
    /// scrub obvious identifiers but do not relieve the caller of that duty.
    pub reason: String,
    /// Scope the caller asserts for this action (single alarm, tenant, or
    /// global); validated against the target alarm by authorizers.
    pub scope: AlarmActionScope,
    /// Optional expiry of the action's intent (e.g. end of the maintenance
    /// window motivating a suppression). Recorded for operators; the manager
    /// does not currently auto-revert the state when it passes.
    pub expires_at: Option<OffsetDateTime>,
    /// Optional identifier linking the action to an external change ticket or
    /// maintenance record; carried into audit events for traceability.
    pub correlation_id: Option<String>,
}

impl AlarmActionContext {
    /// Creates a minimal context from the three mandatory ingredients:
    /// principal, justification, and scope. Tenant, expiry, and correlation
    /// id start unset; add them with the `with_*` builders.
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

    /// Restricts the context to one tenant; tenant-scoped contexts cannot act
    /// on global alarms or alarms of other tenants.
    pub fn with_tenant(mut self, tenant: impl Into<String>) -> Self {
        self.tenant = Some(tenant.into());
        self
    }

    /// Records when the action's intent lapses (e.g. the end of a maintenance
    /// window for a suppression).
    pub fn with_expiry(mut self, expires_at: OffsetDateTime) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// Attaches an external change/maintenance ticket reference that will be
    /// carried into audit events.
    pub fn with_correlation_id(mut self, correlation_id: impl Into<String>) -> Self {
        self.correlation_id = Some(correlation_id.into());
        self
    }
}

/// Authorization denial returned by authorizers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlarmActionDenied {
    /// Human-readable denial reason; surfaced to the caller via
    /// `AlarmOpResult::Unauthorized` and recorded in the audited denial
    /// event, so it must not contain sensitive material.
    pub message: String,
}

impl AlarmActionDenied {
    /// Creates a denial carrying the given operator-facing reason.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}
