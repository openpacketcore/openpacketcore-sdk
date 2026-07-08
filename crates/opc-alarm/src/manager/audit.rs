//! Audit events and the sink trait for policy-protected alarm admin actions.
//! Suppression and acknowledgement are audited per RFC 013 §10, including
//! denials, and the manager fails closed: an authorized action whose audit
//! record cannot be written is abandoned.

use crate::manager::admin::{AlarmAction, AlarmActionContext, AlarmActionScope};
use crate::model::{Alarm, AlarmId, AlarmType, ProbableCause};
use time::OffsetDateTime;

/// Outcome recorded for an administrative alarm action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlarmAuditOutcome {
    /// The authorizer allowed the action. Recorded *before* the alarm state
    /// changes; if recording fails, the state change is abandoned.
    Authorized,
    /// The authorizer (or the security-critical suppression policy) rejected
    /// the action. Denials are audited so unauthorized suppression attempts
    /// leave a trace (RFC 013 §19.3).
    Denied,
}

/// Audit event emitted before a policy-protected alarm action is finalized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlarmAuditEvent {
    /// Which admin action (acknowledge or suppress) was attempted.
    pub action: AlarmAction,
    /// Whether the action was authorized or denied; the alarm state only
    /// changes on the authorized path.
    pub outcome: AlarmAuditOutcome,
    /// Id of the target alarm, copied at decision time.
    pub alarm_id: AlarmId,
    /// Alarm type of the target, retained so audit rows stay meaningful after
    /// the alarm leaves the store.
    pub alarm_type: AlarmType,
    /// Probable cause of the target alarm; lets auditors spot suppression of
    /// security-relevant causes at a glance.
    pub probable_cause: ProbableCause,
    /// Operator identity from the action context. Copied verbatim; sinks that
    /// persist it are responsible for RFC 010 scrubbing of free-form values.
    pub principal: String,
    /// Tenant assertion from the action context, if any.
    pub tenant: Option<String>,
    /// Operator-supplied justification from the action context (free text,
    /// caller-redacted per RFC 010).
    pub reason: String,
    /// Scope the action asserted (single alarm, tenant, or global).
    pub scope: AlarmActionScope,
    /// External change/maintenance ticket reference from the context, if any.
    pub correlation_id: Option<String>,
    /// UTC time the audit event was created (decision time, immediately
    /// before any state change is applied).
    pub occurred_at: OffsetDateTime,
}

impl AlarmAuditEvent {
    pub(crate) fn from_action(
        action: AlarmAction,
        outcome: AlarmAuditOutcome,
        alarm: &Alarm,
        context: &AlarmActionContext,
    ) -> Self {
        Self {
            action,
            outcome,
            alarm_id: alarm.alarm_id.clone(),
            alarm_type: alarm.alarm_type.clone(),
            probable_cause: alarm.probable_cause.clone(),
            principal: context.principal.clone(),
            tenant: context.tenant.clone(),
            reason: context.reason.clone(),
            scope: context.scope.clone(),
            correlation_id: context.correlation_id.clone(),
            occurred_at: OffsetDateTime::now_utc().max(alarm.raised_at),
        }
    }
}

/// Audit hook for policy-protected alarm actions.
pub trait AlarmAuditSink {
    /// Durably records one admin-action audit event. Returning `Err` from an
    /// `Authorized` event makes the manager abandon the state change and
    /// report `AlarmOpResult::AuditFailed` — audit is fail-closed, so no
    /// suppression or acknowledgement can take effect without a persisted
    /// record. The error string is surfaced to the caller and must therefore
    /// not leak sensitive backend details.
    fn record_alarm_action(&mut self, event: AlarmAuditEvent) -> Result<(), String>;
}
