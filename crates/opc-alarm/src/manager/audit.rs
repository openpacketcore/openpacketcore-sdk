use crate::manager::admin::{AlarmAction, AlarmActionContext, AlarmActionScope};
use crate::model::{Alarm, AlarmId, AlarmType, ProbableCause};
use time::OffsetDateTime;

/// Outcome recorded for an administrative alarm action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlarmAuditOutcome {
    Authorized,
    Denied,
}

/// Audit event emitted before a policy-protected alarm action is finalized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlarmAuditEvent {
    pub action: AlarmAction,
    pub outcome: AlarmAuditOutcome,
    pub alarm_id: AlarmId,
    pub alarm_type: AlarmType,
    pub probable_cause: ProbableCause,
    pub principal: String,
    pub tenant: Option<String>,
    pub reason: String,
    pub scope: AlarmActionScope,
    pub correlation_id: Option<String>,
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
            occurred_at: OffsetDateTime::now_utc(),
        }
    }
}

/// Audit hook for policy-protected alarm actions.
pub trait AlarmAuditSink {
    fn record_alarm_action(&mut self, event: AlarmAuditEvent) -> Result<(), String>;
}
