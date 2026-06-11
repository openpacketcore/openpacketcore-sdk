use crate::manager::admin::{AlarmAction, AlarmActionContext, AlarmActionDenied};
use crate::model::{Alarm, ProbableCause, Severity};

/// Policy hook for alarm acknowledgement and suppression.
pub trait AlarmActionAuthorizer {
    fn authorize_alarm_action(
        &self,
        action: AlarmAction,
        alarm: &Alarm,
        context: &AlarmActionContext,
    ) -> Result<(), AlarmActionDenied>;

    /// Security-critical suppression is denied by default even after the normal
    /// action authorization check succeeds.
    fn allow_security_critical_suppression(
        &self,
        _alarm: &Alarm,
        _context: &AlarmActionContext,
    ) -> bool {
        false
    }
}

pub(crate) fn alarm_requires_explicit_suppression_policy(alarm: &Alarm) -> bool {
    alarm.severity == Severity::Critical
        || matches!(
            alarm.probable_cause,
            ProbableCause::AuthorizationPolicyInvalid
                | ProbableCause::IdentityUnavailable
                | ProbableCause::CertificateExpired
                | ProbableCause::KeyUnavailable
                | ProbableCause::AuditChainInvalid
                | ProbableCause::PrivacyPolicyViolation
        )
}
