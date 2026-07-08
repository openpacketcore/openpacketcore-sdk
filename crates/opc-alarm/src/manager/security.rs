//! Authorization hooks for alarm admin actions (RFC 013 §10). Suppression
//! and acknowledgement must be authorized, and security-critical alarms
//! (critical severity or security/integrity causes) are non-suppressible
//! unless a policy explicitly opts in.

use crate::manager::admin::{AlarmAction, AlarmActionContext, AlarmActionDenied};
use crate::model::{Alarm, ProbableCause, Severity};

/// Policy hook for alarm acknowledgement and suppression.
pub trait AlarmActionAuthorizer {
    /// Decides whether `context` (principal, tenant, scope) may perform
    /// `action` on `alarm`. Implementations should verify the principal, that
    /// the asserted scope actually covers the target alarm, and tenant
    /// alignment. Returning `Err` yields `AlarmOpResult::Unauthorized` and an
    /// audited denial; the alarm state is left untouched.
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
                | ProbableCause::StorageCorruption
                | ProbableCause::AuditChainInvalid
                | ProbableCause::LiDeliveryFailed
                | ProbableCause::PrivacyPolicyViolation
                | ProbableCause::SecurityBreakGlass
        )
}
