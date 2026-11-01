//! Alarm bridging for commit and startup failures: maps stable error codes to
//! severities/probable causes, raises redacted management-plane alarms, and
//! clears them again once a later commit or validation succeeds.

use opc_alarm::{
    AffectedObject, Alarm, AlarmDetails, AlarmOpResult, AlarmType, ProbableCause, RedactedText,
    Severity, SharedAlarmManager,
};
use opc_config_model::{CommitError, CommitErrorCode, CommitResult, CommitStatus};

use crate::types::{StoreError, StoreErrorCode};

pub(crate) const CONFIG_BUS_ALARM_KIND: &str = "config-bus";
pub(crate) const CONFIG_BUS_ALARM_INSTANCE: &str = "global";
pub(crate) const CONFIG_BUS_COMMIT_FAILURE_ALARM_TYPE: &str = "config-bus.commit.failure";
pub(crate) const CONFIG_BUS_STARTUP_FAILURE_ALARM_TYPE: &str = "config-bus.startup.failure";
pub(crate) const VALIDATE_ONLY_RECOVERED_ERROR_CODES: &[&str] = &[
    "syntax_validation_failed",
    "semantic_validation_failed",
    "diff_failed",
];

pub(crate) fn config_bus_alarm_object() -> AffectedObject {
    AffectedObject::NfInstance {
        kind: CONFIG_BUS_ALARM_KIND.to_string(),
        instance: CONFIG_BUS_ALARM_INSTANCE.to_string(),
    }
}

pub(crate) fn raise_commit_error(alarm_manager: &SharedAlarmManager, error: &CommitError) {
    let (severity, probable_cause) = commit_error_alarm_spec(error.code);
    raise_config_error_alarm(
        alarm_manager,
        CONFIG_BUS_COMMIT_FAILURE_ALARM_TYPE,
        "commit",
        error.code.as_str(),
        severity,
        probable_cause,
    );
}

/// A coarse rollback failure must not discard positive data evidence. Absence
/// of that evidence never creates a corruption alarm.
pub(crate) fn raise_commit_store_error(
    alarm_manager: &SharedAlarmManager,
    error: &CommitError,
    store_code: StoreErrorCode,
) {
    let (severity, _) = commit_error_alarm_spec(error.code);
    raise_config_error_alarm(
        alarm_manager,
        CONFIG_BUS_COMMIT_FAILURE_ALARM_TYPE,
        "commit",
        error.code.as_str(),
        severity,
        store_failure_cause(store_code),
    );
}

pub(crate) fn store_failure_cause(code: StoreErrorCode) -> ProbableCause {
    match code {
        StoreErrorCode::Crypto
        | StoreErrorCode::RestoreSchemaMismatch
        | StoreErrorCode::InvalidHistorySequence => ProbableCause::StorageCorruption,
        _ => ProbableCause::ConfigApplyFailed,
    }
}

pub(crate) fn raise_startup_error(alarm_manager: &SharedAlarmManager, error: &StoreError) {
    let (severity, probable_cause) = startup_error_alarm_spec(error.code);
    raise_config_error_alarm(
        alarm_manager,
        CONFIG_BUS_STARTUP_FAILURE_ALARM_TYPE,
        "startup",
        error.code.as_str(),
        severity,
        probable_cause,
    );
}

pub(crate) fn preserve_startup_error(
    alarm_manager: &SharedAlarmManager,
    error: StoreError,
) -> StoreError {
    raise_startup_error(alarm_manager, &error);
    error.with_alarm_manager(alarm_manager)
}

pub(crate) fn apply_commit_alarm_outcome(
    alarm_manager: &SharedAlarmManager,
    result: &Result<CommitResult, CommitError>,
) {
    match result {
        Ok(result) if commit_result_clears_all_failure_alarms(result.status) => {
            clear_config_alarm_type(alarm_manager, CONFIG_BUS_COMMIT_FAILURE_ALARM_TYPE)
        }
        Ok(result) if commit_result_clears_validation_failure_alarm(result.status) => {
            clear_config_alarm_by_error_codes(
                alarm_manager,
                CONFIG_BUS_COMMIT_FAILURE_ALARM_TYPE,
                VALIDATE_ONLY_RECOVERED_ERROR_CODES,
            )
        }
        Ok(_) => {}
        Err(err) => raise_commit_error(alarm_manager, err),
    }
}

pub(crate) fn commit_error_alarm_spec(code: CommitErrorCode) -> (Severity, ProbableCause) {
    match code {
        CommitErrorCode::PersistFailed
        | CommitErrorCode::OutcomeUnknown
        | CommitErrorCode::RecoveryRequired
        | CommitErrorCode::RollbackUnavailable => {
            (Severity::Major, ProbableCause::ConfigApplyFailed)
        }
        CommitErrorCode::StateMachineFault => (Severity::Major, ProbableCause::ConfigApplyFailed),
        CommitErrorCode::VersionExhausted => (Severity::Major, ProbableCause::ConfigApplyFailed),
        CommitErrorCode::AdmissionRejected
        | CommitErrorCode::ApplyPlanRejected
        | CommitErrorCode::DeadlineExceeded
        | CommitErrorCode::MissingCandidate
        | CommitErrorCode::RollbackNotFound
        | CommitErrorCode::SyntaxValidationFailed
        | CommitErrorCode::SemanticValidationFailed
        | CommitErrorCode::DiffFailed
        | CommitErrorCode::AuthorizationDenied => {
            (Severity::Warning, ProbableCause::ConfigApplyFailed)
        }
    }
}

pub(crate) fn startup_error_alarm_spec(code: StoreErrorCode) -> (Severity, ProbableCause) {
    match code {
        // An unavailable dependency is not evidence of corrupt stored bytes.
        StoreErrorCode::Unavailable => (Severity::Critical, ProbableCause::ConfigApplyFailed),
        StoreErrorCode::Crypto
        | StoreErrorCode::RestoreSchemaMismatch
        | StoreErrorCode::InvalidHistorySequence => {
            (Severity::Critical, ProbableCause::StorageCorruption)
        }
        // Control-state fences, unknown outcomes and task failures do not
        // establish that any stored bytes were read and rejected.
        StoreErrorCode::OutcomeUnknown
        | StoreErrorCode::Internal
        | StoreErrorCode::RestoreRecoveryRequired
        | StoreErrorCode::RestoreConfirmedDeadline
        | StoreErrorCode::StartupValidationTaskFailed => {
            (Severity::Critical, ProbableCause::ConfigApplyFailed)
        }
        StoreErrorCode::NotFound => (Severity::Major, ProbableCause::ConfigApplyFailed),
        StoreErrorCode::StartupSyntaxValidationFailed
        | StoreErrorCode::StartupSemanticValidationFailed
        | StoreErrorCode::HistoryPageTooLarge
        | StoreErrorCode::HistoryCompacted
        | StoreErrorCode::HistoryCursorAhead => (Severity::Major, ProbableCause::ConfigApplyFailed),
    }
}

pub(crate) fn commit_result_clears_all_failure_alarms(status: CommitStatus) -> bool {
    matches!(
        status,
        CommitStatus::Committed | CommitStatus::RollbackApplied
    )
}

pub(crate) fn commit_result_clears_validation_failure_alarm(status: CommitStatus) -> bool {
    matches!(status, CommitStatus::Validated)
}

pub(crate) fn raise_config_error_alarm(
    alarm_manager: &SharedAlarmManager,
    alarm_type: &'static str,
    phase: &'static str,
    error_code: &'static str,
    severity: Severity,
    probable_cause: ProbableCause,
) {
    let result = alarm_manager.raise(
        AlarmType::new(alarm_type),
        severity,
        probable_cause,
        config_bus_alarm_object(),
        None,
        None,
        None,
        RedactedText::new(format!("Config bus {phase} failure: {error_code}")),
        AlarmDetails::with_value(serde_json::json!({
            "component": CONFIG_BUS_ALARM_KIND,
            "phase": phase,
            "error_code": error_code,
            "boundary": "management-plane"
        })),
    );

    if !matches!(
        result,
        AlarmOpResult::Raised { .. } | AlarmOpResult::Updated { .. }
    ) {
        tracing::warn!(phase, error_code, outcome = ?result, "config-bus alarm was not raised or updated");
    }
}

pub(crate) fn clear_config_alarm_type(
    alarm_manager: &SharedAlarmManager,
    alarm_type: &'static str,
) {
    clear_config_alarm_where(alarm_manager, alarm_type, |_| true);
}

pub(crate) fn clear_config_alarm_by_error_codes(
    alarm_manager: &SharedAlarmManager,
    alarm_type: &'static str,
    error_codes: &[&str],
) {
    clear_config_alarm_where(alarm_manager, alarm_type, |alarm| {
        alarm
            .details
            .as_value()
            .and_then(|details| details.get("error_code"))
            .and_then(serde_json::Value::as_str)
            .is_some_and(|code| error_codes.contains(&code))
    });
}

pub(crate) fn clear_config_alarm_where(
    alarm_manager: &SharedAlarmManager,
    alarm_type: &'static str,
    should_clear: impl Fn(&Alarm) -> bool,
) {
    let active = alarm_manager.active_alarms();
    for alarm in active
        .into_iter()
        .filter(|alarm| alarm.alarm_type.as_str() == alarm_type && should_clear(alarm))
    {
        let result = alarm_manager.clear(
            &alarm.alarm_type,
            alarm.probable_cause,
            &alarm.affected_object,
            alarm.tenant.as_deref(),
            alarm.slice.as_deref(),
            alarm.region.as_ref().map(|region| region.as_str()),
        );
        if !matches!(
            result,
            AlarmOpResult::Cleared { .. } | AlarmOpResult::ClearWithoutActive { .. }
        ) {
            tracing::warn!(alarm_type, outcome = ?result, "config-bus alarm clear returned unexpected result");
        }
    }
}

#[cfg(test)]
mod provider_failure_tests {
    use super::*;

    #[test]
    fn provider_configuration_startup_backpressure_is_not_storage_corruption() {
        assert_eq!(
            startup_error_alarm_spec(StoreErrorCode::Unavailable),
            (Severity::Critical, ProbableCause::ConfigApplyFailed)
        );
    }

    #[test]
    fn provider_configuration_commit_backpressure_is_not_storage_corruption() {
        // These coarse outcomes can all arise from an unusable key provider.
        // None alone proves that persisted bytes are corrupt.
        let observed = [
            CommitErrorCode::PersistFailed,
            CommitErrorCode::OutcomeUnknown,
            CommitErrorCode::RecoveryRequired,
            CommitErrorCode::RollbackUnavailable,
        ]
        .map(commit_error_alarm_spec);
        assert_eq!(
            observed,
            [(); 4].map(|_| (Severity::Major, ProbableCause::ConfigApplyFailed))
        );
    }
    #[test]
    fn coarse_startup_and_state_machine_failures_are_not_data_evidence() {
        for code in [
            StoreErrorCode::OutcomeUnknown,
            StoreErrorCode::Internal,
            StoreErrorCode::RestoreRecoveryRequired,
            StoreErrorCode::RestoreConfirmedDeadline,
            StoreErrorCode::StartupValidationTaskFailed,
            StoreErrorCode::NotFound,
        ] {
            assert_eq!(
                startup_error_alarm_spec(code).1,
                ProbableCause::ConfigApplyFailed,
                "{code:?}"
            );
        }
        assert_eq!(
            commit_error_alarm_spec(CommitErrorCode::StateMachineFault).1,
            ProbableCause::ConfigApplyFailed
        );
        for code in [
            StoreErrorCode::Crypto,
            StoreErrorCode::RestoreSchemaMismatch,
            StoreErrorCode::InvalidHistorySequence,
        ] {
            assert_eq!(
                startup_error_alarm_spec(code).1,
                ProbableCause::StorageCorruption
            );
        }
    }
}
