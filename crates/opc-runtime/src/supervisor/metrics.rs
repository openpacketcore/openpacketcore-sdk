use crate::profile::RuntimeProfile;
use crate::task::{TaskError, TaskName};
use opc_alarm::{
    AffectedObject, AlarmDetails, AlarmOpResult, AlarmType, ProbableCause, RedactedText, Severity,
    SharedAlarmManager,
};

pub(crate) fn runtime_task_failure_alarm_type_base(profile: &RuntimeProfile) -> String {
    format!("{}.runtime.task.failure", profile.nf_kind)
}

pub(crate) fn runtime_task_failure_alarm_type(
    profile: &RuntimeProfile,
    task: &TaskName,
) -> AlarmType {
    AlarmType::new(format!(
        "{}.{}",
        runtime_task_failure_alarm_type_base(profile),
        task
    ))
}

pub(crate) fn runtime_task_failure_probable_cause() -> ProbableCause {
    ProbableCause::Other("opc-runtime.task-failure".to_string())
}

pub(crate) fn runtime_task_failure_object(profile: &RuntimeProfile) -> AffectedObject {
    AffectedObject::NfInstance {
        kind: profile.nf_kind.clone(),
        instance: profile.instance_id.to_string(),
    }
}

pub(crate) fn raise_fatal_task_alarm(
    alarm_manager: &SharedAlarmManager,
    profile: &RuntimeProfile,
    task: &TaskName,
    error: &TaskError,
) {
    let failure_class = match error {
        TaskError::Failed(_, _) => "failed",
        TaskError::Aborted(_) => "aborted",
        TaskError::Panicked(_, _) => "panicked",
    };

    let result = alarm_manager.raise(
        runtime_task_failure_alarm_type(profile, task),
        Severity::Critical,
        runtime_task_failure_probable_cause(),
        runtime_task_failure_object(profile),
        None,
        None,
        None,
        RedactedText::new(format!(
            "Fatal runtime task failure in supervised task {task}"
        )),
        AlarmDetails::with_value(serde_json::json!({
            "nf_kind": profile.nf_kind.as_str(),
            "nf_instance": profile.instance_id.to_string(),
            "runtime_task": task.to_string(),
            "failure_class": failure_class,
            "boundary": "control-plane"
        })),
    );

    if !matches!(
        result,
        AlarmOpResult::Raised { .. } | AlarmOpResult::Updated { .. }
    ) {
        tracing::warn!(task = %task, outcome = ?result, "fatal task alarm was not raised or updated");
    }
}

pub(crate) fn raise_drain_incomplete_alarm(
    alarm_manager: &SharedAlarmManager,
    profile: &RuntimeProfile,
    reason: &str,
) {
    let alarm_type = AlarmType::new(format!("{}.runtime.drain.incomplete", profile.nf_kind));

    let result = alarm_manager.raise(
        alarm_type,
        Severity::Major,
        ProbableCause::Other("opc-runtime.drain-incomplete".to_string()),
        AffectedObject::NfInstance {
            kind: profile.nf_kind.clone(),
            instance: profile.instance_id.to_string(),
        },
        None,
        None,
        None,
        RedactedText::new(format!("Runtime drain incomplete: {reason}")),
        AlarmDetails::with_value(serde_json::json!({
            "nf_kind": profile.nf_kind.as_str(),
            "nf_instance": profile.instance_id.to_string(),
            "reason": reason,
            "boundary": "control-plane"
        })),
    );

    if !matches!(
        result,
        AlarmOpResult::Raised { .. } | AlarmOpResult::Updated { .. }
    ) {
        tracing::warn!(outcome = ?result, "drain incomplete alarm was not raised or updated");
    }
}

pub(crate) fn clear_runtime_task_failure_alarms(
    alarm_manager: &SharedAlarmManager,
    profile: &RuntimeProfile,
) {
    let alarm_type_base = runtime_task_failure_alarm_type_base(profile);
    let alarm_type_prefix = format!("{alarm_type_base}.");
    let affected_object = runtime_task_failure_object(profile);
    let active = alarm_manager.active_alarms();

    for alarm in active.into_iter().filter(|alarm| {
        // Keep the bare base match so startup readiness can clear legacy
        // instance-scoped task-failure alarms raised before task-scoped types.
        (alarm.alarm_type.as_str() == alarm_type_base.as_str()
            || alarm.alarm_type.as_str().starts_with(&alarm_type_prefix))
            && alarm.probable_cause == runtime_task_failure_probable_cause()
            && alarm.affected_object == affected_object
    }) {
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
            tracing::warn!(outcome = ?result, "runtime task-failure alarm clear returned unexpected result");
        }
    }
}
