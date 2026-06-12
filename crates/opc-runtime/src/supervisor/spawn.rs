use opc_alarm::{AffectedObject, AlarmDetails, AlarmType, ProbableCause, RedactedText, Severity};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use crate::metrics::METRICS;
use crate::profile::RuntimeMode;
use crate::shutdown::ShutdownToken;
use crate::supervisor::metrics::runtime_task_failure_object;
use crate::supervisor::{Supervisor, SupervisorRuntimeCtx, TaskMetadata, TaskState};
use crate::task::{
    Criticality, RestartPolicy, RuntimeError, TaskError, TaskHandle, TaskKind, TaskName, TaskSpec,
};

pub(crate) fn check_budget_limits_impl(
    supervisor: &Supervisor,
    tasks_count: usize,
) -> Result<(), RuntimeError> {
    let max_tasks = supervisor
        .profile
        .budget
        .as_ref()
        .map(|b| b.max_tasks)
        .unwrap_or(supervisor.profile.max_tasks);
    if tasks_count >= max_tasks {
        METRICS
            .runtime_budget_exhausted
            .fetch_add(1, Ordering::Relaxed);
        let alarm_type = AlarmType::new(format!(
            "{}.runtime.budget.exhausted",
            supervisor.profile.nf_kind
        ));
        let _ = supervisor.alarm_manager.raise(
            alarm_type,
            Severity::Major,
            ProbableCause::Other("opc-runtime.budget-exceeded".to_string()),
            AffectedObject::NfInstance {
                kind: supervisor.profile.nf_kind.clone(),
                instance: supervisor.profile.instance_id.to_string(),
            },
            None,
            None,
            None,
            RedactedText::new("Resource budget limit exceeded: max tasks limit reached"),
            AlarmDetails::with_value(serde_json::json!({
                "nf_kind": supervisor.profile.nf_kind.as_str(),
                "nf_instance": supervisor.profile.instance_id.to_string(),
                "budget_limit": "max_tasks",
                "limit_value": max_tasks,
                "boundary": "control-plane"
            })),
        );
        return Err(RuntimeError::Supervisor(format!(
            "Resource budget limit exceeded: max tasks limit reached (limit {max_tasks})"
        )));
    }

    if let Some(ref budget) = supervisor.profile.budget {
        if let Some(max_heap) = budget.max_heap_bytes {
            if supervisor.memory_limiter.usage() >= max_heap {
                METRICS
                    .runtime_budget_exhausted
                    .fetch_add(1, Ordering::Relaxed);
                let alarm_type = AlarmType::new(format!(
                    "{}.runtime.budget.exhausted",
                    supervisor.profile.nf_kind
                ));
                let _ = supervisor.alarm_manager.raise(
                    alarm_type,
                    Severity::Critical,
                    ProbableCause::Other("opc-runtime.memory-budget-exceeded".to_string()),
                    AffectedObject::NfInstance {
                        kind: supervisor.profile.nf_kind.clone(),
                        instance: supervisor.profile.instance_id.to_string(),
                    },
                    None,
                    None,
                    None,
                    RedactedText::new(
                        "Resource budget limit exceeded: memory budget pressure detected",
                    ),
                    AlarmDetails::with_value(serde_json::json!({
                        "nf_kind": supervisor.profile.nf_kind.as_str(),
                        "nf_instance": supervisor.profile.instance_id.to_string(),
                        "budget_limit": "max_heap_bytes",
                        "limit_value": max_heap,
                        "current_usage": supervisor.memory_limiter.usage(),
                        "boundary": "control-plane"
                    })),
                );
                return Err(RuntimeError::Supervisor(format!(
                    "Resource budget limit exceeded: memory pressure (limit {max_heap} bytes)"
                )));
            }
        }
    }
    Ok(())
}

pub(crate) async fn update_budget_alarms_impl(supervisor: &Supervisor, tasks_len: usize) {
    let alarm_type = AlarmType::new(format!(
        "{}.runtime.budget.exhausted",
        supervisor.profile.nf_kind
    ));

    let mut has_mem_pressure = false;
    let mut max_heap = 0;
    if let Some(ref budget) = supervisor.profile.budget {
        if let Some(heap) = budget.max_heap_bytes {
            max_heap = heap;
            if supervisor.memory_limiter.usage() >= heap {
                has_mem_pressure = true;
            }
        }
    }

    if has_mem_pressure {
        let _ = supervisor.alarm_manager.raise(
            alarm_type.clone(),
            Severity::Critical,
            ProbableCause::Other("opc-runtime.memory-budget-exceeded".to_string()),
            AffectedObject::NfInstance {
                kind: supervisor.profile.nf_kind.clone(),
                instance: supervisor.profile.instance_id.to_string(),
            },
            None,
            None,
            None,
            RedactedText::new("Resource budget limit exceeded: memory budget pressure detected"),
            AlarmDetails::with_value(serde_json::json!({
                "nf_kind": supervisor.profile.nf_kind.as_str(),
                "nf_instance": supervisor.profile.instance_id.to_string(),
                "budget_limit": "max_heap_bytes",
                "limit_value": max_heap,
                "current_usage": supervisor.memory_limiter.usage(),
                "boundary": "control-plane"
            })),
        );
    } else {
        let _ = supervisor.alarm_manager.clear(
            &alarm_type,
            ProbableCause::Other("opc-runtime.memory-budget-exceeded".to_string()),
            &runtime_task_failure_object(&supervisor.profile),
            None,
            None,
            None,
        );
    }

    let max_tasks = supervisor
        .profile
        .budget
        .as_ref()
        .map(|b| b.max_tasks)
        .unwrap_or(supervisor.profile.max_tasks);
    if tasks_len < max_tasks {
        let _ = supervisor.alarm_manager.clear(
            &alarm_type,
            ProbableCause::Other("opc-runtime.budget-exceeded".to_string()),
            &runtime_task_failure_object(&supervisor.profile),
            None,
            None,
            None,
        );
    }
}

pub(crate) async fn register_impl(
    supervisor: &Supervisor,
    name: TaskName,
    kind: TaskKind,
    criticality: Criticality,
    restart: RestartPolicy,
) -> Result<(), RuntimeError> {
    let mut tasks = supervisor.tasks.write().await;
    if tasks.contains_key(&name) {
        return Err(RuntimeError::Supervisor(format!(
            "task {name} already registered"
        )));
    }

    supervisor.check_budget_limits(tasks.len())?;

    if supervisor.profile.mode == RuntimeMode::Production {
        restart.validate()?;
    }

    // Insert the task into the registry
    tasks.insert(
        name.clone(),
        TaskState {
            metadata: TaskMetadata {
                kind,
                criticality,
                restart,
                readiness_gated: false,
                heartbeat_timeout: None,
            },
            handle: None,
            failures_in_window: 0,
            window_start: supervisor.clock.monotonic(),
            last_failure: None,
            last_error: None,
            is_failed: false,
            is_ready: false,
            readiness_gated: false,
            shutdown: ShutdownToken::new(),
            last_heartbeat: Some(supervisor.clock.monotonic()),
        },
    );

    tracing::debug!(
        task = %name,
        kind = %kind,
        criticality = %criticality,
        "task registered with supervisor"
    );

    supervisor.notify_state_change();

    Ok(())
}

pub(crate) async fn register_spec_impl(
    supervisor: &Supervisor,
    spec: TaskSpec,
) -> Result<(), RuntimeError> {
    let mut tasks = supervisor.tasks.write().await;
    let name = spec.name;
    if tasks.contains_key(&name) {
        return Err(RuntimeError::Supervisor(format!(
            "task {name} already registered"
        )));
    }

    supervisor.check_budget_limits(tasks.len())?;

    if supervisor.profile.mode == RuntimeMode::Production {
        spec.restart.validate()?;
    }

    tasks.insert(
        name.clone(),
        TaskState {
            metadata: TaskMetadata {
                kind: spec.kind,
                criticality: spec.criticality,
                restart: spec.restart,
                readiness_gated: false,
                heartbeat_timeout: spec.heartbeat_timeout,
            },
            handle: None,
            failures_in_window: 0,
            window_start: supervisor.clock.monotonic(),
            last_failure: None,
            last_error: None,
            is_failed: false,
            is_ready: false,
            readiness_gated: false,
            shutdown: ShutdownToken::new(),
            last_heartbeat: Some(supervisor.clock.monotonic()),
        },
    );

    tracing::debug!(
        task = %name,
        kind = %spec.kind,
        criticality = %spec.criticality,
        "task registered with supervisor"
    );

    supervisor.notify_state_change();

    Ok(())
}

pub(crate) async fn spawn_impl(
    supervisor: &Supervisor,
    name: TaskName,
    kind: TaskKind,
    criticality: Criticality,
    restart: RestartPolicy,
    task_fn: impl Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), TaskError>> + Send>>
        + Send
        + 'static,
) -> Result<TaskHandle, RuntimeError> {
    supervisor
        .spawn_internal(name, kind, criticality, restart, None, task_fn)
        .await
}

pub(crate) async fn spawn_spec_impl(
    supervisor: &Supervisor,
    spec: TaskSpec,
) -> Result<TaskHandle, RuntimeError> {
    if spec.restart.max_restarts > 0 {
        return Err(RuntimeError::Supervisor(
            "TaskSpec owns a single future; use Supervisor::spawn for restartable tasks"
                .to_string(),
        ));
    }

    let name = spec.name.clone();
    let kind = spec.kind;
    let criticality = spec.criticality;
    let restart = spec.restart;
    let heartbeat_timeout = spec.heartbeat_timeout;

    let task_fn_cell = std::sync::Mutex::new(Some(spec.task_fn));
    supervisor
        .spawn_internal(
            name,
            kind,
            criticality,
            restart,
            heartbeat_timeout,
            move || {
                let mut lock = task_fn_cell.lock().unwrap();
                if let Some(fut) = lock.take() {
                    fut
                } else {
                    Box::pin(async {
                        Err(TaskError::Failed(
                            "task future already consumed".to_string(),
                            std::sync::Arc::new(std::io::Error::other("consumed")),
                        ))
                    })
                }
            },
        )
        .await
}

pub(crate) async fn spawn_internal_impl(
    supervisor: &Supervisor,
    name: TaskName,
    kind: TaskKind,
    criticality: Criticality,
    restart: RestartPolicy,
    heartbeat_timeout: Option<Duration>,
    task_fn: impl Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), TaskError>> + Send>>
        + Send
        + 'static,
) -> Result<TaskHandle, RuntimeError> {
    let tasks = supervisor.tasks.clone();
    let ctx = supervisor.runtime_ctx();

    let name_for_spawn = name.clone();
    let tasks_for_spawn = tasks.clone();

    let metadata = {
        let mut t = tasks.write().await;
        if let Some(existing) = t.get(&name) {
            if let Some(ref handle) = existing.handle {
                if handle.is_running() {
                    return Err(RuntimeError::Supervisor(format!(
                        "task {name} already running"
                    )));
                }
            }
            tracing::debug!(task = %name, "spawn reusing registered metadata");
            existing.metadata.clone()
        } else {
            supervisor.check_budget_limits(t.len())?;

            if supervisor.profile.mode == RuntimeMode::Production {
                restart.validate()?;
            }

            let meta = TaskMetadata {
                kind,
                criticality,
                restart,
                readiness_gated: false,
                heartbeat_timeout,
            };
            t.insert(
                name.clone(),
                TaskState {
                    metadata: meta.clone(),
                    handle: None,
                    failures_in_window: 0,
                    window_start: supervisor.clock.monotonic(),
                    last_failure: None,
                    last_error: None,
                    is_failed: false,
                    is_ready: false,
                    readiness_gated: false,
                    shutdown: ShutdownToken::new(),
                    last_heartbeat: Some(supervisor.clock.monotonic()),
                },
            );
            meta
        }
    };

    let notify = Arc::new(tokio::sync::Notify::new());
    let notify_for_spawn = notify.clone();
    let (exit_tx, exit_rx) = tokio::sync::watch::channel(false);

    let handle = tokio::spawn(Supervisor::run_supervised_task(
        name_for_spawn.clone(),
        metadata.clone(),
        task_fn,
        SupervisorRuntimeCtx {
            tasks: tasks_for_spawn.clone(),
            ..ctx
        },
        notify_for_spawn,
        exit_tx,
    ));

    let abort_handle = handle.abort_handle();
    let task_handle = TaskHandle::new(name.clone(), abort_handle, exit_rx);

    {
        let mut t = tasks.write().await;
        if let Some(state) = t.get_mut(&name) {
            state.handle = Some(task_handle.clone());
        }
    }

    supervisor.notify_state_change();

    Ok(task_handle)
}
