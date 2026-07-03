use crate::supervisor::metrics::raise_fatal_task_alarm;
use crate::supervisor::{FatalTaskFailure, Supervisor};
use crate::task::{Criticality, TaskError, TaskName};
use std::sync::atomic::Ordering;
use std::time::Duration;

const HEARTBEAT_MONITOR_MIN_INTERVAL: Duration = Duration::from_millis(10);
const HEARTBEAT_MONITOR_MAX_INTERVAL: Duration = Duration::from_secs(1);

pub(crate) async fn record_heartbeat_impl(supervisor: &Supervisor, name: &TaskName) {
    let mut t = supervisor.tasks.write().await;
    if let Some(state) = t.get_mut(name) {
        state.last_heartbeat = Some(supervisor.clock.monotonic());
        if state.is_failed {
            if let Some(ref last_err) = state.last_error {
                if last_err.to_string().contains("heartbeat timeout") {
                    state.is_failed = false;
                    if state.metadata.criticality == Criticality::Degrade {
                        supervisor.degrade_count.fetch_sub(1, Ordering::SeqCst);
                    }
                }
            }
        }
    }
}

pub(crate) async fn check_heartbeats_impl(supervisor: &Supervisor) {
    let now = supervisor.clock.monotonic();
    let mut expired = Vec::new();

    {
        let mut tasks = supervisor.tasks.write().await;
        for (name, s) in tasks.iter_mut() {
            if let Some(timeout) = s.metadata.heartbeat_timeout {
                if !s.is_failed && s.handle.as_ref().is_some_and(|h| h.is_running()) {
                    let last = s.last_heartbeat.unwrap_or(s.window_start);
                    if now.duration_since(last) > timeout {
                        tracing::error!(task = %name, "task hung detection: heartbeat timeout exceeded");
                        s.is_failed = true;
                        s.is_ready = false;
                        s.last_failure = Some(now);
                        let error = TaskError::Failed(
                            format!("heartbeat timeout of {timeout:?} exceeded"),
                            std::sync::Arc::new(std::io::Error::other(
                                "task stopped making progress",
                            )),
                        );
                        s.last_error = Some(error.clone());

                        // Abort/fence the hung task
                        if let Some(ref handle) = s.handle {
                            handle.abort();
                        }

                        expired.push((name.clone(), s.metadata.criticality, error));
                    }
                }
            }
        }
    }

    for (name, criticality, error) in &expired {
        match criticality {
            Criticality::Fatal => {
                let mut ff_write = supervisor.fatal_failure.write().await;
                *ff_write = true;
                let mut ff_err = supervisor.fatal_failure_error.write().await;
                *ff_err = Some(FatalTaskFailure {
                    task: name.clone(),
                    error: error.clone(),
                });
                raise_fatal_task_alarm(&supervisor.alarm_manager, &supervisor.profile, name, error);
                supervisor.shutdown.request_shutdown();
            }
            Criticality::Degrade => {
                supervisor.degrade_count.fetch_add(1, Ordering::SeqCst);
                raise_fatal_task_alarm(&supervisor.alarm_manager, &supervisor.profile, name, error);
            }
            Criticality::BestEffort => {}
        }
    }

    if !expired.is_empty() {
        supervisor.notify_state_change();
    }
}

pub(crate) async fn monitor_heartbeats_impl(supervisor: Supervisor) {
    let mut state_rx = supervisor.subscribe_state_changes();

    loop {
        if supervisor.shutdown.is_shutdown_requested() {
            return;
        }

        let interval = heartbeat_monitor_interval(&supervisor).await;
        tokio::select! {
            _ = supervisor.clock.sleep(interval) => {
                supervisor.check_heartbeats().await;
            }
            changed = state_rx.changed() => {
                if changed.is_err() {
                    return;
                }
            }
        }
    }
}

async fn heartbeat_monitor_interval(supervisor: &Supervisor) -> Duration {
    supervisor
        .tasks
        .read()
        .await
        .values()
        .filter_map(|state| state.metadata.heartbeat_timeout)
        .min()
        .map(|timeout| {
            timeout
                .checked_div(2)
                .unwrap_or(HEARTBEAT_MONITOR_MIN_INTERVAL)
                .clamp(
                    HEARTBEAT_MONITOR_MIN_INTERVAL,
                    HEARTBEAT_MONITOR_MAX_INTERVAL,
                )
        })
        .unwrap_or(HEARTBEAT_MONITOR_MAX_INTERVAL)
}
