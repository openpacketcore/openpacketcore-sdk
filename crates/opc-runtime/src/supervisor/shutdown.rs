use crate::supervisor::metrics::raise_drain_incomplete_alarm;
use crate::supervisor::Supervisor;
use crate::task::{ShutdownPolicy, TaskHandle, TaskName};
use futures_util::future::join_all;

pub(crate) async fn shutdown_all_impl(supervisor: &Supervisor, policy: ShutdownPolicy) {
    if !matches!(policy, ShutdownPolicy::Immediate) {
        supervisor.shutdown.request_shutdown();
        let tasks = supervisor.tasks.read().await;
        for state in tasks.values() {
            state.shutdown.request_shutdown();
        }
    }
    let names: Vec<TaskName> = supervisor.tasks.read().await.keys().cloned().collect();

    // For Drain policy, apply a shared deadline so N tasks don't multiply wait time
    let effective_policy = if matches!(policy, ShutdownPolicy::Drain) {
        ShutdownPolicy::DrainWithTimeout(supervisor.profile.drain_timeout)
    } else {
        policy
    };

    // Drain all tasks concurrently
    let futures: Vec<_> = names
        .iter()
        .map(|name| supervisor.shutdown_task(name, effective_policy))
        .collect();

    join_all(futures).await;
}

pub(crate) async fn shutdown_task_impl(
    supervisor: &Supervisor,
    name: &TaskName,
    policy: ShutdownPolicy,
) {
    // Clone handle and shutdown token while holding the lock, then drop the lock
    let (handle, task_shutdown) = {
        let t = supervisor.tasks.read().await;
        t.get(name).map(|s| (s.handle.clone(), s.shutdown.clone()))
    }
    .unzip();

    let handle = handle.flatten();

    if let (Some(handle), Some(task_shutdown)) = (handle, task_shutdown) {
        match policy {
            ShutdownPolicy::Immediate => {
                handle.abort();
                supervisor.wait_for_task(&handle).await;
            }
            ShutdownPolicy::Drain => {
                task_shutdown.request_shutdown();
                let timeout = supervisor.profile.drain_timeout;
                tokio::select! {
                    biased;
                    _ = supervisor.wait_for_task(&handle) => {} // Task exited cleanly
                    _ = supervisor.clock.sleep(timeout) => {
                        // Timeout exceeded — force abort
                        tracing::warn!(task = %name, "task did not drain gracefully within timeout, aborting");
                        raise_drain_incomplete_alarm(
                            &supervisor.alarm_manager,
                            &supervisor.profile,
                            &format!("task {name} did not drain gracefully within timeout"),
                        );
                        handle.abort();
                        supervisor.wait_for_task(&handle).await;
                    }
                }
            }
            ShutdownPolicy::DrainWithTimeout(timeout) => {
                task_shutdown.request_shutdown();
                tokio::select! {
                    biased;
                    _ = supervisor.wait_for_task(&handle) => {} // Task exited cleanly
                    _ = supervisor.clock.sleep(timeout) => {
                        tracing::warn!(task = %name, "task drain timeout exceeded, aborting");
                        raise_drain_incomplete_alarm(
                            &supervisor.alarm_manager,
                            &supervisor.profile,
                            &format!("task {name} drain timeout exceeded"),
                        );
                        handle.abort();
                        supervisor.wait_for_task(&handle).await;
                    }
                }
            }
        }
    }
}

pub(crate) async fn wait_for_task_impl(_supervisor: &Supervisor, handle: &TaskHandle) {
    let mut rx = handle.exit_rx.clone();
    while !*rx.borrow() && handle.is_running() {
        if rx.changed().await.is_err() {
            break;
        }
    }
}
