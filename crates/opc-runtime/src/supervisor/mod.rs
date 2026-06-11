use futures_util::FutureExt;
use opc_alarm::SharedAlarmManager;
use std::collections::hash_map::RandomState;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{watch, RwLock};

use crate::health::Readiness;
use crate::profile::RuntimeProfile;
use crate::shutdown::ShutdownToken;
use crate::task::{
    Criticality, RestartPolicy, RuntimeError, ShutdownPolicy, TaskError, TaskHandle, TaskKind,
    TaskName, TaskSpec,
};
use crate::testkit::{Clock, RealClock};

pub(crate) mod heartbeat;
pub(crate) mod metrics;
pub(crate) mod restart;
pub(crate) mod shutdown;
pub(crate) mod spawn;
pub(crate) mod task;

#[cfg(test)]
pub(crate) mod tests;

pub(crate) use metrics::raise_drain_incomplete_alarm;
pub use task::TaskStateView;
pub(crate) use task::{TaskMetadata, TaskState};

#[derive(Debug, Clone)]
pub(crate) struct FatalTaskFailure {
    pub(crate) task: TaskName,
    pub(crate) error: TaskError,
}

/// Simulated memory manager for fault injection.
#[derive(Debug, Clone, Default)]
pub struct MemoryLimiter {
    simulated_usage: Arc<std::sync::atomic::AtomicUsize>,
}

impl MemoryLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_usage(&self, bytes: usize) {
        self.simulated_usage
            .store(bytes, std::sync::atomic::Ordering::SeqCst);
    }

    pub fn usage(&self) -> usize {
        self.simulated_usage
            .load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[derive(Clone)]
pub(crate) struct SupervisorRuntimeCtx {
    pub(crate) profile: RuntimeProfile,
    pub(crate) tasks: Arc<RwLock<HashMap<TaskName, TaskState>>>,
    pub(crate) fatal_failure: Arc<RwLock<bool>>,
    pub(crate) fatal_failure_error: Arc<RwLock<Option<FatalTaskFailure>>>,
    pub(crate) degrade_count: Arc<AtomicU32>,
    pub(crate) shutdown: ShutdownToken,
    pub(crate) jitter_source: RandomState,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) state_tx: watch::Sender<()>,
    pub(crate) alarm_manager: SharedAlarmManager,
}

/// Supervisor for all long-lived CNF tasks.
pub struct Supervisor {
    pub(crate) profile: RuntimeProfile,
    pub(crate) shutdown: ShutdownToken,
    pub(crate) tasks: Arc<RwLock<HashMap<TaskName, TaskState>>>,
    pub(crate) fatal_failure: Arc<RwLock<bool>>,
    pub(crate) fatal_failure_error: Arc<RwLock<Option<FatalTaskFailure>>>,
    pub(crate) degrade_count: Arc<AtomicU32>,
    pub(crate) jitter_source: RandomState,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) state_tx: watch::Sender<()>,
    pub(crate) alarm_manager: SharedAlarmManager,
    pub(crate) memory_limiter: MemoryLimiter,
}

impl std::fmt::Debug for Supervisor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Supervisor")
            .field("profile", &self.profile)
            .finish()
    }
}

impl Clone for Supervisor {
    fn clone(&self) -> Self {
        Self {
            profile: self.profile.clone(),
            shutdown: self.shutdown.clone(),
            tasks: self.tasks.clone(),
            fatal_failure: self.fatal_failure.clone(),
            fatal_failure_error: self.fatal_failure_error.clone(),
            degrade_count: self.degrade_count.clone(),
            jitter_source: self.jitter_source.clone(),
            clock: self.clock.clone(),
            state_tx: self.state_tx.clone(),
            alarm_manager: self.alarm_manager.clone(),
            memory_limiter: self.memory_limiter.clone(),
        }
    }
}

/// Aggregated health of supervised tasks.
#[derive(Debug, Clone, Default)]
pub struct SupervisorHealth {
    /// True if any fatal task has failed.
    pub fatal_failure: bool,
    /// True if any degrade task has failed.
    pub degraded: bool,
    /// Count of degrade-level failures.
    pub degrade_count: u32,
    /// Task states for observability.
    pub task_states: HashMap<String, TaskStateView>,
}

pub(crate) struct NotifyOnDrop(pub(crate) Arc<tokio::sync::Notify>);
impl Drop for NotifyOnDrop {
    fn drop(&mut self) {
        self.0.notify_one();
    }
}

/// Exit guard for propagating exit status.
pub(crate) struct ExitSignalGuard(pub(crate) tokio::sync::watch::Sender<bool>);
impl Drop for ExitSignalGuard {
    fn drop(&mut self) {
        let _ = self.0.send(true);
    }
}

impl Supervisor {
    /// Create a new supervisor.
    pub fn new(profile: RuntimeProfile, shutdown: ShutdownToken) -> Self {
        Self::new_with_clock(profile, shutdown, Arc::new(RealClock))
    }

    /// Create a new supervisor with an explicit clock implementation.
    pub fn new_with_clock(
        profile: RuntimeProfile,
        shutdown: ShutdownToken,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self::new_with_clock_and_alarm_manager(
            profile,
            shutdown,
            clock,
            SharedAlarmManager::default(),
        )
    }

    /// Create a new supervisor with an explicit clock and shared alarm manager.
    pub fn new_with_clock_and_alarm_manager(
        profile: RuntimeProfile,
        shutdown: ShutdownToken,
        clock: Arc<dyn Clock>,
        alarm_manager: SharedAlarmManager,
    ) -> Self {
        let (state_tx, _) = watch::channel(());
        Self {
            profile,
            shutdown,
            tasks: Arc::new(RwLock::new(HashMap::new())),
            fatal_failure: Arc::new(RwLock::new(false)),
            fatal_failure_error: Arc::new(RwLock::new(None)),
            degrade_count: Arc::new(AtomicU32::new(0)),
            jitter_source: RandomState::new(),
            clock,
            state_tx,
            alarm_manager,
            memory_limiter: MemoryLimiter::new(),
        }
    }

    /// Create a supervisor that publishes fatal runtime alarms into a shared manager.
    pub fn new_with_alarm_manager(
        profile: RuntimeProfile,
        shutdown: ShutdownToken,
        alarm_manager: SharedAlarmManager,
    ) -> Self {
        Self::new_with_clock_and_alarm_manager(
            profile,
            shutdown,
            Arc::new(RealClock),
            alarm_manager,
        )
    }

    /// Access the simulated memory limiter for fault injection.
    pub fn memory_limiter(&self) -> &MemoryLimiter {
        &self.memory_limiter
    }

    pub(crate) fn runtime_ctx(&self) -> SupervisorRuntimeCtx {
        SupervisorRuntimeCtx {
            profile: self.profile.clone(),
            tasks: self.tasks.clone(),
            fatal_failure: self.fatal_failure.clone(),
            fatal_failure_error: self.fatal_failure_error.clone(),
            degrade_count: self.degrade_count.clone(),
            shutdown: self.shutdown.clone(),
            jitter_source: self.jitter_source.clone(),
            clock: self.clock.clone(),
            state_tx: self.state_tx.clone(),
            alarm_manager: self.alarm_manager.clone(),
        }
    }

    /// Get the clock instance used by this supervisor.
    pub fn clock(&self) -> Arc<dyn Clock> {
        self.clock.clone()
    }

    /// Check resource budget limits before registering/spawning a task.
    pub(crate) fn check_budget_limits(&self, tasks_count: usize) -> Result<(), RuntimeError> {
        spawn::check_budget_limits_impl(self, tasks_count)
    }

    /// Update budget alarms based on current state.
    pub(crate) async fn update_budget_alarms(&self, tasks_len: usize) {
        spawn::update_budget_alarms_impl(self, tasks_len).await;
    }

    /// Register a task's metadata with the supervisor.
    pub async fn register(
        &self,
        name: TaskName,
        kind: TaskKind,
        criticality: Criticality,
        restart: RestartPolicy,
    ) -> Result<(), RuntimeError> {
        spawn::register_impl(self, name, kind, criticality, restart).await
    }

    /// Register a task's spec directly.
    pub async fn register_spec(&self, spec: TaskSpec) -> Result<(), RuntimeError> {
        spawn::register_spec_impl(self, spec).await
    }

    /// Spawn and supervise a single task with restart policy.
    pub async fn spawn(
        &self,
        name: TaskName,
        kind: TaskKind,
        criticality: Criticality,
        restart: RestartPolicy,
        task_fn: impl Fn()
                -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), TaskError>> + Send>>
            + Send
            + 'static,
    ) -> Result<TaskHandle, RuntimeError> {
        spawn::spawn_impl(self, name, kind, criticality, restart, task_fn).await
    }

    /// Spawn a task with a spec.
    pub async fn spawn_spec(&self, spec: TaskSpec) -> Result<TaskHandle, RuntimeError> {
        spawn::spawn_spec_impl(self, spec).await
    }

    pub(crate) async fn spawn_internal(
        &self,
        name: TaskName,
        kind: TaskKind,
        criticality: Criticality,
        restart: RestartPolicy,
        heartbeat_timeout: Option<Duration>,
        task_fn: impl Fn()
                -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), TaskError>> + Send>>
            + Send
            + 'static,
    ) -> Result<TaskHandle, RuntimeError> {
        spawn::spawn_internal_impl(
            self,
            name,
            kind,
            criticality,
            restart,
            heartbeat_timeout,
            task_fn,
        )
        .await
    }

    /// Record a heartbeat for a task to prove it is still making progress.
    pub async fn record_heartbeat(&self, name: &TaskName) {
        heartbeat::record_heartbeat_impl(self, name).await;
    }

    /// Check for heartbeat timeout expiration on all supervised tasks.
    pub(crate) async fn check_heartbeats(&self) {
        heartbeat::check_heartbeats_impl(self).await;
    }

    /// Get aggregated readiness for health probes.
    pub async fn readiness(&self) -> Readiness {
        self.check_heartbeats().await;

        let ff = *self.fatal_failure.read().await;
        if ff {
            return Readiness::NotReady;
        }

        let tasks = self.tasks.read().await;
        self.update_budget_alarms(tasks.len()).await;

        // If memory pressure is currently active, readiness must be NotReady
        if let Some(ref budget) = self.profile.budget {
            if let Some(max_heap) = budget.max_heap_bytes {
                if self.memory_limiter.usage() >= max_heap {
                    return Readiness::NotReady;
                }
            }
        }

        // Empty supervisor (no tasks registered) is not ready
        if tasks.is_empty() {
            return Readiness::NotReady;
        }

        // Check if all non-best-effort tasks are healthy (either running and ready or completed cleanly if draining)
        let all_healthy = tasks.values().all(|s| {
            if s.metadata.criticality == Criticality::BestEffort {
                true
            } else {
                let is_running = s.handle.as_ref().is_some_and(|h| h.is_running());
                if self.shutdown.is_shutdown_requested() {
                    (is_running && s.is_ready) || !s.is_failed
                } else {
                    is_running && s.is_ready
                }
            }
        });

        // Check if any Degrade task is currently failed/not running
        let any_degrade_failed = tasks
            .values()
            .any(|s| s.metadata.criticality == Criticality::Degrade && s.is_failed);

        if all_healthy && !any_degrade_failed {
            Readiness::Ready
        } else if any_degrade_failed {
            Readiness::Degraded
        } else {
            Readiness::NotReady
        }
    }

    /// Get supervisor health snapshot.
    pub async fn health(&self) -> SupervisorHealth {
        let ff = *self.fatal_failure.read().await;
        let tasks = self.tasks.read().await;
        let d = tasks
            .values()
            .any(|s| s.metadata.criticality == Criticality::Degrade && s.is_failed);
        let degrade_count = self.degrade_count.load(Ordering::SeqCst);

        SupervisorHealth {
            fatal_failure: ff,
            degraded: d,
            degrade_count,
            task_states: tasks
                .iter()
                .map(|(name, state)| {
                    (
                        name.to_string(),
                        TaskStateView {
                            kind: state.metadata.kind.to_string(),
                            criticality: state.metadata.criticality.to_string(),
                            running: state.handle.as_ref().is_some_and(|h| h.is_running()),
                            restart_count: state.failures_in_window,
                        },
                    )
                })
                .collect(),
        }
    }

    /// Stop all supervised tasks gracefully.
    pub async fn shutdown_all(&self, policy: ShutdownPolicy) {
        shutdown::shutdown_all_impl(self, policy).await;
    }

    /// Shutdown a specific task.
    pub async fn shutdown_task(&self, name: &TaskName, policy: ShutdownPolicy) {
        shutdown::shutdown_task_impl(self, name, policy).await;
    }

    /// Wait for a task to finish (future that completes when the task exits).
    pub(crate) async fn wait_for_task(&self, handle: &TaskHandle) {
        shutdown::wait_for_task_impl(self, handle).await;
    }

    /// Mark a task as readiness-gated. Gated tasks must explicitly call `set_task_ready`
    /// to be considered healthy/ready. Non-gated tasks are ready as soon as their future starts running.
    pub async fn set_readiness_gated(&self, name: &TaskName, gated: bool) {
        let mut t = self.tasks.write().await;
        if let Some(state) = t.get_mut(name) {
            state.readiness_gated = gated;
            state.metadata.readiness_gated = gated;
        }
        self.notify_state_change();
    }

    /// Mark a task as ready/serving.
    pub async fn set_task_ready(&self, name: &TaskName, ready: bool) {
        let mut t = self.tasks.write().await;
        if let Some(state) = t.get_mut(name) {
            if ready && state.is_failed {
                state.is_failed = false;
                if state.metadata.criticality == Criticality::Degrade {
                    self.degrade_count.fetch_sub(1, Ordering::SeqCst);
                }
            }
            state.is_ready = ready;
        }
        self.notify_state_change();
    }

    pub(crate) fn subscribe_state_changes(&self) -> watch::Receiver<()> {
        self.state_tx.subscribe()
    }

    pub async fn fatal_task_failure(&self) -> Option<(TaskName, TaskError)> {
        self.fatal_failure_error
            .read()
            .await
            .clone()
            .map(|fatal| (fatal.task, fatal.error))
    }

    /// Access the task-local shutdown token.
    pub async fn task_shutdown_token(&self, name: &TaskName) -> Option<ShutdownToken> {
        let t = self.tasks.read().await;
        t.get(name).map(|s| s.shutdown.clone())
    }

    /// Shared alarm manager used by this supervisor.
    pub fn alarm_manager(&self) -> SharedAlarmManager {
        self.alarm_manager.clone()
    }

    /// Clears active runtime task-failure alarms for this CNF instance.
    pub fn clear_runtime_task_failure_alarms(&self) {
        metrics::clear_runtime_task_failure_alarms(&self.alarm_manager, &self.profile);
    }

    pub(crate) fn notify_state_change(&self) {
        self.state_tx.send_replace(());
    }

    pub(crate) async fn run_supervised_task(
        name: TaskName,
        metadata: TaskMetadata,
        task_fn: impl Fn()
                -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), TaskError>> + Send>>
            + Send
            + 'static,
        ctx: SupervisorRuntimeCtx,
        notify: Arc<tokio::sync::Notify>,
        exit_tx: tokio::sync::watch::Sender<bool>,
    ) {
        let _exit_guard = ExitSignalGuard(exit_tx);
        let _notify_guard = NotifyOnDrop(notify);
        let restart = metadata.restart;

        let local_shutdown = {
            let t = ctx.tasks.read().await;
            t.get(&name)
                .map(|s| s.shutdown.clone())
                .unwrap_or_else(ShutdownToken::new)
        };

        loop {
            // Check shutdown first at loop entry
            if ctx.shutdown.is_shutdown_requested() || local_shutdown.is_shutdown_requested() {
                tracing::debug!(task = %name, "shutdown requested at loop entry, exiting supervisor loop");
                break;
            }

            // Reset failure window if it has expired since the last failure/window start
            {
                let mut t = ctx.tasks.write().await;
                if let Some(state) = t.get_mut(&name) {
                    let now = ctx.clock.monotonic();
                    let elapsed = now.duration_since(state.window_start);
                    let expired = if restart.window_secs == 0 {
                        elapsed > Duration::ZERO
                    } else {
                        elapsed.as_secs() >= restart.window_secs
                    };
                    if expired {
                        state.failures_in_window = 0;
                        state.window_start = now;
                    }
                }
            }

            // Execute the task — catch panics during construction
            let construct_res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(&task_fn));

            let result: Result<(), TaskError> = match construct_res {
                Err(panic_payload) => {
                    let msg = if let Some(s) = panic_payload.downcast_ref::<&str>() {
                        s.to_string()
                    } else if let Some(s) = panic_payload.downcast_ref::<String>() {
                        s.clone()
                    } else {
                        "unknown panic".to_string()
                    };
                    Err(TaskError::Panicked(name.to_string(), msg))
                }
                Ok(future) => {
                    // Automatically mark task as ready if it's NOT gated
                    {
                        let mut t = ctx.tasks.write().await;
                        if let Some(state) = t.get_mut(&name) {
                            if !state.readiness_gated {
                                state.is_ready = true;
                                if state.is_failed {
                                    state.is_failed = false;
                                    if metadata.criticality == Criticality::Degrade {
                                        ctx.degrade_count.fetch_sub(1, Ordering::SeqCst);
                                    }
                                }
                            }
                        }
                    }
                    ctx.state_tx.send_replace(());
                    // Await the future and catch any panic during async execution
                    match std::panic::AssertUnwindSafe(future).catch_unwind().await {
                        Ok(Ok(())) => {
                            if ctx.shutdown.is_shutdown_requested()
                                || metadata.criticality == Criticality::BestEffort
                            {
                                Ok(())
                            } else {
                                Err(TaskError::Failed(
                                    "unexpected clean exit outside shutdown".to_string(),
                                    std::sync::Arc::new(std::io::Error::other(
                                        "clean exit outside shutdown",
                                    )),
                                ))
                            }
                        }
                        Ok(Err(task_res_err)) => Err(task_res_err),
                        Err(panic_payload) => {
                            let msg = if let Some(s) = panic_payload.downcast_ref::<&str>() {
                                s.to_string()
                            } else if let Some(s) = panic_payload.downcast_ref::<String>() {
                                s.clone()
                            } else {
                                "unknown panic".to_string()
                            };
                            Err(TaskError::Panicked(name.to_string(), msg))
                        }
                    }
                }
            };

            match result {
                Ok(()) => {
                    // Task exited cleanly — supervisor loop terminates normally
                    tracing::debug!(task = %name, "task exited cleanly");
                    break;
                }
                Err(ref e) => {
                    // Task returned an error (or panicked) — classify and handle
                    // We need a dummy Supervisor instance to call handle_task_failure
                    let sup = Supervisor {
                        profile: ctx.profile.clone(),
                        shutdown: ctx.shutdown.clone(),
                        tasks: ctx.tasks.clone(),
                        fatal_failure: ctx.fatal_failure.clone(),
                        fatal_failure_error: ctx.fatal_failure_error.clone(),
                        degrade_count: ctx.degrade_count.clone(),
                        jitter_source: ctx.jitter_source.clone(),
                        clock: ctx.clock.clone(),
                        state_tx: ctx.state_tx.clone(),
                        alarm_manager: ctx.alarm_manager.clone(),
                        memory_limiter: MemoryLimiter::default(),
                    };
                    restart::handle_task_failure_impl(
                        &sup,
                        &name,
                        metadata.criticality,
                        metadata.restart,
                        e,
                        &ctx,
                    )
                    .await;

                    // For Fatal tasks, do not restart — supervisor loop terminates
                    if metadata.criticality == Criticality::Fatal {
                        tracing::debug!(task = %name, "fatal task failed, not restarting");
                        break;
                    }

                    // For non-fatal, check restart budget (freshly computed after failure is recorded)
                    let should_restart = {
                        let t = ctx.tasks.read().await;
                        if let Some(state) = t.get(&name) {
                            state.failures_in_window <= restart.max_restarts
                        } else {
                            false
                        }
                    };

                    if !should_restart {
                        tracing::debug!(task = %name, "restart budget exhausted, not restarting");
                        break;
                    }

                    // Prevent restarts once shutdown has been requested
                    if ctx.shutdown.is_shutdown_requested() {
                        tracing::debug!(task = %name, "shutdown requested before backoff, not restarting");
                        break;
                    }

                    // Apply backoff before restarting
                    let backoff = restart::compute_backoff_impl(
                        &name,
                        &restart,
                        &ctx.tasks,
                        &ctx.jitter_source,
                    )
                    .await;
                    tracing::debug!(task = %name, backoff_ms = %backoff.as_millis(), "task failed, backing off before restart");

                    tokio::select! {
                        _ = ctx.clock.sleep(backoff) => {}
                        _ = ctx.shutdown.shutdown_acknowledged() => {
                            tracing::debug!(task = %name, "shutdown requested during backoff, not restarting");
                            break;
                        }
                        _ = local_shutdown.shutdown_acknowledged() => {
                            tracing::debug!(task = %name, "local shutdown requested during backoff, not restarting");
                            break;
                        }
                    }
                }
            }
        }
    }
}

impl ShutdownPolicy {
    /// Convert to tokio timeout duration if applicable.
    pub fn timeout(&self) -> Option<Duration> {
        match self {
            ShutdownPolicy::DrainWithTimeout(d) => Some(*d),
            _ => None,
        }
    }
}
