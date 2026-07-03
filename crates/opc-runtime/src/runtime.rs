//! Runtime lifecycle: phase state machine, the `RuntimeHandle` returned by
//! `Builder::build`, and the top-level `run`/`run_with_hooks` entry points.
//!
//! `RuntimePhase` mirrors the RFC 008 section 6 startup state machine;
//! `RuntimeHandle` exposes phase/readiness inspection, config-version
//! metadata, the shutdown token, and drives the ordered drain sequence on
//! shutdown (drain hooks, readiness observation window, then supervised task
//! drain within `drain_timeout`).

use opc_alarm::{ReadinessImpact, SharedAlarmManager};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::{watch, RwLock};

use crate::admin::ConfigVersionMetadata;
use crate::bootstrap::PanicHookMetadata;
use crate::health::Readiness;
use crate::profile::{RuntimeMode, RuntimeProfile};
use crate::shutdown::{DrainHook, ShutdownToken};
use crate::supervisor::Supervisor;
use crate::task::RuntimeError;
use crate::testkit::Clock;

#[derive(Debug)]
pub(crate) struct BackgroundTaskGuard {
    pub(crate) handle: tokio::task::JoinHandle<()>,
}

impl Drop for BackgroundTaskGuard {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UnixSignalKind {
    Sigterm,
    Sigint,
}

#[cfg(unix)]
impl UnixSignalKind {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Sigterm => "SIGTERM",
            Self::Sigint => "SIGINT",
        }
    }

    pub(crate) fn register(self) -> std::io::Result<tokio::signal::unix::Signal> {
        match self {
            Self::Sigterm => {
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            }
            Self::Sigint => {
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
            }
        }
    }
}

#[cfg(unix)]
pub(crate) type UnixSignalFactory =
    dyn Fn(UnixSignalKind) -> std::io::Result<tokio::signal::unix::Signal> + Send + Sync;

/// Runtime state transitions per RFC 008 startup state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum RuntimePhase {
    /// Process initialization: CLI/env parsing, panic hook, logging bootstrap.
    ProcessInit = 0,
    /// Telemetry initialization: metrics/tracing/logging exporters.
    TelemetryInit = 1,
    /// Security initialization: identity, trust bundles, key providers.
    SecurityInit = 2,
    /// Configuration bootstrap: load initial config.
    ConfigBootstrap = 3,
    /// Resource preflight: verify CPU, memory, filesystem, devices.
    ResourcePreflight = 4,
    /// Service bind: bind listeners but do not report ready.
    ServiceBind = 5,
    /// Peer warmup: optional NRF registration, discovery, backend connection.
    PeerWarmup = 6,
    /// CNF is ready to serve its intended role.
    Ready = 7,
    /// Termination accepted, new work limited.
    Draining = 8,
    /// All supervised tasks have exited.
    Stopped = 9,
}

impl std::fmt::Display for RuntimePhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuntimePhase::ProcessInit => write!(f, "ProcessInit"),
            RuntimePhase::TelemetryInit => write!(f, "TelemetryInit"),
            RuntimePhase::SecurityInit => write!(f, "SecurityInit"),
            RuntimePhase::ConfigBootstrap => write!(f, "ConfigBootstrap"),
            RuntimePhase::ResourcePreflight => write!(f, "ResourcePreflight"),
            RuntimePhase::ServiceBind => write!(f, "ServiceBind"),
            RuntimePhase::PeerWarmup => write!(f, "PeerWarmup"),
            RuntimePhase::Ready => write!(f, "Ready"),
            RuntimePhase::Draining => write!(f, "Draining"),
            RuntimePhase::Stopped => write!(f, "Stopped"),
        }
    }
}

/// Runtime handle returned after successful startup.
pub struct RuntimeHandle {
    /// Current phase.
    pub(crate) phase: Arc<RwLock<RuntimePhase>>,
    /// Shutdown token for propagation.
    pub(crate) shutdown: ShutdownToken,
    /// Supervisor for task management.
    pub(crate) supervisor: Supervisor,
    /// Runtime-wide alarm manager used by supervised tasks and runtime lifecycle hooks.
    pub(crate) alarm_manager: SharedAlarmManager,
    /// Latest-value notification channel for when the runtime has fully stopped.
    pub(crate) stop_tx: watch::Sender<bool>,
    /// Phase observer callback.
    pub(crate) phase_observer: Option<Arc<dyn Fn(RuntimePhase) + Send + Sync>>,
    /// Panic hook metadata installed during this runtime's build.
    pub(crate) panic_hook_metadata: PanicHookMetadata,
    /// Time source.
    pub(crate) clock: Arc<dyn Clock>,
    /// Registered drain hooks.
    pub(crate) drain_hooks: Vec<Arc<dyn DrainHook>>,
    /// Background signal listener task handle.
    pub(crate) signal_handle: Option<Arc<BackgroundTaskGuard>>,
    /// Background heartbeat monitor task handle.
    pub(crate) heartbeat_monitor_handle: Option<Arc<BackgroundTaskGuard>>,
    /// Idempotency guard for drain hook execution.
    pub(crate) drains_executed: Arc<AtomicBool>,
    /// Number of externally-owned runtime handles.
    pub(crate) owner_count: Arc<AtomicUsize>,
    /// Signals background tasks to exit once the last externally-owned handle drops.
    pub(crate) owner_drop_tx: watch::Sender<bool>,
    /// Whether this handle instance counts as an external owner.
    pub(crate) counts_owner: bool,
    /// Monotonic time when the runtime was created.
    pub(crate) started_at: std::time::Instant,
    /// Current configuration version metadata.
    pub(crate) config_version: Arc<RwLock<ConfigVersionMetadata>>,
}

impl std::fmt::Debug for RuntimeHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuntimeHandle")
            .field("phase", &self.phase)
            .field("shutdown", &self.shutdown)
            .field("supervisor", &self.supervisor)
            .field("stopped", &*self.stop_tx.borrow())
            .field("panic_hook_metadata", &self.panic_hook_metadata)
            .finish()
    }
}

impl Clone for RuntimeHandle {
    fn clone(&self) -> Self {
        if self.counts_owner {
            self.owner_count.fetch_add(1, Ordering::SeqCst);
        }
        Self {
            phase: self.phase.clone(),
            shutdown: self.shutdown.clone(),
            supervisor: self.supervisor.clone(),
            alarm_manager: self.alarm_manager.clone(),
            stop_tx: self.stop_tx.clone(),
            phase_observer: self.phase_observer.clone(),
            panic_hook_metadata: self.panic_hook_metadata.clone(),
            clock: self.clock.clone(),
            drain_hooks: self.drain_hooks.clone(),
            signal_handle: self.signal_handle.clone().filter(|_| self.counts_owner),
            heartbeat_monitor_handle: self
                .heartbeat_monitor_handle
                .clone()
                .filter(|_| self.counts_owner),
            drains_executed: self.drains_executed.clone(),
            owner_count: self.owner_count.clone(),
            owner_drop_tx: self.owner_drop_tx.clone(),
            counts_owner: self.counts_owner,
            started_at: self.started_at,
            config_version: self.config_version.clone(),
        }
    }
}

impl Drop for RuntimeHandle {
    fn drop(&mut self) {
        if self.counts_owner && self.owner_count.fetch_sub(1, Ordering::SeqCst) == 1 {
            self.owner_drop_tx.send_replace(true);
        }
    }
}

impl RuntimeHandle {
    /// Get current runtime phase.
    pub async fn phase(&self) -> RuntimePhase {
        *self.phase.read().await
    }

    /// Set runtime phase (internal use for phase transitions).
    pub(crate) async fn set_phase(&self, new_phase: RuntimePhase) {
        let mut p = self.phase.write().await;
        if *p < new_phase {
            tracing::info!(from = ?*p, to = ?new_phase, "runtime phase transition");
            *p = new_phase;
            if let Some(ref obs) = self.phase_observer {
                obs(new_phase);
            }
            if new_phase >= RuntimePhase::Ready && new_phase < RuntimePhase::Stopped {
                crate::metrics::METRICS
                    .runtime_health_startup
                    .store(1, std::sync::atomic::Ordering::Relaxed);
            } else {
                crate::metrics::METRICS
                    .runtime_health_startup
                    .store(0, std::sync::atomic::Ordering::Relaxed);
            }
            if new_phase == RuntimePhase::Stopped {
                crate::metrics::METRICS
                    .runtime_health_live
                    .store(0, std::sync::atomic::Ordering::Relaxed);
                crate::metrics::METRICS
                    .runtime_health_ready
                    .store(0, std::sync::atomic::Ordering::Relaxed);
            } else {
                crate::metrics::METRICS
                    .runtime_health_live
                    .store(1, std::sync::atomic::Ordering::Relaxed);
            }
            if new_phase == RuntimePhase::Ready {
                self.supervisor.clear_runtime_task_failure_alarms();
            }
            if new_phase == RuntimePhase::Stopped {
                self.shutdown
                    .transition_phase(crate::shutdown::ShutdownPhase::Stopped);
                self.stop_tx.send_replace(true);
            }
        }
    }

    /// Get readiness state.
    pub async fn readiness(&self) -> Readiness {
        let phase = self.phase.read().await;
        let mut r = if *phase < RuntimePhase::Ready {
            Readiness::NotReady
        } else if *phase >= RuntimePhase::Draining {
            Readiness::Draining
        } else {
            self.supervisor.readiness().await
        };
        if matches!(r, Readiness::Ready | Readiness::Degraded) {
            let mut degraded = false;
            for alarm in self.alarm_manager.active_alarms() {
                match alarm.readiness_impact() {
                    ReadinessImpact::ForceNotReady => {
                        r = Readiness::NotReady;
                        degraded = false;
                        break;
                    }
                    ReadinessImpact::DegradedOnly => degraded = true,
                    ReadinessImpact::NoImpact => {}
                }
            }
            if degraded && r == Readiness::Ready {
                r = Readiness::Degraded;
            }
        }
        let ready_val = if r.can_serve() { 1 } else { 0 };
        crate::metrics::METRICS
            .runtime_health_ready
            .store(ready_val, Ordering::Relaxed);
        r
    }

    /// Trigger graceful shutdown.
    pub async fn shutdown(&self) {
        // In Conformance mode, we must drive the full drain sequence synchronously since no background monitor exists.
        if self.supervisor.profile.mode == RuntimeMode::Conformance {
            self.drive_drain_sequence(false).await;
            return;
        }

        self.enter_draining().await;
    }

    /// Returns true when runtime has fully stopped.
    pub async fn is_stopped(&self) -> bool {
        *self.phase.read().await == RuntimePhase::Stopped
    }

    /// Wait until the runtime reaches the fully stopped phase.
    ///
    /// This method is notification-only: it does not consume the handle and it
    /// does not map fatal supervised task failures into a return value. Callers
    /// that need fatal failure details should inspect
    /// `self.supervisor().fatal_task_failure().await` after this method returns,
    /// or use `try_run` / `try_run_with_hooks`.
    pub async fn wait_stopped(&self) {
        let mut stop_rx = self.stop_tx.subscribe();
        loop {
            if *stop_rx.borrow_and_update() {
                return;
            }
            if stop_rx.changed().await.is_err() {
                return;
            }
        }
    }

    /// Complete shutdown: transition to Draining, drain all tasks, then Stopped.
    ///
    /// Used by `run()` when no drain monitor is active (e.g., Conformance mode).
    pub async fn complete_shutdown(&self) {
        self.drive_drain_sequence(false).await;
    }

    /// Get the supervisor for task management.
    pub fn supervisor(&self) -> &Supervisor {
        &self.supervisor
    }

    /// Get the current config version metadata.
    pub async fn config_version(&self) -> ConfigVersionMetadata {
        self.config_version.read().await.clone()
    }

    /// Update the config version metadata.
    pub async fn update_config_version(&self, metadata: ConfigVersionMetadata) {
        let mut cv = self.config_version.write().await;
        *cv = metadata;
    }

    /// Get the shared alarm manager used by this runtime.
    pub fn alarm_manager(&self) -> SharedAlarmManager {
        self.alarm_manager.clone()
    }

    /// Get the shutdown token.
    pub fn shutdown_token(&self) -> &ShutdownToken {
        &self.shutdown
    }

    pub(crate) async fn enter_draining(&self) {
        self.shutdown.request_shutdown();
        self.set_phase(RuntimePhase::Draining).await;
    }

    pub(crate) async fn abort_startup(&self) {
        self.drive_drain_sequence(false).await;
    }

    fn drain_hook_timeout(&self) -> std::time::Duration {
        self.supervisor
            .profile
            .shutdown_grace
            .min(self.supervisor.profile.drain_timeout)
    }

    fn readiness_observation_budget(
        &self,
        drain_started_at: std::time::Instant,
    ) -> std::time::Duration {
        let elapsed = self.clock.monotonic().duration_since(drain_started_at);
        self.supervisor
            .profile
            .shutdown_grace
            .saturating_sub(elapsed)
            .min(
                self.supervisor
                    .profile
                    .drain_timeout
                    .saturating_sub(elapsed),
            )
    }

    pub(crate) async fn drive_drain_sequence(&self, observe_readiness_window: bool) {
        if self
            .drains_executed
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            tracing::debug!("drain sequence has already been executed; skipping repeat execution");
            return;
        }

        let drain_started_at = self.clock.monotonic();
        self.enter_draining().await;
        self.execute_drain_hooks(self.drain_hook_timeout()).await;

        if observe_readiness_window {
            let remaining = self.readiness_observation_budget(drain_started_at);

            // Allow external routers and probes to observe readiness=false before worker drain
            // begins. This observation window is carved out of the shared drain budget, not
            // added on top of it.
            self.clock.sleep(remaining).await;
        }

        // Any readiness-observation sleep above already consumed part of the shared drain budget,
        // so the remaining timeout computed here naturally shrinks before supervisor shutdown begins.
        self.finish_shutdown_with_remaining_budget(drain_started_at)
            .await;
    }

    async fn finish_shutdown_with_policy(&self, policy: crate::task::ShutdownPolicy) {
        self.shutdown
            .transition_phase(crate::shutdown::ShutdownPhase::ProtocolDraining);
        self.supervisor.shutdown_all(policy).await;
        self.supervisor
            .shutdown_all(crate::task::ShutdownPolicy::Immediate)
            .await;
        self.set_phase(RuntimePhase::Stopped).await;
    }

    async fn finish_shutdown_with_remaining_budget(&self, drain_started_at: std::time::Instant) {
        let elapsed = self.clock.monotonic().duration_since(drain_started_at);
        let remaining = self
            .supervisor
            .profile
            .drain_timeout
            .saturating_sub(elapsed);
        self.finish_shutdown_with_policy(crate::task::ShutdownPolicy::DrainWithTimeout(remaining))
            .await;
    }

    async fn execute_drain_hooks(&self, timeout: std::time::Duration) {
        let mut futures = Vec::with_capacity(self.drain_hooks.len());
        for hook in &self.drain_hooks {
            futures.push(hook.on_drain());
        }
        if !futures.is_empty() {
            let all_hooks = futures_util::future::join_all(futures);
            tokio::select! {
                biased;
                results = all_hooks => {
                    let mut failed_hooks = Vec::new();
                    for (i, res) in results.iter().enumerate() {
                        if let Err(e) = res {
                            tracing::error!(hook_index = i, error = %e, "drain hook failed");
                            failed_hooks.push(format!("hook {i} failed: {e}"));
                        }
                    }
                    if !failed_hooks.is_empty() {
                        let reason = failed_hooks.join("; ");
                        crate::supervisor::raise_drain_incomplete_alarm(
                            &self.alarm_manager,
                            &self.supervisor.profile,
                            &reason,
                        );
                    }
                }
                _ = self.clock.sleep(timeout) => {
                    tracing::warn!("drain hooks timed out after {:?}", timeout);
                    crate::supervisor::raise_drain_incomplete_alarm(
                        &self.alarm_manager,
                        &self.supervisor.profile,
                        &format!("drain hooks timed out after {timeout:?}"),
                    );
                }
            }
        }
    }

    pub(crate) async fn promote_ready_if_possible(&self) -> bool {
        if self.shutdown.is_shutdown_requested() {
            return false;
        }

        let phase = self.phase().await;
        if phase != RuntimePhase::PeerWarmup {
            return phase >= RuntimePhase::Ready;
        }

        let sup_readiness = self.supervisor.readiness().await;
        if matches!(sup_readiness, Readiness::Ready | Readiness::Degraded) {
            self.set_phase(RuntimePhase::Ready).await;
            return true;
        }

        false
    }

    pub(crate) fn background_clone(&self) -> Self {
        Self {
            phase: self.phase.clone(),
            shutdown: self.shutdown.clone(),
            supervisor: self.supervisor.clone(),
            alarm_manager: self.alarm_manager.clone(),
            stop_tx: self.stop_tx.clone(),
            phase_observer: self.phase_observer.clone(),
            panic_hook_metadata: self.panic_hook_metadata.clone(),
            clock: self.clock.clone(),
            drain_hooks: self.drain_hooks.clone(),
            signal_handle: None,
            heartbeat_monitor_handle: None,
            drains_executed: self.drains_executed.clone(),
            owner_count: self.owner_count.clone(),
            owner_drop_tx: self.owner_drop_tx.clone(),
            counts_owner: false,
            started_at: self.started_at,
            config_version: self.config_version.clone(),
        }
    }
}

/// Run the CNF runtime with a profile and supervised tasks.
pub async fn run(
    profile: RuntimeProfile,
    init: impl FnOnce(Supervisor, ShutdownToken) -> Pin<Box<dyn Future<Output = ()> + Send>>
        + Send
        + 'static,
) -> Result<(), RuntimeError> {
    run_with_hooks(profile, Vec::new(), init).await
}

/// Run the CNF runtime with a profile, custom drain hooks, and supervised tasks.
pub async fn run_with_hooks(
    profile: RuntimeProfile,
    drain_hooks: Vec<Arc<dyn DrainHook>>,
    init: impl FnOnce(Supervisor, ShutdownToken) -> Pin<Box<dyn Future<Output = ()> + Send>>
        + Send
        + 'static,
) -> Result<(), RuntimeError> {
    try_run_with_hooks(profile, drain_hooks, move |supervisor, shutdown| {
        Box::pin(async move {
            init(supervisor, shutdown).await;
            Ok(())
        })
    })
    .await
}

/// Run the CNF runtime with a profile and fallible supervised task initialization.
///
/// # Errors
///
/// Returns startup errors from `Builder::build`, including errors returned by
/// the fallible init callback. After a successful startup, fatal supervised task
/// failures are returned as `RuntimeError::TaskCriticalFailure` after shutdown
/// completes.
pub async fn try_run(
    profile: RuntimeProfile,
    init: impl FnOnce(
            Supervisor,
            ShutdownToken,
        ) -> Pin<Box<dyn Future<Output = Result<(), RuntimeError>> + Send>>
        + Send
        + 'static,
) -> Result<(), RuntimeError> {
    try_run_with_hooks(profile, Vec::new(), init).await
}

/// Run the CNF runtime with custom drain hooks and fallible initialization.
///
/// # Errors
///
/// Returns startup errors from `Builder::build`, including errors returned by
/// the fallible init callback. After a successful startup, fatal supervised task
/// failures are returned as `RuntimeError::TaskCriticalFailure` after shutdown
/// completes.
pub async fn try_run_with_hooks(
    profile: RuntimeProfile,
    drain_hooks: Vec<Arc<dyn DrainHook>>,
    init: impl FnOnce(
            Supervisor,
            ShutdownToken,
        ) -> Pin<Box<dyn Future<Output = Result<(), RuntimeError>> + Send>>
        + Send
        + 'static,
) -> Result<(), RuntimeError> {
    let mode = profile.mode;
    let mut builder = crate::builder::Builder::new(profile).try_with_init(init);
    for hook in drain_hooks {
        builder = builder.with_drain_hook(hook);
    }
    let handle = builder.build().await?;
    let shutdown = handle.shutdown_token().clone();

    // Wait for external shutdown signal (not self-initiated)
    shutdown.shutdown_acknowledged().await;

    // In Conformance mode, no drain monitor is spawned, so we must drive
    // the shutdown sequence inline. In other modes, wait for the drain monitor.
    if mode == RuntimeMode::Conformance {
        handle.complete_shutdown().await;
    } else {
        handle.wait_stopped().await;
    }

    if let Some((task, error)) = handle.supervisor.fatal_task_failure().await {
        return Err(RuntimeError::TaskCriticalFailure(task.to_string(), error));
    }

    Ok(())
}
