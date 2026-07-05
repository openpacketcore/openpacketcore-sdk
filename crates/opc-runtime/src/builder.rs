//! Runtime construction through the RFC 008 startup state machine.
//!
//! `Builder` drives a CNF process from `ProcessInit` through `TelemetryInit`,
//! `SecurityInit`, `ConfigBootstrap`, `ResourcePreflight`, `ServiceBind`, and
//! `PeerWarmup`, installs the redacting panic hook and Unix signal handlers,
//! validates resource budgets and required drain hooks, and only promotes the
//! runtime to `Ready` once supervised tasks report readiness.

use opc_alarm::SharedAlarmManager;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::admin::ConfigVersionMetadata;
use crate::bootstrap::{BootstrapError, PanicHookMetadata};
use crate::profile::{RuntimeMode, RuntimeProfile, SigintHandling};
use crate::runtime::{BackgroundTaskGuard, RuntimeHandle, RuntimePhase};
use crate::shutdown::{DrainHook, ShutdownToken};
use crate::supervisor::Supervisor;
use crate::task::RuntimeError;
use crate::testkit::{Clock, RealClock};

#[cfg(unix)]
use crate::runtime::{UnixSignalFactory, UnixSignalKind};

/// Boxed one-shot initialization callback passed to `Builder::with_init`.
///
/// Receives the runtime's `Supervisor` and `ShutdownToken` and is awaited
/// after `PeerWarmup` but before the runtime can transition to `Ready`, so it
/// is the place to register and spawn all supervised tasks.
pub type InitFn =
    Box<dyn FnOnce(Supervisor, ShutdownToken) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send>;

/// Boxed one-shot fallible initialization callback passed to `Builder::try_with_init`.
///
/// Receives the runtime's `Supervisor` and `ShutdownToken` after
/// `PeerWarmup`, but before readiness promotion can start. Returning an error
/// aborts startup, drains any partially spawned tasks, and makes
/// `Builder::build` return the original `RuntimeError`.
pub type TryInitFn = Box<
    dyn FnOnce(
            Supervisor,
            ShutdownToken,
        ) -> Pin<Box<dyn Future<Output = Result<(), RuntimeError>> + Send>>
        + Send,
>;

/// Telemetry bootstrap callback stored in `StartupPhases::init_telemetry`.
///
/// Invoked with the runtime profile during the `TelemetryInit` phase to set
/// up metrics/tracing/logging exporters; returning a `BootstrapError` aborts
/// startup.
pub type TelemetryInitFn = dyn Fn(
        &RuntimeProfile,
    )
        -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), BootstrapError>> + Send>>
    + Send
    + Sync;

/// Builder for RuntimeHandle.
pub struct Builder {
    pub(crate) profile: RuntimeProfile,
    pub(crate) phases: StartupPhases,
    pub(crate) phase_observer: Option<Arc<dyn Fn(RuntimePhase) + Send + Sync>>,
    pub(crate) init: Option<TryInitFn>,
    pub(crate) alarm_manager: Option<SharedAlarmManager>,
    pub(crate) clock: Option<Arc<dyn Clock>>,
    pub(crate) drain_hooks: Vec<Arc<dyn DrainHook>>,
    pub(crate) required_drain_hooks: Vec<String>,
    #[cfg(unix)]
    pub(crate) signal_factory: Arc<UnixSignalFactory>,
}

impl std::fmt::Debug for Builder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Builder")
            .field("profile", &self.profile)
            .finish()
    }
}

impl Builder {
    /// Create a new builder with the given profile.
    pub fn new(profile: RuntimeProfile) -> Self {
        Self {
            profile,
            phases: StartupPhases::default(),
            phase_observer: None,
            init: None,
            alarm_manager: None,
            clock: None,
            drain_hooks: Vec::new(),
            required_drain_hooks: Vec::new(),
            #[cfg(unix)]
            signal_factory: Arc::new(|kind: UnixSignalKind| kind.register()),
        }
    }

    /// Set custom startup phases.
    pub fn with_phases(mut self, phases: StartupPhases) -> Self {
        self.phases = phases;
        self
    }

    /// Register a phase transition observer.
    pub fn with_phase_observer(
        mut self,
        observer: impl Fn(RuntimePhase) + Send + Sync + 'static,
    ) -> Self {
        self.phase_observer = Some(Arc::new(observer));
        self
    }

    /// Register an infallible supervisor/shutdown initialization callback.
    ///
    /// The callback runs after `PeerWarmup` and before readiness promotion.
    /// This method shares one effective init slot with `try_with_init`: if both
    /// setters are called, the later setter replaces the earlier callback.
    pub fn with_init(
        mut self,
        init: impl FnOnce(Supervisor, ShutdownToken) -> Pin<Box<dyn Future<Output = ()> + Send>>
            + Send
            + 'static,
    ) -> Self {
        self.init = Some(Box::new(move |supervisor, shutdown| {
            Box::pin(async move {
                init(supervisor, shutdown).await;
                Ok(())
            })
        }));
        self
    }

    /// Register a fallible supervisor/shutdown initialization callback.
    ///
    /// The callback runs after `PeerWarmup` and before readiness promotion. Use
    /// this for required startup work, such as binding listeners before their
    /// long-running supervised tasks are spawned. If the callback returns an
    /// error, `build` performs startup-abort cleanup and returns that original
    /// `RuntimeError`.
    ///
    /// This method shares one effective init slot with `with_init`: if both
    /// setters are called, the later setter replaces the earlier callback.
    pub fn try_with_init(
        mut self,
        init: impl FnOnce(
                Supervisor,
                ShutdownToken,
            ) -> Pin<Box<dyn Future<Output = Result<(), RuntimeError>> + Send>>
            + Send
            + 'static,
    ) -> Self {
        self.init = Some(Box::new(init));
        self
    }

    /// Use a caller-provided alarm manager for runtime task alarms and lifecycle clearing.
    pub fn with_alarm_manager(mut self, alarm_manager: SharedAlarmManager) -> Self {
        self.alarm_manager = Some(alarm_manager);
        self
    }

    /// Set an explicit clock implementation.
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = Some(clock);
        self
    }

    /// Register a drain hook to run on shutdown.
    pub fn with_drain_hook(mut self, hook: Arc<dyn DrainHook>) -> Self {
        self.drain_hooks.push(hook);
        self
    }

    /// Enforce that a specific drain hook by name must be registered before build.
    pub fn require_drain_hook(mut self, name: &str) -> Self {
        self.required_drain_hooks.push(name.to_string());
        self
    }

    #[cfg(all(test, unix))]
    pub(crate) fn with_signal_factory(mut self, factory: Arc<UnixSignalFactory>) -> Self {
        self.signal_factory = factory;
        self
    }

    /// Build the runtime handle.
    pub async fn build(mut self) -> Result<RuntimeHandle, RuntimeError> {
        if let Err(e) = self.profile.validate_resource_limits() {
            return Err(BootstrapError::InvalidResourceBudget(e).into());
        }

        // Sync max_tasks and max_queued_bytes from budget if present
        if let Some(ref budget) = self.profile.budget {
            self.profile.max_tasks = budget.max_tasks;
            self.profile.max_queued_bytes = budget.max_queue_bytes;
        }

        if self.profile.requires_nrf_drain_hook {
            self.required_drain_hooks.push("NrfDrainHook".to_string());
        }

        // Validate that all required hooks are registered
        for required in &self.required_drain_hooks {
            let present = self.drain_hooks.iter().any(|hook| hook.name() == required);
            if !present {
                if self.profile.mode.fail_closed() {
                    return Err(BootstrapError::MissingRequiredDrainHook(required.clone()).into());
                } else {
                    tracing::warn!(
                        required_hook = %required,
                        nf_kind = %self.profile.nf_kind,
                        "Missing required drain hook during startup. Registration should not be omitted in production environments."
                    );
                }
            }
        }

        if self.profile.shutdown_grace
            > self
                .profile
                .drain_timeout
                .saturating_sub(self.profile.readiness_observation_window)
        {
            tracing::warn!(
                shutdown_grace = ?self.profile.shutdown_grace,
                drain_timeout = ?self.profile.drain_timeout,
                readiness_observation_window = ?self.profile.readiness_observation_window,
                "Mis-tuned runtime shutdown/drain budgets: shutdown_grace plus readiness_observation_window can consume the entire drain_timeout and starve task graceful draining."
            );
        }

        let phase = Arc::new(tokio::sync::RwLock::new(RuntimePhase::ProcessInit));

        if let Some(ref obs) = self.phase_observer {
            obs(RuntimePhase::ProcessInit);
        }

        let panic_hook_metadata = PanicHookMetadata::from_profile(&self.profile);

        #[cfg(test)]
        {
            let _panic_hook_test_guard = crate::bootstrap::panic_hook_test_guard();
            crate::bootstrap::install_panic_hook(panic_hook_metadata.clone());
        }
        #[cfg(not(test))]
        crate::bootstrap::install_panic_hook(panic_hook_metadata.clone());

        // Initialize shutdown token
        let shutdown = ShutdownToken::new();

        // Bootstrap logging if enabled
        if self.profile.mode != RuntimeMode::Conformance {
            self.phases.init_logging()?;
        }

        // Phase 1: TelemetryInit
        {
            let mut p = phase.write().await;
            *p = RuntimePhase::TelemetryInit;
            if let Some(ref obs) = self.phase_observer {
                obs(RuntimePhase::TelemetryInit);
            }
        }
        self.phases.init_telemetry(&self.profile).await?;

        // Phase 2: SecurityInit (placeholder — RFC 003 handles actual identity)
        {
            let mut p = phase.write().await;
            *p = RuntimePhase::SecurityInit;
            if let Some(ref obs) = self.phase_observer {
                obs(RuntimePhase::SecurityInit);
            }
        }

        // Phase 3: ConfigBootstrap (placeholder — RFC 001 handles actual config)
        {
            let mut p = phase.write().await;
            *p = RuntimePhase::ConfigBootstrap;
            if let Some(ref obs) = self.phase_observer {
                obs(RuntimePhase::ConfigBootstrap);
            }
        }

        // Phase 4: ResourcePreflight (placeholder)
        {
            let mut p = phase.write().await;
            *p = RuntimePhase::ResourcePreflight;
            if let Some(ref obs) = self.phase_observer {
                obs(RuntimePhase::ResourcePreflight);
            }
        }

        // Phase 5: ServiceBind (placeholder)
        {
            let mut p = phase.write().await;
            *p = RuntimePhase::ServiceBind;
            if let Some(ref obs) = self.phase_observer {
                obs(RuntimePhase::ServiceBind);
            }
        }

        // Phase 6: PeerWarmup (placeholder)
        {
            let mut p = phase.write().await;
            *p = RuntimePhase::PeerWarmup;
            if let Some(ref obs) = self.phase_observer {
                obs(RuntimePhase::PeerWarmup);
            }
        }

        let alarm_manager = self.alarm_manager.unwrap_or_default();

        // Create supervisor
        let clock = self.clock.clone().unwrap_or_else(|| Arc::new(RealClock));
        let supervisor = Supervisor::new_with_clock_and_alarm_manager(
            self.profile.clone(),
            shutdown.clone(),
            clock.clone(),
            alarm_manager.clone(),
        );
        let heartbeat_monitor_handle = Arc::new(BackgroundTaskGuard {
            handle: supervisor.start_heartbeat_monitor(),
        });
        let mut readiness_rx = supervisor.subscribe_state_changes();

        // Install SIGTERM and optional SIGINT signal handlers under Unix.
        #[cfg(unix)]
        let signal_factory = self.signal_factory.clone();
        #[cfg(unix)]
        let mut sigterm = match signal_factory.as_ref()(UnixSignalKind::Sigterm) {
            Ok(stream) => Some(stream),
            Err(e) if self.profile.mode.fail_closed() => {
                return Err(BootstrapError::SignalRegistration {
                    signal: UnixSignalKind::Sigterm.label(),
                    source: e,
                }
                .into());
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to register SIGTERM stream");
                None
            }
        };
        #[cfg(unix)]
        let mut sigint = if self
            .profile
            .sigint_handling
            .enables_graceful_shutdown(self.profile.mode)
        {
            let fail_closed_sigint = self.profile.mode.fail_closed()
                && self.profile.sigint_handling == SigintHandling::GracefulShutdown;
            match signal_factory.as_ref()(UnixSignalKind::Sigint) {
                Ok(stream) => Some(stream),
                Err(e) if fail_closed_sigint => {
                    return Err(BootstrapError::SignalRegistration {
                        signal: UnixSignalKind::Sigint.label(),
                        source: e,
                    }
                    .into());
                }
                Err(e) => {
                    tracing::warn!(error = %e, "failed to register SIGINT stream");
                    None
                }
            }
        } else {
            None
        };

        #[cfg(unix)]
        let signal_handle = if sigterm.is_none() && sigint.is_none() {
            tracing::error!("both SIGTERM and SIGINT signal stream registrations failed; no signal handling is active");
            None
        } else {
            let shutdown_clone = shutdown.clone();
            let join_handle = tokio::spawn(async move {
                tokio::select! {
                    _ = async {
                        if let Some(ref mut sig) = sigterm {
                            sig.recv().await;
                        } else {
                            futures_util::future::pending::<()>().await;
                        }
                    } => {
                        tracing::info!("SIGTERM received, initiating graceful shutdown");
                    }
                    _ = async {
                        if let Some(ref mut sig) = sigint {
                            sig.recv().await;
                        } else {
                            futures_util::future::pending::<()>().await;
                        }
                    } => {
                        tracing::info!("SIGINT received, initiating graceful shutdown");
                    }
                }
                shutdown_clone.request_shutdown();
            });
            Some(Arc::new(BackgroundTaskGuard {
                handle: join_handle,
            }))
        };

        #[cfg(not(unix))]
        let signal_handle = None;

        let owner_count = Arc::new(std::sync::atomic::AtomicUsize::new(1));
        let (owner_drop_tx, _) = tokio::sync::watch::channel(false);
        let started_at = clock.monotonic();
        let config_version = Arc::new(tokio::sync::RwLock::new(ConfigVersionMetadata::default()));

        let (stop_tx, _) = tokio::sync::watch::channel(false);

        let handle = RuntimeHandle {
            phase,
            shutdown,
            supervisor: supervisor.clone(),
            alarm_manager,
            stop_tx,
            phase_observer: self.phase_observer.clone(),
            panic_hook_metadata,
            clock: clock.clone(),
            drain_hooks: self.drain_hooks.clone(),
            signal_handle,
            heartbeat_monitor_handle: Some(heartbeat_monitor_handle),
            drains_executed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            owner_count,
            owner_drop_tx,
            counts_owner: true,
            started_at,
            config_version,
        };

        let drain_monitor = if self.profile.mode != RuntimeMode::Conformance {
            let h = handle.background_clone();
            let mut owner_drop_rx = handle.owner_drop_tx.subscribe();
            Some(tokio::spawn(async move {
                let observe_readiness = tokio::select! {
                    biased;
                    _ = h.shutdown_token().shutdown_acknowledged() => {
                        true
                    }
                    _ = owner_drop_rx.changed() => {
                        h.shutdown_token().is_shutdown_requested()
                    }
                };

                // Now transition to draining (readiness will become NotReady/Draining).
                h.drive_drain_sequence(observe_readiness).await;
            }))
        } else {
            None
        };

        // Run the init callback to spawn tasks before transitioning to Ready
        if let Some(init) = self.init {
            if let Err(err) = init(supervisor, handle.shutdown_token().clone()).await {
                handle.abort_startup().await;
                if let Some(drain_monitor) = drain_monitor {
                    let _ = drain_monitor.await;
                }
                return Err(err);
            }
        }

        let readiness_handle = handle.background_clone();
        let shutdown_token = handle.shutdown_token().clone();
        let mut owner_drop_rx = handle.owner_drop_tx.subscribe();
        tokio::spawn(async move {
            let mut shutdown_rx = shutdown_token.subscribe();
            loop {
                if readiness_handle.promote_ready_if_possible().await {
                    break;
                }

                if readiness_handle.phase().await >= RuntimePhase::Draining {
                    break;
                }

                if readiness_handle.shutdown_token().is_shutdown_requested() {
                    break;
                }

                tokio::select! {
                    res = readiness_rx.changed() => {
                        if res.is_err() {
                            break;
                        }
                    }
                    res = shutdown_rx.changed() => {
                        if res.is_err() {
                            break;
                        }
                    }
                    res = owner_drop_rx.changed() => {
                        if res.is_err() || *owner_drop_rx.borrow_and_update() {
                            break;
                        }
                    }
                }
            }
        });

        // Delay the Ready phase until after the caller has bound/spawned required tasks
        // and the runtime actually satisfies readiness.
        handle.promote_ready_if_possible().await;

        Ok(handle)
    }
}

#[derive(Default)]
/// Startup phases callback container.
pub struct StartupPhases {
    /// Optional logging bootstrap callback run during `ProcessInit`; `None`
    /// is a no-op. Skipped entirely in Conformance mode to keep test output
    /// deterministic. A `BootstrapError` aborts startup.
    pub init_logging: Option<Box<dyn Fn() -> Result<(), BootstrapError> + Send + Sync>>,
    /// Optional exporter bootstrap callback run during the `TelemetryInit`
    /// phase with the runtime profile; `None` is a no-op. A `BootstrapError`
    /// aborts startup.
    pub init_telemetry: Option<Box<TelemetryInitFn>>,
}

impl StartupPhases {
    /// Runs the configured logging callback, or returns `Ok(())` when none is
    /// set. An `Err` from the callback aborts `Builder::build`.
    pub fn init_logging(&self) -> Result<(), BootstrapError> {
        if let Some(f) = &self.init_logging {
            f()
        } else {
            Ok(())
        }
    }

    /// Runs the configured telemetry callback with the given profile, or
    /// returns `Ok(())` when none is set. An `Err` from the callback aborts
    /// `Builder::build` during the `TelemetryInit` phase.
    pub async fn init_telemetry(&self, profile: &RuntimeProfile) -> Result<(), BootstrapError> {
        if let Some(f) = &self.init_telemetry {
            f(profile).await
        } else {
            Ok(())
        }
    }
}
