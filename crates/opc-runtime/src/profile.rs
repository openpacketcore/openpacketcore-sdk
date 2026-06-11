//! Runtime profile configuration.

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Runtime operational mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuntimeMode {
    /// Permissive, local files, debug endpoints on loopback.
    Dev,
    /// Production-like, explicit waivers allowed.
    Lab,
    /// Fail closed, debug gated, strict resource limits.
    #[default]
    Production,
    /// Deterministic test profile.
    Conformance,
    /// Optimized benchmark profile.
    Perf,
}

impl RuntimeMode {
    /// Returns true if this mode must refuse to start (rather than degrade)
    /// when required bootstrap material is missing, per RFC 008 section 3.1.
    ///
    /// True for `Production` and `Conformance`; `Dev`, `Lab`, and `Perf`
    /// downgrade such failures to warnings.
    pub fn fail_closed(&self) -> bool {
        matches!(self, RuntimeMode::Production | RuntimeMode::Conformance)
    }

    /// Returns true if debug/admin endpoints may be served without being
    /// authorization-gated in this mode.
    ///
    /// True for `Dev`, `Lab`, and `Conformance`; `Production` and `Perf`
    /// require debug surfaces to be gated or disabled.
    pub fn debug_enabled(&self) -> bool {
        matches!(
            self,
            RuntimeMode::Dev | RuntimeMode::Lab | RuntimeMode::Conformance
        )
    }
}

/// SIGINT handling policy for Unix runtimes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SigintHandling {
    /// Use the runtime-mode default from RFC 008:
    /// graceful drain in Dev/Lab/Conformance, disabled in Production/Perf.
    #[default]
    ModeDefault,
    /// Register SIGINT and treat it as a graceful drain trigger.
    GracefulShutdown,
    /// Do not register SIGINT handling.
    Disabled,
}

impl SigintHandling {
    /// Resolves this policy against a runtime mode, returning true when a
    /// SIGINT handler should be registered as a graceful drain trigger.
    ///
    /// `ModeDefault` enables SIGINT handling only in Dev, Lab, and Conformance
    /// modes; `GracefulShutdown` always enables it; `Disabled` never does.
    pub fn enables_graceful_shutdown(self, mode: RuntimeMode) -> bool {
        match self {
            Self::ModeDefault => matches!(
                mode,
                RuntimeMode::Dev | RuntimeMode::Lab | RuntimeMode::Conformance
            ),
            Self::GracefulShutdown => true,
            Self::Disabled => false,
        }
    }
}

/// Declared runtime resource budget per RFC 008 section 9.1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceBudget {
    /// Heap ceiling in bytes; `None` disables the memory-pressure check.
    /// When simulated usage reaches this value the supervisor refuses new task
    /// spawns and reports readiness `NotReady`. Default 256 MiB; must be <= 1 TiB.
    pub max_heap_bytes: Option<usize>,
    /// Maximum number of supervised tasks; registration and spawn fail once
    /// reached. Overrides `RuntimeProfile::max_tasks` when a budget is set.
    /// Default 4096; must be in 1..=100,000.
    pub max_tasks: usize,
    /// Maximum number of bounded channels the CNF may create. Default 1024;
    /// must be in 1..=100,000.
    pub max_channels: usize,
    /// Total bytes that may sit queued across all channels. Overrides
    /// `RuntimeProfile::max_queued_bytes` when a budget is set. Default
    /// 64 MiB; must be <= 10 GiB.
    pub max_queue_bytes: usize,
    /// Maximum accepted size in bytes for a single request body. Default
    /// 10 MiB; must be <= 1 GiB.
    pub max_request_body_bytes: usize,
    /// Maximum number of simultaneously open file descriptors. Default 1024;
    /// must be <= 1,000,000.
    pub max_open_files: usize,
    /// Maximum number of concurrent connections to backend peers. Default
    /// 256; must be <= 100,000.
    pub max_backend_connections: usize,
}

impl Default for ResourceBudget {
    fn default() -> Self {
        Self {
            max_heap_bytes: Some(256 * 1024 * 1024), // 256 MiB
            max_tasks: 4096,
            max_channels: 1024,
            max_queue_bytes: 64 * 1024 * 1024,        // 64 MiB
            max_request_body_bytes: 10 * 1024 * 1024, // 10 MiB
            max_open_files: 1024,
            max_backend_connections: 256,
        }
    }
}

impl ResourceBudget {
    /// Checks every limit against its allowed range (all limits must be
    /// non-zero and below their documented maxima).
    ///
    /// Returns `Err` with a human-readable message naming the first offending
    /// field. Called automatically by `RuntimeProfile::validate_resource_limits`
    /// during `Builder::build`.
    pub fn validate(&self) -> Result<(), String> {
        if self.max_tasks == 0 || self.max_tasks > 100_000 {
            return Err("max_tasks must be > 0 and <= 100,000".to_string());
        }
        if self.max_channels == 0 || self.max_channels > 100_000 {
            return Err("max_channels must be > 0 and <= 100,000".to_string());
        }
        if self.max_queue_bytes == 0 || self.max_queue_bytes > 10 * 1024 * 1024 * 1024 {
            return Err("max_queue_bytes must be > 0 and <= 10 GiB".to_string());
        }
        if self.max_request_body_bytes == 0 || self.max_request_body_bytes > 1024 * 1024 * 1024 {
            return Err("max_request_body_bytes must be > 0 and <= 1 GiB".to_string());
        }
        if self.max_open_files == 0 || self.max_open_files > 1_000_000 {
            return Err("max_open_files must be > 0 and <= 1,000,000".to_string());
        }
        if self.max_backend_connections == 0 || self.max_backend_connections > 100_000 {
            return Err("max_backend_connections must be > 0 and <= 100,000".to_string());
        }
        if let Some(heap) = self.max_heap_bytes {
            if heap == 0 || heap > 1024 * 1024 * 1024 * 1024 {
                // 1 TiB
                return Err("max_heap_bytes must be > 0 and <= 1 TiB".to_string());
            }
        }
        Ok(())
    }
}

/// Runtime profile for a CNF instance.
#[derive(Debug, Clone)]
pub struct RuntimeProfile {
    /// Operational mode.
    pub mode: RuntimeMode,
    /// NF kind identifier (e.g., "amf", "smf", "upf").
    pub nf_kind: String,
    /// Instance identifier.
    pub instance_id: uuid::Uuid,
    /// Number of async worker threads.
    pub async_workers: usize,
    /// Max blocking threads.
    pub blocking_threads: usize,
    /// Max tasks.
    pub max_tasks: usize,
    /// Max queued bytes across all channels.
    pub max_queued_bytes: usize,
    /// Shutdown grace period.
    ///
    /// It is recommended that `shutdown_grace <= drain_timeout / 2` to prevent
    /// the observation window and drain hooks from consuming the entire
    /// `drain_timeout` budget and starving task graceful draining.
    pub shutdown_grace: Duration,
    /// Drain timeout.
    ///
    /// The maximum total duration allowed for the entire runtime shutdown sequence.
    pub drain_timeout: Duration,
    /// SIGINT handling policy.
    pub sigint_handling: SigintHandling,
    /// Whether an NRF deregistration/drain hook must be registered.
    pub requires_nrf_drain_hook: bool,
    /// Resource budget limits.
    pub budget: Option<ResourceBudget>,
}

impl Default for RuntimeProfile {
    fn default() -> Self {
        Self {
            mode: RuntimeMode::Production,
            nf_kind: "unknown".to_string(),
            instance_id: uuid::Uuid::new_v4(),
            async_workers: num_cpus::get().max(4),
            blocking_threads: 512,
            max_tasks: 4096,
            max_queued_bytes: 64 * 1024 * 1024, // 64 MiB
            shutdown_grace: Duration::from_secs(30),
            drain_timeout: Duration::from_secs(60),
            sigint_handling: SigintHandling::default(),
            requires_nrf_drain_hook: false,
            budget: None,
        }
    }
}

impl RuntimeProfile {
    /// Create a dev profile for local testing.
    pub fn dev(nf_kind: impl Into<String>) -> Self {
        let nf_kind = nf_kind.into();
        let requires_nrf_drain_hook = matches!(nf_kind.as_str(), "amf" | "smf" | "upf");
        Self {
            mode: RuntimeMode::Dev,
            nf_kind,
            requires_nrf_drain_hook,
            budget: Some(ResourceBudget::default()),
            ..Default::default()
        }
    }

    /// Create a conformance/test profile.
    pub fn conformance(nf_kind: impl Into<String>) -> Self {
        let nf_kind = nf_kind.into();
        let requires_nrf_drain_hook = matches!(nf_kind.as_str(), "amf" | "smf" | "upf");
        Self {
            mode: RuntimeMode::Conformance,
            nf_kind,
            shutdown_grace: Duration::from_secs(5),
            drain_timeout: Duration::from_secs(10),
            requires_nrf_drain_hook,
            budget: Some(ResourceBudget::default()),
            ..Default::default()
        }
    }

    /// Create a production profile.
    pub fn production(nf_kind: impl Into<String>, instance_id: uuid::Uuid) -> Self {
        let nf_kind = nf_kind.into();
        let requires_nrf_drain_hook = matches!(nf_kind.as_str(), "amf" | "smf" | "upf");
        Self {
            mode: RuntimeMode::Production,
            nf_kind,
            instance_id,
            requires_nrf_drain_hook,
            budget: None,
            ..Default::default()
        }
    }

    /// Validate resource limits owned by the runtime profile.
    pub fn validate_resource_limits(&self) -> Result<(), String> {
        if self.async_workers == 0 || self.async_workers > 4096 {
            return Err("async_workers must be > 0 and <= 4096".to_string());
        }
        if self.blocking_threads == 0 || self.blocking_threads > 100_000 {
            return Err("blocking_threads must be > 0 and <= 100,000".to_string());
        }

        match (&self.mode, &self.budget) {
            (RuntimeMode::Production, None) => {
                return Err("Production profile requires an explicit ResourceBudget".to_string());
            }
            (_, Some(budget)) => budget.validate()?,
            (_, None) => {}
        }

        Ok(())
    }

    /// Configure a Tokio runtime builder with the profile's worker limits.
    ///
    /// `Builder::build()` is async and runs inside an already-created Tokio
    /// runtime. CNF binaries that need the SDK to own Tokio worker sizing should
    /// create their process runtime through [`Self::tokio_runtime_builder`] and
    /// then call `opc_runtime::Builder::build()` inside that runtime.
    pub fn configure_tokio(&self, builder: &mut tokio::runtime::Builder) {
        builder.worker_threads(self.async_workers);
        builder.max_blocking_threads(self.blocking_threads);
    }

    /// Create a Tokio runtime builder configured from this profile.
    pub fn tokio_runtime_builder(&self) -> Result<tokio::runtime::Builder, String> {
        self.validate_resource_limits()?;

        let mut builder = tokio::runtime::Builder::new_multi_thread();
        builder.enable_all();
        self.configure_tokio(&mut builder);
        Ok(builder)
    }
}

#[cfg(test)]
mod tests {
    use super::{ResourceBudget, RuntimeMode, RuntimeProfile, SigintHandling};

    #[test]
    fn sigint_handling_enables_graceful_shutdown_matrix() {
        for mode in [RuntimeMode::Dev, RuntimeMode::Lab, RuntimeMode::Conformance] {
            assert!(SigintHandling::ModeDefault.enables_graceful_shutdown(mode));
        }
        for mode in [RuntimeMode::Production, RuntimeMode::Perf] {
            assert!(!SigintHandling::ModeDefault.enables_graceful_shutdown(mode));
        }

        for mode in [
            RuntimeMode::Dev,
            RuntimeMode::Lab,
            RuntimeMode::Production,
            RuntimeMode::Conformance,
            RuntimeMode::Perf,
        ] {
            assert!(SigintHandling::GracefulShutdown.enables_graceful_shutdown(mode));
            assert!(!SigintHandling::Disabled.enables_graceful_shutdown(mode));
        }
    }

    #[test]
    fn production_resource_limits_require_budget_and_valid_workers() {
        let mut profile = RuntimeProfile::production("pcf", uuid::Uuid::new_v4());
        assert_eq!(
            profile.validate_resource_limits().unwrap_err(),
            "Production profile requires an explicit ResourceBudget"
        );

        profile.budget = Some(ResourceBudget::default());
        profile.async_workers = 0;
        assert_eq!(
            profile.validate_resource_limits().unwrap_err(),
            "async_workers must be > 0 and <= 4096"
        );

        profile.async_workers = 2;
        profile.blocking_threads = 0;
        assert_eq!(
            profile.validate_resource_limits().unwrap_err(),
            "blocking_threads must be > 0 and <= 100,000"
        );
    }

    #[test]
    fn profile_builds_owned_tokio_runtime() {
        let mut profile = RuntimeProfile::conformance("runtime-owner-test");
        profile.async_workers = 2;
        profile.blocking_threads = 4;

        let runtime = profile
            .tokio_runtime_builder()
            .expect("valid runtime builder")
            .build()
            .expect("tokio runtime should build");

        assert_eq!(runtime.block_on(async { 42 }), 42);
    }
}
