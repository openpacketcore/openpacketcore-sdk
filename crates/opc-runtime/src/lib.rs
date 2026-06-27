#![deny(missing_docs)]
//! OpenPacketCore CNF runtime chassis.
//!
//! Provides standardized process startup, task supervision, health probes,
//! graceful shutdown, and testkit for deterministic time-based testing.
//!
//! # Required Listener Startup
//!
//! Required listeners should perform their bind or startup handshake inside
//! `Builder::try_with_init` before spawning the long-running supervised task.
//! Return a `RuntimeError` from that callback if the bind or handshake fails.
//! For readiness-gated listeners, call `Supervisor::set_readiness_gated` before
//! spawning the task and call `Supervisor::set_task_ready` only after the
//! listener is actually serving.
//!
//! # RFC Reference
//! Owned by [RFC 008: CNF Runtime Chassis and Resource Governance](../../docs/rfc/008-cnf-runtime-chassis.md).

pub mod admin;
pub mod bootstrap;
pub mod health;
pub mod metrics;
pub mod profile;
pub mod shutdown;
pub mod supervisor;
pub mod task;
pub mod testkit;

pub mod builder;
pub mod runtime;

#[cfg(test)]
mod tests;

pub use admin::ConfigVersionMetadata;
pub use bootstrap::BootstrapError;
pub use health::{HealthModel, Readiness, StartupPhase};
pub use profile::{ResourceBudget, RuntimeMode, RuntimeProfile, SigintHandling};
pub use shutdown::{DrainHook, ShutdownToken};
pub use supervisor::{MemoryLimiter, Supervisor};
pub use task::{
    Criticality, RestartPolicy, RuntimeError, ShutdownPolicy, TaskError, TaskHandle, TaskKind,
    TaskName, TaskSpec,
};
pub use testkit::{fake_clock, Clock, FakeClock, RealClock, Timestamp};

pub use builder::{Builder, StartupPhases, TryInitFn};
pub use runtime::{run, run_with_hooks, try_run, try_run_with_hooks, RuntimeHandle, RuntimePhase};
