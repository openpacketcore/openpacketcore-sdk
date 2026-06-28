#![deny(missing_docs)]
//! OpenPacketCore CNF runtime chassis.
//!
//! Provides standardized process startup, task supervision, health probes,
//! graceful shutdown, and testkit for deterministic time-based testing.
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
pub use health::{
    known_gates, GateImpact, GateName, GateStatus, HealthGate, HealthGateSet, HealthModel,
    Readiness, StartupPhase,
};
pub use profile::{ResourceBudget, RuntimeMode, RuntimeProfile, SigintHandling};
pub use shutdown::{DrainHook, ShutdownToken};
pub use supervisor::{MemoryLimiter, Supervisor};
pub use task::{
    Criticality, RestartPolicy, RuntimeError, ShutdownPolicy, TaskError, TaskHandle, TaskKind,
    TaskName, TaskSpec,
};
pub use testkit::{fake_clock, Clock, FakeClock, RealClock, Timestamp};

pub use builder::{Builder, StartupPhases};
pub use runtime::{run, run_with_hooks, RuntimeHandle, RuntimePhase};
