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
//! # Shutdown Listener Timing
//!
//! Traffic listeners should stop accepting new external traffic when shutdown
//! is requested, or when their domain-specific no-new-work phase begins.
//! Management and admin readiness endpoints may remain alive until
//! [`ShutdownPhase::ProtocolDraining`] so readiness=false and drain state remain
//! observable during the shutdown observation window.
//!
//! [`ShutdownPhase::ManagementStopped`] means mutable management operations and
//! writes have stopped. It does not require every management, admin, or
//! readiness listener task to exit at that phase. Long-running protocol and
//! session workers should honor their supervised task shutdown token and drain
//! within the runtime drain timeout. Products may choose stricter behavior, but
//! should document it because it affects Kubernetes and OpenShift probe
//! observability.
//!
//! # RFC Reference
//! Owned by [RFC 008: CNF Runtime Chassis and Resource Governance](../../docs/rfc/008-cnf-runtime-chassis.md).

pub mod admin;
pub mod admission;
pub mod bootstrap;
pub mod health;
pub mod metrics;
pub mod profile;
pub mod shutdown;
pub mod supervisor;
pub mod task;
pub mod testkit;
pub mod udp;

pub mod builder;
pub mod runtime;

#[cfg(test)]
mod tests;

pub use admin::ConfigVersionMetadata;
pub use admission::{
    SourceAdmissionDecision, SourceTokenBucket, SourceTokenBucketPolicy,
    SourceTokenBucketPolicyError,
};
pub use bootstrap::BootstrapError;
pub use health::{
    known_gates, GateImpact, GateName, GateStatus, HealthGate, HealthGateSet, HealthModel,
    Readiness, StartupPhase,
};
pub use profile::{ResourceBudget, RuntimeMode, RuntimeProfile, SigintHandling};
pub use shutdown::{DrainHook, ShutdownPhase, ShutdownToken};
pub use supervisor::{MemoryLimiter, Supervisor};
pub use task::{
    Criticality, RestartPolicy, RuntimeError, ShutdownPolicy, TaskError, TaskHandle, TaskKind,
    TaskName, TaskSpec,
};
pub use testkit::{fake_clock, Clock, FakeClock, RealClock, Timestamp};
pub use udp::{
    bind_udp_socket_with_destination_metadata, recv_udp_datagram_with_destination,
    UdpDestinationMetadataSocket, UdpDestinationMetadataSupport, UdpLocalDestination,
    UdpLocalDestinationStatus, UdpLocalDestinationUnavailableReason, UdpReceivedDatagram,
};

pub use builder::{Builder, StartupPhases, TryInitFn};
pub use runtime::{run, run_with_hooks, try_run, try_run_with_hooks, RuntimeHandle, RuntimePhase};

/// Build an `init_logging` callback that installs `opc-observability`.
///
/// The returned closure is intended for [`StartupPhases::init_logging`] and
/// runs during [`RuntimePhase::ProcessInit`].
#[cfg(feature = "observability")]
#[must_use]
pub fn init_observability_logging(
    directive: Option<&str>,
) -> Box<dyn Fn() -> Result<(), BootstrapError> + Send + Sync> {
    let directive = directive.map(str::to_string);
    Box::new(move || {
        opc_observability::init(directive.as_deref())
            .map_err(|err| BootstrapError::Env(Box::new(err)))
    })
}
