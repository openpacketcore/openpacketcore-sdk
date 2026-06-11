//! OpenPacketCore Testbed and Simulator Framework
//!
//! Shared scenario DSL, virtual time, assertions, fixture provenance, and
//! simulator building blocks for conformance testing. See RFC 012.
//!
//! All NF testkits SHOULD build on this crate rather than inventing isolated
//! mocks.

#![forbid(unsafe_code)]

pub mod assertions;
pub mod error;
pub mod evidence;
pub mod fixtures;
pub mod runner;
pub mod scenario;
mod schema;
pub mod simulators;
pub mod virtual_time;

// Re-exports for convenience (populated as modules are implemented).
// Use explicit names to avoid ambiguous glob warnings across modules.
pub use assertions::{evaluate, Assertion, AssertionOutcome};
pub use error::TestbedError;
pub use evidence::{ScenarioEvidence, ScenarioOutcome};
pub use fixtures::{FixtureProvenance, FixtureRegistry};
pub use runner::{
    HardwareLabRunner, HardwareLabRunnerConfig, KindRunner, KindRunnerConfig, LocalRunner,
};
pub use scenario::{NfSpec, Scenario, Step, Topology, DSL_VERSION};
pub use virtual_time::{Clock, VirtualClock};

// simulators::* intentionally not glob-reexported; use opc_testbed::simulators::...
