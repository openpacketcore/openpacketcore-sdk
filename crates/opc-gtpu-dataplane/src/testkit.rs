//! Structural consumer fixtures, without kernel or TrafficReady authority.
//!
//! These fixtures run the real protected selector coordinator against an
//! isolated simulated backend. They never issue trusted traffic proofs or
//! qualify Linux forwarding, cancellation of kernel IO, or packet continuity.

pub use crate::ebpf::grouped_simulation::GroupedGtpuDataplaneSimulation;
