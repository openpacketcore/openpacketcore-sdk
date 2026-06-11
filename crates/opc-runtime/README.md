# opc-runtime

OpenPacketCore CNF runtime chassis — standardized process startup, task supervision,
health probes, graceful shutdown, and testkit for deterministic time-based testing.

## Overview

This crate provides the shared runtime skeleton used by every OpenPacketCore CNF
(AMF, SMF, UPF, NRF, PCF, SEPP, SMSC, etc.). It standardizes:

- **Startup phases**: ordered initialization through `ProcessInit → TelemetryInit → SecurityInit → ConfigBootstrap → ResourcePreflight → ServiceBind → PeerWarmup → Ready`
- **Task supervision**: named, criticality-graded worker tasks with restart policies
- **Health model**: `/livez`, `/readyz`, `/startupz` probe semantics
- **Graceful shutdown**: SIGTERM drain with configurable grace period
- **Fake-clock testkit**: deterministic time-based testing without real-time delays

## RFC Reference

Owned by [RFC 008: CNF Runtime Chassis and Resource Governance](../../docs/rfc/008-cnf-runtime-chassis.md).

## Public API

```rust
// Run the CNF runtime with a profile and supervisor
pub async fn run(
    profile: RuntimeProfile,
    init: impl FnOnce(Supervisor, ShutdownToken) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>,
) -> Result<(), RuntimeError>

// Run the CNF runtime with explicit drain hooks
pub async fn run_with_hooks(
    profile: RuntimeProfile,
    drain_hooks: Vec<Arc<dyn DrainHook>>,
    init: impl FnOnce(Supervisor, ShutdownToken) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>,
) -> Result<(), RuntimeError>

// Builder pattern for initializing the runtime chassis with phase transitions
pub struct Builder { ... }
impl Builder {
    pub fn new(profile: RuntimeProfile) -> Self
    pub fn with_phases(self, phases: StartupPhases) -> Self
    pub fn with_phase_observer(self, observer: impl Fn(RuntimePhase) + Send + Sync + 'static) -> Self
    pub async fn build(self) -> Result<RuntimeHandle, RuntimeError>
}

// Runtime handle containing supervisor, phase, and shutdown utilities
pub struct RuntimeHandle { ... }
impl RuntimeHandle {
    pub fn supervisor(&self) -> &Supervisor
    pub fn shutdown_token(&self) -> &ShutdownToken
    pub async fn phase(&self) -> RuntimePhase
    pub async fn readiness(&self) -> Readiness
    pub async fn shutdown(&self)
}
```
