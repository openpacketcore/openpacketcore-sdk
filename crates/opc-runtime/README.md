# opc-runtime

CNF runtime chassis for startup, supervision, health, shutdown, and resource
governance.

## Purpose

`opc-runtime` provides the process-level runtime frame for OpenPacketCore CNFs:
startup phases, supervised tasks, readiness gates, graceful drain, admin health,
resource budgets, source admission, and deterministic test clocks.

## API Shape

- `Builder::new(profile)` creates a runtime builder. It supports startup phase
  hooks, init callbacks, alarm manager injection, clock injection, drain hooks,
  and `build`.
- `RuntimeHandle` exposes phase, readiness, shutdown, supervisor, config
  version metadata, alarm manager, and shutdown token access.
- `RuntimeProfile`, `RuntimeMode`, `ResourceBudget`, and `SigintHandling`
  define mode-specific runtime behavior.
- `Supervisor` registers and spawns `TaskSpec` tasks with `Criticality`,
  `RestartPolicy`, `ShutdownPolicy`, task kind, heartbeat timeout, and memory
  pressure checks.
- Health APIs include `HealthModel`, `HealthGateSet`, `HealthGate`,
  `GateStatus`, `Readiness`, `StartupPhase`, and `known_gates`.
- Shutdown APIs include `ShutdownToken`, `ShutdownPhase`, and `DrainHook`.
- Admission APIs include `SourceTokenBucketPolicy`,
  `SourceTokenBucket`, and `SourceAdmissionDecision`.
- UDP helpers expose destination-address metadata where the platform supports
  it.
- Feature `observability` adds `init_observability_logging`.

```rust,no_run
use opc_runtime::{Builder, RuntimeProfile};

async fn start() -> Result<opc_runtime::RuntimeHandle, opc_runtime::RuntimeError> {
    let profile = RuntimeProfile::dev("nrf");
    let runtime = Builder::new(profile).build().await?;
    Ok(runtime)
}
```

## Relationships

- Used by AMF-lite and CNF crates as the process lifecycle owner.
- Optional `observability` integration delegates logging setup to
  `opc-observability`.
- Alarm integration composes with `opc-alarm` through injected shared managers.

## Status Notes

- `RuntimeMode::Production` and `RuntimeMode::Conformance` fail closed when
  required bootstrap material is missing.
- Dev, Lab, and Conformance modes allow debug endpoints without production
  gating; Production and Perf require debug surfaces to be gated or disabled.
- Empty supervisors are not ready.
- Memory-limit pressure can force readiness to NotReady.
- AMF/SMF/UPF dev, conformance, and production profiles require an NRF drain
  hook.

## Roadmap

- Keep listener startup and shutdown semantics documented in the crate root.
- Add runtime surfaces only when they can be supervised, health-gated, and
  tested deterministically.
- Keep optional integrations feature-gated.

## Verification

- Source checked: `Cargo.toml`, `src/lib.rs`, builder, runtime, supervisor,
  health, profile, shutdown, admission, UDP, admin, and tests.
- Run with: `cargo test -p opc-runtime`.

## License

Licensed under the [Apache License, Version 2.0](../../LICENSE).
