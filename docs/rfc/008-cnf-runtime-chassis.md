# OPC-SDK-RFC-008: CNF Runtime Chassis and Resource Governance

**Status**: Draft for Implementation  
**Version**: 1.0.0  
**Date**: 2026-05-19  
**Audience**: NF implementers, platform engineers, SREs, security reviewers

## 1. Abstract

This RFC defines the common Rust runtime chassis used by every OpenPacketCore
CNF. It standardizes process startup, task supervision, shutdown, health
probes, admin endpoints, runtime pools, resource budgets, panic policy,
configuration bootstrap, signal handling, telemetry initialization, memory
behavior, and operational debug surfaces.

The goal is that AMF, SMF, UPF, NRF, PCF, SEPP, SMSC, and all other CNFs share
one predictable runtime skeleton instead of each inventing its own Tokio setup,
shutdown behavior, health semantics, and task lifecycle.

## 2. Scope

### 2.1 In Scope

- Runtime initialization.
- Tokio worker and blocking pool configuration.
- Task supervision and cancellation.
- Startup and readiness phases.
- Graceful shutdown and drain.
- Health and admin HTTP endpoints.
- Runtime resource budgets and backpressure hooks.
- Panic and fatal-error policy.
- Metrics, logging, and tracing bootstrap.
- Memory, allocator, and OOM behavior.
- Common CLI/env/bootstrap contract.

### 2.2 Out of Scope

- NF-specific protocol logic.
- Kubernetes controller behavior. See RFC 009.
- Node/NIC scheduling and SR-IOV contracts. See RFC 011.
- Config commit semantics. See RFC 001.

## 3. Design Goals

### 3.1 Security

- Fail closed when required bootstrap security material is unavailable.
- Keep debug endpoints disabled or authorization-gated in production.
- Ensure panic output and fatal-error reports are redacted.
- Make shutdown safe: no partial config writes, key leaks, or unaudited
  emergency exits.

### 3.2 Performance

- Avoid runtime-pool contention between management, control, crypto, and
  data-plane work.
- Bound queues, tasks, memory, and blocking work.
- Make health checks cheap and non-blocking.
- Provide predictable drain behavior under load.

### 3.3 Maintainability

- Provide one reusable `opc-runtime` crate.
- Make lifecycle phases explicit and testable.
- Provide standard task naming and metrics.
- Keep per-NF custom code in callbacks, not in process scaffolding.

### 3.4 Functionality

- Support control-plane, data-plane, and library-like CNF profiles.
- Support local developer mode and production mode.
- Support graceful restart, termination, and Kubernetes probe integration.
- Support runtime introspection without exposing secrets.

## 4. Runtime Crate

The shared crate is `opc-runtime`.

```text
crates/opc-runtime/
  src/
    lib.rs
    bootstrap.rs
    profile.rs
    supervisor.rs
    task.rs
    shutdown.rs
    health.rs
    admin.rs
    resources.rs
    panic.rs
    telemetry.rs
    memory.rs
    signals.rs
    testkit.rs
```

Every NF binary SHOULD be a thin wrapper around `opc_runtime::run`.

## 5. Runtime Profile

```rust
pub struct RuntimeProfile {
    pub mode: RuntimeMode,
    pub nf_kind: NetworkFunctionKind,
    pub instance_id: InstanceId,
    pub async_workers: WorkerCount,
    pub blocking_threads: ThreadLimit,
    pub crypto_threads: ThreadLimit,
    pub management_threads: ThreadLimit,
    pub max_tasks: usize,
    pub max_queued_bytes: usize,
    pub shutdown_grace: Duration,
    pub drain_timeout: Duration,
}
```

Profiles:

- `dev`: permissive, local files, debug endpoints enabled on loopback.
- `lab`: production-like, explicit waivers allowed.
- `production`: fail closed, debug gated, strict resource limits.
- `conformance`: deterministic test profile.
- `perf`: optimized benchmark profile with fixed CPU/resource assumptions.

## 6. Startup State Machine

Every CNF starts through:

| Phase | Purpose |
| :--- | :--- |
| `ProcessInit` | parse CLI/env, install panic hook, initialize logging |
| `TelemetryInit` | metrics/tracing/logging exporters |
| `SecurityInit` | identity, trust bundles, key providers |
| `ConfigBootstrap` | load initial config through RFC 001 |
| `ResourcePreflight` | verify CPU, memory, filesystem, devices |
| `ServiceBind` | bind listeners but do not report ready |
| `PeerWarmup` | optional NRF registration, discovery, backend connection |
| `Ready` | readiness probe returns success |
| `Draining` | termination accepted, new work limited |
| `Stopped` | all supervised tasks exited |

Startup MUST fail closed in production if any required phase fails.

## 7. Task Supervision

### 7.1 Task Model

All long-lived tasks MUST be registered with the supervisor:

```rust
pub struct TaskSpec {
    pub name: TaskName,
    pub kind: TaskKind,
    pub criticality: Criticality,
    pub restart: RestartPolicy,
    pub shutdown: ShutdownPolicy,
}
```

Task kinds:

- `listener`
- `protocol-worker`
- `session-worker`
- `management-worker`
- `background-sync`
- `metrics-exporter`
- `watcher`
- `timer`

### 7.2 Criticality

| Criticality | Behavior on Failure |
| :--- | :--- |
| `fatal` | Transition CNF to fatal shutdown |
| `degrade` | Mark degraded and optionally restart |
| `best-effort` | Log/metric and continue |

Critical task failures MUST be visible through readiness and alarm state.

### 7.3 Restart Policy

Restart policy MUST include:

- max restarts per window,
- backoff,
- jitter,
- failure classification,
- whether restart is allowed after config changes.

Unbounded task restart loops are forbidden.

## 8. Runtime Pool Isolation

The runtime MUST expose separate execution domains:

- async I/O workers,
- blocking/CPU pool,
- crypto pool,
- management pool,
- data-plane workers where applicable.

Data-plane CNFs SHOULD integrate with RFC 011 CPU pinning and IRQ affinity.
Management-plane work MUST NOT execute on data-plane pinned workers.

## 9. Resource Governance

### 9.1 Budgets

Each CNF declares:

```rust
pub struct ResourceBudget {
    pub max_heap_bytes: Option<usize>,
    pub max_tasks: usize,
    pub max_channels: usize,
    pub max_queue_bytes: usize,
    pub max_request_body_bytes: usize,
    pub max_open_files: usize,
    pub max_backend_connections: usize,
}
```

Budgets MUST be profile-configurable and observable.

### 9.2 Backpressure

The runtime provides shared primitives:

- bounded mpsc channels,
- byte-accounted queues,
- weighted semaphores,
- admission guards,
- deadline propagation,
- cancellation tokens.

Unbounded channels are forbidden in production runtime code unless an RFC 006
waiver exists.

### 9.3 Memory Behavior

The runtime SHOULD:

- expose allocator metrics where available,
- support an optional hardened allocator profile,
- fail fast on configured memory-budget breach,
- avoid memory-heavy debug dumps in production,
- support heap profile endpoints only under explicit authorization.

## 10. Shutdown and Drain

### 10.1 Signals

The runtime MUST handle:

- `SIGTERM`: graceful drain.
- `SIGINT`: graceful drain in dev, configurable in production.
- fatal internal errors: controlled shutdown path when possible.

### 10.2 Drain Sequence

Drain order:

1. Stop accepting new external work.
2. Mark readiness false.
3. Notify NRF/deregister where applicable.
4. Stop management writes except emergency recovery.
5. Drain protocol workers up to timeout.
6. Flush audit and evidence breadcrumbs.
7. Checkpoint local state where applicable.
8. Shut down listeners and background tasks.

Each NF can add steps but MUST preserve safety ordering.

### 10.3 Kubernetes Integration

`terminationGracePeriodSeconds` MUST be at least `shutdown_grace` plus probe
latency margin. PreStop hooks MAY call admin drain but MUST NOT be the only
drain mechanism.

## 11. Health and Admin Surface

### 11.1 Endpoints

Default admin listener:

- `/livez`
- `/readyz`
- `/startupz`
- `/metrics`
- `/debug/runtime` gated
- `/debug/tasks` gated
- `/debug/config-version` gated

Production debug endpoints MUST require authorization or be disabled.

### 11.2 Health Semantics

`/livez` means the process event loop is alive. It MUST NOT depend on external
peers.

`/readyz` means the CNF can serve its intended role. It SHOULD include:

- config applied,
- critical tasks healthy,
- required listeners bound,
- required security material valid,
- required backends reachable according to NF policy.

## 12. Panic and Fatal Error Policy

### 12.1 Panics

Production builds MUST install a panic hook that:

- redacts secrets,
- records task name,
- increments fatal metrics,
- emits a structured fatal log,
- triggers supervisor policy.

Panics in parser or protocol handlers are bugs and MUST be covered by RFC 005
fuzzing regression tests.

### 12.2 `unwrap` and `expect`

Runtime and NF code MUST avoid `unwrap` and `expect` outside tests, build
scripts, and explicitly justified invariants. Justifications MUST be grep-able
and evidence-linked.

## 13. Bootstrap Contract

CLI/env values are limited to bootstrap concerns:

- config bootstrap source,
- management bind address,
- admin bind address,
- production/dev mode,
- identity socket path,
- tracing exporter endpoint,
- initial log level,
- feature gates for explicit waivers.

Dense protocol behavior MUST come from canonical config, not env vars.

## 14. Telemetry Initialization

The runtime initializes:

- structured JSON logging,
- OpenTelemetry tracing,
- Prometheus metrics,
- build info,
- runtime profile info,
- panic/fatal counters.

Required metrics:

- `opc_runtime_build_info{nf,version,git_sha}`
- `opc_runtime_tasks{nf,kind,state}`
- `opc_runtime_task_restarts_total{nf,task}`
- `opc_runtime_queue_depth{nf,queue}`
- `opc_runtime_queue_bytes{nf,queue}`
- `opc_runtime_shutdown_total{nf,reason}`
- `opc_runtime_panic_total{nf,task}`
- `opc_runtime_memory_bytes{nf,kind}`
- `opc_runtime_ready{nf}`

## 15. Time and Clocks

The runtime MUST provide a clock abstraction for tests:

```rust
pub trait Clock: Send + Sync {
    fn now(&self) -> Timestamp;
    fn monotonic(&self) -> Instant;
}
```

Security expiry and audit timestamps use wall clock plus monotonic sequencing
where required. Timers use monotonic time.

## 16. Module Ownership

| Module | Responsibility |
| :--- | :--- |
| `opc-runtime-bootstrap` | CLI/env/profile loading |
| `opc-runtime-supervisor` | task registry, restart, failure policy |
| `opc-runtime-shutdown` | signal handling and drain orchestration |
| `opc-runtime-health` | health model and probe endpoints |
| `opc-runtime-admin` | gated debug/admin routes |
| `opc-runtime-resources` | budgets, queues, semaphores |
| `opc-runtime-telemetry` | logging, metrics, tracing init |
| `opc-runtime-testkit` | fake clock, fake tasks, shutdown tests |

Agents implementing NF business logic should consume `opc-runtime`; they should
not fork startup/shutdown code.

## 17. Testing Requirements

### 17.1 Unit Tests

- Startup state transitions.
- Task restart/backoff.
- Fatal vs degraded task failure.
- Bounded queue byte accounting.
- Panic hook redaction.
- Health state aggregation.
- Clock abstraction.

### 17.2 Integration Tests

- SIGTERM drains in order.
- Readiness flips false before listeners stop.
- NRF deregistration hook is called during drain.
- Background task failure degrades readiness.
- Debug endpoints are disabled or authorized in production.

### 17.3 Fault Injection

- Hung task on shutdown.
- Task restart loop.
- Telemetry exporter unavailable.
- Missing identity socket.
- Memory budget breach.
- Queue saturation.
- Panic in a worker task.

### 17.4 Performance Gates

- `/livez` p99 under 1 millisecond in healthy process.
- Supervisor task spawn overhead negligible relative to direct spawn in NF
  startup tests.
- Runtime metrics collection does not allocate on every scrape for static
  metric sets.
- Queue admission overhead p99 under 10 microseconds.

## 18. Acceptance Criteria

This RFC is implemented when:

1. Every NF binary uses `opc-runtime` for startup, supervision, health, and
   shutdown.
2. Long-lived tasks are supervised and named.
3. Readiness semantics are consistent across CNFs.
4. Shutdown drains safely and predictably.
5. Production debug endpoints are gated or disabled.
6. Runtime pools and queues are bounded.
7. Panic and fatal-error handling is redacted and observable.
8. Runtime behavior is covered by shared testkit and fault injection tests.
