# ADR 0005: Runtime Observability And Admin Probes

## Status

Accepted

## Date

2026-06-08

## Context

Production CNFs need consistent runtime health, readiness, metrics, alarm
visibility, and debug/admin routes. These surfaces must be shared and
redaction-safe, not reimplemented by each NF.

## Decision

Runtime observability is a shared SDK surface:

- `opc-runtime` owns liveness, readiness, startup, debug, and admin route
  semantics.
- Production and lab admin/probe/debug endpoints require bearer token
  authorization.
- `/metrics` exports Prometheus text through a shared `SdkMetrics` registry.
- Metrics use low-cardinality, redaction-safe labels.
- Runtime, ConfigBus, persistence, session store, NACM, and alarms report
  counters/gauges/histograms through the shared metrics surface.
- Runtime failures and drain failures raise SDK-managed alarms.

## Consequences

Downstream CNFs should wire the SDK runtime and metrics instead of creating
incompatible health/admin conventions.

Debug endpoints are production-controlled operational surfaces. They must never
expose raw configs, tokens, SQL, file paths, certificate material, subscriber
IDs, or other sensitive data.

## Evidence

- `crates/opc-runtime/src/admin.rs`
- `crates/opc-runtime/src/health.rs`
- `crates/opc-redaction/src/metrics.rs`
- `crates/opc-sdk-integration/tests/observability.rs`
- `docs/operator-readiness.md`

