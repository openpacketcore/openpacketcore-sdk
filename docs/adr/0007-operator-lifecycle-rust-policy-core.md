# ADR 0007: Operator Lifecycle Rust Policy Core

## Status

Accepted

## Date

2026-06-08

## Context

The SDK is not a product operator, but downstream CNF operators need common
policy decisions for compatibility, admission, configuration apply, migration,
drain, rollback, and fleet status. Those policy decisions should be reusable
from Rust SDK code and Go Kubernetes operators.

## Decision

Operator lifecycle policy lives in Rust SDK crates:

- `operator-lifecycle` owns lifecycle phases, admission checks, compatibility
  matrix policy, config-apply decisions, and rollback constraints.
- `operator-controller` owns deterministic conversion helpers, migration plan
  execution, drain client orchestration, and multi-cluster status aggregation.
- Policy functions use structured inputs/outputs and fail closed on unknown,
  malformed, stale, or unsupported state.
- Error messages are sanitized before crossing operator or webhook boundaries.

## Consequences

The SDK can expose consistent policy decisions to multiple operator
implementations without forcing all Kubernetes code into Rust.

Rust lifecycle crates do not deploy workloads by themselves. Product CNF
operators still own reconciliation of Deployments, StatefulSets, Services,
protocol-specific CRDs, and live cluster behavior.

## Evidence

- `crates/operator-lifecycle/`
- `crates/operator-controller/`
- `crates/operator-lifecycle-cli/`
- `docs/operator-readiness.md`

