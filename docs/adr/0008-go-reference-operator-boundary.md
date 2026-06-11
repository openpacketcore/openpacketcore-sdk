# ADR 0008: Go Reference Operator Boundary

## Status

Accepted

## Date

2026-06-08

## Context

The original repository direction is polyglot: SDK core behavior is Rust, while
Kubernetes operator integration should use Go `controller-runtime`, which is the
first-class Kubernetes operator ecosystem. At the same time, this repository is
an SDK, not an AMF/SMF/UPF product operator.

## Decision

The repository includes a Go reference operator harness under
`operators/sdk-reference-operator`.

The Go harness demonstrates:

- CRD API versions and conversion wiring.
- Validating webhook integration.
- Controller reconciliation shape and status updates.
- Kustomize/RBAC/cert-manager/manager manifests.
- A Go-to-Rust JSON CLI bridge to `operator-lifecycle-cli`.

The harness is explicitly not a production CNF operator and does not encode
product-specific reconciliation.

## Consequences

Downstream CNF teams get a concrete Go integration pattern without importing
product behavior into the SDK repository.

Reference tests use Go unit tests, fake-client controller/webhook tests,
rendered Kustomize manifests, and Rust CLI contract tests. Product CNF
operators must add envtest, kind, and real-cluster end-to-end tests around their
own reconciliation logic.

Manager images must package both the Go manager binary and the Rust
`operator-lifecycle-cli`, or set `OPERATOR_LIFECYCLE_CLI_PATH` to a valid CLI
location.

## Evidence

- `operators/sdk-reference-operator/`
- `crates/operator-lifecycle-cli/`
- `docs/operator-readiness.md`
- `docs/implementation-status.md`

