# ADR 0006: Fail-Closed Fault Injection Validation

## Status

Accepted

## Date

2026-06-08

## Context

Happy-path tests are insufficient for SDK stability claims. Storage, KMS,
SPIFFE, consensus, session replication, runtime, and evidence release gates all
have failure modes where unsafe behavior can look like success unless tested
directly.

## Decision

The SDK validates production safety with explicit fault injection and chaos
tests:

- Persistence can simulate disk full, fsync/write failure, corrupt database,
  corrupt WAL, failed rollback target load, failed rollback point creation, and
  audit-chain corruption.
- Config and session HA are tested under partitions, crashes, stale leaders,
  stale fences, rejoin/catch-up, split-brain healing, and partial writes.
- SPIFFE and KMS are tested under expiry, rotation, bundle removal, timeout,
  and unavailability.
- Runtime and admin routes are tested for authentication, malformed requests,
  timeouts, and redaction.
- Release gates are tested for missing evidence, malformed JSON, dirty
  provenance, missing signatures, tampered bundles, and unsafe evidence values.

## Consequences

Test-only fault hooks are acceptable when explicitly gated and named as
dangerous test hooks. Production APIs should not expose fault injection knobs.

Regression tests must prefer fail-closed assertions: no publish, no partial
commit, no stale promotion, no sensitive error leak, and no unsafe readiness
claim.

## Evidence

- `crates/opc-sdk-integration/tests/fault_injection.rs`
- `crates/opc-security-testkit/`
- `crates/opc-session-testkit/`
- `crates/opc-evidence/tests/evidence_pipeline.rs`

