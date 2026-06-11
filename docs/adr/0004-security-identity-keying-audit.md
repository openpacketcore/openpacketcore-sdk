# ADR 0004: Security Identity, Keying, And Audit Integrity

## Status

Accepted

## Date

2026-06-08

## Context

The SDK needs reusable production security substrates rather than bespoke
per-CNF wiring. Identity, mTLS transport, key retrieval, audit redaction, and
tamper evidence must be consistent across config, session, persistence, alarm,
and operator-facing paths.

## Decision

Production security uses explicit shared adapters:

- `opc-identity` watches SPIFFE SVIDs and trust bundles.
- `opc-tls` builds reloadable mTLS client/server configurations from identity
  material.
- `opc-key` provides durable `KmsKeyProvider` adapters over authenticated KMS
  transports or local Unix-socket agents.
- Memory key providers remain deterministic test/conformance adapters.
- Persistence audit records redact sensitive values before storage and before
  hash-chain/HMAC material is calculated.
- Alarm administration uses NACM-backed authorization and durable audit sinks.

## Consequences

Production deployments must supply real identity and KMS infrastructure.
Unauthenticated TCP KMS and in-memory keys are not production key sources.

Security failures should fail closed and surface sanitized errors rather than
leaking paths, SQL details, PEM material, keys, subscriber identifiers, or
network addresses.

## Evidence

- `crates/opc-identity/`
- `crates/opc-tls/`
- `crates/opc-key/`
- `crates/opc-persist/src/backend.rs`
- `crates/opc-alarm/src/nacm_adapter.rs`
- `crates/opc-alarm/src/persist_adapter.rs`

