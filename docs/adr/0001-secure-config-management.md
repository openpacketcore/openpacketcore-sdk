# ADR 0001: Secure Config Management

## Status

Accepted

## Date

2026-06-08

## Context

The SDK exposes shared configuration management primitives that downstream CNFs
will use for production configuration changes. Early helper APIs made it too
easy to wire allow-all authorization or treat commit-confirmed behavior as a
test-only convention.

For carrier deployments, configuration writes must be explicit, authorized,
recoverable, and auditable. Pending configuration must either be confirmed
before its deadline or roll back to a confirmed point without silently accepting
unsafe state.

## Decision

Configuration management is secure by default:

- Production-facing `ConfigBus` constructors require an explicit
  `ConfigAuthorizer`.
- Allow-all construction is limited to clearly named dev/test helpers.
- Commit-confirmed state is persisted durably with deadline metadata.
- Expired pending commits roll back to a previous confirmed configuration.
- Failed rollback or failed confirmation fences the bus into recovery-required
  state instead of allowing further writes.
- Configuration audit records are persisted after redaction and protected by a
  hash chain/HMAC.

## Consequences

Downstream CNFs must provide an authorization adapter rather than relying on SDK
defaults. Tests can still use dev-only allow-all constructors, but production
call sites are visibly different.

Rollback and recovery behavior is now part of the SDK contract. Operators can
recover from failed commits, but they cannot pretend a pending or failed commit
is a confirmed production state.

## Evidence

- `crates/opc-config-bus/src/lib.rs`
- `crates/opc-persist/src/backend.rs`
- `crates/opc-persist/tests/persist.rs`
- `docs/implementation-status.md`

