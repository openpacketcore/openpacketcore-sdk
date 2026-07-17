# opc-mgmt-audit

Audit-event contracts for management operations.

This crate defines management audit events and a sink trait for recording them.
It complements the durable config-bus commit log by covering allowed, denied,
failed, and non-config management operations.

## API Shape

Public API:

- `AuditEvent`, the structured event record.
- `AuditSink`, the synchronous fail-closed sink trait.
- `TracingAuditSink`, a best-effort sink that emits events through `tracing`.
- `AuditOperation`, `AuditOutcome`, `AuditReasonCode`, `AuditTxId`, and
  `SchemaNodePath`.
- Label-safe helpers: `label_safe_transport`, `label_safe_outcome`, and
  `label_safe_reason`.
- Principal and transport helpers: `principal_descriptor` and `transport_code`.
- `tracing_audit_events_dropped`, the dropped-event counter for tracing sinks.

Example:

```rust
use opc_mgmt_audit::{AuditSink, TracingAuditSink};

let sink: std::sync::Arc<dyn AuditSink> = std::sync::Arc::new(TracingAuditSink);
```

Audit schema paths are predicate-free and reason codes are bounded
machine-readable strings. Metric-label helpers sanitize unknown values through
the redaction helpers used elsewhere in the SDK.

## Relationships

- Consumed by gNMI, NETCONF, alarm, and config-management entry points.
- Uses `opc-config-model` principal/source types.
- Does not replace config-bus durable commit records.

## Status And Limits

Current scope:

- Stable event structure for management operations.
- Best-effort `tracing` sink for local development and integration tests.
- Label-safe metric helpers.

Production note:

- `TracingAuditSink` is not durable or tamper-evident. Production deployments
  should use `opc-mgmt-audit-store::DurableAuditSink`, which durably
  acknowledges the event through the reference SQLite profile.

## Durable Adapter

`opc-mgmt-audit-store` persists only this crate's existing structured fields.
It adds authenticated chaining, bounded retention/query pages, restart
verification, production storage preflight, and bounded worker acknowledgement
without moving storage dependencies into this core contract crate.

## Verification

Run:

```sh
cargo test -p opc-mgmt-audit
```
