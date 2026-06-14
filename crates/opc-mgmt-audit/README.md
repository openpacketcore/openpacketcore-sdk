# opc-mgmt-audit

Management-plane audit event model and sink for the OpenPacketCore gNMI/NETCONF
servers.

`opc-config-bus` durably records *committed* config changes, but the spec
requires auditing **every** management operation — including the failed and
**denied** ones that never produce a commit (NACM denials, validation failures,
rejected reads). This crate is that complementary sink.

`AuditEvent` captures SDK request id, principal, transport, operation, outcome,
the touched **schema-node paths** (predicate-free, so no list-key *values* leak
into the audit), and the transaction id when one exists. Tenant and principal
descriptor are derived from `TrustedPrincipal`; transport is the SDK
`TransportType`, not a free-form string. Outcomes carry stable machine codes
(`AuditReasonCode`, validated to a bounded machine-code alphabet), never
free-form messages.

`AuditSink` is the pluggable seam. It returns a payload-free `AuditError` so
callers can fail closed when an operation must not proceed without an audit
record. `TracingAuditSink` is a working default that emits a structured event on
the dedicated `opc_mgmt_audit` tracing target; a CNF that needs a durable,
tamper-evident trail wires an `opc-persist`-backed sink.

Audit is a *privileged* record (it legitimately names the principal); it is
distinct from a redaction-scrubbed diagnostic bundle. This crate does not emit
metrics, but it exposes label-safe helpers for outcome, reason, and transport;
principal and request id must not be used as metric labels.
