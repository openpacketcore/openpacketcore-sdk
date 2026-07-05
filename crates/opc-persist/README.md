# opc-persist

SQLite-backed persistence, audit, consensus replication, and security-policy
storage for the OpenPacketCore management substrate.

This crate provides:

- `SqliteBackend`: durable and in-memory SQLite storage with audit-key checks,
  schema migration, WAL/preflight validation, and redaction-safe errors.
- `ConfigStore` implementations for append-only config commits, rollback
  points, confirmed-commit markers, and latest-state reads.
- `SqliteSecurityPolicyService`: encrypted staging, validation, application,
  rollback, metadata inspection, and audit for NACM security policies.
- NACM policy serialization for flat rules and RFC 8341-style group-scoped
  rule-lists, preserving `TrustedPrincipal.groups` evaluation after decrypting
  and recompiling stored policy.
- Break-glass session storage and approval checks backed by active NACM policy.
- Consensus types and TCP replication support for quorum-backed config storage.
- Mock and fault-injection stores used by SDK tests and downstream adapters.

Security-policy mutation remains fail-closed: callers must match the target
tenant, carry the `security-admin` role, and pass the active NACM
`security-admin` check on `/security:policy`. Group-scoped NACM rule-lists are
evaluated with groups resolved from signed principal policy, not transport
metadata.

The crate does not implement northbound gNMI, NETCONF, or gNSI transport
servers. Those layers adapt their verified principals and requests into the
storage and policy services exposed here.
