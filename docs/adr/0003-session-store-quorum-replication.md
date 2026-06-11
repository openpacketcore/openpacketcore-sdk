# ADR 0003: Session Store Quorum Replication

## Status

Accepted

## Date

2026-06-08

## Context

Authoritative telecom session state cannot rely on single-node storage,
wall-clock last-writer-wins, or best-effort replica repair. Session records need
monotonic fencing, compare-and-set semantics, TTL handling, watch resume
support, and stale replica recovery.

## Decision

Authoritative session HA is implemented as quorum ordered-log replication in
`QuorumSessionStore`.

The session store contract includes:

- Monotonic fences and CAS for authoritative writes.
- Durable ordered replication logs for lease acquire, renew, release, CAS,
  delete, TTL refresh, and batch operations.
- Idempotent replay using log position, generation, fence, and transaction ID.
- Majority-supported committed-prefix repair for stale or divergent replicas.
- Watch/change-stream resume cursors.
- Partial-quorum write rollback to prevent failed writes from resurrecting
  during later catch-up.
- Truthful capability reporting so standalone SQLite does not claim replicated
  behavior.

## Consequences

Standalone `SqliteSessionBackend` remains useful as a durable local backend,
but it is not HA. Production CNFs that need authoritative session HA must use
`QuorumSessionStore` or an equivalent replicated profile.

The SDK favors fail-closed reads over returning divergent session state when a
majority cannot agree.

## Evidence

- `crates/opc-session-store/src/quorum.rs`
- `crates/opc-session-store/src/sqlite.rs`
- `crates/opc-session-testkit/`
- `docs/ha-design.md`
- `docs/operator-readiness.md`

