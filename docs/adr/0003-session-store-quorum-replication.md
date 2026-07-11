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

The target architecture for authoritative session HA is quorum ordered-log
replication in `QuorumSessionStore`.

The target session-store contract includes:

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

The current `QuorumSessionStore`/`opc-session-net` profile is experimental, not
a production HA profile. Protocol v2 supplies validated, frame-bounded
per-replica restore-scan transport, but its exact-version handshake requires a
coordinated v1-to-v2 upgrade. Valid topology, fresh-quorum readiness,
authenticated replica identity, durable commit authority, commit-proven
repair, operator-safe fork recovery, and bounded majority-authoritative
restore remain open in #123–#125, #127–#129, and #133. Fixed-width wire DTOs
and invariant-safe model decoding remain #134/#135.

## Consequences

Standalone `SqliteSessionBackend` remains useful as a durable local backend,
but it is not HA. Production CNFs need a separately qualified replicated
profile; the current `QuorumSessionStore`/`opc-session-net` combination is not
yet that profile.

The SDK favors fail-closed reads over returning divergent session state when a
majority cannot agree.

## Evidence

- `crates/opc-session-store/src/quorum.rs`
- `crates/opc-session-store/src/sqlite/mod.rs`
- `crates/opc-session-testkit/`
- `docs/ha-design.md`
- `docs/operator-readiness.md`
