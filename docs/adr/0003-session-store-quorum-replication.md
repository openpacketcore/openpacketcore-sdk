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

- A validated immutable topology: stable logical replica IDs, canonical network
  endpoints, expected TLS identities, unique failure/backing identities, and one
  exact local logical ID. Logical IDs are never inferred from endpoint strings.
- Monotonic fences and CAS for authoritative writes.
- Durable ordered replication logs for lease acquire, renew, release, CAS,
  delete, TTL refresh, and batch operations.
- Idempotent replay using log position, generation, fence, and transaction ID.
- Majority-supported committed-prefix repair for stale or divergent replicas.
- Watch/change-stream resume cursors.
- Fail-closed partial-quorum write handling that never treats a failed write as
  committed and requires recovery evidence before later catch-up.
- Truthful capability reporting so standalone SQLite does not claim replicated
  behavior.
- Fresh, deadline- and work-bounded durable-readiness evidence from a distinct
  configured majority, independent of cached capability declarations.

Configured topology admission now rejects empty/even/undersized or over-31 HA sets,
missing or ambiguous self, duplicate declared identities, and duplicate
process-local adapter instances before I/O.
`ValidatedQuorumTopology::try_new_lab_singleton` is a
separate one-replica profile that reports `single-replica`, never HA. The
deprecated raw-vector constructor is non-operational and reports `unknown`.

This closes configured topology admission only. It does not prove that a
declared member is the authenticated peer. `probe_durable_readiness` now
supplies fresh, bounded point-in-time evidence without consulting cached
capabilities. Its report states `Ready`, `NoQuorum`, `TopologyInvalid`, or
`RecoveryRequired`; records configured, freshly reachable, agreeing, and
required voter counts plus the optional majority-visible prefix; and classifies
replica failures as `Transport`, `Authentication`, `Timeout`, `Protocol`,
`Backend`, `LogUnavailable`, `Divergent`, `RepairFailed`, or
`ProbeBudgetExceeded`. Authoritative quorum reads and writes repeat the same
store-level policy and assessment instead of trusting an earlier probe. Log
evidence is fetched in bounded adaptive pages, so the aggregate log need not
fit one wire frame.

Readiness repair is deliberately narrow: only a strict shorter prefix may have
the majority-visible suffix appended. Conflicting entries and longer minority
tails return `RecoveryRequired` without destructive rebuild. The prefix is
called majority-visible, not committed, because durable commit authority is not
yet established.

The current `QuorumSessionStore`/`opc-session-net` profile therefore remains
experimental, not a production HA profile. Protocol v2 supplies validated,
frame-bounded per-replica restore-scan transport, but its exact-version
handshake requires a coordinated v1-to-v2 upgrade. Authenticated replica
identity, durable commit authority, commit-proven repair, operator-safe fork
recovery, and bounded majority-authoritative restore remain open in #125,
#127–#129, and #133. Fixed-width wire DTOs and invariant-safe model decoding
remain #134/#135; oversized-TTL and zero-replication-sequence panic elimination
remain #137/#138.

## Consequences

Standalone `SqliteSessionBackend` remains useful as a durable local backend,
but it is not HA. Production CNFs need a separately qualified replicated
profile; the current `QuorumSessionStore`/`opc-session-net` combination is not
yet that profile.

The SDK favors fail-closed reads over returning divergent session state when a
majority cannot agree.

Capability/profile validation and fresh readiness have different scopes. The
former is static admission evidence. The latter is a bounded observation that
can become stale immediately, so a CNF must gate traffic continuously and each
authoritative operation must reassess quorum.

A product composes one descriptor per physical vote. For example, logical self
`epdg-app-0` may select the member whose dial endpoint is the full
`epdg-app-0.epdg-app-quorum.epdg-gateway.svc.cluster.local:7443`; the SDK does
not shorten the FQDN or compare it with the logical ID.

## Evidence

- `crates/opc-session-store/src/quorum.rs`
- `crates/opc-session-store/src/readiness.rs`
- `crates/opc-session-store/src/topology.rs`
- `crates/opc-session-store/tests/quorum_durable_readiness.rs`
- `crates/opc-session-store/tests/quorum_topology.rs`
- `crates/opc-session-net/tests/three_node_quorum.rs`
- `crates/opc-amf-lite/tests/amf_lite_tests.rs`
- `crates/opc-session-store/src/sqlite/mod.rs`
- `crates/opc-session-testkit/`
- `docs/ha-design.md`
- `docs/operator-readiness.md`
