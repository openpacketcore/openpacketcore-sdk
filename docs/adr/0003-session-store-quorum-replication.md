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
- One public 365-day maximum for `Duration`-based session refresh and lease
  TTLs, with zero accepted as immediate expiry and exact checked deadline
  arithmetic at every direct, nested, persistence, quorum, and transport
  boundary.
- Idempotent replay using log position, generation, fence, and transaction ID.
- Commit-proven, majority-supported repair for stale or divergent replicas as
  a target contract; #128/#129 remain open and current automatic repair is
  limited to strict shorter prefixes.
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

Protocol v3 adds authenticated replica identity. One immutable
`SessionReplicationManifest` combines a cluster ID, an operator-controlled
configuration generation, and the complete descriptor set into an
order-independent SHA-256 configuration ID. Production client and server
constructors accept only opaque authenticated TLS configs. Before backend
dispatch, both sides extract the canonical SPIFFE URI from the live certificate
and require it to match the manifest member's stable `ReplicaId`, expected
opposite replica, cluster, and configuration ID. The client also verifies that
the server echoes its fresh challenge. DNS/FQDN/IP
aliases remain routing inputs only. There is no production v2 fallback.
TLS session caches, tickets, resumption, early data, and 0-RTT are disabled;
every reconnect performs a full mutual-TLS certificate exchange so rotated
SVIDs cannot inherit cached replica authority.

That reconnect rule is necessary but not sufficient for production rotation.
The qualified CNF/operator profile must rotate workload certificates and trust
bundles seamlessly, without interrupting session service, while proving trust
overlap, revocation, retirement of long-lived connections, reconnect-storm
behavior, and a documented maximum authentication age. This evidence remains
open in #143. Session/lease TTL is an application-state lifetime and does not
set certificate expiry, trust-bundle validity, or authentication age.

Authenticated remote adapters expose a `BackendPeerBinding` to topology
admission. The admitted member must match the binding's local and remote IDs,
expected TLS identity, local and remote descriptor fingerprints, member count,
and shared configuration scope. This evidence connects topology composition to
the transport contract; a local in-process backend may remain unbound, and the
manifest does not prove physical-store provenance.

`probe_durable_readiness` supplies separate fresh, bounded point-in-time
evidence without consulting cached capabilities. Its report states `Ready`,
`NoQuorum`, `TopologyInvalid`, or `RecoveryRequired`; records configured,
freshly reachable, agreeing, and required voter counts plus the optional
majority-visible prefix; and classifies replica failures as `Transport`,
`Authentication`, `Timeout`, `Protocol`, `Backend`, `LogUnavailable`,
`Divergent`, `RepairFailed`, or `ProbeBudgetExceeded`. Authoritative quorum
reads and writes repeat the same store-level policy and assessment instead of
trusting an earlier probe. Log evidence is fetched in bounded adaptive pages,
so the aggregate log need not fit one wire frame.

Readiness repair is deliberately narrow: only a strict shorter prefix may have
the majority-visible suffix appended. Conflicting entries and longer minority
tails return `RecoveryRequired` without destructive rebuild. The prefix is
called majority-visible, not committed, because durable commit authority is not
yet established.

The current `QuorumSessionStore`/`opc-session-net` profile therefore remains
experimental, not a production HA profile. Protocol v3 supplies authenticated,
frame-bounded per-replica transport, but its exact-version handshake and ALPN
require a coordinated v2-to-v3 stop/upgrade/start; mixed fleets are not
supported. This identity binding is not consensus or fork recovery. Durable
commit authority, commit-proven repair, operator-safe fork recovery, and
bounded majority-authoritative restore remain open in #127–#129 and #133.
Fixed-width wire DTOs and invariant-safe model decoding remain #134/#135;
checked TTL rejection is implemented under #137, and malformed sequence zero,
checked increment, rebuild-prefix, SQLite signed-boundary, cache, and
authenticated wire rejection are implemented under #138. Production
qualification, including seamless credential/trust rotation, remains #143.
Watch handoff correctness (#145), recursively protected nested replicated CAS
payloads (#147), and absolute-record-expiry admission (#148) also remain open.

## Consequences

Standalone `SqliteSessionBackend` remains useful as a durable local backend,
but it is not HA. Production CNFs need a separately qualified replicated
profile; the current `QuorumSessionStore`/`opc-session-net` combination is not
yet that profile.

The SDK favors fail-closed reads over returning divergent session state when a
majority cannot agree.

`MAX_SESSION_TTL` is exactly 365 days. Zero remains valid as immediate expiry;
larger values return `StoreError::InvalidSessionTtl` or
`LeaseError::InvalidSessionTtl` before application/backend effects. The
implementation converts seconds/nanoseconds and adds deadlines with checked
integer operations rather than floating point or panicking timestamp
arithmetic. This prevents an oversized direct or authenticated input from
unwinding a process, but supplies no consensus or commit proof.

The new public and serialized error variants require exhaustive callers and
all session-net participants to upgrade as one same-v3 compatibility unit;
valid v3 wire traffic is unchanged. Operators must first audit persisted legacy
replication logs: a TTL-bearing entry above 365 days now fails closed during
replay/rebuild and is neither clamped nor rewritten automatically. Replicated
deadline validation admits at most one microsecond above exact
`entry.timestamp + ttl` solely for legacy `seconds_f64` rounding; new deadlines
remain exact, the TTL maximum is unchanged, and larger mismatches fail closed.

Capability/profile validation and fresh readiness have different scopes. The
former is static admission evidence. The latter is a bounded observation that
can become stale immediately, so a CNF must gate traffic continuously and each
authoritative operation must reassess quorum.

A product composes one descriptor per physical vote. For example, logical self
`epdg-app-0` may select the member whose dial endpoint is the full
`epdg-app-0.epdg-app-quorum.epdg-gateway.svc.cluster.local:7443`; the SDK does
not shorten the FQDN or compare it with the logical ID. Any resolver override
changes only where the client connects; the expected replica and SPIFFE
identity remain fixed by the manifest.

## Evidence

- `crates/opc-session-store/src/quorum.rs`
- `crates/opc-session-store/src/readiness.rs`
- `crates/opc-session-store/src/topology.rs`
- `crates/opc-session-store/tests/quorum_durable_readiness.rs`
- `crates/opc-session-store/tests/quorum_topology.rs`
- `crates/opc-session-net/tests/three_node_quorum.rs`
- `crates/opc-session-net/tests/authenticated_replica_identity.rs`
- `crates/opc-amf-lite/tests/amf_lite_tests.rs`
- `crates/opc-session-store/src/sqlite/mod.rs`
- `crates/opc-session-testkit/`
- `docs/ha-design.md`
- `docs/operator-readiness.md`
