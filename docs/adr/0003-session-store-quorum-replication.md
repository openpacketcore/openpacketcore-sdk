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
- Structural owner and session-key identities: owner IDs and custom key-type
  names contain 1 through 128 UTF-8 encoded bytes; reserved key-type strings
  have one canonical well-known representation; ordering follows the persisted
  string; and model, persistence, and transport decode all fail closed.
- Bounded iterative replication trees: depth 16 from a depth-1 root and 256
  total operation nodes per entry, counting every node including `Batch`.
- Encryption/sealing of every nested replicated CAS before delegation and
  decryption/unsealing of every nested CAS before log/watch exposure.
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
experimental, not a production HA profile. Protocol v4 supplies authenticated,
fixed-width, frame-bounded per-replica transport, but its exact
`opc-session-net/4` ALPN, version, and contract profile require a coordinated
v3-to-v4 stop/upgrade/start; mixed fleets and downgrade negotiation are not
supported. This identity binding is not consensus or fork recovery. Durable
commit authority, commit-proven repair, operator-safe fork recovery, and
bounded majority-authoritative restore remain open in #127–#129 and #133.
Fixed-width private wire DTOs and checked domain conversion are implemented
under #134. Invariant-safe owner/key model decoding, bounded count-only SQLite
admission, and typed-invalid handover rejection are
implemented under #135; checked TTL rejection is implemented under #137, and
malformed sequence zero, checked increment, rebuild-prefix, SQLite
signed-boundary, cache, and authenticated wire rejection are implemented under
#138. Production qualification, including seamless credential/trust rotation,
remains #143.
Watch handoff correctness (#145) and absolute-record-expiry admission (#148)
also remain open. Bounded nested-CAS protection is implemented under #147;
it does not change the profile's experimental status.

The v4 wire uses `u32` for restore/log request limits and the client restore
response budget; `u64` for restore cursors, excluded counts,
`max_value_bytes`, and size-bearing store errors; and checked conversion before
backend dispatch or caller exposure. It omits restore `loaded_count` and
`complete` and recomputes them after decode. Independent limits admit 256 batch
operations, 1,024 restore records, 65,536 replication-log entries, and 65,536
rebuild entries, in addition to the configured frame-size bound. The exact
profile also pins wire-schema/error-set revisions 1, 128-byte
owner/custom-key/state-type bounds, depth-16/256-node replication trees, and the
31,536,000-second TTL maximum. Public
`Request`/`Response` remain, but `Hello`/`HelloAck` gain an optional
`contract_profile`; exhaustive construction and matching must account for the
new field.

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

The new public error variants require exhaustive callers. Protocol v4 carries
them through private fixed-width error DTOs under pinned error revision 1, and
rejects a v3 peer during negotiation. Operators must first audit persisted legacy
replication logs: a TTL-bearing entry above 365 days now fails closed during
replay/rebuild and is neither clamped nor rewritten automatically. Replicated
deadline validation admits at most one microsecond above exact
`entry.timestamp + ttl` solely for legacy `seconds_f64` rounding; new deadlines
remain exact, the TTL maximum is unchanged, and larger mismatches fail closed.

Under #135, `OwnerId` and custom session-key names accept 1 through 128 UTF-8
encoded bytes. `SessionKeyType::Other` now contains a validated
`CustomSessionKeyType`; reserved names decode only to the canonical well-known
variants, and ordering uses canonical string order. Serde, SQLite hydration,
and session-net decode reuse that admission. Valid identity JSON strings retain their
shape, but Rust construction is source-breaking and semantic admission is
stricter. An older v3 peer may emit values v4 rejects, so all clients, servers,
and wrappers require coordinated stop/upgrade/start. Protocol v4's exact
profile now binds this admission rule.

Existing SQLite replicas must be drained and checked with
`opc-session-store-audit identity-invariants` using explicit non-zero
`--max-rows`, `--max-entry-json-bytes`, and `--max-total-json-bytes` budgets.
The per-entry budget cannot exceed the total or SQLite's signed `i64` length
range.
The read-only/query-only audit scans one snapshot in fixed 256-row pages and
emits version-1 count-only JSON. Only `compliant` with exit 0 passes;
`violations_found`/1, `incomplete`/2, and redacted `error`/2 block upgrade. It
never emits database paths or persisted raw values and never truncates,
renames, repairs, or rewrites state. A violation requires a reviewed
semantic-preserving migration or audited store replacement and a new audit.

New handover envelopes use the `OPCH` magic and an exact version byte. The exact
bounded non-`OPCH` classifier in RFC 004 §10.3 accepts current-valid original
syntax and some bare payloads; ambiguous, truncated, oversized JSON-looking,
malformed, unknown, or typed-invalid claims return a fieldless error before
mutation. Successful detection is not provenance. The identity audit does not
classify live or nested-log payload bytes, so products require the complete
provenance-aware replay preflight. Once any live/replayable `OPCH` copy is
written, old SDKs silently see opaque `Stable` data; downgrade requires a
coherent drained checkpoint restore or reviewed reverse migration of every
record/log/snapshot/restore copy across every handover reader/writer.

This closes the scoped #135 boundary, not durable authority or production HA.
#127 remains open; #134 closes the fixed-width v4 wire boundary only, and #143
still requires distributed qualification, including seamless SVID,
payload-protection-key, and trust-bundle rotation.

`MAX_REPLICATION_OPERATION_DEPTH` is 16 and
`MAX_REPLICATION_OPERATIONS_PER_ENTRY` is 256. The root operation is depth 1,
and every node—including `Batch`—counts once. Complete entries, rebuild
prefixes, and returned pages are preflighted iteratively. A violation returns
the fieldless `StoreError::ReplicationOperationLimitExceeded` without revealing
the tree shape.

Protection wrappers transform every nested CAS, not only the root or first
batch level. Replicate/rebuild transformations are fully staged before backend
delegation; log/watch transformations complete before an entry/page is exposed.
Provider calls are sequential. A late provider failure may follow earlier
provider calls, but it causes no backend delegation on writes and no partial
entry/page exposure on reads.

This added a public error variant before the v4 boundary. An older peer cannot
decode it and, more critically, an older wrapper can forward deep
plaintext/unsealed CAS payloads. Protocol v4 rejects the older wire participant
and pins the depth-16/256-node limits and error revision, but it cannot attest
that a protection wrapper is actually installed. All clients, servers, and
wrapper participants require a coordinated upgrade plus composition
verification, not a rolling compatibility claim.

Historical nested plaintext is not automatically scrubbed. Before upgrade,
operators must audit persisted tree shape and payload encoding offline. An
affected entry within the new limits may be explicitly rewritten/rebuilt
through the configured protection wrapper. Over-limit history fails before
transformation and requires a separately reviewed atomicity-preserving offline
migration or audited store replacement before the new SDK starts; it must not
be clamped or split ad hoc. A raw inner-backend rebuild is insufficient.

These guarantees close #147's traversal/confidentiality boundary only. They do
not establish consensus, durable authority, or production HA. #143 remains the
production qualification owner, including separate proof of seamless SVID
rotation, payload-protection key rotation, and trust-bundle rotation.

Capability/profile validation and fresh readiness have different scopes. The
former is static admission evidence. A v4 version/profile/authentication or
malformed-handshake failure clears the remote cache and reports every capability
boolean false with `max_value_bytes = 0`; a cache retained after transient
transport loss remains descriptive only. Fresh readiness is a bounded
observation that can become stale immediately, so a CNF must gate traffic
continuously and each authoritative operation must reassess quorum.

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
- `crates/opc-session-store/tests/encryption.rs`
- `crates/opc-session-store/tests/replication_structure_bounds.rs`
- `crates/opc-session-store/tests/persisted_identity_bounds.rs`
- `crates/opc-session-store/tests/sqlite_identity_audit.rs`
- `crates/opc-session-store/tests/sqlite_identity_audit_cli.rs`
- `crates/opc-session-store/tests/handover.rs`
- `crates/opc-session-net/tests/three_node_quorum.rs`
- `crates/opc-session-net/tests/authenticated_replica_identity.rs`
- `crates/opc-amf-lite/tests/amf_lite_tests.rs`
- `crates/opc-session-store/src/sqlite/mod.rs`
- `crates/opc-session-testkit/`
- `docs/ha-design.md`
- `docs/operator-readiness.md`
