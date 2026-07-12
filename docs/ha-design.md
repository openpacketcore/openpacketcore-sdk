# OpenPacketCore High Availability and Consensus Design

This document details the High Availability (HA) architecture and implementation for the
OpenPacketCore config and session persistence surfaces.

- **Config Store**: `ConsensusConfigStore` is a durable config-consensus
  prototype with durable membership, transport-level mTLS/SPIFFE identity checks,
  Raft-like safety guards, snapshots, metrics hooks, and multi-process fault
  tests. These are tested prototype properties, not carrier HA qualification.
- **Session Store**: `QuorumSessionStore` is an in-process quorum ordered-log
  adapter with fail-closed configured-topology admission, a
  fresh bounded durable-readiness assessment, safe strict-prefix catch-up,
  watch cursors, and chaos tests. Production networked HA depends on the
  experimental `opc-session-net` transport and further safety and
  distributed/soak evidence.

Historical closure language below refers only to scoped algorithms and test
harnesses. Config-store qualification (`GAP-001-006`) and production networked
session HA (`GAP-004-004`) remain open; neither component is approved as a
production deployment profile.

---

## 1. Durable Config Store Consensus Prototype: `ConsensusConfigStore`

`ConsensusConfigStore` implements a durable prototype for config commits,
confirmations, and rollback points using a replicated, transaction-safe
consensus log on top of local SQLite databases.

### Consensus & Log Model
The backend implements a term-based Raft-like state machine. 
- Log entries are appended to a durable SQL log table (`consensus_log`) on the leader.
- The leader replicates log entries to peers using `AppendEntries` RPCs.
- An entry is considered **committed by this prototype** once it is appended to
  a majority of node logs and applied by the leader.
- Committed entries are applied to the state machine (the core config history and audit tables) in strict sequential order. Log replay is completely idempotent.

### Durable Metadata & Node Identity
Each replica has a unique, durable node ID configured at startup. The SQLite database stores the following state across restarts:
- **Consensus State** (`consensus_state`): Persists `current_term` (epoch) and `voted_for` (candidate ID who received this node's vote in the current term) to ensure election safety across restarts.
- **Consensus Log** (`consensus_log`): Persists log index, term, operation type, and operation payload.
- **Consensus Applied** (`consensus_applied`): Tracks the `applied_index` to guarantee that each applied entry is applied exactly once to the underlying config store.

### Leader Fencing
To prevent split-brain issues:
- Candidates must secure votes from a majority of nodes to become the leader.
- Nodes reject `AppendEntries` and `RequestVote` RPCs from any sender with a term lower than the node's durable `current_term`.
- If a leader receives an RPC response indicating a peer is running a higher term, the leader immediately steps down to the `Follower` role and updates its term.
- Writes attempted on a non-leader node are rejected immediately with a `stale leader: not the leader` error.

- When the leader receives a read, it verifies its leadership by obtaining current-term responses from a majority of the cluster before serving the read. This prevents minority reads and ensures linearizability.

### Replica Catch-Up & Rejoin
Rejoining replicas are caught up before they can participate as authoritative readers/writers:
- The leader tracks the log progress of peers.
- If a peer's log is stale or it has missed commits, the leader performs log probing to find the last common log entry and replicates all missing entries sequentially.
- A newly elected leader does not automatically apply every local log entry. It
  only applies entries through the committed/applied path, preventing failed
  local no-quorum writes from becoming visible just because the node later wins
  an election.

### Failure & Operator Assumptions
- **Quorum Sizing**: A cluster of $N$ nodes requires a majority quorum of $\lfloor N/2 \rfloor + 1$ online nodes to commit writes or serve reads.
- **Failure Closed**: If a partition splits the cluster such that no group has a majority, both sides fail closed. Reads and writes fail immediately, preventing split-brain or data divergence.
- **Membership**: Initial/current membership and node identity are persisted in
  the SQLite schema (`consensus_membership` table). Controlled voter changes use
  the joint-consensus path, quorum cannot shrink accidentally, and startup is
  rejected when the configured node ID differs from the persisted identity.

### Config-store consensus prototype evidence (`GAP-001-006`)

`ConsensusConfigStore` has these validated prototype properties:

- **Transport-level mTLS & SPIFFE Peer Identity**: RPC communication is secured over transport-level mTLS using `rustls`. Client and server certificates are verified against the configured CA bundle, certificate SAN SPIFFE IDs are parsed with `x509-parser`, and peer identity is bound to the local node's configured SPIFFE workload profile, the expected node ID, the request cluster ID, and active cluster membership. The legacy JSON certificate fields are ignored for trust decisions.
- **Controlled Server Concurrency & Lifecycle**: The TCP server handles connection binding with `SO_REUSEADDR` socket option enablement, implements an explicit oneshot shutdown hook, limits server-side concurrency to 100 connections via semaphore, and enforces connection handshake, read, and write timeouts (5s).
- **Raft Safety & No-Op Commits**: Newly elected leaders block client operations until they commit and apply a `NoOp` log entry in the current term, enforcing complete Raft commit rules.
- **Caught-up Non-voter Promotion**: Non-voting members can be promoted only after catching up to the leader's log index. Node removal rejects self-removal and preserves replica node identities.
- **Snapshot HMAC Validation**: Compacted snapshots are cryptographically validated using HMAC-SHA256 keyed by the local `AuditKey`.
- **Operator Metrics Hooks**: Detailed atomic counters and dump output track elections, leader changes, RPC failures/timeouts, snapshot installs/failures, peer lag, active connections, authentication failures, and read/write quorum failures. Prometheus/runtime telemetry export (`GAP-001-004`) has been fully implemented.
- **Multi-Process Failure Evidence**: Integration tests simulate multi-process stores and verify leader/follower crashes, network partitions, split-brain resistance, partition heal catch-up, no-quorum writes rejection, schema mismatches, and audit-chain integrity.
- **Process-Level HA Test Harness (Milestone 4)**: The process-level HA test harness has been fully implemented and verified. This covers process campaigns, failovers, network partitions, and pending commits surviving process restarts.
- **Out-of-Process Raft Joint Consensus Transitions**: Raft joint consensus transitions (voter membership changes) are fully implemented and verified out-of-process.

Platform hardening concerns—including TLS/SPIFFE SVID and bundle watch/reload (`GAP-003-001`), KMS-backed durable key providers over mTLS TCP or local Unix-socket KMS agents (`GAP-003-004`), and storage-fault injection (`GAP-001-005`)—have been implemented and verified as reusable library mechanisms. That scoped closure does not qualify seamless session-net certificate/trust rotation; the service-level evidence remains #143.


---

## 2. Replicated Session Store Ordered Log: `QuorumSessionStore`

The algorithm below describes intended and prototype-tested behavior; it is not
yet durable distributed proof or a production deployment contract. Configured
topology admission and fresh durable readiness are implemented. Authenticated
identity binding is implemented in protocol v3; durable sequencing and safe
fork recovery (#127–#129), and bounded majority-authoritative restore (#133)
remain open. Fixed-width wire DTOs remain #134. #135's structural owner/key
model, persistence/transport decode validation, bounded offline SQLite audit,
and typed-invalid handover rejection are implemented. Checked session TTL and
replication-sequence handling now fail closed at direct, wrapper, cache,
SQLite, quorum, and authenticated transport boundaries under #137/#138.
Bounded iterative protection of every nested replicated CAS is implemented
under #147. These boundary fixes do not provide durable authority.

`QuorumSessionStore` coordinates session leases and CAS mutations across a set of `SessionStoreBackend` replicas using quorum-backed ordered replication. It is not a Raft implementation; its target safety contract is a durable committed log prefix where an entry is authoritative only after the same sequence entry is present on a majority of replicas.

### Configured topology admission

Operational construction consumes `ValidatedQuorumTopology`. HA admission
requires an odd set of 3 through 31 members, one exact local `ReplicaId`, and
unique logical IDs, canonical endpoints, expected TLS identities, failure
domains, backing-store identities, and process-local adapter instances. The required
quorum is precomputed from that immutable configured membership, and vote
accounting is keyed by `ReplicaId` rather than raw vector entries.

Logical identity, endpoint, TLS identity, failure domain, and backing identity
are independent. A bare local ID can belong to a member with an FQDN endpoint;
no hostname shortening or endpoint-as-identity inference occurs. The explicit
lab singleton reports `single-replica`. The deprecated raw-vector constructor
reports `unknown`, masks capabilities, and refuses operations.

For authenticated network adapters, admission also verifies
`BackendPeerBinding`: the configured local and remote IDs, exact remote TLS
identity, both descriptor fingerprints, member count, and one shared opaque
configuration scope must match the admitted topology. An in-process local
backend may remain unbound. This is composition evidence, not fresh peer
reachability or physical-store provenance, and it does not establish durable
commit/repair/restore authority (#127/#128/#133).

### Structural identity and legacy persistence admission

`OwnerId` and each deployment-specific session-key type name now contain 1
through 128 UTF-8 encoded bytes. `SessionKeyType::Other` wraps a private
`CustomSessionKeyType`; the five reserved canonical strings map only to their
well-known variants. Known and custom values serialize, persist, hash, and sort
by the canonical string, not enum declaration order.

Serde, SQLite record/restore/active-lease/fenced-mutation/log hydration, and
session-net request/response decoding apply the same invariant. A bad owner or
key type—including one nested in a replication operation—fails closed before
mutation or caller exposure with a fixed or fieldless error that omits the raw
value. New handover envelopes use an exact `OPCH` magic/version header. The
bounded non-`OPCH` classifier accepts current-valid original syntax and some
bare payloads; ambiguous, truncated, oversized JSON-looking, unknown, or
typed-invalid claims fail before mutation. Successful syntax detection is not
provenance. The identity audit does not classify live or nested-log payloads, so
products must run the complete provenance-aware replay preflight in RFC 004
§5.2/§10.3.

Existing valid v3 values keep their JSON string shape, but source construction
and pattern matching change and admission is stricter. An older v3 member may
emit an invalid value a new member rejects, so #135 is not a same-v3 rolling
compatibility claim. Prefer deploying it together with #134. Until the
fixed-width DTO and handshake negotiate the contract, drain and stop every
client, server, and wrapper plus every product handover reader/writer, audit
identities and handover payloads, upgrade the complete fleet, and restart it
together. Once any live or replayable `OPCH` copy is written, rollback to an
older SDK requires a drained coherent fleet-wide checkpoint restore (with
post-checkpoint mutation handling) or reviewed reverse migration of every live,
log, snapshot, and restore copy; #134 does not make the format backward-readable.

The offline command is:

```text
opc-session-store-audit identity-invariants \
  --database PATH \
  --max-rows N \
  --max-entry-json-bytes N \
  --max-total-json-bytes N
```

All budgets are required and non-zero, with the per-entry JSON limit no larger
than the total or SQLite's signed `i64` length range. The audit opens one drained SQLite snapshot read-only and
query-only, scans the four identity-bearing tables in fixed 256-row pages, and
emits version-1 count-only JSON. `compliant`/0 is the sole pass;
`violations_found`/1, `incomplete`/2, and redacted command/setup `error`/2 all
block upgrade. Reports contain version/status, limits, bounded scanned and
violation counts, and an optional bounded `incomplete_reason` only—never a
database path, row identity, owner, key type, session key,
payload, transaction, or raw JSON. Neither the audit nor runtime truncates,
renames, repairs, or rewrites an invalid value. Use a reviewed
semantic-preserving product migration or audited store replacement, then
re-audit before startup.

This is #135 boundary evidence, not durable consensus or production HA. #127,
#134, and #143 remain open; #143 includes seamless SVID,
payload-protection-key, and trust-bundle rotation under live distributed load.

### Fresh durable readiness

Capability declarations and `SessionStorePlatformProfile::Quorum` remain
admission evidence only. `QuorumSessionStore::probe_durable_readiness` bypasses
cached capabilities and performs a fresh, deadline- and log-work-bounded
assessment of the admitted voters. `DurableReadinessReport` exposes these stable
states: `Ready`, `NoQuorum`, `TopologyInvalid`, and `RecoveryRequired`;
configured, freshly reachable, agreeing, and required voter counts
(`configured_voters`, `fresh_reachable_voters`, `agreeing_voters`, and
`required_quorum`); an optional `majority_visible_prefix_index`; and one typed
observation per configured voter.

The limits are configured once on the store and are shared by explicit probes
and authoritative operations. Log evidence is fetched in bounded adaptive
pages, so a healthy log larger than one network frame remains assessable.

Per-replica failure classes are `Transport`, `Authentication`, `Timeout`,
`Protocol`, `Backend`, `LogUnavailable`, `Divergent`, `RepairFailed`, and
`ProbeBudgetExceeded`. These are bounded reason codes rather than raw peer,
transport, or backend errors. The report is point-in-time evidence rather than
a lease, and each authoritative operation repeats the same fail-closed
assessment.

Automatic readiness repair is limited to appending a majority-visible suffix
to a replica whose complete log is a strict shorter prefix. A conflict or
longer minority tail produces `RecoveryRequired`; this path neither truncates
nor destructively rebuilds the replica. The observed index is deliberately
called majority-visible rather than committed until #127/#128 establish durable
commit and repair authority.

### Bounded TTL inputs

All `Duration` inputs used for session refresh and lease TTLs use the public
`MAX_SESSION_TTL` bound of exactly 365 days. Zero is accepted as immediate
expiry and the exact maximum is accepted. Larger values fail with
`StoreError::InvalidSessionTtl` or
`LeaseError::InvalidSessionTtl`. Conversion to the internal duration and
addition to an injected/backend clock use exact checked integer arithmetic, so
an oversized input or a near-maximum clock cannot unwind the process.

Validation occurs before effects for direct acquire/renew/refresh calls,
TTL-bearing batch and replication entries, wrappers, quorum dispatch, local
backends, and authenticated client/server admission. Here, effects means
application/backend mutation or provider work: clients reject before
resolution/dialing, while servers reject after request receipt but before
backend dispatch and may return the typed response. The new public and
serialized error variants require external exhaustive matches and a
coordinated same-v3 fleet upgrade. The TTL wire shape is unchanged for entries
admitted by the operation-tree contract below. Operators must audit legacy
persisted logs before upgrade because a TTL-bearing entry
above the bound now fails closed during replay/rebuild rather than being
clamped or rewritten. Replicated deadline validation permits at most one
microsecond above exact `entry.timestamp + ttl` for legacy `seconds_f64`
rounding only; new deadlines remain exact, the TTL bound is unchanged, and
larger mismatches fail closed.

This closes only the duration-input/process-availability gap in #137. It does
not make a majority-visible entry committed and does not change the open
consensus, repair, restore, or qualification work. Caller-authored absolute
record expiry remains #148.

### Bounded protected replication trees

`MAX_REPLICATION_OPERATION_DEPTH` is 16 and
`MAX_REPLICATION_OPERATIONS_PER_ENTRY` is 256. The root is depth 1, each child
increments depth, and every operation node—including each `Batch`—counts toward
the entry total. Validation and transformation use iterative traversal. An
over-limit entry fails with the fieldless
`StoreError::ReplicationOperationLimitExceeded`, without exposing count, depth,
key, payload, provider detail, or nesting shape.

Entry and complete rebuild-prefix preflight finishes before provider or backend
work. Complete returned pages are validated before transformation or caller
exposure. `EncryptingSessionBackend` and `RemoteSealingSessionBackend` protect
every nested CAS on replicate/rebuild and unprotect every nested CAS on log and
watch reads. Provider calls remain sequential and operation order/non-payload
fields are preserved. A late provider error may follow earlier provider calls,
but a write performs no backend delegation and a read exposes no partially
transformed entry/page; earlier independent watch items may already have been
yielded.

This is a breaking confidentiality contract within protocol v3. An older peer
cannot decode the new error, and an older wrapper may forward a deep CAS as
plaintext/unsealed data. Mixed versions are not confidentiality-safe and must
not be called rolling-compatible. Drain and upgrade all clients, servers, and
wrapper participants together. #134 still owns a versioned fixed-width DTO and
handshake contract that pins these two limits and the error encoding.

Historical nested plaintext is not automatically scrubbed. Operators must
audit persisted tree shape and payload encoding offline before upgrade. Entries
within the new limits may be explicitly rewritten/rebuilt through the configured
protection wrapper. Over-limit history fails before transformation and requires
a separately reviewed atomicity-preserving offline migration or audited store
replacement before the new SDK starts; it must not be clamped or split ad hoc.
Raw inner-backend rebuild does not add protection.

#147 closes only this bounded nested-payload path. The session profile remains
experimental and blocked on #143 and its other dependencies. Seamless SVID
rotation, payload-protection key rotation, and trust-bundle rotation remain
separate mandatory production qualifications.

### Authenticated network transport (protocol v3)

`opc-session-net` protocol v3 carries validated restore-scan requests and pages
to individual remote replicas. A server may shorten a multi-record page to the
smaller client/server frame budget; callers resume from `next_cursor`, while a
single record that cannot fit returns `RestoreScanResponseTooLarge`.

Every production participant is created with an opaque authenticated TLS
config and a binding derived from one immutable `SessionReplicationManifest`.
The manifest's configuration ID is an order-independent SHA-256 digest of the
cluster ID, operator-controlled generation, and every field of every replica
descriptor. During the v3 handshake, each side extracts the canonical SPIFFE
URI from the live certificate and requires it to match the claimed stable
`ReplicaId`, expected opposite member, cluster, and configuration ID before
dispatch. The client verifies its fresh challenge is echoed by the server.
DNS/FQDN/IP aliases and resolver overrides affect
routing only; they never redefine replica identity.

The exact v3 ALPN and handshake have no production fallback to v2. A v2-to-v3
change is a coordinated stop/upgrade/start of all clients and servers, not a
mixed-version rolling deployment.

#135 also requires that coordinated pattern even though accepted owner and key
type values retain the v3 JSON shape. New model deserializers reject empty or
oversized values before dispatch/exposure, while an older v3 peer can still
emit them. Deploy #135 with #134 when possible; unchanged wire
shape for valid values is not semantic negotiation.

The #147 confidentiality contract is also coordinated even though both old and
new builds identify as v3: mixed builds cannot negotiate the new operation-tree
limits and are not confidentiality-safe. #134 must make that contract explicit
in the versioned DTO/handshake rather than relying on an SDK-version
assumption.

Session caches, tickets, resumption, early data, and 0-RTT are disabled, so a
reconnect performs a full mutual-TLS certificate exchange. Production still
requires seamless certificate and trust-bundle rotation without interrupting
session service, including trust overlap, revocation, long-lived-connection
retirement, reconnect storms, and a documented maximum authentication age.
That distributed qualification remains #143. Session TTL is application-state
lifetime; the 365-day bound is not a certificate-expiry, trust-validity, or
authentication-age policy.

This closes per-replica transport parity only. Quorum selection/merge remains
#133, while durable sequencing and repair authority remain #127/#128.
Authenticated membership does not make protocol v3 a consensus algorithm and
does not reconcile a divergent or forked log.

### Log & Replication Model
- **Persisted Replica Logs**: The current coordinator assigns sequence numbers to replicated mutations (AcquireLease, RenewLease, ReleaseLease, CompareAndSet, DeleteFenced, RefreshTtl, Batch), and each accepting replica writes them to `session_replication_log`. Operation trees are bounded to depth 16 and 256 total nodes, and protection wrappers iteratively transform every nested CAS before delegation/exposure. Leader/term-gated global sequence authority remains #127.
- **Idempotency & Replay Semantics**: Duplicate delivery is handled safely. Before appending, replicas check whether the entry's sequence has already been applied. Only an exact full-entry match is accepted as an idempotent success; reusing the same transaction ID with a changed operation or timestamp fails closed as divergence. Replaying an exact entry does not mutate the state twice.
- **Current Majority-Visible Prefix Heuristic**: The coordinator compares fresh logs visible from the configured majority. It may append a missing suffix to an exact strict-prefix replica, but a conflict or longer minority tail fails with `RecoveryRequired` and is not truncated. This remains a heuristic, not durable commit proof: without #127/#128, a later visible majority may still omit a previously acknowledged entry.
- **Resume Tokens / Watch Cursors**: Exposes watches backed by sequence numbers, allowing consumers to supply sequence cursors and resume receiving updates from the exact sequence they left off.
- **Replica Catch-Up & Read Repair Prototype**: The coordinator freshly queries replica log progress on every write or read and uses the same bounded assessment path as the readiness probe. Reads require identical records on a majority quorum and fail closed if no quorum result exists, but commit and repair authority remain unproven until #127/#128.
- **Failed-Write Fail-Closed Fixture**: If a new replication entry reaches fewer than a majority of replicas, the operation fails closed and the existing write path attempts a best-effort rollback of the partial suffix. Separately, an already-visible ambiguous minority tail returns `RecoveryRequired` without mutation. These fixtures do not establish durable repair authority or prove resurrection safety across partitions/restarts before #127/#128.
- **Feature Declarations**: Replicated adapters declare `ordered_replication_log = true` and `watch = true`, while standalone SQLite reports `false`. These bits describe implemented methods; they are not fresh-quorum readiness or production qualification. Consumers must use `probe_durable_readiness` for current evidence.
- **Low-Cardinality Readiness Telemetry**: Metrics expose probe success/failure, the latest ready state, configured/freshly-reachable/agreeing/required voter counts, the majority-visible prefix, and bounded failure reasons (`timeout`, `authentication`, `transport`, `divergent`, and `recovery_required`) without replica IDs, endpoints, or raw errors as labels.

---

## 3. Local Session Cache Invalidation: `SessionCache`

`SessionCache` (implemented in the `opc-session-cache` crate) provides a local, in-memory read-through cache for session records in downstream CNFs. It keeps cache hits behind an explicit coherence gate: local values are served only when the background watch stream is active and the processed sequence is caught up to the backend's reported replication sequence. If the cursor cannot be verified, reads bypass local memory and go directly to the authoritative backend.

### Coherence & Invalidation Model
- **Read-Through Population**: When `get` misses the local cache, the record is fetched from the authoritative backend. It is populated in memory only after the cache verifies that the watch cursor is caught up to `max_replication_sequence`. If the cursor is lagging, unavailable, or syncing, the read succeeds from the backend but the value is not cached.
- **Coherent Cache Hits Only**: Before serving a cached value, the cache checks that the watched sequence is at least the backend's current reported sequence. If the backend is ahead, the cache clears local state, marks the watch unhealthy, and bypasses cache hits until the watch loop catches up or resyncs.
- **Background Watch Subscription**: Spawns a background task that subscribes to `watch(last_sequence + 1)` on the session store, receiving replication entries in monotonic order. Any mutation (CompareAndSet, DeleteFenced, RefreshTtl, AcquireLease, RenewLease, ReleaseLease) to a key results in the key being evicted from the cache.
- **Monotonic Sequence Tracking & Gaps**: The cache tracks the processed sequence number globally. If a gap is detected (`sequence > last_sequence + 1`), indicating missed log entries, the cache invalidates its entire state and triggers a full resync from the current maximum sequence number of the backend.
- **Idempotency**: Duplicate events (`sequence <= last_sequence`) are detected and ignored, preserving the sequence cursor and cache safety.
- **Fail-Closed & Gap Recovery**: If the watch stream encounters a connection error, reports a gap, lacks ordered-watch capabilities, or cannot prove the cursor is current, the cache clears its local entries and bypasses local reads. It attempts to re-establish the watch from the latest sequence after querying `max_replication_sequence`; subsequent `get` calls fall back to direct backend lookups until coherence is restored.
- **Write-Through Wrapper Safety**: `SessionCache` implements the `SessionBackend` trait and delegates mutations to the authoritative backend. Mutating calls through the wrapper evict affected keys before and after successful writes, so callers do not need to wait for the async watch stream to invalidate their own local writes.
- **Redacted Diagnostics**: Key operations and lifecycle state transitions (such as resyncs and stream restarts) are logged with redacted session keys, protecting subscriber identifiers from diagnostics exposure.

---

## 4. Chaos Testkit Status: `opc-session-testkit`

`opc-session-testkit` and `crates/opc-persist/tests/consensus_tests.rs` provide focused failure-mode simulation tests.

### Config Store HA Failure Tests (Persisted)
- **3-node happy path**: Verifies that commits persist on a majority and survive replica restarts.
- **Stale leader fencing**: Proves stale leader writes are rejected after a newer leader is elected in a higher term.
- **Partition split-brain**: Verifies that a minority partition cannot commit writes or serve reads, while the majority partition functions correctly.
- **Partition healing & catch-up**: Proves that a stale replica successfully catches up to the leader's state after a partition heals.
- **Crashed replica rejoin**: Verifies a crashed replica with stale logs cannot overwrite newer committed data and is caught up by the leader.
- **Commit-confirmed failover**: Verifies that pending commit-confirmed deadlines survive leader crash and failover to a new leader.
- **Rollback target safety**: Verifies that rollback target selection rejects uncommitted or pending minority states.
- **Duplicate log idempotency**: Confirms replayed/duplicate log entries are idempotent and apply exactly once.
- **Failed-write regression**: Confirms a no-quorum write that returned an error is not resurrected after a later campaign or successful commit.
- **Snapshot regression**: Confirms stale snapshot installation cannot move a follower back to older applied state.
- **Compaction appendability**: Confirms compacted leaders retain the snapshot index/term needed to append later committed entries.

### Session Store HA Failure Tests (Ordered Replication)

These in-process fixtures exercise observed behavior; they are not durable
distributed commit or repair proof (#127/#128).

- **Fresh durable readiness**: Exercises ready/no-quorum/recovery-required
  outcomes, bounded probe work, strict-prefix append, and typed replica
  failures independently of cached capabilities.
- **Split-brain healing**: Exercises coordinator recovery after simulated partitions are resolved.
- **Durable catch-up**: Rejoining replicas are caught up automatically with log replication.
- **Duplicate delivery**: Duplicate entries are resolved idempotently without duplicate mutations.
- **Partial-write fail-closed evidence**: Failing mid-flight writes are rejected;
  the fixtures do not claim automatic destructive reconciliation.
- **Stale-fence replay**: Stale fence updates are rejected monotonically.
- **Strict-prefix repair**: A stale strict-prefix replica may be appended and
  verified on read; divergent or longer-tail replicas instead require
  recovery and are not mutated.
- **Restart/rejoin across profiles**: Exercises restart/rejoin behavior under fake, SQLite, and replicated profiles.
- **No wall-clock LWW**: Observes that the tested ordering paths do not select authoritative state by wall-clock time.
- **Bounded TTLs**: Exercises zero, the exact 365-day maximum, maximum plus one,
  and `Duration::MAX` across direct, nested, persisted, quorum, and
  authenticated-wire paths, including no-partial-effect and near-maximum-clock
  cases.
- **Nested payload protection**: Exercises depth/count edges, deep CAS
  encryption/sealing round trips through replicate/rebuild/log/watch, complete
  prefix/page preflight, sequential-provider failure, and no backend delegation
  or partial entry/page exposure.
