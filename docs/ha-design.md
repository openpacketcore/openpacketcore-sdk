# OpenPacketCore High Availability and Consensus Design

This document details the High Availability (HA) architecture and implementation for the
OpenPacketCore config and session persistence surfaces.

- **Config Store**: the current `opc-persist` config-consensus implementation is
  a transition-only custom prototype. ADR 0019 requires its replacement with
  the shared Openraft engine under #177 before the workspace can claim one
  production consensus architecture.
- **Session Store**: `ConsensusSessionStore` (and its `QuorumSessionStore` type
  alias) uses Openraft as the sole election, log, commit, membership, and
  linearizable-read authority. The SDK supplies validated identity,
  authenticated bounded transport, deterministic session semantics, committed
  journal/watch output, and encrypted-envelope storage below the application
  protection wrapper.

Historical closure language below refers only to scoped algorithms and test
harnesses. The config migration (#177), session repair/recovery/restore
(#128/#129/#133), and production networked qualification (#143 plus the
credential-rotation chain) remain open; neither component is yet approved as a
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

### Consensus RPC Deadline, Retry, and Fan-Out Contract

The `TcpPeer` timeout (the `opc-consensus-node --rpc-timeout` value in
milliseconds) is one absolute deadline for a logical RPC. It covers local
authentication/TLS-connector locks, bounded cooperative request encoding, TCP
connect, mTLS, request writes, response length/body reads, bounded cooperative
decode, every attempt, and the 50/100 ms retry backoffs. Zero is immediate
expiry, unrepresentable monotonic-clock durations fail closed, and no new stage
or retry begins after expiry.

Raft vote/append/snapshot requests replay the same term/log coordinates and
read requests are side-effect free, so those families may retry after an
ambiguous write. `TimeoutNow` is different: delivery may already have launched
a campaign, so it is not replayed once request bytes may have reached the peer.
Permanent local identity/connector failures and certificate-verification
failures also fail immediately instead of being retried into a timeout.

Election votes and replication fan out concurrently across peers. A catch-up
pass within one peer is sequential but bounded to 64 snapshot/append RPC
rounds. A rejected snapshot can fall through to one append in the same round,
so a pass issues at most 128 logical RPCs and its maximum transport wait is
`128 * peer timeout`, plus local database and scheduling work, rather than one
RPC timeout. A later synchronous pass or background trigger resumes from the
stored `next_index`; large gaps should converge through snapshot installation
or repeated bounded passes.

The logical-deadline interpretation is a breaking change from the former
per-stage timeout reset. An upgrade must retune the timeout as an end-to-end
budget and coordinate that value across cluster members; downstream exhaustive
matches on `PersistErrorKind` must also handle `ConsensusRpcTimeout`.

### Replica Catch-Up & Rejoin
Rejoining replicas are caught up before they can participate as authoritative readers/writers:
- The leader tracks the log progress of peers.
- If a peer's log is stale or it has missed commits, the leader performs at
  most 64 log-probe/snapshot/append rounds (at most two logical RPCs per round)
  in one trigger. If the common prefix is still not found, a later trigger
  resumes from `next_index` rather than leaving one unbounded task alive.
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
- **Live Identity Lifecycle**: `set_identity` atomically replaces the local
  server identity/acceptor pair and atomically invalidates each adapter's
  cached client connector for new attempts, while in-flight attempts may
  complete with the old connector. Multi-peer propagation is serialized but
  can be partial on error or cancellation, so the caller must retry under trust
  overlap and fresh-handshake readiness. A production CNF must watch
  workload identity/trust-bundle updates, distribute old/new trust overlap
  before rotating leaves, preserve the exact SPIFFE/node identity, drain old
  connections, verify new handshakes, and remove old trust only after the
  maximum authentication age. The `opc-consensus-node` test binary reads PEM
  files only at startup and does not provide that rotation controller.

### Config-store consensus prototype evidence (`GAP-001-006`)

`ConsensusConfigStore` has these validated prototype properties:

- **Transport-level mTLS & SPIFFE Peer Identity**: RPC communication is secured over transport-level mTLS using `rustls`. Client and server certificates are verified against the configured CA bundle, certificate SAN SPIFFE IDs are parsed with `x509-parser`, and peer identity is bound to the local node's configured SPIFFE workload profile, the expected node ID, the request cluster ID, and active cluster membership. The legacy JSON certificate fields are ignored for trust decisions.
- **Controlled Server Concurrency & Lifecycle**: The TCP server handles
  connection binding with `SO_REUSEADDR`, implements an explicit oneshot
  listener-shutdown hook, limits server-side concurrency to 100 handlers, and
  applies a fixed five-second timeout to TLS acceptance. Post-handshake request
  length/body reads and the response write are 16 MiB frame-bounded but do not
  currently have an independent server-side I/O deadline; the client logical
  RPC deadline must not be described as a server slow-client bound.
- **Raft Safety & No-Op Commits**: Newly elected leaders block client operations until they commit and apply a `NoOp` log entry in the current term, enforcing complete Raft commit rules.
- **Caught-up Non-voter Promotion**: Non-voting members can be promoted only after catching up to the leader's log index. Node removal rejects self-removal and preserves replica node identities.
- **Snapshot HMAC Validation**: Compacted snapshots are cryptographically validated using HMAC-SHA256 keyed by the local `AuditKey`.
- **Operator Metrics Hooks**: Detailed atomic counters and dump output track
  elections, leader changes, RPC failures, typed logical timeouts, snapshot
  installs/failures, peer lag, active connections, authentication failures,
  and read/write quorum failures. `rpc_timeouts_by_family` and
  `rpc_timeouts_by_stage` use fixed bounded keys and never use endpoints, node
  IDs, SPIFFE identities, tenants, or request data as dimensions.
  Prometheus/runtime telemetry export (`GAP-001-004`) has been fully
  implemented.
- **Multi-Process Failure Evidence**: Integration tests simulate multi-process stores and verify leader/follower crashes, network partitions, split-brain resistance, partition heal catch-up, no-quorum writes rejection, schema mismatches, and audit-chain integrity.
- **Process-Level HA Test Harness (Milestone 4)**: The process-level HA test harness has been fully implemented and verified. This covers process campaigns, failovers, network partitions, and pending commits surviving process restarts.
- **Out-of-Process Raft Joint Consensus Transitions**: Raft joint consensus transitions (voter membership changes) are fully implemented and verified out-of-process.

Platform hardening concerns—including TLS/SPIFFE SVID and bundle watch/reload (`GAP-003-001`), KMS-backed durable key providers over mTLS TCP or local Unix-socket KMS agents (`GAP-003-004`), and storage-fault injection (`GAP-001-005`)—have been implemented and verified as reusable library mechanisms. That scoped closure does not provide seamless session-net certificate/trust rotation; its lifecycle implementation is tracked by #158 and service-level qualification remains #143.


---

## 2. Openraft Session Store: `ConsensusSessionStore`

#127 replaces the custom majority-prefix coordinator with Openraft.
`ConsensusSessionStore` is the implementation and `QuorumSessionStore` is an
alias to it. Openraft alone elects leaders, persists votes, matches logs,
commits entries, owns membership and snapshot lineage, and supplies
linearizable read barriers. The SDK implements deterministic session commands,
SQLite storage traits, bounded authenticated RPC adapters, idempotent request
outcomes, a committed application journal, watch cursors, logical expiry time,
and encryption-envelope admission.

This is durable sequencing authority, but not yet a complete production
deployment claim. Committed-state repair and legacy-fork recovery remain
#128/#129, bounded majority-authoritative restore remains #133, watch and expiry
hardening remain #145/#148, and network/resource/rotation qualification remains
#143 and the #162 -> #161 -> #163 -> #158 -> #164 credential chain. Stable IDs,
durable transaction IDs, and log-range cursors remain #167/#168/#171.

### Configured topology admission

Operational construction consumes `ValidatedQuorumTopology`. HA admission
requires an odd set of 3 through 31 members, one exact local `ReplicaId`, and
unique logical IDs, canonical endpoints, expected TLS identities, failure
domains, backing-store identities, and derived stable node IDs. The topology is
descriptor-only: the node's one local SQLite backend and exact remote
consensus-peer map are supplied separately after admission. Admission also
requires a cluster ID, monotonic configuration epoch, and an
order-independent configuration digest that exactly matches the descriptors.
Stable Openraft node IDs are derived from cluster plus logical `ReplicaId`, fit
SQLite's positive signed-64-bit domain, and do not change when other members
are reordered, added, or removed. Openraft owns vote accounting and quorum.

Logical identity, endpoint, TLS identity, failure domain, and backing identity
are independent. A bare local ID can belong to a member with an FQDN endpoint;
no hostname shortening or endpoint-as-identity inference occurs. The explicit
consensus lab singleton uses the same engine but reports `single-replica`.

Production peers use the dedicated `opc-session-consensus/1` ALPN. Every RPC
binds the live SPIFFE identity, configured local and remote logical IDs, stable
node IDs, cluster/configuration/epoch, sender field, expected server profile,
and a fresh challenge before Openraft dispatch. This is authentication and
composition evidence, not physical-store provenance. A CNF must still map each
logical voter to exactly one durable backing volume.

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

Existing valid v4 values keep their JSON string shape, but source construction
and pattern matching change and admission is stricter. An older v3 member may
emit an invalid value v4 rejects, so this is not a rolling-compatibility claim.
The fixed-width DTO and handshake now bind the contract. Drain and stop every
client, server, and wrapper plus every product handover reader/writer, audit
identities and handover payloads, upgrade the complete fleet, and restart it
together. Once any live or replayable `OPCH` copy is written, rollback to an
older SDK requires a drained coherent fleet-wide checkpoint restore (with
post-checkpoint mutation handling) or reviewed reverse migration of every live,
log, snapshot, and restore copy; the v4 handshake does not make the format
backward-readable.

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

This is #135 boundary evidence, not production HA. #127 now supplies durable
consensus independently; #134 closes only fixed-width legacy-v4 admission.
#143 still includes distributed load and payload-protection-key qualification,
while seamless SVID/trust rotation follows the dedicated rotation issue chain.

### Fresh durable readiness

Capability declarations and `SessionStorePlatformProfile::Quorum` remain
admission evidence only. `QuorumSessionStore::probe_durable_readiness` bypasses
cached capabilities and invokes Openraft's bounded linearizable-read barrier,
then waits until the local state machine has applied through that log ID.
`Ready` therefore proves the same fresh quorum path required by real reads, not
merely that a listener was bound. Writes use bounded `client_write`; reads use
the barrier every time and never trust a prior readiness result.

The report remains point-in-time evidence rather than an ownership lease.
Products must continuously close ownership publication and traffic
advertisement when it becomes `NoQuorum`. Diagnostics remain bounded and
redacted; peer identities and peer-controlled errors are not labels or report
payloads.

Openraft reconciles normal follower log divergence. Recovery of an already
forked legacy custom-coordinator database requires #128/#129 because the old
format cannot prove which conflicting tail was committed. Readiness never
guesses or performs an unaudited destructive rebuild.

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
backend dispatch and may return the typed response. The new public error
variants require external exhaustive matches. Protocol v4 maps them through
private fixed-width DTOs under error revision 1 and rejects v3 peers during the
exact handshake. Operators must audit legacy
persisted logs before upgrade because a TTL-bearing entry
above the bound now fails closed during replay/rebuild rather than being
clamped or rewritten. Replicated deadline validation permits at most one
microsecond above exact `entry.timestamp + ttl` for legacy `seconds_f64`
rounding only; new deadlines remain exact, the TTL bound is unchanged, and
larger mismatches fail closed.

This closes only the duration-input/process-availability gap in #137. Openraft
commit authority is independent; repair, restore, and qualification work remain
open. Caller-authored absolute record expiry remains #148.

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

This was a breaking confidentiality contract before protocol v4. An older peer
cannot decode the new error, and an older wrapper may forward a deep CAS as
plaintext/unsealed data. Protocol v4 rejects the older wire participant and
pins the limits/error revision, but cannot attest that a protection wrapper is
actually installed. Drain and upgrade all clients, servers, and wrapper
participants together, verify product composition, and do not call this
rolling-compatible.

Historical nested plaintext is not automatically scrubbed. Operators must
audit persisted tree shape and payload encoding offline before upgrade. Entries
within the new limits may be explicitly rewritten/rebuilt through the configured
protection wrapper. Over-limit history fails before transformation and requires
a separately reviewed atomicity-preserving offline migration or audited store
replacement before the new SDK starts; it must not be clamped or split ad hoc.
Raw inner-backend rebuild does not add protection.

#147 closes only this bounded nested-payload path. The session profile remains
experimental until the remaining non-consensus gates pass. Seamless SVID/trust-bundle lifecycle remains #158;
remote-seal historical-key rotation remains #179, while distributed
payload-protection and production qualification remain #143. These are
separate mandatory gates.

### Consensus transport and encryption boundary

The production authority path uses `SessionConsensusServer` and
`RemoteSessionConsensusPeer` over the exact `opc-session-consensus/1` ALPN.
Consensus DTOs carry only bounded Openraft RPC families and application
forward/read-barrier requests. Sender identity is checked against both the
authenticated peer and the inner Openraft vote/log sender before dispatch.
The legacy writable backend protocol cannot negotiate on this listener.

Payload protection remains outside consensus:

```text
application -> EncryptingSessionBackend / RemoteSealingSessionBackend
            -> ConsensusSessionStore -> Openraft -> SQLite and snapshots
```

New plaintext writes are sealed before `client_write`. Openraft, consensus RPC
encoding, follower apply, replay, outcomes, snapshots, and restart have no key
provider and see only opaque envelopes. Historical-key lookup occurs only when
a read crosses the outer wrapper. Tests prove plaintext and raw key canaries are
absent from RPC frames, state/log/outcome tables, WAL/SHM, and snapshot files;
provider call counts stay unchanged during replication, snapshot, and restart.
Missing historical keys fail reads closed without preventing already-sealed
quorum recovery.

This is payload-envelope encryption, not full-database encryption. Membership,
indexes, routing fields, owners, fences, timestamps, and envelope key IDs remain
visible unless a separate approved storage layer protects them.

### Legacy backend and restore transport (protocol v4)

`opc-session-net` protocol v4 carries validated restore-scan requests and pages
to individual remote replicas. A server may shorten a multi-record page to the
smaller client/server frame budget; callers resume from `next_cursor`, while a
single record that cannot fit returns `RestoreScanResponseTooLarge`.

Every production participant is created with an opaque authenticated TLS
config and a binding derived from one immutable `SessionReplicationManifest`.
The manifest's configuration ID is an order-independent SHA-256 digest of the
cluster ID, operator-controlled generation, and every field of every replica
descriptor. During the v4 handshake, each side extracts the canonical SPIFFE
URI from the live certificate and requires it to match the claimed stable
`ReplicaId`, expected opposite member, cluster, and configuration ID before
dispatch. The client verifies its fresh challenge is echoed by the server.
DNS/FQDN/IP aliases and resolver overrides affect
routing only; they never redefine replica identity.

The exact `opc-session-net/4` ALPN, version, and contract profile have no
production fallback to v3. A v3-to-v4 change is a coordinated
stop/upgrade/start of all clients and servers, not a mixed-version rolling
deployment or highest-common-version negotiation. Public `Request`/`Response`
remain available, but `Hello`/`HelloAck` gain an optional `contract_profile`, so
exhaustive construction and matching must account for the new field.

Wire-schema revision 2 extends the exact v4 bootstrap with directional frame
budgets. Hello sends `requested_response_frame_size`; HelloAck returns the
client/server-minimum `accepted_response_frame_size` plus the independent
`server_request_frame_size`. Each checked `u32` must be at least
`MIN_NEGOTIATED_FRAME_SIZE` (8 KiB, or 8,192 bytes) and at most
`MAX_NEGOTIATED_FRAME_SIZE` (16 MiB, or 16,777,216 bytes).
`MIN_RESTORE_SCAN_RESPONSE_FRAME_SIZE` aliases the same minimum. Unequal
client/server settings are therefore explicit. Revision-1 and revision-2 v4
participants do not interoperate even though their ALPN text is the same.

The private v4 DTOs use `u32` for restore/log request limits and the restore
response budget, and `u64` for restore cursors/excluded counts,
`max_value_bytes`, and size-bearing store errors. Restore `loaded_count` and
`complete` are omitted and recomputed after decode. Independent work limits
admit 256 batch operations, 1,024 restore records, 65,536 log entries, and
65,536 rebuild entries; the configured frame bound remains separate. The exact
profile pins wire-schema revision 2, error-set revision 1, 128-byte
owner/custom-key/state-type bounds, the 31,536,000-second TTL maximum, and
depth-16/256-node replication trees. Revision 2 also pins
`min_frame_size = 8192`, `max_frame_size = 16777216`,
`stable_id_max_bytes = 64`,
`replication_tx_id_max_bytes = 128`, and `cas_request_id_bytes = 36`.
Transported stable IDs contain 1 through 64 bytes, transaction IDs contain 1
through 128 UTF-8 bytes, and CAS request IDs, when present, use the canonical
lowercase hyphenated 36-byte UUID encoding.

Every server response and watch item is fully bounded-encoded before a length
prefix is emitted. Common non-pageable and complete-page successes use one
bounded encode without a sizing preflight. An oversized pageable direct attempt
emits no prefix; bounded logarithmic sizing probes and the final encode share
one absolute deadline established before the first encode/probe and continuing
through prefix, payload, and flush. Lazy exact-length boxed chunks are not
coalesced and retained encoded-JSON
byte storage stays within the limit; metadata and allocator slab/RSS overhead
remain separate. Storage/sizing sinks check deadline and server-abort
cancellation cooperatively between serializer writes/chunks. Tokio cannot
preempt one synchronous serializer callback, whose input remains bounded by the
profile. Expiry closes the connection and returns the handler/connection permit.
Get/CAS records and positional batch vectors are never truncated. Restore may
return a complete cursor-correct prefix; replication-log reads return the
largest complete contiguous-sequence prefix that fits. Watch cannot skip an
oversized entry; it emits a fixed SDK-owned error when representable and ends,
or closes immediately. A fixed fallback that itself cannot fit also causes a
fail-closed close. Rejected nested entries keep iterative disposal and bounded
work.

Transport `max_value_bytes` is clamped to the backend maximum and exactly
`(frame - 8192) / 8` for both the accepted response and server request frames.
The reserve and factor cover the record/key/error envelope, worst-case JSON
byte-array expansion, and equal escaping/metadata headroom. The advertised
maximum can perform a real write/read round trip under unequal limits. It
is zero at the exact 8 KiB minimum; payload-bearing traffic requires a larger
frame. The 1 MiB default advertises 130,048 bytes; the 16 MiB ceiling advertises
2,096,128, and SQLite's full 1 MiB limit requires at least 8,396,800 frame
bytes. A 16 MiB setting is recommended for that profile. This is per frame: at
the default 128 connection slots, concurrent ceiling-sized encodes can retain
about 2 GiB before metadata/TLS/runtime overhead. The aggregate scales with
`with_max_connections`, so aggregate limiting and resource/soak evidence remain
#143. It remains descriptive, not traffic or quorum authority.

A version/profile/authentication or malformed-handshake failure clears cached
capabilities and reports every boolean false with `max_value_bytes = 0`.
Capabilities retained after transient transport loss remain descriptive only;
they never authorize a store operation or readiness. Use fresh bounded quorum
evidence and continuous traffic gating.

Before the v4 rollout, drain traffic and writers, run the #135 count-only
identity audit, and preflight every live/replayable handover and nested-payload
copy. Stop and upgrade every client, server, protection wrapper, and product
handover reader/writer together; verify exact-v4 authenticated restore/log
traffic and fresh quorum evidence before reopening traffic. Once `OPCH` has
been written, rollback to a v3 binary additionally requires a coherent drained
checkpoint restore or reviewed reverse migration of every live and replayable
record, log, snapshot, and restore source.

The revision-1 to revision-2 profile transition uses the same coordinated
stop/upgrade/start and verification; it is not a same-ALPN rolling upgrade.
#159 does not rewrite persisted store bytes. In-profile stores need no format
conversion, but strict revision-2 transport rejects retained empty/over-64-byte
stable IDs and empty/over-128-byte UTF-8 transaction IDs. Before startup,
quiesce writers, inventory every record/log/snapshot/restore/replay source, and
perform a decoder-first product-aware migration or coherent store replacement
under #167/#168. The migration reader must decode the legacy representation
before rewrite, must not truncate/hash/rename durable identities, and the strict
decoder must verify the result before writers restart. Rollback must first
install a decoder that reads the retained target representation, or restore a
coherent checkpoint/run a reviewed reverse migration. Every participant still
moves to one exact profile together. Rollback across `OPCH`/#135 retains its
independent coherent-checkpoint or reverse-migration requirement.

Session caches, tickets, resumption, early data, and 0-RTT are disabled, so a
reconnect performs a full mutual-TLS certificate exchange. Production still
requires seamless certificate and trust-bundle rotation without interrupting
session service, including trust overlap, revocation, long-lived-connection
retirement, reconnect storms, and a documented maximum authentication age.
The seamless lifecycle remains #158 and distributed qualification remains
#143. Session TTL is application-state lifetime; the 365-day bound is not a
certificate-expiry, trust-validity, or authentication-age policy.

Response delivery is not atomic with backend mutation. A CAS, batch slot, lease
change, replicated append, or rebuild may commit before bounded encoding or the
socket write fails. Missing responses are ambiguous; clients recover through
the operation's request-ID/idempotency and fencing rules plus authoritative
re-read, never by assuming rollback and blindly replaying. Operational evidence
uses bounded operation-family/reason categories for oversize/fallback/timeout
without logging keys, payloads, owners, transaction IDs, peer identities, or
backend/peer-controlled error text.

This closes per-replica compatibility transport parity only. Restore
selection/merge remains #133. Protocol v4 is not the production consensus
protocol and does not establish authority; #127 uses the separate Openraft
transport above, while legacy-fork repair remains #128/#129.

### Log & Replication Model
- **Openraft Log Authority**: Openraft allocates and commits its zero-based log
  indexes. No SDK coordinator assigns an authoritative distributed sequence or
  performs majority-prefix rollback. Vote, log, committed/applied/purged,
  membership, and snapshot metadata persist transactionally in SQLite.
- **Deterministic Application Journal**: Committed mutations (AcquireLease,
  RenewLease, ReleaseLease, CompareAndSet, DeleteFenced, RefreshTtl, Batch) are
  applied in order and produce the existing 1-based
  `session_replication_log` as a state-machine output for watches/restores. It
  is not a second consensus log.
- **Idempotent Outcomes**: Durable request IDs bind to a digest of semantic
  intent. Exact retries return the original logical time, journal sequence,
  Raft index, and result, including after leader change; a changed intent under
  the same ID fails closed.
- **Logical Expiry Time**: Expiry-sensitive reads first commit monotonic
  logical time, preventing clock rollback or leader failover from resurrecting
  an expired record or lease.
- **Resume Tokens / Watch Cursors**: Watches publish only committed application
  entries and allow consumers to resume from the 1-based sequence cursor.
- **Raw Authority Rejection**: Direct `replicate_entry`, whole-state rebuild,
  and caller-selected lease metadata operations are rejected by
  `ConsensusSessionStore`.
- **Feature Declarations**: Replicated adapters declare `ordered_replication_log = true` and `watch = true`, while standalone SQLite reports `false`. These bits describe implemented methods; they are not fresh-quorum readiness or production qualification. Consumers must use `probe_durable_readiness` for current evidence.
- **Low-Cardinality Readiness Telemetry**: Metrics expose probe success/failure and bounded Openraft state without replica IDs, endpoints, SPIFFE IDs, tenants, keys, or raw errors as labels.

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

### Session Store HA Failure Tests (Openraft)

The fleet tests use three distinct file-backed SQLite databases and real
Openraft RPC handlers over controllable in-process paths; the testkit does not
implement a second quorum algorithm.

- **Cold-start concurrency**: Concurrent first writes form one gap-free
  committed journal without equal-sequence forks.
- **Cross-node authority**: Lease/CAS writes converge, follower reads pass a
  linearizable barrier, and only Openraft-backed stores claim quorum.
- **Partition and healing**: A node isolation causes bounded readiness/write
  failure where quorum is unavailable; healed paths catch up and rejoin.
- **Ambiguous response retry**: A delivered-but-lost forwarded response can be
  retried with the same durable request identity and produces exactly one
  committed application event.
- **Raw authority rejection**: Direct replication/rebuild/lease-sequence
  surfaces cannot bypass Openraft.
- **Encryption/HKMS isolation**: Real outer-wrapper writes, key rotation,
  snapshots, restart, and missing historical keys prove only sealed envelopes
  enter consensus and no provider calls occur below the wrapper.
- **Stale-fence replay**: Stale fence updates are rejected monotonically.
- **No wall-clock LWW**: Leader-selected monotonic logical time, not replica
  wall-clock last-writer-wins, drives expiry state.
- **Bounded TTLs**: Exercises zero, the exact 365-day maximum, maximum plus one,
  and `Duration::MAX` across direct, nested, persisted, quorum, and
  authenticated-wire paths, including no-partial-effect and near-maximum-clock
  cases.
- **Nested payload protection**: Exercises depth/count edges, deep CAS
  encryption/sealing round trips through replicate/rebuild/log/watch, complete
  prefix/page preflight, sequential-provider failure, and no backend delegation
  or partial entry/page exposure.
- **Required bounded-response qualification**: Must exercise equal/unequal revision-2 budgets,
  8 KiB/16 MiB/MAX+1 admission, a non-power-of-two retained-chunk allocation,
  exact-limit and one-byte-over response families, conservative maximum-payload
  round trips, cursor/sequence-preserving prefixes, non-truncated batches,
  fixed redaction-safe fallbacks, authenticated slow-reader reaping, connection
  slot recovery, ambiguous mutation outcomes, and deterministic shutdown.
  Passing those tests demonstrates the #159 transport boundary only; it does
  not close #167/#168 retained-identity work, #169 persist RPC deadlines, #158
  seamless credential lifecycle, or #143 production qualification.
