# OpenPacketCore High Availability and Consensus Design

This document details the High Availability (HA) architecture and implementation for the
OpenPacketCore config and session persistence surfaces.

- **Config Store**: `ConsensusConfigStore` is a durable config-consensus
  prototype with durable membership, transport-level mTLS/SPIFFE identity checks,
  Raft-like safety guards, snapshots, metrics hooks, and multi-process fault
  tests. These are tested prototype properties, not carrier HA qualification.
- **Session Store**: `QuorumSessionStore` is an in-process quorum ordered-log
  adapter with a majority-visible-prefix repair prototype, watch cursors,
  stale-replica catch-up, and chaos tests. Production networked HA depends on the experimental
  `opc-session-net` transport and further distributed/soak evidence.

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

Platform hardening concerns—including TLS/SPIFFE SVID and bundle watch/reload (`GAP-003-001`), KMS-backed durable key providers over mTLS TCP or local Unix-socket KMS agents (`GAP-003-004`), and storage-fault injection (`GAP-001-005`)—have been fully implemented, verified, and closed.


---

## 2. Replicated Session Store Ordered Log: `QuorumSessionStore`

The algorithm below describes intended and prototype-tested behavior; it is not
yet durable distributed proof or a production deployment contract. Validated
topology/readiness/identity (#123–#125), durable sequencing and safe fork
recovery (#127–#129), and bounded majority-authoritative restore (#133) remain
open; wire-width and shared model-decoding hardening remain #134/#135.

`QuorumSessionStore` coordinates session leases and CAS mutations across a set of `SessionStoreBackend` replicas using quorum-backed ordered replication. It is not a Raft implementation; its target safety contract is a durable committed log prefix where an entry is authoritative only after the same sequence entry is present on a majority of replicas.

### Network restore transport (protocol v2)

`opc-session-net` protocol v2 carries validated restore-scan requests and pages
to individual remote replicas. A server may shorten a multi-record page to the
smaller client/server frame budget; callers resume from `next_cursor`, while a
single record that cannot fit returns `RestoreScanResponseTooLarge`. The Hello
handshake requires an exact version match, so v1/v2 peers require a coordinated
upgrade and cannot form a mixed rolling deployment.

This closes per-replica transport parity only. Quorum selection/merge remains
#133, while durable sequencing and repair authority remain #127/#128.

### Log & Replication Model
- **Persisted Replica Logs**: The current coordinator assigns sequence numbers to replicated mutations (AcquireLease, RenewLease, ReleaseLease, CompareAndSet, DeleteFenced, RefreshTtl, Batch), and each accepting replica writes them to `session_replication_log`. Leader/term-gated global sequence authority remains #127.
- **Idempotency & Replay Semantics**: Duplicate delivery is handled safely. Before appending, replicas check if the entry's sequence has already been applied. If the transaction ID (`tx_id`) matches, the duplicate is accepted as an idempotent success; if it differs, the replica fails closed on sequence divergence. Replaying operations does not mutate the state twice.
- **Current Majority-Visible Prefix Heuristic**: The coordinator compares the logs visible from the current online majority and rebuilds replicas to that shared prefix. This is prototype behavior, not durable commit proof: without #127/#128, a later visible majority can omit a previously acknowledged entry and drive unsafe truncation.
- **Resume Tokens / Watch Cursors**: Exposes watches backed by sequence numbers, allowing consumers to supply sequence cursors and resume receiving updates from the exact sequence they left off.
- **Replica Catch-Up & Read Repair Prototype**: The coordinator queries replica log progress on every write or read and repairs against the current majority-visible prefix. Reads require identical records on a majority quorum and fail closed if no quorum result exists, but repair authority remains unproven until #127/#128.
- **Failed-Write Rollback Fixture**: If a new replication entry reaches fewer than a majority of replicas, the current implementation attempts to rebuild successful partial writes to the previously observed prefix. Tests exercise this path; they do not prove resurrection safety across partitions/restarts before #127/#128.
- **Feature Declarations**: Replicated adapters declare `ordered_replication_log = true` and `watch = true`, while standalone SQLite reports `false`. These bits describe implemented methods; they are not fresh-quorum readiness or production qualification (#124).

---

## 3. Local Session Cache Invalidation: `SessionCache`

`SessionCache` (implemented in the `opc-session-cache` crate) provides a local, in-memory read-through cache for session records in downstream CNFs. It keeps cache hits behind an explicit coherence gate: local values are served only when the background watch stream is active and the processed sequence is caught up to the backend's committed replication sequence. If the cursor cannot be verified, reads bypass local memory and go directly to the authoritative backend.

### Coherence & Invalidation Model
- **Read-Through Population**: When `get` misses the local cache, the record is fetched from the authoritative backend. It is populated in memory only after the cache verifies that the watch cursor is caught up to `max_replication_sequence`. If the cursor is lagging, unavailable, or syncing, the read succeeds from the backend but the value is not cached.
- **Coherent Cache Hits Only**: Before serving a cached value, the cache checks that the watched sequence is at least the backend's current committed sequence. If the backend is ahead, the cache clears local state, marks the watch unhealthy, and bypasses cache hits until the watch loop catches up or resyncs.
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

- **Split-brain healing**: Exercises coordinator recovery after simulated partitions are resolved.
- **Durable catch-up**: Rejoining replicas are caught up automatically with log replication.
- **Duplicate delivery**: Duplicate entries are resolved idempotently without duplicate mutations.
- **Partial-write recovery**: Failing mid-flight writes are recovered and reconciled to majority nodes.
- **Stale-fence replay**: Stale fence updates are rejected monotonically.
- **Read repair**: Divergent nodes are updated and verified on read.
- **Restart/rejoin across profiles**: Exercises restart/rejoin behavior under fake, SQLite, and replicated profiles.
- **No wall-clock LWW**: Observes that the tested ordering paths do not select authoritative state by wall-clock time.
