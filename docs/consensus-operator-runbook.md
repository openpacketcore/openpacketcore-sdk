# OpenPacketCore Consensus Operator Runbook

This runbook describes operational procedures, bootstrap sequences, failover/recovery scenarios, membership transitions, disaster recovery protocols, and verification methods for the High Availability (HA) consensus store (`ConsensusConfigStore`) in `opc-persist`.

---

## 1. Bootstrap Procedures

### 1.1 Node Identity & SPIFFE Certificate Formatting
Each replica node in the cluster must be provisioned with an X.509 certificate carrying a valid SPIFFE Subject Alternative Name (SAN) URI. The URI must follow this precise format:
`spiffe://test/trust-domain/tenant/test/ns/default/sa/svc/nf/test/instance/<node_id>`

Where `<node_id>` matches the numerical node ID configured in the cluster membership settings.

### 1.2 Trust Domain Validation
- During the TLS handshake, peers perform mutual TLS (mTLS).
- The server extracts the SAN URI from the client certificate.
- It validates that the scheme is `spiffe://`.
- It validates the trust domain matching, ensuring the peer belongs to the authorized trust domain and tenant.
- It parses the trailing `<node_id>` and checks it against the active membership:
  - The sender node ID presented in the RPC request must match the ID extracted from the client certificate.
  - The node must belong to the active cluster membership.
  - If validation fails, the RPC is rejected immediately with an authentication error.

### 1.3 Cluster ID Configuration
At startup, nodes require a matching `cluster_id` configuration.
- The `cluster_id` is persisted in the SQLite schema (`consensus_membership` table).
- If the configured `cluster_id` does not match the persisted `cluster_id` from a previous run, startup is aborted to prevent operator errors (such as re-assigning a database disk to a different cluster).

### 1.4 Startup Order
To bring up a cluster cleanly:
1. **CA and Certificate Authority Setup**: Generate or obtain the shared root/intermediate CA certificate and keys.
2. **Client Config & Certificate Generation**: Issue server/client certificates for each node with the correct SPIFFE ID mapping the node ID.
3. **Database Initialization**: Ensure the SQLite database path is writable.
4. **Server Loop Launch**:
   - Configure the network listener socket with `SO_REUSEADDR`.
   - Launch the TCP/TLS server loop, binding the socket, limiting it to 100
     concurrent connection handlers, and applying the fixed five-second
     timeout to the TLS handshake.
   - Do not interpret that handshake timeout as a five-second timeout for all
     server I/O. After mTLS completes, request length/body reads and the
     response write are bounded by the 16 MiB frame limit but currently have no
     independent server-side I/O deadline. The client logical deadline
     described below bounds the client call and closes its connection on
     expiry; it is not a substitute for a server-side post-handshake
     slow-client deadline.
   - Start the consensus background loops (election timer, heartbeat driver, log replication loop).

### 1.5 Logical RPC Deadline and Retry Contract

`TcpPeer::new(..., timeout)` and the test-node `--rpc-timeout <MS>` option use
one absolute deadline for one logical peer RPC. The budget starts before local
authentication and TLS-connector lock acquisition and includes cooperative
request serialization, TCP connect, the mTLS handshake, request writes,
response length/body reads, cooperative response decoding, all retry attempts,
and the 50/100 ms retry backoffs. A stage or retry is not started after the
deadline. Zero expires before setup or network I/O; a duration that cannot be
represented by the monotonic clock fails closed.

The transport makes no more than three attempts, and only when the remaining
logical deadline permits them. Retry behavior is request-specific:

- `RequestVote`, `AppendEntries`, and `InstallSnapshot` repeat the same Raft
  term/log coordinates and may be replayed after ambiguous delivery.
- `LoadLatest` and `LoadRollback` are read-only and may be retried.
- `TimeoutNow` can launch a campaign. Once any request bytes may have reached
  the server, a lost response is ambiguous and the transport must not replay
  it. The operator must observe the resulting term/leadership state rather than
  assuming that the trigger failed.
- Invalid local identity/TLS configuration and certificate-verification
  failures are permanent for that call; they fail immediately instead of
  being retried until reported as a timeout.

Election vote requests and replication across different peers fan out
concurrently, so peer count does not multiply a single fan-out round's
transport deadline. Catch-up within one peer remains sequential and is capped
at 64 snapshot/append rounds per synchronous pass or background trigger. A
rejected snapshot can fall through to one append in the same round, so a pass
issues at most 128 sequential logical RPCs. The maximum transport wait for one
such peer pass is therefore `128 * rpc-timeout`; local database work and
scheduling add overhead. If the peer is still behind, the task exits and a
later replication trigger resumes from the stored `next_index`. Size
election/failover and drain budgets with that distinction in mind.

This is a breaking timing-semantic change from SDK versions that reset the
configured value for every I/O stage. Before upgrading, retune
`TcpPeer::timeout`/`--rpc-timeout` as an end-to-end value, update election,
failover, and drain budgets, and roll out the selected value coherently across
cluster members. SDK consumers that exhaustively match `PersistErrorKind` must
also add the typed `ConsensusRpcTimeout` variant.

### 1.6 Seamless Certificate and Trust-Bundle Rotation

`set_identity` atomically replaces the local server identity/acceptor pair, and
each peer adapter atomically invalidates its cached client connector for new
RPC attempts. An in-flight attempt may finish with the previous connector; a
later attempt reads the current connector. Multi-peer propagation is
serialized but not transactional: failure or cancellation can leave mixed
peer generations. The caller must retain trust overlap, retry, and gate on
fresh-handshake evidence. A production CNF must supply the lifecycle around
that API:

1. Watch the workload identity and trust bundle and call the live
   `set_identity` path when they change. The `opc-consensus-node` test binary
   reads PEM files only at startup and is not a production rotation controller.
2. Distribute a trust bundle containing both old and new issuers before
   switching leaf certificates.
3. Rotate leaves without changing the node's exact SPIFFE workload profile or
   instance identity, allow old in-flight connections to drain, and verify new
   mTLS connections across every peer.
4. Remove the old issuer only after the maximum old-connection/authentication
   age has elapsed and rollback is no longer required.

Replacing leaf and trust material simultaneously without overlap can interrupt
quorum communication. The CNF operator must gate traffic/readiness on the
rotation, bound reconnect storms, and alert on authentication failures; a
certificate expiry timer alone is not a seamless-rotation design.

---

## 2. Shutdown & Recovery

### 2.1 Graceful Shutdown

To shut down a node cleanly:

- Trigger a shutdown via the oneshot shutdown hook (`server_shutdown`) or SIGTERM signal handling.
- The shutdown hook stops the listener from accepting new connections.
  Connection handlers are detached tasks: the hook does not wait for them,
  close them, or provide a flush barrier.
- Before invoking the hook, the CNF must remove the pod from readiness, stop
  new client and peer traffic, and allow in-flight RPCs and durable writes to
  drain within its termination grace period.
- Active leaders that are shut down gracefully will fail to send heartbeats, triggering a new election among the remaining online replicas.

### 2.2 Hard Crash / Kill Recovery
If a node is killed abruptly (`kill -9` or power outage):
- **Durability Guarantee**: All consensus state (current term, voted for, applied index, consensus log) is stored in the local SQLite database using transaction-safe journaling (WAL mode and fsync enabled).
- **Restart Replay**: Upon restart, the node reads the persistent database state:
  - Restores the epoch term (`current_term`) and last vote (`voted_for`).
  - Restores the last applied index (`applied_index`) and membership.
  - Replays any applied config changes up to `applied_index` idempotently.
  - rejoins the cluster as a Follower and waits for heartbeats or campaigns.

---

## 3. Membership Transitions

### 3.1 Non-Voter Promotion & Leader Transfer
- **Non-Voter Promotion**: A new node is added as a non-voter first. The leader
  replicates the consensus log to the non-voter until its log catch-up index is
  close to the leader's commit index. Each catch-up pass stops after 64 rounds
  (at most two logical RPCs per round); if more work remains, later triggers
  resume from `next_index`. Only after the log is verified caught up can the
  non-voter be promoted to a voting member.
- **Leader Transfer**: To safely step down a leader, it can trigger a role transition to Follower, allowing a caught-up peer to win the next election campaign.

### 3.2 Raft Joint Consensus for Additions/Removals
To add or remove nodes without risk of split-brain:
1. **Stage 1 (Joint State)**: The leader commits a transitional configuration entry $C_{\text{old,new}}$. A majority of both the old configuration $C_{\text{old}}$ and the new configuration $C_{\text{new}}$ must independently commit the change.
2. **Stage 2 (New State)**: The leader commits the new configuration entry $C_{\text{new}}$. Only a majority of the new configuration is required to commit entries from this point onward.
3. **Epoch Monotonicity**: Every configuration change increments the membership epoch. Stale updates with lower epochs are rejected to maintain order.

---

## 4. Disaster Recovery

### 4.1 Quorum Loss (Split-Brain)
- If a network partition splits a 3-node cluster into a 2-node partition and a 1-node partition:
  - The 1-node partition cannot form a majority quorum and fails closed: it rejects writes and fails reads.
  - The 2-node partition forms a majority quorum ($2/3$) and continues processing reads and writes.
- If a 2-node cluster suffers a 1-node failure, the remaining node cannot form a majority and fails closed.

### 4.2 Partition Isolation & Healing
- **Isolation**: Stale leaders on the isolated side of a partition cannot contact a majority. They will step down to Followers upon failing heartbeat replies or when they receive an RPC from a higher term.
- **Healing**: When the network heals, the stale nodes reconnect. The active leader probes their logs, detects the discrepancy, truncates uncommitted stale entries, and replicates missing logs to catch them up.

---

## 5. Compaction & Backups

### 5.1 Compaction Boundary Rules
- Log entries are periodically compacted into database snapshots to save disk space.
- Compaction must never truncate logs beyond the current `applied_index` to ensure unapplied entries are not lost.
- The compacted snapshot retains the index and term of the last compacted log entry to maintain log continuity.

### 5.2 Log Truncation Synchronization
- If a follower's log diverges from the leader's log, the leader sends an RPC to overwrite or truncate the follower's uncommitted log entries.
- Follower log truncation is synchronized and transactional, ensuring that no committed entry is ever truncated.

### 5.3 Snapshot HMAC Validation
- Compacted snapshots are cryptographically sealed with HMAC-SHA256.
- The HMAC key is derived from the node's local `AuditKey`.
- When loading a snapshot or restoring from backup, the node verifies the HMAC. If the HMAC signature is invalid or tampered with, the snapshot is rejected, preventing corruption from spreading.

---

## 6. Operations & Alerts

### 6.1 Metrics Interpretation
The consensus engine exports several atomic counters and gauges:
- `election_count`: Monotonic counter of election campaigns started.
- `leader_changes`: Counter of leadership role transitions.
- `rpc_failures`: Counter of logical peer RPC calls that ultimately failed
  after the bounded retry policy. Individual failed transport attempts are
  debug events, not separate increments of this counter.
- `rpc_timeouts`: Count of typed logical RPC deadline expirations observed by
  the consensus store. Permanent authentication/configuration failures are not
  included.
- `rpc_timeouts_by_family`: The same logical timeout events split across the
  fixed `request_vote`, `append_entries`, `install_snapshot`, `load_latest`,
  `load_rollback`, and `timeout_now` keys.
- `rpc_timeouts_by_stage`: The same events split across fixed setup,
  serialization, TCP, TLS, write, response-read/decode, and retry-backoff
  keys: `deadline_setup`, `authentication_setup`, `request_serialization`,
  `tls_configuration`, `tcp_connect`, `tls_handshake`, `request_write`,
  `response_length`, `response_body`, `response_decode`, and `retry_backoff`.
  Endpoints, node IDs, SPIFFE identities, tenants, and request data are never
  metric dimensions.
- `snapshot_installs`: Counter of snapshot installations.
- `read_quorum_failures`: Counter of linearizable read failures due to lack of peer contact.
- `server_rejected_connections`: Counter of incoming connections rejected by
  the bounded server admission or authentication checks.

### 6.2 Alarm Manager Triggers
The following alarms are registered and triggered via the `SharedAlarmManager`:
- **Quorum Loss / Election Failure**: Raised if no leader is elected for an extended period, or if the local node cannot contact a majority.
- **TLS Handshake / Auth Failures**: Raised if there is a persistent wave of unauthenticated peer connections (e.g. mismatching trust domains).
- **Disk Full / DB Write Errors**: Raised if SQLite returns database write/commit errors.

### 6.3 Unsupported Operations
- **Unapproved Node Rejoining**: A node whose certificate or node ID is not in the active membership list must not be allowed to join or connect. It will be rejected during mTLS validation.
- **Self-Removal**: Active nodes cannot trigger their own removal from the cluster directly without coordinating a leader transfer first.

---

## 7. Verification Commands

### 7.1 Run Sequential Tests
Because testing consensus protocols requires clean database states and port availability, run the end-to-end test suite sequentially using:
```bash
ulimit -n 2048 && cargo test --locked -p opc-persist --all-features -- --test-threads=1
```

### 7.2 Run Formatter Check
Verify code formatting:
```bash
cargo fmt --all --check
```

### 7.3 Run Clippy Linter Check
Verify clean lints:
```bash
cargo clippy --workspace --all-targets --all-features -- -D warnings
```
