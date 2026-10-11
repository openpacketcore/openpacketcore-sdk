# opc-persist

Persistence primitives for configuration commits, audit chains, security
policy, and Openraft-backed configuration consensus.

## Purpose

`opc-persist` provides the durable storage contracts used by configuration and
security-policy code. `SqliteBackend` remains the reference single-replica
implementation. `ConsensusConfigStore` coordinates that SQLite state through
the workspace's shared Openraft engine; it is the only distributed config
authority in this crate.

The adapter is implementation evidence, not carrier-production qualification.
Standalone SQLite remains a development, lab, conformance, or explicitly
accepted single-replica profile.

## API shape

- `ConfigStore` is the async commit-store trait: `load_latest`,
  follower-local `load_committed_latest`, bounded ordered `load_since`,
  `wait_for_committed_change`, `load_rollback`, `append_commit`,
  `mark_confirmed`, `create_rollback_point`, and `preflight`.
- `SqliteBackend::open_with_audit_key` opens or creates SQLite state. Durable
  opens require an explicit non-zero `AuditKey`; this API is not reopen-only.
- Retained configuration voters use explicit `provision_config_authority`,
  `reopen_config_authority`, and `provision_config_member_repair` operations.
  Missing retained storage never falls back to creation during reopen. See the
  [retained lifecycle contract](RETAINED_CONFIG.md) for scope binding,
  interruption, repair, durability choices and rollback-freshness limits.
- `AuditKey::new([u8; 32])` rejects all-zero keys, and
  `AuditKey::new_with_epoch` adds an explicit rotation epoch. Consensus binds
  the non-secret epoch/fingerprint into peer and durable identity and verifies
  current audit HMAC state at startup.
- `ConsensusConfigStore` supplies Openraft-coordinated writes, linearizable
  reads/readiness, bounded durable request outcomes, and snapshots. Its voter
  set is immutable within one topology epoch. Construction requires an exact
  `ConfigConsensusTopology` and one
  shared `opc_consensus::ConsensusPeer` route for every configured remote
  voter. Every node may call `initialize_cluster` concurrently; on clean first
  formation only the canonical lowest node initializes Openraft and the other
  pristine nodes wait for replicated membership. Nodes reopening durable
  Openraft state skip bootstrap and re-admit normally. Clean first formation
  fails closed when the canonical node is absent; it never lets another
  pristine node mint competing initial authority.
- `ConsensusConfigStore::retain_history_idempotent` commits an exact-head,
  explicitly acknowledged retention decision with `ConfigHistoryRetention` and
  `ConfigHistoryLimits`. `ConfigHistoryFull` rejects capacity overflow atomically;
  `ConfigHistoryProtected` rejects unresolved history references. The authenticated
  `retained_history_floor` distinguishes an intentionally pruned cursor from
  corruption. Raft snapshots alone do not prune this application history.
- `ConsensusConfigStore::rpc_handler` exposes the shared bounded inbound
  consensus port. `opc-persist` does not contain a second TCP or TLS transport.
- `ConsensusConfigStore::ensure_local_authority` performs a local-only
  Openraft read-index barrier, waits for local apply, and verifies exact
  admitted membership. It returns `LocalAuthority`, `Retry` with an optional
  canonical node ID, or `Unavailable`; unlike ordinary store operations it
  never forwards the check to a peer. Management protocols use this result to
  redirect before touching a local projection or mutation path.
- `ConsensusConfigStore::ensure_local_authority_at_config_head` additionally
  drains the fixed proposal-admission cohort under the same operation deadline,
  compares the payload-free projected transaction/version with the canonical
  local SQLite state-machine head, and repeats the same-term Openraft barrier.
  Every return path releases the drained permits.
- `ConsensusConfigStore::open_local_authority_projection` keeps that same
  cohort held around a consumer-owned, payload-free projection callback, then
  rechecks term and exact durable head before opening local writes. It is the
  product-neutral leader-open seam for a live config projection; it adds no
  consensus or leader tracker.
- `ApprovedLegacyConfigRecovery` is the explicit offline admission object for
  replacing nonempty legacy authority with one exact applied snapshot.
- `SecurityPolicyService` and `SqliteSecurityPolicyService` stage, validate,
  apply, dry-run, roll back, inspect, and list security policies.
- Break-glass APIs model request, approval, activation, denial, revocation,
  and expiry with alarm and approval hooks.

```rust,no_run
use opc_persist::{AuditKey, ConfigStore, SqliteBackend};

async fn open_store() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let key = AuditKey::new([3u8; 32])?;
    let store =
        SqliteBackend::open_with_audit_key("config.db", false, 10 * 1024 * 1024, key).await?;
    store.preflight().await?;
    Ok(())
}
```

`ConsumerCheckpointStore` provides separate, sealed single-owner consumer
storage with explicit provision/reopen, bounded CAS/readback and owned shutdown.
It implements no configuration-authoring or voter trait. Its
[consumer contract](../opc-config-bus-consensus/CONSUMER_CHECKPOINT.md) documents
the exact custody, apply ordering and rollback-freshness limits.

## Voter-slot incarnation profile

The unadvertised [RFC 023](../../docs/rfc/023-voter-slot-incarnations.md) profile
uses `ConfigConsensusTopology::for_voter_slots` and
`ConsensusConfigStore::open_with_voter_slots`. Its separate
`VoterPeerResolver` must bind every channel to the committed descriptor,
workload credential and incarnation key. Raw legacy RPC admission is refused.
`replace_voter` accepts a verified controller request; `voter_replacement_status`
resolves an accepted request under current controller authorization without
renewing the original credential or granting another replacement.

A provisional retirement is stored with the exact retained Prepare log entry.
The committed table and bounded receipt are published with apply. Truncation
and snapshot installation release a provisional gate only when durable evidence
resolves its entry. Engine response fences are restored before RPC admission;
Openraft continues to own every election, membership and quorum decision.
After Fence applies with effect, survivors finish joint and uniform membership
without another candidate barrier. The format boundary requires a fresh
installation. Lost-canonical bootstrap, activation continuity and adversarial
process qualification are later RFC slices; this API is not an advertised
replacement capability.

## One consensus authority

Returning retained voters can call `initialize_cluster` with a majority of
compatible configured voters, including themselves. Each remote voter counted
in that majority must prove the exact existing configuration wire/command
revisions and audit-key epoch/fingerprint on its authenticated connection.
An absent peer is checked when it connects, and a mismatched peer cannot reach
Vote, AppendEntries or InstallSnapshot. Proof belongs to the connection;
reconnects and replacement processes negotiate again. If no compatible
majority is available and no peer has proved incompatible, admission returns
`CompatibleQuorumUnavailable`. A known mismatch without a verified majority
returns `ClusterFormationRejected`, even when another peer is merely absent.
The caller can retry `initialize_cluster` on the same open store as compatible
peers return; the SDK does not schedule that retry itself.

The optional handshake extension changes no stored format or compatibility
profile value. First formation still requires every configured peer. Peers
without the extension retain the explicit compatibility probe and never count
toward the connection-verified majority. When that majority is unavailable,
admission requires a successful explicit probe of every configured peer.
Legacy engine calls are also explicitly probed before dispatch; that legacy
evidence is not connection-bound. The new receiving gate cannot change the
behavior of traffic between two old binaries.

Quorum admission requires the negotiated mTLS extension at both endpoints.
The plaintext transport always supplies legacy evidence and therefore needs
the complete-fleet admission fallback. Wrappers must forward all four optional
methods together: `ConsensusPeer::with_compatibility`,
`ConsensusPeer::call_with_compatibility`, `ConsensusRpcHandler::compatibility`
and `ConsensusRpcHandler::handle_with_compatibility`. Forwarding none selects
legacy all-peer admission. Partial forwarding can prevent all engine traffic:
a receiver rejects an unproved engine call when its reverse probe proves that
the sender supports connection compatibility. Forward the configured peer
returned by `with_compatibility` and preserve the actual connection's proof.

Every configuration Vote, AppendEntries and InstallSnapshot, including each
heartbeat, first sends an explicit compatibility `ReadBarrier` probe even on
a modern connection. A receiver running the compatibility gate also
reverse-probes calls without connection proof before engine dispatch. Between
updated endpoints this adds one round trip on modern links and two on legacy
links; old binaries retain their previous request path. Those probes share
the existing engine-call deadline and grant no extra time for election,
commitment or replication. The local probe reply only compares the profile
and does not run a linearizable read.

For a fixed three-voter set, rolling one voter at a time works in either
direction while the retained membership and compatibility profile stay equal:

| Running builds | Returning-voter admission | After admission |
| --- | --- | --- |
| Three new | Any two compatible voters suffice | Any compatible majority serves |
| Two new, one old | The two new voters can admit while the old voter is absent; the old voter still requires all peers | An admitted new/old majority also serves |
| One new, two old | All three must answer explicit probes; one new plus one old cannot use quorum admission | Any admitted compatible majority serves |
| Three old | Existing all-peer admission | Existing majority operation |

Unadmitted stores reject consumer reads and writes, including local committed
projection/history reads. Admitted follower-local reads still use local applied
state without a leader/read-index round. Failed admission needs no store
replacement, volume cleanup or coordinated restart; the caller retries the
same store as connectivity returns.

The HA composition is:

```text
application -> HKMS-backed encryption -> ConsensusConfigStore
            -> Openraft -> SQLite and Openraft snapshots
```

The application protection layer seals configuration before calling the
`opc-config-bus-consensus::RaftManagedDatastore` adapter. Production callers
place `opc-config-bus::EncryptingManagedDatastore` outside that adapter; the
adapter implements only the sealed-config datastore port and cannot receive a
plaintext config or a key provider. A successful `opc-crypto` encryption mints a one-shot
capability; the config-bus adapter consumes it at the consensus proposal seam
and binds the exact ciphertext plus plaintext digest. Raw ciphertext cannot use
the consensus append API. The capability, provider, and key handle are erased
before the command is serialized. The adapter also validates config AAD, masks
audit values, HMAC-tokenizes YANG predicate values, and finalizes the audit
chain before proposal. Openraft persists and replicates only sealed ciphertext,
deterministic metadata, and redacted finalized audit records. Plaintext,
provider objects, provider/key handles, and raw key material never enter an
Openraft command, RPC, log, outcome, or snapshot.

Openraft is exact-pinned behind `opc-consensus` and exclusively owns election,
vote/term state, log matching, quorum commit, membership, linearizable barriers,
and snapshot lineage. The removed custom Raft implementation, majority config
wrapper, TCP peer/server, and standalone consensus-node binary are not
alternative authority paths.

Config command and config-specific RPC revision 7 separate mutation checkpoints
from verified-export retention authority. Revision 6 added authenticated management
key transitions, frozen exports and required external checkpoints. Revision 5
introduced the replicated management ledger and authenticated operation recovery.
Revisions 1 through 6 retain their
original command semantics, including revision 4's acknowledged application
history retention. Configuration storage and snapshot representation 5 carry
the authenticated authorities and management continuity state. Earlier representations are
refused; a coordinated binary restart alone is not a state conversion. See
[the management-audit contract](../../docs/replicated-management-audit.md) for
admission, atomic results, privacy, bounded recovery and the remaining
protocol integration boundary,
[ADR 0025](../../docs/adr/0025-management-audit-continuity.md) for signing,
export, checkpoint and pruning contracts, and
[ADR 0023](../../docs/adr/0023-bounded-configuration-history.md) for the existing
configuration-history bounds and protected references.

Online recipient exports keep their original expiry across quorum and independent
checkpoint waits. Expiry at completion releases the export permit.

Creating the `config_raft_identity` table claims the database for Openraft in
the same immediate SQLite transaction that checks or imports legacy state.
Every public standalone mutation checks consensus metadata under the same
connection lock. Each backend clone also retains the claimed requirement, so
even removing all consensus tables cannot re-enable local writes. Live history
reads authenticate the complete retained metadata chain and query it in one
SQLite read transaction; missing or modified authority is a refusal, including
negative lookups. The same transaction checks the SDK-defined base and consensus
schema before reads or mutation, rejecting unexpected executable or temporary
objects so a lifecycle update cannot re-authenticate unrelated damage. Snapshot
installation checks the destination schema before replacing any authority rows;
an admitted schema still permits repair of damaged rows from an authenticated
snapshot. The backend exposes neither its raw
SQLite connection nor its audit key, and `AuditKey` does not expose key bytes;
typed operations are the only safe public authority surface. Protect the
database directory with the CNF's normal filesystem identity and permissions,
because code holding an independently authorized OS path can always bypass a
Rust API by opening SQLite directly.

## Shared transport boundary

`ConsensusConfigStore` consumes the transport-neutral `ConsensusPeer` and
`ConsensusRpcHandler` ports from `opc-consensus`. The workspace's production
mTLS listener/peer implementation and live peer authentication belong to
`opc-session-net`; `opc-persist` deliberately owns no listener, socket framing,
certificate parser, or TLS state. The transport's currently session-named
server and peer accept/implement these shared ports and do not decode config
commands or make config consensus decisions. A three-node integration forms
the real config Openraft store and commits/reads through this loopback mTLS
adapter, proving the shared composition without restoring a private transport.

Certificate and trust-bundle rotation therefore remains an existing shared
transport/CNF lifecycle responsibility. This migration does not add a private
config transport or a second rotation API. Preserve trust overlap, force and
verify fresh authenticated connections, gate on durable readiness, and retire
old trust according to the shared transport runbook. Shared real-mTLS tests
prove that a subsequent new call/full handshake observes a renewed SVID and
rejects a wrong rotated identity; they do not exercise retained-connection
retirement or seamless continuity. The config storage adapter does not broaden
that scoped transport evidence.

## Legacy migration and rollback

A database with nonempty legacy config or consensus authority is never
reinterpreted at startup. Normal `open` returns
`ConfigConsensusOpenError::RecoveryRequired`. Recovery is offline and explicit:

1. Drain the complete old fleet and preserve untouched, checkpointed
   pre-migration database backups.
2. Select one externally established authoritative applied SQLite snapshot.
   Record its exact SHA-256 checksum, latest transaction ID, and latest config
   version.
3. Construct `ApprovedLegacyConfigRecovery` with those values and the explicit
   `DiscardUnknownAppendedSuffix` disposition.
4. Use `open_with_legacy_recovery` only while the old authority is stopped.
   The source must be a complete SQLite file with no nonempty WAL. Recovery
   opens it without following symlinks, consumes the exact opened descriptor,
   and rechecks path/device/inode and WAL state after staging. It verifies
   SQLite integrity, the required tables, the exact checksum, and the complete
   linear history before the approved chain head. The first retained
   record may start at any positive version but has no parent; every subsequent
   record must name the prior transaction and increment its version by exactly
   one. Audit integrity and sealed config envelopes are also verified before
   replacing the target state and claiming Openraft authority in one
   target-database transaction.

The disposition is intentionally destructive: every legacy suffix after the
approved applied snapshot is unknown and is discarded, never guessed to be
committed. Atomicity is per database; operators must still coordinate the
fleet and use the same approved authority evidence on every converted member.

There is no in-place downgrade or reverse translation from Openraft metadata
to the removed legacy engine. Rollback is supported only by stopping the
entire fleet and restoring the preserved pre-migration backups. Do not drop
`config_raft_*` tables, remove the authority marker, or copy selected
Openraft-era rows into an old database. Openraft-era writes are not retained by
that rollback and require an explicit operator disposition.

See [ADR 0002](../../docs/adr/0002-config-store-consensus-ha.md),
[ADR 0019](../../docs/adr/0019-one-openraft-consensus-engine.md), and the
[consensus operator runbook](../../docs/consensus-operator-runbook.md).

## Status notes

- `ConfigConsensusTopology` accepts an explicit singleton profile or an odd HA
  voter set from 3 through 9, containing the local node.
- The configured peer map must exactly cover all remote configured voters.
- The exact voter set cannot shrink or expand within the epoch; a membership
  transition requires a reviewed new topology/configuration epoch.
- The complete config operation timeout is non-zero and at most 60 seconds;
  it bounds routing, quorum, commit, and apply. Forwarded writes and read
  barriers carry the remaining caller budget, and receivers use the lesser of
  that budget and their local cap rather than starting a new timeout.
- Durable log append/apply batches accept at most 1,024 entries, 16 MiB per
  encoded entry, and 64 MiB encoded in aggregate. Serialization writes through
  a bounded sink inside the cancellable SQLite worker, so hostile iterator
  hints and oversized entries cannot trigger an unbounded preflight allocation.
  Committed, applied, and purged floors cannot be rewritten or truncated;
  startup and reads reject persisted holes while an uncommitted suffix remains
  replaceable through Openraft's explicit truncate/append sequence.
- Snapshot storage must be a private `0700`, non-symlink directory on the same
  admitted durable device as SQLite. The adapter holds its descriptor and
  rechecks the path/device/inode binding before build, install, read, and purge.
  Startup verifies the referenced snapshot before a bounded directory cleanup.
  Build and install use one absolute 60-second deadline across file work,
  stepped SQLite backup, validation, and the drained authority transaction;
  timeout cannot leave a detached worker or report failure after commit.
  Interrupted receive/build/install/promote artifacts, SQLite sidecars,
  approved-recovery staging, and unreferenced snapshots are removed without
  following unsafe file types; drop guards clean canceled staging work.
- `probe_durable_readiness` uses Openraft's linearizable path; listener bind or
  a local SQLite read is not readiness evidence.
- `ensure_local_authority` is deliberately distinct from routed durable reads:
  only the current local leader can pass it. Unknown leadership, quorum loss,
  membership drift, or apply timeout is an unavailable result, never
  permission to serve stale local state.
- `ConsensusConfigStore::status` snapshots engine progress and live exact
  membership under one Openraft metrics guard, releases that guard, and only
  then updates admission state. Status remains a synchronous observation and
  cannot self-deadlock behind a queued metrics publication during an election.
- Normal trait mutations derive request IDs from durable operation identity;
  explicit caller-retained IDs remain available. Outcomes retain the most
  recent 4,096 applications, so steady-state snapshot size is bounded. Reusing
  a retained ID for a different payload returns the stable
  `PersistErrorKind::RequestIdCollision` outcome and leaves the original result
  recoverable while retained. After expiry, callers must perform a fresh
  authoritative read.
- Config and session consensus share the fixed eight-slot proposal-admission
  profile. Config admission uses the operation's original deadline; after
  `client_write_ff` accepts a request, a detached supervisor owns its permit
  until Openraft resolves that exact request. Cancellation or result timeout
  cannot release the slot early. A caller recovering an unavailable explicit
  idempotent call must retry the same retained request ID; the state machine
  returns the original persisted outcome rather than applying the mutation
  twice.
- Fresh reads and mutation preflights pass through exactly one
  supervisor-owned Openraft linearizability check per node and at most 64 total
  callers across the active and waiting cohorts. Callers collected before
  dispatch may share that exact result; later callers await a subsequent check
  under their original deadlines. Caller
  cancellation or timeout cannot cancel a dispatched check or start an
  overlapping one, and Openraft remains the sole quorum authority.
- Committed-watch reads are intentionally different from fresh authoritative
  reads: `load_committed_latest` and `load_since` return only the calling
  node's contiguous Openraft-applied, recovery-cleared prefix without a
  leader/read-index round. An applied `recovery_required` tail remains hidden,
  blocks successors, and becomes visible only after its clear mutation applies
  locally. A confirmed-deadline row remains visible once this publication
  fence is clear. The local head may lag, but its history is committed,
  ordered, and independently serviceable during loss of the read-barrier path.
  Apply notifications merely wake consumers; config-bus validates the next
  durable page before emission.
- `dangerous-test-hooks` exposes fault injection only for explicitly gated
  test profiles. It is not a production feature.

## Relationships

- Uses `opc-consensus` for the single approved Openraft engine and bounded
  transport ports.
- Uses `opc-key` and `opc-crypto` to validate the config envelope boundary;
  the caller owns encryption and HKMS/provider composition above consensus.
- Consumed by `opc-config-bus`, AMF-lite integration, and security-policy
  services.
- Uses `opc-nacm` concepts at the caller/service boundary; this crate is not a
  northbound gNMI, NETCONF, or gNSI server.

## Verification

- Openraft config-store coverage:
  `cargo test --locked -p opc-persist --test consensus_openraft`
- Provider-backed application-encryption boundary:
  `cargo test --locked -p opc-amf-lite --test config_consensus_encryption`
- Default crate contract: `cargo test --locked -p opc-persist`
- Workspace formatting: `cargo fmt --all --check`

The config tests cover atomic authority fencing, sealed/redacted persistence,
fail-closed legacy admission, exact approved-snapshot recovery, three-node
formation, partition/failover/heal, response-loss idempotency, and snapshots.
The AMF-lite integration composes the real config encryption wrapper with the
Openraft store, rotates provider-backed keys, exercises followers, snapshots,
and restart, and scans complete shared-consensus wire frames, live
DB/WAL/SHM, log/outcome/history rows, snapshots, and restarted artifacts for
plaintext, raw-key, provider-endpoint, and opaque-handle canaries. Provider
call counts prove Openraft and maintenance stay below the seal/unseal boundary.
This qualifies the three-node provider/HKMS boundary, not a remote-HKMS or
production-network deployment. These tests do not by themselves establish
multi-process/deployed-network compatibility, resource, soak, seamless
connection retirement, or release qualification. The shared transport suite
separately provides in-process three-node real-mTLS config composition and
new-call SVID evidence.

## License

Licensed under the [Apache License, Version 2.0](../../LICENSE).
