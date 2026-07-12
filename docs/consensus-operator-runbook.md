# OpenPacketCore Consensus Operator Runbook

This runbook covers the Openraft-backed configuration store in `opc-persist`,
including bootstrap, readiness, legacy migration, failure handling, backup,
and rollback. It describes SDK mechanisms; a product operator must supply the
deployment controller, authenticated shared transport, alarms, and release
qualification.

## 1. Authority and security boundaries

There is one distributed authority:

```text
application -> HKMS-backed encryption -> ConsensusConfigStore
            -> Openraft -> SQLite and Openraft snapshots
```

| Responsibility | Owner |
|:---|:---|
| Authorization, validation, plaintext handling, HKMS/provider calls, and config encryption | Application/config protection layer |
| AEAD-envelope/AAD admission, audit redaction/finalization, deterministic config apply, and durable request outcomes | `opc-persist` config adapter |
| Election, term/vote, log matching, quorum commit, membership, linearizable reads, compaction, and snapshot lineage | Openraft through `opc-consensus` |
| Vote/log/application/membership/outcome rows and snapshot files | Per-node SQLite/Openraft storage adapter |
| Production mTLS, bounded network framing, live peer authentication, and credential lifecycle | Shared `opc-session-net` transport and CNF composition |

Openraft persists and replicates sealed ciphertext and redacted finalized audit
content. It must never receive plaintext, an HKMS/KMS provider, a provider or
key handle, or raw key material. Provider failure blocks protection of a new
plaintext write before proposal; it must not be worked around by sending
plaintext into consensus.

`opc-persist` no longer supplies a private TCP peer, TCP server, or node
process. Do not deploy an old config consensus listener beside Openraft, and
do not place a custom majority writer in front of or behind
`ConsensusConfigStore`.

## 2. New-cluster bootstrap

### 2.1 Prepare immutable identity and storage

Before starting any member:

1. Choose one cluster ID, configuration ID, and positive configuration epoch.
   Configure the exact same values on every member.
2. Assign each member a stable, positive consensus node ID. Do not derive the
   ID from a transient address or pod ordering.
3. Configure either the explicit singleton profile or an odd voter set of 3,
   5, 7, or 9 nodes. Every node's topology must include itself.
4. Give every node exactly one authenticated `ConsensusPeer` route for each
   configured remote voter, and no extra route. Peer IDs must match the
   topology.
5. Provision a durable SQLite path and a private `0700`, non-symlink snapshot
   directory on the same durable device. Supply the same non-zero audit key and
   explicit audit-key rotation epoch on every voter; the non-secret
   epoch/fingerprint is part of durable and peer compatibility.
6. Configure the shared production mTLS transport. Bind the certificate's live
   peer identity to the same cluster/configuration/epoch and stable node IDs
   used by consensus. A successful socket bind is not cluster readiness.

A normal open is appropriate only for a pristine database or a database
already claimed by the same Openraft identity. A nonempty legacy database must
follow Section 4.

### 2.2 Start and admit the cluster

For each node:

1. Construct `ConfigConsensusTopology` and call `ConsensusConfigStore::open`
   (or `open_with_operation_timeout`).
2. Install `ConsensusConfigStore::rpc_handler()` on the authenticated shared
   consensus listener before cluster initialization.
3. Make all configured peer routes reachable.
4. Call `initialize_cluster()` on the nodes. Concurrent calls are supported;
   Openraft performs the one admissible initialization and existing members
   re-admit the persisted configuration.
5. Keep the node out of traffic readiness until
   `probe_durable_readiness()` succeeds.

`initialize_cluster` and every operation fail closed if durable identity,
peer coverage, membership, or engine state does not match. Do not repair an
identity mismatch by editing SQLite rows.

### 2.3 Readiness and operation deadlines

The default complete config operation timeout is 10 seconds. An override must
be greater than zero and no more than 60 seconds. It bounds leader discovery
and routing, the linearizable barrier, quorum commitment, and local apply.
Each forwarded mutation/read barrier carries the remaining caller budget, and
the receiver uses the lesser of that remainder and its local cap. A route or
receiver never starts a fresh full operation timeout. Each shared transport
call also has its transport-owned complete deadline within that operation.

Use only `probe_durable_readiness` for traffic admission. The probe exercises
Openraft's linearizable path and current admitted membership. These are not
readiness evidence:

- listener bind or successful TLS configuration;
- a cached capability report;
- presence of a leader in a stale observation;
- a local SQLite read; or
- a successful standalone preflight from before the authority claim.

`status()` is a redaction-safe observation containing node, term, leader,
independently persisted committed index, applied index, non-secret audit-key
epoch/fingerprint, and admission state. Use it for routing and
diagnostics, but keep readiness gated by the fresh probe.

## 3. Normal write and response-loss handling

The application encrypts through `EncryptingManagedDatastore`. A successful
`opc-crypto` operation mints a one-shot claim bound to the exact ciphertext and
plaintext digest. The persistence adapter consumes that claim, validates the
canonical envelope/AAD, tokenizes YANG predicate values, redacts audit values,
and finalizes the audit chain. Raw ciphertext cannot enter the consensus append
API, and the claim/provider/key handle is gone before Openraft serialization.

Normal trait mutations derive a stable request ID from their durable operation
identity; explicit idempotent methods accept a caller-retained ID. The most
recent 4,096 outcomes are retained. If a response is lost, retry the same
logical operation/ID within that finite horizon or perform a fresh authoritative
read. Reusing a retained request ID for different content fails closed.
It returns the stable `PersistErrorKind::RequestIdCollision`, never the
original successful result or an ordinary config-version conflict. The
original request/payload pair remains retryable while its outcome is retained;
after expiry, recover through a fresh authoritative read rather than assuming
the old response is still cached.

After the Openraft authority marker exists, direct mutation through
`SqliteBackend` is fenced, including through clones freshly opened or retained
around the claim. The safe API exposes no raw SQLite connection, audit key, or
audit-key bytes. A direct-mutation failure is expected safety behavior, not a
reason to remove the marker. Independently opening the database at the OS path
is outside the Rust API boundary, so enforce CNF filesystem identity and
permissions.

## 4. Offline legacy migration

The removed custom engine cannot prove which appended legacy suffix was
committed. Normal startup therefore returns `RecoveryRequired` for any
nonempty legacy config or consensus authority. There is no automatic majority
scan, log conversion, or startup repair.

### 4.1 Establish the approved applied state

1. Stop config traffic and drain every old writer and old consensus process.
   Keep them stopped for the complete migration.
2. Produce untouched, coherent pre-migration backups for rollback. Preserve
   every member's backup outside the paths the migration will modify.
3. From operator evidence, select one SQLite snapshot representing the exact
   authoritative applied config state. Do not select an uncommitted log tail
   merely because it appears on one or more replicas.
4. Checkpoint the selected snapshot and close every writer. Its main database
   file must be complete and its `-wal` file absent, empty, or fully
   checkpointed.
5. After the file is final, compute and record its exact SHA-256 checksum and
   record the exact latest applied config transaction ID and config version.
   A later byte change invalidates the approval.
6. Verify the retained config history is one linear chain. Its first retained
   record has no parent (its version need not be 1), and each later record names
   the immediately prior transaction with exactly the prior version +1.
7. Record the explicit operator decision
   `DiscardUnknownAppendedSuffix`. This acknowledges that any target state
   beyond the approved head is unprovable and will be destroyed.

Keep the approved source read-only. Do not use a source already containing an
Openraft `config_raft_identity` marker.

### 4.2 Apply the per-database authority hand-off

For each nonempty legacy target database being converted:

1. Open the target `SqliteBackend` with the correct audit key.
2. Construct `ApprovedLegacyConfigRecovery::new` with the approved snapshot
   path, SHA-256, transaction ID, version, and
   `LegacyConfigTailDisposition::DiscardUnknownAppendedSuffix`.
3. Call `ConsensusConfigStore::open_with_legacy_recovery` with the new exact
   topology, snapshot directory, and peer map.
4. Keep the shared listener and all old writers stopped until all target
   databases have either converted successfully or the rollout has been
   abandoned and restored from backup.

The adapter opens the source without following symlinks, binds the copy to that
exact file descriptor, checks the path/device/inode and offline WAL state both
before and after staging, and hashes the complete source. It verifies SQLite
integrity and required tables, rejects an Openraft source, checks the exact
latest transaction/version and complete linear parent/version history, verifies
stored audit chains and every sealed config envelope, and requires the explicit
suffix disposition. It then replaces the target config/audit state, redacts
and reseals imported audit data, removes the legacy consensus tables under the
explicit suffix disposition, creates the Openraft schema and authority marker,
and commits the target replacement in one immediate SQLite transaction.

That transaction is atomic for one target database. It is not a fleet-wide
transaction. Use the same approved authority evidence throughout the rollout,
and do not start the new cluster until the coordinated conversion has
completed.

If any checksum, head, integrity, audit, envelope, schema, or identity check
fails, recovery fails closed without authorizing a best-effort suffix. Diagnose
the source or restore the preserved backups; do not weaken the approval.

### 4.3 Start after migration

Once all intended members have converted:

1. Start the shared authenticated listeners and install each config handler.
2. Call `initialize_cluster()` under the new exact topology.
3. Require fresh durable readiness on every admitted traffic-serving node.
4. Verify the selected transaction/version is visible through the
   linearizable config read and verify the audit chain.
5. Retain the pre-migration backups according to the rollback decision window.

There is intentionally no `opc-persist` migration CLI or node binary. Product
tooling must collect the operator approval and invoke the typed API without
logging paths, checksums, transaction IDs, keys, or payload contents.

## 5. Failure handling

### 5.1 Quorum loss or partition

An HA cluster needs a majority of the admitted voters. A minority partition
cannot commit writes or satisfy a linearizable read/readiness probe. Keep
traffic gated and investigate shared-transport reachability, authentication,
storage health, and Openraft status. Do not enable standalone writes on an
isolated SQLite database.

When connectivity returns, Openraft owns normal uncommitted-log reconciliation
and catch-up. Do not truncate, append, or copy `config_raft_log` rows by hand.

### 5.2 Crash and restart

Restart with the same database, snapshot directory path/device/inode binding,
cluster/configuration/epoch, audit-key epoch/fingerprint, node ID, exact voter
set, and authenticated peer bindings. Openraft restores
its vote/log/commit/application/membership state from SQLite and resumes
through its normal recovery path. Keep readiness false until the fresh
linearizable probe succeeds.

On open, the adapter first verifies any snapshot referenced by durable state.
It then scans at most 8,192 directory entries and removes only recognized
interrupted receive/build/install/promote, approved-recovery, SQLite-sidecar,
and unreferenced snapshot artifacts. Unsafe recognized file types or an
oversized directory fail closed. Do not replace this with an unbounded cleanup
script or delete the referenced snapshot.

An identity, schema, checksum, or snapshot failure is not a rebootstrap signal.
Stop the node, preserve the evidence, and use a reviewed restore procedure.

### 5.3 Storage failure

Disk-full, corrupt SQLite/WAL, unavailable snapshot paths, or failed durable
writes must fail closed. Remove traffic readiness and preserve the files for
analysis. Never copy a locally readable config table into a live member and
never edit vote, log, membership, applied, outcome, or snapshot metadata.

## 6. Membership and topology epochs

The configured voter set is immutable within one config topology epoch.
`change_membership` only re-asserts that exact set and rejects a subset or
superset before Openraft work begins. To add, remove, or replace a voter, drain
the fleet and execute a reviewed topology/configuration-epoch transition with
coherent durable state and peer identity evidence. Never emulate membership by
editing mTLS authorization, peer routes, or SQLite rows.

## 7. Shared mTLS certificate rotation

The #177 storage migration does not alter certificate ownership. Rotation
remains the existing `opc-session-net`/CNF shared-transport responsibility; do
not add a config-only listener or a private credential-update path in
`opc-persist`.

Follow the shared transport procedure:

1. Publish trust that accepts both old and new issuers.
2. Install renewed leaves while preserving exact peer and consensus scope.
3. Retire or reconnect old connections so peers perform fresh mutual
   authentication.
4. Gate traffic on fresh durable readiness and verify every peer path.
5. Remove old trust only after the required authentication age and rollback
   window have elapsed.

Real-mTLS tests prove that a subsequent new call/full handshake observes a
renewed correctly scoped SVID and rejects a wrongly scoped rotated identity.
They do not exercise an in-flight or retained old connection. Keep seamless
connection retirement, trust-bundle, revocation, authentication-age,
multi-process/soak, and production-release gates open until their own evidence
passes.

## 8. Snapshots, backups, and rollback

`trigger_snapshot()` asks Openraft to build and compact a state-machine
snapshot. It is a forward recovery/catch-up mechanism. Openraft remains the
only authority allowed to select snapshot lineage or truncate logs.

An Openraft snapshot is not the legacy rollback artifact. Before migration,
preserve complete, coherent, untouched backups of the old databases and any
other state required by the old release.

Rollback after a successful authority claim is only:

1. stop traffic and the complete new fleet;
2. preserve the failed/new state for investigation;
3. restore the full pre-migration backup set to clean paths;
4. verify the old release's exact database and consensus identity; and
5. restart the old fleet together under the old release procedure.

There is no supported in-place downgrade. Do not drop `config_raft_*` tables,
delete `config_raft_identity`, translate Openraft logs into legacy rows, or
copy application tables selectively. Writes committed after migration are not
present in the pre-migration backup. Treat their loss or external replay as an
explicit operator/data-owner decision before rollback.

## 9. Verification

Run implementation tests serially when sharing constrained storage resources:

```bash
cargo test --locked -p opc-persist --test consensus_openraft -- --test-threads=1
cargo test --locked -p opc-amf-lite --test config_consensus_encryption
cargo test --locked -p opc-session-net --test consensus_transport
```

Run the default package contract and formatting check:

```bash
cargo test --locked -p opc-persist
cargo fmt --all --check
```

Current config tests cover sealed/redacted singleton persistence, direct-write
fencing, fail-closed legacy admission, exact approved-snapshot recovery,
three-node formation, partition/failover/heal, response loss, restart, and
snapshots through in-process shared peer ports. The AMF-lite test composes the
real outer encryption wrapper and qualifies the three-node provider/HKMS
boundary through key rotation plus durable canaries;
the shared transport test covers a renewed SVID on a subsequent new call/full
handshake and wrong-scope rejection, not seamless retained-connection
retirement. That suite also forms a real three-node config Openraft cluster and
commits/linearizably reads through the loopback mTLS peer/server. The evidence
does not alone qualify remote HKMS, out-of-process/deployed-network
compatibility, restart/rejoin under deployed storage, resource limits, soak,
seamless certificate rotation, or a carrier release. Track that remaining
evidence under `GAP-001-006`.
