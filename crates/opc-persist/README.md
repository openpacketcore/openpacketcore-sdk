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
  `load_rollback`, `append_commit`, `mark_confirmed`,
  `create_rollback_point`, and `preflight`.
- `SqliteBackend::open_with_audit_key` opens durable SQLite state. Durable
  opens require an explicit non-zero `AuditKey`.
- `AuditKey::new([u8; 32])` rejects all-zero keys, and
  `AuditKey::new_with_epoch` adds an explicit rotation epoch. Consensus binds
  the non-secret epoch/fingerprint into peer and durable identity and verifies
  current audit HMAC state at startup.
- `ConsensusConfigStore` supplies Openraft-coordinated writes, linearizable
  reads/readiness, bounded durable request outcomes, and snapshots. Its voter
  set is immutable within one topology epoch. Construction requires an exact
  `ConfigConsensusTopology` and one
  shared `opc_consensus::ConsensusPeer` route for every configured remote
  voter.
- `ConsensusConfigStore::rpc_handler` exposes the shared bounded inbound
  consensus port. `opc-persist` does not contain a second TCP or TLS transport.
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

## One consensus authority

The HA composition is:

```text
application -> HKMS-backed encryption -> ConsensusConfigStore
            -> Openraft -> SQLite and Openraft snapshots
```

The application protection layer seals configuration before calling the
consensus adapter. A successful `opc-crypto` encryption mints a one-shot
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

Creating the `config_raft_identity` table claims the database for Openraft in
the same immediate SQLite transaction that checks or imports legacy state.
Every public standalone mutation checks that marker under the same connection
lock and fails closed after the claim, including mutations through a retained
or freshly reopened `SqliteBackend` clone. The backend exposes neither its raw
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
   verifies SQLite integrity, the required tables, the exact checksum, and the
   complete linear history before the approved chain head. The first retained
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
- Durable log appends are contiguous and capped at 16 MiB per encoded entry.
  Committed, applied, and purged floors cannot be rewritten or truncated;
  startup and reads reject persisted holes while an uncommitted suffix remains
  replaceable through Openraft's explicit truncate/append sequence.
- Snapshot storage must be a private `0700`, non-symlink directory on the same
  admitted durable device as SQLite. The adapter holds its descriptor and
  rechecks the path/device/inode binding before build, install, read, and purge.
  Startup verifies the referenced snapshot before a bounded directory cleanup.
  Interrupted receive/build/install/promote artifacts, SQLite sidecars,
  approved-recovery staging, and unreferenced snapshots are removed without
  following unsafe file types; drop guards clean canceled staging work.
- `probe_durable_readiness` uses Openraft's linearizable path; listener bind or
  a local SQLite read is not readiness evidence.
- Normal trait mutations derive request IDs from durable operation identity;
  explicit caller-retained IDs remain available. Outcomes retain the most
  recent 4,096 applications, so steady-state snapshot size is bounded. Reusing
  a retained ID for a different payload returns the stable
  `PersistErrorKind::RequestIdCollision` outcome and leaves the original result
  recoverable.
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
