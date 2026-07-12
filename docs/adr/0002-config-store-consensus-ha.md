# ADR 0002: Config Store Consensus HA

## Status

Accepted

## Date

2026-06-08

Amended 2026-07-12 for the atomic #177 migration to the workspace's shared
Openraft engine.

## Context

Single-node SQLite persistence cannot support a carrier-HA configuration
claim. The earlier `opc-persist` hardening prototype implemented its own
Raft-style election, replication, read, membership, snapshot, and TCP/mTLS
paths, while `QuorumConfigStore` supplied another majority algorithm. Keeping
either path beside the workspace's Openraft authority would leave two possible
answers to election, commitment, and recovery questions.

Config values also cross a sensitive boundary. Consensus must replicate the
result of application encryption without acquiring the ability to obtain a
key, call HKMS, or observe plaintext. Migration from the removed engine cannot
infer which legacy suffix was committed: only an externally established
applied state is admissible.

## Decision

`ConsensusConfigStore` uses the exact-pinned Openraft engine exported by
`opc-consensus`. Openraft is the sole distributed authority for configuration
state. It exclusively owns election, term/vote persistence, leader authority,
log matching, quorum commit, membership transitions, linearizable read
barriers, log compaction, and snapshot lineage/install authority.

The SDK continues to own the deterministic config command and SQLite adapter:
sealed commit application, confirmed-commit and rollback-point semantics,
redacted audit finalization, durable idempotent request outcomes, bounded
codecs, cluster/configuration/epoch scope, and fail-closed errors. None of
those surfaces counts votes or implements a second log-repair algorithm.

The removed custom consensus modules, `QuorumConfigStore`, private config TCP
peer/server, and standalone consensus-node binary are not compatibility
authority paths and must not be reintroduced behind another constructor or
feature.

### Protection boundary

The production composition is:

```text
application -> HKMS-backed encryption -> ConsensusConfigStore
            -> Openraft -> SQLite and Openraft snapshots
```

The outer application layer encrypts configuration first. Before proposal,
the config adapter validates the authenticated AEAD envelope and config AAD,
replaces every present audit value with the redaction marker, and finalizes the
audit chain. Openraft RPCs, logs, outcomes, follower apply, replay, catch-up,
SQLite state, and snapshots contain only sealed ciphertext, deterministic
metadata, and redacted audit records. They never contain plaintext, a provider,
a provider or key handle, or raw key material, and Openraft never calls HKMS.

This is payload-envelope protection, not full-database encryption. Openraft
terms, indexes, membership, request IDs, timestamps, envelope key IDs, and
other routing metadata remain visible unless a separately qualified
database/volume encryption layer protects them.

### Storage authority claim

Opening a pristine database creates the Openraft schema and durable
`config_raft_identity` authority marker in one immediate SQLite transaction.
The same transaction checks legacy authority first. Every standalone SQLite
mutation checks that marker under the shared connection lock and fails closed
after the claim, including through handles retained from before the claim or a
freshly reopened backend. Safe public APIs expose neither the raw SQLite
connection nor the audit key/key bytes; OS-level access to the database path
remains a deployment filesystem-permission boundary.

The SQLite log adapter accepts only contiguous appends and caps each encoded
entry at 16 MiB. Committed, applied, and purged floors are immutable; reads and
startup reject persisted holes, while Openraft may explicitly truncate and
replace only an uncommitted suffix. Startup verifies the referenced snapshot
before a bounded directory scan removes recognized canceled staging,
sidecars, approved-recovery staging, and unreferenced snapshots. Drop guards
also remove staging files when async snapshot work is canceled.

The topology admits an explicit singleton or an odd voter set of 3 through 9,
must contain the local stable node ID, and requires an exact peer route for
every configured remote voter. Cluster, configuration, and positive epoch are
persisted and validated on reopen. Reads and readiness use Openraft's
linearizable barrier; a local SQLite read or listener bind is not quorum
evidence.

### Shared transport

`opc-persist` consumes only the transport-neutral `ConsensusPeer` and
`ConsensusRpcHandler` ports in `opc-consensus`. The production mTLS
implementation, connection authentication, bounded network framing, and
credential lifecycle belong to the existing shared `opc-session-net`
transport composition. `opc-persist` owns no second TCP listener, client, TLS
configuration, certificate parser, or certificate-rotation mechanism. The
transport's currently session-named server/peer types accept and implement the
shared ports; naming does not give the transport config-state authority. A
three-node integration forms and commits the real config Openraft store over
the loopback mTLS adapter, proving this composition in process.

Forwarded mutations and read barriers carry a validated remaining caller
budget. The receiver uses the lesser of that budget and its own operation cap,
so routing cannot create a fresh full server timeout. Zero, oversized, or
malformed budgets fail before work begins.

Certificate and trust-bundle rotation keeps the shared transport's existing
responsibility and qualification status. Operators must use its trust-overlap,
fresh-authentication, connection-drain, readiness, and old-trust retirement
procedure. Real-mTLS tests prove that a subsequent new call/full handshake
observes a renewed SVID and rejects a wrong rotated identity; they do not prove
retained-connection retirement or seamless continuity merely because the
config adapter uses the shared port.

### Legacy admission and rollback

Normal open rejects any nonempty legacy config/consensus authority with
`RecoveryRequired`. It never parses a legacy log as Openraft metadata and
never selects a majority tail at startup.

The only legacy admission path is offline
`open_with_legacy_recovery` with an `ApprovedLegacyConfigRecovery` that binds:

- one checkpointed SQLite snapshot with no nonempty WAL;
- its exact non-zero SHA-256 checksum;
- the exact latest applied transaction ID and config version; and
- `DiscardUnknownAppendedSuffix`, an explicit decision to discard every
  unprovable suffix in the target legacy database.

Before replacement, the adapter stages and hashes the complete source, checks
SQLite integrity and required tables, rejects a source already claimed by
Openraft, verifies the exact chain head and complete parent/version lineage,
loads and verifies every audit chain, and validates every sealed config
envelope. The first retained version need not be version 1, but it has no
parent and every next record names the prior transaction at version +1. The
target state is replaced and the Openraft authority marker is created in one
immediate target-database transaction. This atomicity is node-local; operators
must still drain and coordinate the whole fleet and preserve the same
authority decision across members.

Migration is one-way. Rollback to the legacy software is permitted only by
stopping the fleet and restoring untouched pre-migration backups. Deleting
`config_raft_*` tables, removing the authority marker, or copying selected
Openraft-era rows into legacy storage is not a rollback procedure. Any writes
accepted after migration are absent from the restored backup and require an
explicit operator disposition.

## Consequences

The workspace has one consensus engine for SDK-owned distributed persistence.
`opc-persist` no longer maintains custom election, replication, membership,
snapshot, retry, or TCP/TLS implementations. Config and session state retain
separate deterministic schemas and adapters while sharing Openraft and the
bounded authenticated transport boundary.

The implementation provides durable config authority, atomic local admission,
sealed/redacted consensus state, exact legacy recovery, partition/failover
tests, and linearizable reads. An AMF-lite integration composes the real config
encryption wrapper, rotates provider-backed keys, exercises
followers/snapshots/restart, captures the shared wire, and scans live and
restarted DB/WAL/SHM, log/outcome/history rows, and snapshots for plaintext,
raw-key, provider-endpoint, and opaque-handle canaries while asserting exact
provider-call counts. This qualifies the three-node provider/HKMS
boundary; it does not alone establish a carrier-production profile or a
remote-HKMS deployment. The shared transport suite also qualifies in-process
three-node real-mTLS config formation/commit and new-call SVID reload. Deployed
multi-process compatibility and restart/rejoin, resource bounds, soak,
seamless connection retirement/trust lifecycle, and candidate release evidence
remain production qualification work under `GAP-001-006`.

Standalone `SqliteBackend` remains valid only for single-replica profiles that
explicitly accept that availability model.

## Evidence

- `crates/opc-consensus/`
- `crates/opc-persist/src/consensus/store.rs`
- `crates/opc-persist/src/consensus/raft_adapter.rs`
- `crates/opc-persist/src/consensus/storage.rs`
- `crates/opc-persist/src/consensus/sqlite.rs`
- `crates/opc-persist/src/backend/ops.rs`
- `crates/opc-persist/tests/consensus_openraft.rs`
- `crates/opc-amf-lite/tests/config_consensus_encryption.rs`
- `crates/opc-session-net/tests/consensus_transport.rs`
- `docs/consensus-operator-runbook.md`
- `docs/adr/0019-one-openraft-consensus-engine.md`
