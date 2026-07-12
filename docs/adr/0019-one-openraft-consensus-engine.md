# ADR 0019: One Openraft Consensus Engine

## Status

Accepted

## Date

2026-07-12

## Context

The SDK historically grew two distributed-persistence implementations: a
custom config-store Raft-style engine in `opc-persist` and a custom
majority-visible session coordinator. Splitting elections, voting, log
matching, commitment, membership, read barriers, snapshots, and repair across
SDK-owned algorithms multiplied failure modes and made qualification
ambiguous. Combining Openraft with a custom majority writer in one authority
path would be worse: either side could select different durable truth.

The SDK must still own domain state machines, persistence schemas,
authenticated transport composition, bounded codecs, payload protection,
metrics, and operator policy. Those are adapters around consensus, not reasons
to implement consensus again.

## Decision

Openraft is the only consensus engine permitted for SDK-owned distributed
persistence authority.

- `opc-consensus` exact-pins and re-exports the approved Openraft version. No
  domain crate imports Openraft directly.
- Openraft exclusively owns election, term/vote state, leader authority, log
  matching, quorum commitment, membership transitions, linearizable read
  barriers, compaction, and snapshot lineage/install authority.
- Domain adapters may implement deterministic commands and state machines,
  Openraft storage traits, bounded RPC encoding, authenticated peer routing,
  application journals/watch cursors, idempotent request outcomes, and
  redaction-safe status. They must not count votes, select a majority value,
  allocate an authoritative sequence outside `client_write`, or repair a
  distributed log through an independent algorithm.
- Raw append, truncate, rebuild, term/vote mutation, membership mutation, and
  snapshot-install APIs are not production service surfaces. An offline
  migration may replace legacy state only under explicit bounded operator
  approval; it cannot run as a second live authority.
- `ConsensusSessionStore` is the session adapter delivered by #127.
  `QuorumSessionStore` may remain only as a type alias to it.
- `ConsensusConfigStore` is the config adapter migrated under #177. The custom
  config Raft modules, `QuorumConfigStore`, config TCP peer/server, and
  standalone consensus-node binary are removed rather than retained as a
  compatibility engine.

Kubernetes controller leader election, gNMI master arbitration, local
single-node SQLite transactions, session fencing leases, caches, and test
fakes do not become Openraft concerns unless they start deciding distributed
durable state authority.

## Encryption and HKMS boundary

For configuration persistence the production composition is:

```text
application -> HKMS-backed encryption -> ConsensusConfigStore
            -> Openraft -> SQLite and Openraft snapshots
```

The session composition follows the same outer-protection rule through its
encryption or remote-sealing wrapper. Consensus commands contain already
sealed envelopes. The config adapter additionally masks audit values and
finalizes the audit chain before proposal. Openraft therefore persists and
replicates sealed ciphertext and redacted finalized audit content, never
plaintext, an HKMS/KMS provider, a provider or key handle, or raw key material.
Follower apply, replay, catch-up, request outcomes, and snapshot installation
do not call a provider. Reads decrypt only after crossing back through the
outer protection adapter.

Provider unavailability blocks a new plaintext protection operation before
`client_write` and can block decryption, but it does not prevent Openraft from
replicating or recovering already sealed state.

The envelope marker alone is insufficient. Each adapter validates its
canonical envelope/AAD representation and record-visible binding before
proposal and again when persisted state is decoded. A durable authority marker
fences public standalone config mutations after Openraft claims a database;
each domain may impose a stricter raw-storage fence.

This is payload-envelope encryption. Unless a separate storage layer says
otherwise, consensus metadata, routing fields, terms/indexes, timestamps,
ownership/fence metadata, request IDs, and envelope key IDs are not
full-database encrypted.

## Shared transport boundary

`opc-consensus` owns the bounded, transport-neutral `ConsensusPeer` and
`ConsensusRpcHandler` contracts. Domain crates provide handlers and consume
peers; they do not provide competing sockets. The production mTLS listener and
peer, live certificate authentication, framing, and connection lifecycle are
owned by `opc-session-net` and the CNF composition. A real three-node
`ConsensusConfigStore` integration forms Openraft and commits/linearizably
reads through `RemoteSessionConsensusPeer`/`SessionConsensusServer` over mTLS,
proving that config uses this shared boundary in process.

The #177 migration deliberately deletes the private `opc-persist` TCP/mTLS
stack. It does not create another endpoint or another credential-rotation API.
Certificate and trust-bundle rotation remains the shared transport's existing
responsibility, including trust overlap, fresh authentication, connection
drain, readiness gating, and old-trust retirement. Real-mTLS tests qualify a
renewed SVID on a subsequent new call/full handshake and wrong-scope rejection;
retained-connection retirement, seamless continuity, and broader production
qualification gates remain unchanged.

## Migration rule

An adapter must never reinterpret a nonempty legacy consensus log as Openraft
metadata or use startup heuristics to choose a legacy tail. Pristine state may
be claimed directly. Nonempty legacy config authority fails closed with
`RecoveryRequired` unless the fleet is offline and an operator explicitly
approves one applied SQLite snapshot.

Config recovery must bind the complete source file's exact SHA-256 checksum,
the exact latest applied transaction ID and config version, and an explicit
`DiscardUnknownAppendedSuffix` disposition. The source must be checkpointed
with no nonempty WAL. Integrity, required tables, audit chains, config
envelopes, checksum, and chain head are verified before the target is replaced
and the Openraft marker is created in one immediate SQLite transaction. Every
unprovable target suffix is discarded; it is never merged or promoted.

The transaction is atomic for one database, not for a fleet. Operators must
drain every old authority, preserve one coherent authority decision, convert
members under a coordinated rollout, and keep untouched pre-migration backups.

Migration is one-way. Rollback to a removed engine is only a stopped-fleet
restore of those pre-migration backups. Removing Openraft tables or markers,
or attempting to reconstruct legacy logs from Openraft state, is prohibited.

## Consequences

The SDK accepts the dependency and integration cost of Openraft once in
`opc-consensus` and no longer maintains competing distributed-safety
algorithms. Config and session tests focus on deterministic state-machine and
adapter behavior; shared engine and transport qualification can exercise one
set of election, replication, membership, read, and snapshot semantics.

#127 and #177 close the single-engine implementation transition. They do not
by themselves declare either domain carrier-production ready. Recovery,
restore, credential lifecycle, real-network compatibility, restart/rejoin,
resource, soak, and candidate release evidence retain their domain-specific
gates.

## Evidence

- `crates/opc-consensus/`
- `crates/opc-session-store/src/consensus/`
- `crates/opc-session-store/tests/consensus_openraft.rs`
- `crates/opc-persist/src/consensus/`
- `crates/opc-persist/tests/consensus_openraft.rs`
- `crates/opc-amf-lite/tests/config_consensus_encryption.rs`
- `crates/opc-session-net/src/consensus.rs`
- `crates/opc-session-net/tests/consensus_transport.rs`
- `docs/adr/0002-config-store-consensus-ha.md`
- `docs/adr/0003-session-store-quorum-replication.md`
- `docs/consensus-operator-runbook.md`
