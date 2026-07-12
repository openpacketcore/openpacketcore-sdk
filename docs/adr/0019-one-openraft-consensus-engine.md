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
SDK-owned algorithms multiplies failure modes and makes production
qualification ambiguous. Combining an external consensus engine with a custom
majority writer in the same authority path is worse: either side can make a
different state authoritative.

The SDK still owns telecom-specific state-machine semantics, persistence
schemas, authenticated transport composition, bounded codecs, encryption
boundaries, metrics, and operator policy. Those are adapters around consensus,
not reasons to reimplement consensus.

## Decision

Openraft is the only consensus engine permitted for SDK-owned distributed
persistence authority.

- `opc-consensus` exact-pins and re-exports the approved Openraft version. No
  other crate imports Openraft directly.
- Openraft exclusively owns election, term/vote state, leader authority, log
  matching, quorum commitment, membership transitions, linearizable read
  barriers, and snapshot lineage/install authority.
- Domain adapters may implement deterministic commands and state machines,
  Openraft storage traits, bounded transport DTOs, authenticated peer routing,
  application journals/watch cursors, idempotent request outcomes, and
  redaction-safe metrics. They must not count votes, select a majority value,
  allocate an authoritative sequence outside `client_write`, or repair a
  distributed log through an independent algorithm.
- Raw append, truncate, rebuild, term/vote mutation, membership mutation, and
  snapshot-install APIs are not production service surfaces. Any legacy
  migration tool must be offline, explicitly enabled, bounded, audited, and
  unable to run as a second live authority.
- `ConsensusSessionStore` is the session-store Openraft adapter delivered by
  #127. `QuorumSessionStore` may remain only as a type alias to it; the removed
  majority-prefix coordinator must not remain available behind another
  constructor or test helper.
- The custom `opc-persist` config consensus and `QuorumConfigStore` are a
  transition blocker tracked by #177. Until that migration deletes or
  quarantines those authorities, the workspace must not claim completion of
  this ADR or a unified production consensus profile.

Kubernetes controller leader election, gNMI master arbitration, local
single-node SQLite transactions, session fencing leases, caches, and test fakes
do not become Openraft concerns unless they start deciding distributed durable
state authority.

## Encryption and HKMS boundary

Consensus operates below payload protection:

```text
application -> encryption or remote sealing -> domain consensus adapter
            -> Openraft -> durable storage and snapshots
```

Commands contain already-encrypted envelopes. Openraft, follower apply,
replay, catch-up, outcomes, and snapshots never receive plaintext, key bytes,
an HKMS provider, or a key handle and never call a provider. Reads decrypt only
after crossing back through the outer adapter. Provider unavailability blocks
a new plaintext write before `client_write` but does not prevent replication or
recovery of already-sealed state.

The envelope marker is not sufficient admission evidence. The session adapter
validates the canonical RFC 003 envelope/AAD representation and record-visible
AAD fields before proposal, log persistence, replay, or snapshot acceptance.
The durable SQLite consensus marker also fences every public standalone
backend path, including handles opened before or after consensus admission.

This is payload-envelope encryption. Unless a separate storage layer says
otherwise, consensus metadata, routing fields, timestamps, ownership/fence
metadata, and envelope key IDs are not full-database encrypted.

## Migration rule

An adapter must not reinterpret a nonempty legacy consensus log as Openraft
metadata. Migration fails closed unless an operator-approved procedure can
identify a coherent applied snapshot from authoritative evidence. Unknown or
minority tails are discarded only through that explicit recovery procedure,
never by startup heuristics. A pristine deployment may initialize directly;
an existing fleet requires versioned schema admission, backup/rollback
evidence, and a coordinated rollout.

## Consequences

The SDK accepts the dependency and integration cost of Openraft once in
`opc-consensus` and avoids maintaining competing safety algorithms. Domain
tests focus on deterministic application semantics and adapters, while
multi-node qualification covers cold start, concurrent writes, partitions,
leader loss, response loss, restart, snapshot install, membership, and
authenticated transport.

Session #127 can land independently because it removes the custom authority
from that domain. It does not make the workspace single-engine while #177 is
open. Production-profile documentation and operator admission must state that
transition explicitly.

## Evidence

- `crates/opc-consensus/`
- `crates/opc-session-store/src/consensus/`
- `crates/opc-session-store/tests/consensus_openraft.rs`
- `docs/adr/0003-session-store-quorum-replication.md`
- Issue #177 for the `opc-persist` migration
