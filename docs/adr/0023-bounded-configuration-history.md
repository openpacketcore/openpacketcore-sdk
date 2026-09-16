# ADR 0023: Bounded acknowledged configuration history

## Status

Implementation contract for SDK #802. Qualification is recorded separately;
this decision makes no deployment, availability, or performance claim.

## Decision

The existing `ConsensusConfigStore` is the sole configuration-history writer.
`retain_history_idempotent(request_id, ConfigHistoryRetention)` commits one
explicit retention decision through the same proposal admission, replication,
state-machine transaction, and bounded request-outcome mechanism as other
configuration mutations. Snapshotting the Raft log alone does not prune
application history.

The caller supplies an exact expected transaction/version head, an explicitly
acknowledged prefix, the first version to retain, and record/encoded-byte limits.
Acknowledgement means every external operation and history reference through
that prefix has been resolved or retired by its owner. Merely observing a head,
a worker checkpoint, elapsed time, process restart, and a successful snapshot
are not acknowledgement. In particular, the caller must not acknowledge a lost
response while its requester is still reconciling the result. This API belongs
to the privileged configuration authority, not a watcher or worker.

The SDK independently protects named and explicit rollback points, unresolved
confirmation and recovery records, their necessary predecessors, and the target
of the current `Previous` rollback selector. It keeps at least the head and its
predecessor. A protected reference rejects the entire decision. There is no
partial pruning, autonomous acknowledgement, time-based expiry, or second writer.
The consumer chooses when to advance acknowledgement and can retain a wider
window than the acknowledged prefix requires.

## Retained authority and transaction

A singleton authenticated state binds the exact consensus identity and epoch,
audit-key epoch, limits, acknowledged prefix, surviving boundary, complete
head's transaction/version/ciphertext digest, retained record count, and an
ordered digest of every retained transaction/version/ciphertext, audit anchor,
record metadata, named rollback reference and lifecycle audit row. The
existing audit-key HMAC primitive has a separate history domain. The canonical
state is bounded to 4096 encoded bytes, uses a closed versioned shape, and is
verified before authoritative reads, retention, reopen, and snapshot acceptance.
The key does not leave the existing persistence authority.

Every live history read, including floor and negative replay/rollback lookups,
verifies the complete ordered record digest before consulting mutable metadata.
Validation and the resulting query share one SQLite read transaction; the Rust
connection mutex alone cannot exclude an independently opened SQLite writer.
That transaction also validates the exact SDK-defined base and consensus schema,
rejecting unexpected triggers, indexes, constraints and temporary objects before
history use. Only bounded SDK-authored DDL enters Rust memory; the supplied
catalog is compared inside SQLite. A schema-only change cannot make a legitimate
lifecycle update alter and re-authenticate an unrelated protected revision.
These scans use the existing bounded, cancellable blocking worker. Every apply
batch likewise authenticates its prior history in the same transaction before
admission or cached-outcome decisions. Missing consensus identity with residual
consensus state is corruption. Once a backend has claimed consensus, every clone
retains that requirement even if all consensus tables are later removed; absence
cannot re-enable standalone reads or direct writes. An actual standalone backend
that has never claimed consensus retains its existing contract.

Append extends the authenticated record digest with the new record only;
it cannot authenticate an unrelated change to an older record. A command that
legitimately changes an existing record first validates the complete prior
digest, then recomputes it after that mutation within the same savepoint. This
includes confirmation, recovery-marker clearing and rollback-point creation;
such an operation cannot re-authenticate unrelated damage. Before pruning,
retained reopen, or snapshot acceptance, full sealed-state validation checks the
ordered digest and every retained audit anchor and encrypted metadata binding.
Removing an audit chain together with its count/terminal hash, clearing a rollback
flag or confirmation deadline, or damaging labels and lifecycle metadata is also
corruption.
Pruning recomputes the digest over the surviving rows in the same transaction.
These scans retain one record at a time and honor cancellation. No decryption
key or plaintext configuration is needed, and corruption in a prefix cannot be
erased and replaced with an authenticated compaction boundary.

Configuration AEAD binds the original parent transaction. Pruning never decrypts,
rewrites, or reseals that configuration. The first retained SQLite row has a null
physical foreign-key parent because its predecessor no longer exists locally.
The authenticated boundary retains that original predecessor, and every external
record projection reconstructs the exact original AEAD-bound lineage. Snapshot
validation checks the physical retained chain and the reconstructed encrypted
metadata. Missing rows or missing/modified boundary state cannot manufacture a
compaction permission.

Pruning removes only the acknowledged prefix and its associated configuration
audit/lifecycle rows. Existing bounded consensus request outcomes remain intact,
including outcomes for removed configurations and rejected retention requests.
A replayed request ID returns its original result; a reused ID with a different
payload conflicts. A fresh request carrying a stale expected head conflicts.
Current encrypted configurations remain complete snapshots, not deltas requiring
removed predecessors.

Each newly applied command owns a SQLite savepoint inside the existing Raft
apply transaction. History-capacity checking runs before releasing it. Failure
rolls back all domain effects, including a pending-confirmation resolution and
its audit records, before persisting a definite `ConfigHistoryFull` outcome.
I/O ambiguity retains the existing consensus outcome-unknown semantics.

## Bounds and replay

Limits admit 2 through 1,000,000 complete records and 1 through 1,073,741,824
encoded data bytes. The byte charge includes ciphertext, stored metadata, audit,
lifecycle and rollback-label data, with conservative fixed per-row allowances.
A policy starts only on an explicit successfully committed decision. Once active,
new mutations that exceed either limit are rejected; they cannot evict unresolved
work. Raising limits remains another exact-head decision within these bounds.
A rejected request keeps its original result after space becomes available; a
caller must explicitly submit a fresh operation after resolving that rejection.

These are canonical retained-data bounds, not SQLite file-size, free-space,
process RSS, Raft-log or total snapshot-storage guarantees. SQLite can retain
free pages for reuse; its WAL, retained Raft entries, independently bounded
request outcomes, and immutable snapshots retain their existing lifecycle.
No new mount, vacuum task, timer, or session-store hot-path work is introduced.

The managed datastore exposes `retained_history_floor`. Under active retention,
a ConfigBus replay miss must bind the exact current base even for a mutation
without a candidate, such as rollback. An expired request must not silently
become a fresh mutation against a newer head. An exact retained replay is still
resolved before that guard. A caller must reconcile unresolved operations before
acknowledging them; the bounded outcome cache is not an unlimited receipt archive.

## Watch and recovery

If the first retained version is `r`, the oldest valid cursor is `r - 1`.
An older cursor gets typed `ConfigHistoryCompacted`/`HistoryCompacted`; an equal
cursor gets its exact successor. Missing or modified state is a refusal, not an
empty successful page or a fabricated compaction outcome. Pages remain bounded
and contiguous and cannot cross an unresolved publication fence.

The existing encrypted datastore and authenticated ConfigWatch recover a complete
snapshot at or above the consumer's known floor, then continue from that snapshot's
cursor. A commit between snapshot receipt and tail subscription must still be
delivered. If that tail itself has since been acknowledged and compacted, recovery
is required again. Snapshot acceptance does not mean skipped intermediate
revisions were applied by a consumer and does not grant worker serving authority.

## Representation and lifecycle

Config commands and config-specific RPCs advance to revision 4. Legacy command
variants retain their original discriminants and payload-digest semantics;
revision 3 cannot carry retention. Exact peer revision matching prevents downgrade.
The authenticated retention table advances configuration storage and snapshot
representations to revision 2. Old representation-1 databases and snapshots are
not silently upgraded, provisioned, or treated as empty by this implementation.
Preserve them with their matching binary; adopting representation 2 for an
existing authority requires a separately admitted state-conversion contract.
Stopping and restarting older files with the new binary is not such a conversion.

Provision, retained reopen, and surviving-quorum member repair remain separate
operations. Replicated snapshots carry history limits/boundary/outcomes but never
the sender's local storage admission binding. Reopen and snapshot installation
validate the retained representation before admission. Natural leader change uses
the same committed state and can neither reset the floor nor mint new revisions.
Snapshot validation and import share one read-only transaction and copy the
closed state-table set one row at a time into one destination transaction. This
does not widen retained storage's pinned file namespace through SQL `ATTACH`.
Openraft can queue log purging before its independent snapshot worker finishes;
the configuration log adapter waits outside the SQLite worker for durable
application within its existing 30-second I/O deadline. Only an exact log,
installed snapshot boundary, or existing purge boundary supplies lineage; an
equal index with a different term is rejected. Missing installation proof never
permits deleting unapplied logs.
`Ephemeral` remains an explicit operator durability choice. Native session WAL
and Durable/Async storage, consumer checkpoints, and external audit continuity
are separate contracts and are unchanged.

## Required evidence

The real encrypted consensus and ConfigWatch detectors cover production pruning,
exact and old cursors, complete snapshot/tail recovery, row/byte caps, protected
references, atomic confirmation rollback, response replay, immediate live-read
and admission refusal after metadata corruption, concurrent SQLite mutation,
unexpected executable schema and temporary shadowing, missing identity and
complete consensus-table removal, retained
reopen, natural election and member snapshot installation. Preserve the initial
missing-behavior RED, fix-removal RED, and independently mutated cursor RED.
Repository gates and whole-change review are required before a merge claim.
