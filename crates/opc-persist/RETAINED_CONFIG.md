# Retained configuration-authority lifecycle

`SqliteBackend::provision_config_authority` explicitly creates new configuration
authority. `SqliteBackend::reopen_config_authority` opens established retained
authority. `SqliteBackend::provision_config_member_repair` explicitly creates
replacement storage that must recover history from the existing authenticated
quorum. Ordinary startup calls only reopen; it must never catch a reopen error
and call either provisioning operation.

Interrupted provisioning is resumed with the same independently authorized
binding and key using `begin_resume_config_authority` or
`begin_resume_config_member_repair`. Callers with a separately retained request
identifier use `RetainedConfigProvisionRequest` and
`begin_provision_config_transaction`, `begin_resume_config_provision`, and
`begin_reopen_config_transaction`. A resume is an explicit continuation of the
original provisioning authorization, never permission to replace lost authority.

This contract addresses SDK #800 and #1114. It is not a production-qualification,
whole-store rollback-freshness, or consumer-checkpoint claim (#798 and #799).
The existing `open_with_audit_key` remains an explicitly create-or-open API for
its existing consumers; it does not acquire this retained lifecycle guarantee.

## Caller contract

Construct `RetainedConfigBinding` from the exact configured consensus identity,
configuration epoch, local member and complete voter roster, plus independently
admitted opaque backing and key-scope digests. Do not derive expected authority
from the storage being reopened. Supply the approved `AuditKey`, an absolute
path, a validation byte budget, an operation deadline and an explicit
`RetainedConfigDurability` choice. There are no implicit defaults.

For an explicitly identified request, retain `RetainedConfigProvisionRequest`
outside the destination database. Ordinary startup uses
`begin_reopen_config_transaction` with that same request; the binding-based
`reopen_config_authority` does not open an explicitly identified transaction.
Only an interrupted provisioning operation uses `begin_resume_config_provision`.

`Durable` requires the SDK filesystem checks and reserved free space.
`Ephemeral` remains an operator choice that waives durable-filesystem
qualification. It still requires lifecycle separation, scope/key validation,
an exclusive opener and intact authenticated state. It is not general-purpose
production durability evidence.

After the backend is returned, pass the same topology to
`ConsensusConfigStore::open`, wire its authenticated consensus transport, and
call `initialize_cluster`. Returning a backend does not itself establish quorum
or serving readiness. A repair member never bootstraps a new cluster, including
when it is the canonical lowest member or after its next restart. While its
storage is empty, it rejects engine RPCs and does not campaign. It pulls bounded
snapshot chunks from an authenticated leader that proves a fresh surviving
quorum. The snapshot covers the leader's accepted log prefix, including any
tail that must finish applying, before Openraft installs the restored state and
vote. Only then can the replacement participate in ordinary replication. This
also supports repair after a planned handoff while the successor stays live.
Repairing every member of a lost quorum cannot mint fresh genesis.

Cancellation or a lost quorum leaves the empty member unadmitted; retry
`initialize_cluster` on the same store when the quorum is available. A bounded
attempt retains its verified partial download for the next call, so a large
snapshot can progress across operation deadlines. If a saved attempt makes no
progress, the next call rediscovers authenticated sources within its existing
budget. A fresh response reuses the checkpoint only when its source, committed
vote, and complete snapshot metadata still match; a successor or changed
snapshot starts a new download.
The source waits for the snapshot cut to cover the accepted prefix within the
request budget before fetching the snapshot; unrelated engine metrics updates
do not cause repeated fetches.
Cancellation and shutdown
remove that partial download automatically, and ordinary startup removes any
staging left by a crash. A completed repair persists through the
ordinary retained reopen path and can rejoin with a compatible majority. This
does not reset a leader's recorded replication progress, change stored formats,
or require manual cleanup during restart.

Snapshot reads pin the last published record under a brief publication gate,
then open and verify an independent descriptor outside the gate. The pin keeps
the old path available until open completes; after that, the descriptor remains
valid when a successor removes the path. Building and installing a successor,
including its durable SQLite commit, use separate serialization. Readers do not
queue on that SQLite worker. Startup validates and restores the same published
record before the engine starts. Snapshot waiters fetch only after the completed
cut covers the required log prefix. They retry a swallowed build trigger at a coarse
interval even when an idle maintenance build finishes at the same cut;
unrelated engine updates do not cause repeated snapshot fetches. The coordinator
awaits one accepted read even when it exceeds an RPC budget. Verification limits
individual I/O stalls to 60 seconds, renewing that budget as bounded chunks make
progress, so snapshot size alone does not expire a healthy read.

## SDK-owned local state

The SDK exclusively creates the database, its `.opc-retained` admission file,
and its `.opc-retained-complete` completion file.
The admission file is an authenticated, versioned, fixed-size record and the
lifetime exclusive lock. The caller never writes, repairs or interprets it.
It binds the configured scope and audit key epoch/fingerprint to the exact
parent and admission-file identities, the provisioning request, and the
new-authority/member-repair disposition. The authenticated database binding and
completion file also name the exact database inode. Completion is published only
after database publication, directory sync, and bounded admission validation.
An existing completion record with a missing database refuses recovery rather
than initializing new authority. Existing constructors derive a request identifier
from the independently supplied binding and key; explicit request constructors
accept a nonzero 32-byte identifier retained by the caller. Requests are scoped
to the admitted destination, not a distributed uniqueness service. Neither marker presence nor database absence is
permission to initialize authority.

The profile requires private regular files without hard-link aliases or
symlink path components on a supported Linux filesystem. Unnamed temporary files
and atomic no-replacement links publish complete files; SQLite read-write
opening omits `CREATE` and uses
`SQLITE_OPEN_NOFOLLOW`. The exclusive lock remains held by the SQLite
connection, including detached bounded operations. File identity is checked
again during admission and subsequent statement authorization. This is
cooperative SDK lifecycle admission within a trusted local process/storage
domain, not isolation against a malicious same-UID process, root, or a hostile
filesystem. External actors must not rename, relink or modify a live SQLite
database or its journals.

After the final SDK connection/operation owner finishes, all extra database
descriptors close before its guard explicitly unlocks the admission file.
Closing only the lock descriptor is insufficient:
an unrelated preflight child can inherit the same open file description until
exec. That inherited descriptor must neither extend a completed SDK admission
nor release a later owner's lock when it closes. A failed lock acquisition
never constructs an unlocking guard. A shared connection wrapper retains the
guard through SQLite close, including the earlier removal of its authorizer.
These semantics follow the Unix
[flock lifetime contract](https://man7.org/linux/man-pages/man2/flock.2.html).

The local binding table is removed from outgoing consensus snapshots before
compaction. Incoming snapshots containing local binding authority are rejected;
installation copies only replicated state and preserves the receiver's own
binding. Backing replacement therefore uses explicit member repair with a new
admitted binding, rather than transferring a sender's local storage identity.

## Provisioning interruption and reopening

| Last completed boundary | Ordinary reopen | Explicit same-request resume |
| --- | --- | --- |
| Unnamed intent file created, written or synchronized | Reject missing storage. | Start the same authorized request; unnamed files retire on exit. |
| Authenticated intent published and directory synchronized | Reject missing database. | Build a complete database for this exact intent. |
| Database/schema/binding built in memory or in an unnamed file | Reject missing database. | Rebuild automatically; no partial database is published. |
| Complete synchronized database published without completion | Reject incomplete provisioning. | Re-sync publication, validate the database, and publish completion. |
| Authenticated completion published | Validate the exact binding, schema and sealed history. | Re-sync publication and validate the same completed result. |
| Completion remains but the database is missing | Reject established storage loss. | Reject established storage loss without initialization. |

Provisioning never overwrites partial or foreign artifacts. Each persistent
artifact created by this protocol is authenticated resumable intent, a complete
database, or authenticated completion. No marker deletion, backing replacement or operator cleanup
is needed for an interruption of this transaction. The new admission encoding
refuses the previous format; crossing this stored-format boundary requires a
fresh installation. See the [publication protocol](../../docs/design/retained-config-provisioning.md)
for ordering, bounds and filesystem assumptions.
An earlier `.opc-retained.intent` also denies initialization and returns
`RecoveryRequired`; it is never interpreted as permission to recover or replace
another format.

Reopening never initializes or migrates retained storage or invokes legacy
recovery. It compares the complete base schema with an SDK-owned in-memory
reference, including the exact unique replay index. A digest stored in the
database cannot authorize changed DDL, and compatibility-digest exclusions do
not exempt extra objects from validation. Consensus schema/identity/key/history
and local binding are independently checked before returning a usable backend.

Even a read-only SQLite open can create WAL coordination files. Admission
therefore validates a bounded SDK-private copy of the database and recovery
journals first. Rejection at this stage leaves retained file contents and the
file set unchanged. The original validated database is then opened for WAL
recovery and revalidated. Failure, deadline or cancellation after possible
original mutation returns `Indeterminate`, without a usable capability; it does
not claim that no recovery effect occurred. Retry uses reopen and authoritative
readback. Filesystem errors never cause create-or-open fallback.

Four concurrent admission operations are permitted per process, including
cancelled blocking operations until they finish. Copying uses a fixed buffer
and caller-bounded aggregate database/journal bytes (at most 64 GiB). Operations
have caller-selected deadlines of at most one hour. Errors and `Debug` surfaces
are value-free; no paths, keys or binding values enter lifecycle diagnostics.

## Owning opener completion

The three existing async constructors keep their signatures and admission
outcomes. Callers that must account for shutdown completion can instead call
`SqliteBackend::begin_provision_config_authority`,
`SqliteBackend::begin_provision_config_member_repair`, or
`SqliteBackend::begin_reopen_config_authority`. Each starts the same admission
work immediately and returns a `RetainedConfigOpen`. These entry points retain
the same independent provisioning authorization, member-repair restriction,
and existing-only reopen contract.

Keep this operation in the lifecycle owner, outside a startup or shutdown
future that may be cancelled. `wait(&mut self)` waits only until the original
absolute admission deadline. Cancelling a polled wait or reaching that deadline
requests cancellation and denies any later capability transfer. A ready
successful result is checked again before transfer, because a ready task may
win over an expired timer. An unpolled wait has made no cancellation request.

`cancel()` requests cooperative cancellation. `cancel_and_join(&mut self)`
requests cancellation, discards any unclaimed successful backend on the
runtime's blocking pool, and joins both opening and disposal. Cancelling that
join future leaves its handles inside the operation; call it again to finish.
The join has no deadline. Blocking system calls and SQLite close cannot be
forcefully aborted, so no finite wall-clock retirement bound is promised.

The returned `RetainedConfigOpenRetirement` distinguishes:

- `Released { admission_error }`: opening and disposal have finished and the
  operation's connection, retained lock and admission slot have been released.
  `Indeterminate` still requires authoritative readback; joining is not rollback.
- `BackendReturned`: `wait` already transferred a backend. Its clones and
  outstanding work belong to the caller and are outside this retirement proof.

A completed, unclaimed result retains its admission slot. A successful one also
holds its SQLite connection and retained lock. Discarding it releases SQLite
and the lock before the slot; at most four openers or unclaimed results can be
owned at once. Taking an admitted backend releases the opener's slot while the
backend continues to own its retained lock through the existing connection
lifetime contract.

Dropping the operation requests cancellation and relinquishes its handles; it
provides no completion evidence. Drop attempts to move handle/result destruction
to the captured runtime's blocking pool. Runtime shutdown can reject that work
and run destruction synchronously. For explicit retirement, keep that runtime
available until `cancel_and_join` finishes. A cancelled shutdown *future* does
not itself shut down the runtime or relinquish the operation's ownership.

## Remaining external authority

An intact authenticated database plus admission record can be coherently rolled
back together on the same backing. Local authentication cannot detect that
event. Before serving or claiming convergence, the caller must revalidate its
target/history against the configured fresh external authority and the relevant
audit-continuity contract. The reopen check does not supply that freshness.
Total quorum loss requires an explicitly approved recovery/new-authority plan;
a workload restart, retained volume identifier or fixed roster is insufficient.

SQLite's [open flags](https://www.sqlite.org/c3ref/open.html) distinguish
read-write opening from creation; its `EXCLUSIVE` open flag is not file
reservation. The SDK publishes complete unnamed files using atomic no-replacement links. SQLite's
[file and journal integrity guidance](https://www.sqlite.org/howtocorrupt.html)
also applies throughout the lifetime of the admitted storage.


The Linux profile requires `O_TMPFILE` on the destination filesystem and procfs
at `/proc/self/fd`, in addition to the stated lock and synchronization guarantees.
