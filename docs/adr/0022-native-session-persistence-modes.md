# ADR 0022: Native session storage and explicit persistence modes

## Status

Accepted feature contract. Correctness, performance, and consumer qualification
are separate executed evidence; this decision does not declare their completion.
This supersedes ADR 0021's private-only activation, SQLite application
composition, and proposed migration scope. Its durable WAL implementation and
regressions remain part of the SDK.

## Date

2026-09-10

## Decision

The SDK owns the native session state machine, strict generation/snapshot
validation, and ordered durable WAL. Openraft remains the sole consensus
authority. Fixed three- and five-voter construction supports an explicit public
`SessionPersistenceMode` choice, independent of `SnapshotIntegrityPolicy`:

- `Durable` preserves ordered durable log/vote/commit acknowledgement followed
  by real quorum commitment and application. Existing constructors and the
  enum default select this mode.
- `Async` acknowledges validated resident storage to the engine, then retains
  actual quorum replication and committed application as the public success
  boundary. A single coalescing writer selects completed local generations in
  the background. Disk progress may lag successful public operations.

Async is a supported storage configuration. It requires no test-control
feature, private activation token, consumer transaction API, or product-owned
storage backend. The operation types, encryption and provider boundaries,
exact V1/V2 results, ownership/fencing, and ambiguity rules are preserved.
`OutcomeUnknown` remains a status/reconciliation outcome and never permits
automatic replay. `NotTransmitted` retains its existing exact meaning.

The public constructors are
`ConsensusSessionStore::open_fixed_quorum_with_persistence(topology, backend,
snapshot_dir, peers, snapshot_integrity, persistence)` and
`open_fixed_quorum_with_clock_and_persistence(topology, backend, snapshot_dir,
peers, clock, operation_timeout, snapshot_integrity, persistence)`.
The first uses `SystemClock` and the existing ten-second default. The second
carries the caller's existing complete-operation deadline, including routing,
quorum, and apply; background scheduling cannot extend it. Both require Linux,
file-backed storage, the exact fixed topology, and authenticated scope-bound
peers. The existing topology names containing `fixed_durable` identify that
fixed membership profile; persistence is the separate explicit constructor
argument.

## Native state and durable ordering

Native log, application, receipts, fixed authority, restore state, and snapshots
share one lifecycle-owned storage authority. Selected native reads and apply
use that authority rather than a second mutable SQLite application projection.
SQLite remains the public file-backed construction type and the verified
snapshot interchange format. Standalone SQLite and the historical private WAL
fixtures retain their existing contracts.

Durable mode retains the segmented WAL's intent/data/publication ordering,
single completion owner, exact committed/application cuts, bounded admission,
strict decoding, and failure fence. A native generation checkpoint or snapshot
must be completely written, validated, synchronized, and selected before its
durable completion. Recovery validates the selected generation and all
acknowledged retained history; it cannot silently fall back to older state or
repair damage within acknowledged coverage.

Ordinary construction selects a fresh native root or reopens its exact selected
state. The backing retains native-selection knowledge independently of the
native directory, so missing selected state is an error. Existing populated
legacy state is not silently converted. No legacy or cross-mode migration is
included in this feature.

## Async writer and local observations

Foreground admission applies the original validators to resident state and
owns no per-operation disk request, disk-queue capacity permit, checkpoint
drain, or retention I/O. Real engine/proposal admission and finite native
memory bounds remain. Encoding, generation append/verification, file sync,
selector replacement, and relocation work belong to one storage writer.
At most one detached generation is being persisted per voter while later
resident changes coalesce.

The ordinary capture schedule is 250 ms; explicit drain, shutdown, and
snapshot/install work can request an earlier capture. The schedule is not a
maximum durability lag. The selected generation records exact resident
generation/sequence and committed/applied cuts. A completed selector supplies
local reopen input and permits only the corresponding validated relocation.
The current per-voter generation extent ceiling is 8 GiB; journal/verification
working-set limits remain separate. Neither number is a process RSS claim.

`persistence_health()` returns passive `SessionPersistenceHealth`: configured
mode, engine and storage lifecycle, first typed storage failure, recovery
posture, and `SessionAsyncPersistenceProgress`. The latter reports resident,
captured and completed generation; resident/completed sequence; completed
committed/applied indices; lag; completed bytes; extent limit; saturation; and
the first background failure. These observations can race subsequent work.

Ordinary background I/O failure latches the original typed category and stops
new persistence. Resident quorum operations may still succeed while the owner
and finite allocation remain usable. Corruption or an ownership/lineage failure
fences the owner. Storage/memory capacity failures set `saturated`; they are
not hidden by an infinite queue or automatic retry. A restart uses only the
last completely selected generation and must satisfy cold admission below.

`drain_async_persistence()` requests the call's captured resident cut through
the same writer and original complete-operation deadline. It does not wait for
arbitrary later mutations. Timeout/cancellation preserves the writer's
accepted responsibility. Typed errors distinguish `NotAsync`, `Unavailable`,
`Failed`, and `DeadlineExceeded`. Shutdown drains or fails owned work and joins
it before releasing storage. Local drain success cannot attest a durable
quorum or authorize restarting an all-cold fleet.

## Cold-incarnation admission

Raft's ordinary restart argument assumes voting/log persistence. Async cannot
reuse that argument after losing resident state. Every existing Async root is
quarantined before the engine starts, including a retained committed self-vote
that causes the engine to restore an internal leader role. The SDK gate covers
incoming engine RPCs, outgoing requests/results, manual/bootstrap elections,
proposals, forwarding, and readiness. A retained vote is never erased or
lowered to make repair easier.

After the caller installs `rpc_handler()`, `initialize_cluster()` performs
the following recovery protocol within the configured operation deadline:

1. Drain operations admitted under an earlier attempt. Create a nonce tied to
   the current process incarnation and a monotonically distinct attempt.
2. Ask the live peers for a genuinely new committed command appended for that
   nonce while this incarnation cannot vote or acknowledge replication. The
   successful completion retains the command's actual full `LogId`, exact
   scope/configuration/epoch, requester, fixed voter digest, membership log
   identity, and the same full committed leader vote observed around submission
   and completion. A cached logical-time result or an old completion cannot
   be relabeled as a new certificate.
3. Permit catch-up only under that certified full vote and lineage. The live
   quorum must already have committed the barrier. Append confirmation uses
   the actual successful sending range and requires numeric coverage with the
   same leader identity; `leader_commit`, scalar index, or ordinary `LogId`
   ordering alone is insufficient.
4. Require local committed application through the certified prefix plus exact
   current fixed authority, effective membership identity, full vote, and
   leader. Replication success before application cannot activate the voter.
5. Publish Active only from that still-current CatchingUp attempt while holding
   its exclusive activation fence. In-flight cold RPCs retain their shared
   fence through definitive completion. Cancellation or replacement cannot
   let an old callback activate the new attempt or cut over its snapshot.

Snapshot repair retains the selected PortableVerified or FsVerity policy,
exact authority, metadata identity, and completed installation. A pre-barrier
snapshot can supply only a base. A snapshot covering the barrier still needs
the certified leader's subsequent successful matching-prefix confirmation and
local application before activation. Snapshot chunk receipt or metadata index
coverage is insufficient. Failed final installation retains its original
storage error and wakes blocked purge/application waits without advancing the
applied frontier.

The fresh-entry argument applies to the exact uniform fixed membership. A
majority must commit the new barrier without the quarantined incarnation.
Pre-crash cached acknowledgements cannot reach an entry appended after the new
nonce, and ordinary range/session validation is preserved. A stale candidate
without that entry still faces the original full-vote and log-freshness checks
at the intersecting live voters. This argument does not authorize a joint or
replacement configuration or claim instantaneous knowledge of a remote
election during a partition.

Pristine first formation uses a durably established root/mode identity before
participation. Reopen is cold even when no background generation completed.
An all-cold set remains `RecoveryRequired`; local completed generations,
snapshots, equal indices, or waiting longer do not manufacture a surviving
quorum. Destroying/recreating backing is not a supported recovery workflow.
Async can lose acknowledged results if the live volatile quorum is lost.

## Mode isolation and traffic authority

The persistence choice is immutable for a root and must agree across all
voters. A mismatch rejects before engine or forwarded-control mutation.
Async engine, recovery, and successful control replies carry a bounded mode
tag within the original payload limits; Durable encoding is preserved.
Snapshot integrity remains an independent choice and cannot enable Async.

`probe_fixed_quorum_readiness()` and its placement/time variants return
`SessionQuorumReadinessReport`. Granted requires exact recovery clearance,
membership, a fresh majority barrier, and local application within the original
operation deadline. Async does not wait for disk generation progress. Placement
resilience and passive persistence health are separate fields. Every actual
operation repeats its own authority checks.

Existing durable probes return `PersistenceNotDurable` for Async. Thus changing
configuration cannot silently turn a durable-readiness declaration into a
weaker persistence claim. Products select the storage mode and mode-aware
traffic gate explicitly; they do not mint SDK authority from counters.

## Verification and remaining qualification

The regression matrix includes ordinary public writer delay and ENOSPC,
selected-generation reopen, lost voting state, an all-cold fleet, restored
leader suppression, exact certificate bindings, real leadership changes and
cached completions, original append ranges, incompatible suffix repair,
delayed apply, compacted snapshot recovery, failed final install, and
cancellation immediately before activation and snapshot cutover. These use
actual three/five-voter schedules and original operation deadlines. Durable
log, application, snapshot, and public API regressions remain required.

The performance acceptance still requires the original encrypted public call
path, workloads, pacing, exact outcomes, tail/deadline assertions, snapshots on
every voter, and resource limits. An Async measurement must explicitly identify
its acknowledgement mode. Functional writer independence does not qualify
scale or process RSS. Required local/hosted gates, signed immutable source,
independent integration review, and the checked consumer revision remain
separate completion requirements.
