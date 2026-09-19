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
fixtures remain separate from native persistence. The explicit legacy SQL
qualification fixture retains an already-started read's WAL guard through
post-read validation when its caller disappears. It keeps the original
pre-admission deadline, checks expiry while holding the WAL lock before
success, and fences failed or expired validation before releasing a waiting
durability callback. Cancellation before worker start still reclaims queued
admission. Delayed async result delivery fails without fencing an owner that
validated on time. Non-SQL waiting/cleanup is not preemptible at that deadline.
This fixture rule adds no production persistence mode and does not change
ordinary SQL cancellation, native storage or snapshot policy.

Durable mode retains the segmented WAL's intent/data/publication ordering,
single completion owner, exact committed/application cuts, bounded admission,
strict decoding, and failure fence. A native generation checkpoint or snapshot
must be completely written, validated, synchronized, and selected before its
durable completion. Recovery validates the selected generation and all
acknowledged retained history; it cannot silently fall back to older state or
repair damage within acknowledged coverage.

The business key, V2 receipt, and generic receipt indexes share immutable
full-key/row entries through pointer-sized persistent hash-trie slots. Hashes
only select buckets: collision resolution compares every original key byte.
Replacing an entry preserves all earlier captures, and physical relocation
continues to carry the existing independent `SharedRow` revision. Map codecs
retain the original complete key and row fields; this changes resident
allocation ownership, not persisted formats or history retention. Allocation
regressions measure the actual live owners and capture releases. Those focused
measurements do not replace the full three-voter process RSS qualification.

Native snapshot export writes the portable SQLite business projection directly
into the staging inode that will be sealed and published. It does not write
local Raft log payloads and then allocate a second database to compact them
away. The immutable native capture still validates local Raft frontiers and
reads/authenticates the covered selected log bytes. Portable state retains all
required records, leases, receipts, watch history, roster state, and the exact
applied/membership cut. Finalization rotates restore metadata and validates the
synced output before the existing seal, publication, and reclamation sequence.
Install-base export separately retains the complete local predecessor required
by the installer. The snapshot format and existing SQLite fallback are unchanged.

This removes the native raw/compacted payload duplication; it does not reserve
filesystem bytes against concurrent users. Capacity must still cover retained
snapshots and origins, one growing portable staging database per active native
builder, integrity metadata, and the separate native generations. The existing
extent and namespace limits remain enforced. Retention limits and process RSS
qualification are independent of this workspace reduction.

Native journal-page construction has a separate process-wide 32 MiB admission
pool inside the unchanged 128 MiB verification budget. Before any output
allocation, a read counts the complete requested interval's canonical copy
charge, containers, and validator allowance, then acquires both reservations.
Selected extent lengths supply allocation bounds only; authenticated decoding,
full fingerprint validation, and exact canonical-size checks remain required.
An inadmissible request returns the existing `BackendUnavailable` result and
may be retried as a smaller complete page under the caller's original deadline.
It cannot silently shorten a successful page or advance its cursor.

This is optional-read resource policy, independent of persistence mode and wire
cardinality. It prevents journal output from taking more than one quarter of
the verifier while snapshot/application work is active; it does not guarantee
that every other verifier can run under arbitrary concurrent pressure. Selected
input, decoding, encoding, retained images, and worker stacks keep their
existing separate charges. Both construction reservations end after temporary
output is destroyed or at the existing successful caller handoff. Returned
caller-owned values are outside that construction pool, so it is not a process
RSS or end-to-end output-memory guarantee. Integrity errors and storage failure
fencing retain their existing behavior.

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
reuse that argument after losing resident state. An existing Async root without
the completed-shutdown proof below is
quarantined before the engine starts, including a retained committed self-vote
that causes the engine to restore an internal leader role. The SDK gate covers
incoming engine RPCs, outgoing requests/results, manual/bootstrap elections,
proposals, forwarding, and readiness. A retained vote is never erased or
lowered to make repair easier.

After the caller installs `rpc_handler()`, `initialize_cluster()` performs
the following live-quorum recovery protocol within the configured operation deadline.
The unanimous retained-owner path below applies when a compatible live majority
is unavailable:

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

A live leader can remember a prefix acknowledged by the cold voter's former
volatile incarnation. Its remembered match is only a catch-up scheduling hint:
when that match exceeds the reopened local log, the certified leader sends an
ordinary bounded snapshot through the fresh barrier and then a real matching
AppendEntries. Cold append conflicts also request this repair while returning
unavailability to the live engine. The SDK never reports regressed progress as
durable, invents a successful acknowledgement, or changes the leader's vote to
restart replication. Snapshot creation, transfer and confirmation consume the
original initialization deadline; the scheduling hint grants no authority.

The fresh-entry argument applies to the exact uniform fixed membership. A
majority must commit the new barrier without the quarantined incarnation.
Pre-crash cached acknowledgements cannot reach an entry appended after the new
nonce, and ordinary range/session validation is preserved. A stale candidate
without that entry still faces the original full-vote and log-freshness checks
at the intersecting live voters. This argument does not authorize a joint or
replacement configuration or claim instantaneous knowledge of a remote
election during a partition.

Pristine first formation uses a durably established root/mode identity before
participation. Uncertified reopen is cold even when no background generation completed.
An uncertified all-cold set requires the unanimous protocol below; local
completed generations, snapshots, equal indices, or waiting longer do not
manufacture authority. Destroying/recreating backing is not a supported recovery workflow.
Async can lose acknowledged results if the live volatile quorum is lost.

### Completed consensus shutdown

Completed-shutdown evidence was introduced with `OPCNA002`; new Async roots
use `OPCNA003`, with an additional durable authority reservation and a distinct
root-binding hash domain. Old
readers reject this format before participating: a reader that did not consume
the one-use proof could otherwise retain it while acknowledging new volatile
work. Legacy `OPCNA001` roots retain their original admission rules; there is
no implicit format migration or retrospective certification.

The clone-wide shutdown coordinator first joins maintenance lanes, Raft and
every actual storage/snapshot owner. Only an incarnation that was Active and
whose engine stopped normally can request certification. Openraft shutdown's
successful join alone does not prove a normal exit; its final running state
must also be `Fatal::Stopped`. A quarantined incarnation cannot certify a
predecessor's already-missing state. Ordinary WAL shutdown or Drop cannot
request certification.

While retaining LOCK, the Async writer drains its final generation and verifies
the complete resident/completed cut and absence of any outstanding native
operation or recorded failure. It writes and fsyncs `ASYNC-CLOSED.preparing`,
renames it to `ASYNC-CLOSED`, then fsyncs the directory. The proof binds the
exact root digest, complete selected anchor (including generation, sequence,
full LogIds and snapshot origin), full vote, committed/purged frontier and
membership. No generation is lowered or selected using only an index.

Under the same exclusive root ownership, reopening first validates the entire
selected native state and any retained snapshot origin. It verifies the proof
and its file identity, unlinks it and fsyncs the directory before starting a
writer or Raft. Interrupted preparation grants no authority. Missing proof
uses normal cold admission; corrupt, foreign or stale selected proof rejects
opening. A failure after unlink cannot accidentally reuse the consumed proof.

This evidence permits ordinary Raft participation after orderly majority or
all-voter restart. It does not select a leader or grant application authority:
the original full vote/log checks, initialization, membership and fresh quorum
barriers remain required. Shutdown cancellation preserves the shared drain and
root lock through definitive completion. Public handles must still be released
before reopen because they own the snapshot namespace. Ordinary Async session
acknowledgements retain their resident replication/application boundary.

### Reserved authority and replicated retirement

An `OPCNA003` owner syncs its root-bound `ASYNC-AUTHORITY` reservation before
starting volatile consensus. Its finite range bounds terms, indices and
authority allocators independently of completed session generations. Ordinary
operations compare resident counters against the reservation without writing
it. Exhaustion, a missing reservation or inconsistent input fails closed.

The native state machine recognizes an internal recovery-boundary command.
Ordinary application submission rejects this command. It retires the entire
predecessor range, invalidates retained leases, advances absent-key fence and
history floors, and compacts the externally visible watch stream. Physical
notification inventory and history conservation remain independently checked.
The boundary survives native generation and portable snapshot admission;
snapshot downgrade or removal is rejected. Configured protected-roster trust
roots and retained protected authority are outside this retirement vocabulary.

### Unanimous retained-owner recovery (SDK #908)

Normal Async acknowledgements remain independent of disk. An `OPCNA003` root
reserves a finite range **before** any volatile issuance. The initial ceiling
is `2^40 - 1`; each recovery era advances by `2^40`. Eras and all reserved
frontiers are bounded below the signed-counter limit. Exhaustion rejects work;
there is no wraparound or automatic reset. The reservation is independent of
session generations and survives reclamation. Reservation alone grants no
votes, leases or traffic authority.

This pre-loss bound is necessary because a live but isolated survivor can miss
an entire acknowledged majority tail, including higher fences and revocation
of earlier credentials. Every retained copy may contain the revoked credential
and allocator values below externally issued values. Local expiry, maximum
retained generation, equal indices or promoting the survivor cannot recover
that missing bound. Reserving only during recovery would be too late.

The recovery protocol uses the existing authenticated member transport and
exact immutable three/five-voter configuration. All configured retained owners
must participate; a majority of disks is insufficient. The canonical smallest
member coordinates bounded attempts, but its identity grants no new authority.
Every transition validates the configuration/epoch, fixed voter digest, root
binding, process incarnation, reservation era and exact round digest.

1. **Prepare.** Each participant closes ordinary admission, drains previously
   admitted effects and durably promises a strictly higher range. Publication
   holds the root owner through file sync, atomic selection and directory sync.
   A real self-vote advances its term above the retired range, retaining full
   log freshness and the engine's existing leader-lease checks. Preparation
   waits for the actual vote/log/application cut to be selected on disk.
2. **Select.** All prepared cuts must carry the exact same applied membership.
   Select the greatest full last `LogId`, breaking ties by smallest node, and
   require coverage of every retained committed/applied cut. Retained entries
   compare complete identities; a validated purged committed prefix must cover
   the cut without lowering its term/index. Conflicting evidence is rejected,
   never silently reconciled as acknowledged data loss.
3. **Reform.** Permit only the selected candidate's actual next-term election
   and its replication. The engine must grant real votes and commit an internal
   recovery-boundary proposal. No synthetic successful response, new member,
   erased vote, lowered generation or forged commit substitutes for this step.
   Snapshot catch-up retains existing validation and ownership; actual matching
   append plus committed local application is still required.
4. **Persist and activate.** Every member reports its applied boundary, full
   vote, membership and completed generation/sequence from its current owner.
   Only the exact all-member completion set permits participation. Activation
   is idempotent if the same boot still contains that committed boundary after
   a later real election; it grants no application authority by itself.
   The ordinary fresh quorum and Recovery/application gates remain required.

The boundary retires all earlier reserved lease/credential authority, including
unpersisted acknowledgements. New allocations exceed the prior ceiling;
retained and absent-key leases cannot revive. It also retires V1 outcome
visibility, V2 history and external watch cursors while preserving immutable
old request bindings and independently checked history/notification accounting.
Old delayed credentials cannot mutate the successor. Retained session records
survive if selected; acknowledged records/results absent from every retained
cut can be lost. External consumers must enforce the SDK's fence and history
contracts; this protocol does not certify or revoke arbitrary external effects.

A proposal captures its admission incarnation before asynchronous authority
reads and holds a shared fence through enqueue. The activated raw V2 path
acquires that fence before its final uncached acceptance snapshot. Preparation
holds the exclusive side. Incoming and outgoing accepted engine operations
retain their admission owner through definitive completion. Disk sync runs
under a joined owner without holding the passive-health state mutex. Shutdown
cannot release a root with an accepted promise still writing. Cancellation
ends the caller's wait, not these responsibilities. A replaced boot rejects old
rounds and completion replies; retry after an interrupted election prepares a
new durable range instead of replaying a guessed vote.

Every RPC, lock wait, election wait, persistence drain and activation consumes
the existing complete-operation deadline. A timed-out call can leave safe,
owned progress; retrying initialization continues it. Fixed passive states
separate `PreparingRecovery`, `ReformingQuorum`, `AwaitingRecoveryParticipants`
and unsupported/repair-required authority. `Active` never replaces traffic
readiness or a subsequent operation's own checks.

### Compatibility and unsupported authority

`OPCNA001`/`OPCNA002` roots lack a pre-loss allocation ceiling. Their live-quorum
and completed-shutdown paths remain available as applicable, but this protocol
cannot retroactively bound a lost tail. An already-fenced legacy installation
needs independent authority that can durably retire its lost scope and finish
or revoke accepted effects at every affected consumer, then authorize one
exact successor state. Neither data-loss acceptance nor the existing product
Recovery object supplies those facts. The existing operator-recovery API itself
requires a live quorum. No migration/reset recipe is provided as a substitute.

All participants must retain applied exact fixed membership. If loss predates
its first persisted generation, this protocol does not synthesize membership
or rerun genesis; health reports `RetainedMembershipRequired`. Missing/corrupt
roots, conflicting committed histories and exhausted ranges also require
separate repair. A configured protected-roster trust root or retained protected
authority reports `ProtectedAuthorityRequired`: its external retirement
vocabulary is outside this protocol, including lost volatile activation.
These are availability limits, never successful fence-only recovery outcomes.

The protected restriction also applies to newly provisioned `OPCNA003` roots;
it is independent of older deployment migration. The provider contract fences
one immutable admission/member binding. Issuing a larger consensus fence for
a different admission does not advance that old provider row. A local permit
can still authorize its provider effect while consensus subsequently rejects
its terminalization. Expiring the permit prevents new calls but neither undoes
an earlier durable effect nor reconstructs lost admitted bytes. Disk waits
during recovery alone cannot supply this missing authority.

The real retained-root/mTLS RED and independent disk-backed provider controls
are recorded in [the protected recovery follow-up](../async-protected-recovery-908.md).
They establish the need for recovery-only scope retirement and exact effect
reconciliation, not a requirement to make ordinary Async acknowledgements
wait for disk. No such protected recovery capability is implemented yet.

The Async wire discriminator advances to `OPC-ASYNC-2` so older peers cannot
admit state without understanding retirement/snapshot semantics. Mixed-version
Async membership is rejected. Upgrade members and consumers together; Durable
encoding and acknowledgement semantics remain unchanged.

[`docs/async-majority-recovery-908.md`](../async-majority-recovery-908.md)
records the meaningful pre-change RED, lost-tail RED/GREEN, adversarial checks
and remaining qualification. SDK results do not establish product recovery,
packet continuity, audio or production HA.

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
