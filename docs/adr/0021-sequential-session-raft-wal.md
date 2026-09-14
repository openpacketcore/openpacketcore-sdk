# ADR 0021: Sequential Session Raft WAL

## Status

Historical private design. [ADR 0022](0022-native-session-persistence-modes.md)
supersedes its application composition, public activation, and migration scope.
The ordered durable WAL implementation and its failure/recovery tests are
preserved. The body below records the original SQLite-projection design and
must not be read as the current public configuration or qualification status.

## Date

2026-09-08

## Decision

The following was the initial private implementation decision. The supported
native application and selectable persistence contract are recorded in ADR
0022; no legacy migration engineering is part of that decision.

Replace the session Raft log's SQLite persistence with an SDK-owned sequential,
segmented WAL and bounded group commit. SQLite is the initial durable session
state-machine implementation; its retention is provisional, subject to measured
end-to-end results. Openraft remains the only consensus authority. Do not implement
a separate split-SQLite prototype or change `opc-persist`'s configuration log.

This is a performance hypothesis, not a throughput result. Existing consumer
types, constructors, builders, errors, deadlines, encrypted transport and call
sequences remain compatible. There is no consumer transaction API or engine
selection knob. Keep the candidate private and test-only until adapter,
snapshot, recovery and migration integration receive independent review.

## Ordered persistence contract

The pinned Openraft 0.9.24 fork at
`f607e636406b16bd0ad7925dbb631da1b7a4cd96`, `storage/v2.rs`, requires ordered
write IO, including votes; consecutive logs; readable entries when append
returns; and successful `LogFlushed` completion only after durability.
`save_vote` must await durability. The SDK's existing durable committed-watermark
contract also remains mandatory.

One lifecycle-owned writer serializes append, vote, committed watermark,
truncate and purge records. Admission bounds requests, encoded bytes and
callbacks before accepting ownership. Each accepted callback has exactly one
completion owner, including cancellation, shutdown and writer failure. Reads
may observe a bounded validated pending view after admission. Pending
visibility, local durability, quorum commitment and SQLite application are
different states. Only Raft-committed entries reach SQLite apply, which keeps
last-applied, membership and receipt changes atomic.

Compatible already-queued operations may share a flush. An idle singleton is
flushed promptly; the initial policy introduces no deliberate fill delay.
Count and byte limits bound a group and outstanding work. Queue wait, write
time, sync time, group distribution and callback delay must be recorded
separately. A timer cannot bound a stalled filesystem sync or make an abandoned
writer safe. Shutdown must join owned work before closing its files.

The pinned core awaits each append callback inline before updating replication
progress (`raft_core.rs:707-732,1622-1632`). Independent submitter tests establish
queue ownership, not group formation in that core. Measure actual core groups
and all singleton barriers through the public SDK before claiming improvement.

## Format and validation

The private format binds a version, storage identity, generation and ordered
segment lineage. Length limits are checked before allocation. Frames bind their
type, sequence and complete body with a checksum. Entries retain the complete
`SessionRaftTypeConfig` representation and the existing exact V2 decoder,
command validation and membership/receipt projection. Checksums do not replace
those validators. No SQL validation or operator-recovery authority is removed
from the production adapter by the private slice.

Segment creation and rollover require file and parent-directory durability.
A durable publication record binds the accepted log cut; acknowledgement must
follow both data durability and publication. Before any data write, the private
v3 writer creates a 192-byte immutable intent under `cut-N.preparing`, syncs
it, renames it to `cut-N.pending`, and syncs the directory. This intent binds
the generation/basis, predecessor publication hash, exact prior cut, operation
count, physical byte charge and exact planned final segment/offset. Planning
uses the queued operations' actual lengths and canonical fragment packing.

After syncing the data, the writer appends a 160-byte final cut to the same
file without overwriting the intent, syncs it, renames it to `cut-N.cut`, and
syncs the directory before any success callback. Each complete publication is
352 bytes; the next intent hashes that whole publication. This requires
**five sync calls per group**, including singleton votes and committed markers.
Rollover adds a segment-header sync and directory sync, plus a data sync when
the preceding segment is dirty. Initial basis/lock creation has additional
setup syncs. Observations separate intent, queue, write, data-sync, publication
and callback timing. These barriers remain a measured performance cost.

Queue residence starts after admission. Separate observations cover encoding,
mutex wait, full projection, total admission and submit-to-callback duration;
none of those private timings substitutes for public SDK call latency. The
pending-view slice replays its unapplied suffix during each admission, so its
repeated validation cost also remains a performance limitation.

The private v3 format splits a complete ordered operation into physical
fragments of at most 1 MiB. Each 100-byte header binds its operation sequence,
total byte length, exact fragment offset, previous fragment hash and body.
An append retains at most 64 independently bounded 16 MiB entries without
concatenating them into another aggregate allocation. Recovery parses this
stream into individual entries and runs the original complete decoder and
projection only after the whole operation has arrived. A fragment cannot be a
published operation cut or complete a callback. Every dirty segment crossed by
an operation is synced before rollover; the final segment and publication are
also synced before its single completion. A cut naming a valid middle fragment
still fails recovery.

An append larger than the ordinary queue/group byte budget enters only when
there is no outstanding work and executes alone, within the fixed full-operation
bound. Further admission waits for its completion. The retained byte/segment
budget remains finite and requires moving-basis reclamation before production.
An application batch can exceed 64 entries: exact comparisons use bounded read
chunks, while log materialization, business effects, last-applied, marker and
responses retain the original whole-batch transaction and result boundary.

The recovery basis uses the existing snapshot database extent ceiling. The
pending projection is an anonymous SQLite temporary database, opened exclusively
and immediately unlinked by the bundled Unix VFS, with no reusable connection
path. A fresh projection is reconstructed on each open. Rollback journaling
stays enabled; synchronous is off because the projection is disposable. After
backup establishes the actual page size, the common writer extent guard is
installed and verified and the 8 MiB page-cache target is reapplied. That target
is not a process-memory cap. Full basis hashing and content audits remain at
attachment, and the applied-prefix proof also checks data_version alongside
its sole connection's write and schema counters.

The private moving-basis handoff gates new admission and drains every accepted
completion owner. The sole writer then holds the application/admission mutex
while auditing and copying the complete projection, including acknowledged
unapplied and uncommitted entries. An unselected `basis-N.preparing` may be
incomplete. The complete image is closed, synced, hash-bound, renamed without
replacement to `basis-N.sqlite`, and directory-synced before selection.

A bounded canonical `CURRENT` selector binds the immutable root identity, basis
hash and extent, monotonic checkpoint epoch, exact acknowledged operation/cut
position and hashes, and the retained segment prefix hash. Its temporary file
is synced before atomic replacement, and the directory is synced before any
covered file is reclaimed or the checkpoint can return success. The anchor
segment remains intact; recovery verifies its prefix and replays only the
suffix after the selected offset. Operation, publication and segment numbers
remain monotonic, while retained byte/count/segment limits start at that basis.

Recovery never falls back from a damaged selected image or selector. It validates
the basis, retained prefix, every acknowledged suffix and pending-tail proof
before mutation, then stabilizes the publication namespace before removing
covered cuts, earlier segments, or obsolete/unselected basis preparations.
Interrupted cleanup can leave any subset of covered names. Reopen repeats the
directory durability boundary even when a prior cleanup already removed them.

The selector carries the current durable cut and the exact older application
marker/cut still required by the cache, at most two cuts. That expectation
survives a checkpoint made before cache attachment. A missing marker cannot
become acceptable merely because the advanced basis now has the same applied
pointer. An intact marker restores; a later original application transaction
may extend its frontier; relabeling the same applied image is rejected.

Detailed flush samples retain at most the configured history count of requests,
including all vectors owned by each retained group. Fixed-size totals cover all
completed flushes in the current writer incarnation across checkpoints. Reports
separate retained and discarded samples from those totals and capture both
under the same mutex. The private internal checkpoint also supports the
snapshot metadata handoff below. Normal construction, automatic triggers and
snapshot installation remain required before production activation.

Ordered Raft purge uses the original complete logical-purge transaction and
may advance only through the selected basis's exact applied coverage. Logical
reads omit covered rows, while the projection and application cache retain
their physical validation rows. The full recovery comparison includes those
rows, so a changed or missing cache payload below the logical floor still
fails. Moving the WAL basis does not authorize a one-sided physical delete;
application-row reclamation requires the coordinated snapshot/cache handoff.

Before any repair, recovery verifies every published cut, all acknowledged
segments and frames, exact whole-operation boundaries, LogId lineage and the
complete original semantic/authority projection. Missing or damaged acknowledged
history is rejected with every file preserved. A checksum error alone never
authorizes truncation. Complete published cuts are adopted even if their reply
was lost. After all validation and any repair, recovery syncs the publication
directory before returning a usable owner, including when no pending file
remains. A prior writer may have renamed a synced final cut but died before
its directory sync; this handoff sync prevents later power loss from reverting
that observed cut to pending after the reopened adapter exposed it as durable.
A failed handoff sync returns no usable owner. Coordinated rollback of all
evidence is not detectable without an independent monotonic anchor.

At most one next-ordinal preparation or pending intent may survive. A partial
`preparing` file authorizes no data mutation; it can be removed only when the
data already ends exactly at the fully audited published cut. A valid `pending`
intent proves the next group could not have received a success callback: that
name must have been durably replaced before success. Its immutable prefix
survives failed/partial final-cut writes. Recovery requires its exact origin,
predecessor hash and planned bounds before discarding any suffix. Unrelated
segment names, foreign header prefixes, impossible packing, excessive extents,
or missing intent with remaining data are rejected without mutation.

Repair truncates the retained last segment and always syncs it, even if a prior
interrupted truncation already changed its observed length. It removes only
intent-owned later segments, then syncs the directory before unlinking the
intent and syncing the directory again. The intent remains durable throughout
data cleanup. An interrupted directory sync can persist unlinks in any order;
holes are accepted only beyond the verified acknowledged cut and within the
same intent's planned extent. A retry repeats the retained-segment sync before
retiring proof. This restart path covers append, rollover, publication and
cleanup interruptions; corruption inside acknowledged coverage remains fatal.
Private v2 artifacts retain their original binding and are not adopted as v3.

The first executable slice pins one hash-bound frozen SQLite image, including
its exact applied LogId, membership, application sequence, logical time and
receipt/history state. Every admission and replay runs the original full-row
decoder and SQL membership/receipt projection on one serialized anonymous
projection containing that base plus the ordered WAL suffix. Application advances the
projection through the original apply implementation; recovery still starts
at the frozen image. Purge is limited to that image's applied cut and retained disk
evidence is never reclaimed. The private adapter implements the actual
Openraft `RaftLogStorage` and `RaftLogReader` traits. The serialized writer owns
`LogFlushed` directly; awaited metadata uses oneshots without detached relay
tasks. Empty appends use an ordered barrier record. Both dynamic and fixed
authority are supported using the original full fixed-authority checks and
the hash-bound basis's membership, bindings and placement policy. Creation
rejects live or consumed operator-recovery sidecars; live sidecars remain an
explicit integration boundary.

## Application cache integrity

The private application adapter admits only exact WAL entries at or below an
already-durable committed cut. Within the original Immediate apply transaction
it materializes that committed SQL log prefix, advances the cache's committed
pointer only to the applied batch, executes all original business and receipt
logic, and writes a marker binding generation, cut sequence/hash and applied
LogId. The cut itself records its committed frontier. A known older cut cannot
authorize an application beyond that frontier. The WAL owns Raft log/vote/
commit authority; SQL rows are an application and snapshot validation cache.

Attachment/recovery replays WAL entries into the pending view and compares the
complete materialized prefix and all non-log schema/data with one SQLite read
image. The durable cache is never repaired by overwriting unexplained evidence.
After attachment, the serialized apply path uses the same validated base,
same entries, capabilities and original deterministic apply implementation for
SQL and the projection; it compares complete responses and replication notifications.
It does not rescan retained business history on each application.

Normal application also inherits an exact audited log prefix. A private proof
binds its full applied LogId to the immutable generation/basis and the sole
anonymous projection connection's write, data-version and schema counters. Only a complete
recovery comparison or a successful, fully validated extension followed by both
original apply transactions can establish that proof. Each application still
checks the acknowledged committed cut, exact new entry bodies, ordered LogIds,
all crossed/following compaction markers, and the original business validators.
Append-only admission preserves the old prefix; vote, committed-pointer and
barrier transactions cannot alter it. Their successful transactions may carry
the proof forward under the same state mutex. Truncate, purge and rejected
projection attempts discard it. Recovery and destructive operations keep full
audits, and the first subsequent apply reestablishes the complete prefix before
reuse. Unexpected projection writes or DDL fence the owner. These live connection
counters are writer-exclusion evidence; they cannot replace the full content
audits at restart, snapshot or generation boundaries.

One temporary nonce binds the attached SQLite connection. Its total_changes,
main data_version and schema_version are checked before use and again under
the Immediate transaction. Together they detect unexpected writes on that
connection, commits by other connections, and DDL. The next expected counters
are captured inside the successful transaction, never sampled as a new trusted
baseline after commit. Any unexpected change requires a terminal fence and a
fresh recovery audit. These counters prove the connection's write ownership;
they are not content hashes or a replacement for durable recovery validation.
Production integration must route every legitimate application/snapshot writer
through this ownership boundary and durably exclude legacy writers.

Physical application reads also retain the common WAL fence while checking
the cache before and after the original read. Each read must finish its SQLite
transaction before the second check, so a foreign commit during that read is
detected before its result escapes or a waiting callback succeeds. This covers
Openraft applied-state/current-snapshot reads, SDK application/receipt reads,
restore scans, and live fixed-authority checks. The private route sends
acceptance reads through the single attached primary connection; generation-
bound secondary readers remain an integration and performance requirement.
Unsupported pending-membership opens reject the private token before staging.

Invalid caller entries or a not-yet-durable committed frontier are local
rejections. Corrupt/mismatched cache state, an apply failure or ambiguous SQL
commit fences admission, reads and later success callbacks under the common
State mutex, including an empty apply. A crash after SQL commit restores the
bound applied base without repeating SQL business effects. The second original
apply remains real work that must be measured through the public SDK.

The real-Raft integration fixture explicitly opts a fresh file-backed backend
into this candidate under `cfg(test)` on Linux. Existing SDK constructors then
use the actual WAL log adapter and original application transaction. A retained
private test token remembers the exact basis binding for orderly SDK reopen;
it supplies no production selector or legacy migration authority. Every routed
log operation checks the attached application cache and pristine recovery
sidecar state. The existing store shutdown barrier precedes the WAL writer
join. The private builder uses the snapshot metadata handoff below; receive and
install still reject before mutation. The fixture retains the existing public call shapes,
fixed validators and timeout configuration; its local-AEAD calls and in-process
Raft peers are functional/cost observations, not remote, snapshot or quiet-host
performance qualification.

The private cost cases separately observe eight ordinary concurrent CAS calls
and public eight-item V2 batches. The first V2 batch retains unanimous
capability/history admission and the original activation singleton; a later
eight-item batch uses the existing warmed route. Every result and retained
receipt is checked on all three voters, with encrypted SDK reads. Cumulative
phase observations occur outside public timers and do not drain followers.
Constant-space cache/application totals separate validation, physical reads,
original SQLite apply, its commit-and-return subset, and the second projected
apply. Flush observations include request kind and append-entry cardinality,
so one storage request is not confused with one Raft entry. These intervals
overlap across threads/voters and are not additive public latency components.
Optimized private observations run these SDK cases alone; the original remote
one-second and bounded eight-op/800ms/strict-snapshot gates remain required.

## Failure states

| Boundary | Required result and recovery behavior |
|:--|:--|
| Rejected before admission | No pending visibility or durable effect; a callback already transferred into the method is completed once with failure. |
| Accepted, pending write | Read visibility is provisional; cancellation leaves the writer responsible. |
| Data written, sync or publication uncertain | No success acknowledgement; fence the writer and later operations. Restart audits all acknowledged history before repairing only a suffix covered by the durable pending intent. |
| Durable cut published, reply lost | Reopen the exact cut; never invent a replacement entry, vote or operation identity. |
| Writer error or panic | Complete every accepted callback once with failure unless its success was already durably established. Never acknowledge beyond an unexplained gap. |
| Partial frame, checksum mismatch, missing segment or lineage mismatch in acknowledged coverage | Reject reopening; retain corrupt evidence. A valid pending intent cannot excuse damage to that coverage. |
| Interrupted tail cleanup | Retain intent through all tail syncs; retry the retained-segment sync even when its observed length is already correct. |
| Truncate or purge crosses committed/unapplied history or a recovery fence | Reject before publication. |
| Shutdown with accepted work | Drain or fail each owned completion and join the writer; elapsed timeout alone is not successful cleanup. |

## Snapshot and migration integration

The private builder keeps the original snapshot gate and primary cache
connection while the sole WAL writer drains accepted callbacks. It selects a
complete old basis, applies the original snapshot metadata transaction to its
projection and prepares a complete new basis. A bounded canonical checksummed
`SNAPSHOT.pending` binds both exact anchors and application digests. Its file
and directory are durable before the first cache metadata write. Both anchors
retain the same operation cut and exact application marker. This protocol
does not install another application image.

The actual private builder declares `Compact` in the pending proof and invokes
the original physical-purge validator inside the metadata transaction on both
the projection and cache. It deletes only through the verified snapshot's exact
last LogId, retaining every later physical row. A stronger existing logical
floor remains intact while even a delayed snapshot removes its covered rows
from both images. Missing transformation retains the exact original
metadata-only proof encoding; an older reader rejects the new explicit field.
The handoff owns and audits both images, so an independent background prune
cannot delete cache rows across it. Deletion permits SQLite page reuse without
claiming file shrinkage.

The cache uses the original Immediate metadata transaction, checks its old
whole application image and captures its next connection guard inside the
transaction. The complete new image, exact raw applied log and marker are
audited again after commit. The writer then selects and syncs the new basis,
unlinks and syncs the pending proof, and only then reclaims old files and
permits successor admission. Failure fences the common owner. The actual
builder retains its external candidate before the first fallible preparation,
so an ambiguous proof rename cannot cause cleanup to unlink recovery evidence.
An exact generic SQLite metadata readback cannot override a WAL failure.

Pending recovery retains the WAL lock while the original immutable descriptor
checks pin both external snapshot files. It validates both complete bases and
all acknowledged history, then repeats those audits under the cache Immediate
transaction before any repair or scavenging. Replaying the declared original
metadata transaction and optional physical purge on a verified old image must
reproduce every schema object and physical row of the new image. Only
old-selector/old-cache abandonment,
old-selector/new-cache completion and new-selector/new-cache completion are
admissible. A later WAL cut, damaged cache, missing descriptor or inconsistent
image rejects without repair. Proof retirement is synced before reclaim;
restart also syncs the publication directory when unlink was already visible.

Source capture checks the cache owner around fixing its separate read image.
An authorized later apply may advance the live cache while the captured
snapshot retains its earlier cut. Foreign writes must fence capture or
publication, and the cache metadata transaction excludes competing writers.
Portable finalization removes the local application-lineage table. These
private controls do not yet resolve the earlier generic constructor DDL:
normal new-format opening must establish authority before legacy initialization
can repair or mutate an image that requires an exact audit.

Private remote installation extends this same two-image handoff with an
explicit Install transform. It holds the physical WAL position, chain, retained
prefix and root constant while the original install transaction establishes
the incoming exact applied/committed frontier. A single installed cut binds
the installing epoch and exact candidate metadata digest; it is never a
fabricated ordinary log acknowledgement. Sequence zero and repeated identical
installs are valid. Later checkpoints retain this origin until marker lineage
no longer needs it; ordinary acknowledgements create ordinary cuts.

Replay obtains incoming RAW exclusively from the continuously pinned published
envelope, including bounded derivation at pending recovery. It never uses NEW
as the incoming source. The sole choice taken from NEW is the fresh local
restore epoch/key, read through the existing complete restore-state validator.
The original copy-then-rotate transaction produces incoming revision plus one.
Complete transformed-image equality includes retained unapplied physical rows;
the cache audit uses the marker of whichever OLD or NEW image it selects.
Immediate source revalidation precedes commit, selection and proof retirement.
Committed detach failure fences the owner without generic readback revival.
The original live recovery gate, primary connection release, applied progress
publication and prune permit release continue to govern the actual adapter.
Once the proof is retired, completed selected-image recovery needs no RAW
derivative. These private changes still require their focused execution and
the normal constructor/migration/recovery integration described below.

Snapshot publication/install must bind the verified SQLite image, exact applied
LogId and membership to one durable WAL cut. Preserve strict fs-verity,
portable verified reads, and Active/Pending operator-recovery sidecars and
terminal latches. Purge must not remove application-unapplied committed entries
or the sole recovery evidence. Append and apply remain separate transactions
on opposite sides of quorum commitment.

The integration sequence is: executable private WAL and fault tests; shared
full-row validation and real storage-trait adapter; exact snapshot/cut and
recovery-fence integration; crash-safe legacy migration; independent review;
then production routing through the existing constructors. Until each boundary
is implemented, refuse unsupported state rather than substitute a weaker
authority or enable the candidate implicitly.

Migration must stop the old writer and hold a SQLite Immediate transaction
while copying and verifying the complete legacy state into a distinct
generation. Retain an exact pre-interlock image and the original database.
Before selecting the new generation, commit an old-binary rejection format
plus denial triggers covering writes from already-open legacy connections.
The same transaction must bind the exact prepared generation. A selector
unknown to old binaries is not a writer fence.

Before that interlock commits, restart uses legacy state and preserves any
unselected candidate. After the interlock commits, restart must finish or
validate selection of its exact bound generation; it cannot fall back to
legacy. Selection follows complete generation durability and requires an
atomic namespace publication plus directory sync. Ambiguous or damaged
publication fails closed. These migration transitions still require executable
implementation and interruption tests before production routing. There is no
automatic destructive conversion or promised old-binary format rollback.

The selected-generation boundary must also route the existing operator-recovery
physical-log readers/writers in `recovery/sqlite.rs` and the public
`audit_sqlite_identity_invariants_at` entry point. They may not continue reading
stale legacy `consensus_log` rows after a switch. The storage adapter's exact
apply wait and Active/Pending terminal fences remain required at compaction.

## Qualification

Focused tests must cover real file persistence, flush-before-ack, ordered votes,
pending reads, callback ownership, cancellation/shutdown, short writes, sync
failure/ENOSPC, rollover, reopen, acknowledged-prefix damage and full V2/authority
validation. Snapshot/migration interruption tests and real fs-verity disk plus
encrypted authenticated three-voter tests remain required before qualification.

Retain every #776 change unless integration makes a particular part unnecessary
or incorrect and documents why. Preserve the original failures. Final evidence
must meet the unchanged #741 target of at least 1,000 durable logical operations
per second, existing eight-operation V2 batches and at most 800 ms per public
operation, with two strict snapshots per voter and zero storage errors. Report
logical operations separately from records, commands, batches and syncs.
The existing singleton selector/descriptor sequence must also meet its original
deadline over the encrypted remote three-voter path. Neither this ADR nor an
isolated WAL result proves those outcomes. Parent owns independent integration
review and the final required repository gates; ePDG remains stopped.
