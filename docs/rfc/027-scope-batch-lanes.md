# RFC 027: Independent scope batch lanes and exact outcomes

Status: implemented; qualification of the combined scope profile is recorded
separately.

## Purpose and boundaries

Permit eight independent, bounded outstanding batches in one scope, with exact
retry, cancellation and recovery. Preserve atomic child/claim/counter changes
and protect a predecessor that a handoff reads without rewriting it.

The contract builds on the untimed authority in
[RFC 022](022-scope-leases.md), including its stable-scope floors and closure
contract. The
[request](../../crates/opc-session-store/src/scope_batch.rs) and
[planner](../../crates/opc-session-store/src/scope_batch/state.rs) implement eight
independent sequences, complete read predicates and an optional scope-wide
revision guard.

The batch coordinator consumes `ScopeNamespace` and `ScopeAuthorityStamp`; it
creates no authority, clock dependency or timeout-based ownership. Admission,
process closure and retirement follow RFC 022. Coherent paged scans, scheduling
and authenticated transport retain their own contracts.
Stable scope binds the configured name-derived cluster identity from
`ConsensusClusterId::new`; voter replacement changes neither worker authority
nor lane identity. Reusing the cluster name reuses that identity; a separate
installation-qualified identity is deferred to SDK #1187.
This proposal chooses bounded per-lane receipts over a global serialization
point or an unbounded request journal.

## API and arbitration

These interfaces implement the lane and exact-outcome contract:

| Interface | Contract |
| --- | --- |
| `ScopeBatchCoordinator::reserve(class)` | Obtain the class's resident credit before a shared lane; established Emergency takes exclusive lane 7 before its resident credit. Construct the request only after both grants. Handles from one execution's coordinator share arbitration state. |
| `ScopeBatchRequest` | Namespace, complete authority stamp, lane, sequence, request ID, mutations, read conditions and optional whole-scope revision condition. |
| `ScopeBatchAttempt` | Immutable namespace/stamp/lane/sequence/ID/canonical-digest identity derived from the request. |
| `ScopeBatchStore::execute(request)` | Apply once or recover the exact retained result. A refusal at one cut is not permission to abandon possible submitted copies. |
| `cancel(attempt)` | Order cancellation against that exact attempt; return its winning terminal result. |
| `ScopeBatchStore::lookup(attempt)` | Authenticated, read-only exact outcome classification at a committed cut. |
| `reopen()` | Return the eight lane frontiers, retained results, counters and authority at one cut for reconciliation before reuse. |
| Coordinator completion stream / `ack(attempt)` | Bounded terminal-result delivery to the execution's supervised reconciler; acknowledge the exact attempt before releasing its lane. |
| Coordinator lane status | Per-lane age of unresolved work and of the oldest locally observed unacknowledged terminal result, with the latest unresolved failure; diagnostic only. |

`ScopeBatchCoordinator::open_port` accepts an authenticated `ScopeBatchPort`, an
existing committed authority capability, the shared scheduler and an opening
class. The port's `reopen`, `apply` and `cancel` receive the current effective
class. Adapters preserve it through transport capacity without a second lane or
resident reservation. The local adapter uses the complete ReadIndex barrier;
untimed scope reads never submit a Maintenance/TTL proposal. Decoded reopening
claims are validated against the same fixed ledger rules and grant no capability.

Terminal completion is `Applied(ScopeBatchOutcome)`, `Cancelled` or
`NotApplied(proof)`. Only Applied and Cancelled occupy a retained lane receipt.

Each admitted execution owns one shared coordinator context, supplied to every
store/client handle, including reconnects. Factories reuse that context rather
than seed new per-handle counters from a view; no mutex spans a network wait.
Apply still arbitrates competing exact lane requests independently. A process
restart requires authority succession, not a fresh local lane counter under the
predecessor's stamp.

Lane 7 is reserved for trusted established Emergency work; Normal, recovery,
Maintenance and classification/unverified work use lanes 0–6 when they need a
batch lane and cannot borrow it. Emergency work may also depend on a shared lane.
A lane number from a request grants no priority or authorization.
Scope authority controls use their separate path, never wait for a data lane,
and do not consume its receipt. SafetyControl cannot reserve a data lane.
Scheduling and transport preserve this separation through dispatch.
Capacity exhaustion suspends producers: eight lanes
bound outstanding work, not attaches or retained sessions. Waiting producers
do not allocate unbounded request copies.

The scheduler owns the arbitration policy and its `ScopeLane` primitive, as
specified in [RFC 024](024-scope-priority-scheduler.md). The coordinator composes
that guard with replay-lane ownership. Every shared lane grants in scheduler
class order, FIFO within each class.
For eligible data work the order is Emergency, EmergencyClassification, Normal,
then Maintenance; SafetyControl remains on its independent path. The oldest
waiter may be bypassed at most **eight** times; the next grant goes to it
regardless of class. Cancelled waiters leave no holes or stale inheritance.

For shared lanes 0–6, the acquisition order is scheduler resident reservation,
lane grant, running credit, then the current view and request construction.
A producer waiting for its class budget holds no shared lane, so it cannot
obstruct admitted work of another class. A shared-lane waiter holds its original
resident credit and fixed waiter metadata, with no built request. Exclusive
Emergency lane 7 takes its lane before its resident credit: queued producers
behind a stalled scope hold no Emergency credits needed by healthy scopes.
An explicit Emergency dependency on a shared lane retains resident-first order.
After both grants, read the current revision and all predicates, then seal the
request under a running credit or bounded blocking pool. This applies to the
whole-scope guard as well as selective read conditions; it does not remove
apply-time validation. The builder must not await another lane, peer or unrelated
request's outcome while holding these resources.

Every rebuilt attempt needs a fresh request ID, including a rebuild after
cancellation or a revision conflict. Only an exact retry of unchanged bytes
reuses its ID. Before dispatch, the coordinator refuses an ID found in the
build cut's retained receipts, any occupied local slot, or the last observed
stored receipt ID per lane. The coordinator retains those eight IDs across local
acknowledgement, so a same-ID completion acknowledged while the builder awaits
cannot escape the pre-dispatch check. Only Applied or Cancelled updates that
lane's cached ID; a NotApplied proof consumes no receipt. That refusal releases
the reservation without consuming a sequence or sending a command.

## Atomic apply and read dependencies

Each lane accepts only `sequence = committed_sequence + 1`, independently of
the other seven. Sequences use checked positive signed-range integers. The
scope's batch revision still advances on every terminal lane transition, but
ordinary disjoint batches do not compare it. Authority revision advances only
through the authority service, so a successful unrelated batch invalidates neither authority nor
another lane's reservation.

Apply first resolves retained exact attempts without effects; every new
transition then checks the current authority incarnation, retired-through floor,
Active execution, admission generation and authority revision. In the same
native/SQLite transaction, compare the lane, all child versions, claims,
counters and read conditions before publishing anything. Conflicts or authority
refusals change no child, claim, counter, birth, lane or revision field.

All 16 counters are rise-only between zero and `i64::MAX`. Apply refuses
`next < expected` with `InvalidRequest` before any effect; `next == expected` is
a read-only comparison of that counter. Equality does not exempt the rest of
the batch from lane, authority or predicate validation. Accounting that must
decrease belongs in child rows. Constructor and codec checks complement, never
replace, apply-time validation through the same checked constructor.

Add read-only conditions for exact live child `(key, birth, generation)` and
claim `(key, revision, owner)`, where owner is an exact child/birth or Released.
A missing, deleted or recreated child fails a live condition. Child conditions
are unique and disjoint from child mutations, which already compare versions;
claim conditions compare the same pre-state as claim mutations. All conditions
are namespace-bound. Absence/range dependencies require the whole-scope guard,
not an unversioned selective predicate. Retain a
combined limit of 64 distinct read/mutated children, 512 claim comparisons,
16 counter comparisons and the complete 2 MiB command bound.

A handoff obtains a coherent scan view, validates its logical relationship, and
names **every** dependency through mutations or read conditions: predecessor,
barrier, both locators and allocation owners. Apply compares read-only records
even when only the successor changes. SDK revisions protect the decoded fields;
the SDK does not interpret
sealed application payloads. Concurrent cleanup, delete/recreate, owner transfer
or barrier change therefore refuses the entire batch without a dummy predecessor
write. A caller unable to enumerate all dependencies uses the optional exact
whole-scope revision condition; every lane invalidates it when advancing.
A lane-local comparison or local lock alone never proves this handoff safe.

The whole-scope guard is for rare, low-concurrency operations; handoffs use the
complete selective read set. Its coordinator helper rereads and rebuilds only
after the preceding attempt is terminal, backing off from 25 ms up to 1 s on
revision conflicts. After 16 resolved conflict attempts it returns typed
`ScopeGuardStalled`; no submitted copy is abandoned and no uncertain lane is
freed. An Applied race returns its exact result. This bounds conflict churn,
not quorum recovery or ownership, and is neither an attach ceiling nor authority
to drop a session.

Read conditions cannot match recycled values: claim changes take the next
stable-scope batch revision, child creation takes the next stable-scope birth,
and child generation advances within a birth. Recreating identical payloads or
owners cannot recreate those identities. Physical reclamation and namespace
drop must never reset or reuse revision or birth floors.

Across lanes, Emergency may contend with Normal work on the same child or claim.
Its progress bound depends on the scheduler's class-ordered proposal admission, including
retries and forwarded requests; a reserved lane alone cannot provide it. The
three-voter hot-record contention gate below qualifies that composition.

The canonical request digest binds all those conditions, ordering, namespace
and complete worker stamp. The current voter/configuration admission stamp
stays outside it, allowing an exact request through a configuration change.
Conflict reports contain bounded opaque keys and counter indexes, no payloads.

## Cancellation, retry and restart

One lane has at most one unresolved attempt. Before submission, dropping a
reservation releases it without advancing a sequence. Once submission may have
occurred, dropping a future detaches the observer only. Ownership of the exact
request and lane transfers atomically to the SDK supervisor **before dispatch**.
A timeout, transport close or ordinary no-effect conflict cannot free that slot
while submitted copies might still arrive. To abandon an attempt, order
`CancelAttempt` for its original identity, under the same current authority,
before reusing the lane.

Apply and cancel race for the same next sequence. If apply wins, cancel returns
the retained `Applied` result and undoes nothing. If cancel wins, it advances
only the lane and scope batch revision, retains `Cancelled` for the original
attempt, and permanently prevents its child effects. This is an explicit
successful lane-state transition, not a side effect of a refused request.
Altered digests conflict; duplicate apply/cancel returns the same terminal
result. Cancellation is neither process closure nor authority retirement.
There is no extra reservation or acknowledgement commit on the successful
normal path.

Automatic retry keeps exact bytes and uses current configuration admission. An unresolved
holder also retains its original scheduler resident entitlement and shared-lane
guard under the supervisor; it releases only the bounded attempt's running
credit and retries through `start_in_lane`, never through a new scheduler
`reserve`.
Retained unresolved request bytes count in that resident budget.

A holder's next resolution attempt uses at least its original class and inherits
the highest class of any trusted waiter it blocks. `start_in_lane` observes
waiter arrivals and cancellations while awaiting a running credit. This applies
to exact retry, outcome lookup and cancellation needed to release the lane,
including predecessor work joined by a higher-class operation. The scheduler permits one
such holder per lane to use the inherited class's running credit while retaining
its original resident entitlement. It acquires no second resident slot or
payload. An already running attempt keeps its granted class through completion;
the next attempt observes current waiters. Inheritance changes trusted scheduling
metadata only, outside canonical request bytes, ID, sequence and digest; adapters
carry it through transport and proposal admission. It changes no authority
and does not preempt an accepted effect.

Unknown outcomes keep their lane occupied while other lanes proceed. Quorum
recovery resumes reconciliation without a timer clearing state. Known conflicts require
the supervisor to seal the attempt with cancellation or a permanent no-apply
proof before releasing it; the original caller need not survive. A colliding
same-lane receipt permanently excludes a different attempt at its own sequence
or exactly the next sequence: replacing that receipt would consume the attempted
sequence. The supervisor emits `NotApplied` with `IdempotencyConflict` in that
case. A collision on another lane, a future sequence gap or pruned history does
not supply this proof and remains visibly unresolved. Replanning rereads
predicates and chooses a fresh ID. No effect or success is published from uncertainty.

After succession, `reopen` reconciles the predecessor's frontiers before issuing
successors on those lanes. An applied result is delivered for recovery, not
submitted again under a new ID. A request proven not applied may be rebuilt
under current authority with a fresh ID after rereading its predicates. Completion delivery is
at least once. The execution's supervised reconciler acknowledges an exact
result only after reconciling durable child/intent state; dropping its original
caller cannot lose the result or acknowledge it. `reopen` feeds retained results
through that same bounded stream. A stale acknowledgement cannot free a later
attempt. Local acknowledgement adds no consensus command.
This is outcome recovery, not restoration of an unconfirmed retired cohort.
Reconciliation reads durable state and acknowledges the result before it needs
another batch on that lane; awaiting that batch first would wait on its own result.

`lane_status()` exposes the age of unresolved submitted work, its latest failure,
and the oldest unacknowledged terminal result on each lane. These are local
diagnostics; the coordinator does not publish a metrics service. Measure terminal
age from its first local observation
using monotonic process time; a receipt recovered after restart starts a new
observation interval, without claiming its pre-restart age. Redelivery preserves
the interval, and exact acknowledgement clears it. Age is diagnostic only: it
never expires a receipt, releases a lane or cancels an emergency session.
Unacknowledged results retain a bounded slot and lane guard even after all
producer handles disappear; the supervised reconciler must explicitly drain them.

## Exact outcomes and authority composition

Read the authority and stable-scope batch ledger from **one backend snapshot**
after the full-round linearizable read barrier, with configuration admission
revalidated. Two independent point reads are insufficient. Reads append no
application command and use no leader-lease clock assumption. Authorized
workers, observers and scope controllers may inspect the permitted namespace;
only the current worker may execute or cancel. Results never mint an effect
capability or authorize a predecessor's resubmission.

| Result | Required evidence and caller action |
| --- | --- |
| `Applied(outcome)` / `Cancelled` | Retained identity and digest match exactly; return the immutable terminal result. |
| `IdempotencyConflict` | A retained ID is presented with changed digest; do not reinterpret or replace it. |
| `NotApplied` | That exact sequence is terminal under another ID, or the sequence is above the retained frontier and the same read proves the request's authority permanently fenced. It cannot subsequently apply. |
| `NotRecorded` | Above the frontier with authority still eligible; absence does not resolve possible submission. Retain/retry or cancel. |
| `Pruned` | At or below the discarded-result floor; it cannot execute again, but its former outcome is not reconstructible from this ledger. Never translate this to not-applied. |
| `Unavailable` / `Corrupt` | No trusted complete read or inconsistent retained state; preserve uncertainty and expose the typed reason. |

The authority service's predecessor-resolution rule applies to the last **unresolved** attempt
in each lane. After committed Close/succession, a request above its frontier
with no result is known not applied, since the old stamp can never mutate again.
It does not apply to arbitrary historical IDs whose receipts were replaced.
Such `Pruned` queries use the consumer's durable operation state for recovery,
never blind re-execution. A compliant coordinator cannot prune an unresolved
frontier by issuing a later sequence.

## Retained format and integration

Authority, batch lanes and coherent scans use one shared scope record profile, **4**, with new request,
cancel, outcome and ledger codecs and one exact activation/apply digest.
Advertise it only when all three implementations and their joint checks are
present; an intermediate authority implementation is not advertised independently.
Different semantics cannot advertise the same digest. Old rows, logs, snapshots and
activation evidence return `FreshInstallationRequired` without changing bytes.
No migration, compatibility reader or parallel timed profile is supplied.

One reserved ledger per **stable scope** retains its batch revision, all 16
monotonic counter floors, child-birth floor and eight lane entries. Each entry
contains `sequence`, `discarded_through`, and at most one bounded terminal
receipt with the full attempt identity. Applied results include ordered child
revisions in request-mutation order and committed counter values; cancellation has no child results.
Receipts contain no sealed request payloads. For an unused lane both
numbers are zero and the receipt is absent; otherwise
`discarded_through = sequence - 1`. Replacing a receipt advances its floor
atomically. An older lane's outcome revision/counter
snapshot may lag the current ledger; another lane's progress never rewrites it.

The ledger row is capped at 20 KiB: eight complete maximum-identity receipts
need more than the former 16 KiB metadata budget. Other metadata limits stay
unchanged. Canonical reopen is capped at 24 KiB, covering the complete ledger
and authority claims. Request, attempt, outcome, receipt, lookup and reopen
codecs reject trailing bytes, noncanonical encodings and invalid shapes before
use; vector counts are bounded before allocation. These limits and the new lane,
read-condition and cancellation semantics enter the shared activation digest.

In this profile, initial authority admission creates the empty ledger in the
same transaction. A missing ledger under an existing authority is corruption,
not a fresh scope. Selection, namespace drop, ordinary receipt pruning,
compaction, reopen and snapshot installation never erase or lower any of these
floors. Child/claim keys remain incarnation-bound; lane sequences never reset
even when an incarnation changes. Preserve and validate these facts through
native publication/cold reconstruction and SQLite snapshot replacement before
exposing recovered state. Equal sequence/revision requires identical retained
receipt bytes; floor omission or regression refuses publication.

The shared apply path validates authority, batch predicates, reserved codecs and
monotone floors together. Coherent scans consume the revision and read conditions
without taking over lane state. Profile activation and exact-voter continuation
remain mandatory. Arithmetic
exhaustion and corruption never wrap/reset a floor; management stays available.
Ordinary unavailability recovers automatically. No cleanup on another node or
voluntary emergency-session interruption is part of this contract.

## Verification before implementation acceptance

Write deterministic failing regressions, then remove each guard independently
to demonstrate that its test detects the mutation:

- Two disjoint lanes from the same initial view both commit; overlapping child,
  claim or counter comparisons have one winner. A changed read-only predecessor,
  barrier, locator or allocation owner refuses every successor effect, including
  delete/recreate and cleanup races. Check the whole-scope fallback too.
- On every lane, including lane 7, refuse a decreasing counter with a typed
  error and byte-for-byte unchanged child/claim/checkpoint state. Equal compares
  succeed without changing the counter; stale expected values conflict. Repeat
  after compaction, cold reopen and snapshot install. Mutate constructor/codec
  and apply guards independently so a forged decreasing request cannot bypass
  the planner's check.
- Force 16 resolved whole-scope revision conflicts under ongoing lane traffic:
  the helper backs off and returns `ScopeGuardStalled`, with no outstanding
  submitted copy discarded. An apply/cancel race still returns Applied exactly.
  Recreate an identical child/claim payload and prove old read conditions fail;
  repeat across namespace reclamation and snapshot recovery without floor reuse.
- Exercise all eight lanes, independent progress and Emergency service under
  saturated Normal/recovery work. Race handles and competing raw requests; cancel
  waiters, prepared work, submitted work and duplicate apply/cancel in both orders.
  Cancel one attempt without releasing or overwriting another lane's receipt.
- Refuse retained and in-flight request-ID reuse before dispatch, including on
  the reserved Emergency lane. Resolve permanent same-lane collisions without
  a restart; preserve uncertainty for cross-lane collisions, sequence gaps and
  previously applied pruned requests. A guarded rebuild must choose a fresh ID.
- Saturate a lower class's resident budget and queue more producers. They must
  hold no shared lanes against admitted Normal or Emergency dependencies.
- On a shared lane, verify class order and FIFO, then continuous higher-class
  arrivals: the oldest lower-class waiter is bypassed at most eight times and
  receives the next grant. Cancel waiters at the grant boundary. Assert no
  predicate read or request construction occurs before the grant; queued work
  reads the revision produced by the preceding holder.
- Hold a Normal attempt with an unknown outcome and saturate Normal credits.
  An Emergency waiter must boost its resolution without draining the Normal
  FIFO. Change/cancel waiters while the holder awaits a running credit; verify
  effective class, exact byte/digest identity and single-credit accounting.
  Observer cancellation must preserve the guard and retry entitlement. Restore
  quorum with all lanes occupied and new producers waiting; holders must resolve
  without re-reserving resident slots. Mutations removing class order, bypass,
  inheritance, post-grant construction or retained entitlement must fail these
  tests. Classification traffic must not consume lane 7.
- On a real three-voter store, contend one hot allocation-page child from
  saturated Normal lanes and an Emergency handoff on lane 7, entering through
  a follower. Under class-ordered admission and inherited retry, require the
  Emergency batch to commit within a fixed round bound derived from the fixture's
  admitted Normal work. Removing class propagation/admission priority must make
  the test fail; lane reservation alone does not qualify this bound.
- Delay the supervised reconciler's acknowledgement and observe increasing
  unacknowledged-result age for that lane. Redelivery keeps its start, a stale
  acknowledgement changes nothing, and only the exact acknowledgement clears it.
  Reopen starts a new observation interval; advancing time never frees the lane.
- Lose replies before/after apply and cancellation; crash the caller and leader,
  reopen, and recover the same result with one apply. Close/succeed between
  submit and outcome read; pause old commands until after the read. Exercise
  every lookup row above,
  especially `Pruned` versus `NotApplied` and mixed-cut reads.
- Advance other lanes/counters without altering an older exact outcome. Cross
  namespace selection/drop, pruning, compaction, native/SQLite cold reopen and
  snapshot install; reject missing/regressed floors, equal-sequence alteration,
  higher batch revision hiding a lower lane floor, malformed bounds, overflow
  and prior formats while preserving bytes. Altering only an ID, namespace,
  stamp or read condition must defeat exact retry, not change its result.
- Retain authority prepared-before-fence/ordered-after-fence negatives and the
  election/continuation cases. Run real three-process lost-reply/restart histories
  and the repository's final gates after focused tests on both backends.
  Scheduling and transport integration must prove composed priority; local
  arbitration alone cannot.

Public activation requires the combined implementation, mutation evidence,
independent review and the matching consumer pin.
