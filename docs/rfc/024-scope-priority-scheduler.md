# RFC 024: Scope work priorities and backpressure

Status: implemented scheduler and store-admission contract for scope child records.
Source basis: SDK `4df2cc67c1112b9b6784bc6fd90f0f85022f5b6b`.
The scheduler and store-admission implementation lives in `opc-session-store`.
Composed lane and authenticated-transport qualification remain separate.

## Contract and boundaries

Keep retirement, handoff and emergency work serviceable while ordinary writes
or recovery scans saturate their queues. Capacity produces backpressure, never
an attach rejection, session-count ceiling or lifetime admission quota. Scheduling
confers no authority: committed incarnation, execution, generation and exact
request checks still govern every effect. No renewal, expiry priority, timed
ownership or takeover enters this contract. The untimed authority slice replaces
[RFC 022](022-scope-leases.md#atomic-child-batches)'s timed authority checks.

Use separate bounded resident and running credits. A shared priority queue cannot
isolate non-preemptible proposals already running. Every shared bottleneck must
provide class reservations or bounded class arbitration before composed class
isolation can be claimed. Two existing read stages remain class-unaware: the
leader's 64-slot FIFO linearizable-read barrier and each voter's single logical
read-time supervisor. The latter emits one coalesced fence round at a time for
at most 64 live callers across active and waiting cohorts. These bounds prevent
unbounded read work; they do not provide per-class arbitration. Their downstream
read-fence proposals use Normal for the current unclassified read APIs, not the
Maintenance pool. Reserved capacity costs utilization when idle; an active effect
is never cancelled for a higher class.
Raft-internal append, vote, heartbeat and snapshot installation bypass this
application scheduler. Controller-channel management rate limits do not limit
worker sessions.

## API and budgets

The new `opc_session_store::scope_scheduler` module has no store, activation,
clock, retry ledger or payload dependency. Its interfaces are:

```text
#[non_exhaustive]
ScopeWorkClass = SafetyControl | Emergency | EmergencyClassification |
                 Normal | Maintenance
ClassBudget { queued: usize, running: usize }
ScopeSchedulerBudgets { safety_control, emergency, emergency_classification,
                        normal, maintenance: ClassBudget }
ScopeSchedulerOwner::new(budgets) -> Result<ScopeSchedulerOwner, ConfigError>
owner.scheduler() -> ScopeScheduler             // clonable producer
scheduler.reserve(scope_key, class).await -> Result<ScopeWorkReservation, ScopeSchedulerError>
reservation.start().await -> Result<ScopeWorkPermit, ScopeWorkStartError>
reservation.start_in_lane(&lane_guard).await -> Result<ScopeWorkPermit, ScopeWorkStartError>
start_error.error() -> ScopeSchedulerError
start_error.into_reservation() -> ScopeWorkReservation // same entitlement
permit.finish_unknown() -> ScopeWorkReservation // retains resident entitlement
scheduler.snapshot() -> per-class counts
owner.quiesce()                                  // stop new non-control work
owner.close()                                    // explicit final shutdown
ScopeLane::new(scope_key) -> ScopeLane
lane.acquire(class).await -> Result<ScopeLaneGuard, ScopeSchedulerError>
lane_guard.effective_class(reservation_class) -> ScopeWorkClass
```

`queued` bounds all resident descriptors, including preparation, running and
retained unresolved work. A permit retains its resident credit. A retry releases
only its running credit and rejoins the ready FIFO without calling `reserve`.
Thus a full resident queue cannot prevent its unresolved occupants resolving.
Default queued/running budgets are 8/1 SafetyControl, 16/2 established Emergency,
8/1 EmergencyClassification, 24/8 Normal and 8/1 Maintenance. Ordinary work keeps
its existing eight running proposal credits; the five reserved running credits
are additional, for a total bound of thirteen per proposal or outbound pool.
These are concurrent resource bounds, never counts of admitted sessions. There
is no borrowing between classes.

Configuration rejects zero values, `queued < running`, and values beyond Tokio's
semaphore limit. Both the named budget struct and class enum are non-exhaustive;
configure a class with `ScopeSchedulerBudgets::default().with_budget(class, budget)`.
`ScopeSchedulerError::Closed` reports explicit shutdown; `ScopeMismatch` refuses
a reservation used with another scope's lane. `SafetyControlOnDataLane` refuses
control work before it joins a data lane or starts beneath a data-lane guard.
A failed `start` or `start_in_lane` returns `ScopeWorkStartError`, which retains
the original reservation even on close or a composition error. Its supervising
owner recovers that entitlement for exact resolution; dropping the error must
be an explicit abandonment decision. Capacity is never an error.
Each class uses fair resident and running semaphores. A scope first acquires its
own cap, `ceil(class budget / 2)`, then the class-wide credit. This leaves capacity
for another scope when the budget exceeds one; FIFO arbitration provides progress
when it is one. FIFO applies to both reserve and start at each arbitration point;
requests exceeding one scope's cap cannot occupy the global FIFO ahead of another
scope. The store's aggregate non-scope traffic uses a private internal key exempt
from this per-scope reduction; it can use all eight ordinary credits. Public keys,
including an all-zero key, cannot claim that exemption. Inactive scope entries
are reclaimed. A poisoned metadata mutex is recovered;
no lock is held across an await and no dispatcher task is needed.

Create one owner per shared dispatch pool; all producers use its clones. Scope
keys come from the authenticated stable scope, never a per-request random value.
Reservations, permits and the owner are affine and non-serializable. Only the
owner may quiesce or close. Producer clones cannot shut down the shared pool.

## Classification and trusted sources

| Operation | Class | Trusted source |
| :--- | :--- | :--- |
| Untimed `AdmitInitial`, `SucceedClosed`, `Close`; retirement and selection | SafetyControl | Typed authority operation plus its authorized worker/controller role; scheduling never substitutes for the apply fence. |
| Voter replacement, replacement status, bounded candidate pull and catch-up | SafetyControl | Authenticated controller/candidate role and exact replacement operation; large transfers yield between bounded chunks. |
| Transport liveness, candidate-key/channel proof and boot-ticket reads | SafetyControl for controller work; otherwise the corresponding worker class | Separate bounded proof/accept capacity and authenticated role. Unverified worker claims use EmergencyClassification. |
| Child mutations of established emergency sessions | Emergency | Authenticated admitted worker's declaration for its own scope, derived from trusted session state. |
| A bounded lookup to classify one pending request, or unverified emergency claim | EmergencyClassification | Authenticated adapter and bounded classification procedure. |
| Ordinary foreground child mutations, including attaches | Normal | Authenticated admitted worker's own-scope declaration. |
| Coherent restore paging, including its index/claim records | Normal | Typed bounded restore page for an admitted cohort; positively classified emergency work uses Emergency. |
| Observe paging (deferred), reclamation and background reconciliation | Maintenance | Typed bounded page/step, or authenticated own-scope declaration. |
| Logical-time read fences, including session reads, exact status and restore scans | The caller's read class; Normal at current unclassified read entry points, never Maintenance | Typed read purpose. Explicit record-expiry floors and history maintenance remain Maintenance. |
| Exact outcome lookup or predecessor work needed by a blocked operation | At least the resolved request's class, boosted to its highest trusted waiter | Retained exact request and shared-lane guard; no new request bytes or identity. |
| Bounded emergency-index discovery | EmergencyClassification, then Emergency after positive classification | Admitted scope and explicit discovery result. |
| Emergency census and hold reads needed for shutdown/handoff | SafetyControl | Typed authorized control procedure; no elapsed-time override of the hold. |

A voter cannot inspect sealed child values. It accepts Emergency,
EmergencyClassification, Normal or Maintenance metadata from an authenticated
admitted worker for that worker's scope only. A worker cannot request
SafetyControl on a child batch. Typed authority operations determine that class;
caller metadata does not grant a controller role. Store-internal housekeeping
uses Maintenance. Ordinary legacy mutations default to Normal.

Emergency is a property of the whole session, not a bearer's ARP. All procedures
on an established emergency session retain its class, including dedicated-bearer
changes, rekeys, detach and handover. See TS 24.302 §7.4.4 and TS 23.402
§4.5.7.2.1 and §4.5.7.2.4. Classification/unverified work cannot consume established
emergency credits. Classification has a bounded step count: explicit missing or
corrupt results terminate it (possibly scheduling Maintenance quarantine), never
retry forever as unknown. A transient unavailable result is distinct.

MPS/high-priority access is explicitly deferred: consumers do not yet identify
MPS sessions. This is a known gap against TS 23.402 §4.5.9.2 and TS 29.273
§7.1.2.1.4 and Annex D.2; parsing a priority attribute alone does not implement it.
The extensible API leaves room for an independently budgeted priority-access class.
Priority uses an explicit rank, independent of enum declaration order. Serialized
class tags are explicitly fixed at 0/1/2/3/4 for SafetyControl/Emergency/
EmergencyClassification/Normal/Maintenance. Unknown tags fail closed; a future
class receives a new tag without renumbering existing classes or tying its tag
to its scheduling rank.

## Shared lanes, inheritance and bounded waiting

The scheduler supplies the lane arbiter; the batch coordinator composes it with
replay ownership and exact outcome resolution. Obtain the class's resident
reservation **before** acquiring a shared lane. A producer blocked on its class
budget holds no shared lane. Exclusive Emergency lane 7 takes its lane before
its resident reservation, so queued producers behind a stalled scope cannot
consume all Emergency capacity across scopes. Emergency dependencies on shared
lanes still take their resident reservation first. After both grants, acquire a
running credit, then read the current revision and build the request. The builder
must not await another lane, peer, or unrelated request's outcome. One explicit
control exception is activation preflight: it retains a bounded SafetyControl
resident reservation across the read barrier and unanimous peer probe, without a
SafetyControl running credit. One running credit covers one bounded attempt/page,
including its reply; it does not span an indefinite retry loop or an idle reconciliation
wait. CPU-heavy sealing, digest and validation run under a running credit or a
bounded blocking pool.

A shared data lane grants established Emergency, then EmergencyClassification,
then Normal and Maintenance, FIFO within a class. SafetyControl never takes a
data lane: `ScopeLane::acquire` refuses it and typed authority operations use
their independent path. An oldest waiter may be bypassed
at most **eight** times; the next grant goes to it regardless of class. Cancelled
waiters leave no holes. The holder's resolution attempt inherits the highest
class of any trusted waiter it blocks, and never falls below its reservation's
original class. The guard's own acquisition class never raises an unrelated
reservation. `start_in_lane` observes changes while awaiting a credit. This is a bounded
reservation exception: one holder per lane may run using the inherited class's
running credit while retaining its original resident entitlement. It does not
borrow a resident slot, create another payload, preempt running work or change
canonical request bytes. A running attempt keeps its granted class to completion;
the next attempt observes current waiters.

Shared-lane waiters retain their original class's resident credit without
building a request. This trades cross-scope ordinary capacity for admission
priority: with the default budgets, two stalled scopes can each retain twelve
Normal credits, including queued producers, filling the global twenty-four.
Exclusive lane-7 waiters retain only lane-waiter metadata and no resident credit.
Unresolved holders keep their entitlement until exact resolution,
including during quiescence, and never reacquire resident capacity for retries.
Thus a full queue cannot deadlock recovery after quorum returns. An independent
Emergency replay lane remains unavailable to ordinary
traffic; SafetyControl is independent of child-batch lanes. The authority and
lane slices still own request validation, replay and cancellation after submission.

Partitioned credits have no meaningful inter-class dispatch order: each class
progresses on its own. Priority ordering applies at shared lanes. Progress assumes
bounded preparation/attempts, bounded upstream producers and a backend/executor
that progresses. It neither promises a wall-clock deadline nor manufactures
quorum or reorders an already appended Raft prefix.

## End-to-end composition and ownership

The scheduler also replaces both leader proposal-admission acquisitions in
[consensus/store.rs](../../crates/opc-session-store/src/consensus/store.rs)
with the class-aware pool. It retains permit ownership until the accepted
Openraft response resolves, even if the caller cancels or its attempt expires.
Each voter's outbound mutation admission is separately class-budgeted; forwarding
must not recreate one shared FIFO. Typed scope authority selects SafetyControl;
authenticated batch metadata survives forwarding outside the canonical digest.
Existing apply-authority rechecks remain after admission.
Activation reads retain bounded resident state without holding a running control
credit. A cold activation releases the topology read guard before waiting for
that credit, then reacquires the guard and revalidates its exact admission.

The transport slice must use separate connections/streams or reserved capacity
per class through send, receive, accept and proof verification. Put the declared
class in the authenticated frame header so reservation precedes the body read.
Shared credentials alone do not authorize a declaration. These obligations include
the pre-activation replacement/controller channel. A local scheduler cannot
qualify an external transport that serializes all traffic on one connection.

The scan slice yields bounded pages and holds no shared store/apply lock or
installation-blocking permit across a scheduler wait. A separately bounded
coherent view is an explicit retention exception: an admitted immutable native capture or
dedicated SQLite read transaction remains pinned between pages, including while
an accepted page waits for scheduling. Acquire its separate, scope-fair retention
reservation before opening the view; a waiter retains bounded ingress state but
no Normal execution credit. Each page acquires execution capacity before a short
native installation permit or database operation. Snapshot installation invalidates
the view epoch and cancels/drains bounded page work before releasing the view.
A small emergency index avoids waiting for a full restore scan. Joining or helping
a predecessor uses the waiting operation's inherited class.

The memory bound is the sum of resident budgets times maximum request bytes,
plus fixed metadata per bounded producer and replay lane. Running and retained
unresolved descriptors are already counted in the resident budgets. Waiting
state is O(1) per producer and contains no built request. Bound producers at an
upstream socket/scan/backpressure point; a task per waiter is allowed only within
that bound. The scheduler's own queue has no implicit timeout or capacity error.
Store proposal and outbound admission waits do share the operation's existing
absolute deadline. Expiry ends that attempt with `Unavailable` or
`BeforeTransmission`; the scope adapter reports unresolved work as `OutcomeUnknown`
and retains the exact operation for retry. These are liveness nudges, not attach
quotas, authority expiry, or proof that an earlier effect did not happen. Attempt
deadlines do not end ownership or the lifetime of exact unresolved work.

## Cancellation, shutdown, recovery and observation

Dropping an undispatched future/reservation returns its credits with no effect.
After dispatch, the service supervisor keeps the permit until definitive local
attempt completion. Observer cancellation cannot prove absence of an effect.
On an unknown result the supervisor retains exact bytes, lane ownership and the
resident entitlement; retries rejoin only the start queue.

The owner first stops producers and calls `quiesce`: new non-control reservations
and their waiters receive `ScopeSchedulerError::Closed`, while existing entitlements can finish
and retry. It resolves outcomes, commits the final SafetyControl `Close` or
succession, then calls `close` and joins supervised attempts. Final close also
wakes undispatched starts. It never cancels accepted effects. `ScopeSchedulerError::Closed`
means this invocation did not dispatch; an earlier attempt can remain unknown.
Voluntary shutdown is gated by the consumer's emergency hold before this sequence;
elapsed drain time cannot override it. Dropping a producer clone never closes it.

A crash loses volatile credits, not durable authority. A new process constructs
empty schedulers. It resolves the predecessor's uncertain writes through the
untimed authority slice's predecessor-resolution rule and the exact-outcome API;
it must not replay an old boot's request with a new boot's stamp. No manual queue
reset, node action or Pod replacement is needed to free volatile resources.

Snapshots contain per-class resident, running, reserve-waiting and start-waiting
counts. Resident includes running and unresolved entitlements; waiting counts
include callers blocked on either scope or global capacity. Running counts name
the effective class after inheritance. Debug and metrics contain neither scope
keys nor request, subscriber or payload labels. They confer no shedding authority.

## Format and verification

This RFC changes no command, checkpoint, snapshot, apply digest or durable format.
Adding class metadata to the private forwarding RPC **does change its wire
contract**: consensus transport/wire revision 6 rejects revision 5 at bootstrap.
Mixed versions fail closed and require a coordinated fresh installation,
not a compatibility reader. Authority/lane format changes have their own fresh
installation boundary. Later budget-only changes are process-local configuration.

Tests use explicit polls, barriers and notifications, with timeouts only as hang
guards. Cover both directions of class isolation, classification floods, FIFO and
scope fairness, concurrent producer counts well above every budget, cancellations
at every acquisition boundary, close versus quiesce, and exact credit accounting.
Fill a class while an unresolved holder retries; quorum restoration must make
progress. On a shared lane prove inheritance and the eight-bypass bound. Prove
that a producer cannot close the pool and final SafetyControl still starts after
quiescence. Verify that failed starts return the original entitlement, data lanes
refuse SafetyControl, and a guard cannot raise a reservation without a waiter.
Hold Maintenance while logical read fences complete; retain eight ordinary
non-scope proposals while reserved work progresses. Test redaction, frozen class
tags and configuration validation.

Use a real three-voter strictly durable store: hold Normal and Maintenance credits
on every voter and queue ordinary proposals; SafetyControl and Emergency entering
through a follower must commit before held ordinary proposals resolve. Preserve
accepted-proposal cancellation and authority-cutover tests. Freeze the preceding
wire shape and test missing/invalid class rejection. Mutations merging class pools,
removing inheritance/bypass, re-reserving unresolved work, closing control on
quiescence, releasing accepted permits early, dropping forwarding metadata,
acquiring global resident capacity before the scope cap, or allowing a declared
SafetyControl child batch at the leader must turn the corresponding tests red. Composed lane/transport and emergency-continuity
qualification remains with those integrations, followed by independent review and
hosted CI before merge.

The three-voter test uses the actual native durable store with in-process peers.
It does not qualify TLS connection/accept capacity. The existing
`RemoteSessionConsensusPeer` shares a two-connection pool; the transport slice
must partition that actual voter-to-leader hop as well as worker ingress before
claiming end-to-end isolation. Its adapter must carry the verified class through
connection selection and retain the private forward's required class field.
