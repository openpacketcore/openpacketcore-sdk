# Roster admission capacity

Design for [SDK #1307](https://github.com/openpacketcore/openpacketcore-sdk/issues/1307).
Baseline: `601343e14037794aab7dbca6dceef9c5e6c76c97`.

## Decision

Completed work must not consume an operation quota. Remove the 131,072 limits
on live-plus-retained rows, durable bindings, partition floors and retirement
cursors from admission and every reopen, snapshot and recovery validator.
Their counters remain exact accounting, not admission limits. Do not replace
the limit with a larger number or a retry-count ceiling.

Bound ordinary capacity by current live work and retained bytes. Keep the 1,024
ordinary live threshold and the existing roster-only logical byte budget, including
the peak terminal reservation made at admission. Terminalization and release
must not need a new ordinary admission slot. Every restored row still needs
canonical, authority, uniqueness, floor, horizon and exact-witness validation;
stream validation and charge accounting bound allocation before publication.

The minimal change retains the current 24-hour recovery-evidence policy.
It ceases to imply a fixed number of completions in that interval. Existing
bounded maintenance releases retained bytes and the final partition metadata.
An eligible oldest tombstone prefix is retired before newer rows are reclaimed;
one retirement command spans admission epochs up to the existing 1,024-row
bound. Each partition receives one floor/cursor action. Its floor advances only
when no binding survives through the greatest selected epoch; otherwise both
floor and cursor remain unchanged. Both engines check the activated policy
before maintenance writes. SQLite makes a separate readiness decision for each
profile, after checking the exact layout and before either profile writes:

| Profile state | Maintenance decision |
| --- | --- |
| Malformed layout or namespace | Return the existing validation error. |
| No rows and no namespace | Nothing to maintain. |
| Current-scope roster certificate with the compiled policy, in a settled scope | Maintain this profile. |
| Foreign roster-policy digest or stale certificate scope | Reject before any maintenance write. |
| Missing certificate, current-scope generic fenced-transition certificate, inactive layout, or pending/unsettled scope | Defer this profile successfully without changing its rows. |

Both certificates are checked before either ready profile mutates rows or the
shared witness. Thus a deferred profile cannot hide a foreign policy in the
other profile. A membership cutover may clear a certificate while retaining
history; unrelated committed apply and logical-time advances still succeed.
Reclaim selects only ready profiles, with the existing retention and batch
bounds. Retirement keeps the global terminal order across both profiles and
stops at any deferred binding, including a tombstone. Its floor checks still
count every surviving binding in both profiles, so a ready profile advances
only where the shared floors and terminal horizon permit. Deferred history is
never authorized by a fabricated certificate.

Retirement creates no tombstones, so both
phases progress under continuous arrivals. The leader runs at most two bounded commands
per maintenance tick,
without changing the retention boundary or either phase's batch limit.
An owned local-leader lane observes the existing ordered reclaim and terminal
indexes and proposes `AdvanceLogicalTime` only when a bounded turn is eligible.
It refreshes unknown occupancy, wakes on leadership changes, and joins before
shutdown handoff. A successful turn keeps its base cadence even if concurrent
terminal completions mask progress in the occupancy gauges. Proposal service time
counts toward the one-second tick; a slow turn coalesces missed ticks rather than
adding another full idle interval or replaying a burst of missed turns. Failed
observations retain the existing bounded retry delay. Shutdown starts its automatic
handoff deadline before joining maintenance, so that join cannot restart the budget
reserved for handoff and consume the final engine/storage drain interval.
The signed arrival measurement makes ten completions due at each absolute
one-second boundary for 180 seconds, independently of maintenance completion.
It runs the real native and SQLite maintenance lanes with their production wait
and cadence. Every boundary records due and tombstone backlogs, including while
service is in flight, followed by another original operation-budget observation
window. Peaks, boundary lateness and remaining backlog describe that host run;
they are not timing assertions. The deterministic proofs below are the gates.

A separate paused-time proof drives the production loop and its default sleep
with explicit proposal-completion gates. Its conditional bound assumes a healthy
lane, one partition with distinct admission epochs, two phases per turn, at most
1.25 seconds per phase and at most 0.25 seconds of dispatch jitter per turn.
Because successful service consumes the one-second tick and overruns coalesce,
reclaim snapshots are at most `max(1, 2 * 1.25) + 0.25 = 2.75` seconds apart.
An arrival just after a snapshot waits at most another 1.25 seconds for the next
reclaim to commit: four seconds, or 40 rows at ten per second. Retirement finishes
before another reclaim and holds at most the three buckets between snapshots.
The initial tick plus jitter plus service is also below four seconds. The proof
samples all 180 boundaries before coincident completions, and after each
completion. A six-second-service negative control breaches the same bound before
the first proposal completes. There are no retries, authority changes or deferred-profile barriers in this
model. The service assumptions are not guaranteed by the ten-second operation
deadline; the real-backend measurement reports the resulting backlog under
physical I/O.

Paused-time tests also drive the production wait's metrics and stop receivers.
Commit and heartbeat publications every 100 milliseconds cannot restart its
one-second deadline. Leader/term changes wake it early, zero delay returns
without advancing time, and shutdown returns false.

Additional controlled-turn tests deliberately pause arrivals until each real
store finishes one supplied turn. They require exact reclamation of ten due rows,
retirement across distinct epochs, and at most two commands per turn. They make
no arrival-rate or physical latency claim. A separate work comparison seeds
1,800 and 18,000 signed retained rows, then measures ten turns of ten due rows
at each size. It requires identical work in corresponding maintenance turns:
native index entries visited and carriers hydrated, or SQLite VM instructions.
Each backend uses its real signed append, commit and apply path; the separate
controlled-turn tests cover replication on three voters. Both histories retain
young rows throughout, so the comparison holds partition closure behavior constant.
This covers leader eligibility reads and maintenance selection and mutation;
periodic checkpoint publication and unrelated executor delays remain part of
the physical measurement.
All tests retain the retention boundary and command batch limits.

Earlier reclamation is a separate semantic choice: a terminal commit alone
does not prove that every external recovery obligation is settled. Do not
invent a settlement acknowledgement or erase unresolved evidence to make a
capacity test pass.

## Emergency admission

Every admission capacity class must distinguish ordinary and emergency work.
Carry that class in the authenticated immutable admission through the client,
transport, consensus command and reservation. It cannot be a process-local
queue hint: ordinary traffic from another client must not consume emergency
headroom in the shared ledger.

Emergency work bypasses admission policy limits for live reservations,
retained history and aggregate bytes, and any local admission-capacity limit
on the same path, including local authority reservations and global/per-scope
provider and publication scheduling. Consensus proposal and forwarding policy
quotas are bypassed for authenticated emergency admissions and completions,
which travel as Emergency. Ordinary completions are metered as Normal. Every
completion uses its existing admission reservation without acquiring a new
slot. The signed terminal body and frame bind its class; apply rejects a class
mismatch, including a replay after compaction. Signature, binding and authority
checks remain mandatory. Ordinary work stops
below physical capacity. A finite
emergency reserve alone is insufficient if exhausting it would cause another
capacity refusal or wait; emergency admission must still use available
physical resources. Capacity never becomes an emergency deadline, queue
expiry or refusal. Physical resource or quorum failure remains a real failure;
authority, binding, corruption and checked-representation validation remain
mandatory. Writer serialization that protects accepted effects is a separate
correctness requirement. The owning consumer prioritizes emergency work when
its writer opens; the SDK scheduler itself owns no waiting queue.

The durable accounting and every reopen/restore validator must accept valid
emergency occupancy above ordinary thresholds and preserve the capacity
reserved for its completion. Qualify each admission-capacity class with a
deterministic RED: fill the ordinary share from multiple clients, then require
immediate emergency admission without a capacity wait or failure. Preserve
ordinary waiting and all authority/ambiguity controls.

## Backpressure and authority

An ordinary admission waits on a conclusive live/byte-capacity response and
retries the identical immutable request with paced, bounded work. It retains
the original lease/deadline; waiting cannot mint authority or extend that
budget. Capacity retry delay grows from 25 ms to a one-second ceiling with
bounded jitter and is always clamped to the original deadline. The next retry
is scheduled within that ceiling after a conclusive capacity rejection. The
waiting future owns its state, without an unbounded shared queue, detached task
or new provider dispatch. Transport ambiguity, cancellation
after transmission and non-capacity rejection retain their existing recovery
rules. Only a conclusive live/byte capacity verdict permits this internal retry.
The retained `HistoryFull` wire verdict covers irreversible epoch/floor
rejection after count quotas are removed and is never treated as transient.
Terminal-read guards cannot classify a request until authenticated readback;
they therefore have no policy count quota for either class and are reclaimed
when the owning read completes or is cancelled.

The narrowed #1306 contract stays independent: authenticated absent recovery
is read-only, and exact provider closure resumes an existing sealed live
obligation. This change adds no absent-slot discharge, durable acknowledgement,
retirement witness or provider execution authority. Live-admission retirement
after provider loss remains #1298.

## Compatibility and evidence

Capacity semantics are installation contract data. Preserve the frozen ordinary
V1 payload and profile digest, but bind the revised shared capacity-policy
commitment into V1 activation authority and the V2 activation descriptor. The
new policy supersedes the historical quota fields in the frozen V1 descriptor.
Old activation authority cannot authorize the new policy; document and test the
resulting fresh-installation boundary, with no mixed-peer or old-snapshot reuse.

Represent emergency class with a distinct canonical admission-frame discriminator
and class-bound admission commitment. The ordinary frame and field layout stay
unchanged; the emergency frame uses the same bounded payload. Ingress signs the
whole capsule, and consensus, stored reservations, exact readback and provider
proofs retain the class-bound commitment. The trusted consumer selects the class
before the first attempt; it cannot be changed on a pending input. Decode/restore
must preserve it, and a class substitution conflicts with the original binding.
This applies to both present- and absent-predecessor admission. Class selection
never bypasses authority, scope, business reservation or effect serialization.

First add a deterministic RED at the real 131,072 boundary and a controlled
capacity wait/release RED. Then implement and prove progress beyond that
boundary at unchanged logical time, bounded live admission, reserved terminal
completion, cancellation/ambiguity behavior and snapshot/reopen continuity.
Preserve existing tests and assertions; obsolete quota expectations must be
explicitly converted into checks of the replacement resource invariant,
without removing corruption, authority or lifecycle assertions.

The [store cap inventory](store-cumulative-cap-inventory.md) records related
limits separately so this change does not silently expand into other protocols.

The sustained-history regression uses 131,073 independently signed, one-member
V2 admissions and terminal records at a fixed logical time. It retains every roster
carrier. The fixture purges duplicate Raft command payloads after supplying their
exact applied snapshot frontier, while a single owned writer persists temporary
carrier extents with production verified append, readback and relocation. At most
one 1,024-row capture overlaps the next working batch. These temporary extents are
not selected recovery catalogs: a complete final base remains the cold-reopen
boundary. The populated image is fully validated, all process-local owners and
old extents are dropped, every carrier is reopened and validated, and one additional
roster is admitted, completed and fully validated. Independent immutable validation
passes run concurrently; none is omitted. The proof reports both temporary and
final file bytes at their simultaneous peak. It never advances retention, deletes
a roster row, expands the verifier budget or changes the literal history boundary.
The ordinary three-row smoke test follows the same path.

Profile digest computation depends only on compiled protocol descriptors and
domain constants. Memoize each public V1/V2 digest once per process, preserving
every input, the frozen known-answer digests and all per-carrier validation.
Parameterized digest helpers remain uncached so descriptor-mutation checks
still exercise each input. The history proof uses test O3 with debug assertions
and overflow checks enabled, and reports stage timings. Frame encoding retains one
fully authenticated hydration while counting and writing that frame; readback and
cold admission still perform their complete independent validation.
