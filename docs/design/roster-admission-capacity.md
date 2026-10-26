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
An owned local-leader lane observes the existing ordered reclaim and terminal
indexes and proposes `AdvanceLogicalTime` only when a bounded turn is eligible.
It refreshes unknown occupancy, wakes on leadership changes, and joins before
shutdown handoff. A successful turn keeps its base cadence even if concurrent
terminal completions mask progress in the occupancy gauges.
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
quotas are bypassed for authenticated emergency admission. Terminal completion
uses its existing admission reservation and bypasses those quotas for both
classes; its compact command uses the safety-control transport class, and all
signature, binding and authority checks remain mandatory. Ordinary work stops
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
V2 admissions and terminal records at a fixed logical time. It writes a native
generation in bounded batches using the production verified-append and cold
relocation path, then writes a complete base, drops the resident state and old
generation, reopens every authenticated carrier and admits one additional
roster. This keeps the existing verifier-memory budget while preserving every
retained row. The test neither advances retention nor deletes history.
Its optimized, isolated CI profile keeps the full boundary affordable; the
ordinary smoke test exercises the same path with three records.

Profile digest computation depends only on compiled protocol descriptors and
domain constants. Memoize each public V1/V2 digest once per process, preserving
every input, the frozen known-answer digests and all per-carrier validation.
Parameterized digest helpers remain uncached so descriptor-mutation checks
still exercise each input. The history proof uses test O3 with debug assertions
and overflow checks enabled, and reports stage timings without changing the
fixed history count, logical time, persistence operations or assertions.
