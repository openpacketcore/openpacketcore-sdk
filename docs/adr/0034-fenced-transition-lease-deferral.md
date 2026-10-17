# ADR 0034: Durable lease-contention deferral

## Status

Accepted contract. Implementation validation is pending.

## Decision

Stores created with `FencedTransitionV2Profile::V2WithLeaseDeferral` extend
the [void profile](0029-fenced-transition-void.md) with a durable nonterminal
binding for an acquire-and-mutate request refused by a live predecessor lease.
The original `V2` and `V2WithVoid` profiles retain terminal `LeaseHeld` receipts.
The new immutable profile has its own digest, checked by every voter and every
durable reader. Crossing profiles requires a fresh install.

The first deferral binds the complete 56-byte request identity and sealed body
to one existing history ordinal. Further refusals use that binding without
allocating a request identity, epoch, attempt credit, history entry or caller
journal row. Repeated refusals advance consensus logical time but do not
advance the application sequence or watch sequence. They are distinct from
an unknown outcome: they conclusively report no business effect for that
committed attempt while preserving the original request's ability to execute.

An exact subsequent submission atomically rechecks the original expected
fence and generation and the current lease. A renewed predecessor lease keeps
the request deferred. A newer owner or changed generation produces the
ordinary terminal fencing or conflict result. An available lease permits
exactly one acquisition and mutation. Either terminal outcome replaces the
pending response at the same ordinal; later submissions replay it. A void
can likewise replace pending with a terminal no-effect receipt. It never
acquires a lease or mutates a session.

## History and persistence

The pending response uses codec error tag 27 and reserves
`9999-12-31T23:59:59.999999999Z` as its retention marker. The marker and typed
response must agree; a response-free pending marker is corrupt. The response
retains the actual consensus time at which deferral first bound. Pending work
never expires or compacts, even at the clock horizon. If terminal retention
cannot be represented, execution preserves pending and returns unknown.

Pending work may outlive epoch closure. Receipt lookup precedes active-epoch
and capacity checks, so that exact request can finish while new work remains
bounded by the existing history limits. Retirement cannot pass an epoch with
pending work. Resolving it starts the ordinary 24-hour terminal retention
window. Because completion can change retention out of ordinal order, the new
profile uses the maximum retention across the epoch, with pending counted
separately in the native index. Completion removes the pending pin; it cannot
leave the maximum timestamp cached forever.

SQLite, native images, generation bases and deltas, cold receipt reads, and
offline recovery retain and validate the selected profile. The one permitted
retained-row replacement is exact pending-to-terminal with a nonregressing
response time. Cold metadata includes the pending response's actual time and
checks it against the decoded response. A concurrent read can refresh that
one terminal successor; it cannot refresh back to pending or repeatedly
replace terminal receipts. No migration or alternate-format fallback exists.

Apply and checkpoint grouping do not alter those decisions. A terminal
deadline preserves its exact resolution time even after the response expires.
Validation checks that time against the pending binding and the captured
interval before evaluating retirement. A deletion in this profile carries
its original before-row hash, full ID, ordinal and final retention deadline;
replay validates that witness before removing the row. Remaining pending
rows still block retirement. This deletion vocabulary is part of the profile
digest, so crossing from an earlier experimental profile requires a fresh
install and its stored profile is refused.

## Membership and ordered application

Initial history activation still requires epoch one. After initialization,
the new profile's activation certificate proves the exact current membership
scope, voter set and profile independently of the command's request epoch.
It grants no business authority. Ordered application separately enforces
retired floors, body binding, active-epoch admission, capacity, retention,
outer caller authority and business fencing.

Append-time membership projection validates the request and exact activation
certificate and advances logical time. It does not predict the business
outcome or history mutations of unapplied commands: a pending receipt can
resolve based on earlier ordered business changes. This separation lets a
lagging follower admit a valid committed sequence without inferring lease
state from its older materialized history. The original profiles keep their
existing projection rules. New-profile batches evaluate ordered singleton
commands and their application sequences and digests within one atomic
transaction, retaining each original identity and authority envelope.

## Consumer recovery and lifetime

The singleton wire response `FencedTransitionV2Deferred` and status
`LeaseDeferred` carry the complete request ID. Clients match all 56 bytes and
require an acquire request before accepting deferral. A raw uncorrelated error
is neither a pre-dispatch rejection nor proof of a recorded terminal outcome.
The facade returns `FencedTransitionExecuteError::LeaseDeferred`, keeps its
sealed journal row, and makes that handle receipt-only. Status loops return
deferral immediately without making the row releasable.

`resume_deferred_fenced_transition` authenticates the retained row and reads
fresh authoritative status under a new caller budget. Only a correlated
deferral yields a new affine handle for that same sealed request. It does not
prepare or seal again, call a key provider, or add a row. The returned handle
must pass current execution admission and cannot abandon a binding. Recovery
handles remain status-only. Unknown outcomes, unavailable reads, `NotFound`,
and local absence never authorize dispatch. A later affirmative deferral may
resolve earlier ambiguity and permit explicit resumption.

Owned journals serialize resumption against reclamation and the previous
call. A live unknown call must end or reach its deadline before a replacement
can register. A known deferral allows explicit resume while protecting the
live caller from void until its deadline or drop. Replacement disables the
previous call's dispatch guard. An inherited row can resume after the same
fresh status proof. Process exit releases the existing ownership lock;
restart needs no new identity, manual cleanup, or journal repair. Abandoned
pending work remains eligible for consensus void under the existing owned
journal lifetime rules. Terminal receipts are released normally, making the
bounded journal capacity reusable.

## Validation scope

The acceptance cases cover sixteen refusals without growth, one completion
after store-clock expiry, caller restart, predecessor renewal and newer-owner
races, an interrupted completion followed by unavailable or absent status,
and repeated release and reuse. Additional tests cover wire correlation,
profile isolation, pending retirement pins, grouped expiry and retirement,
reclaimed resolution witnesses, cold persistence, and caller
lifetime exclusion. These are synthetic SDK contracts; they establish no
deployment, live traffic, continuity or performance qualification.
