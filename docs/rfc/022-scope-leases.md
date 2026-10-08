# Scope leases and atomic child batches, profile 3

Status: experimental scope authority, atomic child batches and activation continuity, slices 1–3 of issue #1134.

## Authority and admission

A stable scope identifies a consensus cluster, tenant, network function and
opaque slot. An execution additionally identifies an authenticated consumer,
an admitted incarnation, a workload identity, a process nonce and a monotonic
platform admission generation. Restarted
processes must use a new nonce. Platform admission remains outside the generic
store: the trusted admission policy verifies all these claims against the
authenticated connection and current platform selection. Generation numbers
are verified admission facts, not arbitrary caller-chosen fences. A controller
or an independently authenticated selected candidate may stage the selection.
Possession of a serialized execution or permit is not authentication.
Gate adapters accept the non-deserializable `CommittedScopePermit` returned by
`ScopeLeaseStore::grant`, then check their own current execution, generation
and time. Raw `ScopePermit` fields and read results cannot construct that token.

`ScopeLeaseStore` is a quorum-side service over a strictly durable
`ConsensusSessionStore`. It rejects asynchronous persistence. Scope checkpoints
contain authority metadata visible to apply, including execution claims and
deadlines; they contain neither credentials nor child session payloads. A transport adapter must supply its authenticated peer identity;
it must never copy that identity from a request body. This slice supplies the
service boundary, not a new consumer transport protocol or packet gate.

Constructing the service checks durable persistence and the immutable cluster
binding. Build `ScopeLeaseId` from the configured topology’s
`consensus_identity()`, which does not require a synchronous store probe.
`consumer_scope()` is a synchronous authority probe and may refuse while the
WAL owner is busy. Constructing an identifier grants no traffic authority and does not require an idle storage
reader. Each read and mutation separately checks current admission within its
deadline; constructing a handle never bypasses fencing.

Each request has a scope, random request ID, expected record revision, and one
operation: Select, Acquire, Renew, ResumeSameExecution or Release. Selection
and grant epochs only increase. Selection requires a strictly higher admitted
generation, an exact record revision, and proof that the old permit has expired
or been released. It cannot supersede an execution with a live permit. An
intervening renewal/resume defeats the expected-revision CAS. A committed
selection permanently forbids the previous selection's resume. Even a fresh
record revision cannot restage an old admission generation.

Acquire consumes one selection and increments the grant epoch. Renew and
same-execution resume preserve that epoch and replace the complete timed
permit. They require the exact current permit and unchanged selection. A
released selection cannot acquire again. No historical execution list is
needed: current selection, last granted selection and the grant floor retain
the evidence that an intervening owner or selection occurred.
For every mutation, the admission policy binds the authenticated connection
to its exact admitted execution; credentials shared across executions need
additional retained admission evidence, such as a connection-bound policy.
The service checks that execution against committed state. Copied permit
claims and a shared identity alone are insufficient. Renewal and resume can
use this retained binding without an external platform lookup on every renewal.

## Time and packet use

The profile fixes a healthy renewal interval `h = SCOPE_RENEWAL_INTERVAL`,
a permit grace `G = SCOPE_FORWARDING_GRACE`, and a separate exclusion guard
`SCOPE_CLOCK_GUARD`. A grant records immutable issuance, next-renewal, stop and
exclusion deadlines. The next renewal deadline is not recomputed when a reply
arrives. A delayed response or an exact retry never extends a deadline.

The service requires a trusted clock source reporting an interval containing
current time in a common time domain. The interval must include offset between
hosts, drift, suspend and sampling uncertainty, and be no wider than one second.
Unknown, inverted, overly wide or regressing bounds refuse a new operation.
There is deliberately no implementation which treats `SystemClock`,
`CLOCK_MONOTONIC`, or a caller's timestamp as proof of these bounds.

The permit's deadlines are:

```text
renew_by = issuance_upper + h
stop = issuance_upper + h + G
excluded_until = issuance_upper + h + G + guard
```

A gate stops when its current upper bound reaches `stop`. A successor waits
until its lower bound reaches `excluded_until`. Consequently, if both clock
intervals contain true time, the old execution has stopped before the successor
is admitted, including across a change of leader. Remote takeover without
graceful release follows `h + G + guard` from issuance, subject to the
successor's trusted lower bound reaching exclusion. If the clock provider loses
its bound, an enforcing gate must close. A kernel adapter must preserve this
rule while userspace is paused and across suspend; this module's `is_live_at`
helper is not kernel enforcement.

The packet-gate deadline formula is
`D = min(H, b0 + floor((S - U - J) * Q / (Q + d)))`, where `Q = 10^9`,
`b0` is the original sample/first-send BOOTTIME, `U` the common-time upper bound,
`S` the immutable stop, `J` the correlation/correction allowance, and `H` the
clock guarantee's horizon. When the permit's issuance upper bound supplies `U`,
the remaining interval `S - U` is `h + G`:

```text
D = min(H, b0 + floor((h + G - J) * Q / (Q + d)))
```

All durations in this formula use integer nanoseconds. Full-grace availability
needs both directions of the clock envelope and the correct renewal reference
point. Define `epsilon` as the issuance interval's excess above true time at its
sample, and `tau` as elapsed time from the original first send to that sample.
Then `renew_by` is `h + epsilon + tau` after true time at the original first send.
The interval-width bound gives `epsilon <= 1 s`; it does not bound `tau`.

For the qualified profile, tick adjustment is within ten percent, frequency
adjustment within 500 ppm, and the additional adjtime rate within 500 ppm.
These adjustments add in the
[kernel rate calculation](https://github.com/torvalds/linux/blob/v6.18/kernel/time/ntp.c),
so use the conservative combined bounds:

```text
r_min = 0.9 - 0.0005 - 0.0005 = 0.899
r_max = 1.1 + 0.0005 + 0.0005 = 1.101
d = ceil((1 / r_min - 1) * Q) = 112347053 ppb
```

The provider must additionally guarantee aggregate positive phase gain
`P <= 0.5 s` over the entire horizon: for elapsed time `t`,
`b(t) - b0 <= r_max * t + P`. The
[kernel phase limit](https://github.com/torvalds/linux/blob/v6.18/include/linux/timex.h)
is per offset update. It does not by itself prove this aggregate bound when
updates repeat. Qualification must bound their total, include all other
oscillator/domain errors, and retain the safe-side aggregate allowance
`J <= 1 s` for residual corrections and missing elapsed time. A per-update
bound or a synchronization-status flag is insufficient.

Let `B = floor((h + G - J) * Q / (Q + d))`. Provided `H` covers `b0 + B`,
the gate cannot close before elapsed time `(B - P) / r_max`. Its minimum
remaining forwarding interval after the actual `renew_by` is therefore:

```text
F_min = floor((B - P) / r_max) - h - epsilon - tau
F_min >= 60 s
G >= ((h + epsilon + tau + 60 s) * r_max + P) * (Q + d) / Q + J - h
```

With `h = J = epsilon = 1 s`, `P = 0.5 s`, and initially `tau = 0`, the
whole-second choice is:

```text
G >= (62 * 1.101 + 0.5) * 1.112347053 s
  >= 76.487208058386 s
smallest whole-second G = 77 s
G = 75 s: F_min = 58.785649369 s - tau
G = 76 s: F_min = 59.602179795 s - tau
G = 77 s: F_min = 60.418710222 s - tau
```

These results round both the BOOTTIME deadline and elapsed-time conversion
downward to nanoseconds. The full sixty-second guarantee therefore requires
`tau <= 0.418710222 s` under the stated worst-case interval and phase bounds.
A 400 ms transport qualification budget leaves at least 60.018710222 seconds.
The clock-provider and authenticated-transport slices must prove this sampling
budget together with the rate, aggregate phase and full-horizon bounds before
advertising the guarantee. Interval width alone cannot establish it. The
budget describes an already installed grant's deadline; a late initial reply
cannot supply traffic authority retroactively. Unbounded transport delay cannot
be covered by any finite fixed grace.

For the selected profile, `h + G` is 78 seconds and remote exclusion
`h + G + guard` is 79 seconds after issuance. The unrounded, zero-sampling-delay
lower bound would give about 78.49 seconds of remote exclusion; whole-second
grace rounding makes the implemented value 79 seconds. A remote successor still
waits for its trusted lower bound to reach that immutable exclusion deadline.

Sampling and reply delay are charged from the original `b0`; receipt and retry
never start a new lifetime. The separate exclusion guard is reserved for
post-gate queued packets and is not spent on clock error. A shorter horizon,
larger error/phase allowance or excessive sampling delay preserves the safety
rule by closing earlier, but does not meet the sixty-second availability
contract. Such a profile must not be advertised as qualified for that contract;
increasing the permit grace does not qualify a clock provider by itself.

A store outage does not alter a previously issued permit. The consumer can
retain existing traffic until its stop deadline, but changes still require
quorum commits. After expiry, explicit resume may reopen retained state only
for the exact execution and permit, without an intervening selection. A
process which lost its local state uses successor selection and acquisition.
An early Resume returns retryable `Held` while the lower clock bound has not
reached expiry, including the uncertainty window after Renew reports `Expired`.

## Graceful release and emergency sessions

For a voluntary stop, the consumer first honors any emergency-session hold,
then closes every data and control gate and confirms closure. Only then may
it construct `ScopeGateClosed` and submit Release. This acknowledgement is a
trusted effect-boundary assertion, not a kernel proof. After sending Release,
the consumer must never reopen the old permit, including after a lost reply.

Committed release permits a selected successor to acquire immediately. A
predecessor can release after a successor was selected. A crash before the
release commits preserves the original exclusion deadline. No node cleanup,
workload replacement or manual intervention is required by scope authority itself.
This primitive does not decide when an emergency session can be drained and
does not authorize an application to interrupt one for a voluntary restart.

## Consensus and stored format

Each operation is one `ScopeLease` consensus command. Admission uses the exact
current configuration and the committed apply path independently checks scope,
expected revision, execution, selection, permit and clock bounds. A live
membership transition changes request admission, not the stable scope. Existing
services and checkpoints can renew, release and select after the transition's
new voter set has inherited durable activation as described below.
If a command was stamped before the authority switch and applies afterward,
apply returns retryable `Unavailable` without changing the checkpoint. The
service resolves the retained request if possible, otherwise returns
`OutcomeUnknown`; the caller retries that exact request through current
admission. A configuration switch is not a platform admission refusal.

The authority row retains one fixed 4096-byte checkpoint per scope. Its body
starts with `OPSL` and version 2, unchanged in profile 3; length framing and zero
padding are checked exactly. The command outcome uses fixed-width hexadecimal encoding, which is
not encryption. Checkpoints live in dedicated reserved authority rows, outside
all ordinary request-receipt collections. Even deleting the ordinary receipt
collection cannot remove selection or grant floors. Each successful operation
replaces the same checkpoint; refused operations do not allocate receipts.
There is no per-scope mutation lease, per-operation ordinary receipt or watch
event. ReadIndex barriers issue no application command. Normal Raft log
retention and snapshot compaction still apply.

The checkpoint contains an apply-visible grant fence: exact stable scope,
selected execution, selection and grant epoch, current permit, and release
state. Renew and Resume replace deadlines while preserving the grant epoch.
Child batches compare this stable fence and the currently retained permit's
validity during apply. The per-renewal checkpoint revision is not a batch fence.

Initial activation, before the first `ScopeLease` or `ScopeBatch`, probes
**every voter** for the exact scope profile digest, under current configuration
admission. A separately committed activation certificate binds that digest to
the admitted identity and voter set. Apply checks the certificate again.
After activation, normal operations require a quorum; an unavailable minority
does not undo the established certificate. Before learner replication, joining
voters acknowledge the exact lease and batch profile through the authenticated
staged control path. The leader then commits `CertifyScopeProfileContinuation`,
binding the profile to the exact transition ID and request digest, predecessor
identity and voters, and successor identity and voters. Its evidence lives in
one reserved continuation row per cluster, outside ordinary request receipts.
The applied log index is its monotonic floor. A new leader uses this durable
attestation; one process's remembered probe result cannot authorize a joiner.
Once Prepare applies, initial profile activation is refused with a retryable,
no-effect result until the transition settles. Thus the coordinator's check
after Prepare sees every activation that can precede cutover. A resumed Prepare
can certify after the learner marker: both certification and Fence accept an
exact proof committed after Prepare. Before proposing Fence the coordinator
checks this durable proof. Missing or mismatched decodable proof at apply is a
committed `topology_transition_rejected` refusal, which permits normal resume or
abort; only read/decode faults abort apply. These no-effect control refusals do
not bind a permanent rejection receipt against an exact retry.

Authority fencing and voter promotion require that exact committed evidence.
The uniform membership cutover carries the activation certificate to the
successor in the same transaction. No unanimous reactivation is needed after
cutover: renewals and batches retain ordinary quorum availability. Scope commands
for an already-active profile pass transition admission during Prepare and
learner catch-up, until the Fence entry. The replicated Fence drains predecessor
authority: an old stamp ordered after it returns retryable `Unavailable` without
changing a checkpoint or child batch. Permits issued before Fence remain valid
under the successor voter set; membership itself changes neither their grant nor
their absolute deadlines.

**Operational limit:** permits cannot be extended while no leader is available,
or from the Fence entry until successor admission. If either window outlasts
the remaining permit budget, permits lapse `h + G` after the last issuance;
the packet gate may close earlier under its conservative clock bound. Learner
catch-up and a coordinator paused before Fence no longer create this refusal
window. Callers retain exact requests across retryable uncertainty.

An aborted transition keeps the predecessor activation. The durable Abort
decision restores predecessor authority, so active scope renewals, reads and
batches continue while unreachable learners await cleanup. Its retained continuation
cannot authorize another transition because all request and configuration
bindings must match. A later transition replaces the one continuation row with
a higher log index. Restart, compaction and snapshot installation retain this
row; snapshot installation refuses to erase or regress its floor. Membership
changes without scope activation do not create a continuation or activate scopes.

A command that reaches apply before initial activation returns
`ProfileNotActivated` with no effect. This is retryable: retain the exact request
and retry it; the service attempts current-configuration activation automatically.
`OutcomeUnknown` still requires exact retry to resolve a possibly committed effect.

Initial cluster activation remains a separate unanimous prerequisite. Each
subsequent scope operation is one command, including after membership changes.

The continuation command is appended to the existing wire vocabulary. Profile 3
changes the exact capability digest, probe domain, reserved-row codec (`OPSC` 3)
and state type (`opc-scope-state-v3`); profile 2 is not compatible.
Crossing this stored-format change requires deleting the old volumes and a
fresh installation, with no migration or in-place conversion. Prior checkpoint
placements, unsupported profiles and malformed records are refused instead of
silently forgetting their floors. Reopening recognized profile-2 storage returns
the typed `ConsensusSessionStoreOpenError::FreshInstallationRequired` reason;
the refusal preserves the retained bytes. Ordinary consumer and roster APIs cannot
access any reserved scope key type; consumer restore scans filter those rows
while retaining pagination progress. The in-process quorum service remains a
trusted boundary and requires authenticated platform admission on every call.
Downgrading after scope-profile activation is unsupported: older binaries may
not decode the committed commands, snapshots or retained rows. The scope-lease,
atomic-batch and activation-continuity slices must all land before an SDK
release or consumer dependency pin uses these APIs.

The checkpoint retains only the last exact request ID and digest. While that
request remains current, retry returns its original state and absolute
deadlines. After another mutation, the old expected revision makes the retry
obsolete; it never performs a new grant. A canceled command may still commit,
so uncertainty must be resolved using the exact retained request before a new
operation. A delayed command loses if another request changes its predecessor.

## Atomic child batches

`ScopeBatchStore::execute` commits a typed `ScopeBatchRequest` with up to 64
child mutations, up to eight unique claims per child, and comparisons for up
to sixteen fixed counters. The complete serialized consensus command is capped
at 2 MiB; each already sealed value is capped at 1 MiB. A maximum-size sealed
value and its full claim set fit together. `ScopeSealedValue` accepts a bounded
RFC 003 envelope; the consumer binds scope and child identity in its AAD and
verifies that binding when decrypting. Plaintext child values are refused.

Create requires an absent child and allocates a monotonically increasing birth
at apply. CAS and Delete require the exact birth and generation. Updates
advance that birth’s generation; delete retains a tombstone, and recreate uses
a new birth. A stale delete, CAS or delayed create cannot affect a replacement.
All child, claim and counter predicates are evaluated before any publication.
A conflict identifies the children, claims or counters to reread and regroup;
none of the batch takes effect, including its birth allocation and result.

Claims are unique within their scope and bind to an exact child birth. A CAS
supplies the complete successor claim set; deletion releases all predecessor
claims. Releasing old claims before acquiring successors permits an atomic swap
within one batch. A shared allocation pool spanning scopes needs a separately
chosen shared claim authority; this API does not imply cross-scope uniqueness.
Releasing a claim leaves its row with `owner = None`; it does not physically
delete the key. Retained claim rows therefore grow with the number of distinct
claim keys ever used. Native publication, cold reconstruction and SQLite
snapshot validation currently require predecessor scope keys to remain present.
The reclamation slice must make all three checks floor-aware before removing
released claims or child tombstones; compaction alone does not reclaim them.
Counters are exact compare-and-set values between zero and `i64::MAX`. They
are bounded accounting fields, with no default session quota or capacity policy.

Apply checks the authenticated admitted execution’s stable grant and selection
against the authority checkpoint. It rejects a released, replaced or expired
grant, including a command prepared while the permit was live but applied
after its stop deadline. Renewal preserves the batch fence. Both the trusted
clock upper bound and replicated application time must precede the current
permit’s stop deadline. Point reads are linearizable and issue no application
command; they are observations, not ownership or coherent scans.

This initial batch profile permits one unresolved request per scope. Retain the
complete request, serialize successors using the returned batch revision, and
retry the exact request after `OutcomeUnknown`, including during configuration
cutover, and retry the no-effect `Scope(ProfileNotActivated)` result as described
above. The request and outcome already contain a lane and a positive sequence.
Only lane zero is active, with sequence equal to expected batch revision plus one.
The checkpoint reserves eight fixed lane slots, each with a floor, sequence,
request ID, digest and bounded outcome; the other seven remain canonical zero.
The current checkpoint retains one exact request digest and result in lane zero.
An exact retry while retained returns that original outcome without another
effect; a changed body with the same ID conflicts. After a successor replaces
the result, `RevisionConflict` prevents an obsolete request from executing but
does not recover its original outcome. Eight independent replay lanes and
outcome reads are the next slice. Reserving their complete stored layout avoids
another layout change, but enabling lanes also changes
apply semantics and the profile digest. The planned lanes profile therefore
requires another fresh installation: mixed binaries cannot safely apply a
certificate checked against different local digests. A rolling transition would
need separately reviewed support for both profiles until unanimous activation;
the reserved fields alone do not provide it.

The reserved row types are `opc-scope-lease`, `opc-scope-batch`,
`opc-scope-child`, `opc-scope-claim`, `opc-scope-profile`, and
`opc-scope-continuation`. Their metadata codec is explicit and cannot be used
through ordinary session operations.
Child values remain sealed inside that codec. Native publication and cold
reconstruction validate child/claim links; compaction preserves authority,
birth and generation floors. Tombstones remain until the future reclamation
profile supplies a safe physical deletion boundary. A committed batch survives
restart or a lost reply without exposing a partial child/claim/counter change.
The service adds no shutdown or emergency-session interruption policy.

This profile adds no session-count limit. Follow-on slices own eight replay
lanes, coherent scans, physical reclamation, and scheduling.
SafetyControl priority must include scope renewals under child-write load. The
remaining integrations also have explicit owners in the slice plan: an
authenticated consumer transport, a production bounded-clock provider, and
store-side same-domain handover with independently verified predecessor-exit
proof. That planned operation allows immediate handover within the same
workload instance once the store accepts proof of predecessor exit, closed
gates, and retired or blocked old
transports, with old forwarding state retired or safely adopted. It does not
wait for the remote exclusion timer; another workload still does. Until that
store operation exists, a successor without graceful release follows remote
exclusion. This slice supplies no packet gate, kernel reset or external
predecessor-exit proof producer.
