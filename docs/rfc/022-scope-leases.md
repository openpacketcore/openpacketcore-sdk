# Scope leases, profile 2

Status: experimental scope authority, the first slice of issue #1134.

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
binding. It grants no traffic authority and does not require an idle storage
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

The profile fixes a one-second healthy renewal interval, followed by sixty
seconds of forwarding grace. A grant records immutable issuance, next-renewal,
stop and exclusion deadlines. Exclusion extends one additional second beyond
the stop deadline. The next renewal deadline is not recomputed when a reply
arrives. A delayed response or an exact retry never extends a deadline.

The service requires a trusted clock source reporting an interval containing
current time in a common time domain. The interval must include offset between
hosts, drift, suspend and sampling uncertainty, and be no wider than one second.
Unknown, inverted, overly wide or regressing bounds refuse a new operation.
There is deliberately no implementation which treats `SystemClock`,
`CLOCK_MONOTONIC`, or a caller's timestamp as proof of these bounds.

The permit's stop deadline is issuance's upper bound plus 61 seconds. A gate
stops when its current upper bound reaches that deadline. A successor waits
until its lower bound reaches the previous permit's exclusion deadline.
Consequently, if both clock intervals contain true time, the old execution has
stopped before the successor is admitted, including across a change of leader.
If the clock provider loses its bound, an enforcing gate must close. A kernel
adapter must preserve this rule while userspace is paused and across suspend;
this module's `is_live_at` helper is not kernel enforcement.

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
services and checkpoints can renew, release and select after the transition.
If a command was stamped before the authority switch and applies afterward,
apply returns retryable `Unavailable` without changing the checkpoint. The
service resolves the retained request if possible, otherwise returns
`OutcomeUnknown`; the caller retries that exact request through current
admission. A configuration switch is not a platform admission refusal.

Profile 2 retains one fixed 4096-byte authority checkpoint per scope. Its body
starts with `OPSL` and version 2; length framing and zero padding are checked
exactly. The persisted wire representation uses a fixed-width hexadecimal
encoding. This encoding is not encryption. The checkpoint shares the existing
durable keyed-outcome storage collection under a domain-separated key derived
from the full scope. A hash collision or another record kind at that key fails
closed. Each successful operation replaces the same checkpoint; refused
operations do not allocate receipts. There is no mutation lease, per-operation
ordinary receipt, watch event, or child-record mutation. ReadIndex barriers
issue no application command. Normal Raft log retention and snapshot compaction
still apply, independently of the fixed per-scope business state.

The checkpoint contains an apply-visible grant fence: exact stable scope,
selected execution, selection and grant epoch, current permit, and release
state. Renew and Resume replace deadlines while preserving the grant epoch.
Slice 2 must check that fence and permit validity during apply, never compare a
child batch against the per-renewal checkpoint revision.

The command and outcome variants are appended to the existing wire vocabulary.
Every voter must support this profile before use. This is a fresh-install
boundary for scope authority, with no migration from profile 1. A legacy
`opc-scope-lease` session record is refused instead of silently forgetting its
selection or grant floor. Unsupported or malformed checkpoints fail closed.
Ordinary consumer and roster APIs cannot access the reserved key type; consumer
restore scans filter it while retaining pagination progress. The raw in-process
consensus store remains a privileged trusted component.

The checkpoint retains only the last exact request ID and digest. While that
request remains current, retry returns its original state and absolute
deadlines. After another mutation, the old expected revision makes the retry
obsolete; it never performs a new grant. A canceled command may still commit,
so uncertainty must be resolved using the exact retained request before a new
operation. A delayed command loses if another request changes its predecessor.

This profile adds no session-count limit. Follow-on slices own batched child
writes, eight replay lanes, coherent scans, physical reclamation, and scheduling.
SafetyControl priority must include scope renewals under child-write load. The
remaining integrations also have explicit owners in the slice plan: an
authenticated consumer transport, a production bounded-clock provider, and
store-side same-domain handover with independently verified predecessor-exit
proof. Until that handover operation exists, a successor without graceful
release follows the remote exclusion deadline. This slice supplies no packet
gate, kernel reset or external predecessor-exit proof producer.
