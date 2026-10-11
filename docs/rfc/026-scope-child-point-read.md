# RFC 026 addendum: bounded worker child reads

Status: implemented. Addresses
[#1221](https://github.com/openpacketcore/openpacketcore-sdk/issues/1221) and the
follow-on authority adapter in [#1225](https://github.com/openpacketcore/openpacketcore-sdk/issues/1225).
Applies to [RFC 026](026-scope-authenticated-transport.md)
and [RFC 027](027-scope-batch-lanes.md); [RFC 025](025-local-kernel-lifecycle.md)
owns the kernel authority contract, and retained restore remains RFC 028.

## API and linearization

Add `ScopeClient::read_children(authority, keys, class, deadline)`, returning
`Result<Vec<Option<ScopeChildRecord>>, ScopeChildReadError>`. Accept **1–32
distinct nonzero keys**, preserve caller order, and return exactly one entry per
key. A convenience `read_child` uses the same method with one key.
`authority` is this process's genuine `CommittedScopeAuthority`; its full stamp
supplies the explicit namespace. Keys are opaque `ScopeChildKey`, never internal
`SessionKey`. The deadline is one absolute monotonic `tokio::time::Instant`,
established before admission and covering admission, connection ownership,
proof and reply. A Duration wrapper computes it once; no stage restarts it.

The worker checks scope, execution and its live process gate. The server checks
live principal/scope/method/class policy, TLS and boot-key possession against
the full stamp. Only the current worker may read. Ticket and Pod-bound-token
verification are inherited through the committed execution; reads recheck the
boot key and exact active stamp, without reissuing tickets or fetching tokens.

Add `ScopeBatchStore::read_current(authenticated, stamp, keys)` beside `read`:
**one complete current-configuration ReadIndex barrier and one backend cut**
for active authority and all children. Native uses one admitted immutable
generation; SQLite one read transaction. Check exact namespace, authority
revision, execution and admission generation, retaining configuration-authority
checks. Followers forward the complete barrier and wait for applied position;
obsolete configuration authority cannot release a result.

Method 17 bypasses the generic RPC path's auxiliary `Current` reads, including
cached-connection promotion refresh. Verify possession and the carried
execution's boot key before any barrier. At the sole cut, check active authority
and the independent current-execution/key binding **before** established
Emergency dispatch admission. Unproven work uses EmergencyClassification
capacity; a cached promotion hint alone grants no authority or current credit.
Hold this bounded cut through class admission and child materialization, at
most **10 seconds from opening the cut**, using a server-local monotonic timer.
The request carries no deadline. Watch peer closure while waiting, as the scan
path does; peer close or expiry cancels admission/materialization and releases
the cut. On expiry, release it before sending the existing retryable
`ProvenNoEffect(Retry)` refusal if the peer remains connected. Never send a late
child observation. The client's original deadline remains independently binding.
Backend ownership must not hold a process gate or synchronous mutex across an
async wait. Count exactly one full barrier for the entire successful RPC, on
fresh and reused connections.

Method 17 selects `WorkerCurrent` proof share only from a cached promotion hint;
an unpromoted worker uses `WorkerUnproven`. An unpromoted Emergency call charges
`EmergencyClassification` proof capacity. The hint neither replaces the cut nor
authorizes Emergency dispatch. A successful read promotes the connection to
the stamp checked at its cut; `StaleAuthority` or either boot-key mismatch clears
the hint before another call. A stale hint can therefore spend at most one
current-share credit. Only the verified current cut admits established Emergency
dispatch. These rules apply to method 17's own path without a refresh barrier.

`None` means missing or a tombstone at that cut. A present record includes
namespace, key, birth, generation, batch revision, complete claims and canonical
sealed envelope. Add `ScopeChildRecord::batch_revision()` and bounded canonical
helpers sharing stored-row validation. Envelope authentication, decryption and
logical AAD checks stay with the consumer. Reads cannot construct effect
capabilities. One call is a multi-key snapshot; separate calls, including
splits, are not. After acquiring the full consumer key set, exact conditions/CAS
still protect updates and delete/recreate with a new birth.

Append no application command, make no TTL or Maintenance proposal, and allocate
no replay lane, sequence or retained scan. Revalidate live policy and TLS before
response release.

## Admission, whole-builder budget and capacity

Standalone reads reserve native resident/running read capacity under the stable
scope key, without a lane. Carry trusted Normal, established Emergency,
EmergencyClassification or Maintenance through authenticated framing and the
separate listener, connection, handshake, proof and dispatch pools. Refuse
SafetyControl.

Add `ScopeBatchReservation::submit_with_reads` with a borrowed
`ScopeBatchReadContext<'run>` and required `ScopeBatchReadBudget`. Expose the
build context and `read_children` through a new trusted `ScopeBatchPort` read
operation. Native and local adapters reuse the builder's resident/running
entitlement; neither reserves again. Server admission remains independent.
Keep existing `submit` for builders without reads.

The context fixes the full stamp and the **running attempt's effective class**,
including inheritance at grant, as RFC 027 requires. It is not Clone, has no
public constructor, and serializes reads through a mutable borrow. It cannot
escape the builder, survive cancellation or be detached. Its enclosing builder
retains the original lane; reads acquire none. Take the process gate per poll
so a waiting read cannot hold Close.

The whole-builder budget has one absolute deadline and a caller-selected
maximum of **1–64 exchanges**, normally one. Debit each attempted call,
including refusals, splits and retries, before transport admission; exhaustion
returns `ReadBudgetExceeded` without an exchange. Use the earlier of each
call's deadline and the unchanged builder deadline. A running Normal builder
cannot extend lane occupancy with fresh per-key timeouts. Cancellation releases
read resources without submitting, cancelling or resolving an application batch.
Splitting is explicit: recursive bisection costs at most 63 calls for 32 keys
(33 for 17 keys). There is no automatic split or retry loop.

For a representative attach with 17 predicate keys fitting one response and one
activation, budget:

| Operation | Serialized exchanges |
| --- | ---: |
| Coordinator reopen | 1 |
| Predicate read of all 17 keys | 1 |
| Apply through the coordinator | 1 |
| #1225 activation readback | 1 |
| Each later effect recheck | 1 |

There is no per-effect `Current` or normal-path outcome lookup. With B predicate
calls (including refused/split calls) and R later rechecks, budget `3+B+R`.
An exchange is Call/Challenge/Proof/Result. One pooled connection per worker and
class serializes exchanges across all lanes. An **illustrative, unmeasured**
2 ms mean complete exchange gives about 8 ms for B=1/R=0, an upper bound near
125 attaches/s per worker/class before write quorum, CPU, bandwidth and queueing.
Large records reduce it.

At V voters, current-worker proof capacity for a class is V×C (default C=4),
also bounded by active client connections and each listener's 64 connections.
A target rate λ requires at least `λ × (3+B+R) × t` concurrent exchanges at
mean service time t, plus other traffic and headroom. Three voters provide 12
default current-worker credits per class: the same ideal model gives at most
1,500 attaches/s aggregate, **not measured capacity**. Proof budgets still
reserve four roles across five class buckets within 128 total credits per
voter; increasing C cannot remove those reservations.

The leader's ReadIndex admission remains class-unaware FIFO: 64 callers, one
coalesced round at a time. For Q queued/concurrent callers, plan roughly
`ceil(Q/64)` rounds, **conditional on bounded round completion**. Proof-bearing
scope calls are bounded by 128 per voter; count other ReadIndex consumers in Q
too. Three voters alone can contribute six waves. Elections or unavailable
quorum provide no time guarantee: expiry gives `Unavailable`. Add leader class
arbitration when the target Emergency deadline/throughput cannot be met under
measured, bounded Normal occupancy. Separate transport pools alone cannot
promise that bound.

## Wire and errors

[The wire appendix](026-scope-authenticated-transport-wire.md#revision-2)
pins changed bytes, full enum tables and revision-2 vectors. Method **17
ChildRead** takes 1–32 keys. Status **7 ChildObservation** returns all entries
or typed `ObservationTooLarge`, with **no partial observations**. Preserve the
**2 MiB + 512 byte complete Call/Result cap**, including header. The caller
may split within its budget; overflow never means missing.

`ScopeChildReadError` distinguishes `Batch(ScopeBatchError)`,
`ObservationTooLarge`, `ReadBudgetExceeded` and `TransportRevisionMismatch`.
The latter three add no stored batch-error encoding. Other scope RPC APIs
preserve mismatch as their own typed variant, including a local-only,
non-serializable `ScopeBatchError::TransportRevisionMismatch` where the batch
interface requires it. Canonical batch-error tags and receipt bytes stay fixed.
The canonical encoder must refuse the local-only mismatch variant, never assign
it a tag or silently encode a different error.

| Condition | Exact child-read result |
| --- | --- |
| Empty/duplicate/zero keys, count >32, invalid local stamp | `Batch(InvalidRequest)` |
| SafetyControl, wrong listener or principal/scope/process/boot-key policy refusal | `Batch(Scope(Unauthorized))` |
| Obsolete authority or admission generation, including Close | `Batch(Scope(StaleAuthority))` |
| Retired scope | `Batch(Scope(Retired))` |
| Verified inactive profile | `Batch(Scope(ProfileNotActivated))` |
| Verified corrupt/incompatible stored row | `Batch(FormatMismatch)` |
| Authenticated canonical store refusal | `Batch(e)`, preserving exact `ScopeBatchError` e |
| Aggregate exceeds frame limit | `ObservationTooLarge`; no partial result |
| Whole-builder exchange budget exhausted | `ReadBudgetExceeded` |
| No-common-ALPN alert or frame 1 on authenticated connection 2 | `TransportRevisionMismatch`; no immediate retry, never latched |
| Voter replacement from Fence to successor admission | `Batch(Unavailable)`, never `StaleAuthority` |
| Admission closure, unavailable barrier, zero/elapsed deadline, TLS/time failure, malformed/noncanonical/oversized or mismatched peer observation | `Batch(Unavailable)` |
| Existing ambiguous transport OutcomeUnknown | `Batch(OutcomeUnknown)` |

No error returns an absent entry or capability. Test every supported canonical
store-error variant; preserve conflict, cancellation and uncertainty.
Local mismatch is never serialized as `BatchError`.

Typed store errors require live TLS, nonce and full header/request correlation.
The existing **pre-challenge ProvenNoEffect** is the explicit exception to
proof/response-binding processing: TLS authenticates it and its nonce/header
correlate its fixed reason before proof transmission. Unauthorized maps as
above; Invalid to `Batch(InvalidRequest)`; Retry/AuthTimeUnavailable to
`Batch(Unavailable)`; ProfileUnavailable to `Batch(Scope(ProfileNotActivated))`,
matching the batch path. It proves nothing about a different
or pending mutation. Parser failure, absence and successful reads likewise
cannot settle that mutation.

## Native kernel authority (#1225)

Use sealed backend type state (`ScopeKernelAuthority<B = LocalScopeAuthority>`):
preserve the local `ScopeKernelAuthority` constructor and
`commit_activation`. `from_scope_client` returns
`ScopeKernelAuthority<NativeScopeAuthority>`, with **no commit_activation
method**. An optional `native-scope` feature enables `store` and
`opc-session-net`. The concrete constructor consumes a genuine committed
capability, local execution/lifecycle and worker ScopeClient, checking their
identity/scope/process binding. A checked `Current` wrapper may run at
construction. A caller-supplied observation provider is not a capability factory.
`CommittedScopeEffect` stays concrete and non-generic in GTP-U and XFRM APIs;
erase the sealed backend internally and retain the effect's trusted class there.
Default and `store`-only consumers, including XFRM's `scope-store`, do not
depend on `opc-session-net`. Default lifecycle and XFRM consumers also remain
free of storage and TLS dependencies. The existing store adapter already
depends on `opc-tls` through `opc-key`; `native-scope` preserves that baseline
and makes the scope transport opt-in. The dependency-contract check,
`ci/local-kernel-lifecycle-cases.json` and the native shard case list cover
these boundaries and both authority adapters.

The consumer commits through the **shared batch coordinator**, retains the
original full request and supplies its committed completion to
`readback_activation` **before ack(attempt)**. Carry an opaque
native-authenticated completion provenance token from the concrete ScopeClient
apply/reconciliation path through the coordinator, binding client/process,
stamp, full request digest, lane, sequence, trusted effect class and outcome.
It is neither serializable nor publicly constructible. A deserializable
`ScopeBatchOutcome` or a completion synthesized by an arbitrary public
`ScopeBatchPort` is insufficient. Reconnection preserves provenance for the same
bound execution, never retagging another client/attempt's result.

Require Applied, `matches_request` against the original full request, and a
valid non-delete operation index. One method-17 read verifies exact active stamp
and child's namespace, key, birth, generation, **batch revision equal to the
outcome revision**, sealed bytes and complete claims. Share checks with the
local adapter, including the new batch-revision comparison. Combine with local
fence, reset epoch, single effect owner and bounded shared consumption before
issuing a token. Rechecks repeat the one-cut child/current-stamp validation and
local checks. **Neither path surrounds the child read with two Current calls.**
The local adapter also uses `ScopeBatchStore::read_current`; its pre-submission
`current()` in `commit_activation` stays, so obsolete local authority cannot
submit a new activation.

Each readback/recheck takes the effect's **trusted work class from its activation
submission**, matching bound provenance. Construction uses Current on its
reserved control path; the constructor takes no effect class. Readback and
rechecks refuse SafetyControl. Normal never spends Emergency capacity; Emergency rechecks must progress while Normal is saturated.
Keep the effect's original trusted class distinct from the scheduler's inherited
running class: a temporary lane priority boost cannot promote an ordinary
effect's later standalone rechecks into Emergency capacity.
Builder predicates use the borrowed running context; other checks use
standalone read admission.

Exact-outcome lookup is only recovery of a lost supervised completion:
authenticate provenance and match the full original request. No normal-path
duplicate lookup, raw ApplyBatch, extra lane, rebuilt retry or automatic ack.
Ack permits receipt pruning on lane reuse: early-ack `Pruned` and `NotRecorded`
are unknown and yield no token. Only authenticated exact Cancelled/NotApplied
evidence proves no effect. Preserve unavailable/unknown through existing
local-effect refusal; expose `LocalEffectError::TransportRevisionMismatch`
distinctly. This exhaustive enum change requires updating both backend matches
and RFC 025's error mapping; it grants no effect or teardown authority.

## Integration with the landed contracts

| Contract | Consequence for this proposal |
| --- | --- |
| [RFC 028 coherent restore](028-coherent-scope-scans.md) | Retained restore pages and lookups keep their original cut, successor eligibility, claim/tombstone detail and explicit completion. Method 17 supplies fresh bounded predicates; separate calls cannot replace a retained restore. Methods 12–16 and page payload bytes remain unchanged inside revision-2 frames. |
| [RFC 030 IKE recovery](030-ike-recovery-profile.md#durability-writer-fencing-and-ownership) | Return the complete sealed row and store birth/generation so the consumer can preserve exact child CAS, distinct from the protocol window's generation. A latest read cannot settle a possibly applying predecessor: first resolve or fence its exact attempt as RFC 030 requires. Unsealing, provider-unavailable classification, affine runtime ownership and uncertain-operation resolution remain consumer obligations; observations grant no send or effect token. |
| [RFC 023 voter replacement](023-voter-slot-incarnations.md#composition-with-untimed-scope-authority) | The full barrier and follower forwarding retain current-incarnation application admission; from Fence to successor admission return `Batch(Unavailable)`, never `StaleAuthority`. An obsolete voter reply cannot complete the read. Scope-profile continuation preserves scope/execution, birth and lane floors. Transport revision 2 changes neither that profile nor the voter incarnation encoding, and requires no extra all-voter reactivation. |
| [RFC 025 local kernel lifecycle](025-local-kernel-lifecycle.md) | Extend the landed `ScopeKernelAuthority` and its private activation/readback boundary. Replace its surrounding `Current` calls with the one-cut check and add the outcome batch-revision comparison. Preserve the opaque `CommittedScopeEffect` accepted by existing backend/open APIs, with sealed backend dispatch inside the capability. Both adapters retain the lifecycle's single owner, epoch and shared consumption frontier, supervised shutdown and store-independent receipt teardown. The optional native adapter must preserve ordinary XFRM's store-free dependency boundary. |

The configuration-change qualification below includes voter replacement across
Fence and uniform completion, including delayed replies from the retired voter.
The local authority regressions must continue to exercise the landed opening,
reset and cancellation ownership rules with either backend.

## Qualification: guards, tests and mutations

Write **failing tests first**. Each mutation below must fail its protecting
test. Use held gates, paused Tokio time and authenticated scripted peers,
not sleeps. Wrong-content replies have valid TLS, fresh nonce and recomputed
binding, so they reach the target guard. Combine native TLS, parser and backend
tests; preserve all existing assertions and deadlines.

| Guard | Test and exact assertion | Mutation that must fail |
| --- | --- | --- |
| Echo namespace/count/ordered keys | Swap each in a validly bound reply: `Batch(Unavailable)`, never absence | Remove each comparison |
| Record namespace/key | Correct echo, wrong record: `Batch(Unavailable)` | Remove each record/request comparison |
| Canonical bytes, versions, claims, envelope | Overlong/trailing bytes, zero/overflow birth/generation/batch revision, duplicate/ninth claim, malformed envelope: `Batch(Unavailable)` | Bypass each validator/re-encoding |
| Presence/result tags | Unknown tag or present-without-value: `Batch(Unavailable)` | Accept unknown tag or present tombstone |
| Bounded decoding | Counts 0/33, excessive length prefixes, oversized frames and noncanonical records are refused by the header, length and canonical-codec checks. Raw-peer duplicate/zero keys and counts 0/33 are refused before any barrier | Bypass a header, length, canonical-record or server key-set check |
| Atomic aggregate | Mixed presence, 1/17/32 keys; on native and SQLite stores, two near-1-MiB children fit and three give only `ObservationTooLarge`, with one barrier and unchanged application log; split calls use separate cuts | Truncate, silently mark missing, exceed cap |
| Retired incarnation | A validated monotonic retirement seeded in the SQLite store makes a public read of the old incarnation return exactly `Batch(Scope(Retired))` after one barrier | Collapse Retired to stale authority, unavailable or absence |
| Exact stamp at one cut | Hold after full barrier **before opening cut**, commit Close (separately succession), release: `Batch(Scope(StaleAuthority))`, no records, on native and SQLite | Check authority before the held gate |
| Cut retained after capture | A second gate **after opening the cut** holds materialization; commit a child update, and separately Close, then release: return the records from the original cut, on both backends | Fetch children from another cut or refresh Current after capture |
| All keys share the cut | Hold between materializing two keys, commit one batch changing both, release: both returned entries have the original values/revisions | Open a new cut per key |
| Full barrier/configuration | Ordered write through follower; reads held at AfterCapture and BetweenKeys across a committed Fence return `Batch(Unavailable)`. Across a leader change they return the original-cut rows or `Batch(Unavailable)`, never later rows; exactly one full barrier per success | Skip round/applied/config/incarnation check, misclassify cutover or add Current |
| Both boot-key comparisons | Add method 17 to `native_scope_shared_identity_cannot_sign_for_another_slots_boot`: A's key signing B's stamp gets Unauthorized **before any read barrier**, unchanged log/frontiers; A's stamp on B's scope is Invalid before proof. Retain inconsistent-retained-record case and B positive controls | In method 17's own path remove **both** carried-execution/key and cut-level current-execution/key checks: A can read B's children and the test must fail. Retain existing independent single-removal mutations on the generic path; a redundant cut check alone is not claimed to be killed |
| Live policy/process/generation | Held revocation/wrong process/principal/scope: Unauthorized; stale generation: StaleAuthority | Reuse cached grant or compare only namespace |
| Class/currentness | SafetyControl/wrong listener: Unauthorized; stale Emergency boot spends no Emergency dispatch credit; #1225 Emergency progresses with Normal full | Ignore class/listener/currentness or force one fixed class |
| Method-17 proof share/promotion | Unpromoted calls spend only `WorkerUnproven`; success promotes; stale hint or key mismatch clears it, so a second call cannot use `WorkerCurrent` | Treat unpromoted as current, omit promotion or retain a stale hint |
| Unproven Emergency proof | Unpromoted Emergency charges classification proof capacity, spends no established Emergency dispatch credit before the current cut, and progresses after that cut proves currentness | Charge Emergency proof/dispatch before proof of currentness or use only the header class |
| Server cut release | Hold class admission; peer close releases the cut. Separately advance paused time to 10 seconds: release cut, return Retry to a connected peer, never emit a late observation | Omit peer-close watch, fixed maximum or cancellation/drop of cut ownership |
| Absolute deadline/budget | Hold admission, connection lock, exchange separately; paused-time expiry: `Batch(Unavailable)`; exhausted budget: `ReadBudgetExceeded`, no call; later read cannot restart budget | Reset timeout per stage/read or omit debit |
| Borrowed permit/cancellation | Caller resident/running limits 1: 17-key builder progresses; compile-fail escape/detach; cancel/Close release resources | Nested reserve, Clone/owned context, held process gate |
| Every error-table row | Script each exact variant, every canonical batch error and pre-challenge reason; canonical encoder refuses local-only mismatch; never absent or pending-mutation no-effect | Collapse variants, encode mismatch, trust unauthenticated error, infer no-effect |
| No side effects | Compare application log index, all lane sequences/receipts, TTL/Maintenance counters; no capability-producing API | Enter proposal/lane path or fabricate capability |
| Update/delete-recreate | Later update/recreate makes old child condition conflict; observe changed generation/birth | Ignore either version |
| Freshness/uncertainty | Replay nonce/request or drop reply after proof: Unavailable/OutcomeUnknown as applicable, never absence | Remove correlation or map loss to absence |
| Revision/startup | TLS alert both directions, authenticated frame 1 on connection 2, issuer/worker startup and retained TicketNotice: typed mismatch plus value-free signals. Wrong-endpoint alert followed by authenticated revision 2 recovers without restart; bounded probe/log rate, no immediate retry | Fallback, map to Retry, leave purpose/frame at 1, latch mismatch, trust an unauthenticated alert as proof or hot-loop retries/logs |
| Activation provenance/ack | Reject forged outcome/port completion, altered request/row/batch revision/class, early-ack Pruned, epoch change, duplicate consumption; compile-fail native commit_activation | Remove each provenance/readback/fence/consumption guard or expose raw commit |
| Independent bytes | Reference script `--check` runs in required CI and reproduces all revision-2 frames, exporters, proof/bindings and child positive/negative vectors; implementation matches | Change version, unchanged domain/input version, order or bound, or omit the CI check |

Qualification covers the existing local authority cases against both adapters,
native failures, Close, drain, reset and restart. The repository validation gates
include the privileged lifecycle manifest.

## Installation and lifecycle

Revision 2 is **fresh-install only**, consistent with RFC 026: no mixed-revision
rollout or fallback, and no stored-format change. Pin revision 2 with other
fresh-install boundaries so a consumer can cross them in one installation.
Both endpoints emit a value-free mismatch counter and rate-limited log, and
return typed `TransportRevisionMismatch`. A no-common-ALPN alert precedes server
authentication: it may be forged or from a wrong endpoint and is **not proof**
of peer revision. Only frame 1 on an established authenticated connection proves
a mismatch; reject it before body allocation. Neither signal establishes a
pending mutation's outcome.

Fail that call without an immediate retry; **never latch** the mismatch or
require a restart. A later call tries a fresh handshake; unresolved background
work may probe at most once every **30 seconds**, without a hot retry loop.
The first authenticated revision-2 handshake clears the diagnostic condition.
Emit at most one mismatch log per role/purpose/direction every 30 seconds;
the counter may count every event. The coordinator retains any unresolved exact
attempt for later recovery and preserves the typed error distinctly from
Unavailable. It does not acknowledge, cancel or infer an outcome from mismatch.

For later revisions, accept N and N−1 for one release, negotiated per connection;
enable N-only behavior after relevant peers support N, and N+1 may drop N−1.
[SDK #1227](https://github.com/openpacketcore/openpacketcore-sdk/issues/1227)
tracks voter compatibility; this later-release policy also applies to scope
endpoints. Revision 2's fresh-install boundary is not an in-service upgrade.

Restart discards in-flight observations and obtains fresh authentication.
Transport loss prevents new effects without resetting published forwarding.
Preserve local cleanup, cancellation-safe Close, drain, contained reset and the
consumer's emergency-session disruption policy. No Pod lifecycle event needs a
node reboot, manual cleanup or operator recovery.
