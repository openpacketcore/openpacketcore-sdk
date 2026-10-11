# RFC 030: IKE recovery profile and lifecycle qualification

Status: implemented SDK contract and public-API lifecycle fixture. Consumer
integration and third-party peer interoperability qualification remain pending.

## Purpose and implementation boundary

Recover an IKE SA from trusted durable state, preserve exact protocol replay,
and answer empty INFORMATIONAL requests without a write per exchange. Recovery
requires exact compare-and-set persistence, exclusive execution and local
Child-SA reconciliation. Reading stored bytes grants no effect authority.

The existing [committed window](../../crates/opc-proto-ikev2/src/recovery.rs),
[empty receive](../../crates/opc-proto-ikev2/src/recovery/empty.rs),
[in-place readback](../../crates/opc-proto-ikev2/src/recovery/reconcile.rs),
[typed profiles](../../crates/opc-proto-ikev2/src/recovery/profile.rs) and
[canonical replies](../ikev2-canonical-empty-replies.md) provide the protocol
foundation for GCM and CBC. Reuse their cipher, packet and record implementations.
The lifecycle fixture exercises public APIs and an independent peer model.

The following API boundaries have focused implementation coverage and compose
with the fixture below. The raw APIs alone do not supply consumer storage,
execution ownership or effect fencing:

| Surface | Required behavior |
| --- | --- |
| `Ikev2CommittedWindow::replay_request` | Return only a committed request with no committed response. A settled exchange yields `None`. Record the behavior change in the CHANGELOG and reverse the settled-replay regression. |
| Empty and cached-response admission | Permit the narrow outbound-only uncertain-write case for `reply_empty`, the cached branch of `request_disposition` and `replay_response`; retain receive, authority, revocation and sync checks. Only empty replies require current canonical-provider admission; committed ordinary replay needs no cryptography. Do not relax `ready()` for new work or other operations. |
| `recovery/packet.rs::open` | Authenticate an otherwise applicable `SKF` before returning a typed `UnsupportedShape` reason. Unauthenticated input remains an ordinary drop and cannot trigger teardown. |
| Profile record construction | Add a checked `from_profile_persisted` entry point with a mandatory, explicit base/negotiated synchronization-state argument, including explicit recovery-event presence or absence. Reuse existing records. The low-level optional `with_sync_state` sequence alone does not qualify a profile restore. |
| `notify.rs` | Add the `INITIAL_CONTACT` constant and strict typed decoding; authentication, identity matching and cleanup remain composition responsibilities. |
| Pending KE custody | Opt in through `require_dh_checkpoint(group)` and the optional `IkeDhCheckpoint` capability. Export an initiator's private value once into `Zeroizing` bytes; import recomputes and checks its public value. Persist the checkpoint inside the existing row envelope in the request's child CAS. A fixture-held handle surviving a simulated crash is insufficient. |

This work adds no cipher path, general runtime, store trait or SDK storage
format. Provider custody and record construction have separate focused tests
and remain subject to review. Existing generic APIs do not acquire this profile's
composition guarantees merely by remaining callable.

## Supported composition and negotiation

| Dimension | Contract |
| --- | --- |
| Packet/profile | Complete, unfragmented `SK`; existing AES-GCM-16 with 128/192/256-bit keys, or the existing 48 CBC encryption/integrity/PRF combinations. Qualify every configured provider/profile and KE custody capability. |
| Exchange classes | Final IKE_AUTH seeding/replay, CREATE_CHILD_SA and INFORMATIONAL. Handshake authentication precedes established-SA effects. |
| Request windows | One outstanding ordinary request in each independent direction, for both original roles. Never send `SET_WINDOW_SIZE`. Zero is a valid ID where that direction's history permits it; `None` means exhaustion. |
| Empty receive | Canonical policy and preflight, checked restore, then `enable_empty_replies`. CBC uses `preflight_cbc`; sync readiness does not qualify canonical replies. |
| Base recovery | Restore committed history and reconstruct the lost empty prefix. No synthetic local liveness probe. |
| Negotiated sync | Persist authenticated bilateral agreement; require `sync_readiness`, initiation and response handlers. Never assert `IPSEC_REPLAY_COUNTER_SYNC_SUPPORTED` (16421); ESP counter restoration is outside this profile. |
| Persistence | Exact prior birth/generation CAS under the current RFC 022 execution stamp, with the SA, window, IV state and operation outcome committed atomically. |
| Execution | One live window and allocator owner per immutable SA key epoch, including within one process. Positive authority is required to recover that cohort. |
| Excluded histories | Unknown or rolled-back key/IV state, omitted negotiated metadata, partial records, unconfirmed predecessor takeover and restored old ESP sequence state. |

This profile does not negotiate IKE fragmentation. A bilateral fragmentation
agreement permits later SKF use, including a large rekey, so qualifying only the
initial packet sizes is insufficient. The configuration check must cover all
admitted handshake and later exchange shapes. See
[RFC 7383 §§2.3–2.4](https://www.rfc-editor.org/rfc/rfc7383.html#section-2.3).
An authenticated SKF received nevertheless has a typed refusal and enters the
committed, scoped Delete path below; it must not disappear as unexplained noise.

The scoped implementation adds refusal diagnostics and tests, not fragment
recovery. A consumer that requires SKF needs a separately sized extension for
authenticated reassembly, persisted exact fragment responses, IV accounting and
crash/retransmission coverage before enabling this profile. That decision is a
consumer integration gate, not permission to silently narrow an already
negotiated SA. This revision covers typed refusal and its REDs; full fragment
recovery is a separate dependency if the consumer's declared
handshake/rekey shapes require it. Before consumer integration implementation,
the consumer must declare whether its IKE_AUTH or rekey exchanges require
fragmentation; a required extension must then be sized and the integration
reforecast before proceeding. No full-SKF estimate or support claim is made
without that shape decision. Third-party interoperability remains separate for
either cipher.

## Durability, writer fencing and ownership

Every durable IKE write is an [RFC 022 child CAS](022-scope-leases.md#atomic-child-batches)
on the **exact prior child birth and generation**, under the current execution
stamp. This includes ordinary window updates, sync attempts/results/closure,
GCM reservation retry charges and blocks, pending KE material, endpoint changes,
and operation records. Publish the matching session state in the same atomic
batch. The store row generation is not interchangeable with the window's internal
generation: an IV-only update must still compare and advance its store version.
Initial creation compares absence; replacement epochs never overwrite a reused
identity. An acknowledgement must match the exact candidate and request digest.

A cancelled observer or read of generation `g` does not cancel an in-flight
write expecting `g`. Resolve it by exact request-ID/digest retry, or the
[predecessor outcome boundary](022-scope-leases.md#recovery-and-integration-constraints).
For `Unknown` after receipt pruning, first prove the relevant batch sequence has
passed that request, or that committed succession makes its old stamp inapplicable.
Then take one fenced latest read. Never prepare a replacement at the same ID
while the earlier write can still apply. CAS must independently reject delayed
W1 after W2; write ordering or a cache mutex is not a substitute.

Compare readback with the exact acknowledged state or retained candidate, keeping
the live allocator and window. Recover an exact retained outcome idempotently
under current authority. `Unknown` never means `NotApplied` and never licenses
repeating an effect. Only after successfully obtaining and unsealing the fenced
current records can their contents establish an irrecoverably uncertain outcome
and select the typed uncertain-operation resolution and scoped terminal path.
Do not leave an SA waiting forever for a pruned receipt. Store or key-provider
`Unavailable`, timeout or throttling during this read/unseal is retryable
backpressure, never evidence of missing/corrupt history or a terminal outcome.
Preserve that distinction through the consumer wrapper until
[#1197](https://github.com/openpacketcore/openpacketcore-sdk/issues/1197) supplies
it through the full envelope path. Retry budgets bound attempts; their exhaustion
does not turn provider unavailability into proof of permanent key loss.

That last resolution is a consumer operation-state CAS plus idempotent cleanup,
not a fabricated SDK completion token or a claim that an unrecorded operation
succeeded. Preserve the uncertain outcome for callers and revoke that epoch's
send/effect admission when its terminal resolution commits.

The consumer's runtime factory must acquire an affine owner permit for the
complete SA key epoch **before** constructing either window or allocator. It
refuses a second runtime or allocator even when empty replies are disabled.
Transfer that permit only after the old executor has stopped and its outstanding
writes are resolved or fenced. Canonical `CapabilityActive` protects its own
cache only; it does not enforce this ordinary-window/IV requirement. The test
store and driver model both owner refusal and independent CAS rejection. Neither
is misreported as a guard currently supplied by raw `restore`.

## Public API and release ordering

| Boundary | Required sequence |
| --- | --- |
| Process start | Prove exclusive execution; settle/fence prior writes; obtain one latest atomic SA/key/window/IV/operation record; validate mandatory mode and fields; acquire the epoch owner; restore. GCM discards the unused reserved tail. Enable empty replies when the stored lifecycle permits it. |
| In-process uncertain write | Retain the owner, window and allocator. Resolve/fence as above, then `reconcile` the exact base or candidate; recheck the appropriate admission path. No replacement runtime or newly minted completion token. |
| GCM sealing | Charge the existing bounded reservation-retry guard durably before each fresh-block attempt; CAS the IV block before allocating; burn each allocation on preparation or failure. Then commit the window/operation candidate before release. Use the correct Ordinary or Control budget; ordinary sync cannot consume the rekey/Delete reserve. CBC uses its existing random-IV sealing and no GCM allocator. |
| Local ordinary operation | Plan without effects; `prepare_request`; CAS the candidate and operation; acknowledge through `commit_after_durable`; release exact committed bytes. Validate the response and commit completion before its outcome can affect local state. |
| Peer ordinary operation | `open_peer`, then `request_disposition`. `CachedResponse` goes directly to `replay_response`, never a new seal or outcome. For new work, retain its identity; commit response, outcome and receive floor atomically, then consume the current token and release. Failure responses and empty acknowledgements of nonempty requests use this path. |
| Empty peer request | `open_peer`, then `reply_empty`. Hold its borrowed reply and current local send permit through transport submission. No store command, ordinary IV allocation, entropy draw or application outcome. The restricted outbound-witness rule below also applies to cached replies. |
| Sync | `begin_sync` or `begin_sync_response`, existing prepare/commit/release, then `complete_sync` or `retry_sync`. Persist original event, proposals, budget and closure; readback creates no new release token. |
| Closure/retirement | Revoke the local send/effect permit and stop empty replies as well as ordinary traffic. Discard queued/copyable packets. Permanent teardown calls `window.delete()` or the epoch hook when decoding failed before a window existed. |

The external send permit binds the current scope execution, incarnation,
SA/epoch and local admission generation to the live executor. Its owner checks
revocation at submission and stops dispatch when closure, retirement or lost
authority is learned. A cached store success, borrowed reply or timer is not
that permit. This is local authority established by RFC 022's untimed execution
contract; it introduces no per-DPD store read or expiry-based ownership.

Readback preserves the canonical owner/cache, charged attempts, pending identity
and volatile receive high-water. A landed inbound/sync boundary adopts
`max(live, recorded)`, with exhaustion absorbing; outbound readback preserves the
receive phase. Every reconciliation attempt fences prior completion tokens.

## Handshake, rekey and pending key exchange

### Final IKE_AUTH

Persist the final authenticated exchange with the established SA rather than
using a cache-free generation-zero record. Use `from_profile_persisted` over the
existing `from_persisted` representation at generation at least one. The original
responder retains the exact inbound final request, response and attach outcome;
the original initiator retains its outbound exchange and committed response and
outcome. Floors reflect each direction's actual handshake IDs, including EAP
rounds; do not assume that the final ID is one or that both floors are equal.

A lost final response remains recoverable: before initiator completion, its
durable outbound IKE_AUTH remains pending and is replayed exactly; the restored
responder returns its cached response. After initiator completion, replay is
suppressed and restoring the attach result does not repeat its effects. Cover
response loss and crashes on both sides of the attach/completion commits, with
both original roles. No candidate Child SA is installed before its result commits.

### IKE SA rekey epoch hand-off

Commit the old window's rekey response or completion, the operation result and
the complete new epoch atomically. The new epoch has new keys/SPIs, its own owner,
a fresh GCM IV record with the canonical V1 marker or a fresh complete CBC
descriptor, and initial send/receive IDs zero. Preserve the authenticated peer
identity and derive the new original role from this exchange.

Use [the agreement's `inherit_rekey`](../../crates/opc-proto-ikev2/src/message_id_sync/negotiation.rs)
only for a successful authenticated same-peer rekey. Copy no counters, cached
bytes, pending event, IV block or private KE handle into the new epoch. Agreement
inheritance is SDK policy requiring peer qualification, not an RFC 6311 mandate.
The new epoch cannot send before that atomic commit. Keep the old epoch and its
exact rekey response during permitted overlap until its ordinary Delete commits;
then revoke and delete it. Terminal trust loss follows the separate cleanup rule.
Test crossed rekeys, selection of the surviving exchange and crashes before/after
atomic hand-off, first new-epoch send, old Delete commit and local deletion.

### Pending KE custody and erasure

A private checkpoint exists only for the **initiator of the current exchange**,
independent of its original IKE role: a locally initiated CREATE_CHILD_SA carrying
our KE value for a new Child, Child rekey or IKE SA rekey. Its operation record
retains the group/profile, role, operation ID, nonces, SPIs, transcript, expected
public value and versioned private checkpoint. Commit it with the exact outbound
window candidate in the same child CAS before releasing the request.

The responder already has the peer's KE value. It derives the keys, wipes its
private handle and temporary plaintext, and makes **one commit** containing the
exact response, outcome and derived keys inside the sealed row. It persists no
private checkpoint and makes no preliminary checkpoint commit. A restart after
that commit replays the cached response and installs the same derived keys
idempotently. Before that commit, no response or exchange effect is released;
after process loss the peer's retransmitted request can be processed again.

[`IkeDhKeyPair`](../../crates/opc-crypto-provider/src/ops.rs) and
`IkeDiffieHellmanOperations` expose two optional **synchronous** operations,
gated by `IkeDhCheckpoint` and explicit per-group admission:

- Export the live initiator handle's private value once into
  `Zeroizing<Vec<u8>>`, in a bounded, versioned encoding bound to its KE group.
- Import those bytes into an opaque handle, recompute its public value and reject
  a mismatch with the committed expected value before returning the handle.

These calls neither invoke KMS nor depend on `opc-key` or the session store.
Their errors carry stable codes only. The consumer puts the private value in the
operation field of the row's existing
[RFC 003 envelope](003-security-substrate.md#10-aead-envelope-encryption), alongside
the window and operation state. There is **no nested envelope, extra child CAS
or per-checkpoint KMS round trip**, and ordinary `KeyProvider`/`RemoteSealProvider`
deployments require no `AdmittedKeyCustody` adapter. The row's authenticated
scope/incarnation/child binding and operation fields bind the checkpoint to the
SA epoch, exchange and expected public value. Encryption and retry buffers remain
zeroizing; erase them as soon as row sealing or import no longer needs them.

A module that forbids this export declines the capability. Its groups fail
pending-KE qualification at preflight, before any operation is admitted. Any
required provider-wrapped alternative must use the row's own envelope custody
and its existing key interaction; it cannot introduce a second KMS operation.
The checkpoint encoding binds **group and format version, not a module build
identity**. Both sides of a rolling module upgrade must import the same format.
Never log plaintext or sealed checkpoint bytes, including in errors, `Debug`,
`Display`, metrics or diagnostic archives. Do not save entropy to recreate a key.

After successful initiator derivation, wipe the live private handle immediately.
Every terminal operation CAS removes the checkpoint atomically with its outcome:
success/derived keys, crossed-rekey loss, retransmission-budget failure,
abandonment, uncertain-operation resolution or SA teardown. Do not copy it into a
new epoch or keep it for completed-exchange replay. If the CAS is uncertain, the
earlier row remains recoverable until exact resolution; an acknowledgement loss
must not erase the only input before the derived result commits. If storage is
unavailable at a terminal boundary, retain that pending removal under
backpressure and authorize no further use past the exchange's retry budget.
Logical removal and plaintext zeroization do not promise physical erasure of
old encrypted WAL or snapshot bytes.

Apply [#1197](https://github.com/openpacketcore/openpacketcore-sdk/issues/1197) to
every row seal/unseal, including checkpoint creation, restore and fenced readback.
Key-provider `Unavailable`, timeout and throttling are retryable backpressure;
they release no uncommitted request and never select SA teardown. Until that
classification reaches the full SDK envelope path, the consumer key-provider
wrapper must preserve `KeyError::Unavailable` and equivalent transient outcomes
before any generic crypto-error collapse. Do not treat retry-budget exhaustion
as corruption. Authenticated-decryption failure, binding/public-value mismatch,
unknown checkpoint format, provider `InvalidOutput`, or a positively missing (`NotFound`) or revoked key
are terminal. Never infer any of those from an unavailable provider.

Peer KE validation is a separate protocol boundary. `InvalidPeerPublicKey`,
`MalformedKeyExchange` and `KeyAgreementFailed` terminate the exchange and are
never provider backpressure. For an authenticated request, commit an
`INVALID_SYNTAX` response with the failed operation, without a checkpoint or
derived keys. Replay that exact committed response after loss, then close the
IKE SA after releasing the reply, as required by RFC 7296 §2.21.3. A received
`INVALID_SYNTAX` response also closes the IKE SA without an error-message loop.

For an invalid KE in a response, the initiating operation's terminal CAS removes
its checkpoint and records the peer's SPI and the cleanup intent. For a Child
SA, resume a scoped INFORMATIONAL Delete even after restart: RFC 7296 §3.11
requires our inbound SPI from the request, and the response acknowledges the
paired SPI or an already absent pair. Commit completion before forgetting the
intent; lost acknowledgements replay the same Delete bytes. Existing Child SAs
remain intact. For an IKE SA rekey, close the current IKE SA in the terminal CAS
and perform scoped row cleanup; no successor epoch or keys can be installed.

Never invent fresh KE material under a replayed local Message ID. Confirmed
missing/corrupt recovery inputs use the scoped terminal rule and checkpoint
removal above. An IKE rekey is never "cancelled" by deleting its new IKE SPI as a
Child of the old SA.

## Empty receive, replay and liveness

An admitted empty request advances only the volatile next receive ID. Exact
retransmissions reuse the cached response; changed bytes, retired IDs and gaps in
current mode drop. A restored empty-enabled window may accept authenticated
forward IDs to reconstruct a lost prefix. Older replays cannot lower or pin its
high-water. MAX exhausts only that direction, without wrapping.

The first new nonempty request locks its exact identity until an inbound result
or sync cut resolves it. Its response, result and repaired floor commit together.
An outbound-only commit cannot end reconstruction or erase that volatile floor.
`Fresh` requires a new committed inbound/sync boundary in this runtime;
`Replayed` and `Uncertain` establish no fresh liveness or effect authority.

Replay **only a pending local request** until its response is committed or the
SA fails. Never replay a settled request as a probe: a conforming live peer may
have forgotten its response, and even an answer to old bytes is not fresh
liveness. [RFC 7296 §§2.1 and 2.4](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.1)
distinguish retransmission from a new liveness exchange.

This profile has **no local empty-INFORMATIONAL liveness-check API**. Such a
check requires a fresh request; it cannot be implemented by settled replay.
Empty local requests remain `NoDurableWork`, and no DPD write stream is added.
Fresh authenticated IKE/ESP traffic, including genuinely new peer DPD, supplies
inbound evidence; reconstructed uncertain DPD does not. With only outgoing
traffic, the consumer must schedule genuine committed new work, such as rekey,
within its declared liveness bound. Failure follows unanswered new requests and
their bounded retransmission policy, or the legitimate SA lifetime policy, not
silence after a settled replay. Detection is consequently bounded by that rekey/
lifetime interval plus protocol retries; this is not a fast local DPD facility.
With no prior request, `replay_request` yields `None`; real new work can still
progress at the retained send ID after reconciliation.

### Store outage must not silence empty replies

Avoid discretionary local preparation while the scheduler reports backpressure.
Also change empty admission and exact cached-response replay to allow an
unresolved **outbound-only witness**: it cannot alter the receive floor, cached
inbound response or pending identity.
Authenticate normally and recheck committed sync lifecycle, terminal/revoked
state, receive admission and current send authority. Empty replies also recheck
canonical policy/provider admission. Already committed ordinary response bytes
need only the canonical capability's revocation check, not provider preflight.
Inbound witnesses, sync witnesses, unclassified quiescence and a pending peer
nonempty identity keep blocking. Allow only the applicable committed
`CachedResponse` branch of `request_disposition` and its `replay_response`, with
the existing exact-request and live-floor checks. This adds no new request
admission, ordinary send, completion, sync or state-changing permission, and
grants no fresh liveness. Empty replies and cached responses need no write,
ordinary IV allocation or entropy.

The driver must not hold a mutable prepared-window borrow across store I/O.
Capture the owned candidate and its witness, drop the preparation, and dispatch
one CAS while retaining the live window/allocator. This leaves empty receive
available during acknowledgement loss. Reconcile the eventual exact result;
pending outbound bytes may then be replayed, and recorded effects require
current authority and idempotent recovery. No discarded token is recreated.
Test an outage longer than the independent peer's DPD timeout, with no store
progress, no IV/entropy draws and continued empty and cached nonempty replies,
then both cancelled and landed readback. Authority revocation must still stop
replies immediately.

## Negotiated restart and terminal policy

Use base reconstruction by default even when RFC 6311 was negotiated. Preserve
pending ordinary exchanges rather than making every restart abandon the peer's
work. Resume an already committed unfinished sync event with its original budget.
Otherwise consume one genuine, locally established recovery event only as a
bounded remedy for a stalled receive ID or authenticated new out-of-window
traffic. A replay or unauthenticated packet cannot create/reset an event; a
retransmission can reveal a stall only within the already established local
recovery cause. Do not infer a new failover from peer silence.

After ordinary work is resolved, a negotiated stalled SA uses sync; a base SA
commits an IKE Delete through its independent send direction. Existing pending
outbound work first completes or reaches its original protocol failure path;
never allocate a second slot. This is an automatic bounded path, not a wait for
lifetime expiry. Valid negotiated peer-initiated sync must also be answered;
there is no policy that advertises support while rejecting all peer initiation.
See [RFC 6311 §§5, 7–9](https://www.rfc-editor.org/rfc/rfc6311.html#section-5).

Initiation preserves the current ordinary-pending exclusion. Crossed sync merges
monotonic floors; interruption of unresolved work retains `OutcomeUncertain`.
The peer model must account for the peer abandoning pending requests and the
resulting inconsistent Child state. Both handlers enforce the declared window
while synchronization is pending. After a lost reply or crash, retry with a
higher proposal and fresh nonce within the same bounded event; do not replay a
persisted sync packet, refresh its budget or silently switch to base recovery.

Protocol clocks only bound sync and reservation events. The consumer clock
source reports an NTP/time step by changing its clock epoch; an epoch change,
rollback or expired deadline closes that event, never extends it. These clocks
decide no store ownership, predecessor closure or execution safety.

Write accounting follows actual transitions: base restore and empty receives
need zero IKE writes. Before any proposal or GCM reservation work, the consumer
persists the original event policy, latest observed clock and a pending-attempt
marker. This extra row CAS preserves the event even if failure occurs before an
SDK proposal exists; restart cannot substitute a new deadline, event identity or
budget. Each later attempt advances that intent before doing work, and the
proposal/cutover CAS clears its pending marker. Exact repetition of an already
persisted pending intent needs no additional intent write.

A local sync proposal and its completion need two window commits in addition to
that intent. A responder needs its intent and cutover commits. A required GCM
block adds a durable retry charge and block commit; CBC has neither block step.
Retries and explicit closure add their own commits. An unfinished intent blocks
ordinary work and has the same rollback, clock-epoch and deadline exits as an
SDK event. Once its cutover is committed, a responder event closes at its original
deadline or upon authenticated committed ordinary peer traffic. A strictly higher
authenticated proposal may then start a new event with its own bounded budget
and backoff, even if the idle peer sent only DPD between events. Before closure,
higher proposals remain retries of the original policy; an unfinished intent
cannot reset its budget. Validate the policy before creating an SDK cutover
witness, then authenticate and check proposal monotonicity before any intent or
reservation write. Do not assume every restart begins with four writes or that
retries are free.

A committed `OutcomeUncertain` or `CloseIkeSa` still revokes the epoch and causes
idempotent cleanup without a new Delete packet. This is an explicit deviation
from the Delete preference in
[RFC 7296 §2.4](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.4): the SDK's
terminal window has already removed all send authority, and inventing a new
permission would reopen a one-way failure boundary. Synchronized counters alone
do not repair uncertain operation effects. Normal, still-ready close paths use a
committed Delete; they must not reuse this exception. The peer can clean an orphan
on its protocol failure path or authenticated INITIAL_CONTACT. A store outage
alone never selects terminal closure of healthy forwarding.

## Failure classification and recovery exits

| Failure class | Automatic action |
| --- | --- |
| Store unavailable/acknowledgement lost | Keep the exact pending CAS and installed healthy forwarding. Apply the outbound-witness empty/cached-response rule; resolve by exact retry/fenced readback. No guessed success, new mutation effect or voluntary SA reset. |
| Key-provider unavailable, timeout or throttling | [#1197](https://github.com/openpacketcore/openpacketcore-sdk/issues/1197): retryable backpressure during any row seal/unseal, checkpoint creation/restore or fenced read. Preserve transient classification through the consumer wrapper until the full envelope path carries it. No uncommitted release, missing/corrupt classification or SA teardown; exhausted retry attempts do not prove key loss. |
| DH custody module or capability state | `CapabilityWithdrawn`, `NotInstalled`, `KeyGenerationFailed`, `Unavailable`, entropy failure, unsupported/unadmitted algorithms, timeouts and throttling are backpressure: retain the SA and pending checkpoint; a rekey that cannot be checkpointed waits. `IdentityChanged` and `ValidationChanged` also stop process admission and raise an alarm, without tearing down individual SAs. Only `InvalidCheckpoint`, `CheckpointPublicValueMismatch` or provider `InvalidOutput` are terminal at this boundary; revoked or positively missing keys follow the envelope rule. |
| Invalid peer KE | `InvalidPeerPublicKey`, `MalformedKeyExchange` and `KeyAgreementFailed` fail the exchange, never backpressure. An authenticated request commits `INVALID_SYNTAX` before reply release and IKE closure. A bad response commits checkpoint removal and Child SA Delete intent, or IKE SA closure for an IKE rekey. Resume cleanup after restart; never install derived keys or a successor epoch. |
| Retryable canonical refusal | `Unavailable`, `LifecycleBlocked`, `CapabilityActive` and `NotCommitted`: retain attempts/cache/identity; retry only after the known cause clears. Join an existing owner rather than constructing duplicates. A terminal lifecycle routes to cleanup, not endless retry. |
| Canonical ID unusable in this process | `AlreadyReleased` or `AttemptsExhausted`: when the window is otherwise usable, take the negotiated sync or committed base Delete path above. Never reseal, clear the ledger, reset attempts or restart a process as a workaround. |
| Epoch/profile refusal | `Invalidated`, `BindingMismatch`, `FormatUnavailable`, `QualificationFailed`, `ValidationOptInRequired` or reserved `IntegrationReviewRequired`: refuse the affected epoch/profile. Retain the qualification latch; do not cycle providers or relabel keys. Invalid trust/binding authorizes no Delete encryption with those keys. |
| Invalid canonical input/output | `InvalidRequest` drops that input without progress. `InvalidOutput` releases no bytes and retains its charge; only the existing bounded evaluation policy may retry, then the ID-failure path applies. |
| Registry sizing failure | `RegistryFull` is a capacity invariant, not a reason to evict another live epoch or drop a healthy session. Preserve existing owners, backpressure new materialization, perform eligible cleanup and report the sizing fault. Qualification includes overlap/recovery headroom. |
| Enable refused at restart | Keep the checked runtime and retry a retryable refusal after sync/old-owner resolution. A terminal profile failure follows its own row. Never treat every enable refusal as record corruption. |
| In-process runtime loss | Stop/join its executor, retain epoch ownership fencing and take exact readback before replacement. Cache bytes may be lost while release history survives; `AlreadyReleased` must reach the bounded remedy, not lifetime waiting. |
| Reconcile failure | Classify row/key-provider failures before calling SDK reconcile. `ReconcileUnavailable` retains the quiescent runtime/cache/witness for provider retry. Other existing reconcile failures revoke the epoch; they do not subsume a transient row-unseal failure. Readback never manufactures effects from an unrecognized record. |
| Authenticated unsupported shape | Report `UnsupportedShape`, retain exact cause, and commit an IKE Delete through the independent send window once pending local work resolves. Unauthenticated packets cannot select this path. |
| Terminal envelope/checkpoint failure | Authenticated-decryption failure, binding/public-value mismatch, unknown checkpoint format, provider `InvalidOutput` or a positively `NotFound`/revoked key: refuse the epoch and perform scoped terminal cleanup. Remove any checkpoint in the terminal CAS. Under [#1197](https://github.com/openpacketcore/openpacketcore-sdk/issues/1197), unavailable/timeout/throttled reads are never these outcomes. |
| Confirmed incomplete recovery history | A successfully unsealed but incomplete record cannot authorize recovery. Resolve its operation through the scoped terminal CAS, removing its checkpoint. Distinguish that evidence from an unavailable store or key provider; a newer-looking partial record alone is not recovery evidence. |

No attach ceiling, per-empty receipt row, whole-worker reset or manual recovery
step is introduced. Provider/store physical unavailability may prevent protocol
progress; it is not permission to discard healthy forwarding or emergency work.

## Endpoint changes and INITIAL_CONTACT

For a peer behind NAT when the local gateway is not behind NAT and MOBIKE is not
in use, treat only a `Fresh` request at the highest accepted ID as a candidate
address/port update. Persist a separate consumer endpoint CAS before changing
the outbound IKE/ESP destination. `Fresh` itself is not effect authority. After
restart, `Uncertain`/`Replayed` empty observations cannot update the endpoint;
use an authenticated response to this side's own genuinely new committed request
and commit its endpoint outcome. A previously pending or settled request is not
such a probe. A candidate source can receive a bounded challenge using genuine
new committed work as above, with its destination committed in the send intent;
it is not yet the accepted IKE/ESP endpoint. Match the response's source and
request identity as well as authentication before the endpoint CAS. Test a
mapping change plus replay of the prior mapping, including
the absence of fresh evidence; do not claim DPD success alone repairs the route.
This implements the freshness restriction of
[RFC 7296 §2.23](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.23).
A local gateway behind NAT does not perform this heuristic. MOBIKE peers use
their authenticated UPDATE_SA_ADDRESSES procedure and committed consumer effects.
The empty reply itself stays write-free; a changed endpoint is separate durable
work, and an unchanged endpoint introduces no write.

Decode `INITIAL_CONTACT` (16384) with zero SPI size, empty SPI and empty
notification data. Send Protocol ID zero and ignore it on receipt, as required
by RFC 7296 §3.10. Act only after authenticating the first IKE_AUTH and
validating the peer identity, including completion of any EAP authentication.
Commit the new SA and an idempotent cleanup intent for *other* SAs of that same
authenticated identity in the same local authorization namespace; retain the new
SA. The sealed intent retains the authenticated final-exchange proof independently
of the ordinary response cache, so later traffic cannot strand cleanup. Fence
each victim's exact identity/birth before cleanup. Unauthenticated,
later-exchange, malformed and cross-identity notifications cannot delete anything.
Duplicate final IKE_AUTH only replays its committed result. Honor
[RFC 7296 §2.4](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.4): do not
send INITIAL_CONTACT for identities permitted to have simultaneous independent
instances. Receiving and sending policies are separate; do not infer identity
from a shared IP address, SPI alone or unverified ID payload.

## Stored representation and fresh installation

The enclosing RFC 003 sealed record contains exact roles/SPIs/keys, immutable
typed domain, both ordinary floors, cached exchanges/outcomes, generations,
operation state, explicit sync mode and every active event/disposition/budget.
GCM also retains its IV high-water, minimum send-IV end and reservation retry
history. CBC retains its complete descriptor/marker and no GCM counter. Only a
pending initiator KE operation has a private checkpoint field in that same
enclosing envelope; responders and terminal operations have none. It is never
persisted outside the row envelope or in a nested envelope. Known empty receive
history remains volatile. Consumer fields also include both local/responder sync
intents and their pending markers, any committed endpoint challenge and its
exact request, and authenticated INITIAL_CONTACT cleanup intents/proof. A fresh
rekey epoch inherits none of these in-progress consumer operations.

Profile reconstruction requires an explicit base or negotiated-state argument;
negotiated state includes responder history and explicit event presence/absence.
The checked constructor validates it against the same authenticated immutable
agreement. There is no default-to-base on decode, and an active event cannot be
omitted. The checked constructor closes accidental omission at the call site;
the consumer codec must still preserve and authenticate every field. Optional
low-level record builders cannot detect a consumer that lies about its mode.

No SDK record layout or storage codec changes are implied. A consumer adopting
these semantics uses a mandatory new enclosing format and fresh installation,
with no compatibility reader or migration. A KE checkpoint is consumer operation
content protected by that existing row envelope, with its group, format version
and public-value binding checked on import. It is independent of module build
identity; a rolling upgrade preserves import of pending checkpoints in the same
format. Any later SDK layout change must separately declare its
fresh-install boundary. Coordinated rollback of all records still requires a
trustworthy latest store cut; validation cannot discover it from bytes alone.

## Deterministic proof and mutation checks

The public-API suite is
[`tests/recovery_profile.rs`](../../crates/opc-proto-ikev2/tests/recovery_profile.rs),
with helpers under `tests/recovery_profile/`:

- `store::CasStore` models exact request/digest retry, child birth/generation CAS,
  dispatch/apply/ack separation, pruned outcomes and committed execution fencing.
  Fenced sibling reads refuse any still-applicable queued write.
- `authority::EpochOwners` acquires ownership before either window or allocator;
  `Transport` checks the current owner while submitting borrowed bytes.
- `codec::ProfileCodec` encodes every required field in a bounded, strict,
  test-only format inside the ordinary `opc-crypto` row envelope. Omitted,
  duplicate, unknown and cross-bound fields refuse. `envelope` preserves transient
  `KeyProvider` errors before generic envelope-error collapse.
- `driver::Runtime` calls production record/window/provider APIs. `effects`,
  `child_owners` and `endpoint::Routes` re-read exact current outcomes and keep
  current owner authority through each idempotent test effect.
- `crash` starts fresh executor processes. Only sealed row images, public wire
  packets and non-secret effect identities cross that boundary. It retains no
  initiator DH handle in the parent. A child exits without running destructors;
  its replacement imports the checkpoint from the row using a changed provider
  build. Child panic reporting includes only the assertion location.

`peer::PeerModel` is independent of SDK window, sync-counter and recovery-state
transition code. It consumes released packets with its own per-direction window,
IDs, exact bytes, response cache and pending operation. `peer_epochs::Epochs`
independently authenticates both rekey directions, tracks old/competing/new SPIs,
selects the crossed winner by the four nonces, moves Child ownership and observes
Delete exchanges. Generic crypto/packet codecs are shared; expected transitions,
M2/P2 values, cache decisions and outcomes do not come from the driver. The
models have separate spec-vector and negative-wire tests, including permitted
response-cache forgetting and bounded protocol timeouts. Their clocks are injected;
wall time supplies no authority. Each child has a 15-minute wall-clock watchdog
that kills and reaps it on expiry and always fails the test. A dedicated negative
test verifies that a deliberately hung child returns a timeout failure.

### Composition cases and action mutations

Each row identifies executable coverage and a mutation in an action or admission
path. Run every selected new test on the unmutated candidate first. Then run the
same exact mutant against the existing `committed_windows`, `empty_recovery` and
`reconcile` suites and the named composition test. A compilation error is not a
kill; only a test assertion failure counts. Record both results, the exact source
and restoration. The fixture-only mutants test consumer obligations; they are
not defects attributed to the raw SDK. The cached-disposition mutation is in
production SDK code.

| Case and executable coverage | Observable oracle | Action mutation |
| --- | --- | --- |
| `delayed_cas_after_readback`: `lifecycle::delayed_cas_after_readback_cannot_replace_the_peers_committed_request` | After W2 commits, delayed W1 cannot replace the peer's same-ID request; check CAS independently of the outer stamp/sequence fence. | `store::CasStore::apply_child`: bypass exact birth/generation comparison. |
| `pruned_outcome_and_duplicate_owner`: `lifecycle::pruned_outcome_and_duplicate_owner_never_create_a_second_allocator` | Pruned receipts require a fenced latest read, and a second runtime cannot create another allocator. | `authority::EpochOwners::acquire`: accept an occupied epoch. |
| `final_ike_auth_restart`: `auth_process::final_ike_auth_restart_keeps_exact_reply_asymmetric_floors_and_one_attach` | Both original roles recover final IKE_AUTH at its actual handshake ID; exact responder replay, pending-only initiator replay and one attach effect survive process loss. | `driver::Runtime::publish_response_inner`: omit the committed inbound cache. |
| `atomic_ike_rekey_handoff`: `handoff_process::atomic_rekey_process_smoke` and its full matrix; `crossed_tests` | Old result/new epoch appear in one cut; fresh keys/IDs and inherited agreement work, crossed winner alone receives the children, and old/losing epochs survive until Delete. | `store::CasStore::apply_child`: apply only the first mutation in the old/new batch. |
| `pending_ke_restart`: `crash::pending_ke_process_smoke_with_intervening_inbound_and_iv_writes` and both full initiator/responder matrices | A pending initiator imports its checkpoint after intervening inbound/IV writes; responder restarts with exact response and derived keys, without checkpoint or new derivation. | `ke::persist_ke`: remove the checkpoint before the request/operation CAS. |
| `checkpoint_failure_and_retirement`: `checkpoint_tests::checkpoint_failure_and_retirement_backpressures_every_envelope_boundary`, actual provider import/export failures and `terminal_process` | Transient failures preserve the exchange; every non-success outcome removes its checkpoint atomically, including acknowledgement loss and process loss. | `envelope::classify_key_error`: turn `Unavailable` into key loss; `ke::settle_operation`: retain terminal checkpoint. |
| `checkpoint_upgrade_and_redaction`: pending-KE process tests and provider checkpoint tests | A changed build restores the same group/format; mismatch and unsupported capability refuse, and secret bytes never enter diagnostics. | `ke::restore_checkpoint`: require the exporting build identity. Public-value and capability mutations are in the separate provider suite. |
| `gcm_charge_block_window_crashes`: `iv_process::gcm_charge_block_window_crashes_never_reuse_an_iv_or_refund_a_charge` | Charge, block, seal, window and release cuts preserve charged attempts and discard unused reservations; replay allocates nothing. | `driver::Runtime::reserve_inner`: omit the committed exclusive IV end. |
| `sync_both_roles_and_handlers`: `sync_tests`, `sync_process` | Higher retry after lost cutover reply, crossed sync, pending-work uncertainty, ordinary traffic after recovery, and pre-proposal crash all preserve original policy and monotonic floors. | `sync_driver::validate_intent`: accept a replacement policy for an unfinished event. |
| `outage_keeps_peer_dpd_alive`: `lifecycle::outage_keeps_peer_dpd_alive_and_replays_a_cached_nonempty_response`, plus admission refusals | An outage beyond the peer timeout still permits empty and applicable cached nonempty replies with zero writes/ordinary IV/entropy; revocation stops them. | SDK `src/recovery.rs::request_disposition`: replace `ready_for_cached_response` with `ready` in the cached branch. Separate focused mutations cover the shared witness guard. |
| `lost_prefix_then_nonempty`: `lifecycle::lost_prefix_then_nonempty_commits_the_repaired_floor` | Lost/reordered empty prefix, cached replay, a fresh nonempty result and MAX exhaustion preserve the peer's independent windows. | `driver::Runtime::restore`: omit enabling empty reconstruction. |
| `cache_loss_refusal_and_shape_exit`: `remedy_tests::canonical_cache_loss_and_attempt_exhaustion_reach_sync_or_committed_delete` and SKF/cleanup tests | Actual cache loss and three invalid-output charges reach the bounded sync/Delete remedy; authenticated SKF is distinct from noise, and positive trust failure permits only scoped cleanup. | `remedy::canonical_failure`: make `AlreadyReleased`/`AttemptsExhausted` wait forever. |
| `nat_mapping_and_initial_contact`: `endpoint_tests`, `contact_tests` | Only committed fresh evidence changes routes; genuine challenge responses bind source and request; authenticated cleanup survives later traffic, excludes other identities/namespaces/new SA and refuses reincarnated victims. | `endpoint::Runtime::endpoint_empty`: accept replay as fresh; `contact::Authenticated::plan`: ignore identity; `contact::cleanup`: ignore birth or require final AUTH to remain in the ordinary cache. |
| `mode_and_effect_authority`: `effect_tests::mode_and_effect_authority_requires_current_committed_outcome_once`, `codec_tests` | Current committed outcomes apply once; candidate/stale/closed outcomes and incomplete records refuse. | `effects::Effects::apply_fenced`: bypass the idempotency entry; `codec::ProfileCodec::decode`: default an omitted mode. |

The normal matrix has 51 encryption/integrity/PRF profiles, both original roles
and both base/negotiated modes. Sync-only matrices cover negotiated mode. Full
pending-KE initiator and responder process matrices also cross all six supported
KE groups and new Child/Child rekey/IKE rekey exchange kinds. The separate rekey,
crossed-rekey, sync and terminal process matrices use each profile's configured
KE group; they do not repeat that six-group cross-product. GCM charge/block/window
cuts apply to its three key sizes; CBC has no IV reservation record.

Process matrices cover final AUTH, initiator and responder KE loss, GCM
reservation cuts, atomic rekey hand-off, local/peer sync and all non-success
checkpoint outcomes. Crossed-rekey Child ownership, endpoint changes and
INITIAL_CONTACT additionally use fenced row reopen and owner replacement in the
same process. The crossed epoch oracle has independent packet-order and nonce
vectors. Terminal schedules redeliver the explicit controller failure cause when
its CAS did not land; they do not infer terminal authority from silence or a
missing receipt. A real consumer must supply that controller contract.

The AUTH fixture validates the final AUTH against a completed authentication
context and carries the first request's identity through it. It is not an EAP,
AAA, identity-index or certificate-policy implementation. The codec, CAS store,
clock, transport and effect sinks are test models, not quorum, kernel, network
continuity, physical secret-erasure or third-party interoperability evidence.

### Existing primitive mutation baselines

These exact sites and named regressions are the baseline to run; listing them
is not a claim that a new mutation run has already passed. All paths below are
under `crates/opc-proto-ikev2`. Record each actual assertion failure and preserve
the original source before attributing additional killing power to composition.

| SDK mutation | Existing regression to run |
| --- | --- |
| `src/recovery/empty.rs::ReceiveState::accepts_new`: remove the `Reconstructing` phase condition | `tests/empty_recovery.rs::strict_empty_admission_rejects_gaps_changed_retransmissions_and_retired_ids` |
| `ReceiveState::boundary_next`: replace `live.max(recorded)` with `recorded` | `tests/empty_recovery.rs::close_commit_never_lowers_the_live_empty_receive_floor`; `tests/reconcile.rs::close_readback_preserves_live_floor_and_exhaustion` |
| `src/recovery/empty.rs::reply_empty`: omit `id.checked_add(1)` advancement | `tests/empty_recovery.rs::empty_then_nonempty_repairs_the_floor_without_a_dpd_write`; `empty_max_is_cached_but_the_receive_counter_never_wraps` |
| `src/recovery.rs::Ikev2PreparedWindow::commit_after_durable`: call `adopt_receive_boundary` for outbound commits too | `tests/empty_recovery.rs::local_outstanding_request_and_its_commit_do_not_erase_the_empty_receive_floor` |
| `src/recovery.rs::request_disposition`: remove the different-pending-request guard | `tests/empty_recovery.rs::admitted_nonempty_work_blocks_empty_reconstruction_and_changed_work` |
| `src/recovery.rs::apply_committed`: remove the `Arc::ptr_eq` instance check | `tests/committed_windows.rs::completion_tokens_are_fenced_by_runtime_instance_and_later_commit_generation` |
| `src/recovery/reconcile.rs::reconcile_checked`: discard the cache or adopt recorded floor for outbound readback | `tests/reconcile.rs::unchanged_and_outbound_request_readback_retain_exact_last_empty_reply`; `outbound_completion_readback_keeps_strict_phase_and_empty_cache` |

The pending-only replay, typed SKF, outbound-witness empty admission, mandatory
profile construction, INITIAL_CONTACT and KE custody changes need focused REDs
and restored-guard GREENs. Update the existing tests that intentionally pin the
old settled-replay, plain-SKF-drop and outbound-quiescence behavior. Distinguish
an API-absence compile failure from a behavioral RED; neither fixture stubs nor
failed compilation count as an assertion-killing mutation.

Run the focused matrices, production-library profile tests, mutations and
required final gates on each candidate. Consumer qualification must additionally cover its real CAS/codec/envelope provider, execution-fenced
transport, kernel readback/fresh-key installation and selected third-party peers.
No simulated peer/effect sink proves packet continuity, carrier scale, physical
secret erasure or unconfirmed lost-owner recovery.
