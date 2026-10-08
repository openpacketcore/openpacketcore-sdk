# opc-proto-ikev2

Transport-neutral IKEv2 mechanisms for OpenPacketCore untrusted-access work.

## Purpose

`opc-proto-ikev2` covers transport-neutral IKEv2 wire mechanisms that are safe
to expose as SDK primitives today: header decode/encode, unencrypted payload
walking, protected-payload boundaries, selected SA_INIT and IKE_AUTH helpers,
NAT detection, NAT-T datagram classification, and product-neutral Child SA
negotiation intent. It includes a strict responder boundary for opened IKE-SA
rekey `CREATE_CHILD_SA` requests and exact successful responses. It also
provides strict opened-payload primitives for the TS 24.302 multiple-bearer
profile: typed QoS/TFT/AMBR notifications, new non-rekey dedicated-bearer
Child SA establishment, bearer modification, and bearer deletion. It also
provides a typed TS 24.302 P-CSCF restoration `INFORMATIONAL` boundary for
forwarding a bounded valued IPv4/IPv6 address list and accepting only the
required empty per-family `CFG_REPLY` echoes.

It does not implement an IKE SA state machine, EAP-AKA cryptography or session
state, retransmission policy, cookie policy, Child SA lifecycle, XFRM/IPsec
programming, bearer admission or allocation policy, carrier acceptance
evidence, or a production ePDG control-plane stack.

## Message-ID synchronization primitives and pure rules

`message_id_sync` provides RFC 6311 support and synchronization Notify codecs.
`Ikev2NotifyPayloadBuild::message_id_sync_supported()` builds the IKE_AUTH
advertisement; `Ikev2IkeAuthCleartextPayloads::message_id_sync_supported()`
distinguishes absence from malformed or duplicate offers. Those errors are
diagnostic non-offers: they cannot establish sync or authorize responder
advertisement, and do not fail IKE_AUTH solely because of an invalid offer.
They do not revoke evidence from an earlier valid EAP round. `Ikev2MessageIdSync`
preserves the four-octet nonce and the sender-relative next-send/next-receive
counters: M1/P1 in a request, P2/M2 in its response. Builders emit Protocol ID
zero; receivers ignore that field for an empty SPI as RFC 7296 requires.

`Ikev2MessageIdSyncNegotiation` accumulates valid offers across protected
IKE_AUTH/EAP rounds. A ready initiator offers first; a responder waits for a
valid initiator offer. Absent, malformed or duplicate offers contribute no new
evidence. Only caller-confirmed full authentication and successful IKE_AUTH
produce an `Ikev2MessageIdSyncAgreement`. Its mode is immutable, including after
sync timeout. An authenticated same-peer IKE rekey can inherit the mode with a
fresh SPI pair and new original role, transferring no counters or pending
proposals. This inheritance is SDK policy still requiring peer qualification.

The agreement's pure rules check SA/role binding, protected INFORMATIONAL
headers, ID zero, a sole sync Notify and the exact response nonce. Counter
inputs distinguish no prior request from ID zero, retain ordinary and sync
history separately, and include a typed pending local proposal in simultaneous
maxima. Responses map peer send/receive into local receive/send; neither a
peer cutover nor a late response can roll back floors. A fresh proposal must
exceed all known used/proposed local IDs. Received M1 at or below any observed
peer ordinary request or accepted proposal silently drops, including duplicates.
The non-normative Appendix A.2/A.3 tuples are arithmetic fixtures only: their
stated histories drop under section 5.1. MAX-valued outcomes require rekey while
an ordinary ID remains, or closure after local ID exhaustion; arithmetic never
wraps. Rekey also requires an available ordinary window and IV budget.

These values are not authentication or persistence authority. Callers must
authenticate packets through the admitted IKE provider and supply same-SA
history. No automatic advertisement, nonce generation, durable commit, packet
protection, once-only response consumption or restart recovery is implemented
by the pure rules. Ordinary GCM IV reservation ordering is described below.
Production offers use the runtime readiness path described below, after the
consumer wires both handlers and their persistence/clock contracts.
ESP replay-counter synchronization is out of scope. See
[CONFORMANCE.md](CONFORMANCE.md).

## Ordinary GCM IV reservations

All ordinary AES-GCM `SK`/`SKF` sealers, including caller-chosen IVs and
`Ikev2AesGcmExplicitIvCounter`, now reject IVs at or above
`IKEV2_AES_GCM_NORMAL_IV_END` (`0xffff_ffff_0000_0000`). Peer packets may still
use the whole wire range. The upper 2^32 values belong to the frozen V1
canonical-reply builder for the whole key lifetime. No ordinary IKE sealing API in this crate can seal in
that region. The generic provider-level `IkeEncryptionOperations::seal_aead` on
`Ikev2SoftwareCryptoOperations` is an unpartitioned raw cipher primitive, not an
IKE send path. Consumers must not call it directly with SA keys; use the admitted
IKE sealers or reservation tokens. The legacy counter alone provides neither
durable ordering nor writer fencing.

`iv_reservation` adds a non-cloneable `Ikev2AesGcmIvAllocator`. Establish its
epoch through `Ikev2AesGcmEpochInputs`: both nonzero SPIs, the original-role
sending direction, the GCM profile and actual key/salt material. `fresh(inputs,
limits)` returns a `Result` and creates the immutable V1 marker before any
encryption. Use `fresh` only with new keys
whose IV history is empty; changing SPIs or making a new descriptor is not a
substitute for fresh keys. The consumer must fence one writer and must not mix
legacy/raw-IV sealing with this allocator under the same key epoch.

`prepare` burns a block locally and exposes an `Ikev2AesGcmIvRecord` without
allocating an IV. Persist its exclusive end, both directional bindings, immutable format marker
and limits atomically with the SA keys, then consume the prepared token with
`activate_after_commit` and that exact record. The SDK checks equality; the
caller supplies the durable-commit fact. Failure, cancellation or uncertainty
releases no IV. Resolve uncertain writes before an older write could roll back
a higher reservation. On restore, rebuild from the latest trusted, fenced SA
record and check the intended domain; the allocator discards the unused tail
and requires another committed reservation before allocating. There is no SDK
storage format or migration in this API.

Limits derive control headroom from maximum newly sealed outbound control
messages per attempt (at least two for IKE rekey and Delete), fragments per
message and attempts. Ordinary allocations stop at the soft threshold with
`RekeyRequired`; only bounded control traffic can consume the remaining reserve.
The hard ceiling returns `Exhausted`, requiring closure if rekey did not finish.
Limits are immutable for the key epoch. Their ceiling is at most 2^32 reserved
ordinary positions per direction key, a conservative SDK policy rather than an
RFC requirement; skipped blocks and tails count against it. Store the original
`control_budget()` and `hard_ceiling()` inputs to rebuild the same limits.

Each allocated token is consumed by `seal`, which checks the actual header,
profile, key and salt and calls the existing admitted crypto module. Dropping a
token or failing to seal burns its IV. Exact-byte retransmission needs no new
allocation. Reserve blocks during initial key setup or state-changing work;
DPD, keepalives and replies to empty requests must not initiate reservation writes.
The allocator alone provides no durable Message-ID admission or exchange commit.
The opt-in `recovery` module below adds those ordering hooks. Canonical byte
regeneration is separate from complete restart recovery and receive admission.
CBC is unchanged.

## Canonical empty-reply primitive

`canonical::Ikev2CanonicalEmptyReplies` produces the frozen 57-byte V1 reply
to an authenticated, same-binding empty INFORMATIONAL request returned by
`Ikev2CommittedWindow::open_peer`. It constructs its own header, padding and
reserved IV (`0xffff_ffff_0000_0000 + Message ID`); there are no output overrides.
The primitive neither admits a receive ID nor grants permission to transmit.
`Ikev2CommittedWindow::enable_empty_replies` and `reply_empty` compose it with
the zero-write receive handler described below.

For every reply, including cached bytes, the consumer must check current receive
admission and `Ikev2CommittedWindow::ready()` and retain send authority through
transmission. A minted capability does not follow later window lifecycle changes.
The lifecycle check alone supplies no receive admission or transmission authority.
`reply_empty` performs both checks on every call, including cache hits, and its
reply borrows the window exclusively while retained. The consumer must still
retain its external fenced SA/send authority; copied bytes carry no authority.

`Ikev2AesGcmIvAllocator::canonical_replies` requires fresh-epoch activation;
`Ikev2CommittedWindow::canonical_replies` requires checked restore. Restored
allocation alone cannot mint one.
DPD-facing windows must use `enable_empty_replies` and `reply_empty`: primitive
replies leave the window's receive floor behind and can drop the next nonempty
request. The complete IV binding and immutable `Some(1)` format marker must come
from one trusted atomic SA record. Missing/unknown markers refuse canonical use; never synthesize or
upgrade a marker for used keys. The SDK defines no durable byte format.

The process checks all eight frozen wire answers for each intended algorithm
through the admitted module once, using public test keys. Call
`Ikev2CanonicalEmptyReplies::preflight` for each configured algorithm before
accepting a deployment that will need this path. Every reply, including byte
reuse, rechecks module admission and readiness. Every newly sealed packet must
match an independently rebuilt 40-byte prefix and open to raw plaintext `00`.
Withheld outputs remain private zeroizing buffers, never logs, errors, persisted
values or Debug output; providers must observe the same confidentiality rule.

At most three evaluations and one new release are allowed per sending key,
salt and Message ID while its undeleted ledger is retained in the process.
After release, only the same capability's
cached bytes are returned. Dropping the capability or `retire(id)` discards
bytes without resetting the process ledger. `invalidate()` permanently revokes
that ledger and retains a recent deletion fingerprint. Invoke it and discard
consumer-held copies
when record trust, IV history or key provenance is lost. A changed/doubted
binding requires fresh IKE keys. Every failed `Window::restore` invalidates all
supplied bindings, even before a capability existed. Reconcile trusted mutable
state and read the window and IV records from one consistent fenced snapshot
before restore; a later corrected read cannot revive a failed epoch. Successful
runtime replacement discards the old cache but retains attempt/release history.
`reply()` returns an owned, thread-safe `Ikev2CanonicalReply` containing
57 verified octets; it holds no ledger lock. Consumer-held copies must also be
discarded when trust or send authority is lost.
Canonical packets never enter durable exchange caches or ordinary IV evidence.

The process registry uses full SHA-256 fingerprints for sending key/salt and
immutable binding, with expected O(1) hash lookup. It retains no SA
keys: the capability's key copies are zeroized when it drops. As the receive
window advances, call `retire_through(id)` below the retained reply window to
discard per-ID entries and permanently close every ID at or below that floor,
including unseen IDs. Entries above it retain their attempts and release status.
Call `delete()` on a live capability, or `delete_epoch(&iv_record)` after it has
dropped, once the SA is permanently deleted. After rekey, retain the old epoch
for permitted retransmissions until the old SA has been deleted. Deletion clears
all ID state and keeps only a recent fingerprint tombstone.

`IKEV2_CANONICAL_MAX_TRACKED_KEYS` (1,048,576) is a per-process cap on concurrently
retained live SA ledgers; they are never evicted, even if their capabilities have
been dropped. This bound must exceed the consumer's largest session count per
Pod, including old/new SA overlap and recovery headroom. Size the deployment's
maximum concurrent sessions accordingly. Only live ledgers count toward
`RegistryFull`, and deleting an SA frees its live slot. This is a concurrency
bound, with no lifetime or per-day SA limit.

Deletion and trust-loss fingerprints use a separate bounded FIFO of the most
recent `IKEV2_CANONICAL_MAX_TOMBSTONES` (1,048,576) distinct deletions. Repeated
deletion does not refresh an entry's age. The FIFO evicts the oldest fingerprint;
deletion churn never causes `RegistryFull`. Restoring a deleted SA after its
tombstone ages out requires a consumer bug and can create a fresh ledger. With
the same persisted binding it can only repeat identical V1 bytes: no different
plaintext or associated data is sealed under that nonce. The once-per-process
release rule limits fault exposure; it is not a lifetime refusal of deleted keys.
Re-admission with a changed binding already violates the key-use precondition,
with the same exposure as after process restart. Consumers must never restore
deleted records or treat tombstone eviction as permission to reuse keys. Refusal
still never enables a fallback.

The [construction and assumptions](../../docs/ikev2-canonical-empty-replies.md)
explain why repeat evaluations have identical GCM inputs. Repeating an IV after
restart deliberately departs from the literal SP 800-38D section 9.1 item 3;
ordinary reservations and committed ordinary/sync recovery retain section 9.1's
persist-ahead/discard behavior. The canonical path carries **no validated-module
or FIPS 140-3 claim**. `Ikev2CanonicalPolicy::default()` refuses a module declaring
`ValidationState::DeclaredValidated`; `explicitly_allow_declared_validated()` is
the dedicated consumer opt-in. It bypasses neither qualification, module policy
nor packet checks. General module admission is not canonical opt-in.

### Constructor migration

| Former public use | Replacement |
| --- | --- |
| `Ikev2AesGcmIvDomain::new` for initial allocation | `Ikev2AesGcmIvAllocator::fresh(Ikev2AesGcmEpochInputs { ... }, limits)?`, then `allocator.domain()`. |
| `Ikev2AesGcmIvDomain::new` for a restore expectation | Use `window_record.domain().send_iv_domain()` from the separately persisted, trusted window record when restoring its IV allocator; see the cross-check below. |
| `Ikev2AesGcmIvRecord::from_persisted(domain, limits, end)` | `from_persisted(epoch_inputs, limits, end, persisted_marker)` with both keys and all fields from that same atomic record. |
| `Ikev2CommittedWindowDomain::new(...)` | `Ikev2CommittedWindowDomain::from_iv_record(&iv_record)` for initial window assembly; restore uses the persisted window domain and cross-checks the IV record. |

Both domain `new` functions are now crate-private. Borrowed epoch inputs and
raw established keys confer no canonical capability or historical-key proof.
A successful constructor cannot make an untrusted record safe.

`Allocator::restore(iv_record.domain(), &iv_record)` only compares the IV record
with itself; it is not an independent binding check. The canonical restore
guarantee comes from `Ikev2CommittedWindow::restore`: it compares the complete
window domain, the separate IV record's two directional domains and marker, and
the supplied profile/keys. Both records must come from the same latest trusted
atomic SA snapshot. For example:

```rust,ignore
let window = Ikev2CommittedWindow::restore(
    window_record.domain(), profile, &keys, &window_record, &iv_record,
)?;
let allocator = Ikev2AesGcmIvAllocator::restore(
    window_record.domain().send_iv_domain(), &iv_record,
)?;
```

These consistency checks cannot detect joint rollback or establish key provenance.

Canonical refusal leaves empty requests unanswered: there is no ordinary-IV or committed
window fallback. A V1 epoch answers them only with V1, or not at all.
DPD-sending peers remain unsupported in durable deployments where canonical
sealing cannot operate, including declared-validated modules without opt-in,
unqualified modules and known-answer failures. The consumer must refuse such
a configuration up front, checking canonical policy and qualification for the
intended algorithms before accepting those peers. A later runtime refusal
still withholds the reply and never enables a fallback.

## Committed ordinary windows and exact replay

`recovery::Ikev2CommittedWindow` is an opt-in window-one profile for complete,
unfragmented AES-GCM `SK` packets. It uses the admitted crypto module, binds both
sending and receiving keys/salts plus the SPI pair and original role, and works
with all three supported GCM key sizes. `SKF` and CBC recovery are outside this
profile. Empty handling is opt-in and includes prefix reconstruction after restore.
Existing generic crypto and fragmentation APIs retain their separate contracts.

Commit an initial `Ikev2CommittedWindowRecord` with the new key epoch and correct
post-handshake floors, then `restore` from the latest trusted fenced record.
Zero means no prior request; an exhausted direction is explicitly `None`.
Supply the latest sending `Ikev2AesGcmIvRecord` to `restore` as well. Restore
validates cached packet authentication, directions, exchange correlation and
counter consistency, and requires the sending-IV record's `exclusive_end` to
exceed the IV in every cached outbound request and inbound response. Peer IVs
belong to the other key and do not constrain this high-water. Restore the IV
allocator from that same record, discarding its unused tail. This cross-check
detects inconsistency visible in the cache; it cannot detect rollback of both
records or prove the absence of forgotten IV use.

Consumer serialization uses the record accessors and
`from_persisted` constructors; this module defines no store format. Never seed
it from a legacy window snapshot or an unknown IV history. The legacy responder
window accepts forward gaps and is insufficient for this durable profile.

Prepare a local request with a slice-3 single-use IV allocation. Persist the
exact candidate record atomically with the SA and operation, then acknowledge
it with `commit_after_durable`. Only then may `replay_request` release the exact
packet. One outbound request remains pending until an authenticated matching
response and consumer-validated outcome are committed. Outcomes are opaque
consumer state; committing a packet does not establish application success.

For peer requests, authenticate with `open_peer` and inspect
`request_disposition`. Returning `New` locks that exact request as pending work
for both sync directions, even before response preparation. In strict mode, only
the exact live expected ID or the exact last applicable cached request is
admitted. Plan a new request's result without effects, prepare its
exact response, and commit the response/outcome/floor together before effects or
sending. This also applies to error replies and empty acknowledgements of
nonempty operations. Storage failure grants no new reply, including
`TEMPORARY_FAILURE`. A cached duplicate replays the last applicable response;
same-ID different bytes, older cached entries and forward gaps are dropped.
An older cached response ceases to apply once a newer empty reply advances the
live floor or a newer nonempty request is admitted. `replay_response` is a
read-only lookup: a miss does not admit work or alter sync history.
Any sync Notify is excluded from ordinary state, including ordinary Message ID 0.

Prepared record accessors exist for persistence, not transmission. Equality of
an acknowledgement checks identity, not durability. Cancellation, failure or an
uncertain commit leaves the runtime quiescent. Fence/settle all older writes,
read back the latest atomic record, and replace the runtime with `restore`.
Read the window and IV records from one consistent fenced snapshot before
restore. For empty handling, then call `enable_empty_replies` to recover the
lost zero-write prefix as described below. A refused enable preserves the
checked runtime for retry after a pending sync completes or the old capability
drops. In-process replacement currently discards the last empty reply's cached
bytes but retains its release history. Retrying that ID returns
`Canonical(AlreadyReleased)`. If that reply was lost, the peer may stall until
synchronization or expiry. This is a known limit on reply retention under
[RFC 7296 §2.3](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.3);
the planned in-place readback API will retain the same capability and cache.
Do not guess whether an uncertain write committed. IVs already consumed by
preparation remain burned. Completion tokens are single-use and must pass
`apply_committed` in the same runtime/current commit generation; restoration or
a later commit fences them. The consumer applies durable outcomes idempotently;
restoration reads history and never manufactures a fresh completion.

A probe replays the last committed request, pending or settled, with no new
Message ID, IV, durable write or outcome. Without such a request there is no
artificial probe. Replies to old bytes do not establish fresh liveness. Empty
INFORMATIONAL requests are refused as durable work; use `reply_empty` below.
Keepalives remain outside IKE windows. Negotiation alone grants no fresh-DPD
bypass or permission to reserve an IV for one.

### Zero-write empty requests and restart reconstruction

Before accepting DPD-sending peers, qualify each intended algorithm with
`Ikev2CanonicalEmptyReplies::preflight` and the deployment's canonical policy.
After checked window restore, call `enable_empty_replies(policy)`. While a
capability is held, another enable
returns `Canonical(CapabilityActive)` without revoking it. For a restored
`AwaitLocalSync`, finish and commit the sync result, then enable. Lifecycle and
capability-active refusals leave the epoch intact and can be retried on the
same checked runtime once the cause clears.
The window owns that epoch's capability; do not mint a second one independently.
Authenticate each complete peer packet with `open_peer`, then pass an empty
INFORMATIONAL request to `reply_empty`. Every call rechecks current module
admission, window `ready()` and receive admission, including byte-cache hits.
Submit the returned `Ikev2EmptyReply` promptly while retaining it and the
external fenced authority through transport submission. SDK lifecycle changes
cannot occur while that reply borrows the window. Discard copied bytes on trust
loss, teardown or a blocked lifecycle.

An admitted request at ID `n` receives the canonical response and advances
`window.next_receive()` to `n+1` without an IV allocation, entropy request,
durable write, generation change or operation outcome. The persisted
`window.record().next_receive()` stays unchanged. A following nonempty request
at `n+1` is admitted normally and commits its response, outcome and repaired
floor atomically. Empty acknowledgements of nonempty requests, including
Delete, always use that ordinary committed path.

The declared receive window is one: never send `SET_WINDOW_SIZE` on an SA using
these windows. Within a runtime, retransmission requires
the identical authenticated request bytes and reuses the same canonical reply
without sealing again. A newer empty reply or pending nonempty request retires
older applicable responses;
canonical ledger entries below the retained window are compacted automatically.
The window remembers at most one empty request identity and one pending
nonempty identity. A canonical failure retains the request identity and charged
attempt history but advances no receive counter or liveness authority. There
is no ordinary-IV, storage or alternate-provider fallback. `u32::MAX` exhausts
the receive direction without wrapping; independent outbound work still uses
its own request window.

After a restart, first fence and resolve all outstanding writes and obtain the
latest trusted atomic SA/window/IV record. Enabling empty replies after `restore`
automatically permits authenticated IDs above the saved floor to repair a
forgotten zero-write prefix. Restore followed by enable is the only composed
entry path. No enabled restored window can opt out of
prefix recovery. Plain restore without empty handling retains strict admission;
enabling after a new inbound or sync boundary commits also stays strict.
Reconstruction never lowers the committed or declared floor or bypasses pending or
terminal synchronization. Older replayed empty IDs cannot pin reconstruction
below a later valid peer request. The first admitted nonempty request locks its
exact identity; further empty or changed work is blocked until its response and
outcome commit, or sync resolves the interruption. That commit ends
reconstruction and restores strict admission. Outbound commits preserve the
volatile receive prefix. Admitted empty and nonempty IDs automatically join
RFC 6311's volatile drop history, even when canonical output is withheld.

`Ikev2EmptyReplyObservation::Replayed` and `Uncertain` establish no fresh
liveness. Restore may have forgotten an unwritten empty prefix,
so it starts uncertain. `Fresh` is possible only beyond a new inbound boundary
or synchronization cutover committed in the current runtime. These observations
never authorize endpoint, key, bearer, lifetime or application-outcome changes.
Outbound liveness checks remain replay-only. An idle peer's DPD after restart
remains `Uncertain` until a nonempty exchange or sync boundary commits, so a
consumer cannot require `Fresh` from DPD alone to recover liveness.
The recovery extension is SDK policy justified by the trusted durable history;
RFC 7296 does not specify crash reconstruction. Its relevant protocol rules are
[§1.4](https://www.rfc-editor.org/rfc/rfc7296.html#section-1.4) (empty
INFORMATIONAL requests and responses),
[§1.4.1](https://www.rfc-editor.org/rfc/rfc7296.html#section-1.4.1) (Delete
acknowledgements), [§2.1](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.1)
(identical retransmissions and reply retention),
[§2.2](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.2) (Message IDs),
[§2.3](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.3) (independent
request directions and the default window of one), and
[§2.4](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.4) (liveness).

Every permanent consumer teardown calls `window.delete()`: peer Delete after
its ordinary acknowledgement, local expiry, DPD timeout, RFC 6311
`OutcomeUncertain` or `CloseIkeSa`, and deletion of the old SA after rekey.
Retain the old epoch during permitted rekey overlap. Every window restore
failure already revokes canonical state for the supplied bindings. A later
recoverable enable refusal is not a restore failure. If decoding or record
rebuilding fails before window restore, call
`Ikev2CanonicalEmptyReplies::delete_epoch(&trusted_iv_record)` without a window.
In every failed-restore or deletion case, discard outer keys, stored SA records
and copied replies; never retry that discarded epoch. Dropping a runtime to perform
fenced readback is not permanent SA deletion and does not free its live ledger.
Timers, transport, peer operation semantics and teardown dispatch belong to the
consumer; the SDK supplies the common deletion hook.

### Responding to negotiated RFC 6311 synchronization

Attach `Ikev2SyncResponderRecord` to the trusted window record with
`with_sync_state`, and persist it atomically with all other SA/window fields.
It retains the immutable agreement, known ordinary/proposal history and ordinary
traffic disposition. `Ikev2MessageIdSyncAgreement::from_persisted` rebuilds an
already authenticated agreement; it does not establish bilateral offers or let a
consumer change modes. Window restore binds its original role and SPI pair to
the expected key domain and checks history against floors and cached requests.
Never omit existing sync metadata during readback or relabel unknown history.
For a generation-zero window, seed each highest ordinary-request ID from its
completed handshake floor minus one; use `None` only when that floor is zero.
The trusted constructors do not infer missing handshake history. The enclosing
stored format must require all persisted sync/recovery fields: omitting
`with_sync_state` can produce a structurally valid ordinary-only record and is
not detected by these hooks.

Call `begin_sync_response` before allocating an IV or creating reservation work.
It authenticates complete peer GCM `SK` packets through the admitted provider and
requires negotiated mode, the matching SA/original direction, INFORMATIONAL
request at ID zero, and exactly one sync Notify. Bad, unnegotiated and duplicate
requests drop without freezing the window or allocating an IV. Both original
roles can respond. `SKF` and CBC recovery remain unsupported.

Admission returns an exclusive capability and freezes ordinary work. The caller
must supply `prepare` a committed single-use **Ordinary** IV allocation to seal
the fixed nonce-echoing P2/M2 reply; it does not reserve a block. When a new block
is necessary, use the bounded reservation guard below with the same recovery
operation, fixed deadline/backoff and at most three fresh-block attempts across
restart. Allocation tokens carry no purpose: supplying **Control** would spend
the rekey/Delete reserve. Persist one guard identity per SA key epoch and peer
recovery event with the enclosing window state, and reuse it for every
re-admission until a cutover lands. A `Closed` guard permits no reply; the peer's
own recovery budget then decides its SA's fate. A duplicate packet cannot
manufacture a new operation or replenish that budget.

Persist `Ikev2PreparedSyncResponse::record()` and the consumer's operation
dispositions together, then acknowledge the exact record with
`commit_after_durable`. Consume its one-use token with `release_sync_response`
before any later commit. Only this releases reply bytes and disposition.
The cutover commits new floors, the highest accepted peer M1 and a new ordinary
generation; it retires ordinary replay caches and fences old completion tokens.
Its `minimum_send_iv_end` retains the largest locally sent cached/attempt/reply
IV plus one across successive cutovers. Persist and restore this field even
when the caches are empty; window restore refuses a lower sending-IV record.
Rolling back both records together remains undetectable.
Below-window, above-window and retired cached requests cannot bypass the newly
declared receive window. Preserve already committed outcomes as idempotent
consumer history in the same durable SA state.

The responder does not wait for pending network replies. Pending outbound work
and inbound requests admitted as `request_disposition(New)` are detected from
the window automatically. Use `pending_inbound` for additional semantic work
admitted outside that SDK path; omitting it cannot hide SDK-admitted work.
Such work becomes `OutcomeUncertain`, which
blocks ordinary traffic and requires idempotent scoped cleanup of this IKE SA and
its Children, including `window.delete()`. It never reports application success
or permits retrying the mutation under a new ID. A simultaneous local
`Ikev2MessageIdSyncPending` instead
contributes its declared floors and retains `AwaitLocalSync` until the initiating
lifecycle completes. When initiating history is attached, the responder uses its
durable pending proposal automatically; an explicit argument must match it.
Omitting the argument cannot unblock that state or discard its floors.
The terminal window currently releases cleanup disposition only and has no
Delete preparation path. Local-only closure leaves the peer to its own liveness
or expiry, or the consumer's base-protocol invalid-SPI handling. Composed recovery
qualification must decide whether to add one narrowly committed Delete using
Control headroom or keep that local-only policy.

Cancellation, failed sealing or uncertain/mismatching commitment leaves the
window quiescent. Fence/settle old writes and restore the latest window and IV
records; discard the unused IV tail. A landed cutover never recreates its reply
permission. Sync replies are not cached: M1 at or below known peer ordinary or
accepted-proposal history drops, even with a different nonce or after restart.
Lost replies require the peer's higher fresh proposal.

The drop floor deliberately excludes a peer's response P2 as a separate bound.
A request withheld during simultaneous sync can therefore remain admissible
before ordinary peer progress, but counter adoption only moves forward. This can
trigger scoped cleanup if new mutations are pending. A minimal proposal M1 = P2
remains admissible unless actual ordinary/proposal history rejects it.
`request_disposition(New)` automatically retains the authenticated request's ID
in the volatile sync drop floor. The consumer need not call an observer for this
safety check. `reply_empty` also records admitted IDs, including reconstruction
and withheld canonical evaluations. `observe_request_for_sync` only records an
expected authenticated request; it grants no reply, liveness or receive-floor
advancement and does not replace empty handling.
After restart, empty requests answered only in memory cannot contribute to the
drop floor until admitted again under the recovery rules above.

### Initiating negotiated RFC 6311 synchronization

`begin_sync` admits one genuine local recovery event after pending ordinary
mutations have been resolved. Pending outbound work and inbound requests admitted
as `request_disposition(New)` are detected automatically and refuse initiation.
Report additional semantic work admitted outside that SDK path through
`pending_inbound`; omitting it cannot bypass the SDK's pending-work check.
Peer-initiated sync keeps the different interruption
policy described above. Invalid packets, silence and replays cannot create an
event. Consumer event identities increase within the same key epoch.

Fix an `Ikev2SyncRecoveryPolicy` with that identity, original clock sample,
exclusive deadline, positive retry delay and at most three proposals total.
Admission freezes ordinary traffic before allocation. Its `prepare` generates a
four-octet nonce only through the admitted module's entropy service, checks up to
four draws against every nonce in this event's bounded history, and seals with a
committed **Ordinary** IV allocation. It accepts no consumer nonce or RNG. Use the
same event's bounded reservation guard when another block is needed; failed
proposal writes never refund fresh-block charges.
Choosing Ordinary remains the caller's obligation here too; the token carries
no allocation purpose.

Persist the complete `Ikev2PreparedSyncInitiation::record()` atomically, including
the attempt count, pending proposal, exact protected request, clock/policy and
`AwaitLocalSync` disposition. Acknowledge with `commit_after_durable(record, clock)`
using a fresh clock sample, then consume its token through `release_sync_action`.
Only `SendRequest` releases request bytes. Stored-byte accessors are serialization
inputs, not send authority. Releasing a request rechecks the deadline.

`complete_sync` authenticates the current live proposal's response, exact nonce,
SA/role/class and non-undercutting counters. It merges component-wise maxima
with concurrent peer cutovers. Commit that result before ordinary traffic resumes.
A result admitted within the deadline stays `Recovered` when its commit lands,
even if storage acknowledges after expiry or a clock step; restore reaches the
same disposition. The acknowledgement clock check applies only to `SendRequest`.
RFC 6311 §8.1 uses strict mode: every ordinary
request, response, replay and completion is blocked while local sync is pending;
after completion only the committed ordinary window is admitted. Old caches and
completion permissions cannot bypass it. `Recovered` is counter synchronization,
not application-mutation success or repeatable liveness evidence.

Request loss, response loss and uncertain restoration use `retry_sync` after the
original positive delay: a higher M1, fresh nonce and new IV-backed bytes, within
the same count and deadline. No exact sync retransmission API is exposed. Restore
preserves all consumed attempts but grants neither old send permission nor old
response-completion authority; a higher fresh proposal is required. The responder
can still merge that persisted pending proposal during simultaneous sync.
Trusted pending/attempt/recovery constructors validate history and floors;
window restoration authenticates all stored attempts and checks nonce/packet
identity, increasing IVs and the sending-IV high-water. Never omit existing
recovery fields or replace the policy on readback.

`Ikev2SyncClock` names UTC milliseconds since the Unix epoch, with CLOCK_REALTIME
semantics and a persistent clock-continuity epoch. The consumer's clock service
changes that epoch on a step in either direction or unknown continuity across
restart. A changed epoch, observed rollback, expiry or exhausted budget closes
the event; it never extends time or selects fallback. Schedule
`check_sync_deadline` even without incoming traffic. Pass epoch mismatch as the
reservation guard's clock-step indication, retaining its original deadline.

`close_sync` commits terminal IKE/Child cleanup before releasing `CloseIkeSa`.
The consumer finishes scoped cleanup and calls `window.delete()`.
It can abandon any `AwaitLocalSync` window, including one entered through a pure
pending proposal without an initiating record. A late or stepped request
acknowledgement adopts the landed proposal but latches closure and emits no
request. Retain expiry/step decisions for pending events across crashes and
readback, and finish idempotent closure. A landed `Recovered` result needs no
additional closure write due to acknowledgement latency or a later clock step.
Uncertain writes still require fencing and latest readback before any retry.

### Runtime readiness for support offers

Before IKE_AUTH, a fresh initial GCM window can mint `Ikev2SyncReadiness` with
`sync_readiness`. It checks the key domain/profile and current admitted encryption
and entropy. Consume it with `negotiate`; `local_offer` rechecks admission and
emits support only under the original-role/EAP offer rules. `observe_peer` takes
an authenticated same-domain ordinary packet, and `finish` still requires the
consumer's full IKE_AUTH authentication result. Active/negotiated windows cannot
mint new handshake readiness. The pure `locally_ready` boolean and generic Notify
builders do not replace this production path.

This capability covers the two complete-GCM sync handlers. It does not establish
consumer storage correctness, canonical empty-reply readiness, fragmented/CBC
recovery or complete restart-recovery qualification.

### Bounded IV reservation attempts

`Ikev2ReservationRetry` adds ordering for genuine state-changing operation work.
Persist an operation identity and immutable `Ikev2ReservationRetryPolicy` with
its start, fixed Unix-millisecond deadline, positive backoff and at most three
fresh-block attempts (a consumer may choose fewer). The operation and policy
survive restart; a replay, outage or restart cannot create a replacement budget.

`prepare_attempt` exposes an attempt charge without preparing or burning a
block. Persist that charge first, then consume `commit_after_durable`'s one-use
permit to `prepare` a block. Persist its exact IV high-water with the same SA and
already charged operation, and call `activate_after_commit` after another clock
check. Never overwrite the charge with stale operation fields. Every fresh block
attempt consumes a charge, including cancellation before block preparation.

An active block refuses a new attempt without charging it: there is no
reserve-ahead. Once the block is depleted, the message needing a new IV waits for
both commitments. Failed or uncertain charge/block writes quiesce the guard;
reconcile both records and all old writes before restoring and retrying. Restore
discards unused IV tails and permits, retaining charges, deadline and backoff.
The caller schedules backoff; the SDK starts no retry loop. Do not bypass the
guard with raw allocator calls for the same operation. `Ordinary` and `Control`
remain the existing exhaustive purpose enum; control is still limited to the
caller's bounded rekey/Delete traffic.

Provide a clock-step indication for either forward or backward discontinuity,
including steps across restart; retain it until that operation is terminal.
Observed rollback, deadline or budget exhaustion returns `Closed`, which must
terminate the operation, never refresh its policy. Record terminal disposition
in the consumer's lifecycle or close the affected SA. This guard is not a clock
service or a complete recovery lifecycle. Replays, DPD, keepalives and replies to
empty requests cannot initiate reservation writes.

## NWu payload profiles

`nwu` adds the TS 24.502 V18.8.0 configuration and opened Child-SA payload
profiles tracked by #786. It supports empty per-family CFG_REQUEST attributes,
correlated CFG_REPLY/NAS endpoints, complete QoS associations and additional
QoS parameters, one applicable UP address, network-initiated creation with
all-packet selectors, full replacement modification, and explicit NWu deletion.
`PendingModification` distinguishes acceptance, rejection, and ambiguous timeout;
`PendingChildDelete` requires the ordinary/crossed received-SPI echo.
`PendingIkeDelete` uses Protocol ID 1 with no SPIs and an empty response.

`AeadPolicy` tries the caller's ordered `AeadSuite` list before peer proposal
order and emits no integrity transform or fallback. Existing
`Ikev2SaInitNegotiationPolicy` supplies ordered whole-IKE-suite selection.
No default downstream suite list is included. Opened payload helpers
return intent only; protection, key custody, replay admission, roster authority,
retransmission scheduling and backend operations belong to their own boundaries.

MOBIKE_SUPPORTED is conditional on the original IPv4 request and UE support.
`nwu::mobike::Responder` authenticates exact UDP/500 or UDP/4500 datagrams using
the concrete IKE provider, binds the established SA and shared message-ID
windows, and checks explicit caller address policy. An update produces IKE
path intent; Child-SA migration additionally requires an unpredictable COOKIE2
probe answered on that exact path. Older probes cannot apply superseded
updates. NAT detection reuses the admitted SHA-1 boundary; source addresses,
cookies and crypto inputs remain absent from diagnostics.
This does not close #786 or establish external interoperability. See
[CONFORMANCE.md](CONFORMANCE.md#nwu-payload-profile) for exact scope and evidence.

## API Shape

- `protocol_key` imports zeroizing K_N3IWF into an opaque association and
  pending operation, then consumes it once for both directional IKE_AUTH MICs
  through the admitted IKE module. Lifecycle retirement clears custody and
  the handle exposes no key bytes. See [the contract and evidence](PROTOCOL_KEY.md).
- `Message<'a>` and `OwnedMessage` provide borrowed and owned IKEv2 messages.
- `header` exposes `Header`, `HeaderFlags`, `decode_header`, and
  `encode_header`.
- `payload` exposes `PayloadChain`, `RawPayload`, `RawPayloadIterator`,
  `PayloadType`, and ordinary or detailed payload-chain validation. The
  detailed boundary retains only an unknown critical payload's exact type and
  bounded chain offset; it never retains the payload body.
- `Ikev2EapPayload::project_aka` explicitly opts a complete EAP payload into
  the canonical `opc-proto-eap` Type 23/50 parser. It returns only bounded,
  redaction-safe structural evidence. Generic EAP packets remain opaque.
- `validation` exposes `Ikev2ValidationProfile`, separating conformant network
  receive behavior from opt-in sender-canonical fixture validation.
- `crypto` defines the caller-supplied `CryptoProvider` boundary and protected
  payload open result types. An arbitrary implementation is not covered by
  process-module admission; validated deployments use the module-routed
  `Ikev2SaInitProtectedPayloadProvider` or an adapter whose identity is bound
  to their admitted module. Direct caller crypto invalidates SDK admission
  claims rather than gaining them from a slot-presence check.
- `certreq` validates one bounded, exact DER X.509 `SubjectPublicKeyInfo` and
  computes its RFC 7296 section 3.7 Certification Authority identifier through
  the admitted IKE hash operation. The result has redaction-safe `Debug`.
- `pre_admission` performs one deliberately narrow configuration operation
  before the process module is installed: bounded, exact-DER inspection of
  unencrypted ECDSA P-256/P-384 PKCS#8. It returns the exact typed
  signature-generation requirement and deterministic public SPKI identity,
  and can require an exact match with a bounded DER leaf certificate. It
  retains no private-key handle and cannot sign. Its RustCrypto secret-key
  object and separate public-point derivation scalar are explicitly zeroized;
  certificate trust and every actual key load/sign operation remain
  caller/module-owned.
- `sa_init`, `sa_init_crypto`, and `sa_init_negotiation` provide typed
  SA/KE/Nonce/Notify helpers, SA_INIT response builders, product-neutral
  responder proposal selection, Diffie-Hellman group/profile types, and
  IKE/Child SA key-material derivation. IKE-SA profiles preserve the complete negotiated
  PRF, DH, encryption/key-size, and optional integrity suite; invalid AEAD plus
  integrity or CBC without integrity combinations cannot be constructed.
  PRF-HMAC-SHA1 and PRF-HMAC-SHA2-256/384/512 are supported for initial IKE-SA
  derivation, IKE-SA rekey (including distinct old/new PRFs), Child-SA KEYMAT,
  restore, and AUTH calculations. MODP-768/MODP-1024 and HMAC-SHA1 are explicit
  legacy-interoperability choices and are never inserted into caller policy.
  Child-SA profiles additionally support ENCR_NULL (11) with a mandatory
  separate supported integrity transform and exactly zero
  encryption/salt KEYMAT octets. The notify-only error builder is deliberately bounded to
  one IKE-SA-shaped `UNSUPPORTED_CRITICAL_PAYLOAD`, `NO_PROPOSAL_CHOSEN`, or
  `INVALID_KE_PAYLOAD`. Typed convenience builders write the offending payload
  type as exactly one octet or the accepted non-zero group as exactly two
  big-endian octets. These failures are mutually exclusive, so the builder
  rejects a multi-Notify response rather than emitting ambiguity.
- `protected_payload_crypto` provides caller-keyed AES-GCM-16 and
  AES-CBC/HMAC encrypt-then-MAC `SK`/`SKF` open/seal helpers for
  already-derived SA_INIT key material. Production CBC sealing obtains a fresh
  16-octet IV from the admitted module's `ApprovedEntropy` operation; callers
  cache the complete already-sealed response for retransmission.
- `ike_auth` and `ike_auth_signature` provide cleartext IKE_AUTH payload
  helpers, shared-key AUTH MIC helpers, signature AUTH helpers, and Child SA
  selector/proposal helpers. RFC 7427 method 14 signing and verification
  require distinct signing and verification authorities. They can only be
  minted after the exact correlated SA_INIT request/response bytes prove both
  `SIGNATURE_HASH_ALGORITHMS` offers, both validated Nonce payloads, and current
  crypto-module admission.
  For RFC 5998, call
  `Ikev2IkeAuthCleartextPayloads::eap_only_authentication()`: absence is
  `Ok(None)`, exactly one canonical Protocol-ID-zero/empty-SPI/empty-data
  Notify is `Ok(Some(_))`, and malformed or duplicate type-16417 occurrences
  are typed errors. Duplicate diagnostics retain only canonical/malformed
  counts and the first structural reason; the lossless raw Notify views remain
  available separately in `notifies`.
- `ike_sa_rekey` strictly decodes authenticated/opened `SA, Ni, KEi`
  `CREATE_CHILD_SA` requests, selects an existing executable IKE-SA profile,
  and builds an immutable exact `SA, Nr, KEr` response chain. It rejects
  Child-SA protocol/SPI shapes, `REKEY_SA`, traffic selectors, `DH=NONE`, and
  KE/group mismatches without owning SPI allocation or IKE-SA lifecycle state.
- `device_identity` validates and builds TS 24.302 DEVICE_IDENTITY requests and
  responses using the redaction-safe exact-15-digit `Imei15` and `Imeisv`
  types. TBCD decoding preserves the received fifteenth IMEI digit (including
  a spare zero or non-Luhn digit) and enforces the terminal filler nibble.
- `notify` exposes the TS 24.302 private error value
  `IKEV2_NOTIFY_AUTHORIZATION_REJECTED` (9003). Construct its canonical
  Protocol-ID-zero, empty-SPI, empty-data body with
  `Ikev2NotifyPayloadBuild::authorization_rejected()`, encode it through
  `build_ike_auth_notify_payload`, and recognize its empty-SPI/empty-data
  receive shape with `Ikev2NotifyPayload::is_authorization_rejected()`.
  Consistent with RFC 7296 section 3.10, receive recognition ignores Protocol
  ID when SPI Size is zero. Choosing this outcome from Diameter or local
  authorization state remains product-owned.
- `notify` also exposes
  `decode_ikev2_eap_only_authentication_notify` for classifying one RFC 5998
  Notify without collapsing malformed type-16417 values into absence. Build
  the canonical sender value with
  `Ikev2NotifyPayloadBuild::eap_only_authentication()`. Whether the negotiated
  EAP method is mutually authenticating, key-generating, and resistant to
  dictionary attacks remains product-owned policy.
- For TS 24.302 P-CSCF restoration capability, `notify` exposes private status
  type `IKEV2_NOTIFY_P_CSCF_RESELECTION_SUPPORT` (41304) and the strict
  `decode_ikev2_pcscf_reselection_support_notify` classifier. It accepts only
  Protocol ID zero, SPI Size zero, empty SPI, and empty notification data;
  malformed matching values return stable payload-free errors while unrelated
  Notify values remain distinguishable. Build the canonical four-octet body
  with `Ikev2NotifyPayloadBuild::p_cscf_reselection_support()`. Deciding
  whether to relay this authenticated UE capability into PCO or APCO remains
  product-owned policy.
- `dedicated_bearer` implements the TS 24.302 multiple-bearer Notify values and
  strict opened-payload views/builders for dedicated-bearer `CREATE_CHILD_SA`
  and `INFORMATIONAL` modification/deletion exchanges. TFT values use the
  canonical `opc-proto-tft` TS 24.008 codec shared with GTPv2-C. Response
  correlation checks the IKE SPIs, Message ID, exchange/flags, selected offered
  proposal/transforms, optional KE group, and traffic-selector narrowing.
- `pcscf_restoration` builds a canonical single-CP `INFORMATIONAL`
  `CFG_REQUEST` that preserves every PGW-provided typed IPv4 and IPv6 P-CSCF
  address in exact order, including repeated entries, and encodes its exact RFC
  7651 value. The configuration-attribute types default to the RFC 7651
  registered pair 20/21; `Ikev2PcscfAttributeTypes` lets a caller name a
  private-use pair instead, for peers that negotiate P-CSCF on private-use
  types (16384-32767) rather than on 20/21. Each family accepts only its
  own registered type or a private-use type, so the procedure cannot squat on
  an unrelated registered attribute or on an unassigned code point. Its strict opened-reply decoder rejects absent, repeated, or
  valued known P-CSCF attributes while retaining unsupported Configuration
  attributes, Vendor IDs, unfamiliar status Notify payloads, and unknown
  non-critical payloads. Error-range Notify and unknown critical payloads fail
  closed. Correlation requires one empty acknowledgement per requested family
  plus matching IKE SPIs, exchange type, Message ID, and direction. Address and
  request `Debug` output is redacted.
- `fragmentation`, `notify`, `nat_detection`, `nat_traversal`, and `exchange`
  expose RFC-specific mechanism helpers without owning product state.

## RFC 7427 signature-hash negotiation

`Ikev2SignatureHashLocalOffer` encodes a canonical type-16431 Notify and
preflights every advertised hash against the installed process crypto module's
admitted verification algorithms. The receive boundary preserves every
standardized, unassigned, and private-use identifier in wire order. It accepts
at most 64 identifiers and rejects reserved zero, empty or odd-length data,
duplicate identifiers or Notify occurrences, a nonzero Protocol ID, or a
nonempty SPI shape.

Negotiation consumes both complete SA_INIT messages, checks their request and
response shape, SPI/message correlation, required payloads (including exactly
one valid Nonce in each message), and absence of trailing bytes, then retains
both exact nonce values and recovers both offers from those exact transcripts.
It computes two independent sets:

- hashes offered by the peer that the admitted local signing path can use;
- hashes sent locally that the admitted local verification path can accept.

RFC 7427 explicitly permits those sets to differ. A local SHA2-256 offer and a
peer SHA2-384 offer therefore authorizes the peer to sign with SHA2-256 and the
local peer to sign with SHA2-384; no common bidirectional hash is required.

```rust
use opc_protocol::DecodeContext;
use opc_proto_ikev2::{
    compute_ike_auth_signature, negotiate_ikev2_signature_hash_algorithms,
    verify_local_ike_auth_signature, Ikev2AuthenticationPayload,
    Ikev2SignatureHashAlgorithm, Ikev2SignatureHashLocalOffer, Ikev2SignatureHashLocalRole,
    IKEV2_AUTH_METHOD_DIGITAL_SIGNATURE,
};

# fn example(
#     profile: opc_proto_ikev2::Ikev2SaInitCryptoProfile,
#     material: &opc_proto_ikev2::Ikev2SaInitKeyMaterial,
#     signed_octets: opc_proto_ikev2::Ikev2IkeAuthSignedOctets<'_>,
#     key: &opc_proto_ikev2::Ikev2SignatureAuthKey,
#     local_public_credential: &opc_proto_ikev2::Ikev2SignaturePublicKey,
#     request_bytes: &[u8],
#     response_bytes: &[u8],
# ) -> Result<(), Box<dyn std::error::Error>> {
let local_offer = Ikev2SignatureHashLocalOffer::new(&[
    Ikev2SignatureHashAlgorithm::Sha2_384,
    Ikev2SignatureHashAlgorithm::Sha2_256,
])?;
let outbound_notify = local_offer.to_notify_payload();
// Encode `outbound_notify` in this peer's IKE_SA_INIT.
let _ = outbound_notify;

let authorities = negotiate_ikev2_signature_hash_algorithms(
    Ikev2SignatureHashLocalRole::Responder,
    request_bytes,
    response_bytes,
    DecodeContext::default(),
)?
.into_authorities();
let signing_authorization = authorities
    .signing()
    .for_exchange(request_bytes, response_bytes)?;
let self_verification_authorization = authorities
    .signing()
    .authorize_local_auth_self_verification(
        request_bytes,
        response_bytes,
        signed_octets,
        Ikev2SignatureHashAlgorithm::Sha2_256,
        local_public_credential,
    )?;
let auth_data = compute_ike_auth_signature(
    profile,
    material,
    signed_octets,
    key,
    Some(signing_authorization),
)?;
verify_local_ike_auth_signature(
    profile,
    material,
    &Ikev2AuthenticationPayload {
        auth_method: IKEV2_AUTH_METHOD_DIGITAL_SIGNATURE,
        auth_data: &auth_data,
    },
    self_verification_authorization,
)?;
// Only transmit the AUTH payload after self-verification succeeds.
# Ok(())
# }
```

For verification, bind `authorities.verification()` with the same
`for_exchange(request_bytes, response_bytes)` call and pass the resulting
one-operation authorization to `verify_ike_auth_signature`. Each non-copyable
authorization checks the method-14 AlgorithmIdentifier hash, both exact
request/response messages, the expected signer role, and the direction-correct
opposite-message nonce (`Nr` for initiator AUTH, `Ni` for responder AUTH)
before transcript PRF or signature execution. Peer/local omission, a presented
stale exchange or nonce, opposite-direction nonce substitution, and
wrong-direction use are typed errors. The product must retain the authority,
exact messages, and key material together as one IKE-SA state: the SDK cannot
infer whether separately supplied key material belongs to a different
application session whose signer-side message happens to be byte-identical.

Local pre-transmit verification deliberately does not invert the IKE role or
reuse the peer verification authority. Instead,
`authorize_local_auth_self_verification` captures the local signed-octet
inputs, selected hash, and caller-selected public credential inside a separate
sealed authorization. `verify_local_ike_auth_signature` consumes that value,
accepts method 14 only, and verifies the generated wire AUTH against the same
admitted crypto-module boundary. Transcript, role, message direction, Nonce,
identity, method, hash, key material, signature, or credential substitution
fails closed. Existing peer-verification integration remains unchanged.

RFC 7296 method 1 is unchanged semantically and passes `None`. This boundary
does not choose certificate identity, certificate trust, signature-key type,
or product hash/key preference.

## Unknown critical payload rejection

`Message::decode_with_rejection` and NAT-T inspection preserve the exact
one-octet payload type required by RFC 7296 section 2.5. A generic message fact
is not reply authority. Only an exact initial IKE_SA_INIT request can be
converted into `Ikev2SaInitUnknownCriticalPayloadRequest`; responses, trailing
datagrams, malformed framing, truncation, and exceeded decode bounds cannot
produce that wrapper. Its header remains private and `build_response()` routes
through the existing bounded Notify type 1 builder:

```rust
use opc_proto_ikev2::{
    inspect_ike_nat_traversal_datagram, IKE_UDP_PORT,
};

# let datagram = [0u8; 0];
let inspection = inspect_ike_nat_traversal_datagram(IKE_UDP_PORT, &datagram);
if let Some(rejection) = inspection.unknown_critical_payload() {
    if let Ok(request) = rejection.rejection().try_into_ike_sa_init_request() {
        let response = request.build_response()?;
        // Apply product-owned source admission, rate limiting, and
        // retransmission caching before sending `response`.
        let _ = response;
    }
}
# Ok::<(), opc_proto_ikev2::Ikev2SaInitNotifyBuildError>(())
```

Authenticated code that has already opened `SK`/`SKF` uses
`PayloadChain::validate_with_rejection` or
`RawPayloadIterator::unknown_critical_rejection` for the same protocol fact;
exchange correlation and protected error transmission remain caller-owned.
The original `classify_ike_nat_traversal_datagram` API keeps its public enum
shape and continues returning the coarse
`MalformedIke { decode_code: UnknownCriticalPayload }` outcome for existing
metrics and exhaustive matches on a fully framed, exact-length offender.
Rejection precedence is deliberately corrected for mixed-invalid input:
malformed offender framing stays malformed, and bytes beyond the declared IKE
length win as `TrailingIkeBytes`; neither produces a typed reply sidecar.

## Process-wide cryptographic module admission

IKEv2 cryptographic operations have no implicit software or `testkit`
fallback. Before accepting IKE traffic, a process must build
`Ikev2CryptoRequirements` from every configured IKE-SA profile, NAT-detection
use, CERTREQ authority hashing use, and signature direction, then admit one
exact `Arc<dyn IkeCryptoModule>`.
Admission probes the module, applies `ProviderPolicy`, preflights every named
algorithm, and sets an immutable process slot only after all checks succeed.
A failed preflight leaves the slot unset; a successful slot cannot be reset or
replaced. The module object may rotate its own keys, trust, sessions, or
material epochs internally without changing its admitted identity.

The runtime integration point is the async `StartupPhases::init_security`
hook. This complete composition aborts startup before any runtime-mediated
service listener binds:

```rust
use std::sync::Arc;

use opc_crypto_provider::{
    IkeCryptoModule, IkeSignatureAlgorithm, ProviderPolicy,
};
use opc_proto_ikev2::{
    install_ikev2_crypto_module, Ikev2CryptoRequirements,
    Ikev2SaInitCryptoError, Ikev2SaInitCryptoProfile,
};
use opc_runtime::{BootstrapError, StartupPhases};

fn security_phases(
    module: Arc<dyn IkeCryptoModule>,
    configured_profiles: &[Ikev2SaInitCryptoProfile],
) -> Result<StartupPhases, Ikev2SaInitCryptoError> {
    let mut requirements = Ikev2CryptoRequirements::new();
    for profile in configured_profiles.iter().copied() {
        requirements.require_ike_sa_profile(profile)?;
    }
    requirements.require_nat_detection();
    requirements.require_certreq_authority_hash();
    requirements.require_signature_generation(
        IkeSignatureAlgorithm::EcdsaP256Sha2_256,
    );
    requirements.require_signature_verification(
        IkeSignatureAlgorithm::RsaPkcs1V15Sha2_256,
    );
    let policy = ProviderPolicy::new()
        .require_all(requirements.required_capabilities());

    Ok(StartupPhases {
        init_security: Some(Box::new(move |_runtime_profile| {
            let module = Arc::clone(&module);
            let requirements = requirements.clone();
            Box::pin(async move {
                install_ikev2_crypto_module(module, policy, requirements)
                    .await
                    .map(|_report| ())
                    .map_err(|error| BootstrapError::SecurityInit(Box::new(error)))
            })
        })),
        ..StartupPhases::default()
    })
}
```

`require_signature_generation` and `require_signature_verification` are
deliberately separate. Default builds can verify RSA peer AUTH but reject RSA
private-key signing unless the `rsa-signing` feature is compiled. The bundled
`Ikev2SoftwareCryptoModule` is an explicit RustCrypto-backed choice and reports
`ValidationState::NotValidated`; selecting it makes no certification claim.

When the configured private key determines the startup requirement, inspect it
before the one-shot module installation and require its exact public identity
to match the product-validated leaf certificate:

```rust
use opc_proto_ikev2::{
    inspect_ikev2_signature_key_pkcs8_der, Ikev2CryptoRequirements,
    Ikev2PreAdmissionInspectionError,
};

fn add_configured_signing_requirement(
    pkcs8_der: &[u8],
    validated_leaf_certificate_der: &[u8],
    requirements: &mut Ikev2CryptoRequirements,
) -> Result<(), Ikev2PreAdmissionInspectionError> {
    let inspection = inspect_ikev2_signature_key_pkcs8_der(pkcs8_der)?;
    inspection.require_leaf_certificate_spki_match(validated_leaf_certificate_der)?;
    inspection.requirement().apply_to(requirements);
    Ok(())
}
```

This helper accepts neither PEM nor encrypted PKCS#8, performs no certificate
chain/validity/name/key-usage checks, and is never a fallback for IKE traffic.
Its RustCrypto secret-key object and explicitly owned public-point derivation
scalar are zeroized independently; the result retains public metadata only.
After admission, load the configured PKCS#8 and sign only through the installed
module-backed `Ikev2SignatureAuthKey` path.

`require_nat_detection` and `require_certreq_authority_hash` are also
deliberately separate. Both require `IkeHash` and SHA-1, but a configuration
that admits one protocol use does not authorize the other. To build one X.509
CERTREQ authority value, pass the complete DER `SubjectPublicKeyInfo` element
from the configured CA trust anchor—not a whole certificate, PEM, or the bare
public-key BIT STRING:

```rust
use opc_proto_ikev2::{
    ikev2_certreq_authority_key_hash, Ikev2CertReqSubjectPublicKeyInfo,
};

let spki = Ikev2CertReqSubjectPublicKeyInfo::from_der(configured_ca_spki_der)?;
let authority = ikev2_certreq_authority_key_hash(spki)?;
certreq_ca_data.extend_from_slice(authority.as_bytes());
# Ok::<(), Box<dyn std::error::Error>>(())
```

The constructor accepts exactly one DER SPKI with no trailing bytes and rejects
empty, malformed, or over-bounded input before provider selection. Every hash
call then rechecks module identity, validation declaration, capability
admission, advertisement/readiness, SHA-1 operation support, provider success,
and an exact 20-octet output. Neither path has an implicit software/test
fallback.

Every operation rechecks the complete admitted capability set, current module
identity and validation declaration, readiness, advertisement, and the exact
algorithm requirement. Capability withdrawal fails before the provider
operation executes, including reuse of already-created opaque DH or signing
handles. Successful hash, PRF/PRF+, integrity, AEAD/CBC, and DH results are
checked immediately against their algorithm-derived widths. AEAD output must
retain the requested explicit IV; ECDSA output must be valid DER with scalars
in range for the selected curve; and RSA output must match the opaque handle's
public modulus width. DH public values are semantically validated and
snapshotted, and opaque DH/signing handles are rechecked when used. A module
contract violation fails with
`ike_crypto_module_invalid_output` before malformed bytes reach protocol
consumers. Production CBC IVs come from the admitted module's
`ApprovedEntropy` operation. Caller-supplied RNG and explicit-IV APIs remain
caller-owned compatibility/vector boundaries: encryption and integrity still
route through the module, but their supplied IV entropy is outside admission
evidence.

`require_child_sa_profile` admits the PRF used for Child-SA KEYMAT. A
CREATE_CHILD_SA configuration that offers PFS must additionally call
`require_child_sa_pfs_group` for every offered Child-SA DH group; the ESP
profile intentionally does not conflate its transforms with the separately
negotiated PFS transform.

The generic `CryptoProvider::open_payload` SPI/SA-lookup boundary remains
caller-owned. It cannot prove the identity of arbitrary external crypto and is
therefore not itself admitted or validated. The SDK-owned concrete
`Ikev2SaInitProtectedPayloadProvider` routes through this admitted slot. A
deployment using another adapter must bind that adapter to its admitted module;
performing crypto directly outside it is outside the SDK's admission evidence.

### Migration to admitted IKEv2 cryptography

Install the module during `StartupPhases::init_security` before invoking any
IKEv2 cryptographic operation. `ikev2_nat_detection_hash` and
`evaluate_ikev2_nat_detection` are now fallible and return
`Ikev2CryptoModuleError`; callers must propagate or map that error rather than
assuming NAT-D hashing cannot fail.

Applications that construct X.509 CERTREQ authority values must also call
`Ikev2CryptoRequirements::require_certreq_authority_hash` during startup,
validate the configured CA SPKI with
`Ikev2CertReqSubjectPublicKeyInfo::from_der`, and propagate
`ikev2_certreq_authority_key_hash` failures. Enabling NAT-D alone is
intentionally insufficient.

This additive API is source-breaking for downstream exhaustive matches. Add a
`CryptoModuleFailure { error }` arm to matches over:

- `Ikev2SaInitCryptoError`;
- `Ikev2ProtectedPayloadCryptoError`;
- `Ikev2IkeAuthVerificationError`; and
- `Ikev2SignatureKeyError`.

Code-enum matches must also accept
`Ikev2SaInitCryptoErrorCode::CryptoModuleFailure` and
`Ikev2ProtectedPayloadCryptoErrorCode::CryptoModuleFailure`. Existing semantic
error variants and their stable strings are unchanged; the new module-failure
strings are `ike_sa_init_crypto_module_failure`,
`ike_protected_payload_crypto_module_failure`,
`ike_auth_verify_crypto_module_failure`, and
`ike_auth_signature_crypto_module_failure`.

TLS and `opc-key` custody do not use this IKEv2 slot yet; those remain later
#334 slices.

## Network receive and sender-canonical validation

RFC 7296 requires senders to clear several reserved fields but explicitly
requires receivers to ignore them. `Message::decode`, `decode_header`, payload
iteration, and the typed ID/AUTH/KE/TS/CP decoders therefore use
`Ikev2ValidationProfile::NetworkReceive` by default. This remains the correct
profile even with `DecodeContext::conservative()` or `ValidationLevel::Strict`:
those context settings continue to enforce hostile lengths, bounded payload
counts, payload chaining, valid major version, typed cardinality, unknown
critical payloads, integrity, and authentication.

Generated outbound fixtures can opt into the separate canonical checks:

```rust
use opc_proto_ikev2::{Ikev2ValidationProfile, Message};
use opc_protocol::DecodeContext;

# let generated_message = [0u8; 0];
let result = Message::decode_with_profile(
    &generated_message,
    DecodeContext::conservative(),
    Ikev2ValidationProfile::SenderCanonical,
);
# let _ = result;
```

The corresponding `*_with_profile` typed body decoders and
`decode_ike_auth_cleartext_payloads_with_profile` diagnose a non-zero Version
bit, Critical bit on understood payloads, and non-zero SA Proposal/Transform,
ID, AUTH, KE, TS, CP, and CP-attribute reserved fields. Production typed
builders continue to emit zero. The raw `Message` shell deliberately preserves
supplied payload-chain bytes; callers generating outbound raw fixtures should
run sender-canonical validation before sending them.

`Ikev2IdentificationPayload::reserved` retains the exact three received ID
octets. `to_payload_body()` reconstructs the exact received ID body, including
those ignored octets, because RFC 7296 AUTH authenticates that body byte for
byte. It must not be replaced with a zero-canonicalized ID body during AUTH
verification.

## IKE-SA profile configuration

Profile construction is the startup capability-validation boundary. The old
infallible `Ikev2SaInitCryptoProfile::new(prf, dh, encryption)` API was removed
because it could construct AES-CBC without its negotiated integrity algorithm.
AEAD and encrypt-then-MAC suites now use separate validating constructors:

```rust
use opc_proto_ikev2::{
    Ikev2DhGroup, Ikev2EncryptionAlgorithm, Ikev2IntegrityAlgorithm,
    Ikev2PrfAlgorithm, Ikev2SaInitCryptoError, Ikev2SaInitCryptoProfile,
};

fn handset_profile() -> Result<Ikev2SaInitCryptoProfile, Ikev2SaInitCryptoError> {
    Ikev2SaInitCryptoProfile::new_encrypt_then_mac(
        Ikev2PrfAlgorithm::HmacSha2_512,
        Ikev2DhGroup::Modp2048,
        Ikev2EncryptionAlgorithm::AesCbc256,
        Ikev2IntegrityAlgorithm::HmacSha2_512_256,
    )
}

fn existing_gcm_profile() -> Result<Ikev2SaInitCryptoProfile, Ikev2SaInitCryptoError> {
    Ikev2SaInitCryptoProfile::new_aead(
        Ikev2PrfAlgorithm::HmacSha2_256,
        Ikev2DhGroup::Ecp256,
        Ikev2EncryptionAlgorithm::AesGcm16_128,
    )
}
```

Configuration expressed as wire identifiers should use `from_transform_ids`;
its final argument is now `Option<u16>` containing the integrity Transform ID,
not an anonymous key length. `Some(14)` selects
AUTH-HMAC-SHA2-512-256; AEAD profiles pass `None`.

The executable IKE-SA matrix is:

| Mechanism | Transform IDs and sizes | Key/material contract |
| --- | --- | --- |
| PRF | HMAC-SHA1 (2, compatibility), HMAC-SHA2-256 (5), HMAC-SHA2-384 (6), HMAC-SHA2-512 (7) | 20, 32, 48, or 64 octets for each of `SK_d`, `SK_pi`, and `SK_pr` |
| DH | MODP-768 (1, compatibility), MODP-1024 (2, compatibility), MODP-2048 (14), ECP-256 (19), ECP-384 (20), ECP-521 (21) | Exact public/shared widths: MODP 96/96, 128/128, 256/256; ECP public 64/96/132 and shared 32/48/66 octets |
| AES-GCM-16 | ENCR 20 with 128, 192, or 256-bit key; no INTEG | AES key plus four-octet salt; eight-octet explicit IV and 16-octet tag on the wire |
| AES-CBC | ENCR 12 with 128, 192, or 256-bit key | Raw 16, 24, or 32-octet `SK_e*`; fresh 16-octet IV per newly sealed message |
| Integrity | AUTH-HMAC-SHA1-96 (2, compatibility) or AUTH-HMAC-SHA2-256-128 (12), 384-192 (13), or 512-256 (14) | 20/32/48/64-octet `SK_a*`; 12/16/24/32-octet ICV |

Every CBC key size may be paired with each supported integrity
algorithm. `validate_executable()` is the explicit startup check, although all
public profile constructors already enforce the same contract.

### Legacy IKE interoperability profiles

MODP-768, MODP-1024, PRF-HMAC-SHA1, and AUTH-HMAC-SHA1-96 exist only to
interoperate with peers that cannot negotiate the stronger profiles above.
RFC 8247 marks MODP group 1 as `MUST NOT`, group 2 as `SHOULD NOT`, and the
SHA-1 PRF/integrity transforms for deprecation; RFC 9395 also deprecates group
1. The SDK deliberately has no default proposal policy, and recognizing these
typed algorithms does not offer or select them. A product must explicitly add
the exact compatibility profile to its `Ikev2SaInitNegotiationPolicy`:

```rust
use opc_proto_ikev2::{
    Ikev2DhGroup, Ikev2EncryptionAlgorithm, Ikev2IntegrityAlgorithm,
    Ikev2PrfAlgorithm, Ikev2SaInitCryptoProfile, Ikev2SaInitNegotiationPolicy,
    Ikev2SaInitNegotiationError,
};

fn compatibility_policy(
) -> Result<Ikev2SaInitNegotiationPolicy, Ikev2SaInitNegotiationError> {
    let legacy = Ikev2SaInitCryptoProfile::new_encrypt_then_mac(
        Ikev2PrfAlgorithm::HmacSha1,
        Ikev2DhGroup::Modp1024,
        Ikev2EncryptionAlgorithm::AesCbc128,
        Ikev2IntegrityAlgorithm::HmacSha1_96,
    )
    .map_err(Ikev2SaInitNegotiationError::UnsupportedConfiguredProfile)?;
    Ikev2SaInitNegotiationPolicy::new(vec![legacy])
}
```

Keep stronger profiles earlier in the caller-owned preference list. No DES,
3DES, MD5, unauthenticated CBC, or other legacy algorithm is enabled by this
compatibility boundary.

## Authenticated-only ESP Child SAs

ENCR_NULL is an explicit Child-SA capability, not a deployment default or a
policy preference. It is never accepted for an IKE SA and it is not added to
any allowlist automatically. A product that deliberately permits
authenticated-only ESP constructs or restores the exact typed profile:

```rust
use opc_proto_ikev2::{
    Ikev2ChildSaCryptoProfile, Ikev2IntegrityAlgorithm, Ikev2PrfAlgorithm,
    Ikev2SaInitCryptoError,
};

fn authenticated_only_child() -> Ikev2ChildSaCryptoProfile {
    Ikev2ChildSaCryptoProfile::new_authenticated_only(
        Ikev2PrfAlgorithm::HmacSha2_256,
        Ikev2IntegrityAlgorithm::HmacSha2_256_128,
    )
}

fn restore_authenticated_only_child(
) -> Result<Ikev2ChildSaCryptoProfile, Ikev2SaInitCryptoError> {
    Ikev2ChildSaCryptoProfile::from_transform_ids(
        5,        // PRF_HMAC_SHA2_256
        11,       // ENCR_NULL
        None,     // Key Length is prohibited for ENCR_NULL
        Some(12), // AUTH_HMAC_SHA2_256_128
    )
}
```

RFC 7296 Child-SA KEYMAT contains `initiator A | responder A` for this
profile: each directional encryption and salt slice is empty, while the
selected integrity key is derived normally. Negotiation rejects ENCR_NULL
without INTEG, ENCR_NULL carrying any Key Length attribute, and AEAD carrying
a separate INTEG. Response construction copies transform 11 without adding an
attribute. Profile and key-material debug output remains redaction-safe.

The optional `opc-ipsec-xfrm` IKEv2 mapper installs this as Linux's canonical
zero-key `ecb(cipher_null)` crypt attribute plus the selected auth attribute.
That Linux-only adapter representation does not add protocol KEYMAT. Current
Linux kernels reject an ESP `NEWSA` containing auth but no crypt/aead
attribute, so consumers must use the mapper or `Algorithm::null()` rather than
constructing a raw auth-only `SaParameters` value.

### Migration from the anonymous integrity length

The old constructor could represent AES-CBC without its algorithm, and the old
wire-ID constructor accepted an arbitrary `usize` integrity-key length:

```text
Ikev2SaInitCryptoProfile::new(prf, dh, encryption)
Ikev2SaInitCryptoProfile::from_transform_ids(7, 14, 12, Some(256), 64)
```

Replace those calls with a fallible typed constructor or a typed integrity
Transform ID, and reject errors during configuration loading:

```rust
use opc_proto_ikev2::{Ikev2SaInitCryptoError, Ikev2SaInitCryptoProfile};

fn configured_handset_profile() -> Result<Ikev2SaInitCryptoProfile, Ikev2SaInitCryptoError> {
    let profile = Ikev2SaInitCryptoProfile::from_transform_ids(
        7,         // PRF_HMAC_SHA2_512
        14,        // 2048-bit MODP
        12,        // ENCR_AES_CBC
        Some(256),
        Some(14),  // AUTH_HMAC_SHA2_512_256
    )?;
    profile.validate_executable()?;
    Ok(profile)
}
```

Downstream exhaustive matches must add these exact arms:

- `Ikev2EncryptionAlgorithm::Null` (Child-SA only; reject it in IKE-SA
  protected-payload paths);
- `Ikev2PrfAlgorithm::HmacSha2_512`;
- `Ikev2SaInitCryptoError::{MissingIntegrityTransform,
  UnexpectedIntegrityTransform}` and the corresponding
  `Ikev2SaInitCryptoErrorCode` variants;
- `Ikev2ProtectedPayloadCryptoError::{InvalidIvLength,
  InvalidCiphertextLength, RandomIvGenerationFailed}` and the corresponding
  `Ikev2ProtectedPayloadCryptoErrorCode` variants.

The existing `UnsupportedEncryptionProfile` error also changes field shape
from `integrity_key_len: usize` to
`integrity: Option<Ikev2IntegrityAlgorithm>`. Existing authentication,
authenticated-padding, unsupported-integrity, and key-material errors retain
their variants and stable codes.

Consumers must remove any blanket `integrity.is_some()` rejection. Preserve
the selected typed INTEG transform in the profile, pass that profile through
derivation/restore and protected-payload construction, and select the CBC
open/seal path when `encryption().is_aead()` is false. Restored CBC SAs pass the
same typed profile to `Ikev2SaInitKeyMaterial::from_established_keys`; integrity
ID 14 requires 64-octet `SK_ai`/`SK_ar`, while AES-CBC-256 requires 32-octet
`SK_ei`/`SK_er`. Existing AES-GCM callers use `new_aead`, retain empty `SK_a*`,
and keep their monotonic explicit-IV state.

## IKE_SA_INIT proposal selection

`Ikev2SaInitNegotiationPolicy` is the startup capability and responder
preference boundary. It accepts only complete executable profiles. The selector
combines transforms by type, so wire order never affects selection and
same-type alternatives remain valid. It returns one exact response proposal,
including the initiator's selected Key Length attribute unchanged:

```rust
use opc_proto_ikev2::{
    negotiate_ike_sa_init, Ikev2SaInitNegotiationError,
    Ikev2SaInitNegotiationPolicy, Ikev2SaInitPayloads,
};

fn select_handset_suite(
    payloads: &Ikev2SaInitPayloads<'_>,
) -> Result<opc_proto_ikev2::Ikev2SaInitNegotiation, Ikev2SaInitNegotiationError> {
    let profile = handset_profile()
        .map_err(Ikev2SaInitNegotiationError::UnsupportedConfiguredProfile)?;
    let policy = Ikev2SaInitNegotiationPolicy::new(vec![profile])?;
    negotiate_ike_sa_init(payloads, &policy)
}
# fn handset_profile() -> Result<opc_proto_ikev2::Ikev2SaInitCryptoProfile,
#     opc_proto_ikev2::Ikev2SaInitCryptoError> {
#     opc_proto_ikev2::Ikev2SaInitCryptoProfile::new_encrypt_then_mac(
#         opc_proto_ikev2::Ikev2PrfAlgorithm::HmacSha2_512,
#         opc_proto_ikev2::Ikev2DhGroup::Modp2048,
#         opc_proto_ikev2::Ikev2EncryptionAlgorithm::AesCbc256,
#         opc_proto_ikev2::Ikev2IntegrityAlgorithm::HmacSha2_512_256,
#     )
# }
```

`NoAcceptableProposal` is a stable typed outcome suitable for
`NO_PROPOSAL_CHOSEN`. A supported offered suite whose DH transform does not
match the KE payload returns `KeyExchangeDhGroupMismatch`, allowing the product
to decide whether to send the bounded `INVALID_KE_PAYLOAD` response. Duplicate
transforms or attributes fail closed. NAT detection, fragmentation,
signature-hash, redirect, and unknown non-critical/private-use notifications do not
participate in algorithm selection. The product still owns responder SPI and
nonce allocation, anti-amplification policy, transaction caching, and the IKE
SA state machine.

## IKE-SA rekey responder boundary

`decode_ike_sa_rekey_request` accepts an already-authenticated and opened RFC
7296 IKE-SA rekey request. The outer header must identify a non-response
`CREATE_CHILD_SA` protected by `SK` on an established IKE SA. The inner chain
must contain exactly one SA payload, one Nonce, and one KE payload. Every
proposal uses Protocol ID IKE, a consecutive Proposal Number, and a non-zero
eight-octet new initiator SPI. The default decoder preserves Vendor IDs,
unrecognized Notify payloads, and unknown non-critical payloads as
redaction-safe borrowed views. The explicit-context decoder honors `Drop` for
the latter two classes and preserves them under both `Preserve` and `Reject`:
RFC 7296 requires these extensions to be ignored, so a generic reject policy
cannot reject this request. Unknown critical payloads always fail closed.
`REKEY_SA`, TSi/TSr, `DH=NONE`, other semantically invalid known payloads, and
a KE group absent from the proposals also fail closed with stable structural
codes.

Pass the decoded request to `negotiate_ike_sa_rekey` with the same
`Ikev2SaInitNegotiationPolicy` used for initial IKE-SA selection. The result
contains the selected transforms, the selected proposal's new initiator SPI,
and an `Ikev2SaInitCryptoProfile` that can be passed directly to
`derive_ike_sa_rekey_key_material` without re-decoding generated wire bytes.
That KDF accepts only the selected group's fixed-width shared secret: 256
octets for DH14 and 32, 48, or 66 octets for DH19, DH20, or DH21. A mismatch
returns the pre-existing stable `ike_sa_init_crypto_invalid_key_length` error
with only a redaction-safe input label and actual length; callers can obtain the
required width from `Ikev2DhGroup::shared_secret_len()`.

`build_ike_sa_rekey_response` requires a selected negotiation, a caller-owned
non-zero new responder SPI, Nr, and a KEr whose group and fixed public-value
length match the selected profile. It emits immutable generic-payload bytes in
exactly `SA, Nr, KEr` order. The caller remains responsible for generating DH
and nonce material, allocating collision-resistant SPIs, sealing and caching
the complete `SK` response, handling simultaneous rekeys, installing the new
SA, and deleting the old SA.

## Child-SA rekey initiator response boundary

`Ikev2ChildSaRekeyResponseBoundary` completes the initiator side of an RFC 7296
Child-SA rekey without introducing another request representation. Construct
it from the exact established-IKE-SA request header, the existing
`Ikev2CreateChildSaRekeyRequestBuild`, the exact current Child-SA TSi/TSr
floor, and the established IKE SA's PRF before sending the request. The
current floor is separate because a rekey request may offer a superset, while
RFC 7296 section 2.9.2 forbids the replacement SA from becoming narrower than
the SA it replaces. Retain that boundary with the outstanding transaction,
then pass it the authenticated and opened response:

```rust
# fn example(
#     request_header: opc_proto_ikev2::Header,
#     request: opc_proto_ikev2::Ikev2CreateChildSaRekeyRequestBuild,
#     current_traffic_selectors:
#         opc_proto_ikev2::Ikev2ChildSaRekeyCurrentTrafficSelectors,
#     response_header: opc_proto_ikev2::Header,
#     response_first_payload: opc_proto_ikev2::PayloadType,
#     opened_response: &[u8],
# ) -> Result<(), opc_proto_ikev2::Ikev2ChildSaRekeyResponseError> {
use opc_proto_ikev2::{
    Ikev2ChildSaRekeyResponseBoundary, Ikev2PrfAlgorithm,
};

let mut pending = Ikev2ChildSaRekeyResponseBoundary::new(
    &request_header,
    request,
    current_traffic_selectors,
    Ikev2PrfAlgorithm::HmacSha2_256,
)?;
let initiator_nonce = pending.initiator_nonce();
# let _ = initiator_nonce;

let accepted = pending.commit_response(
    &response_header,
    response_first_payload,
    opened_response,
)?;
let replacement_initiator_spi = accepted.replacement_initiator_spi();
let replacement_responder_spi = accepted.replacement_responder_spi();
let profile = accepted.profile();
# let _ = (
#     replacement_initiator_spi,
#     replacement_responder_spi,
#     profile,
# );
# Ok(())
# }
```

The response header must retain the exact old IKE SPI pair and Message ID, use
`CREATE_CHILD_SA`, carry the response flag and opposite original-initiator
flag, and name an outer `SK` or `SKF` payload. For `SKF`, the product first
authenticates, opens, and reassembles the fragments, then supplies the first
reassembled inner payload type. The opened chain is order-independent but must
contain exactly `SA, Nr, [KEr], TSi, TSr`. The selected ESP proposal must be
executable and drawn from the exact offer. `DH=NONE` may be represented by
omission where RFC 7296 permits it, but ESP always requires one explicit
SN/ESN transform (ID 0 means no extended sequence numbers). PFS requires the
offered KE group and a valid group public value. Ni and Nr must each be at
least half the established PRF's preferred key length, and both returned
selector sets must cover the current Child SA while remaining within the
request offer. Selector containment compares the exact union of complete
protocol × port × IPv4/IPv6-address boxes, so adjacent or overlapping entries
may collectively cover a selector while address/port checkerboard gaps never
invent coverage. Protocol zero uses only canonical ANY ports (`0..65535`).
RFC 7296 OPAQUE ports (`65535..0`) remain a distinct non-zero-protocol value:
ANY covers OPAQUE, while OPAQUE does not cover ordinary numeric ports.

A valid response error Notify is returned as
`Ikev2ChildSaRekeyResponseError::PeerErrorNotify` and, like success, commits
the boundary terminally. Known errors are validated for this exact exchange;
`CHILD_SA_NOT_FOUND` must identify the exact ESP SPI from the retained
`REKEY_SA`, and `INVALID_KE_PAYLOAD` retains its suggested group. An
unrecognized error-range type still terminally fails the request as RFC 7296
requires, while preserving bounded raw SPI/data behind redaction-safe
diagnostics. Unknown non-critical payloads and unrecognized status Notifies
are ignored under all policies; `Preserve` and normalized `Reject` retain them
for successful-response inspection, while `Drop` discards them. Such
extensions and Vendor IDs do not turn a valid error response into partial
success. A second response cannot commit. Malformed, uncorrelated, or mixed
error/success input does not commit, so the product can continue applying its
own retransmission deadline. The SDK returns the responder nonce, both
selected inbound SPIs, executable Child-SA profile, ESN selection, optional
KEr, and accepted selectors; the boundary retains the initiator nonce for
KEYMAT. Request retransmission and exact-wire caching, simultaneous-rekey
policy, SPI/DH/nonce allocation, KEYMAT invocation, kernel installation, and
old-SA retirement remain product-owned.

## Protected IKE_AUTH integration

For AES-CBC, use `ikev2_aes_cbc_protected_body_len` or
`ikev2_aes_cbc_protected_payload_len` to calculate the final outer IKE Length
and `SK`/`SKF` payload Length before sealing. Then pass the exact bytes through
the protected generic header as `message_prefix`. This is the production
sealing call for a responder IKE_AUTH:

```rust
use bytes::Bytes;
use opc_proto_ikev2::{
    seal_ikev2_sa_init_aes_cbc_protected_payload,
    Ikev2ProtectedPayloadCryptoError, Ikev2ProtectedPayloadDirection,
    Ikev2SaInitCryptoProfile, Ikev2SaInitKeyMaterial, ProtectedPayloadKind,
    ProtectedPayloadSealContext,
};

fn seal_responder_ike_auth(
    profile: Ikev2SaInitCryptoProfile,
    keys: &Ikev2SaInitKeyMaterial,
    final_message_prefix: &[u8],
    cleartext_payload_chain: &[u8],
) -> Result<Bytes, Ikev2ProtectedPayloadCryptoError> {
    seal_ikev2_sa_init_aes_cbc_protected_payload(
        profile,
        keys,
        Ikev2ProtectedPayloadDirection::ResponderToInitiator,
        ProtectedPayloadSealContext {
            kind: ProtectedPayloadKind::Encrypted,
            message_prefix: final_message_prefix,
        },
        cleartext_payload_chain,
    )
}
```

The returned body is `IV || ciphertext || ICV`; for the observed profile the
lengths are 16, a non-empty multiple of 16, and 32 octets respectively. Use
`Ikev2SaInitProtectedPayloadProvider` with `InitiatorToResponder` to open the
handset's request. The provider authenticates the complete message before
decrypting. Well-formed, same-length corruption of authenticated header bytes,
IV, ciphertext, or ICV that reaches cryptographic verification returns the
same `AuthenticationFailed` outcome before decryption. Malformed framing and
lengths return their stable structural errors without decryption;
`InvalidPadding` is reachable only after successful authentication. Use the
same APIs for `SKF`; its four-octet Fragment Number/Total Fragments prefix is
included in the final authenticated prefix. Cache and replay the complete
already-built wire message for retransmissions—calling the production CBC
sealer again deliberately generates a different IV. The explicit-IV sealer is
a low-level test/vector boundary and must not be used by production callers.

`open_protected_payloads` preserves the provider error by value. With the
concrete SA_INIT-key provider its error type is
`Ikev2ProtectedPayloadOpenError`, and
`ProtectedPayloadOpenError::ProviderRejected(failure)` exposes
`failure.provider_error.code()` as an
`Ikev2ProtectedPayloadCryptoErrorCode`. This typed value is local diagnostic
evidence only. The outer error redacts it from both `Debug` and `Display`; a
caller that explicitly inspects a custom provider error remains responsible
for redaction. Do not send the inner variant or code to the peer: every
provider rejection retains the uniform outer
`ike_protected_payload_provider_rejected` classification, and products must
apply one peer-visible rejection/drop policy to authentication, malformed
length, and authenticated-padding failures. The outer error's `Display` text
is deliberately uniform as an additional defense against accidental detail
leakage; inspect the typed field locally instead.

## Dedicated-bearer integration

The dedicated-bearer API consumes and emits the cleartext payload chain inside
an authenticated `SK` payload. The application remains responsible for IKE SA
state, message-ID allocation, encryption/authentication, timer policy, and
installing or deleting the resulting Child SA.

```rust
use opc_proto_ikev2::{
    build_ikev2_dedicated_bearer_create_child_sa_request,
    decode_ikev2_dedicated_bearer_create_child_sa_response,
    validate_ikev2_dedicated_bearer_create_child_sa_response_correlation,
    Header, Ikev2DedicatedBearerCreateChildSaRequest,
    Ikev2DedicatedBearerCreateChildSaRequestBuild,
    Ikev2DedicatedBearerCreateChildSaResponse, PayloadType,
};

fn encode_new_bearer(
    input: &Ikev2DedicatedBearerCreateChildSaRequestBuild,
) -> Result<(PayloadType, bytes::Bytes), Box<dyn std::error::Error>> {
    let cleartext = build_ikev2_dedicated_bearer_create_child_sa_request(input)?;
    // Seal these exact bytes once, then cache the complete encrypted request
    // for retransmission; do not reseal retransmissions with a new IV.
    Ok(cleartext.into_parts())
}

fn accept_new_bearer_response<'a>(
    request_header: &Header,
    request: &Ikev2DedicatedBearerCreateChildSaRequest<'_>,
    response_header: &Header,
    first_payload: PayloadType,
    opened_payloads: &'a [u8],
) -> Result<Ikev2DedicatedBearerCreateChildSaResponse<'a>, Box<dyn std::error::Error>> {
    let response = decode_ikev2_dedicated_bearer_create_child_sa_response(
        response_header,
        first_payload,
        opened_payloads,
    )?;
    validate_ikev2_dedicated_bearer_create_child_sa_response_correlation(
        request_header,
        response_header,
        request,
        &response,
    )?;
    Ok(response)
}
```

Modification uses
`build_ikev2_dedicated_bearer_modification_request`; deletion uses
`build_ikev2_dedicated_bearer_delete_request`. A normal Delete response is
built/decoded with `build_ikev2_dedicated_bearer_delete_response` and
`decode_ikev2_dedicated_bearer_delete_response`: the ePDG request names its
inbound ESP SPI, while the UE response names the paired UE inbound ESP SPI.
Pass both values through `Ikev2DedicatedBearerDeleteResponseExpectation::PairedSa`
to `validate_ikev2_dedicated_bearer_delete_response_correlation` before changing
application state. An empty response is accepted only with the explicit
`SimultaneousDelete` expectation when RFC 7296 crossed Delete requests apply.
Modification responses remain empty or typed-error INFORMATIONAL responses and
use their corresponding decoder/correlation helper.

P-CSCF restoration keeps the selected family set with the immutable opened
request so a decoded reply can be correlated without downstream wire
constants. The application seals and caches the request, opens the
authenticated response, and owns retransmission and Update Bearer policy:

```rust
use std::net::{Ipv4Addr, Ipv6Addr};

use opc_proto_ikev2::{
    build_ikev2_pcscf_restoration_request,
    decode_ikev2_pcscf_restoration_response,
    validate_ikev2_pcscf_restoration_response_correlation, Header,
    Ikev2PcscfRestorationAddress, Ikev2PcscfRestorationRequest, PayloadType,
};

fn begin_pcscf_restoration(
) -> Result<Ikev2PcscfRestorationRequest, Box<dyn std::error::Error>> {
    let request = build_ikev2_pcscf_restoration_request(
        &[
            Ikev2PcscfRestorationAddress::Ipv4(Ipv4Addr::new(192, 0, 2, 10)),
            Ikev2PcscfRestorationAddress::Ipv6(Ipv6Addr::new(
                0x2001, 0x0db8, 0, 0, 0, 0, 0, 10,
            )),
        ],
    )?;
    // Seal request.first_payload()/request.bytes() once and cache both the
    // complete protected message and this immutable request for correlation.
    Ok(request)
}

fn accept_pcscf_restoration_reply(
    request_header: &Header,
    request: &Ikev2PcscfRestorationRequest,
    response_header: &Header,
    first_payload: PayloadType,
    opened_response: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let response = decode_ikev2_pcscf_restoration_response(
        response_header,
        first_payload,
        opened_response,
    )?;
    validate_ikev2_pcscf_restoration_response_correlation(
        request_header,
        response_header,
        request,
        &response,
    )?;
    Ok(())
}
```

TS 23.380 section 5.6.5.2 requires the ePDG to forward the available P-CSCF
address list received from the PGW, so request attributes carry exact four- or
sixteen-octet values. TS 24.302 section 7.2.3.2 separately requires the UE's
reply attributes to be empty acknowledgements; the decoder rejects valued
known P-CSCF reply attributes. It retains unsupported Configuration
attributes, Vendor IDs, unfamiliar status Notify payloads, and unknown
non-critical payloads through redaction-safe borrowed accessors. Unknown
critical payloads, error-range Notify payloads, and known payloads invalid for
this procedure fail closed. The explicit-context decoder honors `Drop` for
unsupported material and normalizes `Reject` to preservation because RFC 7296
requires those extensions to be ignored rather than rejected; Vendor IDs are
always retained. IKE SA opening/sealing, APCO interpretation, P-CSCF address
selection, retransmission, and session policy remain outside this boundary.

The IKE-only establishment-and-deletion flow is in
[`examples/dedicated_bearer_ikev2.rs`](examples/dedicated_bearer_ikev2.rs).
The complete SDK composition from a triggered GTPv2-C Create Bearer request,
through a correlated IKEv2 Child-SA exchange and GTP response commit, followed
by Delete Bearer and Child-SA deletion, is executable as
[`examples/dedicated_bearer_sdk_flow.rs`](examples/dedicated_bearer_sdk_flow.rs).
That example makes the application-owned admission, allocation, and dataplane
boundaries explicit and proves exact GTP retransmission replay.

Integer-kbps bearer QoS must be mapped onto the discrete TS 24.301 NAS grid
before building `EPS_QOS`/`EXTENDED_EPS_QOS`. The checked mapping API makes the
operator-QCI GBR classification and quantization policy explicit and returns
the rate actually represented on the wire:

```rust
use opc_proto_ikev2::{
    Ikev2EpsBearerBitRatesKbps, Ikev2EpsQosKbps, Ikev2EpsQosMapping,
    Ikev2QosQuantization,
};

let mapped = Ikev2EpsQosMapping::from_kbps(
    Ikev2EpsQosKbps::Gbr {
        qci: 200, // Operator-specific: the variant supplies its GBR type.
        rates: Ikev2EpsBearerBitRatesKbps {
            maximum_uplink: 10_000_001,
            maximum_downlink: 9_900_000,
            guaranteed_uplink: 9_000_000,
            guaranteed_downlink: 9_000_000,
        },
    },
    Ikev2QosQuantization::Ceiling,
)?;

assert_eq!(
    mapped.represented_rates().map(|rates| rates.maximum_uplink),
    Some(10_000_200),
);
# Ok::<(), opc_proto_ikev2::Ikev2QosMappingError>(())
```

`Exact` rejects rates between grid points. `Ceiling` is a documented SDK
policy that selects the smallest representation not below the requested rate;
TS 24.301 requires mapping to an explicit value but does not mandate that
rounding direction. `Ikev2ApnAmbrMapping` provides the same checked boundary
for APN-AMBR, including Extended APN-AMBR above 65,280 Mbps. See
[`examples/dedicated_bearer_qos_mapping.rs`](examples/dedicated_bearer_qos_mapping.rs).

The compact-code constructors remain available for lossless compatibility, but
they are not a way around the production profile. Strict decoders apply the TS
24.301 receiver interpretation for APN-AMBR compact aliases and extended-unit
aliases, then expose and re-encode their canonical equivalents. Reserved base
code 0 and inconsistent profiles still fail closed. Typed Notify builders and
`CREATE_CHILD_SA`/`INFORMATIONAL` builders accept manually supplied canonical
values but reject raw aliases, QCI resource mismatches, lower-tier saturation
errors, invalid maximum/guaranteed relationships, non-canonical units,
extension-threshold misuse, and inconsistent compact sentinels before any
payload bytes are returned.

## Example

```rust
use opc_proto_ikev2::Message;
use opc_protocol::{BorrowDecode, DecodeContext};

let packet = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0, 0, 0, 0, 0, 0, 0, 0,
    40, 0x20, 34, 0x08,
    0, 0, 0, 0,
    0, 0, 0, 36,
    0, 0, 0, 8, 0x11, 0x22, 0x33, 0x44,
];

let (_tail, message) = Message::decode(&packet, DecodeContext::default())?;
assert_eq!(message.payloads().count(), 1);
# Ok::<(), opc_protocol::DecodeError>(())
```

## Features

- `rsa-signing` enables RSA private-key signing for IKE_AUTH methods 1 and 14.
  It is off by default; RSA verification is still available in default builds.
- `testkit` exposes deterministic fixture builders for tests and downstream
  harnesses.

## Status And Limits

The crate is experimental and `publish = false`. The dedicated-bearer wire
boundary has typed, fail-closed validation and specification-authored tests,
but this crate is not a full IKEv2 implementation. Certificate-chain,
validity-period, name, and key-usage validation are caller responsibilities
when using signature AUTH helpers.

IKE_SA_INIT error responses are unauthenticated. The product owns source
validation, response rate limiting, retransmission behavior, and other
anti-amplification policy. The cleartext builder intentionally rejects
`INVALID_SYNTAX`: RFC 7296 §3.10.1 only permits that error in an encrypted
packet after Message ID and cryptographic checksum validation.

DEVICE_IDENTITY carries equipment identity only; it does not define or weaken
IKE authentication. Emergency procedures continue to use the ordinary RFC 7296
method-2 shared-key AUTH helper with caller-supplied, procedure-derived keying
material. The product layer owns exchange correlation and authorization policy.

The AUTHORIZATION_REJECTED helper only builds the TS 24.302 Notify body. A
product that selects it must still follow TS 24.302 section 7.4.1.2, including
providing the UE the information needed to authenticate the ePDG. The SDK does
not infer that selection from a Diameter result and does not implement captive
portal or provisioning policy.

See [CONFORMANCE.md](CONFORMANCE.md) for the exact evidence boundary and
explicit non-goals.

## Roadmap

- Add independent-peer fixtures before claiming interoperability.
- Continue adding typed cleartext payload bodies with octet-level fixture
  evidence.
- Keep SA state machines, retransmission queues, cookie policy, EAP-AKA
  cryptography/session state, SPI allocation, Child SA installation, and ePDG
  product decisions outside this crate.

## Verification

```bash
cargo check -p opc-proto-ikev2 --all-targets --all-features
cargo test -p opc-proto-ikev2 --all-features
cargo clippy -p opc-proto-ikev2 --all-targets -- -D warnings
cargo run -p opc-proto-ikev2 --example dedicated_bearer_sdk_flow
cargo run -p opc-proto-ikev2 --example dedicated_bearer_qos_mapping
(cd crates/opc-proto-ikev2 && cargo +nightly fuzz list)
(cd crates/opc-proto-ikev2 && cargo +nightly fuzz run dedicated_bearer -- -runs=1000)
```
