# Atomic Fenced Transition Contract

This document defines the generic store-side contract for issue #696. It is
the contract exposed by `AtomicFencedTransitionCapability::V1`,
`FencedTransitionRequest`, `FencedTransitionOutcome`, and
`FencedTransitionStatus` in `opc-session-store`. It is not a product workflow
or a network protocol.

## Scope and linearization

One transition names exactly one opaque `SessionKey`. Its lease action and its
record mutation MUST name that same key; it has no multi-key, batch, selector,
or cross-record meaning. An admitted transition is one consensus command with
one applied log position: the lease action and one mutation are committed
together, or the command records one deterministic no-effect result. Combining
independent CAS, fencing, TTL, lease, or batch operations does not establish
this contract.

The V1 transition itself has one linearization point. A later status operation
is a separate, read-only consensus-barrier observation; it does not submit the
user mutation again.

Only a store that proves `AtomicFencedTransitionCapability::V1` for the exact
current consensus voter scope may advertise or execute this primitive.
Before V1 is activated for that exact scope, capability, observation, and
status access, and admission of the first transition, require a fresh
authenticated V1 reply from **every** exact voter. A Raft quorum is not a
mixed-version proof: an unavailable or incompatible voter fails that
pre-activation access closed with
`StoreError::CapabilityNotSupported("atomic_fenced_transition_v1")` or the
applicable availability error. Legacy capability bits are insufficient
evidence.

The first authorized transition after that unanimous proof carries the current
scope identity and canonical voter-set commitment inside the same single user
transition command, log position, and state-machine application as its receipt,
lease action, and record effect. Apply atomically installs those effects, the
receipt binding, a one-way persistent schema-version downgrade fence, and, when
the scope needs one, its single-row exact-current-scope activation certificate.
It adds no separate user mutation or log position. These proof and commitment
fields are internal durable admission state, not public consumer-wire
semantics.

Once that command commits, ordinary linearizable Raft quorum availability is
sufficient for capability, observation, execution, and status in the certified
scope; leader loss or a minority outage does not re-trigger an every-voter
probe. A topology cutover deletes the old scope certificate but retains the
one-way activated schema fence and all receipt bindings. The successor scope
therefore needs a new every-voter proof and a first activating or recovery
transition, while a stable request ID and body can still recover its retained
receipt across the rollover.

## Lease and mutation rules

`FencedTransitionLease::Acquire` is a new credential allocation. It carries
the exact observed durable per-key fence floor, including deleted history. At
the transition point that floor MUST still equal `expected_fence`; the committed
fence is exactly `expected_fence + 1`, the owner is the requested owner, and a
new nonzero credential ID and expiry are minted. An unexpired active lease
still prevents acquisition. `FencedTransitionObservation` is the preparation
read for this rule; its observation does not reserve a fence.

`FencedTransitionLease::Renew` presents one exact, live `LeaseGuard`. Its key,
owner, fence, credential ID, acquisition time, and previous expiry must match
the active lease at the transition point. Renewing retains the fence,
credential ID, and acquisition time, and replaces only the expiry. A guard
that expires at the admission time is expired, not renewable.

Lease rows created by the published #684 predecessor did not persist an
acquisition timestamp. Upgrade marks that missing authority as `NULL`; it does
not derive or trust a caller-supplied timestamp. Such a legacy guard remains
safe to expire or be superseded, but renew, release, and fenced mutation fail
closed as stale until authority is reacquired. New acquisition, replication,
snapshot, and recovery paths preserve the exact normalized timestamp.
The exact published #684 database and snapshot shapes have no fenced receipt
ledger. A current writable open may add the exact empty ledger, activation
table, and zero marker as the Prepared layout while retaining the predecessor
schema version; no V1 receipt or authority exists yet, and an exact predecessor
reader remains safe. The first authorized activating command changes that
Prepared layout to Activated by installing the persistent higher schema fence,
the exact-scope certificate, and the first receipt atomically with its user
effect. After activation, a missing, weak, partial, or malformed fence or
receipt ledger is corruption and is never reconstructed. The certificate is
either the single exact-current-scope row or, only after a legitimate topology
cutover, absent while the successor scope awaits its new unanimous proof;
same-scope erasure, substitution, or malformed certificate state is corruption.
Main-database open and read-only recovery preserve this state; an exact
predecessor binary rejects the higher schema fence rather than silently reading
an activated database.

Snapshot installation additionally recognizes the exact older
Dynamic-consensus snapshot manifest that predates the #684 authority columns,
lease-acquisition timestamp, and fenced receipt ledger. That exception is
attached-snapshot-only, requires every historical schema product to match
exactly, and supplies only the same empty Prepared classification. It cannot
reopen an old main database, weaken Fixed authority, regress Activated to
Prepared, erase a receipt binding, omit the activated fence, or erase or
substitute a same-scope certificate. A legitimately unactivated successor
scope may have no certificate until its new proof and activating transition.
Every near-miss or hybrid layout fails closed. An offline pre-V1 minority is
not safe to catch up merely because it did not acknowledge the activating
command: an old reader could otherwise silently omit new snapshot state. The
persistent schema fence makes that follower reject the activated image until it
is compatible.

The mutation is exactly one of the following:

- `Create` requires an absent live record and installs generation `1`.
- `Update` requires the exact live `expected_generation` and installs exactly
  its successor generation.
- `Delete` requires the exact live `expected_generation` and removes that
  record.
- `RefreshTtl` requires the exact live `expected_generation`, is valid only
  with `Renew`, and replaces the existing record's deadline with committed
  admission time plus its requested TTL. It does not change generation.

For create and update, the supplied record's key and owner must match the
lease action, and its fence must be the fence that action commits. A renewal
that updates, deletes, or refreshes an existing record must additionally prove
that record has the renewed guard's owner and fence. An acquisition may take
over a record after it has minted the exact successor fence. A record whose
finite expiry is at or before committed admission time is treated as absent;
therefore it cannot satisfy an update, delete, or refresh expectation.

A successful `FencedTransitionOutcome` returns the committed `LeaseGuard`,
the committed generation, a typed mutation result (`Created`, `Updated`,
`Deleted`, or `TtlRefreshed { expires_at }`), the committed logical time, and
its retention deadline. It never echoes the record payload.

## Time, expiry, and bounds

All time-dependent checks use the committed consensus logical time. They do
not use a follower wall clock. Lease and refresh TTLs must be positive and no
greater than `MAX_SESSION_TTL` (exactly 365 days); exactly that maximum is
accepted and one nanosecond over it is rejected with
`StoreError::InvalidSessionTtl`. The resulting deadline must also be
representable.

Create and update validate an absolute record expiry at that same admission
time. `None` remains valid except for `StateClass::EphemeralProcedure`; a
finite expiry must be no more than `MAX_SESSION_TTL` ahead, and this
transition additionally rejects an expiry in the past or equal to admission
time. A finite deadline exactly 365 days ahead is accepted; one nanosecond
later is rejected with `StoreError::InvalidRecordExpiry`. Delete has no record
expiry input. Refresh always creates a finite deadline from its positive TTL.

The bounds relevant to this contract are fixed and enforced before allocation
or durable apply:

- `FencedTransitionRequestId` is exactly
  `FENCED_TRANSITION_REQUEST_ID_BYTES` (16) opaque bytes and may not be all
  zero. The outer consensus request ID must be identical.
- `FENCED_TRANSITION_MAX_HISTORY_ENTRIES` is exactly 4096 permanent
  ID/body-digest receipt bindings for one storage consensus identity. This
  includes full exact-result receipts and compacted tombstones. The limit is a
  protocol contract, not a local retention or recovery setting.
- The current SQLite consensus profile accepts a sealed record payload of
  exactly 1,048,576 bytes and rejects 1,048,577 bytes at follower admission
  and state-machine apply. More generally, callers must honor the selected
  consensus backend's advertised `BackendCapabilities::max_value_bytes`.
- The encoded inner payload of each consensus RPC request and successful
  response is bounded by `SESSION_CONSENSUS_MAX_RPC_PAYLOAD_BYTES` (2 MiB):
  exactly 2 MiB is accepted by the wire boundary and 2 MiB plus one byte is
  rejected. This transport payload cap is not an entitlement to a record
  payload of that size.
- A serialized public outcome is at most
  `FENCED_TRANSITION_MAX_OUTCOME_BYTES` (16 KiB): the byte ceiling is inclusive
  at 16,384 and rejects 16,385. Every valid current typed outcome remains
  strictly below that ceiling under the public field bounds, and its
  payload-free shape makes the response bound independent of the record
  payload.
- `PreparedFencedTransition` uses
  `FENCED_TRANSITION_PREPARED_SCHEMA_V1`, has at most
  `FENCED_TRANSITION_MAX_PREPARED_LAYERS` (8) SDK-owned protection frames, and
  is at most `FENCED_TRANSITION_MAX_PREPARED_BYTES` (2 MiB). Import rejects an
  over-limit, corrupt, noncanonical, trailing, or unsupported token before
  backend or provider work.

## Protected preparation and exact retry bodies

The production protected API is deliberately two phase. A caller first passes
its logical request to `SessionBackend::prepare_fenced_transition`. It MUST
durably persist the returned opaque `PreparedFencedTransition` before calling
`fenced_transition`, and it MUST retain those exact serialized bytes for every
retry and `fenced_transition_status` call. Execute and status borrow the token;
they do not consume it.

Preparation validates the logical request and exact V1 capability across the
complete wrapper stack first. For create and update it then obtains the
authoritative, payload-free record-expiry preflight before any provider call,
protects the record exactly once, validates the resulting physical request,
and lets the inner capable backend add its own bounded token frame. Delete and
refresh carry no record and perform no seal or unseal. The wrapper preserves
the request ID, lease, mutation metadata, record metadata, and committed fence
unchanged; only the create/update payload encoding changes.

The inner backend must explicitly attest that it preserves already protected
payload bytes unchanged through preparation and observation. Raw consensus
does so and transparent adapters forward that witness. Payload-transforming
adapters do not: nesting local and remote protection wrappers in either order
therefore advertises no atomic capability and fails before preflight, provider,
observation, or dispatch work. This prevents double sealing and prevents an
inner envelope from being mislabeled as caller plaintext.

The consensus receipt digest continues to bind the complete physical request,
including the exact `EnvelopeV1` bytes. A fresh nonce, active key, or remote
provider result therefore creates a different body and correctly conflicts
under the same request ID. Preparation never tries to recover a physical body
from readback, process memory, plaintext persistence, or an application-local
retry cache. After successful preparation, execute and status peel only their
bounded local token frame and use the retained physical bytes without provider
I/O, so restart and active-key/provider rotation cannot change the submitted
body. `NotTransmitted` may retry that same token. An `OutcomeUnknown` retains
that token for exact status recovery; `NotFound` still does not prove that a
delayed proposal cannot commit.

Fenced observation delegates the authority-consistent record/fence read and
then unprotects only a present record. It preserves `current_fence` exactly; an
absent record performs no provider call, and any protection failure returns no
partial observation.

The token is opaque application state, not an authorization credential. A
protected create/update token contains request metadata and ciphertext but no
payload plaintext. Its domain-separated digest detects accidental corruption;
it does not authenticate a malicious rewrite. Callers MUST keep tokens in
trusted, integrity-protected durable storage and MUST NOT emit their bytes,
request metadata, provider/key identifiers, or payloads through diagnostics,
logs, or metrics. The generic remote provider interface has no stable token-MAC
operation, so deployments requiring integrity against a writer that can
rewrite and recompute token bytes need a separately approved authenticated
token-storage boundary.

## Idempotency, retention, and uncertainty

The request ID is caller-retained and durably binds the complete canonical
request body to the stable storage/consensus identity: fenced-transition V1,
the lease action, every mutation field, and record bytes. The changing authorized
authority scope, leader timestamps, log position, forwarding origin, and retry
transport metadata are not caller semantics in that binding. Each execution or
status access is independently authorized under its current authority scope,
so an authority rollover does not strand a retained exact result.
An access carrying revoked predecessor authority returns only
`StoreError::TopologyAuthorityRevoked`: it does not disclose a retained result,
body conflict, history-cap state, or retention-horizon state. A currently
authorized successor can still recover or conflict with the permanent binding.

Within `FENCED_TRANSITION_OUTCOME_RETENTION` (exactly 24 hours from committed
logical time), replaying the same ID and complete body returns the original
success or deterministic no-effect result and performs no second mutation. The
same ID with any different canonical body is
`StoreError::FencedTransitionRequestConflict`; it never applies the new body.

Existing fenced receipts always take precedence: the same ID/body replays its
recorded or expired result, and a different body conflicts, even when the
ledger is full. The generic consensus outcome ledger shares the request-ID
namespace, so an otherwise absent fenced ID already used by a generic outcome
is likewise a `RequestConflict` before any capacity decision.

At 4096 fenced bindings, the ledger is absorbing for that storage consensus
identity. A still-unbound fenced ID returns
`StoreError::FencedTransitionHistoryFull` at its committed position before the
lease or mutation executes; it creates no receipt, lease, record, watch entry,
or application-sequence advance. It is replay-style only: committed logical
time and the applied log pointer advance, and the implementation may compact
at most one already-due exact-result response deterministically. Since a
finite ledger cannot durably bind rejected-at-full IDs, later same-body and
different-body attempts for the same still-unbound ID also return
`FencedTransitionHistoryFull`, rather than `RequestConflict`; they can never
execute under that identity.

The exact 24-hour deadline is never shortened or saturated. If committed
logical time plus that complete window is not representable, a still-unbound
ID returns `StoreError::FencedTransitionRetentionExhausted` before the lease or
mutation executes. This is the same bounded replay-style no-effect path as a
full history: no receipt or ID/body binding is created, application and watch
sequences do not advance, and only committed logical time, the applied log
pointer, and at most one already-due response compaction may advance. Because
logical time is monotonic, the condition is absorbing; later same-body and
different-body attempts remain `FencedTransitionRetentionExhausted` and can
never execute under that ID. Existing fenced or generic receipts and the
history-cap decision retain their precedence before this horizon decision.

At the retention deadline (including equality), exact replay and status are
expired. An exact replay deterministically compacts its own response; newly
executed commands compact at most one due response in a deterministic order.
Even before physical compaction, status applies semantic expiry at equality. A
permanent ID/body-digest tombstone remains across restart and snapshot.
Thereafter the same ID/body cannot execute again and returns
`StoreError::FencedTransitionRequestExpired`; a different body remains a
conflict. `fenced_transition_status` returns, for the same complete request,
respectively:

- `Recorded(result)` while its exact result remains retained;
- `RequestConflict` for a different body bound to the ID;
- `Expired` for the same body after retention; or
- `HistoryFull` for an unbound ID when the permanent ledger is at its cap; or
- `RetentionExhausted` for an unbound ID after the exact retention horizon is
  no longer representable; or
- `NotFound` when no binding existed at that status barrier.

`FencedTransitionStorageExhausted` is a retained, body-bound deterministic
no-effect result. It is returned only after ordinary stale-fence, CAS, and
lease admission has established that the transition would otherwise succeed.
The SQLite representability check covers the requested generation and fence,
the exact acquire fence successor and global successor, credential allocation,
the application and watch sequences, and the restore-scan revision. While
retained, the same ID and complete body exactly replays
`Recorded(Err(StorageExhausted))` and status returns that same recorded error;
a different body remains a conflict.
No lease, record, fence, watch, restore, or ordinary mutation effect occurs.
Existing fenced receipts and generic-ID conflicts, `HistoryFull`, and
`RetentionExhausted` retain precedence, and revoked authority masks all of
these storage states.

At the maximum application sequence, the result intentionally binds using the
current nonzero application sequence and digest, advances only logical time,
the applied pointer, and the receipt, and leaves the watch sequence unchanged.
Later blank or membership entries may still apply; this condition does not
promise that generic normal mutations remain available.

`NotFound` is not proof that an earlier delayed proposal cannot commit later.
Only an explicit submission of the identical ID and complete body is
idempotency-safe: it may create the first binding, replay or expire an existing
binding, or return an absorbing unbound rejection. The SDK does not
automatically resubmit after a possibly delivered forwarding write.
If `fenced_transition` returns `StoreError::FencedTransitionOutcomeUnknown`,
the caller MUST retain the exact ID and canonical body and use the bounded,
exact status operation. `HistoryFull` and `RetentionExhausted` are definitive
no-effect rejections, not unknown outcomes. Callers MUST NOT replay under a new ID,
infer an unknown outcome from local intent, continue writes under an uncertain
lease, or derive a next mutation until they have an authoritative observation.
A post-retention history must likewise be re-derived from current authoritative
state under a fresh ID; the old transition is never revived. The consumer wire
revision-3 contract preserves every status distinction, including
`StorageExhausted` inside `Recorded`, through a closed wire-safe enum. Frozen
legacy session-net v5 maps this result fail-closed as an unknown capability; no
v5 wire enum changes and that protocol does not expose the transition operation.

Each durable receipt carries a permanent commitment over fenced V1, its stable
storage identity, row request ID, canonical request digest, and normalized
retention deadline. A retained response additionally carries a commitment over
its canonical typed result and committed metadata. Compaction clears the
response and its response commitment atomically while preserving the permanent
binding commitment. Reopen, status, recovery, and snapshot installation verify
these commitments and reject non-normalized timestamp text or a valid-shaped
result substituted for the originally committed result.

Snapshot installation also preserves monotonic local durability floors before
replacing any state: consensus logical time, application sequence and digest,
watch sequence and cursor-invalidation floor, recovery epoch and plan digest,
and any pending recovery workflow. An exact published #684 snapshot may supply
the empty Prepared layout only when the destination is still Prepared; it
cannot erase a binding or regress an Activated destination. Activated snapshots
must carry the persistent schema fence, any exact-current-scope certificate,
and the complete bounded ledger, including compacted tombstones.

## Validation and diagnostics

Request construction and the public entry point run time-independent semantic
checks before capability probing: nonzero request identity, same key, owner and
fence binding, generation shape, positive and bounded TTL, and record-expiry
profile. Sealed-record envelope, payload-shape, and backend payload-size checks
then run at source admission before any `ForwardMutation` transmission and are
repeated at leader preproposal, follower-log admission, and state-machine
apply.

The leader assigns an immutable command-time floor but does not submit a
separate logical-time preflight. After current-scope authorization,
state-machine apply checks the durable receipt namespace before new-execution
validation; an exact receipt replay remains exact through finite record/lease
input expiry and until receipt-retention equality. Only after a receipt miss,
and after generic-collision and history-cap precedence, do time-dependent
new-execution checks run at the effective committed admission time: the maximum
of the previous committed logical time and the command-time floor. Capability,
membership, receipt, reopen, snapshot, and recovery validation fail closed at
their own boundaries.

Diagnostics are intentionally bounded and non-identifying. Debug formatting,
errors, logs, and metrics redact request, outcome, key, owner, and payload
values. The authorized typed success response necessarily returns its complete
committed `LeaseGuard` credential to its caller; that API value is not a
diagnostic, and the response never returns the record payload. Validation
errors use typed outcomes and SDK-controlled reason
categories; the size error may report only the requested and maximum byte
counts. Diagnostics do not expose opaque IDs, record payloads, keys, owners,
timestamps, topology endpoints, or local storage details.

## Deliberate boundary

This remains generic SDK semantics. Consumer transport revision 3 carries the
same capability, observation, execution, ambiguity, and exact-status contract
over both the one-shot and bounded persistent least-authority mTLS clients
published by #695. It does not expose a generic backend, replication,
membership, snapshot, rebuild, or administrative authority. Product/ePDG
composition and workflow semantics remain outside this SDK operation.

For that consumer surface, the public request ID is byte-identical to the
nested transition ID. The internal receipt ID is domain-separated by the
authenticated consumer identity, stable cluster identity, and public ID; it
excludes the body and changing configuration epoch. The receipt itself binds
the complete canonical body. The current exact scope is enforced under the
activation lifecycle above, so an authorized successor can recover across
rollover while a revoked predecessor cannot observe the receipt. No separate
`BindConsumerRequest` or log entry exists.
