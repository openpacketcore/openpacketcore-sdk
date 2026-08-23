# Atomic Fenced Transition Contract

This document defines the generic V1 store-side contract from issue #696 and
the protected V2 composition from issue #701. It covers
`AtomicFencedTransitionCapability`, `FencedTransitionRequest`,
`FencedTransitionOutcome`, and `FencedTransitionStatus` in `opc-session-store`.
It is not a product workflow or a network protocol.

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
  backend or provider work. A fixed magic/version/body-length header is parsed
  before the frozen V1 body, so an unknown schema is rejected without trying
  to decode it as the current layout. A golden compatibility corpus pins both
  lease forms, every mutation, no-expiry and finite-expiry record shapes, and
  every supported local/remote/consensus protection-stack shape and order.

## Protected preparation and exact retry bodies

The raw physical store and authenticated-consumer transport contract is exactly
`AtomicFencedTransitionCapability::V1`. The production protected API is a
separate V2 composition: it advertises
`AtomicFencedTransitionCapability::V2` only when the outer
`EncryptingSessionBackend` or `RemoteSealingSessionBackend` owns an open,
SDK-owned caller-side `PreparedFencedTransitionJournal` and its exact inner
physical boundary advertises V1. It does not reinterpret an inner V1 as V2.
Constructing either protection wrapper without that journal remains source
compatible, but its protected observation, prepare, execute, status, recovery,
and capability paths fail closed. Raw V1 stores, raw consumer transport, and
older binaries MUST NOT operate the journaled protected atomic path.

The application supplies one caller-stable `FencedTransitionRequestId` that it
can reproduce after restart. It MUST represent the same logical operation for
the operation's whole recovery lifetime and MUST NOT be replaced merely because
status returned `NotFound`. The SDK journal is the sole durable recovery copy
of the complete protected token. A legacy prepared token retained only by the
application, application persistence of request state, plaintext, record keys,
provider state, or a second intent transition is insufficient and does not
enable V2 recovery.

Preparation validates the logical request and exact V1 capability across the
complete wrapper stack, and rejects an ID already present in the journal before
expiry preflight or provider work. For create and update it then obtains the
authoritative, payload-free record-expiry preflight before any payload-provider
call, protects the record exactly once, validates the resulting physical
request, lets the inner V1 backend add its bounded physical marker, and commits
the final outer opaque token to SQLite before returning. Delete and refresh
carry no record and perform no seal or unseal. The wrapper preserves request
identity and all non-payload fields; only the create/update payload encoding
changes. A concurrent race for the same previously absent ID may perform more
than one pre-dispatch provider call, but exactly one immutable journal binding
wins and every loser is a conflict before transport dispatch.

`recover_prepared_fenced_transition(id)` reads that immutable binding after a
process restart and returns `Found(exact_token)` or `Absent`. `Absent` describes
only this journal, never excludes an earlier delayed transport/consensus
request, and never permits deletion of the retained binding or reuse of the
ID. Execute and status first reload the row, authenticate it, and compare the
complete canonical bytes with the supplied token; only that journal copy may
be dispatched. A missing, wrong-key, locked, incompatible, corrupt, or
byte-mismatched journal fails before transport and performs no provider or
transport I/O. Execute reports a condition that proves this invocation did not
dispatch—including a local binding mismatch—as `NotTransmitted`. `Rejected`
is reserved for a confirmed rejection returned by the inner effect boundary;
status and recovery have no `NotTransmitted` result variant and instead return
their typed local fail-closed result without dispatch.

The inner backend must explicitly attest that it preserves already protected
payload bytes unchanged through preparation and observation. Raw consensus
does so. The explicit authenticated-consumer physical bridge is only for use
beneath a protected journaled wrapper, serves the atomic subset only, and fails
every unrelated `SessionBackend` operation without I/O; it never implements
`SessionLeaseManager`. Its token marker binds an opaque commitment to the local
authenticated consumer SPIFFE identity and stable consensus-cluster ID only. It
excludes endpoint/address, TLS server name or identity, current leader or node,
configuration ID/epoch, transport lane, certificate/key, and material epoch, so
a retained token survives authorized endpoint, leader, topology, and credential
rotation. Each new call still performs ordinary current-scope mTLS
authentication and authorization. Payload-transforming adapters do not forward
the witness: nesting local and remote protection wrappers in either order
therefore advertises no atomic capability and fails before preflight, provider,
observation, or dispatch work.

The consensus receipt digest continues to bind the complete physical request,
including the exact `EnvelopeV1` bytes. A fresh nonce, active key, or remote
provider result therefore creates a different body and correctly conflicts
under the same request ID. Preparation never tries to recover a physical body
from readback, process memory, plaintext persistence, or an application-local
retry cache. After successful preparation, execute and status use the retained
physical bytes without provider I/O, so process restart and active-key/provider
rotation cannot change the submitted body. `FencedTransitionExecuteError`
separates `NotTransmitted`, `OutcomeUnknown { request_id }`, and confirmed
`Rejected` results. Any lower-layer may-have-sent ambiguity, including an
invalid returned identity, remains `OutcomeUnknown` under the expected prepared
identity. `NotFound` still does not prove that a delayed proposal cannot commit.

Fenced observation delegates the authority-consistent record/fence read and
then unprotects only a present record. It preserves `current_fence` exactly; an
absent record performs no provider call, and any protection failure returns no
partial observation.

### Journal persistence and security

Provisioning and recovery are separate operations.
`PreparedFencedTransitionJournal::create_new` MUST be used exactly once for a
missing dedicated database; it creates the leaf exclusively and rejects an
existing path. Every restart MUST use `open_existing`, which neither creates a
leaf nor initializes a pristine, truncated, reset, or partial database. The
deprecated `open` alias has the same fail-closed reopen behavior and never
provisions storage.

Both operations take a stable 32-byte
`PreparedFencedTransitionJournalKey`. The key MUST be independent of payload
encryption, remote provider, TLS, and record keys, unique to this exact journal
path/storage boundary, and restored unchanged after a process restart. It is
never stored in the database and MUST NOT be reused for another journal. On
Unix every existing ancestor is descriptor-walked without following symlinks.
The immediate parent and database MUST be owned by the effective user, with no
group or other access (normally `0700` and `0600`, respectively); the database
MUST be a regular, single-link bounded file. The containing directory MUST
reserve the configured leaf plus its derived `-wal`, `-shm`, and `-journal`
names exclusively for this journal. The SDK retains and revalidates the full
ancestor chain, admitted parent/file identity, bounded sidecar metadata, and
SQLite main-file movement state around every operation. Before the sole live
SDK connection opens, a process-local inode admission lease permits one bounded
main-header read; that descriptor closes before SQLite locking begins. No main
or SHM descriptor is retained or opened while an SDK connection is live,
because closing one could release SQLite's process-scoped POSIX locks. The
configured raw integrity key is length-framed into a schema- and
checked-absolute-path-derived key, without persisting or emitting the path.
The journal requires a local filesystem with truthful POSIX locks, `fsync`,
directory sync, and storage-barrier semantics; NFS-like mounts are unsupported.
Another process running with the same effective user and equivalent
path-replacement authority is inside that trust boundary, not an adversary the
SDK can isolate from its own files. Within one process, callers MUST clone the
admitted SDK journal handle rather than reopen the same inode or open it
directly through SQLite. The SDK enforces one live SQLite connection per
admitted inode so its pre-open header check cannot release another connection's
process-scoped POSIX locks. Platforms without the Unix path and SQLite-VFS
checks fail closed rather than advertise V2.

The schema-3 journal uses an application ID, strict tables, a pre-open fixed
page/cache-header check, bounded main/WAL/SHM files, a fixed private page cache,
bounded SQLite limits, a tight initial schema VDBE-work budget and a
separate full-operation budget, bounded catalog/membership scans, WAL,
`synchronous=EXTRA`, `fullfsync`, `checkpoint_fullfsync`, and an atomic
create-only ID binding. Successful provisioning and row insertion independently
sync the held parent directory before returning. It assigns every
journal incarnation a fresh bounded random value and stores an authenticated
membership count and root over the complete request-ID/integrity-tag set. The
membership HMAC commits that incarnation, count, and root; health, lookup,
recovery, and insertion validate the complete small bounded set. Lookup
authenticates the selected token, while insertion re-authenticates its new row,
updates membership metadata in the same transaction, and verifies the result
before commit. A fixed `(request_id, integrity_tag)` covering index keeps a full
membership proof independent of retained token size, and read-only proofs use
WAL snapshots rather than reserving the writer. The schema catalog is an exact
whitelist of the SDK tables, generated primary-key autoindex, and membership
index; every other catalog object, including a reserved-prefix object, is
rejected before journal setup. The authenticated membership index is the
presence authority; its bounded scan cross-validates every rowid, request ID,
and fixed tag against the table and compares independently bounded table and
primary-index scans. Schema 3 stores that fixed tag before the potentially
overflowing prepared body, so the global proof never reads retained bodies. A
selected row separately validates its body against the authenticated tag.
Table/primary/secondary-index divergence therefore cannot become false absence
without making full proofs depend on retained body size. The
journal rejects a wrong key, foreign or
partial schema, unsupported version, corrupt metadata/row, and insecure or
changed path with one fixed coarse availability error. An authenticated full
journal rejects a new ID before expiry, provider, or inner-prepare work.

The journal HMAC authenticates stored bytes but does not encrypt them. A
protected create/update row contains request metadata and ciphertext (never
payload plaintext); record-free transitions still contain their metadata.
The journal therefore belongs on the same trusted private durability boundary
as other sensitive SDK metadata. Token bytes, rows, payloads, identities,
request IDs, paths, keys, request metadata, and provider material MUST NOT be
emitted in examples, fixtures, logs, metrics, errors, diagnostics, crash
evidence, or PR evidence.

This integrity proof detects offline row deletion, addition, primary-key
replacement, and tag corruption within the same durable journal file. A
corrupt selected body fails its exact row authentication and cannot be treated
as absent or rebound. It cannot distinguish restoration of an older complete,
internally valid database snapshot from that older state itself. Whole-database
rollback is outside the same-durable-file guarantee unless deployment supplies
an external monotonic anti-rollback anchor.

The SDK retains canonical token bytes and complete-body import/re-encoding
scratch buffers in wiping allocations. Journal HMAC uses a zeroize-on-drop SHA
state and wipes key-derived pads and intermediate digests. This reduces
allocator residue but does not encrypt the SQLite page cache, filesystem cache,
WAL, storage media, backup, or copies made outside the SDK.

V2 proves process-restart recovery only while the same durable volume, path,
journal key, protection mode/namespace, stable client identity (for the
consumer bridge), and stable consensus cluster remain available. A resolver may
select another authenticated endpoint and a successor configuration may have a
different leader, members, server identity, configuration ID, and epoch. V2
does not claim host failover, host or volume-loss recovery, a replicated
journal, or a second consensus transition. Deployments that reschedule
processes MUST mount the same durable volume and secret. If that boundary is
unavailable before this invocation can dispatch, execute returns
`NotTransmitted`; loss after an earlier ambiguous dispatch is outside the V2
guarantee and must not be described as recovered.

## Prepared-token compatibility and upgrades

The prepared-token wire schema and the journal database schema are separate,
versioned durable formats and, together with capability V2, are downgrade
fences. The current journal can retain only canonical
`FENCED_TRANSITION_PREPARED_SCHEMA_V1` tokens, and its current database
`user_version` is three. Schema 3 changes the physical row order and every
journal-authentication domain, and derives the configured raw journal key from
the checked absolute path. The unshipped schema-2 prototype is deliberately
incompatible and has no in-place migration or downgrade path. Neither durable
version is inferred from the record envelope, consumer wire, or consensus
capability. `AtomicFencedTransitionCapability::V2`
is a local composition promise over an inner V1 physical contract; it does not
rename the consensus or revision-5 authenticated-consumer wire as V2.

A rolling upgrade MUST ensure every process that may execute or query a retained
request understands both schemas and uses the same journal key/path and bound
composition before a new writer is enabled. Unknown journal/token versions,
partial schemas, and unsupported protection markers fail closed before
provider, readback, or transport work. The old reader and original compatible
stack MUST remain available until every retained request is resolved and every
possible delayed proposal is accounted for. A rollback image that predates V2
cannot recover this journal and MUST NOT be deployed until a complete drain; a
compatible rollback must retain every emitted reader plus the same journal and
key. There is no automatic downgrade, token rewrite, journal copy/rekey,
reseal, reconstruction, or in-flight migration path. The V2 journal layer
supplies no journal garbage collection, retention policy, ledger-lifetime
extension, or capacity solution: its fixed bounded row limit is an admission
fence, not a lifecycle claim.

The prepared-token trait surface is intentionally source breaking for custom
backends that previously accepted a raw request at execute or status time. A
third-party backend must implement preparation, exact-token execution, and
exact-token status explicitly, and may attest protected-payload preservation
only when every forwarding and durable layer preserves those bytes unchanged.
Unmodified or partially upgraded adapters retain the trait's fail-closed
defaults and do not advertise V1. There is no compatibility shim that can
safely infer an exact protected body after an ambiguous dispatch.

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

## V2 epoch-fenced history (#702)

This is a distinct protocol contract from the protected V2 composition in
[#701 protected preparation and exact retry bodies](#protected-preparation-and-exact-retry-bodies).
That #701 composition remains a local SDK promise over an inner physical V1
contract: its `fenced_transition` uncertainty path recovers the SDK-journal
token. This #702 protocol has its own 56-byte V2 identity, epoch lifecycle,
receipt capacity, maintenance, and revision-5 consumer lane; its
`fenced_transition_v2` uncertainty path uses that exact V2 ID and canonical
body. Neither contract reinterprets, upgrades, routes, or otherwise replaces
the other.

V1 is frozen. Its 4,096-entry receipt ledger is permanently absorbing for the
storage consensus identity, including after every receipt result has become a
digest tombstone. Implementations MUST NOT reinterpret V1 requests, increase
the V1 limit, locally delete V1 tombstones, or silently route V1 callers to
V2. The V1 capability continues to mean exactly the contract above.

V2 is an explicit, separately probed protocol with schema version 2 and
`FencedTransitionV2Capability::V2`. This capability is distinct from
`AtomicFencedTransitionCapability::V2`, which only promises protected
prepared-token journal recovery. A V2 proof carries the immutable V2 profile
digest; the digest covers the schema, full identity layout, canonical
body-commitment domain, active-epoch limit, operational target, and reclaim
batch. The fixed profile digest is published by
`fenced_transition_v2_profile_digest()` and is exactly
`8a0b70b54654c7250cf5469db6e1e545f35e38e9778d5f500fea670696c4bdc3`.
Before activation, every voter in the exact current voter set, including a
prospective joining voter when it participates in the cutover, MUST reply to
the V2 probe with that exact profile digest. A quorum, a V1 reply, a capability
bit, or a V2 reply with another profile is not evidence.

V2 retains exactly one writable epoch plus at most seven closed, exactly
replayable epochs. Its ceiling is therefore 1,048,576 V2 receipt bindings and
18,469,617,664 semantic bytes. V1's permanent 4,096-binding ledger remains
separate and absorbing, so the combined V1+V2 ceiling is 1,052,672 bindings
and 18,541,535,232 semantic bytes. At the retained-epoch ceiling, reclamation
advances only the retired floor and removes the oldest closed replay epoch in
fixed batches after that epoch's final retention deadline; the active epoch
remains writable throughout reclamation.

The first V2 transition for a scope is one replicated activating command. It
atomically installs the V2 database format (format 3), the exact-scope
activation certificate and immutable profile, its V2 receipt, and its lease
and record effect. A topology cutover clears the old scope certificate; it
does not clear V2 history, the retired floor, or V2 format activation. The
successor scope must obtain a new unanimous exact-profile proof before its
first V2 activating/recovery transition. This is deliberately independent of
V1 activation.

### V2 identity and admission order

A V2 request ID is exactly 56 bytes:

- history epoch in `1..=i64::MAX`, encoded as an 8-byte unsigned integer;
- caller-retained 16-byte nonce; and
- the complete 32-byte SHA-256 commitment to the canonical V2 request body.

Every V2 command and receipt timestamp uses canonical RFC 3339 and the fixed
inclusive year range `0000..=9999` (Unix seconds
`-62167219200..=253402300799`). Optional date-range features may not widen
this profile. Maintenance command time and every derived lease, refresh, and
retention deadline are checked against the same range before any projection or
durable mutation.

The commitment domain includes the V2 schema, epoch, nonce, and canonical
lease/mutation body. All 56 bytes are persisted and compared; no prefix or V1
16-byte namespace may be used. A request is self-authenticated before any
active/retired-floor lookup, receipt lookup, capacity decision, or mutation
admission. Thus a request that keeps an old full ID but substitutes a body is
`FencedTransitionRequestConflict`, even after its epoch's receipt rows have
been deleted. A valid old exact retry reaches the retired floor and returns
`FencedTransitionHistoryEpochRetired` (`FencedTransitionV2Status::Retired`);
it never executes. This ordering is security-significant.

A valid request above the retired floor that does not name the current active
epoch returns `FencedTransitionHistoryEpochNotActive` (status
`EpochNotActive`) without an effect. This includes the immediate successor
while all eight retained epoch slots are occupied. Unlike `Retired`, this
state is not terminal for that epoch: after eligible reclamation frees the
oldest replay slot, a separate maintenance linearization may open the immediate
successor only when the current active epoch is full. Callers must re-read the
linearized history state before deriving new work.

### Epoch lifecycle and maintenance

Only the active V2 epoch accepts new identities. Its exact hard maximum is
131,072 bindings. An implementation must support at least 100,000 committed
unique transitions in one active epoch; the remaining 31,072 bindings are
headroom, not a second configurable limit. Exact results retain the same
24-hour window as V1. There is no age-only cleanup and no local cleanup: a node
may not retire, delete, or open an epoch based on its own clock, compact cycle,
restart, snapshot restore, or memory pressure.

History reclamation is an explicit replicated operator-maintenance command,
available only at the local state-process operator boundary under durable
fixed-quorum authority. The operator entry point is local-leader-only and is
not forwarded through the ordinary application surface; an operator loop MUST
resolve the current leader again after a term change and before each batch. It
is eligible only after the maximum retained deadline of the oldest closed replay
epoch. The first command atomically advances the irreversible retired floor and
deletes the first ordered, fixed 1,024-row batch while preserving the sole
active epoch as writable. Every command is compare-and-set against the observed
lifecycle generation and epoch/floor state. Subsequent commands delete one
ordered batch; the final batch completes physical deletion without changing the
active epoch. The floor is included in recovery and snapshots, so physical row
deletion cannot reopen an identity.

A maintenance transport failure is ambiguous: its lifecycle CAS may already
have committed even though the caller did not receive the reply. The operator
MUST obtain a fresh linearized V2 history state before retrying. If that state
differs from the complete state supplied to the ambiguous CAS, the observed
state is authoritative and the stale CAS MUST NOT be replayed as a request for
another batch. If the complete state is unchanged, retrying that same CAS is
safe. An unavailable reply alone is never evidence that a batch did or did not
commit, and an operator MUST NOT manufacture a later expected generation.

### Capacity and operational sizing

At most 1,052,672 receipt bindings coexist: V1's fixed 4,096 plus eight V2
epochs of 131,072 bindings each (one writable epoch and seven closed replay
epochs). For qualification accounting, a maximum retained V2 row is a
17,408-byte persisted response allowance plus 206 bytes of fixed logical
metadata: 56-byte full ID; 8-byte history epoch; 8-byte ordered epoch ordinal;
8-byte storage configuration epoch; 32-byte canonical body digest; 30-byte
canonical retention timestamp; 32-byte binding digest; and 32-byte response
digest. Therefore one maximum V2 row is 17,614 logical bytes and the eight-epoch
V2 maximum is 18,469,617,664 bytes (17.201 GiB). The V1 row remains 17,558
logical bytes (the same 17,408-byte persisted response allowance, plus 16-byte
ID, 8-byte configuration epoch, 32-byte body digest, 30-byte deadline, and two
32-byte digests); the combined V1+V2 maximum is 18,541,535,232 bytes
(17.268 GiB). These figures deliberately exclude SQLite B-tree, index, page,
WAL, snapshot envelope, and filesystem allocation overhead; deployment capacity
must add those measured overheads rather than treating the logical total as a
disk reservation.

One canonical JSON singleton or per-item outcome remains at most 16 KiB: the
larger 17,408-byte persisted allowance includes durable serialization and
envelope budgeting, and history size does not make one outcome larger. The
fully Postcard-encoded V2 batch request vector and outcome vector each have an
exact 1 MiB (1,048,576-byte) bound. These are inner codec payload bounds; the
outer authenticated-consumer JSON frame remains subject to its separately
negotiated frame bound. Snapshot transfer must budget the combined logical
maximum above plus its envelope and storage-engine overhead; it must stream,
not materialize all receipt outcomes in memory.
Lookup is a keyed/indexed operation, maintenance scans only the deterministic
ordered 1,024-row batch, and durable lifecycle counters (`active_epoch`,
`retired_through`, generation, bound entries, reclaimed entries) make status
and admission avoid a runtime full-history memory scan. No counter may be
reconstructed from a node-local age cleanup pass.

`NotFound` is not proof that an earlier delayed proposal cannot commit later.
Only an explicit submission of the identical ID and complete body is
idempotency-safe: it may create the first binding, replay or expire an existing
binding, or return an absorbing unbound rejection. The SDK does not
automatically resubmit after a possibly delivered forwarding write.
For the protected V1 composition, if `fenced_transition` returns
`FencedTransitionExecuteError::OutcomeUnknown { request_id }`, the caller MUST
retain that stable ID, recover the SDK-journal token, and use the bounded exact
status operation. For the distinct epoch-fenced protocol, if
`fenced_transition_v2` returns
`StoreError::FencedTransitionOutcomeUnknown`, the caller MUST retain the
exact V2 ID and canonical V2 body and use its bounded exact status operation.
In either contract, `HistoryFull` and `RetentionExhausted` are definitive
no-effect rejections, not unknown outcomes. Callers MUST NOT replay under a new
ID, infer an unknown outcome from local intent, continue writes under an
uncertain lease, or derive a next mutation until they have an authoritative
observation.
A post-retention history must likewise be re-derived from current authoritative
state under a fresh ID; the old transition is never revived. The consumer-wire
revision-5 V1 contract preserves every V1 status distinction. The distinct V2
consumer ALPN uses wire revision 5 and preserves every V2 status distinction,
including `EpochNotActive` and `StorageExhausted` inside `Recorded`,
through a closed wire-safe enum. Frozen legacy session-net v5 maps this result
fail-closed as an unknown capability; no v5 wire enum changes and that protocol
does not expose the transition operation.

Each durable V2 receipt carries a permanent, V2-domain-separated binding
commitment over the V2 schema and immutable profile digest, stable storage
identity, complete 56-byte request ID, history epoch, ordered epoch ordinal,
canonical request payload digest, and normalized retention deadline. A retained
response additionally commits the exact fixed-codec response bytes, including
its typed result and committed metadata. Compaction clears the
response and its response commitment atomically while preserving the permanent
binding commitment. Reopen, status, recovery, and snapshot installation verify
these commitments and reject non-normalized timestamp text or a valid-shaped
result substituted for the originally committed result. V1 retains its separate
frozen commitment format and is never reinterpreted as V2.

Snapshot installation also preserves monotonic local durability floors before
replacing any state: consensus logical time, application sequence and digest,
watch sequence and cursor-invalidation floor, recovery epoch and plan digest,
and any pending recovery workflow. An exact published #684 snapshot may supply
the empty Prepared layout only when the destination is still Prepared; it
cannot erase a binding or regress an Activated destination. Activated snapshots
must carry the persistent schema fence, immutable V2 profile, any exact-current
scope certificate, the nonregressing retired floor and reclaim cursor, and
every binding not covered by that floor, including compacted tombstones.

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

This remains generic SDK semantics. The consumer transport revision-5 V1
surface retains #695's capability, observation, execution, ambiguity, and
exact-status contract over both the one-shot and bounded persistent
least-authority mTLS clients. Its public transition ID is the frozen 16-byte V1
ID. V2 does not extend that wire shape: it uses the separate ALPN `/2`
revision-5 lane documented above, including V2's full 56-byte identity and
V2-specific status set. Neither lane exposes a generic backend, replication,
membership, snapshot, rebuild, or administrative authority. Product/ePDG
composition and workflow semantics remain outside this SDK operation.

For the V1 revision-5 consumer surface, the public request ID is byte-identical
to the nested 16-byte V1 transition ID. The internal V1 receipt ID is
domain-separated by the authenticated consumer identity, stable cluster
identity, and public ID; it excludes the body and changing configuration epoch.
The receipt itself binds the complete canonical body. The current exact scope
is enforced under the activation lifecycle above, so an authorized successor
can recover across rollover while a revoked predecessor cannot observe the
receipt. No separate `BindConsumerRequest` or log entry exists.
