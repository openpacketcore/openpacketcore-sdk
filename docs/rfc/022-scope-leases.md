# Scope authority and atomic child batches

Status: experimental scope profile 4, implementing untimed authority alongside
atomic child batches and activation continuity. Authority may land independently
after work-class scheduling, while profile 4 remains unadvertised. Its current
activation digest is provisional: independent batch lanes and namespace scans
update it as they land. The composed profile is advertised only after all
components pass joint qualification; authority alone is not a separately
supported installation profile. Code review and integration qualification
precede release or a consumer pin.

## Untimed authority

Scope authority has one untimed contract. Ownership never
expires: store unavailability delays mutations while installed forwarding can
continue. Same-cohort succession requires positive predecessor-closure
evidence. Unconfirmed loss cannot authorize recovery of that cohort.
Retirement and selection of a new, empty incarnation require a later profile.

### API and admission

`scope_authority` replaces the previous timed module: `ScopeId` retains the existing
cluster/tenant/network-function/opaque-slot domain; `ScopeAuthorityStore` and
`ScopeBatchStore` take durable consensus and `ScopeAuthorityAdmission`, with
no clock argument. The former timed operations, remote exclusion and timeout-based succession
are removed; no compatibility aliases or infinite-duration permit remain. Ordinary RPC deadlines bound waiting only.

`ScopeAuthorityRequest` carries the scope, nonzero request ID, exact expected
authority revision and operation. Its operations are:

| Operation | Committed transition |
| --- | --- |
| `AdmitInitial { execution }` | An unused domain starts incarnation 1 with the verified boot and its positive admission generation. |
| `SucceedClosed { predecessor, execution, evidence }` | Compare the exact predecessor stamp, consume verified closure evidence and a strictly higher verified admission generation, and replace the execution atomically within the same incarnation. A retained successful Close can supply the closure evidence. |
| `Close { current, evidence }` | Mark that exact execution closed after verified closure; retain its identity, generation floor and outcome. It cannot reopen. |

| Action | Worker role | Observer role | Scope controller role |
| --- | --- | --- | --- |
| `AdmitInitial` | Candidate boot itself, with its verified ticket | Denied | Denied |
| `SucceedClosed` | Verified successor boot, with closure evidence | Denied | May submit the exact successor request with verified candidate and closure evidence |
| `Close` | Current execution closing itself, with verified closure evidence | Denied | Denied |
| Current state / exact outcome reads | Authorized scope and boot | Authorized scope, read only | Authorized scope, read only |

These are scope roles; RFC 023's narrow voter-controller role does not acquire
worker permissions. A controller submission returns an outcome, never the
successor's capability. The successor obtains `CommittedScopeAuthority` by
authenticating as that exact boot and retrying the controller's complete
request, including its ID, expected revision and evidence digest. This retry
issues the capability only if the committed successor is still current.

The admission hook enforces those roles independently of request claims.
It verifies the entire candidate boot binding and proof of its process key on
the authenticated channel, bound to the request digest. Shared credentials,
copied tickets, arbitrary higher numbers and liveness responses alone confer
no admission. Fresh admission uses the independently authoritative current
selection, not a client assertion or stale cache. Proof objects are constructed
only by trusted verification adapters; decoding claims cannot construct them.
Closure means **the predecessor process can no longer submit store mutations
or peer-control effects**. A committed `Close` or verified final termination
of that exact process/container proves closure. Installed kernel forwarding
is explicitly excluded: it may continue across a container restart. The platform
adapter resets pin-less predecessor graphs under containment and verifies the rebuilt state;
it never adopts a pin-less graph. A self-Close verifies that the current boot
has shut its mutation and peer-control paths; committing Closed then fences
its store writes permanently.

`ScopeAuthorityAdmission::verify_closure` replaces the old unchecked closure
constructor. The service creates an opaque `VerifiedScopeClosure` only after
the configured trusted verifier validates the predecessor binding and closure kind;
neither request deserialization nor an unchecked public constructor can.
Bind the token's evidence digest into the authority request digest so retries
cannot exchange closure evidence. Missing or uncertain evidence leaves
succession pending; neither a timeout nor absence from an external status API
substitutes for it.

`current()` returns a linearizable `ScopeAuthorityView`, including the retained
generation floor for issuer reconciliation. An admission/succession commit or
its exact retry can return non-deserializable `CommittedScopeAuthority` only
to the authenticated boot while its authority remains current. A view or old
success result cannot construct this capability. The serializable
`ScopeAuthorityStamp` binds scope, worker incarnation, authority revision and
the complete `ScopeExecution`, including admission generation and the boot-key
commitment. Adapters check
the capability against their own current execution and local generation;
reconnect does not change a boot, whereas restart requires a new nonce/key,
higher admitted generation and verified predecessor closure.
`CommittedScopeAuthority::closed_predecessor()` retains the exact positively
closed predecessor only for a committed `SucceedClosed`, including an exact
authenticated retry. Initial admission returns no handoff provenance. Namespace
restore uses this opaque capability fact to admit restore; it does not infer a handoff from
an observed generation or deserialize one from a wire view.

`ScopeBatchRequest` replaces its permit with that stamp. `ScopeBatchStore`
binds an explicit `ScopeNamespace { scope, incarnation }`; reads and future
scans retain this binding instead of silently following a replacement cohort.

### Durable state and apply invariants

Retain one bounded authority row per stable scope:

```text
view {
  scope, revision, retired_through, admission_generation_floor,
  stamp: Option<{
    namespace { scope, incarnation }, revision,
    execution { identity, admission_generation, workload, process, boot_key }
  }>,
  active, closed_digest: Option<[u8; 32]>
},
last_request_id, last_digest
```

`closed_digest` retains the committed Close's exact evidence digest for
`CommittedClose` succession. `last_request_id` and `last_digest` identify the
last accepted request; the current view supplies its result without a separate
stored outcome field.

`view.stamp.execution.boot_key` is the nonzero 32-byte boot-key commitment verified
by the authenticated admission adapter. The authority row commits it atomically
with the exact boot binding. It is included in the immutable request digest and every authority stamp, checked
at apply, and retained through Close, replay, compaction and snapshots. A
successor must supply a fresh independently verified boot key. This commitment
is part of the first profile-4 authority encoding, not a later format addition.

`ScopeIncarnation` is a positive ordered integer identifying a worker cohort.
Remove the former workload-incarnation UUID from `ScopeExecution`; retain the
exact workload identity, process nonce and independently verified boot-key
commitment alongside its admission generation. RFC 023's voter incarnation
is separate. UUIDs are never converted into numeric authority. An unused domain
has zero floors and no execution. Thereafter `current_incarnation >
retired_through`; execution state is Active or Closed. Incarnation, generation
and revision counters use checked arithmetic within the SDK's signed range.
Admission generations increase across the whole scope, including incarnation
changes; the retained floor equals the latest committed execution's generation.
Close and compaction never reset it.

Every newly applied child/claim/counter mutation must match the committed
scope, current incarnation, Active execution, generation and authority
revision, and exceed `retired_through`. Perform this comparison inside the
same atomic apply as the existing child versions, claims, counters and batch
receipt. Leader-side admission/preflight is insufficient. A batch prepared
before succession, closure or retirement but ordered afterward has no effect.
Native and SQLite apply use the same transition predicates. Authority revisions
advance only on authority changes; child/lane revisions remain separate, so
independent batches do not invalidate each other's authority stamps.

Child, claim and future scan identities bind `(scope, incarnation)`.
The batch checkpoint stays keyed by **stable scope**: its revision, 16
monotonic counters and child-birth floor never reset on incarnation selection
or namespace reclamation. Only a batch authorized by the current incarnation
may advance them. Apply refuses `next < expected` for every counter;
`next == expected` compares that counter without changing it. Accounting that
must decrease belongs in child rows. Lane receipts bind their request's
incarnation; independent lanes must preserve their sequence floors independently
of namespace reclamation.
`AdmitInitial` creates the required stable checkpoint atomically with authority.
Its only revision-zero encoding has zero counters, birth and sequence floors,
empty request identifiers and no outcomes. Later admission, succession, replay
and recovery never reinitialize it. A missing checkpoint after admission is
corruption, including a scope that has only counters and no children; reads,
apply, publication and cold reconstruction cannot synthesize empty floors.
Same-cohort succession preserves the child/claim namespace. A later retirement
profile will compare the old authority, advance `retired_through` to the old incarnation and select
the next incarnation with its verified candidate and empty namespace. It will
never relabel retired rows or roll back a floor. The current profile supplies
the storage and apply predicates, not the retirement controller or a public unchecked retire
operation; deterministic retirement fixtures exercise the predicate now.

### Failures and effect boundaries

Retain exact request bytes until an uncertain outcome is resolved. ID plus
digest returns the retained immutable result; reusing an ID with different
content conflicts. Once superseded, the old expected revision cannot apply
again. Historical batch replay performs no mutation and grants no effect
authority. A stale execution/incarnation is refused; unavailable quorum or
voter-profile continuity is retryable and does not itself retire a worker.
Reconnection resolves pending outcomes and checks current authority without
renewal or timed Resume. A closed predecessor stays closed after a lost reply.

Unknown outcomes backpressure and never publish success. Status loss cannot
erase committed floors; issuer repair must reconcile trusted issuance state
with the store and may authorize only the currently selected boot/incarnation.
If that lineage cannot be established, management and retry remain available
without inventing a floor. An admission generation alone proves no closure.

Retirement fences store mutations, not packets already installed or queued on
an unreachable worker. On learning retirement, an adapter stops new admissions,
store writes and peer-control work, while allowing existing forwarding and
local teardown of its own objects without a quorum commit. Store outages or
elapsed ownership time do not authorize dropping that forwarding. Local
containment/reset/readback and positive closure proofs belong to the platform
adapter; authenticated transport and verifier hooks belong to the admission
adapter. Neither a committed stamp nor the SDK promises remote packet drainage. Protocol lifetimes and
bounded retry policy remain separate from ownership.

### Format and integration

Scope profile 4 uses new authority/batch command encodings, reserved
row versions and profile digest, including incarnation in keys and validation
facts. Preserve strictly durable reserved storage outside ordinary receipts;
no TTL, receipt pruning, compaction, snapshot, external status loss or namespace
drop may remove or regress authority, incarnation, generation, any of the 16
counter floors or the stable-scope child-birth floor. Same-revision replacement must
match exactly. Validate native and SQLite replay, snapshot export/install and
floor-preserving replacement before exposing recovered state.

Profile-3 rows, logs, snapshots and activation evidence require a fresh
installation. Recognize the old format only to return
`FreshInstallationRequired`; never migrate, dual-read or infer an empty scope
from old data. Replace the timed types/checks/tests in this implementation.
Earlier profiles are not supported alongside profile 4.

Keep the exact-voter activation/continuation checks for the new profile.
RFC 023 voter incarnations and their narrow controller authorization remain
distinct from worker admission: a voter replacement does not retire a worker
or renew its authority. Independent batch lanes and namespace scans consume the
incarnation-bound namespace and untimed stamp; their concurrency and scan APIs remain separate.

### Recovery and integration constraints

After committed succession, a predecessor's uncommitted batch can no longer
apply. The successor resolves its exact request through the read-only batch
outcome lookup, never by submitting the old stamp. A retained success is already
applied; only a positively established NotApplied result permits a fresh
request under the new execution. A pruned or unavailable outcome remains
explicitly uncertain. The initial one-lane lookup preserves that distinction;
independent lanes retain their sequence floors separately.

A refused authority request changes no authority row field, including its
revision and last-request receipt. Credential/ticket validity can refuse new
admission or succession; it never expires, revokes or retires an already
admitted execution. Authority reads use the full-round read barrier with
leader read leases disabled. Apply predicates consume no clock or replicated
application time. The current voter configuration stamp remains outside the
immutable request digest, so exact retries survive voter changes.

An unused domain has no authority, checkpoint, child, claim or floor row in
any incarnation of that stable scope. Surviving rows without authority are
corruption, never a reason to restart at incarnation 1. The native orphan check
walks every retained key in the store and staged keys on each unused-domain
`AdmitInitial`, including refused retries; its scan cost is linear in that key
inventory. It decodes candidate scope rows after filtering tenant, network
function and reserved key type. SQLite filters those columns in its query.

`ScopeId` uses the
existing name-derived cluster ID produced by `ConsensusClusterId::new`, as
used by `SessionReplicationManifest`; it remains independent of membership
epochs. This profile leaves consensus identity, node IDs and configuration
digests unchanged. Reusing a cluster name reuses its cluster identity; a fresh
installation with the same name does not create a separate authority domain.
Installation-qualified identity requires a separate, explicitly approved
breaking change, tracked in #1187.

Profile 4 does not reserve a retirement command. Retirement requires a new
format and fresh installation (planned profile 5). Until that profile supplies
retirement and empty selection, an unconfirmed lost execution without closure
evidence leaves its slot unable to progress. The current authority profile is
therefore limited to lab stages without lost-worker replacement; a timer never
bypasses that limit.

The removal gate checks scope code for the former clock types, renewal/grace/
guard constants, permit deadlines and liveness helpers, timed operations,
unchecked closure constructors, time-related refusals and command clock bounds.
Ordinary session TTLs, protocol lifetimes and RPC waiting deadlines are outside
this ownership contract.

### Verification

Deterministic regressions and mutation checks cover:

- Order prepared batches after succession, Close and a retirement fixture;
  assert no child, claim, counter or receipt mutation in native and SQLite.
- Exercise exact retry/lost replies, altered digests, revision conflicts,
  repeated restarts, old boot keys, copied claims and forged higher generations.
- Prove same-cohort succession requires closure; unknown closure cannot use a
  timer fallback. Close/retry must never reopen its predecessor.
- Restart and compact with floors present; snapshot omission, rollback,
  same-revision alteration and retired-namespace writes must fail. Current
  data and floors must survive successful restart and snapshot installation.
- Advance counters and allocate a child birth before and after a retirement
  fixture; both remain strictly increasing across namespace drop and snapshot
  installation. Refuse snapshot rollback of any counter or the birth floor.
- Exercise the role table, controller-submit/successor-retry capability path,
  different boot refusal, forged closure claims and changed evidence digests;
  final process termination can prove closure with installed forwarding intact.
- Reject prior timed formats at every restore/replay/activation entry point;
  retain S3's configuration-change and exact-voter continuation regressions.
- Exercise outage/reconnect without a clock provider, authority renewal or
  ownership deadline; verify view deserialization cannot mint capabilities
  and adapters reject a different local boot/generation.

Mutation runs remove incarnation, execution, generation, revision, closure,
digest and snapshot-floor predicates and must turn the corresponding
regressions red. The implementation handoff records exact commands, source
identity and results; cross-slice qualification follows code review.

## Consensus, activation and recovery

Each authority operation commits one `ScopeAuthority` command. The enclosing
configuration stamp is checked at apply and excluded from the immutable scope
request digest. A command stamped before a voter-authority switch and ordered
after it returns retryable `Unavailable` without changing any scope row. A
full-round linearizable read can recover an exact retained result without a
new application command. Ordinary consensus logical time, RPC timeouts and
session TTLs remain independent of the scope authority predicate.

Initial activation probes **every voter** for the exact profile digest. The
committed activation certificate binds that digest to the admitted identity
and voter set, and apply checks it again. After activation, a quorum suffices.
Joining voters acknowledge the profile through the authenticated staged control
path before learner replication. `CertifyScopeProfileContinuation` binds their
support to the exact transition ID and request digest, predecessor identity
and voters, and successor identity and voters. One reserved continuation row
retains this proof; its applied log index is a protected floor.

Prepare freezes initial activation. A resumed Prepare may certify after the
learner marker, but Fence and promotion require exact committed continuation
evidence. Missing or mismatched decodable proof returns a no-effect retryable
control refusal; read/decode faults abort local apply. The uniform cutover
carries activation into the successor configuration in the same transaction.
No unanimous reactivation is needed after cutover. An activated scope can read
and mutate during Prepare and learner catch-up until Fence. Across Fence or
leader loss, mutations may wait, but ownership and installed forwarding do not
expire. A durable Abort restores predecessor authority while learner cleanup
continues. Membership without scope activation creates neither activation nor
continuation evidence. These S3 invariants are unchanged by worker succession.

`ProfileNotActivated` means no effect; exact retry attempts activation under
the current configuration. `OutcomeUnknown` means a command may have committed;
retain and retry its exact bytes. Configuration changes do not permanently
revoke an admitted worker. A delayed authority command loses if another request
has changed its predecessor. Once another authority request replaces the last
receipt, an old revision cannot issue another capability.

## Atomic child batches

A typed batch contains up to 64 child mutations, eight unique claims per child
and 16 counter comparisons. Its complete command is capped at 2 MiB and each
sealed value at 1 MiB. A maximum sealed value and its complete claim set fit.
`ScopeSealedValue` accepts a bounded RFC 003 envelope; the consumer binds the
stable scope, incarnation and child identity in its AAD and verifies those
bindings when decrypting. Plaintext values are refused.

Create requires an absent child and allocates a stable-scope birth at apply.
CAS and Delete compare the exact birth and generation. Updates advance the
generation, deletion retains a tombstone, and recreation allocates a new birth.
All comparisons succeed before publication. A conflict names the children,
claims or counters to reread; it consumes no birth, revision or receipt.

Claims are unique within an explicit incarnation and bind an exact child birth.
CAS supplies the complete successor claim set. Releasing old claims before
acquiring new claims permits an atomic swap in one batch. Cross-scope pools
need a separate shared authority. Released claim rows retain `owner = None`.
Tombstones and claims remain until a future reclamation profile supplies safe
physical deletion; compaction is not namespace reclamation. Counters are exact
CAS floors in `0..=i64::MAX`: apply requires the stored value to equal `expected`
and refuses `next < expected` without changing any batch row. Equality leaves
the counter unchanged; only an increase advances it. Accounting that must
decrease uses child rows. These floors express no session quota or allocation
ceiling.

This profile admits one unresolved batch per stable scope: lane zero, with
sequence equal to expected batch revision plus one. Eight fixed replay slots
are reserved; the other seven remain canonical zero. The current lane retains
one exact request ID, digest and outcome. Receipt replay changes no row and
confers no effects. A successor batch prunes the receipt but retains the
sequence floor. Independent lanes and coherent scans remain separate slices;
reserved space does not by itself authorize new semantics or mixed profiles.

`ScopeBatchStore::predecessor_outcome` provides the initial one-lane resolution
boundary used by independent lanes. It first checks the current stamp through a
full-round read, proving the predecessor stamp can never apply again, then reads the
stable checkpoint. `Applied` returns the exact receipt. `NotApplied` requires
positive sequence evidence. `Unknown` distinguishes pruned receipts and never
licenses repeating a possibly applied effect. The lookup submits no command;
it cannot relabel an old request with the successor's stamp. Reads are
scope-authorized observations; they neither grant effects nor establish a
coherent scan across multiple calls.

## Stored format

The authority key is `opc-scope-authority` plus the stable slot. Its fixed
4096-byte checkpoint has exact length framing, an `OPSA` version-4 body and
zero padding. The row type is `opc-scope-authority-v4`. Response hexadecimal
encoding is not encryption: the checkpoint contains public authority facts,
never credentials or child plaintext. Every successful authority change replaces
this same row; rejected requests create no per-operation receipt or watch.

Other reserved keys are `opc-scope-batch`, `opc-scope-child`, `opc-scope-claim`,
`opc-scope-profile` and `opc-scope-continuation`. Their row codec is `OPSC` 4,
with state type `opc-scope-state-v4`. The single child/claim stable-ID encoding is
`SHA-256("openpacketcore/scope-namespace/key/v4\0" || postcard(ScopeNamespace))[32]
|| logical_key[32]`, with the literal NUL-terminated domain shown here. This
64-byte namespace commitment preserves the SDK's stable-ID bound and provides
an exact namespace scan prefix. Batch checkpoints stay under the stable slot.
`scope_storage::namespace_prefix` and `namespace_key` are the crate-visible
prefix and full-key helpers; the typed `child_key` and `claim_key` wrappers use
that same codec. Independent lanes and namespace scans must reuse these helpers.
A successor obtains its predecessor's incarnation from stable authority and
scans that exact namespace. The broader body-decoding scan remains the orphan
fallback at initial admission; slot-wide cross-incarnation scans are not needed.

Native publication, cold reconstruction and SQLite snapshot installation
validate exact row identity, child/claim links and protected monotonic floors.
Same-revision replacements must match every byte. Authority, incarnation,
retirement, generation, counter, birth and sequence floors live outside ordinary
request receipts and have no TTL. Current-profile corruption remains distinct
from a recognized old-format refusal. The legacy authority key remains reserved
solely to reject prior storage as `FreshInstallationRequired`. Recognized
profile-2/profile-3 rows and activation digests cannot expose recovered authority
or become an apparently empty domain. There is no migration or compatibility
reader. Downgrading after activation is unsupported.

Scope profile 4 is experimental and does not itself supply authenticated network
transport, local kernel reset/readback, scheduling, namespace reclamation or
lost-worker retirement. Those integrations consume this contract. No store
operation authorizes voluntary interruption of an emergency session.
