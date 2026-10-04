# OPC-SDK-RFC-019: NETCONF Required Audit for Exact Configuration Effects

**Status**: Writable-running contract and partial implementation merged. The
retained-target architecture is selected; its detailed extension remains under
review. No independent review or complete implementation is claimed.

**Date**: 2026-09-22

**Version**: 1.2.1

The writable-running profile was delivered by #963. The selected full profile
retains encrypted candidate/startup state in the existing configuration authority.
The [retained-target extension](019-netconf-retained-targets.md) specifies its API,
effect and result representations, lifecycle and compatibility boundary.
Full-profile implementation, qualification and #958 remain open.

## Problem and existing authority

The NETCONF core currently records a protocol `Intent` through `AuditSink`, then
separately submits a configuration request. The replicated observation port
rejects that standalone intent. An accepting replacement would acknowledge an
intent that is not bound to the encrypted effect. Neither changing request
identity nor weakening that refusal supplies the missing handoff.

The existing `ConfigBus::required_config_audit` capability binds one exact worker
and its required datastore append port. After authorization and validation, the
encrypted adapter binds the request, principal, tenant, transport, operation,
candidate, parent, mode and confirmed resolution to one retained audit operation.
This proposal extends that composition to NETCONF and preserves
[ADR 0025](../adr/0025-management-audit-continuity.md), including the independent
checkpoint reservation before effects and truthful results after terminal debt.

## Proposed API and configuration-effect order

Proposed `ReadOnlyNetconfServer::with_required_config_audit` accepts the existing
`RequiredConfigAudit<C>`. Construction checks the binding's exact worker. Every
submission checks it again, because a binding can return a different bus later.
An independently opened bus over the same datastore is not the same worker.
The attachment grants no principal, NACM or configuration authority.

The first implementation slice is an explicit writable-running profile. The
attachment rejects a binding that enables candidate, confirmed commit or
startup. It does not silently remove an advertised capability. The server
rechecks this composition when dispatching each asynchronous RPC, because a
binding can change its capability answers after construction. Configuration
submission also checks the exact bus selected for that request. Registry-free
synchronous helpers cannot drive the asynchronous replicated audit port and
continue to fail closed with it.

This slice covers running `edit-config`, running NMDA `edit-data`, and the base
session/registry operations below. The copy-to-running effect helper uses the
same required submitter, but this profile has no supported distinct source:
candidate and startup are refused, and inline XML copy sources are unsupported.
Same-datastore copy is invalid under RFC 6241 section 7.3. Helper qualification
cannot establish positive wire-protocol copy coverage.

This is partial delivery: copy, candidate, startup and confirmed lifecycle
obligations remain required for #958. The smaller profile cannot close the issue
or stand in for their acceptance evidence.

The authenticated session supplies the principal and tenant. The SDK creates
one request identity per received RPC; the XML `message-id` is reply correlation,
not a durable idempotency key. Raw identities and payloads remain outside public
diagnostics. The existing keyed projection supplies opaque audit correlation.

For a running-configuration mutation:

1. Parse and enforce capability, session, lock, NACM and current-authority gates.
2. Build the immutable complete request with its original identity and base.
3. Transfer that request and its matching intent to the exact required submitter.
   Do not acknowledge a standalone intent through an observation sink.
4. Let the existing encrypted authority admit/checkpoint the exact intent before
   its effect. Rejected or indeterminate intent admission permits no effect.
5. Return the established configuration result. Once required append starts,
   only the retained operation may establish or recover its terminal outcome.
   A generic failure observation must not relabel a possible or known commit.
6. Keep terminal/checkpoint obligations and the write fence until recovery of
   that exact operation completes. Dropping an RPC future does not retract work
   already owned by the ConfigBus worker or persistence authority.

Operation binding uses the request's real operation: replace, patch/update,
delete or rollback. The legacy NETCONF vocabulary labels several of these
`Update`; that vocabulary is insufficient for the required append binding.

## Complete mutation inventory

The following inventory is source inspection, not a qualification result.
All enabled branches must be covered before claiming issue acceptance.

| Advertised operation or trigger | Current effect owner | Required disposition |
| --- | --- | --- |
| `edit-config` to running; NMDA `edit-data` to running | ConfigBus | Exact required submit, with replace/patch/delete binding derived from the actual request. |
| `copy-config` to running | ConfigBus | Exact source-bound copy effect in the full profile; preserve source generation/content and check destination base. |
| Candidate `edit-config`, `edit-data`, `copy-config` | Server candidate buffer | Explicit preparation contract below; never claim a running effect or silently send standalone Intent to observations. |
| `discard-changes` | Server candidate buffer | Explicit preparation contract and candidate lock; no fabricated configuration commit. |
| Plain candidate `commit` | ConfigBus plus candidate buffer | One exact required configuration intent; retire only the candidate actually committed. |
| Empty plain `commit` with no pending confirmation | No configuration effect | Authoritatively check both states before a distinct observation; a pending confirmation still requires its exact effect. |
| Confirmed `commit`, including persistent token | ConfigBus plus server confirmation metadata | Exact tentative effect, fixed deadline, retained parent and correlation; preserve access control. |
| Confirm pending commit | ConfigBus confirmed resolution | Audit the exact pending transaction; no separate unaudited marker update. |
| `cancel-commit`, including persistent token | ConfigBus confirmed resolution | Required rollback intent for the exact pending transaction; wrong token/session permits no effect. |
| Timeout rollback | ConfigBus worker | Existing audited encrypted append, original pending parent/deadline and attributed recovery identity; no protocol sink acknowledgement. |
| Session exit/panic rollback | NETCONF to ConfigBus | Required rollback submit with admitted ownership surviving cancellation of the session. |
| Restore of expired confirmed state | ConfigBus restore path | Same retained pending resolution and audit checkpoint ordering; no reset or new storage owner. |
| Device reboot with an unexpired confirmed commit | Full-profile lifecycle authority and ConfigBus | Resolve the original pending effect by audited rollback before normal write admission, including persistent-token commits. A voter election is a distinct event. |
| Candidate unlock or release on session termination | Session registry plus candidate effect owner | Retained generation-bound discard and terminal obligation; registry release alone is insufficient. |
| Startup `edit-config`/`edit-data`, `copy-config`, `delete-config` | Caller-supplied `StartupDatastore` | Explicit unsupported composition or a separately approved exact-effect port; current synchronous facade proves neither encrypted effect nor retained recovery. |
| Lock/unlock, close/kill session | Session registry, sometimes triggering rollback | Preserve atomic registry semantics and audit admission; do not mistake registry observations for configuration-effect authority. |
| Validate/test-only and reads | Validation/read paths | Distinct observations, never required configuration mutation admission. |

Neither disabling a tested assertion nor omitting an advertised branch satisfies
this inventory. Existing legacy profiles retain their documented behavior.

## Decisions requiring review

The first slice uses the existing required configuration authority and rejects
unsupported local-effect compositions explicitly. The following full-profile
contracts remain required before those compositions can be enabled; they are
not delegated to an accepting application audit callback.

### Selected full-profile authority

The selected full profile retains encrypted candidate and startup target
state in the existing replicated configuration authority. Its atomic application
transaction records both the target effect and the corresponding audit outcome.
It uses the existing KeyProvider and attested encryption seams, native WAL and
independent checkpoint port. It introduces no new backend, consumer audit journal
or application callback that can manufacture successful required admission.

This changes candidate availability and persistence in the opt-in full profile:
staging and discard require the authority and its independent checkpoint. The
candidate generation survives process loss, while lock release still requires
the implicit discard described below. Retention does not make an abandoned
candidate usable. Legacy volatile candidate and synchronous startup facades keep
their existing behavior outside this profile. Complete #958 qualification must
exercise every enabled full-profile path.

The alternative is a volatile candidate owner with a retained owner incarnation
and explicit lost-state outcome. That alternative requires a protocol that binds
the volatile effect and replicated outcome despite cancellation or process loss.
The current closed append port provides no such protocol. Merely wrapping an
in-memory edit in audit calls leaves an ambiguous effect boundary. The
retained-target design is selected. The detailed extension still requires review
and merge before its public API or retained format is implemented.

The following names describe proposed semantics, not available SDK APIs:

- `CandidateGeneration` and `StartupRevision` are distinct opaque values scoped
  to one authority. Neither is a running configuration version. Discard/delete
  retains an absent-state tombstone and advances the generation; recreation
  cannot reuse it. Exhaustion refuses before admission instead of wrapping.
- `PreparedTargetMutation` is an SDK-constructed closed, bounded effect. It binds
  authority, target/action, expected generation, exact encrypted content or
  tombstone, source revision/content for copy, authenticated projected caller,
  original request and fixed expiry. Its debug representation is redacted.
- Retained outcomes distinguish a running commit, candidate application,
  startup application, rejection and unresolved operation. A target generation
  must never be encoded as the existing running `Committed { version }` result.
- The full-profile capability remains tied to one exact ConfigBus worker and
  proves access to the SDK's closed target port. An observation sink, another
  bus over the same store, or an arbitrary `StartupDatastore` implementation
  cannot grant it. Preparation alone grants no effect authority.

| Action | Atomic preconditions and effect | Authoritative result |
| --- | --- | --- |
| Stage/replace candidate | Exact candidate generation and source/running base; replace encrypted target | New candidate generation |
| Discard candidate | Exact generation; install absent-state tombstone | New candidate generation |
| Promote candidate | Exact candidate generation and running version; commit running effect and retire that candidate together | Running version and retired candidate generation |
| Replace/copy startup | Exact startup revision and authenticated source content/revision; replace encrypted target | New startup revision |
| Delete startup | Exact startup revision; install absent-state tombstone | New startup revision |
| Tentative promotion | Promotion plus exact pending transaction, original deadline and protected confirmation ownership in one transaction | Running version and exact pending resolution identity |
| Confirm/cancel/rollback | Exact pending transaction, authority generation and authenticated ownership; apply its one resolution | Typed original pending outcome |

Lock release and session/device lifecycle actions add the incarnation-bound
preconditions below. An empty plain candidate commit is an observation only after
an authoritative read and admission recheck prove no staged target and no pending
confirmation. Confirming an exact pending operation remains a required effect
even without staged content. Missing or ambiguous state is not an empty candidate.
A prepared copy cannot silently read a newer source when its effect is eventually
applied.

For each changing action, the authority must:

1. Preflight the complete eventual encoded command, including its audit metadata
   and terminal reservation, against the existing public capacity contract.
   Inner ciphertext size alone is insufficient. This work does not increase or
   bypass the command budget.
2. Bind target ciphertext through the existing provider seam and a reviewed
   target-specific authenticated-data domain. Bind authority, target, generation,
   schema, tenant and exact effect metadata; preserve historical running domains.
3. Reserve and independently checkpoint the original required intent. Rejection
   or indeterminate admission permits no target effect.
4. Apply that closed effect and retain its typed outcome atomically. A promotion
   of generation A cannot commit generation B or clear B after replacement.
   Retirement is owned by the admitted operation, independently of the RPC.
5. Complete the original terminal/checkpoint obligation. A known applied target
   result remains truthful if reporting fails. Retained debt fences subsequent
   target and running writes until exact-operation recovery completes.
6. Preserve target generations, outcomes, ownership and debt across reopening,
   snapshot installation, pruning and leadership changes. Exact-request replay
   returns its original outcome; conflicting reuse causes no second effect or
   generation increment. No missing-row inference establishes success.

### Retained format and compatibility decision

The retained-target design needs an explicit versioned extension to the closed
consensus command, authenticated authority state and audit outcome encoding.
Adding a target table without authenticated reopen validation, snapshot copying
and history verification is insufficient. These changes must be reviewed as one
format contract before full-profile activation; the names above freeze no binary
layout or public root exports.

The proposed migration is explicit and quiescent. An operator first upgrades all
participating authority readers/writers to a version that can read the existing
format and the reviewed extension. Outstanding old-format operations and terminal
obligations must resolve before activation. A retained, authenticated profile
marker then enables target commands. A process that cannot understand that marker
or a newer required format refuses before admitting writes; an old writer cannot
silently accept a partial representation. If the existing deployment/version seam
cannot prove these conditions, activation remains unavailable.

Activation also requires a quiescent protocol boundary: no held candidate lock,
in-flight staging request, unresolved cleanup or pending confirmation whose
original ownership cannot be recovered. It must not erase a legacy candidate or
claim that an arbitrary startup facade has already supplied authenticated target
state. The initial target generations and absent-state markers need an explicit
authenticated bootstrap record. Import of legacy startup content is a separately
authorized exact target mutation, with independently checked source content and
its own required intent/result. An unresolved bootstrap leaves writes unavailable.

Existing ledger rows, running outcomes, ciphertext authentication and independently
held checkpoints remain byte-preserved. A new reader must verify old histories,
including historical key transitions and retained original operation recovery.
New target outcomes need a disjoint version/tag with bounded decoding; they cannot
reinterpret an old running receipt. Snapshot, export and prune boundaries must
bind the extended authority state without dropping target tombstones or unresolved
operations. Unsupported formats fail closed with typed, value-free errors.

Rollback to an older binary after activation is explicitly unsupported unless a
separately reviewed lossless transition is available. No database reset, historical
MAC replacement, automatic key rotation or silent format rewrite is proposed.
Migration and old-history fixtures, mixed-version refusal, retained-state tamper,
and unsupported snapshot/export negatives are acceptance gates, not assumptions.

### Candidate preparation

Candidate staging is currently volatile, but its mutation already requires
Intent admission. The existing `mutation_audit` tests require failed, panicking
or cancelled admission to leave the candidate unchanged. Replacing that Intent
with an accepted observation would weaken this contract. This proposal does
not authorize that substitution or count it as #958 coverage.

There are two concrete scope choices to review:

1. Preserve the advertised candidate profile and extend an existing SDK effect
   owner to admit an intent bound to the exact candidate generation, encrypted
   content and action. That owner must retain the target result obligation, own
   cancellation after admission, and reject lost or ambiguous retained state
   without fabricating a successful running commit. The current required configuration
   append port does not provide this operation. Its API, retained representation
   and restart semantics need an approved design before implementation.
2. First deliver a smaller required-audit profile that explicitly refuses
   construction with candidate support. This can be a partial PR only; #958
   stays open for candidate staging, discard and commit qualification. Merely
   hiding capabilities or relabeling staging as an observation is insufficient.

The full issue requires the first choice or an equivalent exact-effect contract;
the second is a sequencing option, not a proposal to narrow acceptance. A new
storage backend, consumer callback or local audit journal is outside scope.
In either design, a cancelled or slow commit must not discard a subsequently
staged generation. The final running commit has its own exact encrypted effect
and authenticated committing principal; it cannot reuse a staging receipt.
Candidate retirement must belong to the admitted operation's completion owner,
not solely to the lifetime of the RPC future. Its compare-and-retire condition
must include the staged generation and exact committed request. Dropping the
caller after admission must not leave a success response as the only route to
retirement or permit a second commit of an ambiguous generation.

### Candidate lock release and retained cleanup

The full profile also needs an implicit-discard action when a candidate lock is
released. RFC 6241 section 8.3.5.2 requires cleanup on explicit unlock and
session failure. Retaining encrypted candidate history cannot preserve usable
uncommitted changes after that release. The existing registry-only unlock path
and process-local candidate buffer do not establish this composition.

The proposed effect owner must bind cleanup to the original lock incarnation,
exact candidate generation and authenticated running base. Retain the original
cleanup request and typed result with the same intent/checkpoint/effect ordering
as explicit discard. Do not route the cleanup through an accepting observation
sink, or infer its completion from removal of an in-memory registry entry.

Explicit unlock must not report completion before the required discard is known
applied. A known discard remains truthful if terminal reporting fails; the
retained debt prevents a later write or lock grant from bypassing reconciliation.
Session disappearance cannot depend on a live RPC future to finish cleanup.
It releases the dead session's ownership while an internal retained fence keeps
new changing work out until the exact admitted cleanup is resolved. The fence
must survive reopening and leader replacement without inventing a live session.

Generation and incarnation checks must prevent delayed cleanup for owner A from
clearing a later candidate or a new lock held by owner B. Discard followed by
restaging must advance the generation so an old cleanup cannot match again.
Replayed cleanup recovers the original result and never increments a generation
a second time. The retained representation, atomic release boundary and ordering
with lock admission still require the approved full-profile authority design.

### Startup datastore

Supporting the advertised startup profile needs an SDK-owned exact-effect and
recovery port for the existing startup owner, including encryption, retained
intent/result, cancellation and restart/leadership recovery. The arbitrary
synchronous `StartupDatastore` facade does not supply those guarantees. An
application callback that claims success is insufficient.

A first partial profile could instead refuse construction with startup support.
That must be an explicit constructor error, not silently hidden capabilities,
and must leave startup acceptance and #958 open. Review must decide sequencing
and the port contract; it cannot turn the smaller profile into complete issue
acceptance. No second backend or consumer-local audit protocol is proposed.

### Confirmation and recovery metadata

The durable ConfigBus state includes the exact pending transaction and deadline;
NETCONF also keeps owner-session/persistent-token metadata in memory. Recovery
must not fabricate those credentials after restart. An operation that cannot
prove its original binding stays fenced for explicit recovery. No fresh request
may be submitted merely to discover whether a previous request committed.

The final contract must distinguish automatic rollback attribution from the
original initiating principal. Both must remain connected by the exact pending
effect, without exposing request or transaction identities in diagnostics.
Confirmation ownership must be installed by the same completion owner even if
the initiating RPC is cancelled. The NETCONF deadline must use the persisted
pending deadline; starting a fresh timeout after receipt would extend the
tentative effect's lifetime. A control request must resolve its exact pending
transaction, not whichever pending transaction exists when a delayed worker
finally processes it. Restoration must never invent a session or persistent
token, and automatic rollback must retain its original deadline and parent.

### Reboot, session loss and voter replacement

RFC 6241 section 8.4.1 requires rollback of a pending confirmed commit on device
reboot, including a commit with a persistent token. Persistence protects against
session termination, not this reboot rule. The full profile must distinguish
that event from replacement of one replicated voter and from an ordinary
checkpoint-provider restart. Restoring a future deadline alone proves none of
these distinctions.

Use retained SDK lifecycle evidence to identify the original pending transaction
and device/session incarnation. Device reboot resolves that pending transaction
against its original rollback parent before publishing ordinary write admission.
Loss of a nonpersistent owner session also schedules its exact rollback.
Persistent-token session loss preserves the original pending deadline and
credential binding, subject to later timeout, confirmation, cancellation or
reboot. Recovery must not generate credentials or treat a newly registered
session with a reused numeric identifier as the prior owner.

A repeated delivery or restart of the same recovery event must recover the same
operation. Intent refusal or ambiguity permits no new effect and keeps the
recovery fence. A known rollback with terminal debt remains a known rollback.
A voter election alone must not masquerade as device reboot or extend a timeout.
A protocol follow-up confirmed commit is a distinct authorized operation; it
cannot be confused with extending the lifetime of a retry or recovered request.

This requires an explicit lifecycle/availability contract before implementation.
The current ConfigBus restore path re-arms a future pending deadline; it does
not receive a NETCONF device-reboot classification or recover NETCONF ownership.
Choosing a trusted SDK incarnation boundary, representing it in authenticated
state, and refusing unresolved lifecycle classification remain design gates.
No new lifecycle API or behavior is introduced by this proposal.

### Atomic registry operations and asynchronous observations

Lock/unlock and kill-session use an existing bounded, non-cancellable blocking
job to keep registry checks, audit admission and mutation atomic. Their current
hooks call synchronous `AuditSink::record`. The replicated observation sink
deliberately refuses that entry point; simply installing its async-capable
object does not make these hooks usable.

For the required profile, the existing blocking job must await the selected
authority's real `record_async` result before allowing its registry mutation.
The job keeps the existing atomic permit and registry guard for that lifetime.
An unavailable runtime, rejected audit, or panic permits no registry effect;
dropping the RPC cannot drop an admitted job's ownership. Ordinary async RPCs
must never block an executor thread this way. Legacy synchronous sinks keep
their existing hook behavior. No sink acknowledges a standalone configuration
Intent or fabricates successful admission.

In the partial writable-running profile, registry observations are not encrypted
configuration commits. A successful lock must leave the running version
unchanged. The full candidate profile additionally requires the implicit-discard
composition above; an unlock observation does not acknowledge that effect. Reads,
denials, missing-session results and pressure rejection use the appropriate observation outcome. Any
session termination that can trigger a confirmed rollback additionally needs
the full-profile exact rollback contract; an observed termination is not its
rollback receipt.

## Detector and qualification plan

The initial detector uses the real configuration consensus store, encrypted
ConfigBus, independent synthetic checkpoint provider and replicated observation
port. A direct exact-worker control proves that one encrypted effect can commit
with one intent/result/terminal sequence while standalone Intent is refused.
The NETCONF detector then requires the authenticated running edit to reach the
same authority with its original request. Build/setup errors are not behavioral
RED evidence. A singleton fixture does not establish quorum failover.

Required follow-up evidence includes:

- Every inventory row under each advertised capability combination, including
  unsupported startup composition and wrong-session/token negatives.
- Constructor refusal for each unsupported composition, capability changes
  after attachment, and read/lock/unlock/kill controls through the real
  asynchronous observation authority. Audit refusal and cancellation must
  preserve the registry's existing atomicity and admission bounds.
- Exact-worker mismatch at construction and submission, missing capability,
  unaudited datastore, revoked authorization and non-current authority.
- Rejected/unknown intent admission with authoritative unchanged readback;
  known commit with failed terminal/checkpoint reporting and fenced later writes.
- Cancellation at preparation, admission, effect and terminal boundaries; fixed
  request deadlines; retained restart and leadership-change recovery.
- Duplicate XML message IDs as distinct requests, exact-request read-only
  recovery after ambiguity, and conflicting duplicate request rejection.
- Target generation, action, source revision and ciphertext substitution;
  discard/recreate ABA; delayed promotion after replacement; exact replay versus
  conflicting request reuse; startup mutations with unchanged running/candidate
  readback; old-format recovery and unsupported format/snapshot/export refusal.
- Candidate unlock, close/kill, transport loss and cancelled cleanup, with
  generation/incarnation reuse negatives, authoritative target readback and
  original terminal-debt recovery after restart and leader change.
- Reboot before the original confirmed deadline, with and without a persistent
  token; a separate voter-replacement control; lost-session ownership negatives;
  and one exact rollback outcome with no replay of its configuration effect.
- Required gNMI regressions from #927 and checkpoint/recovery regressions from
  #925; no change to native WAL, Durable/Async behavior or fixed qualifications.
- Fix-removal RED, a separate adversarial mutation, restored exact-tree passes,
  full applicable local/hosted gates and independent full-diff review.

Protocol lifecycle references: [candidate lock release](https://www.rfc-editor.org/rfc/rfc6241.html#section-8.3.5.2)
and [confirmed commit](https://www.rfc-editor.org/rfc/rfc6241.html#section-8.4.1).

Refs #958. No complete implementation or closure is claimed by this draft.
