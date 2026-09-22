# Draft: NETCONF required audit for exact configuration effects (#958)

**Status**: Contract proposal; maintainer and independent review pending.

**Date**: 2026-09-22

**RFC number**: Pending allocation. This proposal does not claim an accepted
API, complete qualification, or closure of #958.

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
| `copy-config` to running | ConfigBus | Same required submit and independently checked source/base. |
| Candidate `edit-config`, `edit-data`, `copy-config` | Server candidate buffer | Explicit preparation contract below; never claim a running effect or silently send standalone Intent to observations. |
| `discard-changes` | Server candidate buffer | Explicit preparation contract and candidate lock; no fabricated configuration commit. |
| Plain candidate `commit` | ConfigBus plus candidate buffer | One exact required configuration intent; retire only the candidate actually committed. |
| Empty plain `commit` | No configuration effect | Distinct observation; no invented encrypted write or receipt. |
| Confirmed `commit`, including persistent token | ConfigBus plus server confirmation metadata | Exact tentative effect, fixed deadline, retained parent and correlation; preserve access control. |
| Confirm pending commit | ConfigBus confirmed resolution | Audit the exact pending transaction; no separate unaudited marker update. |
| `cancel-commit`, including persistent token | ConfigBus confirmed resolution | Required rollback intent for the exact pending transaction; wrong token/session permits no effect. |
| Timeout rollback | ConfigBus worker | Existing audited encrypted append, original pending parent/deadline and attributed recovery identity; no protocol sink acknowledgement. |
| Session exit/panic rollback | NETCONF to ConfigBus | Required rollback submit with admitted ownership surviving cancellation of the session. |
| Restore of expired confirmed state | ConfigBus restore path | Same retained pending resolution and audit checkpoint ordering; no reset or new storage owner. |
| Startup `edit-config`/`edit-data`, `copy-config`, `delete-config` | Caller-supplied `StartupDatastore` | Explicit unsupported composition or a separately approved exact-effect port; current synchronous facade proves neither encrypted effect nor retained recovery. |
| Lock/unlock, close/kill session | Session registry, sometimes triggering rollback | Preserve atomic registry semantics and audit admission; do not mistake registry observations for configuration-effect authority. |
| Validate/test-only and reads | Validation/read paths | Distinct observations, never required configuration mutation admission. |

Neither disabling a tested assertion nor omitting an advertised branch satisfies
this inventory. Existing legacy profiles retain their documented behavior.

## Decisions requiring review

### Candidate preparation

Candidate staging is currently volatile, but its mutation already requires
Intent admission. The existing `mutation_audit` tests require failed, panicking
or cancelled admission to leave the candidate unchanged. Replacing that Intent
with an accepted observation would weaken this contract. This proposal does
not authorize that substitution or count it as #958 coverage.

There are two concrete scope choices to review:

1. Preserve the advertised candidate profile and extend an existing SDK effect
   owner to admit an intent bound to the exact candidate generation, encrypted
   content and action. That owner must retain the local result obligation, own
   cancellation after admission, and distinguish lost volatile state after a
   restart from a successful running commit. The current required configuration
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
- Exact-worker mismatch at construction and submission, missing capability,
  unaudited datastore, revoked authorization and non-current authority.
- Rejected/unknown intent admission with authoritative unchanged readback;
  known commit with failed terminal/checkpoint reporting and fenced later writes.
- Cancellation at preparation, admission, effect and terminal boundaries; fixed
  request deadlines; retained restart and leadership-change recovery.
- Duplicate XML message IDs as distinct requests, exact-request read-only
  recovery after ambiguity, and conflicting duplicate request rejection.
- Required gNMI regressions from #927 and checkpoint/recovery regressions from
  #925; no change to native WAL, Durable/Async behavior or fixed qualifications.
- Fix-removal RED, a separate adversarial mutation, restored exact-tree passes,
  full applicable local/hosted gates and independent full-diff review.

Refs #958. No complete implementation or closure is claimed by this draft.
