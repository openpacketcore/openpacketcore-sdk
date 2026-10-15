# Fenced non-execution settlement after admission reply loss

Design proposal v4 for [SDK #1280](https://github.com/openpacketcore/openpacketcore-sdk/issues/1280).
Source baseline: `4b49fe5b39618af6f523e62f46fb62709212098b`.
Status: v4 amendment awaiting review; v2 implemented.

An admission that committed before its reply was lost must be settled using that
exact admission. Non-execution becomes conclusive only after its execution
generation is irrevocably closed at every member's physical effect boundary and
accepted work is quiescent or conclusively reconciled. Missing intent alone
remains nonconclusive.

## v4 amendment: bounded settlement state

Before submitting a new admission, the trusted adapter registers each exact
`(group, generation, request fingerprint)` in the store's process-local settlement
registry. That same operation returns the store identity committed in the member
descriptor. SDK-bound preparation checks for a matching open registration and
publishes Prepared within one hold of the store lock. Fence closes the
registration under that lock, so a closed or missing registration refuses
preparation. Registration never grants execution authority. Readback,
recovery and release must not register or reopen an old binding, and the adapter
never reuses a group and generation for another admission.

An absence closure consumes no durable live slot and publishes no row. After
checking the original store identity and its complete authenticated history,
fence closes any matching registration and returns a Closed observation built
from the exact retained request. Prepared still becomes durable Closed, and
accepted work retains its existing disposition. Missing or unverifiable history
remains unknown. All 30 durable slots may be held without preventing closure of
absent members, terminal settlement or automatic release of those held rows.

The registry contains at most one entry per binding awaiting a definitive
admission outcome or terminal settlement. The adapter owns that lifecycle across
caller cancellation. A definitive non-admission removes the registration. The
identical retry that `NotTransmitted` permits registers the same binding again
before resubmission; no provider call can exist for an admission that was never
transmitted. An ambiguous admission retains its registration.
After verifying either durable terminal receipt,
release removes the registration and any retained row's settlement hold.
Idempotent release allocates no entry. Delete the process-lifetime released map:
no released binding or tombstone remains in the registry, so its size depends
only on unsettled work, never the cumulative attach count. A delayed prepare
fails because its registration is gone.

After restart, an absent binding may have no registration. Fence may still
report Closed: no execution authority survives restart, preparation requires a
live registration, and every begun binding remains durably retained until
release. This recovery path creates no registration or execution authority.
Before the SDK returns any terminal receipt, it marks the admission's local
authority entry, whichever authority holds it. Every registration of that
admission, including those built by exact readback, then refuses every provider
call before dispatch and at the post-provider check. Readback of a committed
terminal returns only the receipt, before and after restart. Release requires
that receipt, so no settlement call can reach released history. Fence and release
rustdoc must state these preconditions. No recovery path requires a person to
clear state.

## Existing pieces and the gap

Paths below are under `crates/`; links pin the inspected baseline.

| Existing piece | What it establishes, and its limit |
| --- | --- |
| `opc-session-net/.../client.rs`: [retained admission/readback, 1585](https://github.com/openpacketcore/openpacketcore-sdk/blob/4b49fe5b39618af6f523e62f46fb62709212098b/crates/opc-session-net/src/fenced_mutation_roster/client.rs#L1585-L1607), [reconcile, 1724](https://github.com/openpacketcore/openpacketcore-sdk/blob/4b49fe5b39618af6f523e62f46fb62709212098b/crates/opc-session-net/src/fenced_mutation_roster/client.rs#L1718-L1736), [terminal preparation/readback, 1756](https://github.com/openpacketcore/openpacketcore-sdk/blob/4b49fe5b39618af6f523e62f46fb62709212098b/crates/opc-session-net/src/fenced_mutation_roster/client.rs#L1756-L1825) | `AdmissionInput` recovers the committed identity and recovery-only handles. Provider reconciliation and retained terminal requests already handle ambiguity. |
| `opc-session-net/.../runtime.rs`: [registry installation, 775](https://github.com/openpacketcore/openpacketcore-sdk/blob/4b49fe5b39618af6f523e62f46fb62709212098b/crates/opc-session-net/src/fenced_mutation_roster/runtime.rs#L775-L900), [detached calls, 4632](https://github.com/openpacketcore/openpacketcore-sdk/blob/4b49fe5b39618af6f523e62f46fb62709212098b/crates/opc-session-net/src/fenced_mutation_roster/runtime.rs#L4632-L4740), [authority checks, 4867](https://github.com/openpacketcore/openpacketcore-sdk/blob/4b49fe5b39618af6f523e62f46fb62709212098b/crates/opc-session-net/src/fenced_mutation_roster/runtime.rs#L4867-L4928) | Readback preserves the local generation; successor recovery revokes old permits. Checks around a detached provider await cannot prevent a delayed physical effect. |
| `opc-session-net/.../canonical.rs`: [binding, 1646](https://github.com/openpacketcore/openpacketcore-sdk/blob/4b49fe5b39618af6f523e62f46fb62709212098b/crates/opc-session-net/src/fenced_mutation_roster/canonical.rs#L1646-L1669), [provider contract, 2411](https://github.com/openpacketcore/openpacketcore-sdk/blob/4b49fe5b39618af6f523e62f46fb62709212098b/crates/opc-session-net/src/fenced_mutation_roster/canonical.rs#L2411-L2520) | `MemberCall` binds immutable admission/member identity. Providers enforce durable fences and immutable signed outcomes; `reconcile_member` already permits only reconciled non-applied/compensated proofs. |
| `opc-session-store` `ProtectedAsyncRecoveryOwner`; higher-fence control in `docs/async-protected-recovery-908.md` | A whole-scope floor fences every admission in the old fence range, so it cannot close one admission while the same owner's other admissions continue at that fence. The provider fence floor already settles a retained admission under a higher fence, but that needs a successor lease, which is an extra consensus mutation that criterion 6 excludes. |
| `opc-ipsec-xfrm/src/namespace.rs`: [affine authority, 773](https://github.com/openpacketcore/openpacketcore-sdk/blob/4b49fe5b39618af6f523e62f46fb62709212098b/crates/opc-ipsec-xfrm/src/namespace.rs#L773-L806), [actor lifetime, 1040](https://github.com/openpacketcore/openpacketcore-sdk/blob/4b49fe5b39618af6f523e62f46fb62709212098b/crates/opc-ipsec-xfrm/src/namespace.rs#L1040-L1056), [recovery, 3291](https://github.com/openpacketcore/openpacketcore-sdk/blob/4b49fe5b39618af6f523e62f46fb62709212098b/crates/opc-ipsec-xfrm/src/namespace.rs#L3291-L3332) | Exact store/actor authority and serialized execution survive observer cancellation. Ordinary recovery refuses live authority; it cannot retire a delayed holder itself. |
| `opc-ipsec-xfrm/src/durable_roster_flow.rs`: [recovery, 1897](https://github.com/openpacketcore/openpacketcore-sdk/blob/4b49fe5b39618af6f523e62f46fb62709212098b/crates/opc-ipsec-xfrm/src/durable_roster_flow.rs#L1897-L1968) | Existing `Prepared` can retire without effects. Missing records fail at `restore`, before that transition. Running work needs adjacent proofs and exact readback. |

`prepare_terminal` requires complete conclusive observations before committing its terminal lock
([runtime.rs:4140](https://github.com/openpacketcore/openpacketcore-sdk/blob/4b49fe5b39618af6f523e62f46fb62709212098b/crates/opc-session-net/src/fenced_mutation_roster/runtime.rs#L4140-L4185));
it cannot bootstrap the missing proof. Also,
[durable_roster.rs:2611](https://github.com/openpacketcore/openpacketcore-sdk/blob/4b49fe5b39618af6f523e62f46fb62709212098b/crates/opc-ipsec-xfrm/src/durable_roster.rs#L2611-L2667)
prunes terminal records: `NotFound` can mean forgotten execution, not just never prepared.
Preparation prunes terminal records before its duplicate check
([durable_roster.rs:1811](https://github.com/openpacketcore/openpacketcore-sdk/blob/4b49fe5b39618af6f523e62f46fb62709212098b/crates/opc-ipsec-xfrm/src/durable_roster.rs#L1811-L1837)),
so a delayed prepare can recreate a binding after ordinary recovery retires it.
The whole-scope alternative and higher-fence control are documented in
[protected_recovery.rs:457](https://github.com/openpacketcore/openpacketcore-sdk/blob/4b49fe5b39618af6f523e62f46fb62709212098b/crates/opc-session-store/src/consensus/protected_recovery.rs#L457-L482)
and [async-protected-recovery-908.md](../async-protected-recovery-908.md#provider-effect-boundary).

## Proposed API and composition

Keep the signatures and outcome matrix of `FencedMutationRosterClient::reconcile` and `MemberProvider::reconcile_member`. The first `reconcile` closes prepare and execute locally for the whole admission. Each `reconcile_member` call asks the provider to close the exact member binding (`MemberCall::fence_binding_commitment`) permanently, at any fence, before the provider may return `NotApplied + Reconciled`. A conclusive negative requires physical exclusion that holds across restart. The `MemberProvider` documentation and the release notes state that an override returning `NotApplied` without the required exclusion and authenticated history is unsound once equal-fence readback is supported. After any reconcile, an `ActiveRoster` can reach Established only if every member is already Applied. Unsupported providers continue returning unknown.

Add one provider-facing XFRM operation that does not enter the actor queue, schematically:

```text
fence_durable_object_roster(store, group_id, generation, &retained_roster)
    -> Result<XfrmObjectRosterFenceObservation, XfrmObjectRosterDurableError>
```

The proposed opaque observation exposes either authenticated closed-without-effect
evidence for the complete ordered roster, or retained existing dispositions that
need normal observation/recovery. It grants no execution or deletion authority.
Storage errors, unresolved accepted work and unavailable history cannot produce
the former. The adapter signs ordinary SDK receipts; this observation is neither
a consensus receipt nor a new consumer-managed fence request/status protocol.

1. Resolve admission with the retained `AdmissionInput`. On the first reconcile,
   validate current authority, then close execution synchronously in the shared
   `LocalAuthorityRegistry` before provider dispatch. Revoke prepare/execute across
   **all** registrations for that admission, preserving recovery/compensation
   authority. Per-handle locks are insufficient: readback constructs
   [new registrations](https://github.com/openpacketcore/openpacketcore-sdk/blob/4b49fe5b39618af6f523e62f46fb62709212098b/crates/opc-session-net/src/fenced_mutation_roster/runtime.rs#L1684-L1718). Repeated
   readback, successor recovery and `NotTransmitted` must never reopen execution.
   This local change establishes no non-execution proof.
   Each local authority incarnation owns a fresh opaque process-local token. Entries, reservations and permits share that token; replacement creates a distinct token. An old permit retains its old token and cannot match a replacement, and completed incarnations leave no cumulative allocation counter. The closed flag lives on the live entry and is checked for prepare and execute only. This local closure is defense in depth; the regressions assert provider effects, not SDK refusal.
2. The trusted adapter binds the SDK-issued call to the retained XFRM store,
   namespace, group, operation generation and exact ordered request. Validate
   every immutable member, descriptor and expected version before I/O. The SDK
   lease fence, local authority incarnation and XFRM operation generation are
   distinct; do not substitute one for another or manufacture a higher lease.
   The admitted member descriptor commits to the exact group, the generation and an opaque identity of the open roster store (store incarnation, actor incarnation and namespace seal), returned by the registration operation above. The fence treats absence as never-started only when the open store matches that commitment; otherwise the result is unknown. The adapter never reuses a group and generation for another admission.
3. The XFRM effect boundary is the run's durable `Prepared -> Issuing` publication. After the existing store-binding check, the fence acts outside the actor queue under the same process lock: it closes the registration, returns an absence observation without publication, or moves an existing Prepared record to durable Closed. A retained Closed row is neither prunable nor unresolved writer authority. A run that is queued, paused before that publication or held by a delayed adapter then fails its registration check, Prepared-handle check or `Prepared -> Issuing` transition. No effect follows, and the fence does not wait for it. A record already Issuing, Applied or Compensating is accepted work. For such a record the fence reports the existing disposition, and the normal status, adopt and recover calls run on the actor after that work. Existing recover and adopt read a durable Closed record before the live-seal check. Do not burn the store-wide writer epoch, because unresolved work still needs its existing adjacent proofs.
4. Retain every begun binding and immutable canonical member outcome through terminal pruning and namespace reset until the consumer releases it.
   Persist Prepared-to-Closed transitions; an absent binding follows the
   registration rule above without a durable row. Only authenticated complete
   history coverage plus exclusion establishes never-started intent;
   forgotten outcomes or unknown store incarnations stay unknown. Existing
   adopt/recover must read closure evidence.
   Reject every later preparation or run for the closed binding, whatever fence it carries.
   Applied/running/conflicting records retain existing readback, adoption and
   guarded compensation requirements; never relabel Applied as NotApplied.
5. Produce ordinary provider-signed `NotApplied + Reconciled` evidence for each
   never-started member, bound through its `MemberCall` challenge. For already
   applied members use status/adopt; reconciliation cannot return Applied.
   Compensation still needs the complete aborting proof view. Only a complete
   eligible aborting proof set reaches existing `prepare_terminal` and retained
   `terminalize`/`terminal_status`, yielding one immutable Aborted body.
6. Once the consumer holds the durable SDK terminal receipt from `terminalize`
   or exact `terminal_status`, it releases each retained SDK-bound roster through
   the trusted adapter. This applies to both Established and Aborted settlement.
   The adapter verifies the receipt's exact admission/member binding before
   releasing the registration and any retained row; an ambiguous terminal result
   cannot release either.
   Release removes only settlement retention, never the established objects or
   existing cleanup responsibility. Normal finalization is not delayed to retain
   history: an Applied record must leave unresolved writer authority so unrelated
   rosters can prepare. Release is idempotent, remains owned across cancellation,
   and is retried automatically after restart from the durable terminal receipt.
   Batch its durable removal with the next store publication, before checking
   live-record capacity. Completed admissions therefore free their slots for
   later admissions rather than consuming a cumulative attach allowance.
   A binding with no durable row needs no release publication; removing its
   registration is sufficient, and a repeated release creates no retained state.

The interlock in step 3 reuses run admission's
[Prepared-handle validation](https://github.com/openpacketcore/openpacketcore-sdk/blob/4b49fe5b39618af6f523e62f46fb62709212098b/crates/opc-ipsec-xfrm/src/durable_roster_flow.rs#L926-L942)
and the store's
[compare-and-publish](https://github.com/openpacketcore/openpacketcore-sdk/blob/4b49fe5b39618af6f523e62f46fb62709212098b/crates/opc-ipsec-xfrm/src/durable_roster.rs#L1900-L1930)
under its [process lock](https://github.com/openpacketcore/openpacketcore-sdk/blob/4b49fe5b39618af6f523e62f46fb62709212098b/crates/opc-ipsec-xfrm/src/durable_roster.rs#L2318-L2335).
Member zero's install follows that publication; each later install follows its
own [adjacent-proof publication](https://github.com/openpacketcore/openpacketcore-sdk/blob/4b49fe5b39618af6f523e62f46fb62709212098b/crates/opc-ipsec-xfrm/src/durable_roster_flow.rs#L1105-L1125).

Cancellation or a lost closure reply leaves execution closed or unknown, never
ready to retry effects. Until release, repeat existing reconcile/status/adopt
with the same retained requests; reopen the same authenticated store after
restart. Return the same evidence commitment under successor authority.
The caller stops waiting at its original deadline, and the detached provider call keeps the existing fixed provider deadline. Neither extends the lease or authorizes a renewed admission, and expiry preserves ambiguity.
Every in-process store call waits for the store lock instead of failing on
contention. A critical section holds no await, provider call or second store
lease. A caller stops waiting at its existing absolute deadline; the actor
command, or the blocking fence or release task, keeps ownership and completes as
it does after cancellation. No store call therefore gets a deadline or wait
budget of its own. Contention never returns `StoreBusy`, fails a run, consumes
its affine authority or leaves a post-install publication unwritten. Expiry
grants no new effect authority. `StoreBusy` remains reserved for the
cross-process open lock.
Accepted cleanup can finish under existing cancellation-resilient ownership without
extending the call.

## Acceptance tests

These regressions map in order to #1280's six criteria.
Exercise the actual executor and a test `MemberProvider` adapter over the namespace actor that uses real receipt signing; consumers own the production adapter. Use an instrumented XFRM transport for the latches so the regressions run in default CI, and include a real durable-store reopen. Keep real-kernel restart and reset runs in the privileged XFRM workflow. A mock returning `NotFound` is insufficient.

| Criterion | Required regression |
| --- | --- |
| 1. Lost admission, no member started | Lose the committed admission reply; exact readback then reconcile every member. Assert zero backend effects, signed non-execution for every original identity, and one retained/read-back Aborted receipt. |
| 2. Delayed writers | Deliver the Admitted reply to one task, which issues ReadyMembers, then read back the same retained input; it stays recovery-only. Hold four writers: (a) a stale ReadyMember before its precheck, (b) the adapter before actor submission, (c) a run queued behind another actor command and (d) a run before its `Prepared -> Issuing` publication. Fence and settle Aborted while all four are held. Then release each and assert refusal and zero late effects. Repeat equal-fence readback after Aborted and assert that no earlier permit is current. |
| 3. Accepted work | Use two members. Deliver the Admitted reply, then read back the same retained input. Member 0 never starts. Member 1's run is held after its `Prepared -> Issuing` publication and before its install, and its acknowledgement is lost. Closure closes member 0 and reports member 1 as existing accepted work, never NotApplied. After the latch is released, status returns member 1's joined Applied evidence, and the existing compensation guard rolls it back. The roster then reaches Aborted with exact readback. On the baseline the test fails at member 0's non-execution proof. |
| 4. Existing states | Cover Prepared with live authority, Issuing, Applied, partial/conflicting and unavailable cases. Preserve exact readback, foreign objects, compensation guards and immutable outcomes. |
| 5. Ambiguity/restart | Cancel before/after closure persistence; lose closure and terminal replies; repeat readback under same/successor authority and reopen. Assert identical terminal body/evidence and exclusion after pruning/reset. Reject substituted bindings; prove unrelated bindings remain independent. |
| 6. Contract/cost | Count only the existing admission and terminal consensus mutations. Assert original deadline/lease enforcement, no effect replay/CAS/new admission, and rejection of unsigned, substituted or incomplete member evidence. |

For criterion 6, count one provider-local retention-release write for each
retained durable row and zero closure or release writes for an absent binding;
removal of released rows is batched with the next publication. These are not
consensus mutations. Complete and release more than the store's 30
live-record slots over successive admissions without a lifetime capacity failure.
Before release, verify retention across pruning/reset and retain a second
registration from exact readback. After release, keep stale prepare/run holders
and assert zero late provider effects; exact readback returns only the terminal
receipt. Also repeat after real store reopen, preserving the descriptor's
original store identity and the rejection of substituted identity.

Add these tests before changing the implementation. On the v2 implementation,
the capacity, registry-growth, lock-contention, reset-finalization and
released-history tests must fail; the terminal-binding and acknowledgement tests
are positive controls.

- Fill all 30 slots with width-two admissions, each with one Prepared member and
  one absent member. Every admission must settle Aborted and release within its
  existing deadline, without manual cleanup; the next prepare must succeed.
- Settle and release 10,000 bindings, both Established and Aborted, while retaining
  unrelated unsettled bindings. After each release, every in-memory settlement
  entry must belong to an unsettled binding; on the v2 implementation, count the
  released map. Every late prepare must be refused. Definitive non-admission must
  remove its entry, and the identical retry after `NotTransmitted` must register
  again, execute and release.
- Hold the store lock from a test thread when unrelated roster B starts its run,
  and again after B's first install, freeing it each time. B must finish Applied
  with no `StoreBusy`; the v2 implementation fails at the first hold. Then fence
  and release settled binding A on a blocking thread while the actor prepares,
  runs and finalizes B 100 times; every B run must be Applied. Finally hold the
  lock past the deadline of a fence caller and of a release caller. Each caller
  stops waiting at its deadline, both tasks complete once the lock is freed, the
  released row stops counting against capacity, and no effect follows.
- Reset an Applied Held roster and assert that finalization reports Retired.
- Reach Established through the real actor, finalize each roster, compare every
  terminal `settled_member_binding` with its recorded call commitment, release,
  and reject late preparation. Also hold a conclusive `AppliedExecuted` reply
  until reconciliation closes the admission: execute must return OutcomeUnknown
  and the member must never become Applied locally.
- Hold a second registration from exact readback while the ActiveRoster reaches
  Established. Release every roster, then prepare an unrelated roster so the
  released rows are removed. Reconcile each member through the second
  registration: the SDK must refuse before provider dispatch, and the provider
  must record no fence call. Also hold one such reconcile after its precheck
  until release and removal finish; the post-provider check must discard its
  result.

## Risks and review decisions

Reconcile irrevocably closes further prepare and execute for the entire admission
even when its result is unknown. Status/adopt remain available for observation;
an already-applied roster may still establish under the contract above. Review
this semantic change explicitly.

Durable closure must also preserve previously executed outcomes across pruning;
otherwise it creates a false negative.

Retention is per unsettled admission and is never cumulative. Begun SDK-bound
records, including Prepared-to-Closed rows, survive pruning and namespace reset
until the consumer releases them with the durable terminal receipt. Only those
durable rows count against the live-record limit; an absence closure needs no
slot. The live-registration rule prevents delayed preparation after release
without remembering completed bindings. A delayed run still fails because its
Prepared handle can never match again. Execution authority never survives a
restart: a ReadyMember exists only after a fresh admit, `AdmissionInput` is
neither Clone nor serializable, and a later admit of a committed admission cannot
issue one. The store's exclusive lock admits one process. Measure durable release
cost separately from the zero-publication absence case, as required by test 6.

A stored-format change uses a fresh install and rejects other
formats with a stable reason, never interpreting legacy absence as non-execution.

The implementation retains accepted history across a verified empty-namespace
reset using an authenticated reset marker. Its original member outcomes remain
unchanged, but observation, including finalization, reports retirement and it
holds no writer or cleanup authority. This marker never establishes never-started
execution. Prepared becomes Closed, while already-terminal outcomes stay immutable. Release can
then surrender this retained history after the exact SDK terminal receipt.

Every physical submission path must participate, including backend work surviving
timeouts. Review this boundary and authority revocation before implementation;
actor serialization alone is not the proof. Closure of one binding must not fence
another or invalidate its recovery epoch. Normal restart resumes retained
reconciliation automatically; the new path must require no operator cleanup or
restart. Closure authorizes no teardown of already applied traffic; existing
ownership and compensation rules remain decisive.
