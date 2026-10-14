# Fenced non-execution settlement after admission reply loss

Design proposal v2 for [SDK #1280](https://github.com/openpacketcore/openpacketcore-sdk/issues/1280).
Source baseline: `4b49fe5b39618af6f523e62f46fb62709212098b`.
Status: needs-review; no implementation included.

An admission that committed before its reply was lost must be settled using that
exact admission. Non-execution becomes conclusive only after its execution
generation is irrevocably closed at every member's physical effect boundary and
accepted work is quiescent or conclusively reconciled. Missing intent alone
remains nonconclusive.

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

Keep the signatures and outcome matrix of `FencedMutationRosterClient::reconcile` and `MemberProvider::reconcile_member`. The first `reconcile` closes prepare and execute locally for the whole admission. Each `reconcile_member` call asks the provider to close the exact member binding (`MemberCall::fence_binding_commitment`) permanently, at any fence, before the provider may return `NotApplied + Reconciled`. A conclusive negative requires durable physical exclusion. The `MemberProvider` documentation and the release notes state that an override returning `NotApplied` without durable closure is unsound once equal-fence readback is supported. After any reconcile, an `ActiveRoster` can reach Established only if every member is already Applied. Unsupported providers continue returning unknown.

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
   Entry generations come from one process-wide counter and are never reissued, so an entry that readback recreates never matches an earlier permit. The closed flag lives on the live entry and is checked for prepare and execute only. This local closure is defense in depth; the regressions assert provider effects, not SDK refusal.
2. The trusted adapter binds the SDK-issued call to the retained XFRM store,
   namespace, group, operation generation and exact ordered request. Validate
   every immutable member, descriptor and expected version before I/O. The SDK
   lease fence, local revocation counter and XFRM operation generation are
   distinct; do not substitute one for another or manufacture a higher lease.
   The admitted member descriptor commits to the exact group, the generation and an opaque identity of the open roster store (store incarnation, actor incarnation and namespace seal), which the XFRM crate exposes for this purpose. The fence treats absence as never-started only when the open store matches that commitment; otherwise the result is unknown. The adapter never reuses a group and generation.
3. The XFRM effect boundary is the run's durable `Prepared -> Issuing` publication. After the existing store-binding check, the fence makes a store publication outside the actor queue, under the same process lock: an absent binding gets a Closed row, and a Prepared record moves to Closed. Closed is neither prunable nor unresolved writer authority. A run that is queued, paused before that publication or held by a delayed adapter then fails its Prepared-handle check or its `Prepared -> Issuing` transition. No effect follows, and the fence does not wait for it. A record already Issuing, Applied or Compensating is accepted work. For such a record the fence reports the existing disposition, and the normal status, adopt and recover calls run on the actor after that work. Existing recover and adopt read a Closed record before the live-seal check. Do not burn the store-wide writer epoch, because unresolved work still needs its existing adjacent proofs. No separate in-memory gate or seal invalidation is needed.
4. Retain every begun binding and immutable canonical member outcome through terminal pruning and namespace reset until the consumer releases it.
   Persist closure for the exact binding even when it has no intent record. Only authenticated
   complete history coverage plus exclusion establishes never-started intent;
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
   releasing the retained row; an ambiguous terminal result cannot release it.
   Release removes only settlement retention, never the established objects or
   existing cleanup responsibility. Normal finalization is not delayed to retain
   history: an Applied record must leave unresolved writer authority so unrelated
   rosters can prepare. Release is idempotent, remains owned across cancellation,
   and is retried automatically after restart from the durable terminal receipt.
   Batch its durable removal with the next store publication, before checking
   live-record capacity. Completed admissions therefore free their slots for
   later admissions rather than consuming a cumulative attach allowance.

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
Accepted cleanup can finish under existing cancellation-resilient ownership without
extending the call.

## Acceptance tests

These are proposed additions, mapped in order to #1280's six criteria.
Exercise the actual executor and a test `MemberProvider` adapter over the namespace actor that uses real receipt signing; consumers own the production adapter. Use an instrumented XFRM transport for the latches so the regressions run in default CI, and include a real durable-store reopen. Keep real-kernel restart and reset runs in the privileged XFRM workflow. A mock returning `NotFound` is insufficient.

| Criterion | Required regression |
| --- | --- |
| 1. Lost admission, no member started | Lose the committed admission reply; exact readback then reconcile every member. Assert zero backend effects, signed non-execution for every original identity, and one retained/read-back Aborted receipt. |
| 2. Delayed writers | Deliver the Admitted reply to one task, which issues ReadyMembers, then read back the same retained input; it stays recovery-only. Hold four writers: (a) a stale ReadyMember before its precheck, (b) the adapter before actor submission, (c) a run queued behind another actor command and (d) a run before its `Prepared -> Issuing` publication. Fence and settle Aborted while all four are held. Then release each and assert refusal and zero late effects. Repeat equal-fence readback after Aborted and assert that no earlier permit is current. |
| 3. Accepted work | Use two members. Deliver the Admitted reply, then read back the same retained input. Member 0 never starts. Member 1's run is held after its `Prepared -> Issuing` publication and before its install, and its acknowledgement is lost. Closure closes member 0 and reports member 1 as existing accepted work, never NotApplied. After the latch is released, status returns member 1's joined Applied evidence, and the existing compensation guard rolls it back. The roster then reaches Aborted with exact readback. On the baseline the test fails at member 0's non-execution proof. |
| 4. Existing states | Cover Prepared with live authority, Issuing, Applied, partial/conflicting and unavailable cases. Preserve exact readback, foreign objects, compensation guards and immutable outcomes. |
| 5. Ambiguity/restart | Cancel before/after closure persistence; lose closure and terminal replies; repeat readback under same/successor authority and reopen. Assert identical terminal body/evidence and exclusion after pruning/reset. Reject substituted bindings; prove unrelated bindings remain independent. |
| 6. Contract/cost | Count only the existing admission and terminal consensus mutations. Assert original deadline/lease enforcement, no effect replay/CAS/new admission, and rejection of unsigned, substituted or incomplete member evidence. |

For criterion 6, separately count the one provider-local durable release write
per roster on the success path, including when batched with the next publication;
it is not a consensus mutation. Complete and release more than the store's 30
live-record slots over successive admissions without a lifetime capacity failure.
Before release, verify retention across pruning/reset; after release, keep stale
prepare/run holders, recreate a local entry through readback, and assert zero
late provider effects. Also repeat after real store reopen, preserving the
descriptor's original store identity and the rejection of substituted identity.

## Risks and review decisions

Reconcile irrevocably closes further prepare and execute for the entire admission
even when its result is unknown. Status/adopt remain available for observation;
an already-applied roster may still establish under the contract above. Review
this semantic change explicitly.

Durable closure must also preserve previously executed outcomes across pruning;
otherwise it creates a false negative.

Retention is per unsettled admission and is never cumulative. Closed rows and SDK-bound roster records are not pruned or dropped by namespace reset until the consumer, holding the durable SDK terminal receipt, releases them. They count against the existing live-record limit, and no lifetime cap is added. After release, a delayed run still fails because its Prepared handle can never match again. The store handle keeps released closures in memory for the life of the process and refuses a delayed prepare for them. No durable state is needed for this. Execution authority never survives a restart: a ReadyMember exists only after a fresh admit, `AdmissionInput` is neither Clone nor serializable, and a later admit of a committed admission cannot issue one. The store's exclusive lock admits one process. Release adds one provider-local durable write per roster on the success path; batch it with the next publication and report it in test 6.

A stored-format change uses a fresh install and rejects other
formats with a stable reason, never interpreting legacy absence as non-execution.

Every physical submission path must participate, including backend work surviving
timeouts. Review this boundary and authority revocation before implementation;
actor serialization alone is not the proof. Closure of one binding must not fence
another or invalidate its recovery epoch. Normal restart resumes retained
reconciliation automatically; the new path must require no operator cleanup or
restart. Closure authorizes no teardown of already applied traffic; existing
ownership and compensation rules remain decisive.
