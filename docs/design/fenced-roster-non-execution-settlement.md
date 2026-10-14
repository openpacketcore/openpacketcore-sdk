# Fenced non-execution settlement after admission reply loss

Design proposal for [SDK #1280](https://github.com/openpacketcore/openpacketcore-sdk/issues/1280).
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
| `opc-ipsec-xfrm/src/namespace.rs`: [affine authority, 773](https://github.com/openpacketcore/openpacketcore-sdk/blob/4b49fe5b39618af6f523e62f46fb62709212098b/crates/opc-ipsec-xfrm/src/namespace.rs#L773-L806), [actor lifetime, 1040](https://github.com/openpacketcore/openpacketcore-sdk/blob/4b49fe5b39618af6f523e62f46fb62709212098b/crates/opc-ipsec-xfrm/src/namespace.rs#L1040-L1056), [recovery, 3291](https://github.com/openpacketcore/openpacketcore-sdk/blob/4b49fe5b39618af6f523e62f46fb62709212098b/crates/opc-ipsec-xfrm/src/namespace.rs#L3291-L3332) | Exact store/actor authority and serialized execution survive observer cancellation. Ordinary recovery refuses live authority; it cannot retire a delayed holder itself. |
| `opc-ipsec-xfrm/src/durable_roster_flow.rs`: [recovery, 1897](https://github.com/openpacketcore/openpacketcore-sdk/blob/4b49fe5b39618af6f523e62f46fb62709212098b/crates/opc-ipsec-xfrm/src/durable_roster_flow.rs#L1897-L1968) | Existing `Prepared` can retire without effects. Missing records fail at `restore`, before that transition. Running work needs adjacent proofs and exact readback. |

`prepare_terminal` requires complete conclusive observations before committing its terminal lock
([runtime.rs:4140](https://github.com/openpacketcore/openpacketcore-sdk/blob/4b49fe5b39618af6f523e62f46fb62709212098b/crates/opc-session-net/src/fenced_mutation_roster/runtime.rs#L4140-L4185));
it cannot bootstrap the missing proof. Also,
[durable_roster.rs:2611](https://github.com/openpacketcore/openpacketcore-sdk/blob/4b49fe5b39618af6f523e62f46fb62709212098b/crates/opc-ipsec-xfrm/src/durable_roster.rs#L2611-L2667)
prunes terminal records: `NotFound` can mean forgotten execution, not just never prepared.

## Proposed API and composition

Keep `FencedMutationRosterClient::reconcile(&mut RecoverableMember)` and
`MemberProvider::reconcile_member(&MemberCall)` signatures and outcome matrix.
Strengthen their contract: reconciliation requests permanent closure of this
admission's execution generation; a conclusive negative requires durable physical
exclusion. Unsupported providers continue returning unknown.

Add one provider-facing XFRM actor operation, schematically:

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
2. The trusted adapter binds the SDK-issued call to the retained XFRM store,
   namespace, group, operation generation and exact ordered request. Validate
   every immutable member, descriptor and expected version before I/O. The SDK
   lease fence, local revocation counter and XFRM operation generation are
   distinct; do not substitute one for another or manufacture a higher lease.
3. Set closure at a shared gate accessible before actor dispatch, then obtain
   the actor's durable, joined outcome. The gate must exclude a paused command
   that has not crossed the physical boundary without waiting for it to resume.
   Invalidate that generation's prepared authority and interlock closure with
   the last check before physical effect acceptance, including delayed prepare,
   dispatch and backend submission. Queue order or a post-await check is
   insufficient. Accepted operations retain tracked ownership until
   joined or conclusively reconciled. No negative observation may pass while a
   detached backend operation could still apply. Do not burn the store-wide
   [writer epoch](https://github.com/openpacketcore/openpacketcore-sdk/blob/4b49fe5b39618af6f523e62f46fb62709212098b/crates/opc-ipsec-xfrm/src/durable_roster.rs#L2095-L2165): unresolved work still needs its existing adjacent proofs.
4. Retain every begun binding and immutable canonical member outcome in the
   authenticated store before terminal pruning or namespace reset can forget it.
   Persist closure for the exact binding even when it has no intent record. Only authenticated
   complete history coverage plus exclusion establishes never-started intent;
   forgotten outcomes or unknown store incarnations stay unknown. Existing
   adopt/recover must read closure evidence. Reject later preparation/run for
   the closed binding at equal or successor fences. An existing `Prepared`
   record can use its zero-effect retirement after its authority is revoked.
   Applied/running/conflicting records retain existing readback, adoption and
   guarded compensation requirements; never relabel Applied as NotApplied.
5. Produce ordinary provider-signed `NotApplied + Reconciled` evidence for each
   never-started member, bound through its `MemberCall` challenge. For already
   applied members use status/adopt; reconciliation cannot return Applied.
   Compensation still needs the complete aborting proof view. Only a complete
   eligible aborting proof set reaches existing `prepare_terminal` and retained
   `terminalize`/`terminal_status`, yielding one immutable Aborted body.

Cancellation or a lost closure reply leaves execution closed or unknown, never
ready to retry effects. Repeat existing reconcile/status/adopt with the same
retained requests; reopen the same authenticated store after restart. Return the
same evidence commitment under successor authority. All steps share the caller's
original remaining budget and lease bounds: expiry stops waiting and preserves
ambiguity; it does not prove exclusion or authorize a renewed admission. Accepted
cleanup can finish under existing cancellation-resilient ownership without
extending the call.

## Acceptance tests

These are proposed additions, mapped in order to #1280's six criteria. Exercise
the actual composed executor, signed adapter and namespace actor with deterministic
latches and real durable-store reopen; a mock returning `NotFound` is insufficient.

| Criterion | Required regression |
| --- | --- |
| 1. Lost admission, no member started | Lose the committed admission reply; exact readback then reconcile every member. Assert zero backend effects, signed non-execution for every original identity, and one retained/read-back Aborted receipt. |
| 2. Delayed writers | Pause stale SDK capabilities, provider dispatch, actor dispatch and the final pre-effect gate. Fence/settle, release each, assert refusal and zero late effects; equal-fence readback must not revive them. |
| 3. Accepted work | Pause after physical acceptance and lose its acknowledgement. Closure must join/exclude it or remain unresolved; a missing observation or rejected late SDK proof must never yield NotApplied. |
| 4. Existing states | Cover Prepared with live authority, Issuing, Applied, partial/conflicting and unavailable cases. Preserve exact readback, foreign objects, compensation guards and immutable outcomes. |
| 5. Ambiguity/restart | Cancel before/after closure persistence; lose closure and terminal replies; repeat readback under same/successor authority and reopen. Assert identical terminal body/evidence and exclusion after pruning/reset. Reject substituted bindings; prove unrelated bindings remain independent. |
| 6. Contract/cost | Count only the existing admission and terminal consensus mutations. Assert original deadline/lease enforcement, no effect replay/CAS/new admission, and rejection of unsigned, substituted or incomplete member evidence. |

## Risks and review decisions

Reconcile becomes an irrevocable choice for the entire admission even when its
result is unknown; callers needing observation retain status/adopt. Review this
semantic change explicitly.

Durable closure must also preserve previously executed outcomes across pruning;
otherwise it creates a false negative. Retention needs explicit bounds and safe
compaction that preserves exclusion and evidence commitments; capacity exhaustion
must fail closed. A stored-format change uses a fresh install and rejects other
formats with a stable reason, never interpreting legacy absence as non-execution.

Every physical submission path must participate, including backend work surviving
timeouts. Review this boundary and authority revocation before implementation;
actor serialization alone is not the proof. Closure of one binding must not fence
another or invalidate its recovery epoch. Normal restart resumes retained
reconciliation automatically; the new path must require no operator cleanup or
restart. Closure authorizes no teardown of already applied traffic; existing
ownership and compensation rules remain decisive.
