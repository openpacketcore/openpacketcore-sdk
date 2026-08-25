# Protected Atomic Fenced-Mutation Roster

This document defines the generic revision-five protected-roster contract from
SDK issue #707. It combines a bounded external-effect roster with one
authoritative session-record mutation while keeping every external adapter
outside consensus. It does not define product, IKE, XFRM, dataplane, endpoint,
or subscriber semantics.

## Capability and composition

The only supported profile uses consumer revision 5 and persistent mTLS ALPN
`opc-session-consumer/3`. A caller constructs the pool with
`PersistentSessionConsumerClient::from_fenced_mutation_roster_stateless` (or
its configuration-taking counterpart) and consumes it with
`into_fenced_mutation_roster_provider_adapter`. Composition fixes one member
provider, one publication provider, one executor attestor, one authenticated
scope, and one bounded persistent pool for the adapter lifetime. There is no
public raw consensus/store constructor and no per-subscriber connection, task,
channel, provider, or authority entry.

The public contract is additive under the `FencedMutationRoster*` names in
`opc-session-net`. The principal entry points are:

```text
FencedMutationRosterAdmissionProposal::new(
    profile,
    roster_id,
    ordered_members,
    established_mutation,
    protected_plan,
    terminal_checkpoint,
    terminal_result,
)

FencedMutationRosterClient::{prepare, admit, admission_status, recover}
FencedMutationRosterClient::{prepare_member, execute, status, adopt,
                              compensate_member}
FencedMutationRosterClient::{prepare_terminal, terminalize, terminal_status}
FencedMutationRosterProviderAdapter::publish
```

`prepare`, member-provider operations, terminal preparation, and publication
provider operations are local. Admission and terminalization are the only
state-changing remote roster calls.

## Immutable admission

An admission proposal binds all data that must be fixed before the first
effect:

- one nonzero caller-owned 16-byte roster ID;
- one to eight ordered members, with six as the normal fresh-operation shape;
- contiguous immutable ordinals `0..len-1`;
- a distinct nonzero caller-owned 16-byte operation ID for every member;
- each member's nonempty opaque canonical descriptor and nonzero expected
  provider version;
- the exact established session-record mutation;
- the protected plan, protected terminal checkpoint, and exact protected
  terminal result.

The SDK later authenticates the proposal with the session key, exact consumer
scope and tenant partition, immutable logical owner and admission fence, and
expected generation. The immutable admission body and each terminal phase body
have separate commitments beneath the same stable roster identity. A higher
execution fence authorizes takeover but does not alter that immutable body,
reseal protected bytes, or create another operation ID.

The validated bounds are fixed by the profile:

| Item | Bound |
| --- | ---: |
| Members | 8 maximum; 6 normal fresh target |
| Protected plan | 1 MiB |
| Protected terminal checkpoint | 1 MiB |
| Exact protected terminal result | 16 KiB |
| Member descriptor | 16 KiB each |
| Provider evidence | 4 KiB each |
| Live rosters | 1,024 |
| Live plus retained terminal rosters | 131,072 |
| Operational target | 100,000 |
| Reclaim operation | oldest `min(1024, eligible)` |
| Terminal retention | 24 hours from terminal commit |

Admission validates every bound, ordinal, ID, descriptor, expected version,
profile, authority component, current business generation, established
mutation, and protected envelope before any provider poll or effect. It also
atomically reserves the live row and that roster's eventual retained terminal
slot. The reservation survives restart and snapshot. Converting a valid live
row to terminal consumes the same reservation, so terminalization cannot later
fail because history capacity was exhausted.

## Two remote linearization points

The normal successful path has exactly two real remote quorum mutations:

1. `admit` records the exact immutable roster and returns `Admitted`, the
   opaque `PollAdmitted` authority. No provider operation is allowed before
   this receipt.
2. `terminalize` atomically verifies the complete SDK-issued member proof
   bundle, writes the terminal roster receipt, and applies the bound business
   mutation in one consensus log position. It returns either exact
   `Established` or durable nonpublishing `Aborted`.

Provider `prepare`, `execute`, `status`, `adopt`, and compensation journals are
provider-local. They must not submit consensus mutations. Read-only admission,
recovery, and terminal status may use a linearizable consensus read barrier;
they are not a third state transition.

`Established` requires every ordinal to have a conclusive SDK-issued proof for
`Applied + Executed` or `Applied + Adopted`. Its transaction applies the exact
admitted checkpoint mutation and returns the byte-identical checkpoint and
result. Only consuming that receipt creates the opaque publication capsule.

`Aborted` requires every ordinal to have a conclusive SDK-issued proof for
`NotApplied + Reconciled` or `Compensated + Reconciled`. Its transaction writes
the durable terminal receipt and exact checkpoint/result but does not apply the
Established business mutation and cannot create publication authority.

`Pending`, `Indeterminate`, `Unreconciled`, a missing ordinal, a caller-shaped
state value, or a mixed Established/Aborted proof set cannot terminalize.

## Provider proof boundary

`FencedMutationRosterMemberProvider` is generic over opaque descriptors. Its
`prepare`, `execute`, `status`, `adopt`, and optional `compensate_member`
methods receive an SDK-created `FencedMutationRosterMemberCall`. The call binds
the roster and admission commitment, ordinal, stable member operation ID,
descriptor and descriptor commitment, expected version and generation,
authenticated scope/key/owner, current fence and credential, and half-open
lease window.

A provider response is only an observation.
`FencedMutationRosterProviderCallOutcome::conclusive` accepts exactly four
truth-table rows:

| Disposition | Adoption | Terminal direction |
| --- | --- | --- |
| Applied | Executed | Established |
| Applied | Adopted | Established |
| NotApplied | Reconciled | Aborted |
| Compensated | Reconciled | Aborted |

The startup-fixed SDK executor validates the provider result, checks current
authority before and after the call, and signs the exact member/body binding.
Only those nonconstructible `FencedMutationRosterMemberProof` values can enter
a complete proof set. Consensus verifies the complete ordered attestation
bundle again before applying the terminal transaction. A product cannot assert
`Applied` by constructing disposition or adoption enums.

Each provider must keep a durable journal keyed by the stable member binding,
atomically maintain a monotonically increasing execution-fence floor, reject a
lower or expired guard before I/O, and retain the first conclusive logical
outcome and evidence commitment. Cross-pod recovery reuses the original
logical identity with a strictly higher current fence; the old guard fails.

## Ambiguity and recovery

Only a direct `NotTransmitted` result for the exact retained `admit`, member
prepare/execute, terminalize, or inert publication-begin call restores retry
authority for that identical body. Cancellation, timeout, provider error,
partial write, lost reply, or `OutcomeUnknown` changes the corresponding
handle to status/adopt-only. It never permits a new ID, altered bytes, an
opposite terminal phase, or blind effect execution.

`NotFound` is non-exclusionary after ambiguity. It does not prove
`NotApplied`, authorize Aborted, restore execute authority, or permit a new
operation ID. Conclusive status/adoption evidence from the exact provider
journal is required.

`admission_status` authenticates the exact original admission request and
authority after an ambiguous admission reply. `recover` accepts the stable
roster ID and a current authenticated guard, then retrieves the exact admitted
plan, members, descriptors, checkpoint, result, and phase status from
consensus. Recovery does not enumerate subscribers and exposes neither a raw
store nor an existence oracle across scope. A successor may reconstruct the
same terminal proof body from provider status/adoption under its higher fence.
Once a terminal body may have transmitted, only that exact retained body may
be statused or directly retried after a proven non-transmission; Established
cannot be switched to Aborted or vice versa.

Protected plan, checkpoint, and result bytes are stored in the consensus
record and snapshots. Recovery returns the same bytes after voter restart,
leader change, process loss, and local or remote sealing-key rotation; callers
do not reconstruct, reseal, or draw a replacement IV.

## Publication and retention

Only an SDK-issued `FencedMutationRosterEstablishedTerminal` can be consumed
into an `EstablishedPublication`. The publication adapter first observes or
creates an inert provider-local intent and then adopts it. Its durable logical
state is monotonic (`Absent -> Reserved -> Attempted -> Published`), absence is
non-exclusionary after ambiguity, and an attempted or published identity must
not be deleted back to absence. The adapter makes no consensus call.
`FencedMutationRosterAbortedTerminal` deliberately has no publication method.

Maintenance reclaims only terminal payload rows whose terminal commit is at
least 24 hours old. Each operation selects the oldest deterministic
`min(1024, eligible)` rows, including a smaller final batch, and never selects
a live or ambiguous roster. Irreversible conflict/history floors preserve
same-ID replay/conflict behavior after protected payload compaction.

## Diagnostics and isolation

Roster and pool snapshots contain only fixed-cardinality numeric counters,
occupancy, bounded latency buckets, and closed outcome classes. Debug and
diagnostic paths never render keys, values, roster or request IDs, member IDs,
tenant or peer identities, owners/fences, descriptors, endpoints, paths,
certificates, credentials, protected bytes, or raw provider/backend errors.

Scheduling uses one bounded startup-owned executor with a fixed global limit,
fixed tenant/scope classes, fixed shards, and fail-fast overload. There is no
global unbounded queue and no permanent resource keyed by a subscriber.
