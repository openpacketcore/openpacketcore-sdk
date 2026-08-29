# Protected Atomic Fenced-Mutation Roster

This document defines the generic protected-roster contract. It combines a
bounded external-effect roster with one authoritative session-record mutation
while keeping every external adapter outside consensus. It does not define
product, IKE, XFRM, dataplane, endpoint, or subscriber semantics.

## Capability and composition

Profile V1 is frozen as the present-predecessor profile: consumer revision 5,
schema 1, and persistent mTLS ALPN `opc-session-consumer/3`. A caller
constructs the V1 pool with
`PersistentSessionConsumerClient::from_fenced_mutation_roster_stateless` (or
its configuration-taking counterpart) and consumes it with
`into_fenced_mutation_roster_provider_adapter`. Composition fixes one member
provider, one publication provider, one executor attestor, one authenticated
scope, and one bounded persistent pool for the adapter lifetime. There is no
public raw consensus/store constructor and no per-subscriber connection, task,
channel, provider, or authority entry.

Every fixed-durable voter must explicitly activate the exact V1 profile before
advertising `/3`, then install the protected ingress signer on the quorum
consumer server:

```text
store.activate_protected_roster_profile().await?
service = Arc::new(store.consumer_service())
server = SessionQuorumConsumerServer::new(service.clone(), tls, authorizer)
    .with_roster_ingress(service, ingress_signer)
```

Activation persists the voter-set-bound profile certificate. Missing or stale
activation, a mixed-capability voter set, an ingress signer whose trust-root
identity does not match the store, or omission of `with_roster_ingress` keeps
the dedicated lane unavailable and admission fails closed. The public V1
client path is the persistent `/3` composition above; it does not add a
generic `SessionBackend` implementation or expose a raw consensus client.

## Additive absent-predecessor Profile V2

Profile V2 is a separate absent-predecessor contract. It uses consumer
revision 6, schema 2, and persistent mTLS ALPN
`opc-session-consumer/4`. It is not a reinterpretation, upgrade, or fallback
mode of V1. A V2-capable fixed-durable voter must explicitly activate the
exact V2 profile certificate before advertising `/4`; activation binds the
voter set and authenticated configuration identity just as strictly as V1.
A missing, stale, differently scoped, or mixed-capability activation keeps
`/4` unavailable. A peer that cannot negotiate the exact V2 profile fails
closed; it must not downgrade the request to `/3`.

Each V2 voter performs activation and ingress composition explicitly:

```text
store.activate_protected_roster_profile_v2().await?
service = Arc::new(store.consumer_service())
server = SessionQuorumConsumerServer::new(service.clone(), tls, authorizer)
    .with_roster_v2_ingress(service, scope_selecting_ingress_signer)
```

The ingress signer selects only topology-provisioned transport-ingress
authority for the request's authenticated scope. It cannot use one
listener-global leaf as cross-tenant authority. The V2 worker constructs its
one persistent pool and provider adapter at startup:

```text
pool = PersistentSessionConsumerClient::from_fenced_mutation_roster_v2_stateless(
    stateless_client,
)?
adapter = pool.into_fenced_mutation_roster_v2_provider_adapter(
    shared_member_provider,
    shared_publication_provider,
    executor_attestor,
    max_in_flight,
)?
```

The adapter, its persistent connections, and both providers are reused for
every roster in that exact scope. Constructing the pool, TLS material,
resolver, provider, attestor, or network connection inside a roster call is
outside this contract.

The V2 client and provider adapter are startup-owned persistent composition,
with one bounded pool, one member provider, one publication provider, one
executor attestor, and one authenticated scope for their lifetime. There is no
per-subscriber V2 adapter, raw store constructor, generic consensus client, or
ad hoc compatibility bridge. V1 `/3` and V2 `/4` use distinct durable
admission, reservation, activation, and canonical-record lanes. A V1 replay,
reservation, receipt, snapshot, or activation certificate can never authorize
V2, and a V2 object can never be decoded as V1.

V2 admission is valid only for the create-checkpoint mutation at the SDK-fixed
first generation, `Generation::new(1)`. The generation is not a caller input.
After authenticating the exact tenant, scope, key, owner, admission fence,
credential, and immutable V2 body, the first roster mutation proves the
authoritative session row is absent and atomically records the immutable
admission, its exact key-absence reservation, capacity reservation, and
eventual terminal slot. An existing row is a typed no-effect conflict only
after authorization; it is not an existence oracle. There is no preseed,
upsert, synthetic authoritative row, empty record, or sentinel encoding for
absence.

V2 has exactly the same two roster mutations as V1: admission and terminal.
On `Established`, the second mutation re-proves exact absence, inserts exactly
the admitted sealed checkpoint at generation one, retains the exact terminal
receipt, and removes the absence reservation atomically. On `Aborted`, it
re-proves exact absence, retains the exact Aborted receipt, and removes the
reservation without writing a session row. Any unexpected present row at that
point is a failed closed reservation/CAS corruption, never a create retry or
replacement. Only the exact Established receipt grants publication authority.

V2 preserves the complete immutable identity rules: nonzero 16-byte roster
and member operation IDs, authenticated tenant/scope/key/owner/fence binding,
strict current-fence and lease checks, exact replay/conflict commitments, and
the original body across status, adoption, retry, recovery, leader changes,
snapshots, and restart. Ambiguous admission, terminal, provider, or
publication transmission remains status/adopt-only unless exact
non-transmission is proven. `NotFound` never proves authoritative absence.
Provider `prepare`, `execute`, `status`, `adopt`, `reconcile_member`, and
`compensate_member` remain outside consensus, exactly as in V1; they cannot
add a roster mutation or create publication authority.

## Upgrade and topology compatibility

Profile V2 is additive at the roster API and protocol-profile boundary, but it
introduces a new public create-only `ReplicationOp` variant. Exhaustive
downstream matches therefore require a source update. The exact direct
consensus wire-schema revision advances from 7 to 8 so a revision-7 process
cannot silently discard that operation. A fleet must use a coordinated drained
stop/upgrade/start; there is no mixed-revision rolling mode.

V1 durable format 4 and every V1 object remain byte-frozen. Explicit V2
activation advances the local durable store to format 5 and installs distinct
V2 tables and an exact-scope activation certificate. A store at format 5 may
serve V1 only through the unchanged V1 objects and profile; format 5 does not
upgrade, reinterpret, or import a V1 roster. Membership change clears the V2
activation certificate, and traffic stays unavailable until the new exact
voter set proves and persists unanimous activation again.

A prospective learner is admitted only after it reports the exact V2
wire-schema, applied-state digest, and format-5 storage descriptor whenever the
durable history proves that V2 has been installed. This check is independent
of the fenced-transition V2 learner gate. A V1-only, stale, or mismatched
learner is rejected before `add_learner`, snapshot installation, or topology
mutation.

The public contract is additive under the `FencedMutationRoster*` names in
`opc-session-net`. V1 retains its frozen present-predecessor entry points:

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

FencedMutationRosterExecutorAttestorAdapter::new(
    topology_trust_root,
    executor_certificate,
    Arc<dyn FencedMutationRosterExecutorTerminalSigner>,
)

FencedMutationRosterClient::{prepare, admit, admission_status, recover}
FencedMutationRosterClient::{prepare_member, execute, status, adopt,
                              reconcile, compensate_member}
FencedMutationRosterClient::{prepare_terminal, terminalize, terminal_status}
FencedMutationRosterProviderAdapter::publish
```

V2 cannot be reached through that caller-selected-generation constructor. Its
create-only entry points are:

```text
FencedMutationRosterAbsentAdmissionProposal::new(
    profile_v2,
    roster_id,
    ordered_members,
    terminal_state_type,
    protected_plan,
    terminal_checkpoint,
    terminal_result,
)

FencedMutationRosterClient::prepare_absent(lease, proposal)
FencedMutationRosterAdmissionUnknown::recover_absent(current_lease)
FencedMutationRosterAbsentRecoveryInput::new(
    roster_id,
    original_owner,
    original_admission_fence,
    current_lease,
)
FencedMutationRosterClient::recover_absent(absent_recovery_input)
```

After those profile-specific preparation and recovery calls, V2 uses the same
typed `admit`, member, terminal, status, and publication method families. The
runtime profile remains fixed by the startup-owned `/4` adapter; none of these
methods accepts a fallback profile or a raw consensus authority.

`prepare`, member-provider operations, terminal preparation, and publication
provider operations are local. Admission and terminalization are the only
state-changing remote roster calls.

The attestor adapter accepts only topology-provisioned public trust material
and an HSM/KMS signer for SDK-constructed terminal preimages. The signer has no
tenant selector, proof constructor, consensus handle, or administrative
capability. The executor validates the certificate, current authority, exact
scope/body, and complete provider proof set before and after signing. The
public `fenced_mutation_roster_*_signing_digest_*` helpers expose only the exact
prehash for those typed SDK inputs.

## Immutable V1 admission

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

The V1 validated bounds are fixed by the profile:

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

V1 admission validates every bound, ordinal, ID, descriptor, expected version,
profile, authority component, current business generation, established
mutation, and protected envelope before any provider poll or effect. It also
atomically reserves the live row and that roster's eventual retained terminal
slot. The reservation survives restart and snapshot. Converting a valid live
row to terminal consumes the same reservation, so terminalization cannot later
fail because history capacity was exhausted.

## V1 two remote linearization points

The normal V1 successful path has exactly two real remote quorum mutations:

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
they are not a third state transition. The V2 rules above preserve this same
two-mutation boundary.

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

## Shared provider proof boundary

`FencedMutationRosterMemberProvider` is generic over opaque descriptors. Its
`prepare`, `execute`, `status`, `adopt`, `reconcile_member`, and optional
`compensate_member` methods receive an SDK-created
`FencedMutationRosterMemberCall`. The call binds the roster and admission
commitment, ordinal, stable member operation ID, descriptor and descriptor
commitment, expected version and generation, authenticated scope/key/owner,
current fence and credential, and half-open lease window.

A provider response is only an observation.
`FencedMutationRosterProviderCallOutcome::conclusive_receipt` accepts a signed
provider receipt whose typed outcome must be one of exactly four truth-table
rows:

| Disposition | Adoption | Terminal direction |
| --- | --- | --- |
| Applied | Executed | Established |
| Applied | Adopted | Established |
| NotApplied | Reconciled | Aborted |
| Compensated | Reconciled | Aborted |

The operation/outcome matrix is also fixed: `prepare` is never conclusive;
`execute` can conclude only `Applied + Executed`; `status` can reproduce an
applied outcome or report a reconciled non-applied/compensated outcome;
`adopt` can conclude `Applied + Adopted` or a reconciled
non-applied/compensated outcome; `compensate_member` can conclude only
`Compensated + Reconciled`; and `reconcile_member` can conclude only
`NotApplied + Reconciled` or `Compensated + Reconciled`.

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

## Shared ambiguity and recovery

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

V1 and Profile V2 share one ledger-global capacity and terminal-retention
order while keeping their canonical payload rows and wire profiles disjoint.
Q1 proves that the exact binding is vacant in both profile tables in the same
transaction that reserves it; a retained or copied binding in either profile
is a conflict. A format-4 store with no V2 namespace treats that complete
absence as an empty V2 side, while a partial or foreign V2 namespace remains
corrupt and fails closed.

Maintenance reclaims only terminal payload rows whose terminal commit is at
least 24 hours old. Each operation selects the oldest deterministic
`min(1024, eligible)` rows across both profiles, including a smaller final
batch, and never selects a live or ambiguous roster. Irreversible shared
conflict/history floors preserve same-ID replay/conflict behavior after
protected payload compaction and prevent profile-local maintenance from
bypassing an older row in the other profile.

The fixed V3 compact terminal tombstone for V1 is at most 256 bytes (237 bytes at
maximum owner, fence, generation, and Raft-index widths). It binds the exact
scope and request identity, admission and terminal body commitments, a
profile-bound commitment to the immutable admission owner, terminal phase, and
the terminal transaction's actual Raft log index. Reopen and snapshot install
authenticate the admission and terminal signers against their respective
membership intervals and require `0 < admission_index < terminal_index <=
applied_index` for terminal records. A non-genesis roster cannot survive after
its predecessor/history anchor is removed.

Profile V2 retains the same compact conflict closure under its distinct signed
root. That root binds the exact binding, ordered member ordinals, stable member
operation IDs, descriptor lengths and commitments, expected member versions,
the immutable admission authority, and the terminal authority/evidence. Status,
reopen, and snapshot validation reconstruct that root from the retained V2
carrier and reject missing, reordered, copied, cross-profile, or
authority-mismatched evidence before returning a terminal result.

## Diagnostics and isolation

Roster and pool snapshots contain only fixed-cardinality numeric counters,
occupancy, bounded latency buckets, and closed outcome classes. Debug and
diagnostic paths never render keys, values, roster or request IDs, member IDs,
tenant or peer identities, owners/fences, descriptors, endpoints, paths,
certificates, credentials, protected bytes, or raw provider/backend errors.

Scheduling uses one bounded startup-owned executor with a fixed global limit,
fixed tenant/scope classes, fixed shards, and fail-fast overload. There is no
global unbounded queue and no permanent resource keyed by a subscriber.
