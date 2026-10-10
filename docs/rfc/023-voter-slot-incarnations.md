# RFC 023: Voter slot incarnations

Status: design for [#1106](https://github.com/openpacketcore/openpacketcore-sdk/issues/1106),
amended after independent review; implementation qualification is pending.

## Purpose and operational contract

Replace one lost voter of a fixed quorum while a healthy majority continues
serving, without changing the number of logical voter slots. The consumer's
authenticated controller declares loss under its configured time bound or
verified storage-loss policy and requests replacement with an attestation.
The store never initiates replacement on its own timeout, on an empty
directory, or from a reused workload identity. It rejects a claim contradicted
by recent authenticated target traffic. Retirement commits at Prepare, before
refill. A merely down voter that returns with intact storage before retirement
retains its incarnation, including after every voter has stopped and restarted;
an already retired incarnation never returns even if its volume reappears.

This contract covers configuration consensus and every session fixed-quorum
persistence profile. Session fixed quorums currently contain three or five
slots; configuration HA topologies also admit seven and nine. A singleton has
no surviving majority after loss and cannot use this operation. General quorum
resize, majority-loss recovery, and replacement of two slots concurrently are
outside this protocol. With five slots and three healthy survivors, two lost
slots can be replaced sequentially; each operation replaces exactly one slot.
Advertise support separately for each store and persistence mode. Durable
profiles ship first; Async remains unavailable until its additional recovery
obligations below are qualified.

Operators see one slot progress through `Pending`, `CatchingUp`, and `Voting`.
Healthy replicas keep serving; the empty replica is unready for application
traffic until admission completes. No acknowledged strictly durable data is
lost by replacement. Existing Async durability limits still apply to unrelated
application writes. An in-flight operation may need its ordinary exact retry
during election or authority cutover. A crash or reschedule resumes from
retained state; the controller and SDK reconcile their own resources at startup
and exit. There is no node reboot, manual cleanup, recovery command, or manual
Pod replacement in this protocol.

Replacement of a storage replica neither releases a scope nor requests a
consumer shutdown. It changes no scope authority, incarnation,
admission-generation floor, or child-birth floor. A voluntary drain, eviction,
restart, or rollout remains subject to the consumer's emergency-session hold;
replacement is not permission to cut an emergency session. Values and configuration continue to change live or through
one-at-a-time rolling restarts, without a reinstall.

Crossing the stored-format boundary introduced here is a fresh installation
with new volumes; other formats are refused, without modifying their bytes,
with the stable reason `FreshInstallationRequired`.

Detect the storage-format marker before comparing installation or topology
identities. Add `ConfigConsensusOpenError::FreshInstallationRequired` and use
`ConsensusSessionStoreOpenError::FreshInstallationRequired` for the session
boundary; an old format must not surface as a generic identity mismatch.
This is a second session format boundary after scope profile 4, specified in
[RFC 022](022-scope-leases.md).
Deployments crossing both independently perform two fresh installations;
pinning the completed changes together permits one. Neither case adds migration.

## Existing boundaries and chosen approach

The original design was checked against SDK revision
`6dcb7179c8e70d5b825b0e0cfa6f42179336d623`. Scope composition below follows the
current profile-4 contract in [RFC 022](022-scope-leases.md).

| Boundary | Current behavior and required change |
| :--- | :--- |
| [Shared identities](../../crates/opc-consensus/src/identity.rs) and [transport](../../crates/opc-consensus/src/transport.rs) | `ConsensusNodeId` is a positive, signed-64-bit-portable ordinal. The envelope binds configuration and sender, but has no slot incarnation or incarnation credential. Add the bindings below to both directions. |
| [Session topology](../../crates/opc-session-store/src/topology.rs) | A logical replica name determines its Raft ID. Separate logical slot identity from the replaceable Raft member in the new fixed profile. |
| [Session membership coordinator](../../crates/opc-session-store/src/consensus/store/membership.rs) | Already coordinates learners, joint/uniform membership, authority fencing, and durable transition evidence, but rejects fixed-quorum changes. Reuse those mechanisms behind a narrowly authorized replacement operation. |
| [Session Raft adapter](../../crates/opc-session-store/src/consensus/raft_adapter.rs) | Already binds inner senders and drains admission at membership cutover. Extend the gate to retire an incarnation before engine effects and response accounting. |
| [Configuration coordinator](../../crates/opc-persist/src/consensus/store.rs) and [adapter](../../crates/opc-persist/src/consensus/raft_adapter.rs) | Require the immutable configured member set; `change_membership` only reasserts it. Implement the same replacement contract here, including transition-aware admission and snapshots. |
| [Scope authority](022-scope-leases.md) | Profile 4 supplies untimed authority, durable admission and child-birth floors, and activation continuation. Composition below must preserve that contract; the voter profile continues to refuse application families until this combination is qualified. |

The selected approach assigns the replacement a new Raft identity and uses
Openraft's learner and joint-consensus protocol. The stable slot set remains
fixed. Incrementing a side-table counter while reusing the old Raft ID is
rejected: votes, replication acknowledgements, and saved progress would alias
two storage histories. Removing the old member into a smaller uniform quorum
before adding the replacement is also rejected: it changes the configured
fault-tolerance contract and adds an unnecessary transition.

Raft's persistent term/vote requirements, leader completeness, and overlapping
majorities are the safety basis ([Raft, sections 5.2, 5.4, and 6](https://raft.github.io/raft.pdf)).
Openraft is still the only election, replication, membership, and commit
engine. Its [membership API](https://github.com/openpacketcore/openraft/blob/72e327a4f25cbbe3a3695d8c3c0f0970ccb925d5/openraft/src/docs/cluster_control/dynamic-membership.md)
supplies learner addition and joint/uniform changes. SDK admission is an
additional restriction on those operations, never an alternate quorum rule.

## Identity, trust, and committed records

### Stable slot, distinct Raft member

The immutable installation manifest binds the exact logical slot set, slot
ordinals, placement policy, authorized controller identities and genesis
incarnation public keys. Controller authorization binds a trust domain and
SPIFFE ID with per-slot permissions, not an immutable CA key. Validate current
credentials against the platform's rotating trust bundle; authenticated policy
and bundle updates apply live. A cluster's consensus identity includes a fresh
installation nonce; reusing a human-readable cluster name after a fresh install
must not recreate an old authority domain. This is installation identity, not
an application activation certificate.

The manifest digest supplied to `try_from_fixed_voter_slots` must commit to
those placement rules as well as the slot ordinals and genesis keys. The
constructor binds the supplied digest; it does not independently reconstruct
or verify the manifest's placement policy.

Within that cluster, `SlotId` is stable. Assign each slot an immutable ordinal
`s` in `1..=65535`; retain the existing, smaller topology-count limits. An
incarnation `k` is in `1..=2^47`. The new fixed profile uses the injective map:

```text
RaftNodeId(slot, k) = ((k - 1) << 16) | s
```

The result fits `1..=i64::MAX`. Check bounds before arithmetic; never wrap,
truncate, hash away a collision, or recycle an ordinal. All genesis members use
`k = 1`. Historical engine log IDs remain historical IDs; they are not rewritten
when a slot advances. The dynamic profile's existing ID derivation is not
silently changed by this design.

An incarnation key is generated and durably held with that incarnation's local
Raft state. Restart with intact storage keeps the key and incarnation; losing
either requires a newly authorized incarnation. It is not the workload SVID
key. The transport requires both authenticated workload identity and proof of
possession of the committed incarnation key, bound to a fresh channel challenge
and both endpoints' cluster, slot, incarnation, Raft IDs, configuration and
replacement digest. Use a domain-separated incarnation-admission signature
over the channel binding and challenge; signatures for another protocol or
connection cannot be replayed. Certificate rotation can preserve that binding.
A public status result or copied request body cannot construct it.

A repeated SVID subject, reused address, or fresh certificate for the old
process therefore cannot impersonate `k+1`. Only the separately authorized
controller can bind a newly selected candidate key. Peer caches and transport
lanes are keyed by incarnation as well as endpoint and configuration; response
authentication is checked before passing any term, vote, or match progress to
Openraft. The threat model remains crash/recovery Raft with trusted admission,
not Byzantine consensus. Copying an admitted private key and its live storage
to concurrent processes violates the existing exclusive-storage ownership
boundary and must be prevented by deployment admission.

### Replicated metadata

Both stores retain a reserved, versioned `VoterSlotTable`, atomically included
in their application snapshot and membership metadata:

| Field | Meaning |
| :--- | :--- |
| `format`, `cluster_instance`, `manifest_digest` | Exact codec, installation, and immutable slot/placement contract. |
| `revision`, `configuration_epoch` | Monotonic table revision and current uniform configuration epoch. |
| `slots[slot]` | Current incarnation, `retired_through`, current Raft ID, selected key digest and descriptor, and admission phase. |
| `replacement` | At most one active operation: request ID/body digest, expected revision/incarnation, verified loss/admission attestation, predecessor and desired exact configurations, candidate binding, and phase evidence. |
| `phase_evidence` | Full log IDs for Prepare, learner membership, installed snapshot cut, catch-up marker, continuation, Fence, joint, uniform, and Finalize when present. A missing field is distinct from log index zero. |
| `last_result[slot]` | Last request ID/body digest and terminal result, with revision/incarnation floors rejecting older attempts after its receipt is replaced. |

The attestation stores bounded, non-secret, generic verified claims and their
digest, not platform credentials or storage paths. Each table/command codec is
canonical and size-bounded independently of session count. Key material means
public keys/digests here; private keys never enter the replicated state. The
table envelope starts with `OPVI`, version 1. Missing tables in an older
storage format are not interpreted as all slots being pristine.

Under the pinned engine's `single-term-leader` profile, a full log ID contains
only term and index. Never infer a proposer node ID from the local leader view.
Version 1 is the Durable format. Add no speculative Async-only fields now;
enabling Async later requires a new table format version with its necessary
per-member activation evidence. That boundary is a fresh install, not migration.

The successor configuration uses `configuration_epoch + 1`, with its identity
digest binding the immutable manifest and every incarnation-qualified member
and key. Reject epoch exhaustion before Prepare. The database's immutable
storage anchor and stable scope identities do not change. Selecting `k+1` in
the table does not itself change engine membership or application admission:
until cutover, the engine still contains the fenced old ID in `C0`. Derive
quorum requirements from engine membership, never from the slot phase table.

`BeginVoterReplacement` is a compare-and-set of the exact table revision,
configuration, and current incarnation. It commits `k+1`, `retired_through = k`,
the candidate binding, and `Pending` in one application transaction with
Prepare evidence. Two requests racing for the same or different slots cannot
both reserve the one active replacement. Exact retries recover the retained
result; reusing an ID with changed claims returns `IdempotencyConflict`.
An obsolete expected incarnation returns `StaleIncarnation`, never another
increment. Deadlines bound attempts, not the lifetime of committed work.

The floor is permanent. There is no abort back to `k`, including before the
first learner append. Later successful replacement advances it again. One
floor per slot excludes all prior incarnations without an unbounded tombstone
list. Consumer deletes, configuration history pruning, scope reclamation,
snapshot compaction, and membership cleanup cannot remove it.

The native applied slot table is the bounded checkpoint of completed control
history. Decoded log projections are needed only for unapplied membership and
control entries; a Marker changes no table and retains no projection. Selected
checkpoint publication, including snapshot and purge checkpoints, releases
projections covered by its applied cut. Truncation releases an abandoned
suffix. Old captured views keep their immutable facts until their readers
finish. Charges cover the projection's concrete allocation and variable data,
without a fixed per-row verification allowance. Encoded log lineage witnesses
continue through the existing complete generation validators.

The current configuration storage/snapshot version 6 is a fresh-install
boundary for every `ConsensusConfigStore`, including the existing profiles
without incarnation replacement. There is no version-5 database or snapshot
migration. The session incarnation profile has its own native format boundary.

All replacement controls, retirement admission state, promotion evidence, and
the snapshot/catch-up cut are strictly durable before their acknowledgements
count. In an Async session profile, that means flushing the entire preceding
log/application prefix needed by the control cut, not writing a standalone
floor ahead of undurable state. Subsequent ordinary application writes keep
their configured persistence mode. Existing Async cold-recovery and protected
owner checks remain additional admission conditions; a replacement certificate
does not substitute for them. The Async implementation must support this
strict barrier through its existing persistence protocol before claiming
support for #1106.

In particular, a committed Prepare changes the Async recovery participant set:
remove every incarnation at or below its committed retirement floor from the
"every retained member" recovery requirement. Pending/CatchingUp candidates
never join that set. Before uniform, derive retained participants from `C0`
minus those retired incarnations; do not require the successor to recover the
old authority range. The strict Prepare prefix binds that participant change
to the same committed authority cut. All remaining retained participants must
reconcile their existing recovery ranges, votes and applied floors through the
Async recovery protocol; reducing the set does not mean choosing an arbitrary
fresh majority or dropping an acknowledged authority range. At strict uniform
commit, derive the successor recovery set from the new configuration and
retained admission evidence. A candidate that never became active cannot be
required to recover a range it never authorized.

This supplies the forward path when a survivor crashes after Prepare. Before
any retirement commits, one lost Async slot plus a cold survivor can leave no
safe admission quorum; #1106 must return `NoSurvivingQuorum`, not invent a
retirement cut to repair it. That is outside its healthy-majority entry
condition. Async support remains unadvertised until tests prove the participant
transition and authority-range preservation, including the post-Fence case.

### Retirement is an engine admission barrier

An apply callback alone is too late: followers can acknowledge a log append
before they learn that it committed. Before acknowledging durable append of a
valid Prepare intent, the adapter closes that slot's old inbound and outbound
engine admission, drains previously accepted effects, and fences cached replies.
The leader does the same before proposing it and excludes the lost member from
the proposal's replication acknowledgements. Thus a surviving quorum has the
fence before the entry can commit. No acknowledgement from the old member can
authorize retirement or a later entry.

Before commit, this is a **provisional** fence attached to the exact durable
log ID and request, not a committed floor. Reconstruct it before opening RPCs
after restart. A pre-dispatch gate initially belongs to one exact append
attempt. If definitive engine completion plus the serialized durable-log check
proves that the intent was never appended (for example, stale term or log
conflict), release that attempt's gate: it produced no durable acknowledgement.
Once appended, remove its gate only when Openraft definitively truncates that
uncommitted intent or committed apply rejects its CAS without effect; a client
timeout or a leader change is not that proof. Committed apply atomically turns
the successful intent into the permanent floor. Snapshot installation and log
purging must preserve either the intent or its committed result. Concurrent
duplicate/conflicting intents cannot clear one another's gates. A snapshot at
or beyond the intent index resolves it under the same serialized publication:
the matching reservation/floor retains the fence; absence of that reservation
and of its successful result proves that the uncommitted intent was displaced.
A snapshot below that index cannot erase the intent or its gate.

A target whose retirement is only provisional may lead a higher term elected
by a majority that did not acknowledge that Prepare. Admit its authenticated
AppendEntries and InstallSnapshot requests only when their leader term exceeds
the intent's term. This lets the engine replace the uncommitted suffix. Keep
refusing its votes, leadership transfers and response accounting, and never
apply this exception to a committed retirement floor. Admission of the higher
term alone does not release the fence: durable truncation, apply or snapshot
publication must resolve the exact intent. Fence setup drains earlier calls,
but its coordinator lock is released before awaiting Prepare completion so
that the request which resolves it can enter.

Permit at most one replacement intent in the effective uncommitted log, as
well as one operation in applied state. A new leader first resolves/commits its
inherited suffix under a current-term barrier before considering another
intent. Its surviving-majority check excludes all provisional and committed
fences. A concurrent intent for another slot is refused before any new gate is
installed; otherwise two individually harmless fences could stop all progress.

Engine admission and storage publication must have an explicit lock order:
stop new old-incarnation calls, await their definitive engine completion,
persist the intent/floor, then acknowledge. Establish the gate in pre-dispatch
inspection of the authenticated append or local proposal, before queueing the
barrier into Openraft; waiting for queued RPCs from inside a blocking engine
storage callback would deadlock. The incoming append carrying the barrier
comes from a retained leader, not the retired slot. Do not hold an RPC read
guard while awaiting an apply callback that needs that same guard's exclusive
lock. Cancellation never opens a closed gate.

An isolated stale replica cannot learn a commit instantaneously. The guarantee
is that from commit no old-incarnation message or delayed reply can influence
the authoritative quorum, and every replica that obtains the cut refuses it
permanently. A stale minority may exchange rejected or obsolete traffic among
itself; it cannot create authority. An up-to-date quorum's durable fencing and
Raft log rules prevent that minority from erasing the floor or forming a valid
successor quorum. Recovery refreshes floors before admitting application work.

## Replacement state machine

Let `C0 = {A, B, C[k]}` and `C1 = {A, B, C[k+1]}`. The surviving set `{A, B}`
is a majority of both sets. For larger fixed quorums, require a live,
authenticated majority drawn from the unchanged members. Check this with a
fresh engine barrier and successful durable control replication, not metrics
or a count of open sockets. Reject a new operation without that quorum.

```text
Voting(k)
    | controller request + healthy surviving quorum
    | commit BeginVoterReplacement / Prepare, retire <= k
    v
Pending(k+1)
    | exact profile checks, verified snapshot installation, learner addition
    v
CatchingUp(k+1)
    | durable applied marker + continuation if needed + authority Fence
    | commit joint membership C0 && C1
    v
Voting(k+1, joint)
    | commit uniform C1 + atomic authority/activation cutover + Finalize
    v
Voting(k+1, complete)
```

`Voting` includes a membership subphase. It first permits election participation
after committed joint membership; `complete` additionally means uniform
membership, current application admission, and retained final result. Returning
`Voting` without that subphase would misleadingly report full recovery early.

1. **Validate and Prepare.** Authenticate the controller and selected candidate,
   validate positive loss evidence for the expected incarnation, bind the new
   key, and verify a surviving majority. The target cannot be the confirmed
   live leader driving the operation. Commit the exact reservation and
   retirement as above. Serialize this with every other membership operation
   and the activation freeze. Apply the `TargetStillLive` check below before
   the proposal and on each counted survivor. No activation certificate is
   required.
2. **Pending.** A dedicated candidate-open path persists its own incarnation
   binding before exposing control RPCs. It starts as an empty Openraft learner,
   with elections, voting, application service, and ordinary outbound engine
   initiation fenced. It never calls `initialize()`. Before transferring any
   state, check the candidate's support for every format already present and,
   where required, commit the transition-bound capability continuation.
3. **Snapshot.** Install a snapshot through the restricted candidate control
   path **before** `add_learner(new_id, ..., false)`. The leader builds it at a
   committed cut at or after Prepare. Deliver bounded chunks through the same
   authenticated incarnation and verified-artifact checks as ordinary snapshot
   reception, then call Openraft's `install_full_snapshot` on the candidate;
   never copy state around the engine. Include the complete slot table,
   membership, pending transition, activation history and application state.
   Even an empty application has a nonempty consensus/slot snapshot. Persist
   and attest the installed snapshot ID/digest/cut. Commit the exact
   `RecordReplacementSnapshot`, then add the learner and continue normal log
   replication in CatchingUp. The record alone does not imply learner membership.
   A successor leader may deliver a new snapshot only before
   `RecordReplacementSnapshot` commits. After that commit, its retained artifact
   binding is immutable: recheck that installed-cut proof, add the learner and
   close any later gap through ordinary replication. A partially delivered snapshot grants
   nothing and is retried from an authenticated current leader.

   This out-of-band bootstrap avoids coupling correctness to the leader's
   retention policy or purging useful logs on every leader change. The normal
   replication stream never starts against a snapshot-blocked empty candidate,
   so it cannot loop on transport errors. The alternative of snapshotting and
   purging through Prepare, then returning Raft-level conflicts to log probes,
   is valid but unnecessarily changes retention to drive engine backtracking.
4. **CatchingUp.** Tail normal replication. Commit a marker in the current
   leader's term, then require the candidate's durable applied cut to include
   that exact marker, Prepare, and the installed snapshot. Leader-side
   `matched` progress or `add_learner(..., true)` alone is insufficient. On
   retry after a leader change, revalidate live candidate possession and obtain
   a fresh current-term barrier; retained old evidence is not a live response.
   Retain that exact marker across retries in the same leader term. An owned
   proposal must resolve before another can be submitted. Unavailable candidate
   probes back off from 200 ms to a five-second cap; local apply notifications
   cannot bypass that delay.
5. **Fence and joint.** Verify exact continuation evidence, then commit the
   application authority Fence and call the engine's
   `change_membership(C1, false)`. Keep the normal majority size; never treat
   the learner or retired voter as a substitute for the surviving majority.
   Openraft emits the joint and uniform entries. The SDK observes their real
   committed/applied log IDs; it never manufactures membership entries.
   **Fence applied with effect (authority switched) is the point of no return.**
   A Fence entry that commits but is refused at apply has no effect and does not
   prevent supersession. After successful apply, rely on the retained
   learner-marker/continuation evidence and perform no live candidate barrier.
   Specifically, the replacement path must bypass the existing coordinator's
   `AuthorityFenced` recheck of `AppliedLearnerMarker`. Finish joint and uniform
   with the survivors even if the candidate has lost its volume. Refuse a new
   attempt for that slot with `ReplacementPastFence` until completion; then
   replace the dead successor as the next ordinary operation.
6. **Voting and completion.** On each node, admit candidate voting only after
   exact joint commitment and local application of the required incarnation and
   catch-up evidence. The candidate must itself have durably applied the joint
   entry, or installed a snapshot retaining that exact commitment and its
   prerequisites, before its voting gate opens. Uniform apply atomically
   publishes the successor table/configuration, application authority, and
   scope activation continuation. Finalize records completion and releases the
   operation slot.
   Remove retired routes and owned staging resources asynchronously and
   idempotently; no reply from the lost voter is ever required.

Initial snapshot delivery retains one verified artifact at or after Prepare
for the exact operation and leader vote. A retry reuses it, including its ID,
digest and acknowledged offset. Each chunk has a separate operation budget;
there is no whole-transfer deadline that cancels progress. Receivers accept
exact duplicate chunks without changing accepted bytes, so a lost reply does
not force reconstruction. A lost final reply is checked against the candidate's
installed evidence before resending. A receiver that lost its staging file can
request a restart from zero using the retained artifact. Supersession or a
different leader vote invalidates the cached work.

Openraft's [effective membership](https://github.com/openpacketcore/openraft/blob/72e327a4f25cbbe3a3695d8c3c0f0970ccb925d5/openraft/src/docs/data/effective-membership.md)
changes when an entry is observed, before commit. The SDK's stricter voting
gate must cover automatic elections, explicit campaigns, self-votes, inbound
votes, and outbound replies; filtering inbound Vote alone is insufficient.
Start with the pinned engine's runtime election switch off, as cold Async
startup already does; keep explicit campaigns and LeadershipTransfer closed
too. Only if these existing controls fail the self-vote tests is a new engine
hook needed. Do not equate engine `ServerState::Follower` or an effective voter
ID with committed SDK voting admission. Candidate replication acknowledgements
at or beyond the joint entry must also be withheld from quorum accounting
until this gate opens: effective membership must not count the former learner
early. Earlier learner progress proves catch-up only. The unchanged majority
can commit the joint entry and propagate its commit before these responses
are admitted, so the gate does not require the learner to commit itself.

The common surviving majority can commit the joint entry without the new
member voting. During joint consensus Openraft requires both majorities; the
union contains `N+1` engine identities, but each voter set has exactly `N`
slots. The retired identity is unavailable, not silently removed from the
old majority denominator. After uniform commitment the new set governs.

The existing session staging barrier already counts a current quorum; it does
not require every current member. The obstacles to direct reuse are its fixed
profile rejection, fixed engine admission's exact-uniform requirement, and the
post-Fence candidate re-barrier described above. Admit only the
exact shapes authorized by this retained replacement, using the surviving
majority and the candidate where its proof is needed. All other drift remains
an error. Do not enable arbitrary dynamic membership for a fixed deployment.

## RPC refusal rules

Before decoding engine state into an engine call, validate schema and bounds,
installation, source and destination bindings, authenticated incarnation-key
possession, configuration/transition, and the current committed or provisional
gate. Recheck under the gate held through definitive completion. Apply the same
rules to in-process test transports and raw handler entry points, not only mTLS.
Unknown higher incarnations are refused just as lower ones are; callers cannot
advance a floor by advertising a larger number.

| RPC or direction | Admission and refusal |
| :--- | :--- |
| RequestVote and Vote response | Sender and intended recipient must be admitted voting incarnations in the exact engine configuration. Bind the candidate ID in the request to its authenticated source. `Pending`, `CatchingUp`, retired, unknown, or mismatched identities are refused before term/vote updates, timer resets, self-votes, or response tallying. A response's contained vote is not its authenticated responder identity. |
| PreVote and response | The pinned engine has no PreVote RPC. Unknown wire families fail closed. Any future PreVote implementation must use the same incarnation/voting gates before evaluation and tallying, and cannot mutate durable term/vote or grant voting admission. It is not a retirement or promotion proof. |
| AppendEntries, empty heartbeat, and AppendEntriesRoster | Only a currently admitted leader incarnation may initiate. Start the candidate's replication stream only after out-of-band snapshot installation and learner addition; a retired source or destination is refused. Preserve the existing inner leader-ID binding and roster payload checks. Responses from a retired member or an obsolete channel cannot alter term, match index, or commit progress. |
| InstallSnapshot, every chunk and final install | Only an admitted leader can send, addressed to an exact admitted voter or selected candidate. Revalidate the sender/receiver and replacement binding for each chunk and at publication. Refuse regressions in slot floors, table revision, membership/transition evidence, format, or activation floors. A new leader starts a freshly authorized transfer; stale chunks cannot finish it. |
| LeadershipTransfer | Both identities must be admitted voters in the appropriate committed configuration, with the existing exact vote/log checks. No transfer to a learner, retired incarnation, or uncommitted successor. |
| Replacement control / TopologyAdmissionBarrier | Controller authorization or candidate proof admits only typed status, possession, capability, installed-cut, and catch-up operations for the exact request. This path grants no votes, consumer mutation authority, or arbitrary snapshot reads. |
| ForwardMutation, ForwardRosterMutation, ReadBarrier | A replica forwarding application traffic must have current incarnation and application admission. Pending/catching-up replicas cannot proxy authority. Consumer authentication remains separate. During authority cutover preserve retryable no-effect versus outcome-unknown semantics. |

Snapshots can contain historical log IDs referring to a retired member; that
does not make the historical member a valid RPC sender. An older snapshot may
be useful to other existing followers, but cannot initialize this candidate:
its installed snapshot must carry this replacement's Prepare and floors.
Restoring a stale local backup never lowers a floor already known to the
healthy quorum. Keep its engine quarantined while refreshing admission;
application-only quarantine would still let forgotten votes affect elections.
The SDK does not claim to detect an arbitrary externally restored Durable
backup. Restoring a voter volume is therefore a consumer rule: never start the
restored state as that voter; request a new incarnation instead. An intact,
merely lagging voter follows ordinary catch-up without changing incarnation.

A retained voter's routing can be stale when another slot has been replaced.
The restricted control path must allow discovery of current candidate bindings
through the manifest's trusted admission authority, and a fresh quorum-backed
status/read through retained peers. A verified discovery result stages only
recovery transport; the leader's snapshot/log installs the committed table and
membership before normal admission. Neither an unknown higher-incarnation RPC
nor an unauthenticated endpoint hint can supply that result. This path must
work when the current leader is the new member, without requiring an old
leader to return or a person to edit peer configuration.

## Formation before activation and scope continuity

### No application activation dependency

Replacement control is consensus-management authority, reachable on retained
healthy voters before cluster feature activation, scope activation, or ordinary
application readiness. Its requirements are the immutable genesis manifest,
authenticated selected identities, safe local Raft state, and a surviving
majority. It must not call an application facade that first requires scope
authority or unanimous application-profile activation.

For a genuinely pristine installation, every enrolled genesis voter may ask
Openraft to initialize **the same exact manifest**; the lowest voter remains a
preferred initiator, not a single required initiator. The pinned
[initialization contract](https://github.com/openpacketcore/openraft/blob/72e327a4f25cbbe3a3695d8c3c0f0970ccb925d5/openraft/src/raft/mod.rs#L780)
allows this. Persist and authenticate the genesis binding first. A fresh
compatible majority can establish that full configuration even if a minority,
including the preferred initiator, is missing. Never initialize a discovered
subset, infer pristine status from an empty directory, or give a replacement
the genesis key/enrollment of the lost voter. A previously enrolled voter with
lost storage is always a replacement, not pristine genesis.

Formation must therefore separate base protocol/manifest compatibility from
the current complete-fleet application activation probes. A retained voter
resumes its log; a new candidate uses the learner path. The controller keeps
genesis enrollment and loss selection durably so its own restart cannot issue
the old incarnation to an empty volume. No replacement can commit until a
normal leader and surviving majority exist, but neither needs an application
activation certificate. This also covers a cluster whose membership committed
before its first application activation attempt.

A loss before an immutable manifest/enrollment exists is a new enrollment,
not replacement of a committed voter. Never reuse an already issued genesis
binding for an empty volume while other members may have used it.

### Composition with untimed scope authority

Prepare and the incarnation reservation share one serialization boundary with
initial activation. Once Prepare applies, new initial activation is frozen
until replacement reaches uniform completion. An activation ordered before
Prepare is visible in the coordinator's post-Prepare durable read; one ordered
after Prepare receives a retryable no-effect refusal. The same rule must cover
all activation families whose format could otherwise appear during catch-up.

If there is **no** activation/history, replacement does not fabricate a scope
certificate or require one. After completion, initial activation performs its
ordinary all-current-voter check on the new incarnations. This resolves the
fresh-install lost-minority case without unanimous contact with the lost voter.

If scope activation **exists**, probe only the new candidate for the exact
required profile over its authenticated staged control path, then commit
`CertifyScopeProfileContinuation` before any snapshot/log containing that
profile reaches it. Bind the proof to the exact replacement ID/digest,
predecessor and successor identity, complete incarnation-qualified voter sets,
and candidate key. Retain the continuation row and its log floor through
restart, compaction, and snapshot install. A remembered probe is insufficient.
The activation-family policy is explicit:

| Retained family | Replacement rule |
| :--- | :--- |
| No application activation/history | Proceed without an activation certificate; initial activation remains frozen until completion. |
| Scope authority/batch profile 4 | Carry its exact continuation and atomically inherit it at uniform apply. |
| Fenced-transition V2 | Return no-effect `ActivationContinuationUnavailable` before Prepare while its activation/history is present; today's generic cutover deletes its certificate. A separately qualified continuation is required to enable this combination. |
| Protected-roster V2 | The same typed pre-Prepare refusal until a continuation for this family is qualified. Do not add a unanimous post-cutover availability gap. |
| Unknown or unsupported activated format | Refuse before Prepare with `IncompatibleProfile`; never discard format history. |

Reuse the scope-continuation checks at Fence, joint promotion, and uniform
apply. Uniform apply carries the activation certificate to the successor in
the same transaction. Stable scope identity, selected incarnation and execution,
admission-generation and child-birth floors, batch checkpoints, and exact replay
state are unchanged. A closed predecessor stays closed; replacement supplies
no closure proof and cannot grant succession. No all-voter reactivation round
is added. Existing scope authority and batches continue under predecessor
admission during Prepare, Pending, snapshot transfer, and CatchingUp.

The brief authority refusal interval starts at Fence and ends at successor
admission; election is a separate possible interruption. Old-stamped commands
ordered after Fence get the existing retryable no-effect result. An uncertain
client retains its exact request and resolves it under current admission.
Preserve the bounded work classes specified in [RFC 024](024-scope-priority-scheduler.md)
and do not hold an application admission lock across candidate network waits.
After Fence, reconcile toward uniform membership with the surviving majority; do not wait for the retired voter, candidate or external
caller. Candidate loss does not lengthen this window by a refill. A successor
leader uses committed evidence and closes the same transition automatically.

Ownership never expires. Loss of quorum delays store mutations; elapsed time,
store unavailability, and replacement status loss do not authorize dropping
installed forwarding or retiring a scope execution. Ordinary request deadlines
bound waiting only. Reconnection resolves exact pending outcomes and checks
current authority without renewing ownership. Losing only the external
coordinator, including while a candidate is slow, must not close predecessor
admission. The design's forward-only voter retirement must never take the
generic transition Abort path that would restore the retired incarnation.

## Consumer API and unattended reconciliation

The following are proposed typed interfaces, not existing API names. Shared
identity, request, status, and refusal types belong in `opc-consensus`; each
store owns deterministic apply and storage integration. Transport admission
constructs verified facts; deserializing a request never constructs authority.

```text
replace_lost_voter(authenticated_controller, request, deadline)
    -> ReplacementStatus | ReplacementError

request = {
    cluster_instance, request_id, expected_table_revision,
    expected_configuration, slot, expected_incarnation,
    verified_loss_selection, selected_candidate_binding
}

replacement_status(authenticated_controller, cluster_instance, slot, deadline)
    -> linearizable { revision, incarnation, phase, membership_subphase,
                      request_id, request_digest, committed_cuts, reason }

open_replacement_candidate(verified_local_binding, local_store, peer_resolver)
    -> application-fenced candidate handle

pull_candidate_binding(authenticated_candidate, cluster_instance, slot,
    candidate_key_digest, challenge_response, deadline)
    -> committed candidate binding | no committed binding
```

`pull_candidate_binding` belongs to later bootstrap and service integration;
the durable replacement coordinators do not implement or advertise that endpoint.

These methods form a narrow replacement-management service on every retained
voter, independent of the general consumer data transport. A follower forwards
through the current leader for a linearizable result. The controller is not
registered as a Raft voter. The SDK defines a typed service/verified-peer port;
the embedding application may choose its authenticated protocol, but its
adapter must provide all of the following:

- Mutual authentication, integrity and confidentiality, using a verified SPIFFE
  identity in the authorized trust domain and a live rotating trust bundle.
  Enforce controller permissions for the exact cluster and slot. Never derive
  peer identity from the payload or authorize a controller because it has a
  voter SVID.
- Exact canonical byte framing, bounded requests/responses, a hard end-to-end
  deadline and rate limits. Cancellation cannot undo submitted consensus work.
  Return the distinction between no effect, committed status and unknown outcome.
- A fresh channel binding and challenge, replay-resistant proof of candidate-key
  possession, and delivery of verified facts to the service through types that
  cannot be constructed by deserializing user claims.
- A trusted time interval for attestation validity and the current authorized
  controller key/credential. Unknown or regressing time refuses new control
  authorization; it does not revoke an already committed replacement.

The loss attestation is `LostVoterAttestationV1`, a canonical bounded binary
record. Integers use unsigned big-endian fixed widths; variable strings are
UTF-8 with a `u16` byte length, no padding or trailing bytes, and at most 2,048
bytes per SPIFFE identity. The unsigned claims, in order, are:

| Claim | Encoding and meaning |
| :--- | :--- |
| Version and request | `u16 = 1`, 16-byte request ID and 32-byte request-body digest. |
| Target | 32-byte installation-qualified cluster ID, `u16` slot ordinal, `u64` expected old incarnation, 32-byte old descriptor digest. |
| Candidate | 32-byte digest of its canonical compressed P-256 public key, `u64` strictly increasing platform admission generation, length-prefixed candidate SPIFFE ID. |
| Controller | Length-prefixed authorized controller SPIFFE ID and 32-byte signing-credential SPKI digest. |
| Loss policy | `u8` reason (`1 = StorageLost`, `2 = TimeBoundLoss`), 32-byte authorized policy digest, `u64` loss-observation start and loss-decision Unix milliseconds. |
| Validity | `u64` issue and expiry Unix milliseconds, with issue < expiry and observation start <= decision <= issue. A time-bound decision must satisfy the referenced live policy's loss duration. |

Sign `openpacketcore/consensus/lost-voter-attestation/v1\0 || claims` with
ECDSA P-256/SHA-256 using the controller's current verified X.509-SVID key.
An ECDSA P-256 controller SVID is an installation prerequisite; a platform that
only issues other key types is refused during enrollment rather than on the
first replacement. SPIFFE identity alone does not establish this capability.
Encode the signature as 64-byte `r || s`, requiring canonical low-S form;
the verified credential's identity and SPKI digest must match the claims.
Reject other algorithms/versions instead of inferring them. Validate issuance
and expiration against the entire trusted time interval, and authorization
against the current platform policy. The complete frame is capped at 8 KiB.
Proof verification belongs to the trusted admission adapter; deterministic
apply validates the retained verified claims, request bindings and monotonic
selection floors, not an external clock or network call.

The shared `lost_voter_attestation_signing_input` helper emits that exact signing
message. `voter_replacement_request_digest` computes SHA-256 over the domain
`openpacketcore/consensus/replace-lost-voter-request/v1\0` followed, in order, by:
`u16 = 1`; `u64` expected table revision; expected configuration's 32-byte cluster
ID, 32-byte configuration ID and `u64` epoch; candidate `u16` slot and `u64`
incarnation, 32-byte key digest, 32-byte descriptor digest and `u64` admission
generation; then the unsigned claims above with their request-digest field
omitted. All integers are fixed-width big endian. Shared fixed vectors cover
both helpers. Signatures, challenges and transport credentials are excluded.
This avoids a circular self-digest and allows an exact retry after credential
rotation without changing the accepted request body.

The candidate has a separately generated P-256 key, durably bound to its local
state. The service on a retained voter issues a random 32-byte one-use challenge
and verifies a signature over the domain
`openpacketcore/consensus/candidate-possession/v1\0`, cluster, slot, proposed
incarnation, request digest, candidate key digest, challenge and channel
binding. Expire challenges at the request deadline and consume them once;
cross-channel or stale replies cannot bind a candidate. The controller supplies
the selected public binding and signed loss request. During `replace_lost_voter`,
the receiving voter's trusted admission adapter resolves and dials the candidate
responder, challenges it on that authenticated candidate channel, and invokes
`VoterChallengeIssuer::verify_candidate` in the same receiving-voter process.
The adapter passes the resulting opaque `VerifiedVoterCandidate` directly to
`VoterReplacementVerifier::verify`; a controller-supplied serialized witness is
not accepted. Forwarding carries the service-validated command, not a transferable
possession proof.

After Prepare, the candidate can pull its committed binding from any retained
voter by proving the same key over a new challenge; the voter performs a
linearizable lookup by cluster, slot and key digest. The candidate already
knows those fields from enrollment and need not receive a request ID from the
original controller. The challenge supplies the selected incarnation and request
digest from that lookup so the candidate can sign the complete binding. The
returned binding must match those challenged values. A lost controller reply
cannot strand it. This service is
a narrower prerequisite for #1106, not a dependency on a future general-purpose
consumer transport. Both transports must meet the same admission properties
if they share a listener.

Current credentials authorize new calls. A credential expiring or rotating
after Prepare does not invalidate its durable accepted attestation or halt the
supervisor. A currently authorized controller may resolve/retry the recorded
request without making its historical signature fresh. New claims still need
fresh authorization and a higher selection generation where required.

### Recent target traffic

Resolve retained applied results and durable provisional intents before probing
liveness. An exact retry with an unapplied Prepare returns
`ReplacementInProgress`; a returning target cannot turn that result into a
no-effect refusal while the original Prepare may still commit. Reserve the
locally owned attempt before starting the loss probe, so simultaneous retries
also report in-flight state before any Prepare is appended. Caller cancellation
or deadline expiry does not release that reservation before definitive
completion and durable reconciliation.

Use `W = 2 * DURABLE_OPENRAFT_PROFILE.election_timeout_max_millis` as the
recent-traffic window, measured independently on each survivor's monotonic
clock. Before proposing Prepare, query every reachable retained voter under
the bounded management deadline, require fresh no-recent-traffic evidence from
the surviving quorum that will acknowledge it, and reject any positive response
received from a reachable survivor with no-effect `TargetStillLive`. Recheck
each survivor's local observation immediately before its pre-dispatch fence.
Any message proving the target's incarnation key counts, even when a later
check refuses that message for another reason, including during the probe. A restarted
survivor cannot attest absence until it has observed a full W, unless it has
retained equivalent observation evidence.

If a survivor's own recheck finds recent target traffic, it refuses the entire
append carrying the intent before dispatch, without acknowledging any entry
in that append. A veto at the second recheck releases its transient gate and
engine fence after durable absence is proved. It keeps admitting the live
target. Ordinary elections can form a quorum; when the target wins a higher
term, provisional holders admit its authenticated appends and snapshots to
truncate the uncommitted Prepare, as specified above. The originating leader
retains its response fence until durable resolution, including after a crash
and reopen. Writes resume without manual gate clearing or a new request ID.

A lagging follower may hold an older unapplied Prepare while a newer operation
is already committed elsewhere. It temporarily refuses the different intent;
a commit-carrying heartbeat applies the older prefix and lets replication
continue. This is an automatic recovery path, not an operator recovery step.

The no-effect result requires proof that no Prepare for this request can
commit. A positive observation after submission returns `OutcomeUnknown` or
`ReplacementInProgress` until engine reconciliation proves no effect or finds
the committed result; it must never mislabel a possible commit as a refusal.

This check does not prove physical destruction and cannot detect traffic in
an unreachable partition. Time-bound loss remains the authorized controller's
decision under its platform policy. Once Prepare commits, the irreversible
floor wins even if the target subsequently returns. Ordinary engine timeouts
never create a loss attestation or a new incarnation.

`replace_lost_voter` reserves a durable desired operation; completion does not
depend on the lifetime of its future. After acceptance, an SDK leader supervisor
continues it automatically using only replicated state and the configured peer
resolver. Every leadership change and startup reconstructs that work. The
consumer controller watches committed status, supplies the selected process,
and retries uncertain requests exactly. Another controller instance can query
by slot and recover the operation without knowing a lost caller's request ID.
Resolver hints may change on reschedule, but an endpoint must prove the same
committed incarnation key; a hint cannot rebind authority.

Stable refusals include `UnauthorizedReplacement`, `InvalidLossEvidence`,
`StaleIncarnation`, `IdempotencyConflict`, `ReplacementInProgress`,
`NoSurvivingQuorum`, `TargetStillLive`, `ReplacementPastFence`,
`ActivationContinuationUnavailable`, `IncompatibleProfile`, `IncarnationExhausted`,
`ConfigurationEpochExhausted`, and
`FreshInstallationRequired`. Distinguish a proven no-effect rejection from
`OutcomeUnknown` after possible submission. Local observed progress is marked
non-authoritative and cannot resolve uncertainty. A status timeout is not a
reason to choose a new incarnation or clear the active operation.

If the candidate restarts with its data, resume the same phase and identity.
If it loses its data/key, never reopen that Raft ID empty. With new verified
loss/selection evidence, the controller uses the same `replace_lost_voter`
method and `expected_incarnation` naming the lost candidate. Before Fence
applies with effect, the surviving quorum can retire the candidate,
remove its learner through Openraft, and replace the same slot's pending
binding, monotonically advancing the table
floor and invalidating its old continuation. Its caller-stable new request ID,
body digest and CAS bind the active request and expected candidate. Commit the
old attempt's `Superseded` result and reserve the new attempt in the same slot;
do not mutate a request body under its original ID. It cannot clear or replace
another slot's operation. At or after Fence applied with effect, return
`ReplacementPastFence` with the active operation identity and finish that exact
joint/uniform transition using the unchanged majority; then replace the lost
successor through the ordinary next operation. Never rewrite an effective
membership in place. Capability/catch-up evidence must be reacquired for the
new key. This is automated recovery of the same slot, not permission to replace
a second slot concurrently.

## Crash and partition behavior

| Crash or interruption point | Automatic recovery and safety condition |
| :--- | :--- |
| Before Prepare reaches the log | Exact retry may submit it. No committed retirement or allocated successor is reported. |
| Prepare durable but commit unknown | Reconstruct its provisional fence; obtain engine commit/truncation evidence. Do not restore old admission on a timeout. |
| Prepare committed, reply lost | Lookup by slot returns the same Pending operation. The old floor survives and the leader supervisor continues. |
| Candidate-open or partial snapshot | Startup removes only owned incomplete staging files and retries the verified out-of-band transfer before learner addition. The candidate never votes from partial state. |
| Snapshot durable, phase reply lost | Reconcile the installed cut with the retained request and current leader; idempotently continue tail replication. |
| Caught-up marker/probe or continuation reply lost | Inspect committed evidence, revalidate live candidate possession and the current-term barrier, and continue. Never treat a probe-only result as committed evidence. |
| Coordinator gone before Fence | A new coordinator discovers by slot; the SDK supervisor proceeds without it once the selected candidate is present. Existing predecessor authority and batches continue. |
| Fence applied with effect, joint absent | Retained leader resumes `change_membership` for the exact desired set using committed learner evidence, without a live candidate barrier. Supersession is refused; candidate loss cannot delay uniform admission. The controller need not return. |
| Joint appended or committed, uniform absent | Read effective and committed engine configurations; resume the same transition. SDK voting still requires its committed gate. No rollback to the retired identity. |
| Uniform committed, Finalize absent | Reconstruct successor routing/activation from applied membership and commit idempotent Finalize. Local cleanup does not withhold serving authority. |
| Leader process lost before uniform | Re-elect when a surviving majority of each effective set is available. In a three-slot example, losing A while C is lost leaves no old majority: B and the learner cannot bypass that rule. A's automatic restart with retained data restores progress. Permanent second-voter loss exceeds this protocol. |
| Retired volume or process reappears | A typed refusal stops and quarantines its engine. Cleanup of owned files additionally requires an authenticated quorum read in the same installation showing `retired_through >= k`; one peer cannot authorize deletion. The selected replacement progresses independently, and the stale process cannot clear a fence, vote, or serve. |
| All admitted voters restart with intact volumes | Recover the same incarnations, pending phase if any, votes, log and application cuts; perform ordinary admission. No controller replacement request, new floor, or manual action. |
| No quorum during a retry | Retain the operation and refuse new authority. Resume automatically when quorum returns. Do not reinterpret missing replies as new loss evidence. |

Local cleanup is confined to the process's owned staging/channel resources.
Refusing an obsolete format or retired volume does not authorize deleting a
different incarnation's files. The controller's already selected replacement
continues on its own storage; cleanup on an absent node is not a prerequisite.

## Verification required before implementation acceptance

This RFC adds no executable behavior and reports no implementation tests as
passing. The following are acceptance obligations for subsequent implementation,
with independent adversarial review of the concrete implementation.

### Deterministic safety and storage tests

- Kill the candidate after Fence applies but before joint append, including a
  leader restart in that interval. Complete joint/uniform with the survivors,
  refuse candidate supersession with `ReplacementPastFence`, and resume scope
  mutations immediately under successor admission with unchanged authority.
  Assert that no post-Fence step waits for a candidate reply; provision its
  replacement as the next operation.
- Commit a Fence that is refused at apply for missing continuation. It must not
  record `Fenced` or prevent a valid pre-Fence candidate supersession.
- Run snapshot-first bootstrap with a never-purged log and with 1,024 retained
  entries. Observe a real verified snapshot installation into the candidate
  engine before learner addition, followed by catch-up without append-error
  retries. Repeat after leader loss during snapshot delivery.
- In Async qualification, commit and flush Prepare, crash a survivor, and
  recover all non-retired retained participants without the lost incarnation
  or the Pending/CatchingUp candidate. Assert that the retired floor and
  committed authority ranges cannot regress. Also exercise loss before Prepare
  and report the absence of a safe surviving quorum, not a successful recovery.
- Exercise `TargetStillLive` for recent authenticated target traffic seen by
  the leader or another reachable survivor, including traffic arriving during
  the replacement probe and after a survivor restart. Assert a no-effect result:
  no retirement floor, learner, or incarnation allocation. Separately exercise
  authorized time-bound loss with no such evidence and a fully isolated target.
- Hold a Prepare durably appended but uncommitted, deliver fresh target-key
  evidence only to its leader, and retry the same request. Require
  `ReplacementInProgress`, unchanged provisional state, and successful commit of
  the original Prepare after replication resumes. Also hold an earlier accepted
  peer call while Prepare drains it: a retry must report in-flight state even
  before an intent exists in the log. Cover both stores.
- Let the loss probe pass, then deliver target-key-proven traffic to a survivor
  before its pre-dispatch recheck. It must refuse the whole intent append without
  acknowledgement or a new gate. Elect an ordinary leader, truncate the
  uncommitted Prepare and resume writes automatically. Include traffic refused
  later for another reason so a rejected request still establishes liveness.
- Verify the control-attestation golden bytes, signature domain, P-256 key and
  signature canonicality, slot authorization, expiration, admission generation,
  request digest, replay, and candidate challenge/channel binding. Kill the
  controller after Prepare but before delivery; the candidate must pull its
  binding by proving its own key to a retained voter.
- Reject a stale-term or log-conflicting Prepare append before persistence and
  release only its transient gate. Race a second provisional intent for another
  slot; it cannot fence that slot. Replace the uncommitted intent by a snapshot
  past its index, both with and without the reservation, and reconcile its gate.
- For each activation family below, test its explicit continuation or refusal
  policy. Lose a voter during the initial activation probe and during its commit
  reply. Replacement either observes the committed activation and carries it
  forward, or completes unactivated; it cannot guess which case occurred.
- Rotate the controller credential and platform trust bundle during an accepted
  replacement. Completion and authorized exact retries continue without a
  reinstall. A newly revoked credential cannot authorize a new operation.
- Verify that a single peer's retirement refusal can quarantine an old process
  but cannot delete its files; an exact same-installation quorum read authorizes
  only owned-resource cleanup. Reject other formats before identity comparison
  with the named fresh-installation error in each store.
- Qualify capability advertisement independently by store and persistence mode.
  An incomplete or unqualified profile, including the durable record foundation
  alone, advertises no replacement capability even when another store/profile
  is qualified.
- Model `C0`, candidate learner, joint `C0 && C1`, and uniform `C1`, including
  message delay, duplicate/reordered replies, crashes, log truncation, and
  snapshots. Assert no duplicate logical vote, no old-floor resurrection, no
  election/commit using the learner before admission, and no two accepted
  replacements. Include a lagging minority that never saw Prepare.
- Test the exact retirement append/ack/commit/apply gaps: high-term old votes,
  old leader heartbeats/appends, snapshot final chunks, and cached old replies
  paused before admission or publication. Assert no forbidden term change,
  timer reset, accepted log, snapshot publication, or replication accounting.
  Test provisional-intent truncation and CAS rejection without clearing any
  newer or committed fence. Include startup before apply replay completes.
- Cross every RPC family with current, retired, unknown-higher, Pending, and
  CatchingUp identities; vary source, destination, inner candidate/leader ID,
  cluster installation, configuration, SVID, incarnation key, and channel.
  Test a reused SVID with both valid old credentials and a forged `k+1` field.
  Until PreVote exists, its unknown wire form must fail closed; any addition
  must pass the same voting matrix before use.
- Show that effective-but-uncommitted joint membership never enables the
  candidate's self-vote, automatic campaign, explicit campaign, or Vote reply.
  After committed joint plus local durable application, show normal voting.
  Verify both quorum denominators throughout, for each supported HA size.
- Cover snapshot floor regression/omission, altered candidate keys, torn install,
  compacted Prepare, stale backup, ordinal/incarnation overflow, foreign format,
  and a new installation with the same display name. Repeat across configuration
  storage and each session backend/persistence profile, including delayed Async
  disk writes and crash at every strict control barrier.
- Race replacement with initial activation, scope continuation, a different
  membership request, duplicate request IDs, and a second replacement. Verify
  exact no-effect versus uncertain outcomes and bounded receipt/floor storage.
- Exercise candidate data loss before joint and after joint, controller loss,
  and changed endpoints with the same retained key. No test repairs state by
  editing a table, removing a latch, forcing membership, or wiping a survivor.
- Hold candidate progress across repeated request deadlines while exercising
  active scopes and batches before Fence. Verify unchanged untimed authority,
  admission and child-birth floors, continued installed forwarding, and no
  unsolicited scope closure or session deletion. A voluntary consumer rollout
  must still obey its emergency-session hold. Resume a lagging retained voter
  when the replacement is leader, including after snapshot compaction.

### Real three-process quorum proof

Extend the existing process harness in
[scope-authority process tests](../../crates/opc-session-store/tests/consensus_openraft/scope_authority/process_quorum.rs)
and the scope-continuation membership tests. Each voter is an OS process with its
own disk-backed data directory and real transport. Add equivalent configuration
coverage through the configuration consensus adapter; an in-memory session-only
demonstration does not satisfy this issue. Cover real mTLS separately to prove
that repeated SVIDs cannot cross incarnation bindings.

1. Form A, B, C. In one run, lose C's volume before any feature/scope activation
   certificate; in another, keep active scope authority and child writes. Also
   lose the preferred genesis initiator before formation, retaining the exact
   enrolled manifest and the other genesis volumes.
2. Keep a test copy of the retired disk and credentials solely for hostile
   reappearance. Kill C and remove its live volume. A fake platform controller
   supplies synthetic verified loss/selection evidence and automatically
   provisions an empty replacement for the **same slot and SVID**.
3. Keep issuing writes and linearizable reads through the healthy voters.
   Retain a history of acknowledgements and exact retries. Hold the candidate
   in Pending and CatchingUp, proving those states issue no vote and active
   authority and batches still work. Verify a real snapshot installed before tail
   catch-up and that committed strict writes survive on the new member.
4. At each retained phase boundary, kill/restart the external coordinator.
   Separately crash/restart a leader with its disk intact, using the existing
   `set_automatic_election_for_test(false)` and `trigger_election_for_test()`
   hooks to select campaigns, as #1134 does. Let Openraft create and persist
   every vote. These tests qualify replacement across an election, not natural
   election timing. Restart a lost survivor before expecting an old majority.
5. Restart saved old C, with its valid old SVID and key, at four dangerous
   points: Prepare appended before commit, Pending, CatchingUp, and joint
   effective before uniform. Use both a reused endpoint and a separate endpoint.
   Send high-term votes, heartbeats, appends and a final snapshot chunk, and
   fields claiming the successor incarnation. On fenced A and B assert no
   change to term, election timer, vote, match index or commit index. In the
   pre-commit run, hold the append acknowledgement after installing its gate;
   unfenced peers have not yet acquired the retirement guarantee. Complete
   uniform without help from C and repeat the attacks after uniform, compaction,
   leader change, and all current voters restarting.
6. Verify one logical slot advanced, the logical size and quorum denominator
   are unchanged, and only the successor may vote. Assert no acknowledged
   strict write disappeared or forked. Scope incarnation, admission-generation
   and child-birth floors persist; batches continue after cutover under the same
   authority without unanimous reactivation.
   Repeat a replacement of that slot to prove transitive permanent retirement.
7. Stop all current voters and start them with their data. Assert health with
   no replacement calls and unchanged incarnations. Separately deny a new
   replacement with no surviving quorum, then restore connectivity and observe
   automatic exact retry, without state surgery.

Bound each process phase and whole test with hang guards; retain the original
timeout as a failure if it expires. Record the exact source revision, profile,
command, exit status, and log for every qualifying run. Reuse worktree-local
build caches. Run focused tests while implementing, then the repository's
required final gates and fully green remote CI on the integration candidate.
Neither a design review nor a process smoke test replaces those gates.

## Review and implementation boundaries

The independent design review must challenge, in particular, retirement before
commit acknowledgement, reuse of SVIDs/keys, candidate self-voting under
effective membership, lost canonical genesis, Async strict-barrier recovery,
and untimed scope authority across coordinator crashes. An unresolved safety
obligation blocks enabling the feature; it cannot become an operational repair
step.

After approval, implementation can be divided into shared identity/codec and
durable records; admission barriers and fixed-membership coordination in both
stores; bootstrap and activation-continuity integration; and process/fault
qualification. Intermediate code must not advertise replacement capability.
The capability key is `(store domain, persistence mode, incarnation profile)`.
Enable it only after that key's identity, storage, transport, coordinator,
activation rules, unattended recovery and adversarial process proof pass their
gates. Durable session and Durable configuration can qualify independently;
Async remains disabled until its own recovery proof passes. A qualified store
must still return the explicit refusal for an unsupported activation-family
combination. No key inherits another store's or mode's qualification.
