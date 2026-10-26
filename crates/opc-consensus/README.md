# opc-consensus

`opc-consensus` is the shared consensus substrate for OpenPacketCore SDK
durable state machines. It exact-pins and re-exports the SDK's supported
Openraft engine and owns stable cluster, configuration, node, request, digest,
codec, and authenticated transport identities.

Consumers retain their own deterministic state-machine commands, durable
storage adapter, and domain errors. They must use this crate for election,
term, vote, replication, commit, membership, linearizable-read, and snapshot
authority instead of implementing a parallel quorum algorithm.

Session payload encryption remains outside this layer. The session-store
composition seals payloads before they enter consensus, so this crate never
receives plaintext session payloads, HKMS/KMS provider handles, or encryption
key material. This is payload-envelope protection; filesystem and database
metadata confidentiality requires a separately qualified storage or volume
encryption layer.

The public SDK boundary is intentionally small. Openraft is exposed only
through `opc_consensus::engine`, allowing every production consensus consumer
to share one exact engine version while keeping Openraft details out of
domain-facing wire and storage APIs.

## Voter slot formats and admission

`voter_slots` provides the shared data formats for [RFC 023](../../docs/rfc/023-voter-slot-incarnations.md).
`SlotId` and `VoterIncarnation` validate their bounds before mapping to the
injective engine ID `((incarnation - 1) << 16) | slot`. A fixed installation uses
`ConsensusClusterId::for_installation` with a fresh enrollment nonce. The dynamic
profile's existing node-ID derivation is unchanged.

`encode_voter_slot_table` and `decode_voter_slot_table` use exact `OPVI`, version
1 framing with fixed-width big-endian integers. Slot/member counts use `u8`;
variable byte/string lengths use `u16`; options have only the tags `0` and `1`.
Slots and configuration members are strictly ordered by slot ordinal. The table
is capped at 64 KiB and nine slots; loss attestations at 8 KiB, each workload
identity at 2,048 bytes, and each snapshot ID at 256 bytes. Unknown table formats
return `VoterSlotError::FreshInstallationRequired`; crossing a stored-format
boundary requires a fresh install, with no migration or compatibility reader.
Unrecognized magic bytes instead return `InvalidRecord`.

Records retain permanent retirement floors, public incarnation bindings, one
active replacement, exact predecessor/successor configurations, full engine log
IDs, the initial installed snapshot ID/digest/cut, and one terminal receipt per
slot. Log IDs contain only term and index under the pinned engine's
`single-term-leader` profile. `validate_successor_of` rejects snapshot regressions against retained local
metadata, including changes to an existing incarnation key, accepted operation
or terminal receipt, and loss of phase evidence. Before Fence, a new leader may
advance the catch-up marker; after Fence it stays fixed. Fence cannot disappear
into a supersession.

The Durable profile adds deterministic `VoterSlotControl` transitions and a
`VoterSlotDurableState` whose provisional intent names its exact retained Prepare
entry. Both store adapters publish those records atomically with log/apply and
snapshot state. `VoterAdmission` drains old peer calls, installs the serialized
engine response fence and restores required fences before startup admission.
Owned calls survive observer cancellation; obsolete lock entries and fence
receipts are released after the engine drops the retired identity. Durable
retirement floors continue rejecting every older incarnation.

A decoded loss attestation remains untrusted data. `VoterChallengeIssuer` and
`VoterReplacementVerifier` check fresh channel-bound P-256 possession, canonical
low-S signatures, current controller permission and trusted time. The receiving
voter's trusted adapter challenges the candidate and consumes its opaque proof
in the same process. `VoterTransport` requires exact incarnation bindings in
both directions and records proved key traffic before later admission refusal.
Only the coordinator decides `TargetStillLive`; no timeout starts a replacement.

These APIs support the unadvertised store integration. Lost-canonical bootstrap,
activation continuity and adversarial process qualification remain later RFC
slices. Management framing and TLS adapters consume these helpers separately.
No store or persistence mode advertises replacement capability from these types.

Controllers and admission adapters share `lost_voter_attestation_signing_input`
and `voter_replacement_request_digest` for the RFC's exact signing bytes and
body digest. Fixed vectors pin both. Neither helper authenticates its input or
verifies a signature. Controller enrollment requires an ECDSA P-256 SVID.
Async support will require a new record version and a fresh install.

## Shared timing and admission

`DURABLE_CONSENSUS_TIMING_PROFILE` is the sole timing authority for both
durable domains: AppendEntries/Openraft read-index and heartbeat 2,000 ms,
Vote/Pre-Vote 5,000 ms, elections `[5,000 ms, 8,000 ms)`, InstallSnapshot/forwarded
mutation/consumer ReadBarrier and operation default 10,000 ms, and listener
idle/handler ceilings 30,000 ms. The 1,500 ms DNS/TCP/mTLS/bootstrap cold cap is
contained inside the selected family deadline, never added to it.

`DURABLE_CONSENSUS_STALE_LEADER_ROUTE_GRACE` (one heartbeat, 2 s) bounds an outstanding
leader-routed configuration-consensus call after this replica's own engine has
named a successor for the attempted leader. The unanswered call is abandoned and
re-offered through the observed successor, so a black-holed former leader cannot
hold a client write for the complete operation deadline. This is a
route-retirement bound, not an election, heartbeat or forwarded-mutation budget
change: without an observed successor the existing complete-operation deadline
and its typed ambiguous outcome still apply. A forwarded mutation that was
transmitted and then abandoned is classified as possibly transmitted; retries
reuse the same request identity so the state machine idempotency contract keeps
the operation exactly-once. A route this replica has already superseded is not
transmitted. The first observed retirement deadline remains fixed across unknown
or changing successor views. A peer redirect is selected under the local view
at that time; that unchanged view cannot retire the redirected route.

Openraft owns elections, votes and leader authority (ADR 0019). Engine-level
quorum-loss and unplanned-failover improvements remain tracked by #1048 and
#1037. `DURABLE_CONSENSUS_FAILOVER_PATIENCE` derives the combined election lease
and route grace (10 s); it does not trigger an SDK election watchdog or promise
an election completion bound.

`DURABLE_OPENRAFT_PROPOSAL_ADMISSION_SLOTS` fixes the ordinary proposal baseline
at eight concurrent paths. The scope-aware session adapter adds five independent
class-reserved credits above that pool, for thirteen concurrent proposals in
total; other adapters retain the shared baseline. Admission is obtained inside the original
operation deadline. Once `client_write_ff` returns an accepted-result
receiver, a detached supervisor retains that permit until Openraft resolves
the exact proposal, even if the caller disconnects, times out, or is cancelled.
This bounds accepted and pre-accept work without adding a second sequencing or
commit authority.

`EnsureLinearizableSupervisor` admits every fresh read-index or mutation
preflight through exactly one supervisor-owned Openraft check per node and at
most 64 total callers across the active and waiting cohorts. Callers collected
before dispatch may share that exact result; later callers await a subsequent
check under their original deadlines. Once dispatched, caller cancellation or
timeout cannot cancel the check or start an overlapping one.

`LinearizableReadBarrier` is the reusable local-snapshot gate over that
supervisor. A successful `admit(deadline)` waits for the caller-supplied
Openraft metrics watch to report `last_applied >= read_log_id.index` before it
returns `LinearizableReadAdmit`. A deposed node receives the typed
`LinearizableReadBarrierError::NotLeader`; lost quorum, a closed apply watch,
or an expired deadline returns the typed fail-closed `Unavailable`. A consumer
that obtains a barrier from a remote leader uses `wait_for_applied_index` on
its own barrier before reading local state.

The optional `LinearizableReadLease::Enabled` mode reuses a prior successful
Openraft quorum proof only while Openraft still reports the same local leader
and term. Its fixed maximum lifetime is derived from the smaller of the shared
heartbeat interval and read-barrier deadline, remains below the minimum
election timeout, and starts no later than dispatch of the proving round so
delayed task scheduling cannot extend it. The default is `Disabled`, which
retains a fresh coalesced quorum round for every barrier cohort; consumers
cannot supply a lease duration.

Before releasing an engine vote lease for planned retirement, call
`disable_lease_reuse()` on every applicable barrier. The veto is permanent for
that barrier and all its clones: an in-flight proof cannot repopulate the cache
or return a cached admission after the veto. Fresh engine checks retain their
normal authority and deadline requirements. Clearing a cache once is not an
equivalent retirement fence.

The appended `LeadershipTransfer` RPC family carries only an engine-issued
handoff request. Its payload limit is 1,024 bytes and its deadline uses the
existing five-second Vote budget. Consumers must authenticate the exact sender,
vote issuer and membership scope before passing the request to the engine.
This family does not replace ordinary election, quorum or applied-prefix checks.

New leaders can use `open_leader(projection, deadline)` with a
`LeaderReadProjection` implementation. The helper executes the barrier,
drives the consumer-owned projection to Openraft's applied log ID, independently
waits for the projection watch to match that exact ID, and rechecks the same
leader term before returning `LeaderOpenAdmit`. Advertising the node as a read
target is a consumer responsibility and must occur only after that success.
Openraft still supplies every quorum, leadership, term, commit, and apply
signal; these helpers are scheduling and gating, not a parallel authority.

## Deterministic election fixtures

Election regression tests control raw RNG samples and delivery of actual
Pre-Vote and Vote RPCs while the production engine performs automatic campaigns.
Their protocol bounds include the committed-vote lease, sampled timeout, and
election evaluation at intervals of at most 100 ms.
The one-split schedule verifies both survivors retain `[41, 42]`; it is not a
fixed failover guarantee for randomized elections, which can split repeatedly.
Separate three- and five-voter regressions stop the leader during sustained
pipelined writes, with outstanding writes and divergent survivor logs at the
fault. They require fresh quorum authority, a new write and survivor
reconciliation within 26 seconds, preserving acknowledged writes. These paused
engine regressions do not qualify process scheduling or disk latency.
The `dangerous-test-hooks` feature exposes a scoped Tokio runtime adapter for
these fixtures. Outside a script it uses Tokio's ordinary RNG, and production
dependencies do not enable this feature. It uses the engine's existing rand 0.8
version so scripted samples pass through the same range sampler.

## Interim source-build gate

Issue #143 remains open and the HA profile remains experimental. The workspace
pins `https://github.com/openpacketcore/openraft` at the full revision
`2e1fb7455752455a3505b354d003d6effa55985d` (0.9.25 plus fork fixes). The fork adds a distinct,
authenticated Pre-Vote inquiry before ordinary elections and evaluates election
deadlines at intervals of at most 100 ms. Speculative grants do not change the
recipient's term, vote, lease timestamp or durable state. A majority of inquiries
starts the existing persisted-vote election, including both majorities for joint
membership. The 26-second and 30-second acceptance budgets are unchanged;
repeated failed campaigns can still exhaust them. Planned exact-vote handoff
retains its existing election path.

During a mixed-version roll, an eligible legacy voter can send ordinary votes
while being unable to answer Pre-Vote. When that voter's shorter log is refused,
the upgraded engine can start an ordinary election after one bounded inquiry
round, above the observed actual candidate term. It still persists its self-vote
and obtains real quorum grants. A heartbeat, vote, log or membership change,
retirement, or a fence for that peer discards the volatile observation. An
unanswered inquiry alone does not trigger this fallback, and adapters never
translate Pre-Vote into Vote. Upgrade and downgrade require no separate
activation setting; compatibility is exercised against the actual preceding
fork with divergent stored logs and leader loss.

The fork also retains the per-campaign election-timeout fix and preserves a recovering snapshot target's
required log suffix through successful handoff, while failed targets release
their ownership before retrying. When a higher vote ends leadership, the core
joins the former leader's replication readers before a conflicting suffix can
be truncated. Strict storage errors and operation deadlines stay unchanged.
The candidate also includes bounded apply dispatch, joined replication task
retirement, obsolete campaign cleanup and cancellable pacing of append retries
that acknowledge no progress. Bounded apply is opt-in; this dependency update
does not select a new SDK runtime limit. The pin is by `rev`, never a branch or tag.
The frozen HA profiles retain their original revision and evidence; they do
not qualify this later source-build candidate.

Crates that contain this engine or have a transitive normal dependency path to
it are source-build only: `opc-alarm`, `opc-alarm-k8s`, `opc-alarm-testkit`,
`opc-alarm-yang`, `opc-amf-lite`, `opc-amf-lite-testkit`, `opc-config-bus`,
`opc-consensus`, `opc-gnmi-server`, `opc-ipsec-lb`, `opc-mgmt-authz`,
`opc-mgmt-transport`, `opc-netconf-server`, `opc-persist`, `opc-runtime`,
`opc-sa-mirror`, `opc-sbi`, `opc-sdk`, `opc-sdk-integration`,
`opc-session-cache`, `opc-session-net`, `opc-session-store`,
`opc-session-testkit`, `operator-controller`, `operator-lifecycle`, and
`operator-lifecycle-cli`. This exact 26-crate closure is mechanically checked;
the other 51 workspace crates are unaffected. Exact-name crates.io searches on
2026-07-13 found none of the 26. Cargo/git CNF consumers remain supported;
crates.io publication is disabled because a published manifest cannot preserve
the fork revision.

Remove this gate only after an official stable Openraft release contains the
fix, the workspace uses a registry pin and checksum, and the full issue #143
qualification is rerun. Changing the consensus engine does not move payload
sealing or key ownership: session and configuration ciphertext boundaries,
HKMS/KMS provider handles, and at-rest encryption responsibilities remain
outside Openraft exactly as described above.
