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

`DURABLE_CONSENSUS_TIMING_PROFILE` is the sole timing authority for both
durable domains: AppendEntries/Openraft read-index 2,000 ms, heartbeat interval
200 ms, Vote and PreVote 5,000 ms, elections `[5,000 ms, 6,500 ms)`,
InstallSnapshot/forwarded mutation/consumer ReadBarrier and operation default
10,000 ms, and listener idle/handler ceilings 30,000 ms. The 1,500 ms
DNS/TCP/mTLS/bootstrap cold cap is contained inside the selected family
deadline, never added to it. The heartbeat interval is not a call deadline:
every AppendEntries, heartbeats included, uses the 2,000 ms ceiling, and the
shared Openraft configuration enables Pre-Vote.

### Unplanned leader loss

Planned shutdown hands leadership off before the leader stops. An unplanned
loss (a crash, a node failure, or a partition) is detected only by the
election timers of the surviving voters. The pinned engine applies these
rules:

- a voter leases a committed leader's vote for `election_timeout_min`, and
  rejects every candidate during that lease; a leader rejects every candidate
  while a quorum acknowledged it within the same lease;
- a follower campaigns once the longer of the lease and its sampled election
  timeout has passed since its last leader contact, never their sum; every
  sampled timeout covers the lease, so campaigns stay randomized;
- before it raises its term, a voter asks the others in a Pre-Vote round
  whether they would grant it a vote, and campaigns only if a quorum would;
- the engine checks election timers, and sends idle heartbeats, only on a tick
  of `heartbeat * 3 / 2` (300 ms).

The profile helpers expose the resulting bounds, measured from the leader
loss:

| Bound | Formula | Value |
|:---|:---|---:|
| `leader_loss_first_campaign_bound` | `election_timeout_max + tick` | 6,800 ms |
| `unplanned_leader_loss_write_stall` | first campaign `+ 6 * heartbeat + grace + cold connect` | 9,700 ms |

The survivor that heard from the leader last is the last to campaign; by then
every other survivor's lease has expired, so its Pre-Vote and vote are
granted. The write stall adds six round trips, each answered within one
heartbeat interval (Pre-Vote, vote, the successor's first commit, the forwarded
write, the successor's linearizable admission round and the write's own
commit), the one-heartbeat stale-route grace below, and one new connection to
the successor. Profile validation requires that stall to stay below the
operation timeout. A write in flight when the leader is lost, submitted through
a surviving voter and retried only through its own exact request identity after
an ambiguous or unavailable attempt, therefore reaches its committed outcome
within one 10,000 ms operation. The bounds assume:

- a reachable majority of voters whose processes are not suspended or
  CPU-throttled;
- every round trip, disk sync included, completing within one heartbeat
  interval, and every new connection within the cold-connect allowance;
- no split vote. Two survivors that both pass Pre-Vote at the same moment can
  still split one term; that is improbable because every campaign samples a
  fresh timeout, and it adds at most one further election timeout and tick.

A crashed leader refuses the stale attempt at once. A failed node or a
partition can instead black-hole an established connection, so the session
store bounds every leader-routed call (forwarded writes, read barriers, exact
V2 status tickets, capability activation and expiry preflight) by its own
leader view: once its engine names a different leader, a call still unanswered
after one heartbeat interval is abandoned and reported as possibly transmitted,
and the route moves to the successor. The configuration store's routes are not
yet bounded this way: behind a black-holed lost leader, a configuration write
or read waits for its own operation deadline.

The same timers decide when a healthy cluster elects spuriously. A voter
campaigns only after 5,000 ms (`election_timeout_min`) without any
AppendEntries from its leader, that is, after more than sixteen missed 300 ms
ticks; one slow AppendEntries, bounded by the 2,000 ms ceiling, never expires
the lease. Voters therefore need CPU that is never throttled or suspended for
longer than that window. Run voters with guaranteed CPU: either no CPU limit,
or a limit equal to the request with an integer number of cores. CFS quota
exhaustion, a stopped container, or storage that blocks the engine for seconds
can still depose a healthy leader. The election itself remains safe; in-flight
writes on the old leader then end ambiguous and must be resolved through their
exact request identity.

Pre-Vote keeps a voter that cannot win from raising its term. A voter cut off
from the others, or restarted while cut off, keeps its term and rejoins as a
follower without deposing the leader; a voter that can still send but no
longer receives is refused by the other voters' leases and the leader's
quorum-acknowledged lease. The engine has no check-quorum step-down: a minority
leader keeps its role but cannot commit, linearizable reads and admission
rounds fail closed as unavailable, and a write already proposed there ends at
its operation deadline as ambiguous, to be resolved through its exact request
identity.

`DURABLE_OPENRAFT_PROPOSAL_ADMISSION_SLOTS` fixes both durable adapters at
eight concurrent proposal paths. Admission is obtained inside the original
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

The appended `PreVote` RPC family carries the engine's Pre-Vote round. Its
payload and deadline are the Vote family's. It is admitted exactly like a Vote
and never changes engine state; a refused, failed or timed-out PreVote call is
never counted as a grant.

New leaders can use `open_leader(projection, deadline)` with a
`LeaderReadProjection` implementation. The helper executes the barrier,
drives the consumer-owned projection to Openraft's applied log ID, independently
waits for the projection watch to match that exact ID, and rechecks the same
leader term before returning `LeaderOpenAdmit`. Advertising the node as a read
target is a consumer responsibility and must occur only after that success.
Openraft still supplies every quorum, leadership, term, commit, and apply
signal; these helpers are scheduling and gating, not a parallel authority.

## Interim source-build gate

Issue #143 remains open and the HA profile remains experimental. The workspace
pins `https://github.com/openpacketcore/openraft` at the full verified revision
`38c6524a405a55e2d6808b136329ff62ba4e492d` (0.9.25 plus fork fixes). It retains the
per-campaign election-timeout fix and preserves a recovering snapshot target's
required log suffix through successful handoff, while failed targets release
their ownership before retrying. When a higher vote ends leadership, the core
joins the former leader's replication readers before a conflicting suffix can
be truncated. Strict storage errors and operation deadlines stay unchanged.
The candidate also includes bounded apply dispatch, joined replication task
retirement, obsolete campaign cleanup and cancellable pacing of append retries
that acknowledge no progress. A follower campaigns after the longer of its
leader lease and its sampled election timeout, AppendEntries has its own
deadline, an optional Pre-Vote round keeps a voter that cannot win from raising
its term, and a leader rejects other candidates while a quorum acknowledges it.
Bounded apply is opt-in; this dependency update does not select a new SDK
runtime limit. The pin is by `rev`, never a branch or tag.
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
