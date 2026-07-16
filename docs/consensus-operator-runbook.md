# OpenPacketCore Consensus Operator Runbook

This runbook covers the Openraft-backed configuration store in `opc-persist`,
including bootstrap, readiness, legacy migration, failure handling, backup,
and rollback. It describes SDK mechanisms; a product operator must supply the
deployment controller, authenticated shared transport, alarms, and release
qualification.

## 1. Authority and security boundaries

There is one distributed authority:

```text
application -> HKMS-backed encryption -> ConsensusConfigStore
            -> Openraft -> SQLite and Openraft snapshots
```

| Responsibility | Owner |
|:---|:---|
| Authorization, validation, plaintext handling, HKMS/provider calls, and config encryption | Application/config protection layer |
| AEAD-envelope/AAD admission, audit redaction/finalization, deterministic config apply, and durable request outcomes | `opc-persist` config adapter |
| Election, term/vote, log matching, quorum commit, membership, linearizable reads, compaction, and snapshot lineage | Openraft through `opc-consensus` |
| Vote/log/application/membership/outcome rows and snapshot files | Per-node SQLite/Openraft storage adapter |
| Production mTLS, bounded network framing, live peer authentication, and credential lifecycle | Shared `opc-session-net` transport and CNF composition |

Openraft persists and replicates sealed ciphertext and redacted finalized audit
content. It must never receive plaintext, an HKMS/KMS provider, a provider or
key handle, or raw key material. Provider failure blocks protection of a new
plaintext write before proposal; it must not be worked around by sending
plaintext into consensus.

`opc-persist` no longer supplies a private TCP peer, TCP server, or node
process. Do not deploy an old config consensus listener beside Openraft, and
do not place a custom majority writer in front of or behind
`ConsensusConfigStore`.

### 1.1 Interim source-build release boundary

The session and configuration adapters use one fixed runtime profile from
`opc-consensus`; operators cannot tune either domain onto a different election
or heartbeat regime. This workspace revision exact-pins
`https://github.com/openpacketcore/openraft` at
`f607e636406b16bd0ad7925dbb631da1b7a4cd96` so every election campaign samples
a fresh timeout. Confirm the lock resolves only `openraft` and
`openraft-macros` 0.9.24 from that full revision. Do not substitute registry
0.9.24, a branch, a tag, or a downstream partial patch.

This is an interim source-build profile. The 26 workspace crates in the
machine-readable `source_build_gate.affected_workspace_crates` closure must
remain `publish = false`; build the SDK/CNF from the locked git workspace. The
gate may be removed only after an official stable Openraft release contains the
fix, the workspace uses an exact registry pin/checksum, and the complete #143
qualification is rerun. A source-build artifact is not production HA evidence:
the profile remains experimental and must not bypass the product's release
approval.

An Openraft source change does not change the protection boundary above.
Payload envelopes and AAD remain stable; HKMS/KMS provider calls, handles, and
raw keys remain outside consensus. At-rest metadata/database protection remains
the responsibility of the separately qualified storage or volume layer.

## 2. New-cluster bootstrap

### 2.1 Prepare immutable identity and storage

Before starting any member:

1. Choose one cluster ID, configuration ID, and positive configuration epoch.
   Configure the exact same values on every member.
2. Assign each member a stable, positive consensus node ID. Do not derive the
   ID from a transient address or pod ordering.
3. Configure either the explicit singleton profile or an odd voter set of 3,
   5, 7, or 9 nodes. Every node's topology must include itself.
4. Give every node exactly one authenticated `ConsensusPeer` route for each
   configured remote voter, and no extra route. Peer IDs must match the
   topology.
5. Provision a durable SQLite path and a private `0700`, non-symlink snapshot
   directory on the same durable device. Supply the same non-zero audit key and
   explicit audit-key rotation epoch on every voter; the non-secret
   epoch/fingerprint is part of durable and peer compatibility.
6. Configure the shared production mTLS transport. Bind the certificate's live
   peer identity to the same cluster/configuration/epoch and stable node IDs
   used by consensus. A successful socket bind is not cluster readiness.

A normal open is appropriate only for a pristine database or a database
already claimed by the same Openraft identity. A nonempty legacy database must
follow Section 4.

### 2.2 Start and admit the cluster

For each node:

1. Construct `ConfigConsensusTopology` and call `ConsensusConfigStore::open`
   (or `open_with_operation_timeout`).
2. Install `ConsensusConfigStore::rpc_handler()` on the authenticated shared
   consensus listener before cluster initialization.
3. Make all configured peer routes reachable.
4. Call `initialize_cluster()` on every node. Concurrent calls are supported.
   On clean first formation only the canonical lowest stable node ID invokes
   Openraft initialization; other pristine nodes wait for its exact membership
   to replicate. Nodes reopening persisted Openraft state skip bootstrap and
   re-admit normally, including a noncanonical persistent majority. Clean
   first formation fails closed if the canonical node is absent; do not
   designate a substitute initializer under the same topology epoch.
5. Keep the node out of traffic readiness until
   `probe_durable_readiness()` succeeds.

`initialize_cluster` and every operation fail closed if durable identity,
peer coverage, membership, or engine state does not match. Do not repair an
identity mismatch by editing SQLite rows.

### 2.3 Readiness and operation deadlines

The default complete config operation timeout is 10 seconds. An override must
be greater than zero and no more than 60 seconds. It bounds leader discovery
and routing, the linearizable barrier, quorum commitment, and local apply.
Each forwarded mutation/read barrier carries the remaining caller budget, and
the receiver uses the lesser of that remainder and its local cap. A route or
receiver never starts a fresh full operation timeout. Each shared transport
call also has its transport-owned complete deadline within that operation.

The production transport profile is fixed, not operator-tunable:

- AppendEntries and Openraft read-index confirmation: 2 seconds;
- Vote: 5 seconds;
- InstallSnapshot, forwarded mutation, and consumer ReadBarrier: 10 seconds;
- election timeout: freshly sampled from `[5 seconds, 8 seconds)`; and
- server frame-idle and handler ceilings: 30 seconds.

For an initial or replacement connection, DNS, TCP, mTLS, identity admission,
and bootstrap have a 1.5-second sub-bound inside the already-running family
deadline. It is never an additional allowance. A healthy directed peer reuses
a fixed primary/overflow pool of at most two authenticated connections, with
one in-flight RPC per lane. Sequential calls prefer primary, a concurrent call
may use overflow, and further calls wait for lane acquisition inside the same
family deadline. A lane is reusable only after a complete, correlated,
authenticated, validated success or typed semantic `Unavailable` response; the
latter preserves a known stream position but grants no success or authority.
Cancellation, timeout, EOF, protocol, authentication, scope mismatch,
rejection, lifecycle evidence mismatch, or any uncertain stream position
forces that lane to reconnect.

Use only `probe_durable_readiness` for traffic admission. The probe exercises
Openraft's linearizable path and current admitted membership. These are not
readiness evidence:

- listener bind or successful TLS configuration;
- a cached capability report;
- presence of a leader in a stale observation;
- a local SQLite read; or
- a successful standalone preflight from before the authority claim.

`status()` is a redaction-safe observation containing node, term, leader,
independently persisted committed index, applied index, non-secret audit-key
epoch/fingerprint, and admission state. Use it for routing and
diagnostics, but keep readiness gated by the fresh probe.

## 3. Normal write and response-loss handling

The application encrypts through `EncryptingManagedDatastore`. A successful
`opc-crypto` operation mints a one-shot claim bound to the exact ciphertext and
plaintext digest. The persistence adapter consumes that claim, validates the
canonical envelope/AAD, tokenizes YANG predicate values, redacts audit values,
and finalizes the audit chain. Raw ciphertext cannot enter the consensus append
API, and the claim/provider/key handle is gone before Openraft serialization.

Normal trait mutations derive a stable request ID from their durable operation
identity; explicit idempotent methods accept a caller-retained ID. The most
recent 4,096 outcomes are retained. If a response is lost, retry the same
logical operation/ID within that finite horizon or perform a fresh authoritative
read. Reusing a retained request ID for different content fails closed.
It returns the stable `PersistErrorKind::RequestIdCollision`, never the
original successful result or an ordinary config-version conflict. The
original request/payload pair remains retryable while its outcome is retained;
after expiry, recover through a fresh authoritative read rather than assuming
the old response is still cached.

At the config-bus boundary, loss of acknowledgement after durable admission is
reported as `OutcomeUnknown` and raises the recovery fence. gNMI maps that code
to `FAILED_PRECONDITION` rather than retryable `UNAVAILABLE`; NETCONF returns an
application `operation-failed`. In either transport, reconcile with the exact
original request ID (`ConfigBus::resolve_request_id`) or resubmit the exact
original operation with its idempotency key before retrying anything else. A
changed mode, candidate, confirmation timeout, rollback selector,
caller-asserted base-version precondition, or caller context is rejected as a
collision. The fenced bus admits that exact keyed
replay only as a read-only result lookup; it remains fenced and keeps serving
its prior snapshot until rebuilt from the authoritative store. A slow append
that later proves committed remains success even if the caller's local deadline elapsed,
and failure to clear the post-publication recovery marker does not rewrite that
durable success as failure; it fences later writes and requires recovery.

The shared config-bus adapter and atomic named rollback points advance both the
config command and config-specific RPC payload revisions to 3. Drain config
writers, stop every config-consensus member, upgrade the complete voter set,
and restart it as one coordinated operation. Cross-revision paths in a rolling
deployment of mixed
revision-1/revision-2/revision-3 binaries fail closed at the exact formation
probe or RPC revision check before a revision-3 node admits writes; there is no
wire downgrade. Do not rely on that rejection to drain an already-running older
majority. Existing revision-1 and revision-2 persisted commands remain
replayable with their original semantics, but neither older revision may claim
the inline named-rollback behavior. Revision-1 commands carrying either
revision-2 atomic intent remain rejected as corrupt state.

After the Openraft authority marker exists, direct mutation through
`SqliteBackend` is fenced, including through clones freshly opened or retained
around the claim. The safe API exposes no raw SQLite connection, audit key, or
audit-key bytes. A direct-mutation failure is expected safety behavior, not a
reason to remove the marker. Independently opening the database at the OS path
is outside the Rust API boundary, so enforce CNF filesystem identity and
permissions.

## 4. Offline legacy migration

The removed custom engine cannot prove which appended legacy suffix was
committed. Normal startup therefore returns `RecoveryRequired` for any
nonempty legacy config or consensus authority. There is no automatic majority
scan, log conversion, or startup repair.

### 4.1 Establish the approved applied state

1. Stop config traffic and drain every old writer and old consensus process.
   Keep them stopped for the complete migration.
2. Produce untouched, coherent pre-migration backups for rollback. Preserve
   every member's backup outside the paths the migration will modify.
3. From operator evidence, select one SQLite snapshot representing the exact
   authoritative applied config state. Do not select an uncommitted log tail
   merely because it appears on one or more replicas.
4. Checkpoint the selected snapshot and close every writer. Its main database
   file must be complete and its `-wal` file absent, empty, or fully
   checkpointed.
5. After the file is final, compute and record its exact SHA-256 checksum and
   record the exact latest applied config transaction ID and config version.
   A later byte change invalidates the approval.
6. Verify the retained config history is one linear chain. Its first retained
   record has no parent (its version need not be 1), and each later record names
   the immediately prior transaction with exactly the prior version +1.
7. Record the explicit operator decision
   `DiscardUnknownAppendedSuffix`. This acknowledges that any target state
   beyond the approved head is unprovable and will be destroyed.

Keep the approved source read-only. Do not use a source already containing an
Openraft `config_raft_identity` marker.

### 4.2 Apply the per-database authority hand-off

For each nonempty legacy target database being converted:

1. Open the target `SqliteBackend` with the correct audit key.
2. Construct `ApprovedLegacyConfigRecovery::new` with the approved snapshot
   path, SHA-256, transaction ID, version, and
   `LegacyConfigTailDisposition::DiscardUnknownAppendedSuffix`.
3. Call `ConsensusConfigStore::open_with_legacy_recovery` with the new exact
   topology, snapshot directory, and peer map.
4. Keep the shared listener and all old writers stopped until all target
   databases have either converted successfully or the rollout has been
   abandoned and restored from backup.

The adapter opens the source without following symlinks, binds the copy to that
exact file descriptor, checks the path/device/inode and offline WAL state both
before and after staging, and hashes the complete source. It verifies SQLite
integrity and required tables, rejects an Openraft source, checks the exact
latest transaction/version and complete linear parent/version history, verifies
stored audit chains and every sealed config envelope, and requires the explicit
suffix disposition. It then replaces the target config/audit state, redacts
and reseals imported audit data, removes the legacy consensus tables under the
explicit suffix disposition, creates the Openraft schema and authority marker,
and commits the target replacement in one immediate SQLite transaction.

That transaction is atomic for one target database. It is not a fleet-wide
transaction. Use the same approved authority evidence throughout the rollout,
and do not start the new cluster until the coordinated conversion has
completed.

If any checksum, head, integrity, audit, envelope, schema, or identity check
fails, recovery fails closed without authorizing a best-effort suffix. Diagnose
the source or restore the preserved backups; do not weaken the approval.

### 4.3 Start after migration

Once all intended members have converted:

1. Start the shared authenticated listeners and install each config handler.
2. Call `initialize_cluster()` under the new exact topology.
3. Require fresh durable readiness on every admitted traffic-serving node.
4. Verify the selected transaction/version is visible through the
   linearizable config read and verify the audit chain.
5. Retain the pre-migration backups according to the rollback decision window.

There is intentionally no `opc-persist` migration CLI or node binary. Product
tooling must collect the operator approval and invoke the typed API without
logging paths, checksums, transaction IDs, keys, or payload contents.

## 5. Failure handling

### 5.1 Quorum loss or partition

An HA cluster needs a majority of the admitted voters. A minority partition
cannot commit writes or satisfy a linearizable read/readiness probe. Keep
traffic gated and investigate shared-transport reachability, authentication,
storage health, and Openraft status. Do not enable standalone writes on an
isolated SQLite database.

When connectivity returns, Openraft owns normal uncommitted-log reconciliation
and catch-up. Do not truncate, append, or copy `config_raft_log` rows by hand.

### 5.2 Crash and restart

Restart with the same database, snapshot directory path/device/inode binding,
cluster/configuration/epoch, audit-key epoch/fingerprint, node ID, exact voter
set, and authenticated peer bindings. Openraft restores
its vote/log/commit/application/membership state from SQLite and resumes
through its normal recovery path. Keep readiness false until the fresh
linearizable probe succeeds.

On open, the adapter first verifies any snapshot referenced by durable state.
It then scans at most 8,192 directory entries and removes only recognized
interrupted receive/build/install/promote, approved-recovery, SQLite-sidecar,
and unreferenced snapshot artifacts. Unsafe recognized file types or an
oversized directory fail closed. Do not replace this with an unbounded cleanup
script or delete the referenced snapshot.

An identity, schema, checksum, or snapshot failure is not a rebootstrap signal.
Stop the node, preserve the evidence, and use a reviewed restore procedure.

### 5.3 Storage failure

Disk-full, corrupt SQLite/WAL, unavailable snapshot paths, or failed durable
writes must fail closed. Remove traffic readiness and preserve the files for
analysis. Never copy a locally readable config table into a live member and
never edit vote, log, membership, applied, outcome, or snapshot metadata.

## 6. Membership and topology epochs

The configured voter set is immutable within one config topology epoch.
`change_membership` only re-asserts that exact set and rejects a subset or
superset before Openraft work begins. To add, remove, or replace a voter, drain
the fleet and execute a reviewed topology/configuration-epoch transition with
coherent durable state and peer identity evidence. Never emulate membership by
editing mTLS authorization, peer routes, or SQLite rows.

## 7. Shared mTLS certificate rotation

The #177 storage migration does not alter certificate ownership. Rotation
remains the existing `opc-session-net`/CNF shared-transport responsibility; do
not add a config-only listener or a private credential-update path in
`opc-persist`.

Before the campaign, every participant must already run the same session-net
contract profile. The revision-5-to-6 binary/schema transition is a coordinated
drained stop/upgrade/start; connection reauthentication does not make a mixed
profile rolling upgrade safe. Configure the same finite
`ConnectionLifecyclePolicy` on peers and listeners, share an orchestration
`SessionReauthenticationControl`, and alert on the fixed lifecycle/reconnect
metrics. Preserve the encryption/HKMS composition above consensus; rotation
must not move plaintext, a provider handle, or raw key material into Openraft or
session-net.

For each authenticated connection, the hard deadline uses the earliest expiry
across each side's configured/presented SVID certificate chain. Every presented
certificate contributes, including a redundantly presented root. Production
SVID chains should omit the trust anchor, so the bound normally covers the leaf
and every presented intermediate. Certificates that appear only in configured
trust bundles are not independently scanned, and the time an anchor is
administratively removed is not a certificate-expiry deadline input. A
coherently published trust-bundle change creates new material; use the normal
reauthentication path to retire connections admitted under the previous
material.

The bounded same-issuer credential-compromise/revocation mechanism is
short-lived SVID expiry, not rotation or reauthentication. Set the SVID validity
bound to the maximum acceptable exposure window. Publishing a replacement
certificate/key and forcing fresh handshakes moves cooperative members to it,
but does not revoke the old certificate/key: its holder can reconnect until the
earliest expiry in its presented chain while its issuer remains trusted.
Session-net does not implement immediate generic CRL, OCSP,
certificate/identity denylist, or other selective same-issuer revocation. Root
removal is the trust-anchor cutover: later full handshakes reject every chain
that depends on that root, rather than selectively revoking one credential.
Treat any requirement for immediate generic per-credential revocation as
unsupported, not as evidence provided by a rotation campaign.

The SDK's non-ignored single-host regression qualification exercises this
lifecycle in separate three- and five-process Openraft/SQLite fleets. A
test-only consensus-RPC admission gate removes one stable follower while a
different member publishes malformed trust and retains its exact last-good TLS
epoch; survivors must remain durably ready and advance an encrypted canary.
The test restarts the gated member at the exact manifest address, proves
catch-up, repairs the malformed member, and proves its retained-last-good retry
counter stops. It then publishes a same-issuer leaf with a 75-second
remaining-validity/expiry budget. The fixed 30-second drain window establishes
an `expiry - 30 seconds` soft boundary, followed by complete hard-deadline drain
and source/controller `LastGoodExpired`; survivors continue canary progress and
a valid long-lived leaf restores the affected member in the same process. The
replacement proof uses the schedule-bound
`member-scoped-reauth-settled-baseline/v3` checkpoint: its 86-second clock and
60-second two-stage server tail begin at the atomic projected-data rename, and
a final 2.5-second outbound-ledger quiet tail completes the horizon. A
prepublication common-key pulse plus 13-second observation checkpoints requires
one active key to advance on every survivor observer and conservatively bounds
that pulse's worst-case actual event gap to 26 seconds. An independent 26-second
checkpoint requires every active key on every observer and cannot be reset by a
faster key. Each survivor may record at most one rejoin availability episode;
it must recover within that 26-second SLO and settle before the clean baseline,
and a second or late episode fails closed. Fault-era new-attempt and reconnect
deltas remain inside the fixed 85/161 per-node bound (ordinary 24/40, fifteen
five-second refresh rounds over four/eight incident paths, and one scheduled
post-hard-expiry survivor-to-expired network-negative attempt per involved
node). The reverse probe fails local material preflight without dialing. Terminal
outcomes may additionally contain only the exact attempts already outstanding
at the interval baseline, and must satisfy interval conservation; Schedule v6
binds `new-attempts-plus-baseline-outstanding/v1` and
`common-key-pulse-all-active-key-coverage/v1`.
Cancellation-classified `abandoned` outcomes, protocol/backend outcomes, and
drain overruns remain forbidden throughout the fault interval. The following
scoped-reauthentication interval again requires zero transport,
authentication, timeout, protocol, backend, reconnect-failure, and abandoned
outcomes. Continuity polling uses a non-intrusive workload snapshot; final
watch-head settlement retains the fail-closed authoritative replication-head
read.

This evidence does not authorize an operator to treat the admission gate as a
real or deployed network partition. It keeps bounded mixed lease/CAS mutation,
linearizable-read, watch, complete-restore, readiness, and connection-recycling
traffic active through the exact synthetic fault/expiry slice. The
qualification worker may reconcile only a typed backend-unavailable or
operation-outcome-unavailable result observed after the accepted operation
reaches a terminal checkpoint. Mutation or lease outcomes that can make
authority ambiguous discard the prior guard, reacquire same-owner authority
with a strictly higher fence, and validate the exact scheduled record.
Read-only get, restore-scan, and readiness outcomes retain the already-proven
guard and validate that same exact record without minting unnecessary fencing
authority. Evidence binds this routing as `stage-aware-known-authority/v1`.
The private
schedule drops one successful release response per mutator to prove this path.
More than eight such outcomes per node, any recovery episode beyond the fixed
26-second two-election-plus-operation transition envelope, any retry before the
fixed 50 ms delay, or phase completion with an unresolved interruption fails
the campaign. A terminal operation observed after that deadline reports the
closed operation stage and elapsed milliseconds and stays failed; raw backend
text and identity-bearing values do not enter the control protocol. The
admission-loss exact-address restart is watcher-only before exit and joins the
mutator set only after bounded journal reconciliation. A restarted process
that recovers a committed generation does not rearm that
once-per-logical-mutator fault; lease loss, unexpected state, and invariant
failures are never masked. Separately, after malformed-material repair,
exactly one stable follower is killed uncleanly with active mutation and watch
tasks. Survivor commits must advance during the outage, and the same-disk,
exact-address restart must reconcile the bounded committed journal, prove the
exact current record, catch its watch up, and resume under a strictly higher
same-owner fence. Schedule v6 binds this one
`same-disk-exact-address-active-mutator/v3` profile and independently enforces
the following stage deadlines:

| Restart stage | Bound |
| --- | ---: |
| SIGKILL termination and process reaping | 5 seconds |
| Outage work and survivor progress | 26 seconds |
| Replacement-child startup | 45 seconds |
| Openraft recovery and all-voter readiness observation | 37 seconds |
| Bounded journal reconciliation | 25 seconds |
| Higher-fence mutation resume | 26 seconds |

The sequential stages compose to a 164-second crash-to-resume ceiling. Each
stage fails independently and cannot borrow unused time from another stage or
use the total as its timer. The 37-second readiness stage is the 26-second
recovery envelope followed by one 11-second final round: a 10-second backend
operation plus 1 second of bounded local result delivery. This retains the v1
deadline-composition fix and corrects v2's free-running probe admission, which
could strand the final six seconds without one complete all-voter readiness
round. A broader
restart/fault matrix, resource/soak, remote-HKMS, deployed-CNF, signed release,
and evidence-schema/production-profile results remain open; the correction
does not prove deployed production readiness. This does not alter the
runbook's executable CNF campaign or alarms. Openraft remains the sole commit
authority, and payload encryption, AAD, key-provider/HKMS placement,
SQLite/Openraft durable formats, and encryption-at-rest responsibilities
remain unchanged.

### 7.1 Required CNF wiring and signals

Construct one shared `TlsMaterialController` per process through the projected
source's one-time paired authority constructor:

```rust,ignore
let source = opc_identity::ProjectedSvidSource::new_authoritative(
    projected_root,
    "tls.crt",
    "tls.key",
    vec!["ca.crt"],
    Some(projected_poll_interval),
)?;
let controller = opc_tls::TlsMaterialController::new_pinned_from_projected_source(
    &source,
    expected_local_spiffe_id,
)?;

// Keep source and controller clones alive. Build every client/listener from
// controller clones and share one reauthentication control.
```

Malformed projected candidates deliberately do not republish identity state,
so the source records their closed rejection outcomes directly into the shared
registry under the same publication critical section. The source can also be
the first observer of a publication's exact-once expiry. There is no public
outcome cursor or separately droppable monitor. The paired constructor
atomically claims the source's exact identity channel and recorder; a second
controller is rejected before it can mutate telemetry, while controller clones
share the one authority. The controller publishes accepted epoch/expiry gauges;
whichever side first observes expiry of the active accepted ticket may clear its
expiry gauge under the shared lifecycle. Expiry of any rejected, unaccepted, or
superseded ticket cannot change the active gauges. Counters are exact until they
reach `u64::MAX`, then remain saturated without wrapping and set the
corresponding fixed saturation gauge. No path, Kubernetes generation name,
identity, PEM, key, or parser text crosses the telemetry boundary.

The required security families have these exact semantics and fixed label
sets:

| Metric | Meaning |
|:---|:---|
| `opc_security_svid_expires_seconds` | Unix timestamp of the controller's earliest configured/presented SVID-chain expiry; `0` means no coherent unexpired material. Trust-bundle-only certificates are excluded. |
| `opc_security_bundle_version` | Opaque process-local controller epoch. It may differ between pods and resets on process restart; compare each pod only with its own baseline. It is never a Kubernetes directory, path, certificate hash, or cluster epoch. |
| `opc_security_rotation_total{kind,outcome}` | Exactly three kinds (`tls_material`, `svid`, `trust_bundle`) by four outcomes (`success`, `retained_last_good`, `rejected`, `expired`), for 12 series. Ambiguous source failures use `tls_material`; no dynamic label is accepted. |
| `opc_security_rotation_saturated{kind,outcome}` | Fixed 12-series gauge paired with the counters above. `1` means that counter reached `u64::MAX`; the counter never wraps, and the campaign must stop because further exact event cardinality is no longer representable. |

`retained_last_good` is a reload rejection with an unexpired predecessor, not a
peer trust failure. `rejected` means no usable predecessor. `expired` means the
lifecycle expiry of a coherent source publication was observed, whether before
pairing, while controller-active, or after controller rejection. Supersession
alone does not synthesize expiry. Peer authentication or trust failures remain
`opc_session_net_connection_attempts_total{outcome="authentication_or_trust_failure"}`.

Reconnect admission is serialized and exponentially bounded per directed peer,
not per RPC: both consensus lanes share the same cooldown, and legacy direct
requests and watches share the backend's cooldown. A newly published local TLS
material epoch or explicit reauthentication generation supersedes an old-epoch
wait or handshake immediately; it does not bypass fresh mutual-TLS, SPIFFE,
manifest-scope, ALPN, or contract checks. Alert on sustained real connection
attempts, not logical request volume. A transport-observed newer material or
explicit-reauthentication epoch terminates the old attempt as `superseded`. An
attempt guard dropped before explicit terminal classification is `abandoned`,
covering caller abort and runtime teardown without guessing why it ended. Both
preserve `started = terminal + outstanding` after lifecycle settlement;
`timeout` remains reserved for an actual resolver, TCP, TLS, bootstrap, or
frame deadline. Because these are separate relaxed counters, do not require
that equation from one scrape while handlers are changing state.

Material-epoch retirement of an already authenticated cached lane uses the
configured stable per-peer jitter. An explicit reauthentication request is an
operator demand for current-generation proof and retires cached lanes
immediately; it does not wait for material jitter.

Install these alert rules for a consensus CNF. There is deliberately no fixed
reference span. The earlier 1320-second example was unsafe because its
300-second observation/rollback term could not contain even one member's two
bounded 10-minute readiness waits. Generate `HARD_SPAN_SECONDS` from the exact
three- or five-member inventory and the command bounds in the executable
campaign below. It is the sum of maximum authentication age, rotation jitter,
drain, maximum reconnect backoff, observation, and the mechanically derived
worst-case two-pass rollback budget. That budget includes every CNF command,
evidence operation-ID allocation and publication, timeout termination grace,
both fleet gates, final withdrawal, lease release, and authoritative
release/expiry readback. The reference command bounds below
produce rollback budgets of 21240 seconds for three members and 33560 seconds
for five members; with the example 900/30/30/60/300 policy terms, the hard spans
are respectively 22560 and 34880 seconds. The complete forward bounds are 57600
and 91880 seconds, so the first-chain admission horizons (forward plus one full
hard span) are 80160 and 126760 seconds. A deployment may choose smaller command
bounds only when its qualified CNF enforces them.

Critical begins at one complete hard span and warning begins at two. Render the
`{{ HARD_SPAN_SECONDS }}` placeholders below from the same validated campaign
calculation; literal unresolved placeholders are invalid alert rules.
`CNFCTL assert-policy-and-alerts` must compare the rendered numeric threshold,
the script calculation, and every running member before any mutation.

`opc_cnf_expected_member{cluster,namespace,pod}` below is an independently
scraped operator/Kubernetes-inventory series with value `1`; it must not come
from the workload target. The inventory and workload scrape jobs must both
attach the same stable `cluster`, `namespace`, and `pod` topology labels.
Joining on those labels detects a member that disappeared from service
discovery, which `up` alone cannot; `job` remains only a scrape selector and is
never a join key. Missing/zero expiry, a missing target, or a down target is
critical because one full retirement-and-rollback span cannot be proved.

```yaml
groups:
  - name: opc-security-rotation
    rules:
      - alert: OpcSecuritySvidExpiryWarning
        expr: >-
          (
            min by (cluster, namespace, pod) (
              opc_security_svid_expires_seconds{job="opc-consensus"}
            ) - time()
            <= 2 * {{ HARD_SPAN_SECONDS }}
          )
          and
          (
            min by (cluster, namespace, pod) (
              opc_security_svid_expires_seconds{job="opc-consensus"}
            ) - time()
            > {{ HARD_SPAN_SECONDS }}
          )
        for: 60s
        labels: {severity: warning}
      - alert: OpcSecuritySvidExpiryCritical
        expr: >-
          (
            min by (cluster, namespace, pod) (
              opc_security_svid_expires_seconds{job="opc-consensus"}
            ) - time()
            <= {{ HARD_SPAN_SECONDS }}
          )
          or
          (
            max by (cluster, namespace, pod) (
              opc_cnf_expected_member{job="opc-operator-inventory"}
            )
            unless on (cluster, namespace, pod)
            max by (cluster, namespace, pod) (
              opc_security_svid_expires_seconds{job="opc-consensus"}
            )
          )
          or
          (
            max by (cluster, namespace, pod) (
              opc_cnf_expected_member{job="opc-operator-inventory"}
            )
            unless on (cluster, namespace, pod)
            (max by (cluster, namespace, pod) (up{job="opc-consensus"}) == 1)
          )
          or (absent(opc_cnf_expected_member{job="opc-operator-inventory"}) == 1)
        for: 30s
        labels: {severity: critical}
      - alert: OpcSecurityRotationRetainingLastGood
        expr: >-
          sum by (cluster, namespace, pod) (
            increase(opc_security_rotation_total{
              job="opc-consensus",outcome="retained_last_good"
            }[5m])
          ) > 0
        labels: {severity: warning}
      - alert: OpcSecurityRotationRejected
        expr: >-
          sum by (cluster, namespace, pod) (
            increase(opc_security_rotation_total{
              job="opc-consensus",outcome="rejected"
            }[5m])
          ) > 0
        labels: {severity: critical}
      - alert: OpcSecurityRotationExpired
        expr: >-
          sum by (cluster, namespace, pod) (
            increase(opc_security_rotation_total{
              job="opc-consensus",outcome="expired"
            }[5m])
          ) > 0
        labels: {severity: critical}
      - alert: OpcSecurityRotationCounterSaturated
        expr: >-
          max by (cluster, namespace, pod) (
            opc_security_rotation_saturated{job="opc-consensus"}
          ) == 1
        labels: {severity: critical}
      - alert: OpcSessionTlsDrainOverrun
        expr: >-
          sum by (cluster, namespace, pod) (
            increase(opc_session_net_connection_drain_events_total{
              job="opc-consensus",event="overrun"
            }[5m])
          ) > 0
        labels: {severity: critical}
      - alert: OpcSessionAuthenticationOrTrustFailure
        expr: >-
          sum by (cluster, namespace, pod) (
            increase(opc_session_net_connection_attempts_total{
              job="opc-consensus",
              outcome="authentication_or_trust_failure"
            }[5m])
          ) > 0
        labels: {severity: critical}
      - alert: OpcSessionReconnectFailure
        expr: >-
          sum by (cluster, namespace, pod) (
            increase(opc_session_net_reconnect_events_total{
              job="opc-consensus",outcome="failure"
            }[5m])
          ) > 0
        labels: {severity: critical}
      - alert: OpcSessionDurableReadinessLost
        expr: >-
          (
            max by (cluster, namespace, pod) (
              opc_session_store_durable_readiness_ready{job="opc-consensus"}
            ) != 1
          )
          or
          (
            max by (cluster, namespace, pod) (
              opc_cnf_expected_member{job="opc-operator-inventory"}
            )
            unless on (cluster, namespace, pod)
            max by (cluster, namespace, pod) (
              opc_session_store_durable_readiness_ready{job="opc-consensus"}
            )
          )
          or (absent(opc_cnf_expected_member{job="opc-operator-inventory"}) == 1)
        for: 30s
        labels: {severity: critical}
```

The `pod` label above is scrape-target metadata supplied by the deployment, not
an SDK metric label. Do not add replica, endpoint, SPIFFE ID, certificate,
Secret, path, transaction, tenant, or payload labels.

Use this stop/continue matrix for every campaign step:

| Current fleet state | Rotation action | Service action |
|:---|:---|:---|
| The one changed member's projected source and controller are both `Ready`, both per-member versions advanced from their own immediate baselines, all fresh affected paths pass, no new rejection/expiry/overrun/reconnect failure, and fresh durable readiness passes | Continue to the next member. Never publish to two members concurrently. | Continue. |
| Any member `RetainingLastGood` or a new `retained_last_good` outcome | Stop the campaign before another publication, reauthentication, restart, or trust removal. Repair and republish through a new projected generation; resume only after every controller is `Ready`. | Existing service may continue only while the retained expiry exceeds the configured hard rotation span and fresh durable readiness remains true. |
| One member `Unavailable` | Stop the campaign and retain overlapping/old trust. Do not deliberately restart or remove another voter. | A three- or five-voter service may continue only if a fresh probe reports `ready=1`, `fresh_reachable_voters >= required_quorum`, and `agreeing_voters >= required_quorum`; otherwise withdraw Ready and traffic. |
| One member `Unavailable` plus any other member malformed/`RetainingLastGood` | Stop immediately. Repair the unavailable member first, then the malformed candidate. Do not remove old trust or trigger fleet reauthentication. | Continue only under the same fresh quorum inequalities above, with no drain overrun, and while every retained expiry exceeds the configured hard rotation span; otherwise withdraw Ready and stop mutations. Never count the retained member as repaired. |
| Two unavailable voters in a three-voter fleet, three in a five-voter fleet, or any fresh durable probe failure | Abort the campaign. | Withdraw Ready and stop durable mutations; preserve evidence and recover quorum without plaintext or trust weakening. |

Counters are incident signals, not current-state gauges. A later `success` does
not erase an earlier failure. The CNF must expose both the current redaction-safe
projected-source status and `TlsMaterialStatus` for each member. Campaign steps
gate both; serving readiness is controlled by the authoritative controller, not
only projected-source `Ready` or either numeric epoch.

### 7.2 Executable CNF campaign and evidence

The CNF must provide authenticated implementations of every command used below.
After initialization, every command receives the current exclusive lease token
through a dedicated inherited file descriptor, never argv, the environment,
stdout, stderr, campaign state, or evidence. This script does not implement a
distributed lease and must not be treated as the authority. `cnfctl` and its
durable state authority MUST implement the following closed contract:

- acquisition has exactly two non-error outcomes. `Acquired` exits `0` and
  returns `token<TAB>sha256-binding<TAB>monotonic-fence<TAB>expiry-epoch` through
  the private pipe. `Busy` exits `75`, returns no bytes, performs no campaign or
  fleet mutation, and causes this invocation to exit without rollback or
  withdrawal. Every other status is an inconsistent/unavailable authority and
  follows fail-closed recovery;
- a lease has a finite TTL. Acquisition never waits for a holder: an expired
  holder may be fenced and taken over within the bounded acquisition command,
  while a live holder returns `Busy`. Every takeover allocates a strictly
  greater durable fence. A token/fence pair from an earlier holder is rejected
  by every state, evidence, and fleet command, including after process restart;
- before each leased command, the holder renews the same token/fence through a
  bounded operation for at least that command's complete outer bound plus the
  renewal reserve. Renewal returns the same fence and a finite expiry at or
  beyond the requested deadline. This includes the longest overlap wait;
- state transitions are durable, fenced, and idempotent. Completion, rollback
  transition, withdrawal, and release have readback operations. A response loss
  can be retried with the same durable transition key without repeating its
  fleet mutation. Withdrawal outcome readback returns exactly `committed` or
  `not-committed` for its stable idempotency key. Release is idempotent; a lost
  release response is resolved by readback, and otherwise the finite expiry
  fences the abandoned holder;
- recovery attempts release after rollback or withdrawal. A normal completion
  is accepted only after completion readback and released/expired readback.

Initialization returns the secret token and the non-secret binding/fence/expiry
through a private pipe. Every operation is bounded by an outer TERM/KILL
deadline; a CNF's internal timeout is smaller and cannot extend that deadline.
The state authority allocates strictly increasing operation IDs under the lease
and rejects reuse, rollback, or a command bearing an ID/nonce not owned by the
current invocation. These semantics are mandatory CNF guarantees; the shell
only validates their closed results and exercises them in the adversarial mock.

`publish-complete-material` must replace exactly one member's complete Secret
and publish exactly one atomic projected `..data` generation; a fleet-shared
Secret update is not an implementation of this contract. Before each mutation,
`fleet-checkpoint` must prove every expected source/controller is `Ready`, every
fixed metric series is fresh and complete, process incarnations/counters did not
reset, and it must write an opaque checkpoint outside evidence. Evidence carries
only the checkpoint's monotonic non-secret ID, never its path or contents.
Campaign state
must durably record the phase and touched ordinal before the API request so a
timeout, response loss, crash, `INT`, or `TERM` resumes the correct rollback
branch. `resume-action` must emit exactly `forward`, `rollback`, or `complete`;
`complete` is valid only after authoritative completion readback and permits
release/readback but no rollback or further fleet mutation. The
`rollback-branch` must emit exactly `before-removal` or `after-removal`; command
failure or any other output is an inconsistent state and withdraws serving.
Member-list output must contain only unique canonical ordinals from the bound
three- or five-member inventory. The post-removal list is nonempty, and the
renewed list must equal the complete inventory before any old-trust removal or
post-removal rollback.

`wait-source-material` gates the target source's `Ready` state and strictly
advanced process-local source generation; `wait-material` independently gates
the authoritative controller and strictly advanced epoch. Reauthentication and
drain commands operate at both ends of every inbound/outbound path incident to
the target. `probe-directed-current-material --affected-member-ordinal` forces
fresh, non-resumed full handshakes in both directions and proves current epochs
at both ends. The subsequent durable probe must be all-member, fresh, `ready=1`,
and satisfy both quorum inequalities. `fleet-post-gate` then reproves every
source/controller `Ready`, minimum expiry at least the exact operation bound
(the mechanically decreasing forward remainder plus a complete hard-span
reserve, or the deadline remainder during rollback), no process
or counter reset, complete series, and zero new retained/rejected/expired,
drain-overrun, authentication/trust, or reconnect failures since that member's
checkpoint. Only then may the next member change.

Old-trust removal uses one `authorize-and-publish-old-trust-removal` command to
close the authorization/publication TOCTOU gap. Immediately before its API
write, it must bind and recheck the exact topology/configuration epoch, target
ordinal, all process incarnations and source/controller versions, final
target-specific manifest digest, rollback-overlap manifest digest, metric
checkpoint, hard span, fresh all-directed proof, and fresh durable barrier. It
must fail before the write if any binding changed. Campaign state records
`removal-attempted` before this command because a lost response is ambiguous and
requires the post-removal rollback branch.

Every evidence-producing command's stdout uses one exact evidence schema. It
contains only schema, campaign ID, exact release digest,
topology/configuration epoch, policy durations, the fleet-size-derived rollback
budget, full forward bound, maximum forward certificate horizon, and computed
hard span, invocation ID, non-secret lease binding and fence,
monotonic operation ID, one-use operation nonce, phase/step, the exact expected
numeric ordinal or null, the exact checkpoint ID or null,
before/after numeric versions, expected and ready counts, minimum remaining
expiry, affected-path expected/passed counts, durable quorum counts/Boolean,
the exact command-requested success delta, closed aggregate deltas (including
reconnect failure), saturation count,
series/reset/process completeness, the exact remaining validity requirement,
an opaque process-incarnation-set binding, the explicit withdrawal state, and
the bound negative-probe fields.
The latter are null/zero outside the two probe steps; accounting carries the
referenced probe operation ID/nonce, receipt-set binding and exact receipt
count, probe checkpoint and incarnation-set bindings, and expected/observed
member and campaign deltas. UTC timestamp and exit status complete the schema. A metrics
implementation must query in memory per expected member, detect a missing
12-counter/12-saturation-series matrix, stale scrape, process/counter reset, and
only then aggregate. It discards `job`, `pod`, `instance`, `endpoint`, target,
address, URL, pod-IP, and every other scrape label before emitting. The script
validates exact JSON keys/types, compares every binding to the exact requested
invocation, lease/fence, operation, member, checkpoint, phase, and step, and
applies a closed semantic predicate for that exact phase/step pair. A
`source-ready` document has non-null source versions with `before < after`; a
`controller-ready` document has non-null controller epochs with `before <
after`; and a directed-path document has a positive expected count with
`passed == expected`. Except for
withdrawal and the deliberately nonzero bound old-chain probe, a successful
step proves all sources/controllers ready, quorum ready, complete series, no
reset/process change/saturation, expiry at least the requested horizon, equal
expected/passed paths, and zero closed failure deltas. The negative probe and
its accounting permit only the exact bound authentication/trust delta and exact
receipt set. Every non-withdrawal document sets `withdrawal_state` to
`not-withdrawn`. Withdrawal has no readiness claim: it must set that field to
`ready-traffic-and-durable-mutations-withdrawn`, and every readiness, path,
version, probe, alert, success, and unrelated delta field must have its exact
fail-closed null/false/zero value. The validation clock is sampled
only after bounded stdout capture completes and accepts a timestamp from 30
seconds before through five seconds after that sample.
Consequently a cached document from another member, checkpoint, lease,
invocation, or earlier operation cannot pass. The lease token itself is never
persisted or exposed.

Validated evidence is published on the evidence filesystem with a file fsync,
an atomic hard-link no-replace operation, a directory fsync, pending-name
unlink, and another directory fsync. An existing destination is a hard failure,
never a suffix or overwrite. Stdout is
limited to 64 KiB before JSON parsing, must contain exactly one document with
closed phase/step enums and bounded fields, and its recorded exit status must
equal the command's actual process status. Never persist an upstream Prometheus
response or `/targets` response. All raw CNF stderr is drained into a
bounded-lifetime discard pipe. Stdout capture, evidence input, and discard
readers each have their own copy of the producer's wall-clock deadline, so a
descendant that inherits a descriptor cannot extend a command bound. Only fixed local diagnostics can reach the
terminal; raw stderr and parser diagnostics are never persisted.
Commands must not emit identity text, certificate/key bytes, Secret contents,
paths, peer endpoints, payloads, provider handles, material/endpoint hashes, or
parser errors.

The emergency withdrawal is intentionally different. Before a leased action,
renewal either succeeds or returns a proven pre-action failure; only then does
the script mark the outcome ambiguous and invoke the safety action with stdout
and stderr suppressed. Once invocation starts, every raw action exit status,
including `76`, is ambiguous and requires authoritative readback; only the
separate pre-action-renewal result can skip it when no earlier attempt ran. The
action and its outcome readback share one 60-second
deadline and one durable idempotency key. A lost response or failed readback may
retry that same key once; the authority returns the stored result and performs
no second effective fleet mutation. If the monotonic operation allocator is
unavailable, a lease-authenticated withdrawal-only command uses a stable
campaign/topology key, remains action-first and exactly-once, and produces no
evidence. Only an authoritative `committed` readback permits the ordinarily
allocated path to request the exact withdrawal document for the already
completed operation and attempt durable publication. ENOSPC, an unwritable
evidence root, a collision, or fsync failure is reported and terminates the
campaign, but cannot suppress or repeat the withdrawal.
`ERR`, `EXIT`, `HUP`, `INT`, and `TERM` recovery is installed before lease
initialization. Recovery is guarded against re-entry; later signals are noted
and deferred while the bounded rollback continues. Any rollback failure ends in
the independent withdrawal path. An unexpected nonzero exit follows the same
state-authoritative branch and cannot strand a partially published fleet.

Each manifest set contains one complete member-specific projected Secret per
ordinal. `PREVIOUS_OVERLAP_MANIFEST_SET` has the previous leaf/key plus
old-and-new trust, `NEW_SVID_OVERLAP_MANIFEST_SET` has the new leaf/key plus
old-and-new trust, and `FINAL_NEW_ONLY_MANIFEST_SET` has the new leaf/key plus
new-only trust. All sets are validated before mutation. Never patch one file or
update every member at once. Manifest sets are inputs only and must never be
copied into the evidence directory.

```bash
#!/usr/bin/env bash
set -Eeuo pipefail
set +x
umask 077
ulimit -c 0 || exit 64
export LC_ALL=C

: "${NS:?set namespace}"
: "${WORKLOAD:?set StatefulSet name}"
: "${SELECTOR:?set exact member selector}"
: "${CNFCTL:?set one absolute authenticated CNF executable path}"
: "${CAMPAIGN_ID:?set a unique lowercase campaign identifier}"
: "${EXPECTED_MEMBERS:?set the exact member count, 3 or 5}"
: "${RELEASE_DIGEST:?set exact sha256 release digest}"
: "${TOPOLOGY_CONFIG_EPOCH:?set exact topology/configuration epoch}"
: "${EVIDENCE_ROOT:?set persistent approved 0700 evidence root}"
: "${STATE_ROOT:?set persistent approved 0700 campaign-state root}"
: "${ALERT_RULES:?set rendered alert-rule file}"
: "${PREVIOUS_OVERLAP_MANIFEST_SET:?set previous leaf/key + old/new trust set}"
: "${NEW_SVID_OVERLAP_MANIFEST_SET:?set new leaf/key + old/new trust set}"
: "${FINAL_NEW_ONLY_MANIFEST_SET:?set new leaf/key + new-only trust set}"
: "${OLD_CHAIN_PROBE:?set non-secret old-chain negative-probe reference}"
: "${OLD_CHAIN_EXPECTED_FAILURE_DELTA:?set the qualified exact per-member delta}"
: "${MAX_AUTH_AGE_SECONDS:?set running maximum authentication age}"
: "${ROTATION_JITTER_SECONDS:?set running rotation jitter}"
: "${DRAIN_SECONDS:?set running drain bound}"
: "${RECONNECT_MAX_SECONDS:?set running maximum reconnect backoff}"
: "${OBSERVATION_SECONDS:?set approved scrape, alert, and response observation bound}"

[[ "$CNFCTL" = /* && -x "$CNFCTL" && ! -L "$CNFCTL" ]] || exit 64
for utility in base64 date dd jq mktemp od python3 realpath stat timeout tr; do
  command -v "$utility" >/dev/null || exit 64
done
[[ "$CAMPAIGN_ID" =~ ^[a-z0-9][a-z0-9-]{0,62}$ ]] || exit 64
[[ "$EXPECTED_MEMBERS" == 3 || "$EXPECTED_MEMBERS" == 5 ]] || exit 64
[[ "$OLD_CHAIN_EXPECTED_FAILURE_DELTA" =~ ^[1-9][0-9]?$ ]] || exit 64
((10#$OLD_CHAIN_EXPECTED_FAILURE_DELTA <= 2 * (10#$EXPECTED_MEMBERS - 1))) || \
  exit 64
[[ "$RELEASE_DIGEST" =~ ^sha256:[a-f0-9]{64}$ ]] || exit 64
validate_u64() {
  local value=$1
  [[ "$value" =~ ^(0|[1-9][0-9]{0,19})$ ]] || return 1
  # Equal-length decimal strings are intentionally compared lexicographically.
  # shellcheck disable=SC2071
  ((${#value} < 20)) || [[ "$value" < 18446744073709551615 || \
    "$value" == 18446744073709551615 ]]
}
validate_u64 "$TOPOLOGY_CONFIG_EPOCH" || exit 64
for root in "$EVIDENCE_ROOT" "$STATE_ROOT"; do
  [[ "$root" = /* && -d "$root" && ! -L "$root" ]] || exit 64
done
EVIDENCE_ROOT=$(realpath -e -- "$EVIDENCE_ROOT") || exit 64
STATE_ROOT=$(realpath -e -- "$STATE_ROOT") || exit 64
[[ "$EVIDENCE_ROOT" != "$STATE_ROOT" ]] || exit 64
[[ "$EVIDENCE_ROOT" != "$STATE_ROOT/"* ]] || exit 64
[[ "$STATE_ROOT" != "$EVIDENCE_ROOT/"* ]] || exit 64
for root in "$EVIDENCE_ROOT" "$STATE_ROOT"; do
  [[ "$root" = /* && -d "$root" && ! -L "$root" ]] || exit 64
  [[ $(stat -c '%a' "$root") == 700 ]] || exit 64
done

validate_duration() {
  [[ "$1" =~ ^(0|[1-9][0-9]{0,5})$ ]] && ((10#$1 <= 604800))
}
for duration in \
  "$MAX_AUTH_AGE_SECONDS" "$ROTATION_JITTER_SECONDS" "$DRAIN_SECONDS" \
  "$RECONNECT_MAX_SECONDS" "$OBSERVATION_SECONDS"
do
  validate_duration "$duration" || exit 64
done

# Every value is a total wall-clock bound, including a five-second TERM-to-KILL
# grace. The CNF's own --timeout is strictly smaller than the wrapper bound.
# Stdout/stderr readers run concurrently under that same command deadline; they
# are not unbudgeted serial additions. Evidence capture is likewise concurrent
# with its producer, while the separately budgeted validation term begins only
# after bounded capture reaches EOF.
COMMAND_KILL_GRACE_SECONDS=5
LEASE_RENEWAL_OPERATION_SECONDS=10
LEASE_RENEWAL_RESERVE_SECONDS=30
STATE_OPERATION_SECONDS=30
CHECKPOINT_SECONDS=120
PUBLICATION_SECONDS=120
SOURCE_WAIT_SECONDS=610
CONTROLLER_WAIT_SECONDS=610
REAUTHENTICATION_SECONDS=120
DRAIN_WAIT_SECONDS=$((10#$DRAIN_SECONDS + 30))
DIRECTED_PROBE_SECONDS=120
DURABLE_PROBE_SECONDS=120
POST_GATE_SECONDS=120
VALIDITY_PROBE_SECONDS=60
WITHDRAWAL_SECONDS=60
EVIDENCE_STAGE_SECONDS=30
EVIDENCE_VALIDATION_SECONDS=30
EVIDENCE_PUBLISH_SECONDS=30
EVIDENCE_OPERATION_OVERHEAD_SECONDS=$((
  STATE_OPERATION_SECONDS + EVIDENCE_STAGE_SECONDS +
  EVIDENCE_VALIDATION_SECONDS + EVIDENCE_PUBLISH_SECONDS
))
WITHDRAWAL_TOTAL_SECONDS=$((
  STATE_OPERATION_SECONDS + WITHDRAWAL_SECONDS +
  EVIDENCE_STAGE_SECONDS + STATE_OPERATION_SECONDS +
  EVIDENCE_VALIDATION_SECONDS + EVIDENCE_PUBLISH_SECONDS
))
RECOVERY_RELEASE_TOTAL_SECONDS=$((2 * STATE_OPERATION_SECONDS))

# One rollback publication performs a state marker, a fresh material-validity
# proof, the authorized publication, and all seven post-publication gates. Each
# evidence-producing operation also pays the durable-publication bound.
POST_MEMBER_GATE_SECONDS=$((
  SOURCE_WAIT_SECONDS + CONTROLLER_WAIT_SECONDS + REAUTHENTICATION_SECONDS +
  DRAIN_WAIT_SECONDS + DIRECTED_PROBE_SECONDS + DURABLE_PROBE_SECONDS +
  POST_GATE_SECONDS + 7 * EVIDENCE_OPERATION_OVERHEAD_SECONDS
))
ROLLBACK_MEMBER_SECONDS=$((
  2 * STATE_OPERATION_SECONDS + VALIDITY_PROBE_SECONDS +
  EVIDENCE_OPERATION_OVERHEAD_SECONDS + PUBLICATION_SECONDS +
  EVIDENCE_OPERATION_OVERHEAD_SECONDS + POST_MEMBER_GATE_SECONDS
))
FINAL_FLEET_GATE_SECONDS=$((
  STATE_OPERATION_SECONDS + CHECKPOINT_SECONDS + DIRECTED_PROBE_SECONDS + DURABLE_PROBE_SECONDS +
  POST_GATE_SECONDS + 4 * EVIDENCE_OPERATION_OVERHEAD_SECONDS
))

# The fixed term bounds: mark-interrupted, require-rollback, rollback-branch,
# begin-rollback, four list/retain/state operations, and the remaining state
# operations; two final gates; one inter-pass validity proof; fail-safe
# withdrawal plus its best-effort evidence publication; and the final lease
# release plus authoritative release/expiry readback. The member term is the
# worst post-removal branch: two complete sequential passes over the fleet.
ROLLBACK_FIXED_SECONDS=$((
  11 * STATE_OPERATION_SECONDS + 2 * FINAL_FLEET_GATE_SECONDS +
  VALIDITY_PROBE_SECONDS + EVIDENCE_OPERATION_OVERHEAD_SECONDS +
  WITHDRAWAL_TOTAL_SECONDS + RECOVERY_RELEASE_TOTAL_SECONDS
))
ROLLBACK_BUDGET_SECONDS=$((
  ROLLBACK_FIXED_SECONDS + 2 * 10#$EXPECTED_MEMBERS * ROLLBACK_MEMBER_SECONDS
))
HARD_SPAN_SECONDS=$((
  10#$MAX_AUTH_AGE_SECONDS + 10#$ROTATION_JITTER_SECONDS + 10#$DRAIN_SECONDS +
  10#$RECONNECT_MAX_SECONDS + 10#$OBSERVATION_SECONDS + ROLLBACK_BUDGET_SECONDS
))
OVERLAP_WAIT_SECONDS=$((HARD_SPAN_SECONDS + 30))

# Forward validity is not the rollback span alone. The first accepted chain can
# remain in use through every later member/phase and must still leave one full
# hard span for rollback. These terms enumerate every bounded forward command;
# `run_cnfctl` performs lease renewal and all descriptor readers inside, not in
# addition to, each bound.
CHECKPOINT_FLOW_SECONDS=$((
  STATE_OPERATION_SECONDS + CHECKPOINT_SECONDS + EVIDENCE_OPERATION_OVERHEAD_SECONDS
))
FORWARD_MEMBER_SECONDS=$((
  CHECKPOINT_FLOW_SECONDS + STATE_OPERATION_SECONDS +
  VALIDITY_PROBE_SECONDS + EVIDENCE_OPERATION_OVERHEAD_SECONDS +
  PUBLICATION_SECONDS + EVIDENCE_OPERATION_OVERHEAD_SECONDS +
  POST_MEMBER_GATE_SECONDS
))
NEGATIVE_PROBE_SEQUENCE_SECONDS=$((
  CHECKPOINT_FLOW_SECONDS +
  POST_GATE_SECONDS + EVIDENCE_OPERATION_OVERHEAD_SECONDS +
  DIRECTED_PROBE_SECONDS + EVIDENCE_OPERATION_OVERHEAD_SECONDS +
  POST_GATE_SECONDS + EVIDENCE_OPERATION_OVERHEAD_SECONDS
))
FINAL_MEMBER_SECONDS=$((
  STATE_OPERATION_SECONDS + FORWARD_MEMBER_SECONDS +
  NEGATIVE_PROBE_SEQUENCE_SECONDS
))
PREFLIGHT_SECONDS=$((
  STATE_OPERATION_SECONDS + EVIDENCE_OPERATION_OVERHEAD_SECONDS +
  3 * (VALIDITY_PROBE_SECONDS + EVIDENCE_OPERATION_OVERHEAD_SECONDS)
))
OVERLAP_WINDOW_OPERATION_SECONDS=$((
  OVERLAP_WAIT_SECONDS + EVIDENCE_OPERATION_OVERHEAD_SECONDS
))
# campaign-status evidence, mark-complete, completion readback, release, and
# released/expired readback are all independently bounded state operations.
COMPLETION_SECONDS=$((
  STATE_OPERATION_SECONDS + EVIDENCE_OPERATION_OVERHEAD_SECONDS +
  4 * STATE_OPERATION_SECONDS
))
FORWARD_CAMPAIGN_SECONDS=$((
  PREFLIGHT_SECONDS +
  2 * 10#$EXPECTED_MEMBERS * FORWARD_MEMBER_SECONDS +
  OVERLAP_WINDOW_OPERATION_SECONDS +
  10#$EXPECTED_MEMBERS * FINAL_MEMBER_SECONDS +
  FINAL_FLEET_GATE_SECONDS + COMPLETION_SECONDS
))
FORWARD_CERTIFICATE_HORIZON_SECONDS=$((
  FORWARD_CAMPAIGN_SECONDS + HARD_SPAN_SECONDS
))
LEASE_TTL_SECONDS=$((
  OVERLAP_WAIT_SECONDS + LEASE_RENEWAL_RESERVE_SECONDS
))
validate_duration "$DRAIN_WAIT_SECONDS" || exit 64
validate_duration "$ROLLBACK_BUDGET_SECONDS" || exit 64
validate_duration "$HARD_SPAN_SECONDS" || exit 64
validate_duration "$OVERLAP_WAIT_SECONDS" || exit 64
validate_duration "$FORWARD_CAMPAIGN_SECONDS" || exit 64
validate_duration "$FORWARD_CERTIFICATE_HORIZON_SECONDS" || exit 64
validate_duration "$LEASE_TTL_SECONDS" || exit 64

INVOCATION_ID=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n') || exit 1
[[ "$INVOCATION_ID" =~ ^[a-f0-9]{32}$ ]] || exit 1
LEASE_TOKEN=
LEASE_BINDING=
LEASE_FENCE=
LEASE_EXPIRES_EPOCH=0
LEASE_ACQUIRED=0
EXIT_WITHOUT_RECOVERY=0
CAMPAIGN_COMPLETE=0
COMPLETION_RECORDED=0
RECOVERY_ACTIVE=0
RECOVERY_FINISHED=0
RECOVERY_ATTEMPTED=0
SECONDARY_SIGNAL=0
WITHDRAWAL_ATTEMPTED=0
WITHDRAWAL_ACTION_STARTED=0
WITHDRAWAL_ACTION_COMMITTED=0
WITHDRAWAL_ATTEMPT_RESULT=not-run
WITHDRAWAL_ACTION_STATUS=0
WITHDRAWAL_ACTION_DEADLINE_EPOCH=0
LAST_ERROR_STATUS=0
CURRENT_OPERATION_ID=
CURRENT_OPERATION_NONCE=
CURRENT_CHECKPOINT_ID=null
ACTIVE_DEADLINE_EPOCH=0
EXPECTED_AUTH_FAILURE_DELTA=0
EXPECTED_REFERENCED_PROBE_OPERATION_ID=null
EXPECTED_REFERENCED_PROBE_OPERATION_NONCE=null
EXPECTED_PROBE_RECEIPT_SET_BINDING=null
EXPECTED_PROBE_RECEIPT_COUNT=0
EXPECTED_PROBE_CHECKPOINT_ID=null
EXPECTED_PROBE_PROCESS_BINDING=null
EXPECTED_MEMBER_AUTH_DELTA=0
EXPECTED_CAMPAIGN_AUTH_DELTA=0
LAST_EVIDENCE_PROCESS_BINDING=
LAST_EVIDENCE_RECEIPT_SET_BINDING=
LAST_EVIDENCE_RECEIPT_COUNT=0
CAPTURED_OUTPUT=
FORWARD_DEADLINE_EPOCH=0

discard_cnfctl_stderr() {
  local total_seconds=$1 soft_seconds
  # Consume until EOF so a noisy child cannot block. Raw diagnostics are never
  # copied to a terminal or evidence; callers emit only fixed local messages.
  # The reader has the same independent wall-clock deadline as its producer,
  # including the shared TERM-to-KILL grace, so an inherited descriptor cannot
  # leave the wrapper waiting after the command deadline.
  ((total_seconds > COMMAND_KILL_GRACE_SECONDS)) || return 0
  soft_seconds=$((total_seconds - COMMAND_KILL_GRACE_SECONDS))
  timeout --signal=TERM --kill-after="${COMMAND_KILL_GRACE_SECONDS}s" \
    "${soft_seconds}s" dd bs=4096 status=none of=/dev/null || true
}

run_cnfctl_unleased() {
  local total_seconds=$1 soft_seconds
  shift
  ((total_seconds > COMMAND_KILL_GRACE_SECONDS)) || return 64
  soft_seconds=$((total_seconds - COMMAND_KILL_GRACE_SECONDS))
  timeout --signal=TERM --kill-after="${COMMAND_KILL_GRACE_SECONDS}s" \
    "${soft_seconds}s" "$CNFCTL" "$@" \
    2> >(discard_cnfctl_stderr "$total_seconds")
}

run_cnfctl_raw() {
  local total_seconds=$1 soft_seconds
  shift
  ((LEASE_ACQUIRED == 1)) || return 77
  ((total_seconds > COMMAND_KILL_GRACE_SECONDS)) || return 64
  soft_seconds=$((total_seconds - COMMAND_KILL_GRACE_SECONDS))
  timeout --signal=TERM --kill-after="${COMMAND_KILL_GRACE_SECONDS}s" \
    "${soft_seconds}s" "$CNFCTL" --lease-token-fd 9 \
    --lease-fence "$LEASE_FENCE" "$@" \
    9< <(printf '%s' "$LEASE_TOKEN") \
    2> >(discard_cnfctl_stderr "$total_seconds")
}

bounded_read_fd() {
  local fd=$1 maximum_bytes=$2 total_seconds=$3 target=$4
  local soft_seconds encoded decoded
  [[ "$target" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || return 64
  ((total_seconds > COMMAND_KILL_GRACE_SECONDS)) || return 64
  soft_seconds=$((total_seconds - COMMAND_KILL_GRACE_SECONDS))
  encoded=$(timeout --signal=TERM \
    --kill-after="${COMMAND_KILL_GRACE_SECONDS}s" "${soft_seconds}s" \
    dd bs="$((maximum_bytes + 1))" count=1 iflag=fullblock status=none \
    <&"$fd" | timeout --signal=TERM \
      --kill-after="${COMMAND_KILL_GRACE_SECONDS}s" "${soft_seconds}s" \
      base64 --wrap=0) || return 74
  # Bash cannot represent NUL. Reject it before assigning untrusted bytes so a
  # hostile document cannot be transformed into a different valid scalar.
  decoded=$(printf '%s' "$encoded" | timeout --signal=TERM \
    --kill-after="${COMMAND_KILL_GRACE_SECONDS}s" "${soft_seconds}s" \
    base64 --decode | timeout --signal=TERM \
    --kill-after="${COMMAND_KILL_GRACE_SECONDS}s" "${soft_seconds}s" \
    python3 -c '
import sys
data = sys.stdin.buffer.read()
if b"\0" in data:
    raise SystemExit(65)
sys.stdout.buffer.write(data + b"\x1e")
') || return 65
  [[ "$decoded" == *$'\x1e' ]] || return 65
  decoded=${decoded%$'\x1e'}
  ((${#decoded} <= maximum_bytes)) || return 65
  printf -v "$target" '%s' "$decoded"
}

renew_lease_for() {
  local command_deadline=$1 required_expiry capture_fd capture_pid read_fd
  local read_status command_status output fence expiry now_epoch
  required_expiry=$((command_deadline + LEASE_RENEWAL_RESERVE_SECONDS))
  CAPTURED_OUTPUT=
  coproc LEASE_RENEW_CAPTURE {
    run_cnfctl_raw "$LEASE_RENEWAL_OPERATION_SECONDS" \
      campaign-state renew-exclusive-lease --state-dir "$STATE_DIR" \
      --invocation-id "$INVOCATION_ID" --lease-fence "$LEASE_FENCE" \
      --minimum-expiry-epoch "$required_expiry" \
      --output-format fence-tab-expiry
  }
  capture_fd=${LEASE_RENEW_CAPTURE[0]}
  capture_pid=$LEASE_RENEW_CAPTURE_PID
  exec {read_fd}<&"$capture_fd"
  exec {capture_fd}<&-
  if bounded_read_fd "$read_fd" 128 "$LEASE_RENEWAL_OPERATION_SECONDS" \
    output
  then
    read_status=0
  else
    read_status=$?
  fi
  exec {read_fd}<&-
  if ((read_status != 0)); then kill -KILL "$capture_pid" 2>/dev/null || true; fi
  if wait "$capture_pid"; then command_status=0; else command_status=$?; fi
  ((read_status == 0)) || return "$read_status"
  ((command_status == 0)) || return "$command_status"
  ((${#output} <= 128)) || return 65
  if [[ "$output" == *$'\n' ]]; then output=${output%$'\n'}; fi
  [[ "$output" == *$'\t'* && "$output" != *$'\n'* ]] || return 65
  fence=${output%%$'\t'*}
  expiry=${output#*$'\t'}
  validate_u64 "$fence" || return 65
  [[ "$fence" == "$LEASE_FENCE" ]] || return 65
  [[ "$expiry" =~ ^(0|[1-9][0-9]{0,18})$ ]] || return 65
  now_epoch=$(date -u +%s) || return 1
  ((10#$expiry >= required_expiry && 10#$expiry > now_epoch)) || return 65
  LEASE_EXPIRES_EPOCH=$((10#$expiry))
}

run_cnfctl() {
  local total_seconds=$1 now_epoch deadline_remaining command_deadline
  shift
  ((LEASE_ACQUIRED == 1)) || return 77
  if ((ACTIVE_DEADLINE_EPOCH > 0)); then
    now_epoch=$(date -u +%s) || return 1
    deadline_remaining=$((ACTIVE_DEADLINE_EPOCH - now_epoch))
    ((deadline_remaining > COMMAND_KILL_GRACE_SECONDS)) || return 75
    if ((deadline_remaining < total_seconds)); then
      total_seconds=$deadline_remaining
    fi
  fi
  ((total_seconds > LEASE_RENEWAL_OPERATION_SECONDS + \
    COMMAND_KILL_GRACE_SECONDS)) || return 64
  now_epoch=$(date -u +%s) || return 1
  command_deadline=$((now_epoch + total_seconds))
  renew_lease_for "$command_deadline" || return $?
  now_epoch=$(date -u +%s) || return 1
  deadline_remaining=$((command_deadline - now_epoch))
  ((deadline_remaining > COMMAND_KILL_GRACE_SECONDS)) || return 75
  run_cnfctl_raw "$deadline_remaining" "$@"
}

capture_scalar() {
  local total_seconds=$1 pattern=$2 maximum_bytes=$3 output
  shift 3
  capture_cnfctl_bounded leased "$total_seconds" "$maximum_bytes" "$@" || \
    return $?
  output=$CAPTURED_OUTPUT
  if [[ "$output" == *$'\n' ]]; then output=${output%$'\n'}; fi
  [[ "$output" != *$'\n'* && "$output" != *$'\r'* ]] || return 65
  ((${#output} <= maximum_bytes)) || return 65
  [[ "$output" =~ $pattern ]] || return 65
  printf '%s' "$output"
}

capture_cnfctl_bounded() {
  local mode=$1 total_seconds=$2 maximum_bytes=$3
  local capture_fd capture_pid read_fd command_status read_status
  shift 3
  CAPTURED_OUTPUT=
  case "$mode" in
    leased)
      coproc RUNBOOK_CAPTURE { run_cnfctl "$total_seconds" "$@"; }
      ;;
    unleased)
      coproc RUNBOOK_CAPTURE { run_cnfctl_unleased "$total_seconds" "$@"; }
      ;;
    *) return 64 ;;
  esac
  capture_fd=${RUNBOOK_CAPTURE[0]}
  capture_pid=$RUNBOOK_CAPTURE_PID
  exec {read_fd}<&"$capture_fd"
  exec {capture_fd}<&-
  if bounded_read_fd "$read_fd" "$maximum_bytes" "$total_seconds" \
    CAPTURED_OUTPUT
  then
    read_status=0
  else
    read_status=$?
  fi
  exec {read_fd}<&-
  if ((read_status != 0)); then kill -KILL "$capture_pid" 2>/dev/null || true; fi
  if wait "$capture_pid"; then command_status=0; else command_status=$?; fi
  ((read_status == 0)) || return "$read_status"
  ((command_status == 0)) || return "$command_status"
  ((${#CAPTURED_OUTPUT} <= maximum_bytes)) || return 65
}

EVIDENCE_DIR="$EVIDENCE_ROOT/$CAMPAIGN_ID"
STATE_DIR="$STATE_ROOT/$CAMPAIGN_ID"
if [[ -e "$EVIDENCE_DIR" ]]; then
  [[ -d "$EVIDENCE_DIR" && ! -L "$EVIDENCE_DIR" ]] || exit 64
  [[ $(stat -c '%a' "$EVIDENCE_DIR") == 700 ]] || exit 64
else
  mkdir -m 0700 -- "$EVIDENCE_DIR" || exit 1
fi
if [[ -e "$STATE_DIR" ]]; then
  [[ -d "$STATE_DIR" && ! -L "$STATE_DIR" ]] || exit 64
  [[ $(stat -c '%a' "$STATE_DIR") == 700 ]] || exit 64
else
  mkdir -m 0700 -- "$STATE_DIR" || exit 1
fi

MAX_EVIDENCE_BYTES=65536
validate_evidence() {
  local expected_phase=$1 expected_step=$2 expected_member=$3
  local expected_checkpoint=$4 expected_remaining=$5 expected_operation=$6
  local expected_nonce=$7 expected_auth_delta=$8
  local expected_success_delta=${9:-0} capture_timeout=${10:-30} now_epoch
  local encoded encoded_length padding=0 decoded_length
  validate_duration "$capture_timeout" || return 65
  ((capture_timeout > COMMAND_KILL_GRACE_SECONDS)) || return 65
  encoded=$(timeout --signal=TERM \
    --kill-after="${COMMAND_KILL_GRACE_SECONDS}s" \
    "$((capture_timeout - COMMAND_KILL_GRACE_SECONDS))s" \
    dd bs="$((MAX_EVIDENCE_BYTES + 1))" count=1 iflag=fullblock \
    status=none | timeout --signal=TERM \
      --kill-after="${COMMAND_KILL_GRACE_SECONDS}s" \
      "$((capture_timeout - COMMAND_KILL_GRACE_SECONDS))s" \
      base64 --wrap=0) || return 74
  encoded_length=${#encoded}
  case "$encoded" in
    *==) padding=2 ;;
    *=) padding=1 ;;
  esac
  decoded_length=$((encoded_length * 3 / 4 - padding))
  ((decoded_length <= MAX_EVIDENCE_BYTES)) || return 65
  # Freshness is relative to completion of the bounded capture. Sampling before
  # a 120/610-second producer would reject a legitimate completion as "future".
  now_epoch=$(date -u +%s) || return 65

  # The following single-quoted expression is intentionally a jq program.
  # shellcheck disable=SC2016
  printf '%s' "$encoded" | timeout --signal=TERM \
    --kill-after="${COMMAND_KILL_GRACE_SECONDS}s" \
    "$((EVIDENCE_VALIDATION_SECONDS - COMMAND_KILL_GRACE_SECONDS))s" \
    base64 --decode | \
    timeout --signal=TERM --kill-after="${COMMAND_KILL_GRACE_SECONDS}s" \
      "$((EVIDENCE_VALIDATION_SECONDS - COMMAND_KILL_GRACE_SECONDS))s" \
      jq -eS -s \
    --arg expected_campaign_id "$CAMPAIGN_ID" \
    --arg expected_release_digest "$RELEASE_DIGEST" \
    --arg expected_topology_config_epoch "$TOPOLOGY_CONFIG_EPOCH" \
    --arg expected_invocation_id "$INVOCATION_ID" \
    --arg expected_lease_binding "$LEASE_BINDING" \
    --arg expected_lease_fence "$LEASE_FENCE" \
    --arg expected_operation_id "$expected_operation" \
    --arg expected_operation_nonce "$expected_nonce" \
    --arg expected_auth_failure_delta "$expected_auth_delta" \
    --arg expected_success_delta "$expected_success_delta" \
    --arg expected_member_ordinal "$expected_member" \
    --arg expected_checkpoint_id "$expected_checkpoint" \
    --arg expected_phase "$expected_phase" \
    --arg expected_step "$expected_step" \
    --arg expected_referenced_probe_operation_id \
      "$EXPECTED_REFERENCED_PROBE_OPERATION_ID" \
    --arg expected_referenced_probe_operation_nonce \
      "$EXPECTED_REFERENCED_PROBE_OPERATION_NONCE" \
    --arg expected_probe_receipt_set_binding \
      "$EXPECTED_PROBE_RECEIPT_SET_BINDING" \
    --arg expected_probe_checkpoint_id "$EXPECTED_PROBE_CHECKPOINT_ID" \
    --arg expected_probe_process_binding "$EXPECTED_PROBE_PROCESS_BINDING" \
    --arg expected_member_auth_delta "$EXPECTED_MEMBER_AUTH_DELTA" \
    --arg expected_campaign_auth_delta "$EXPECTED_CAMPAIGN_AUTH_DELTA" \
    --argjson expected_probe_receipt_count "$EXPECTED_PROBE_RECEIPT_COUNT" \
    --argjson expected_members "$EXPECTED_MEMBERS" \
    --argjson expected_old_chain_failure_delta \
      "$OLD_CHAIN_EXPECTED_FAILURE_DELTA" \
    --argjson expected_required_remaining_seconds "$expected_remaining" \
    --argjson freshness_lower_bound "$((now_epoch - 30))" \
    --argjson freshness_upper_bound "$((now_epoch + 5))" \
    --argjson expected_max_auth_age_seconds "$MAX_AUTH_AGE_SECONDS" \
    --argjson expected_rotation_jitter_seconds "$ROTATION_JITTER_SECONDS" \
    --argjson expected_drain_seconds "$DRAIN_SECONDS" \
    --argjson expected_reconnect_max_seconds "$RECONNECT_MAX_SECONDS" \
    --argjson expected_observation_seconds "$OBSERVATION_SECONDS" \
    --argjson expected_rollback_budget_seconds "$ROLLBACK_BUDGET_SECONDS" \
    --argjson expected_hard_span_seconds "$HARD_SPAN_SECONDS" \
    --argjson expected_forward_campaign_seconds "$FORWARD_CAMPAIGN_SECONDS" \
    --argjson expected_forward_certificate_horizon_seconds \
      "$FORWARD_CERTIFICATE_HORIZON_SECONDS" '
    def one_of($allowed):
      . as $candidate | ($allowed | index($candidate)) != null;
    def bounded_integer:
      type == "number" and . >= 0 and . <= 9007199254740991 and floor == .;
    def u64:
      type == "string" and
      test("^(0|[1-9][0-9]{0,19})$") and
      (length < 20 or . <= "18446744073709551615");
    def u64_lte($left; $right):
      (($left | length) < ($right | length)) or
      ((($left | length) == ($right | length)) and $left <= $right);
    def u64_pair($before; $after):
      (($before == null) and ($after == null)) or
      (($before | u64) and ($after | u64) and u64_lte($before; $after));
    def u64_strict_pair($before; $after):
      ($before | u64) and ($after | u64) and
      u64_lte($before; $after) and $before != $after;
    def null_or_u64: . == null or u64;
    def null_or_nonce:
      . == null or (type == "string" and test("^[a-f0-9]{32}$"));
    def null_or_binding:
      . == null or (type == "string" and test("^sha256:[a-f0-9]{64}$"));
    def phase_step_pair($phase; $step):
      if $phase == "preflight" then
        ($step | one_of(["policy-binding", "manifest-validation"]))
      elif $phase == "overlap" then
        ($step | one_of([
          "fleet-checkpoint", "publication-material-validity", "publication",
          "source-ready", "controller-ready", "reauthentication", "drain",
          "directed-paths", "durable-readiness", "fleet-post-gate"
        ]))
      elif $phase == "renewed" then
        ($step | one_of([
          "fleet-checkpoint", "publication-material-validity", "publication",
          "source-ready", "controller-ready", "reauthentication", "drain",
          "directed-paths", "durable-readiness", "fleet-post-gate",
          "overlap-window"
        ]))
      elif $phase == "final" then
        ($step | one_of([
          "fleet-checkpoint", "publication-material-validity", "publication",
          "source-ready", "controller-ready", "reauthentication", "drain",
          "directed-paths", "durable-readiness", "fleet-post-gate",
          "negative-probe-baseline", "old-chain-rejection",
          "negative-probe-accounting"
        ]))
      elif $phase == "rollback-before-removal" then
        ($step | one_of([
          "rollback-trigger", "previous-rollback-validity",
          "publication-material-validity", "rollback-authorize-and-publish",
          "rollback-transition-readback",
          "source-ready", "controller-ready", "reauthentication", "drain",
          "directed-paths", "durable-readiness", "fleet-post-gate"
        ]))
      elif $phase == "rollback-converge-overlap" then
        ($step | one_of([
          "fallback-rollback-validity", "publication-material-validity",
          "rollback-authorize-and-publish", "rollback-transition-readback",
          "source-ready", "controller-ready",
          "reauthentication", "drain", "directed-paths", "durable-readiness",
          "fleet-post-gate"
        ]))
      elif ($phase == "rollback-before-removal-final" or
        $phase == "rollback-after-removal-final") then
        ($step | one_of([
          "fleet-checkpoint", "directed-paths", "durable-readiness",
          "fleet-post-gate"
        ]))
      elif $phase == "rollback-after-removal" then
        $step == "rollback-trigger"
      elif ($phase == "rollback-restore-overlap" or
        $phase == "rollback-restore-previous") then
        ($step | one_of([
          "publication-material-validity", "rollback-authorize-and-publish",
          "rollback-transition-readback",
          "source-ready", "controller-ready", "reauthentication", "drain",
          "directed-paths", "durable-readiness", "fleet-post-gate"
        ]))
      elif $phase == "rollback-overlap-restored" then
        ($step | one_of([
          "fleet-checkpoint", "directed-paths", "durable-readiness",
          "fleet-post-gate", "previous-rollback-validity"
        ]))
      elif $phase == "withdrawal" then $step == "withdrawal"
      elif $phase == "complete" then $step == "campaign-status"
      else false
      end;
    def complete_gate($e; $expected_auth):
      $e.withdrawal_state == "not-withdrawn" and
      $e.ready_sources == $e.expected_members and
      $e.ready_controllers == $e.expected_members and
      $e.series_complete == true and $e.reset_count == 0 and
      $e.process_incarnation_changes == 0 and $e.saturated_series == 0 and
      $e.min_expiry_remaining_seconds >= $e.required_remaining_seconds and
      $e.affected_paths_passed == $e.affected_paths_expected and
      $e.durable_ready == true and
      $e.fresh_reachable_voters >= $e.required_quorum and
      $e.agreeing_voters >= $e.required_quorum and
      $e.retained_delta == "0" and $e.rejected_delta == "0" and
      $e.expired_delta == "0" and $e.drain_overrun_delta == "0" and
      $e.reconnect_failure_delta == "0" and
      $e.auth_or_trust_failure_delta == $expected_auth and
      ($e.process_incarnation_set_binding | type == "string" and
        test("^sha256:[a-f0-9]{64}$"));

    if length != 1 then
      error("expected exactly one evidence document")
    else
      .[0] as $e |
      if (
        ($e | type == "object") and
        (($e | keys | sort) == ([
          "affected_paths_expected", "affected_paths_passed", "agreeing_voters",
          "auth_or_trust_failure_delta", "campaign_id", "checkpoint_id",
          "auth_alert_silenced_or_inhibited", "critical_auth_alert_visible",
          "controller_epoch_after",
          "controller_epoch_before", "drain_overrun_delta", "drain_seconds",
          "durable_ready", "exit_status", "expected_members", "expired_delta",
          "expected_campaign_auth_delta", "expected_member_auth_delta",
          "forward_campaign_seconds", "forward_certificate_horizon_seconds",
          "fresh_reachable_voters", "hard_span_seconds", "invocation_id",
          "lease_binding", "lease_fence", "max_auth_age_seconds", "member_ordinal",
          "min_expiry_remaining_seconds", "phase", "process_incarnation_changes",
          "process_incarnation_set_binding", "probe_checkpoint_id",
          "probe_process_incarnation_set_binding", "probe_receipt_count",
          "probe_receipt_set_binding",
          "operation_id", "operation_nonce", "observation_seconds",
          "old_chain_expected_failure_delta",
          "observed_campaign_auth_delta", "observed_member_auth_delta",
          "ready_controllers", "ready_sources", "reconnect_max_seconds",
          "reconnect_failure_delta", "rejected_delta", "release_digest",
          "referenced_probe_operation_id", "referenced_probe_operation_nonce",
          "required_quorum", "required_remaining_seconds", "reset_count",
          "retained_delta", "rollback_budget_seconds",
          "rotation_jitter_seconds", "saturated_series", "schema",
          "series_complete", "source_version_after", "source_version_before", "step",
          "success_delta", "topology_config_epoch", "unaccounted_auth_delta",
          "utc_timestamp", "withdrawal_state"
        ] | sort)) and
        $e.schema == "opc.security.rotation.evidence.v1" and
        $e.campaign_id == $expected_campaign_id and
        $e.release_digest == $expected_release_digest and
        $e.topology_config_epoch == $expected_topology_config_epoch and
        ($e.topology_config_epoch | u64) and
        $e.invocation_id == $expected_invocation_id and
        ($e.invocation_id | test("^[a-f0-9]{32}$")) and
        $e.lease_binding == $expected_lease_binding and
        ($e.lease_binding | test("^sha256:[a-f0-9]{64}$")) and
        $e.lease_fence == $expected_lease_fence and
        ($e.lease_fence | u64) and
        $e.operation_id == $expected_operation_id and
        ($e.operation_id | u64) and
        $e.operation_nonce == $expected_operation_nonce and
        ($e.operation_nonce | test("^[a-f0-9]{32}$")) and
        (($expected_member_ordinal == "null" and $e.member_ordinal == null) or
          ($expected_member_ordinal != "null" and
            ($e.member_ordinal | tostring) == $expected_member_ordinal)) and
        (($expected_checkpoint_id == "null" and $e.checkpoint_id == null) or
          ($expected_checkpoint_id != "null" and
            $e.checkpoint_id == $expected_checkpoint_id and
            ($e.checkpoint_id | u64))) and
        $e.max_auth_age_seconds == $expected_max_auth_age_seconds and
        $e.rotation_jitter_seconds == $expected_rotation_jitter_seconds and
        $e.drain_seconds == $expected_drain_seconds and
        $e.reconnect_max_seconds == $expected_reconnect_max_seconds and
        $e.observation_seconds == $expected_observation_seconds and
        $e.rollback_budget_seconds == $expected_rollback_budget_seconds and
        $e.forward_campaign_seconds == $expected_forward_campaign_seconds and
        $e.forward_certificate_horizon_seconds ==
          $expected_forward_certificate_horizon_seconds and
        $e.forward_certificate_horizon_seconds ==
          ($e.forward_campaign_seconds + $e.hard_span_seconds) and
        $e.required_remaining_seconds == $expected_required_remaining_seconds and
        $e.old_chain_expected_failure_delta == $expected_old_chain_failure_delta and
        $e.hard_span_seconds == $expected_hard_span_seconds and
        $e.hard_span_seconds == (
          $e.max_auth_age_seconds + $e.rotation_jitter_seconds +
          $e.drain_seconds + $e.reconnect_max_seconds +
          $e.observation_seconds + $e.rollback_budget_seconds
        ) and
        $e.phase == $expected_phase and
        $e.step == $expected_step and
        phase_step_pair($e.phase; $e.step) and
        ($e.phase | one_of([
          "preflight", "overlap", "renewed", "final",
          "rollback-before-removal", "rollback-before-removal-final",
          "rollback-after-removal",
          "rollback-converge-overlap", "rollback-overlap-restored",
          "rollback-restore-overlap",
          "rollback-restore-previous", "rollback-after-removal-final",
          "withdrawal", "complete"
        ])) and
        ($e.step | one_of([
          "policy-binding", "manifest-validation", "fleet-checkpoint",
          "source-ready", "controller-ready", "reauthentication", "drain",
          "directed-paths", "durable-readiness", "fleet-post-gate",
          "publication", "rollback-authorize-and-publish", "rollback-trigger",
          "previous-rollback-validity", "fallback-rollback-validity",
          "publication-material-validity", "rollback-transition-readback",
          "withdrawal", "overlap-window",
          "negative-probe-baseline", "old-chain-rejection",
          "negative-probe-accounting", "campaign-status"
        ])) and
        $e.expected_members == $expected_members and
        (($e.member_ordinal == null) or
          (($e.member_ordinal | bounded_integer) and
            $e.member_ordinal < $e.expected_members)) and
        u64_pair($e.source_version_before; $e.source_version_after) and
        u64_pair($e.controller_epoch_before; $e.controller_epoch_after) and
        (($e.step != "source-ready") or
          u64_strict_pair($e.source_version_before; $e.source_version_after)) and
        (($e.step != "controller-ready") or
          u64_strict_pair($e.controller_epoch_before;
            $e.controller_epoch_after)) and
        (($e.step != "directed-paths") or
          $e.affected_paths_expected > 0) and
        ([$e.success_delta, $e.retained_delta, $e.rejected_delta,
          $e.expired_delta, $e.drain_overrun_delta,
          $e.auth_or_trust_failure_delta, $e.reconnect_failure_delta,
          $e.expected_member_auth_delta, $e.observed_member_auth_delta,
          $e.expected_campaign_auth_delta, $e.observed_campaign_auth_delta,
          $e.unaccounted_auth_delta]
          | all(.[]; u64)) and
        $e.success_delta == $expected_success_delta and
        $e.auth_or_trust_failure_delta == $expected_auth_failure_delta and
        ([$e.ready_sources, $e.ready_controllers,
          $e.min_expiry_remaining_seconds, $e.affected_paths_expected,
          $e.affected_paths_passed, $e.fresh_reachable_voters,
          $e.agreeing_voters, $e.required_quorum, $e.reset_count,
          $e.process_incarnation_changes, $e.max_auth_age_seconds,
          $e.rotation_jitter_seconds, $e.drain_seconds,
          $e.reconnect_max_seconds, $e.observation_seconds,
          $e.old_chain_expected_failure_delta,
          $e.rollback_budget_seconds, $e.required_remaining_seconds,
          $e.hard_span_seconds, $e.forward_campaign_seconds,
          $e.forward_certificate_horizon_seconds, $e.saturated_series,
          $e.probe_receipt_count]
          | all(.[]; bounded_integer)) and
        ($e.process_incarnation_set_binding | null_or_binding) and
        ($e.referenced_probe_operation_id | null_or_u64) and
        ($e.referenced_probe_operation_nonce | null_or_nonce) and
        ($e.probe_receipt_set_binding | null_or_binding) and
        ($e.probe_checkpoint_id | null_or_u64) and
        ($e.probe_process_incarnation_set_binding | null_or_binding) and
        $e.ready_sources <= $e.expected_members and
        $e.ready_controllers <= $e.expected_members and
        $e.affected_paths_expected <=
          ($e.expected_members * ($e.expected_members - 1)) and
        $e.affected_paths_passed <= $e.affected_paths_expected and
        ((($e.step != "old-chain-rejection") and
          ($e.step != "negative-probe-accounting")) or
          ($e.affected_paths_expected > 0 and
            $e.affected_paths_passed == $e.affected_paths_expected)) and
        $e.fresh_reachable_voters <= $e.expected_members and
        $e.agreeing_voters <= $e.expected_members and
        $e.saturated_series <= 12 and
        $e.required_quorum == (($e.expected_members / 2 | floor) + 1) and
        ($e.durable_ready | type == "boolean") and
        ((($e.durable_ready | not)) or
          ($e.fresh_reachable_voters >= $e.required_quorum and
            $e.agreeing_voters >= $e.required_quorum)) and
        ($e.series_complete | type == "boolean") and
        ($e.critical_auth_alert_visible | type == "boolean") and
        ($e.auth_alert_silenced_or_inhibited | type == "boolean") and
        ($e.exit_status | bounded_integer) and $e.exit_status <= 255 and
        (
          if $e.step == "withdrawal" then
            $e.exit_status == 0 and
            $e.withdrawal_state ==
              "ready-traffic-and-durable-mutations-withdrawn" and
            $e.member_ordinal == null and $e.checkpoint_id == null and
            $e.required_remaining_seconds == 0 and
            $e.ready_sources == 0 and $e.ready_controllers == 0 and
            $e.min_expiry_remaining_seconds == 0 and
            $e.affected_paths_expected == 0 and
            $e.affected_paths_passed == 0 and
            $e.fresh_reachable_voters == 0 and $e.agreeing_voters == 0 and
            $e.durable_ready == false and $e.series_complete == false and
            $e.reset_count == 0 and $e.process_incarnation_changes == 0 and
            $e.saturated_series == 0 and
            $e.process_incarnation_set_binding == null and
            $e.source_version_before == null and
            $e.source_version_after == null and
            $e.controller_epoch_before == null and
            $e.controller_epoch_after == null and
            $e.success_delta == "0" and $e.retained_delta == "0" and
            $e.rejected_delta == "0" and $e.expired_delta == "0" and
            $e.drain_overrun_delta == "0" and
            $e.auth_or_trust_failure_delta == "0" and
            $e.reconnect_failure_delta == "0" and
            $e.critical_auth_alert_visible == false and
            $e.auth_alert_silenced_or_inhibited == false and
            $e.referenced_probe_operation_id == null and
            $e.referenced_probe_operation_nonce == null and
            $e.probe_receipt_set_binding == null and
            $e.probe_receipt_count == 0 and $e.probe_checkpoint_id == null and
            $e.probe_process_incarnation_set_binding == null and
            $e.expected_member_auth_delta == "0" and
            $e.observed_member_auth_delta == "0" and
            $e.expected_campaign_auth_delta == "0" and
            $e.observed_campaign_auth_delta == "0" and
            $e.unaccounted_auth_delta == "0"
          elif $e.step == "old-chain-rejection" then
            $e.exit_status == 0 and complete_gate($e; $expected_auth_failure_delta) and
            $e.affected_paths_expected > 0 and
            $e.affected_paths_expected == $expected_probe_receipt_count and
            $e.referenced_probe_operation_id == null and
            $e.referenced_probe_operation_nonce == null and
            ($e.probe_receipt_set_binding | type == "string" and
              test("^sha256:[a-f0-9]{64}$")) and
            $e.probe_receipt_count == $expected_probe_receipt_count and
            $e.probe_checkpoint_id == $expected_checkpoint_id and
            $e.probe_process_incarnation_set_binding ==
              $e.process_incarnation_set_binding and
            $e.expected_member_auth_delta == $expected_member_auth_delta and
            $e.observed_member_auth_delta == $expected_member_auth_delta and
            $e.expected_campaign_auth_delta == $expected_campaign_auth_delta and
            $e.observed_campaign_auth_delta == $expected_campaign_auth_delta and
            $e.unaccounted_auth_delta == "0" and
            $e.auth_alert_silenced_or_inhibited == false
          elif $e.step == "negative-probe-accounting" then
            $e.exit_status == 0 and complete_gate($e; $expected_auth_failure_delta) and
            $e.affected_paths_expected == $expected_probe_receipt_count and
            $e.referenced_probe_operation_id ==
              $expected_referenced_probe_operation_id and
            $e.referenced_probe_operation_nonce ==
              $expected_referenced_probe_operation_nonce and
            $e.probe_receipt_set_binding == $expected_probe_receipt_set_binding and
            $e.probe_receipt_count == $expected_probe_receipt_count and
            $e.probe_checkpoint_id == $expected_probe_checkpoint_id and
            $e.probe_process_incarnation_set_binding ==
              $expected_probe_process_binding and
            $e.process_incarnation_set_binding == $expected_probe_process_binding and
            $e.expected_member_auth_delta == $expected_member_auth_delta and
            $e.observed_member_auth_delta == $expected_member_auth_delta and
            $e.expected_campaign_auth_delta == $expected_campaign_auth_delta and
            $e.observed_campaign_auth_delta == $expected_campaign_auth_delta and
            $e.unaccounted_auth_delta == "0" and
            $e.critical_auth_alert_visible == true and
            $e.auth_alert_silenced_or_inhibited == false
          else
            (($e.exit_status == 0) or
              ($e.step == "previous-rollback-validity" and $e.exit_status == 10)) and
            complete_gate($e; "0") and
            $e.referenced_probe_operation_id == null and
            $e.referenced_probe_operation_nonce == null and
            $e.probe_receipt_set_binding == null and
            $e.probe_receipt_count == 0 and $e.probe_checkpoint_id == null and
            $e.probe_process_incarnation_set_binding == null and
            $e.expected_member_auth_delta == "0" and
            $e.observed_member_auth_delta == "0" and
            $e.expected_campaign_auth_delta == "0" and
            $e.observed_campaign_auth_delta == "0" and
            $e.unaccounted_auth_delta == "0" and
            $e.auth_alert_silenced_or_inhibited == false
          end
        ) and
        ($e.utc_timestamp | type == "string" and
          test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$") and
          ((try fromdateiso8601 catch null) as $timestamp |
            ($timestamp | type == "number") and
            $timestamp >= $freshness_lower_bound and
            $timestamp <= $freshness_upper_bound))
      ) then
        $e
      else
        error("evidence document violates the closed schema")
      end
    end
  '
}

allocate_operation() {
  CURRENT_OPERATION_ID=$(capture_scalar "$STATE_OPERATION_SECONDS" \
    '^(0|[1-9][0-9]{0,19})$' 20 \
    campaign-state next-operation-id --state-dir "$STATE_DIR" \
    --invocation-id "$INVOCATION_ID") || return 1
  validate_u64 "$CURRENT_OPERATION_ID" || return 65
  CURRENT_OPERATION_NONCE=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n') || \
    return 1
  [[ "$CURRENT_OPERATION_NONCE" =~ ^[a-f0-9]{32}$ ]] || return 1
}

durable_publish_evidence() {
  local temporary=$1 destination=$2 soft_seconds
  soft_seconds=$((EVIDENCE_PUBLISH_SECONDS - COMMAND_KILL_GRACE_SECONDS))
  timeout --signal=TERM --kill-after="${COMMAND_KILL_GRACE_SECONDS}s" \
    "${soft_seconds}s" python3 - "$temporary" "$destination" \
    "$EVIDENCE_DIR" 2>/dev/null <<'PY'
import errno
import os
import stat
import sys

source, destination, directory = sys.argv[1:]
if os.path.dirname(source) != directory or os.path.dirname(destination) != directory:
    raise OSError(errno.EXDEV, "evidence paths must share the opened directory")
source_name = os.path.basename(source)
destination_name = os.path.basename(destination)
directory_fd = os.open(
    directory,
    os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
)
source_fd = os.open(
    source_name,
    os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
    dir_fd=directory_fd,
)
try:
    metadata = os.fstat(source_fd)
    if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600:
        raise OSError(errno.EPERM, "invalid pending evidence")
    os.fsync(source_fd)
    # link(2) is an atomic no-replace publication on this same filesystem.
    os.link(
        source_name,
        destination_name,
        src_dir_fd=directory_fd,
        dst_dir_fd=directory_fd,
        follow_symlinks=False,
    )
    os.fsync(directory_fd)
    os.unlink(source_name, dir_fd=directory_fd)
    os.fsync(directory_fd)
finally:
    os.close(directory_fd)
    os.close(source_fd)
PY
}

save_current_operation_evidence() {
  local name=$1 expected_phase=$2 expected_step=$3 expected_member=$4
  local expected_checkpoint=$5 expected_remaining=$6 command_timeout=$7
  local temporary destination command_status validation_status
  local reported_status='' line evidence_bindings expected_success_delta=0
  local index success_binding_count=0
  local -a pipeline_status
  local -a member_binding checkpoint_binding command_args
  shift 7
  command_args=("$@")
  [[ "$name" =~ ^[a-z0-9][a-z0-9-]{0,126}$ ]] || return 64
  case "$expected_phase" in
    preflight | overlap | renewed | final | rollback-before-removal | \
      rollback-before-removal-final | rollback-after-removal | \
      rollback-converge-overlap | rollback-overlap-restored | \
      rollback-restore-overlap | rollback-restore-previous | \
      rollback-after-removal-final | withdrawal | complete) ;;
    *) return 64 ;;
  esac
  case "$expected_step" in
    policy-binding | manifest-validation | fleet-checkpoint | source-ready | \
      controller-ready | reauthentication | drain | directed-paths | \
      durable-readiness | fleet-post-gate | publication | \
      rollback-authorize-and-publish | rollback-trigger | \
      previous-rollback-validity | fallback-rollback-validity | withdrawal | \
      publication-material-validity | rollback-transition-readback | \
      overlap-window | \
      negative-probe-baseline | old-chain-rejection | \
      negative-probe-accounting | campaign-status) ;;
    *) return 64 ;;
  esac
  [[ "$expected_member" == null || "$expected_member" =~ ^(0|[1-9][0-9]*)$ ]] || \
    return 64
  [[ "$expected_checkpoint" == null || \
    "$expected_checkpoint" =~ ^(0|[1-9][0-9]{0,19})$ ]] || return 64
  validate_duration "$expected_remaining" || return 64
  validate_duration "$command_timeout" || return 64
  for ((index = 0; index < ${#command_args[@]}; index++)); do
    if [[ ${command_args[$index]} == --target-success-delta ]]; then
      ((index + 1 < ${#command_args[@]})) || return 64
      expected_success_delta=${command_args[$((index + 1))]}
      validate_u64 "$expected_success_delta" || return 64
      success_binding_count=$((success_binding_count + 1))
    fi
  done
  ((success_binding_count <= 1)) || return 64
  if [[ "$expected_member" == null ]]; then
    member_binding=(--evidence-member-null)
  else
    member_binding=(--evidence-member-ordinal "$expected_member")
  fi
  if [[ "$expected_checkpoint" == null ]]; then
    checkpoint_binding=(--evidence-checkpoint-null)
  else
    checkpoint_binding=(--evidence-checkpoint-id "$expected_checkpoint")
  fi
  temporary=$(timeout --signal=TERM \
    --kill-after="${COMMAND_KILL_GRACE_SECONDS}s" \
    "$((EVIDENCE_STAGE_SECONDS - COMMAND_KILL_GRACE_SECONDS))s" \
    mktemp "$EVIDENCE_DIR/.pending.XXXXXX" 2>/dev/null) || {
    printf '%s\n' 'rotation campaign: evidence staging unavailable' >&2
    return 1
  }
  set +e
  run_cnfctl "$command_timeout" "$@" \
    --evidence-invocation-id "$INVOCATION_ID" \
    --evidence-lease-binding "$LEASE_BINDING" \
    --evidence-lease-fence "$LEASE_FENCE" \
    --evidence-operation-id "$CURRENT_OPERATION_ID" \
    --evidence-operation-nonce "$CURRENT_OPERATION_NONCE" \
    --evidence-phase "$expected_phase" --evidence-step "$expected_step" \
    "${member_binding[@]}" "${checkpoint_binding[@]}" \
    --evidence-required-remaining-seconds "$expected_remaining" \
    --evidence-expected-success-delta "$expected_success_delta" \
    | validate_evidence "$expected_phase" "$expected_step" "$expected_member" \
      "$expected_checkpoint" "$expected_remaining" "$CURRENT_OPERATION_ID" \
      "$CURRENT_OPERATION_NONCE" "$EXPECTED_AUTH_FAILURE_DELTA" \
      "$expected_success_delta" "$command_timeout" \
      2> >(discard_cnfctl_stderr "$EVIDENCE_VALIDATION_SECONDS") \
    >"$temporary"
  pipeline_status=("${PIPESTATUS[@]}")
  set -e
  command_status=${pipeline_status[0]}
  validation_status=${pipeline_status[1]}
  if ((validation_status != 0)); then
    rm -f -- "$temporary" 2>/dev/null || true
    printf '%s\n' 'rotation campaign: evidence validation failed' >&2
    return 65
  fi
  while IFS= read -r line; do
    if [[ "$line" =~ ^[[:space:]]*\"exit_status\":[[:space:]]*([0-9]+),?$ ]]; then
      [[ -z "$reported_status" ]] || { reported_status=; break; }
      reported_status=${BASH_REMATCH[1]}
    fi
  done <"$temporary"
  if [[ -z "$reported_status" ]]; then
    rm -f -- "$temporary" 2>/dev/null || true
    return 65
  fi
  if [[ "$reported_status" != "$command_status" ]]; then
    rm -f -- "$temporary" 2>/dev/null || true
    return 65
  fi
  evidence_bindings=$(jq -er '[
      .process_incarnation_set_binding,
      (.probe_receipt_set_binding // ""),
      (.probe_receipt_count | tostring)
    ] | join("|")' "$temporary" 2>/dev/null) || {
    rm -f -- "$temporary" 2>/dev/null || true
    return 65
  }
  IFS='|' read -r LAST_EVIDENCE_PROCESS_BINDING \
    LAST_EVIDENCE_RECEIPT_SET_BINDING LAST_EVIDENCE_RECEIPT_COUNT \
    <<<"$evidence_bindings"
  [[ "$LAST_EVIDENCE_PROCESS_BINDING" =~ ^sha256:[a-f0-9]{64}$ || \
    "$expected_step" == withdrawal ]] || {
    rm -f -- "$temporary" 2>/dev/null || true
    return 65
  }
  [[ "$LAST_EVIDENCE_RECEIPT_COUNT" =~ ^(0|[1-9][0-9]{0,6})$ ]] || {
    rm -f -- "$temporary" 2>/dev/null || true
    return 65
  }
  destination="$EVIDENCE_DIR/$CURRENT_OPERATION_ID-$name.json"
  if ! durable_publish_evidence "$temporary" "$destination"; then
    rm -f -- "$temporary" 2>/dev/null || true
    printf '%s\n' 'rotation campaign: evidence publication failed' >&2
    return 1
  fi
  return "$command_status"
}

save_evidence() {
  allocate_operation || return 1
  save_current_operation_evidence "$@"
}

save_expected_auth_evidence() {
  local expected_delta=$1 saved_delta=$EXPECTED_AUTH_FAILURE_DELTA status
  shift
  validate_u64 "$expected_delta" || return 64
  EXPECTED_AUTH_FAILURE_DELTA=$expected_delta
  set +e
  save_evidence "$@"
  status=$?
  set -e
  EXPECTED_AUTH_FAILURE_DELTA=$saved_delta
  return "$status"
}

save_old_chain_probe_evidence() {
  local expected_delta=$1 expected_campaign_delta=$2 status
  local saved_auth=$EXPECTED_AUTH_FAILURE_DELTA
  local saved_count=$EXPECTED_PROBE_RECEIPT_COUNT
  local saved_member=$EXPECTED_MEMBER_AUTH_DELTA
  local saved_campaign=$EXPECTED_CAMPAIGN_AUTH_DELTA
  shift 2
  validate_u64 "$expected_delta" || return 64
  validate_u64 "$expected_campaign_delta" || return 64
  EXPECTED_AUTH_FAILURE_DELTA=$expected_delta
  EXPECTED_PROBE_RECEIPT_COUNT=$expected_delta
  EXPECTED_MEMBER_AUTH_DELTA=$expected_delta
  EXPECTED_CAMPAIGN_AUTH_DELTA=$expected_campaign_delta
  set +e
  save_evidence "$@"
  status=$?
  set -e
  EXPECTED_AUTH_FAILURE_DELTA=$saved_auth
  EXPECTED_PROBE_RECEIPT_COUNT=$saved_count
  EXPECTED_MEMBER_AUTH_DELTA=$saved_member
  EXPECTED_CAMPAIGN_AUTH_DELTA=$saved_campaign
  return "$status"
}

save_probe_accounting_evidence() {
  local expected_delta=$1 expected_campaign_delta=$2 probe_operation=$3
  local probe_nonce=$4 receipt_binding=$5 receipt_count=$6
  local probe_checkpoint=$7 probe_process_binding=$8 status
  local saved_auth=$EXPECTED_AUTH_FAILURE_DELTA
  local saved_ref_id=$EXPECTED_REFERENCED_PROBE_OPERATION_ID
  local saved_ref_nonce=$EXPECTED_REFERENCED_PROBE_OPERATION_NONCE
  local saved_receipt_binding=$EXPECTED_PROBE_RECEIPT_SET_BINDING
  local saved_receipt_count=$EXPECTED_PROBE_RECEIPT_COUNT
  local saved_checkpoint=$EXPECTED_PROBE_CHECKPOINT_ID
  local saved_process=$EXPECTED_PROBE_PROCESS_BINDING
  local saved_member=$EXPECTED_MEMBER_AUTH_DELTA
  local saved_campaign=$EXPECTED_CAMPAIGN_AUTH_DELTA
  shift 8
  validate_u64 "$expected_delta" || return 64
  validate_u64 "$expected_campaign_delta" || return 64
  validate_u64 "$probe_operation" || return 64
  [[ "$probe_nonce" =~ ^[a-f0-9]{32}$ ]] || return 64
  [[ "$receipt_binding" =~ ^sha256:[a-f0-9]{64}$ ]] || return 64
  [[ "$receipt_count" =~ ^(0|[1-9][0-9]{0,6})$ ]] || return 64
  validate_u64 "$probe_checkpoint" || return 64
  [[ "$probe_process_binding" =~ ^sha256:[a-f0-9]{64}$ ]] || return 64
  EXPECTED_AUTH_FAILURE_DELTA=$expected_delta
  EXPECTED_REFERENCED_PROBE_OPERATION_ID=$probe_operation
  EXPECTED_REFERENCED_PROBE_OPERATION_NONCE=$probe_nonce
  EXPECTED_PROBE_RECEIPT_SET_BINDING=$receipt_binding
  EXPECTED_PROBE_RECEIPT_COUNT=$receipt_count
  EXPECTED_PROBE_CHECKPOINT_ID=$probe_checkpoint
  EXPECTED_PROBE_PROCESS_BINDING=$probe_process_binding
  EXPECTED_MEMBER_AUTH_DELTA=$expected_delta
  EXPECTED_CAMPAIGN_AUTH_DELTA=$expected_campaign_delta
  set +e
  save_evidence "$@"
  status=$?
  set -e
  EXPECTED_AUTH_FAILURE_DELTA=$saved_auth
  EXPECTED_REFERENCED_PROBE_OPERATION_ID=$saved_ref_id
  EXPECTED_REFERENCED_PROBE_OPERATION_NONCE=$saved_ref_nonce
  EXPECTED_PROBE_RECEIPT_SET_BINDING=$saved_receipt_binding
  EXPECTED_PROBE_RECEIPT_COUNT=$saved_receipt_count
  EXPECTED_PROBE_CHECKPOINT_ID=$saved_checkpoint
  EXPECTED_PROBE_PROCESS_BINDING=$saved_process
  EXPECTED_MEMBER_AUTH_DELTA=$saved_member
  EXPECTED_CAMPAIGN_AUTH_DELTA=$saved_campaign
  return "$status"
}

CURRENT_CHECKPOINT=
next_checkpoint() {
  CURRENT_CHECKPOINT_ID=$(capture_scalar "$STATE_OPERATION_SECONDS" \
    '^(0|[1-9][0-9]{0,19})$' 20 \
    campaign-state next-checkpoint-id --state-dir "$STATE_DIR" \
    --invocation-id "$INVOCATION_ID") || return 1
  validate_u64 "$CURRENT_CHECKPOINT_ID" || return 65
  CURRENT_CHECKPOINT="$STATE_DIR/checkpoint-$CURRENT_CHECKPOINT_ID.bin"
  [[ ! -e "$CURRENT_CHECKPOINT" ]] || return 65
}

fleet_checkpoint() {
  local phase=$1 member=$2 required_remaining=$3 member_args=()
  local evidence_member=null
  next_checkpoint || return 1
  if [[ "$member" != fleet ]]; then
    member_args=(--member-ordinal "$member")
    evidence_member=$member
  fi
  save_evidence "$phase-$member-checkpoint" "$phase" fleet-checkpoint \
    "$evidence_member" "$CURRENT_CHECKPOINT_ID" "$required_remaining" \
    "$CHECKPOINT_SECONDS" \
    fleet-checkpoint \
    --namespace "$NS" --workload "$WORKLOAD" --selector "$SELECTOR" \
    --state-dir "$STATE_DIR" --phase "$phase" "${member_args[@]}" \
    --checkpoint-output "$CURRENT_CHECKPOINT" \
    --checkpoint-id "$CURRENT_CHECKPOINT_ID" \
    --hard-span-seconds "$HARD_SPAN_SECONDS" \
    --rollback-budget-seconds "$ROLLBACK_BUDGET_SECONDS" --saturated-series 0 \
    --allow-only-accounted-campaign-negative-probe-alerts \
    --reject-any-unaccounted-or-silenced-alert
}

post_member_gate() {
  local phase=$1 member=$2 checkpoint=$3 checkpoint_id=$4 required_remaining=$5
  save_evidence "$phase-$member-source" "$phase" source-ready \
    "$member" "$checkpoint_id" "$required_remaining" "$SOURCE_WAIT_SECONDS" \
    wait-source-material \
    --state-dir "$STATE_DIR" --checkpoint "$checkpoint" \
    --member-ordinal "$member" --availability ready \
    --require-version-advance --timeout 590s || return 1
  save_evidence "$phase-$member-controller" "$phase" controller-ready \
    "$member" "$checkpoint_id" "$required_remaining" \
    "$CONTROLLER_WAIT_SECONDS" \
    wait-material \
    --state-dir "$STATE_DIR" --checkpoint "$checkpoint" \
    --member-ordinal "$member" --availability ready \
    --require-version-advance --timeout 590s || return 1
  save_evidence "$phase-$member-reauth" "$phase" reauthentication \
    "$member" "$checkpoint_id" "$required_remaining" \
    "$REAUTHENTICATION_SECONDS" \
    request-reauthentication \
    --state-dir "$STATE_DIR" --affected-member-ordinal "$member" \
    --both-path-ends || return 1
  save_evidence "$phase-$member-drained" "$phase" drain \
    "$member" "$checkpoint_id" "$required_remaining" "$DRAIN_WAIT_SECONDS" \
    wait-drained \
    --state-dir "$STATE_DIR" --affected-member-ordinal "$member" \
    --both-path-ends --draining 0 --timeout "${DRAIN_SECONDS}s" || return 1
  save_evidence "$phase-$member-directed" "$phase" directed-paths \
    "$member" "$checkpoint_id" "$required_remaining" \
    "$DIRECTED_PROBE_SECONDS" \
    probe-directed-current-material \
    --state-dir "$STATE_DIR" --affected-member-ordinal "$member" \
    --both-directions --fresh-full-handshake --reject-resumption || return 1
  save_evidence "$phase-$member-durable" "$phase" durable-readiness \
    "$member" "$checkpoint_id" "$required_remaining" \
    "$DURABLE_PROBE_SECONDS" \
    probe-durable-ready \
    --state-dir "$STATE_DIR" --all-members --fresh-barrier \
    --require-ready --require-quorum-inequalities || return 1
  save_evidence "$phase-$member-fleet-post-gate" "$phase" fleet-post-gate \
    "$member" "$checkpoint_id" "$required_remaining" "$POST_GATE_SECONDS" \
    fleet-post-gate \
    --state-dir "$STATE_DIR" --checkpoint "$checkpoint" \
    --target-member-ordinal "$member" --target-success-delta 1 \
    --require-all-sources-ready --require-all-controllers-ready \
    --require-complete-series --reject-process-or-counter-reset \
    --retained-delta 0 --rejected-delta 0 --expired-delta 0 \
    --drain-overrun-delta 0 --auth-or-trust-failure-delta 0 \
    --reconnect-failure-delta 0 \
    --saturated-series 0 \
    --minimum-expiry-remaining "$required_remaining"
}

validate_publication_material() {
  local phase=$1 member=$2 checkpoint=$3 checkpoint_id=$4
  local target_manifest=$5 rollback_manifest=$6 required_remaining=$7
  save_evidence "$phase-$member-publication-material-valid" "$phase" \
    publication-material-validity "$member" "$checkpoint_id" \
    "$required_remaining" "$VALIDITY_PROBE_SECONDS" \
    assert-publication-and-rollback-material-valid \
    --state-dir "$STATE_DIR" --checkpoint "$checkpoint" \
    --member-ordinal "$member" --target-manifest-set "$target_manifest" \
    --rollback-manifest-set "$rollback_manifest" \
    --minimum-expiry-remaining "$required_remaining" \
    --require-complete-chain --require-coherent-key --fresh-read
}

publish_member() {
  local phase=$1 member=$2 manifest_set=$3 rollback_manifest=$4 checkpoint
  local required_remaining
  required_remaining=$(remaining_forward_validity_seconds) || return 1
  fleet_checkpoint "$phase" "$member" "$required_remaining" || return 1
  checkpoint=$CURRENT_CHECKPOINT
  run_cnfctl "$STATE_OPERATION_SECONDS" campaign-state mark-touched \
    --state-dir "$STATE_DIR" \
    --phase "$phase" --member-ordinal "$member" >/dev/null || return 1
  validate_publication_material "$phase" "$member" "$checkpoint" \
    "$CURRENT_CHECKPOINT_ID" "$manifest_set" "$rollback_manifest" \
    "$required_remaining" || return 1
  save_evidence "$phase-$member-publication" "$phase" publication \
    "$member" "$CURRENT_CHECKPOINT_ID" "$required_remaining" \
    "$PUBLICATION_SECONDS" \
    publish-complete-material \
    --state-dir "$STATE_DIR" --checkpoint "$checkpoint" \
    --member-ordinal "$member" --manifest-set "$manifest_set" \
    --rollback-manifest-set "$rollback_manifest" \
    --minimum-expiry-remaining "$required_remaining" \
    --revalidate-target-and-rollback-immediately-before-write \
    --exactly-one-member --complete-secret --atomic-projected-generation || return 1
  post_member_gate "$phase" "$member" "$checkpoint" \
    "$CURRENT_CHECKPOINT_ID" "$required_remaining"
}

publish_phase() {
  local phase=$1 manifest_set=$2 rollback_manifest=$3 member
  for member in "${MEMBERS[@]}"; do
    publish_member "$phase" "$member" "$manifest_set" "$rollback_manifest" || \
      return 1
  done
}

state_members() {
  local list_kind=$1 phases=$2 cardinality=$3 output member expected
  local -A seen=()
  case "$cardinality" in
    allow-empty | nonempty | all) ;;
    *) return 64 ;;
  esac
  STATE_MEMBERS=()
  capture_cnfctl_bounded leased "$STATE_OPERATION_SECONDS" 64 \
    campaign-state list-members --state-dir "$STATE_DIR" --kind "$list_kind" \
    --phases "$phases" --unique --reverse || return 1
  output=$CAPTURED_OUTPUT
  if [[ "$output" == *$'\n' ]]; then output=${output%$'\n'}; fi
  ((${#output} <= 64)) || return 65
  while IFS= read -r member; do
    [[ -z "$member" ]] && continue
    [[ "$member" =~ ^(0|[1-9][0-9]*)$ ]] || return 65
    [[ -n ${SEEN_MEMBERS[$member]+present} ]] || return 65
    [[ -z ${seen[$member]+present} ]] || return 65
    seen[$member]=present
    STATE_MEMBERS+=("$member")
  done <<<"$output"
  case "$cardinality" in
    allow-empty) ;;
    nonempty)
      ((${#STATE_MEMBERS[@]} > 0)) || return 65
      ;;
    all)
      ((${#STATE_MEMBERS[@]} == ${#MEMBERS[@]})) || return 65
      for expected in "${MEMBERS[@]}"; do
        [[ -n ${seen[$expected]+present} ]] || return 65
      done
      ;;
  esac
}

remaining_rollback_seconds() {
  local now_epoch remaining
  ((ACTIVE_DEADLINE_EPOCH > 0)) || return 64
  now_epoch=$(date -u +%s) || return 1
  remaining=$((ACTIVE_DEADLINE_EPOCH - now_epoch))
  ((remaining > COMMAND_KILL_GRACE_SECONDS)) || return 75
  printf '%s' "$remaining"
}

remaining_forward_validity_seconds() {
  local now_epoch remaining
  ((FORWARD_DEADLINE_EPOCH > 0)) || return 64
  now_epoch=$(date -u +%s) || return 1
  remaining=$((FORWARD_DEADLINE_EPOCH - now_epoch))
  ((remaining > COMMAND_KILL_GRACE_SECONDS)) || return 75
  printf '%s' "$((remaining + HARD_SPAN_SECONDS))"
}

rollback_member() {
  local phase=$1 member=$2 manifest_set=$3 checkpoint required_remaining
  local transition_outcome transition_key
  next_checkpoint || return 1
  checkpoint=$CURRENT_CHECKPOINT
  transition_key="$phase/member-$member"
  transition_outcome=$(capture_scalar "$STATE_OPERATION_SECONDS" \
    '^(apply|complete)$' 8 campaign-state prepare-rollback-member \
    --state-dir "$STATE_DIR" --phase "$phase" --member-ordinal "$member" \
    --transition-key "$transition_key" --durable-fenced-exactly-once) || return 1
  required_remaining=$(remaining_rollback_seconds) || return 1
  if [[ "$transition_outcome" == complete ]]; then
    save_evidence "$phase-$member-transition-readback" "$phase" \
      rollback-transition-readback "$member" "$CURRENT_CHECKPOINT_ID" \
      "$required_remaining" "$POST_GATE_SECONDS" \
      readback-completed-rollback-member --state-dir "$STATE_DIR" \
      --phase "$phase" --member-ordinal "$member" \
      --transition-key "$transition_key" --manifest-set "$manifest_set" \
      --require-exactly-once-terminal-state --require-no-new-fleet-mutation \
      --minimum-expiry-remaining "$required_remaining"
    return $?
  fi
  validate_publication_material "$phase" "$member" "$checkpoint" \
    "$CURRENT_CHECKPOINT_ID" "$manifest_set" "$manifest_set" \
    "$required_remaining" || return 1
  required_remaining=$(remaining_rollback_seconds) || return 1
  save_evidence "$phase-$member-safety-and-publication" "$phase" \
    rollback-authorize-and-publish "$member" "$CURRENT_CHECKPOINT_ID" \
    "$required_remaining" "$PUBLICATION_SECONDS" \
    authorize-and-publish-rollback \
    --state-dir "$STATE_DIR" --phase "$phase" --member-ordinal "$member" \
    --transition-key "$transition_key" --durable-fenced-exactly-once \
    --return-stored-terminal-result-after-response-loss \
    --manifest-set "$manifest_set" --checkpoint-output "$checkpoint" \
    --minimum-expiry-remaining "$required_remaining" --fresh-safety-gate \
    --revalidate-selected-manifest-immediately-before-write \
    --refuse-unavailable-plus-retaining --exactly-one-member || return 1
  required_remaining=$(remaining_rollback_seconds) || return 1
  post_member_gate "$phase" "$member" "$checkpoint" \
    "$CURRENT_CHECKPOINT_ID" "$required_remaining"
}

final_fleet_gate() {
  local phase=$1 checkpoint required_remaining
  if ((ACTIVE_DEADLINE_EPOCH > 0)); then
    required_remaining=$(remaining_rollback_seconds) || return 1
  else
    required_remaining=$(remaining_forward_validity_seconds) || return 1
  fi
  fleet_checkpoint "$phase" fleet "$required_remaining" || return 1
  checkpoint=$CURRENT_CHECKPOINT
  if ((ACTIVE_DEADLINE_EPOCH > 0)); then
    required_remaining=$(remaining_rollback_seconds) || return 1
  fi
  save_evidence "$phase-all-directed" "$phase" directed-paths \
    null "$CURRENT_CHECKPOINT_ID" "$required_remaining" \
    "$DIRECTED_PROBE_SECONDS" \
    probe-directed-current-material \
    --state-dir "$STATE_DIR" --all-members --both-directions \
    --fresh-full-handshake --reject-resumption || return 1
  save_evidence "$phase-durable" "$phase" durable-readiness \
    null "$CURRENT_CHECKPOINT_ID" "$required_remaining" \
    "$DURABLE_PROBE_SECONDS" \
    probe-durable-ready \
    --state-dir "$STATE_DIR" --all-members --fresh-barrier \
    --require-ready --require-quorum-inequalities || return 1
  save_evidence "$phase-fleet-post-gate" "$phase" fleet-post-gate \
    null "$CURRENT_CHECKPOINT_ID" "$required_remaining" "$POST_GATE_SECONDS" \
    fleet-post-gate \
    --state-dir "$STATE_DIR" --checkpoint "$checkpoint" \
    --target-success-delta 0 --require-all-sources-ready \
    --require-all-controllers-ready --require-complete-series \
    --reject-process-or-counter-reset --retained-delta 0 --rejected-delta 0 \
    --expired-delta 0 --drain-overrun-delta 0 \
    --auth-or-trust-failure-delta 0 --reconnect-failure-delta 0 \
    --saturated-series 0 \
    --minimum-expiry-remaining "$required_remaining"
}

remaining_withdrawal_seconds() {
  local now_epoch remaining
  ((WITHDRAWAL_ACTION_DEADLINE_EPOCH > 0)) || return 64
  now_epoch=$(date -u +%s) || return 1
  remaining=$((WITHDRAWAL_ACTION_DEADLINE_EPOCH - now_epoch))
  ((remaining > COMMAND_KILL_GRACE_SECONDS)) || return 75
  printf '%s' "$remaining"
}

withdrawal_outcome() {
  local mode=$1 idempotency_key=$2 remaining
  remaining=$(remaining_withdrawal_seconds) || return 1
  capture_cnfctl_bounded "$mode" "$remaining" 16 \
    withdrawal-operation-outcome --state-dir "$STATE_DIR" \
    --campaign-id "$CAMPAIGN_ID" --idempotency-key "$idempotency_key" \
    --output-format committed-or-not-committed || return 1
  case "$CAPTURED_OUTPUT" in
    committed | committed$'\n') printf '%s' committed ;;
    not-committed | not-committed$'\n') printf '%s' not-committed ;;
    *) return 65 ;;
  esac
}

perform_withdrawal_attempt() {
  local mode=$1 idempotency_key=$2 remaining command_deadline action_status
  shift 2
  WITHDRAWAL_ATTEMPT_RESULT=internal-failure
  WITHDRAWAL_ACTION_STATUS=0
  remaining=$(remaining_withdrawal_seconds) || return 1
  if [[ "$mode" == leased ]]; then
    command_deadline=$WITHDRAWAL_ACTION_DEADLINE_EPOCH
    # This explicit result is the only proven pre-action renewal outcome. A raw
    # action exit status, including 76, is never interpreted as this result.
    if ! renew_lease_for "$command_deadline"; then
      WITHDRAWAL_ATTEMPT_RESULT=pre-action-renewal-failed
      return 0
    fi
    remaining=$(remaining_withdrawal_seconds) || return 1
    WITHDRAWAL_ACTION_STARTED=1
    WITHDRAWAL_ATTEMPT_RESULT=action-returned
    if run_cnfctl_raw "$remaining" "$@" \
      --idempotency-key "$idempotency_key" \
      --idempotent-exactly-once --no-evidence >/dev/null
    then
      action_status=0
    else
      action_status=$?
    fi
  else
    WITHDRAWAL_ACTION_STARTED=1
    WITHDRAWAL_ATTEMPT_RESULT=action-returned
    if run_cnfctl_unleased "$remaining" "$@" \
      --idempotency-key "$idempotency_key" \
      --idempotent-exactly-once --no-evidence >/dev/null
    then
      action_status=0
    else
      action_status=$?
    fi
  fi
  WITHDRAWAL_ACTION_STATUS=$action_status
  return 0
}

reconcile_withdrawal() {
  local mode=$1 idempotency_key=$2 attempt action_status outcome
  shift 2
  for ((attempt = 1; attempt <= 2; attempt++)); do
    perform_withdrawal_attempt "$mode" "$idempotency_key" "$@" || return 1
    case "$WITHDRAWAL_ATTEMPT_RESULT" in
      pre-action-renewal-failed)
        # With no prior action this is definitively pre-action. If an earlier
        # attempt ran, its outcome remains ambiguous and still needs readback.
        ((WITHDRAWAL_ACTION_STARTED == 1)) || return 76
        ;;
      action-returned)
        ((WITHDRAWAL_ACTION_STARTED == 1)) || return 65
        action_status=$WITHDRAWAL_ACTION_STATUS
        ((action_status >= 0 && action_status <= 255)) || return 65
        # Every raw action status, including 76, is ambiguous until readback.
        ;;
      *) return 65 ;;
    esac
    if outcome=$(withdrawal_outcome "$mode" "$idempotency_key"); then
      if [[ "$outcome" == committed ]]; then
        WITHDRAWAL_ACTION_COMMITTED=1
        return 0
      fi
    fi
    # Both a lost response and a failed readback are ambiguous. Retry only the
    # same durable idempotency key; the authority must return the stored result
    # and must never execute a second effective fleet action.
  done
  return 1
}

withdraw_serving() {
  local action_status evidence_status=0 operation_available=0
  local saved_deadline=$ACTIVE_DEADLINE_EPOCH idempotency_key mode now_epoch
  local -a action_command
  if ((WITHDRAWAL_ATTEMPTED == 1)); then
    printf '%s\n' 'rotation campaign: serving withdrawal already attempted' >&2
    return 1
  fi
  WITHDRAWAL_ATTEMPTED=1
  WITHDRAWAL_ACTION_STARTED=0
  WITHDRAWAL_ACTION_COMMITTED=0
  WITHDRAWAL_ATTEMPT_RESULT=not-run
  WITHDRAWAL_ACTION_STATUS=0
  ACTIVE_DEADLINE_EPOCH=0
  now_epoch=$(date -u +%s) || return 1
  WITHDRAWAL_ACTION_DEADLINE_EPOCH=$((now_epoch + WITHDRAWAL_SECONDS))
  if ((LEASE_ACQUIRED == 1)); then
    if allocate_operation; then operation_available=1; fi
    mode=leased
    if ((operation_available == 1)); then
      idempotency_key="operation-$CURRENT_OPERATION_ID-$CURRENT_OPERATION_NONCE"
      action_command=(withdraw-ready-traffic-and-durable-mutations \
        --state-dir "$STATE_DIR" --namespace "$NS" --selector "$SELECTOR" \
        --operation-id "$CURRENT_OPERATION_ID" \
        --operation-nonce "$CURRENT_OPERATION_NONCE")
    else
      # The allocator-independent authority uses a stable campaign key. It is
      # action-first, fenced by the lease, and still exactly-once on retry.
      idempotency_key="emergency-$CAMPAIGN_ID-$TOPOLOGY_CONFIG_EPOCH"
      action_command=(emergency-withdraw-ready-traffic-and-durable-mutations \
        --state-dir "$STATE_DIR" --namespace "$NS" --selector "$SELECTOR" \
        --campaign-id "$CAMPAIGN_ID")
    fi
  else
    mode=unleased
    idempotency_key="emergency-$CAMPAIGN_ID-$TOPOLOGY_CONFIG_EPOCH"
    action_command=(emergency-withdraw-ready-traffic-and-durable-mutations \
      --state-dir "$STATE_DIR" --namespace "$NS" --selector "$SELECTOR" \
      --campaign-id "$CAMPAIGN_ID" --release-digest "$RELEASE_DIGEST" \
      --topology-config-epoch "$TOPOLOGY_CONFIG_EPOCH")
  fi
  if reconcile_withdrawal "$mode" "$idempotency_key" \
    "${action_command[@]}"
  then
    action_status=0
  else
    action_status=$?
  fi
  WITHDRAWAL_ACTION_DEADLINE_EPOCH=0
  if ((action_status != 0 || WITHDRAWAL_ACTION_COMMITTED != 1)); then
    ACTIVE_DEADLINE_EPOCH=$saved_deadline
    printf '%s\n' 'rotation campaign: serving withdrawal failed' >&2
    return 1
  fi
  # Evidence is requested and persisted only after committed readback. Failure
  # here is explicit and fail-closed, but can never repeat the fleet action.
  if ((LEASE_ACQUIRED == 1 && operation_available == 1)); then
    save_current_operation_evidence withdrawal withdrawal withdrawal null null 0 \
      "$STATE_OPERATION_SECONDS" report-operation-evidence \
      --state-dir "$STATE_DIR" --operation-id "$CURRENT_OPERATION_ID" \
      --operation-nonce "$CURRENT_OPERATION_NONCE" \
      --require-committed-withdrawal-readback || evidence_status=$?
  else
    evidence_status=1
  fi
  if ((evidence_status != 0)); then
    ACTIVE_DEADLINE_EPOCH=$saved_deadline
    printf '%s\n' 'rotation campaign: withdrawal evidence unavailable' >&2
    return 1
  fi
  ACTIVE_DEADLINE_EPOCH=$saved_deadline
  return 0
}

rollback_before_removal() {
  local member previous_status required_remaining
  required_remaining=$(remaining_rollback_seconds) || return 1
  save_evidence rollback-before-removal-trigger rollback-before-removal \
    rollback-trigger null null "$required_remaining" "$STATE_OPERATION_SECONDS" \
    campaign-state begin-rollback \
    --state-dir "$STATE_DIR" --branch before-removal \
    --acknowledge-trigger --start-new-metric-checkpoint \
    --idempotent-readback-after-response-loss || return 1
  state_members touched overlap,renewed allow-empty || return 1

  required_remaining=$(remaining_rollback_seconds) || return 1
  set +e
  save_evidence rollback-before-removal-previous-valid rollback-before-removal \
    previous-rollback-validity null null "$required_remaining" \
    "$VALIDITY_PROBE_SECONDS" \
    assert-previous-rollback-valid --state-dir "$STATE_DIR" \
    --manifest-set "$PREVIOUS_OVERLAP_MANIFEST_SET" \
    --minimum-expiry-remaining "$required_remaining"
  previous_status=$?
  set -e
  case "$previous_status" in
    0)
      for member in "${MEMBERS[@]}"; do
        rollback_member rollback-before-removal "$member" \
          "$PREVIOUS_OVERLAP_MANIFEST_SET" || return 1
      done
      ;;
    10)
      save_evidence rollback-before-removal-fallback-valid \
        rollback-converge-overlap fallback-rollback-validity \
        null null "$required_remaining" "$VALIDITY_PROBE_SECONDS" \
        assert-new-svid-overlap-rollback-valid --state-dir "$STATE_DIR" \
        --manifest-set "$NEW_SVID_OVERLAP_MANIFEST_SET" \
        --minimum-expiry-remaining "$required_remaining" \
        --cover-partial-overlap-or-renewed \
        --cover-post-hard-span-pre-removal-marker || return 1
      for member in "${MEMBERS[@]}"; do
        rollback_member rollback-converge-overlap "$member" \
          "$NEW_SVID_OVERLAP_MANIFEST_SET" || return 1
      done
      ;;
    *) return 1 ;;
  esac
  final_fleet_gate rollback-before-removal-final
}

rollback_after_removal() {
  local member required_remaining previous_status
  required_remaining=$(remaining_rollback_seconds) || return 1
  save_evidence rollback-after-removal-trigger rollback-after-removal \
    rollback-trigger null null "$required_remaining" "$STATE_OPERATION_SECONDS" \
    campaign-state begin-rollback \
    --state-dir "$STATE_DIR" --branch after-removal \
    --acknowledge-trigger --start-new-metric-checkpoint \
    --idempotent-readback-after-response-loss || return 1
  state_members touched renewed all || return 1
  state_members removal-attempted final nonempty || return 1
  for member in "${STATE_MEMBERS[@]}"; do
    rollback_member rollback-restore-overlap "$member" \
      "$NEW_SVID_OVERLAP_MANIFEST_SET" || return 1
  done
  final_fleet_gate rollback-overlap-restored || return 1

  required_remaining=$(remaining_rollback_seconds) || return 1
  set +e
  save_evidence rollback-previous-valid rollback-overlap-restored \
    previous-rollback-validity null null "$required_remaining" \
    "$VALIDITY_PROBE_SECONDS" assert-previous-rollback-valid \
    --state-dir "$STATE_DIR" --manifest-set "$PREVIOUS_OVERLAP_MANIFEST_SET" \
    --minimum-expiry-remaining "$required_remaining"
  previous_status=$?
  set -e
  case "$previous_status" in
    0)
      state_members touched renewed all || return 1
      for member in "${STATE_MEMBERS[@]}"; do
        rollback_member rollback-restore-previous "$member" \
          "$PREVIOUS_OVERLAP_MANIFEST_SET" || return 1
      done
      ;;
    10)
      run_cnfctl "$STATE_OPERATION_SECONDS" campaign-state \
        retain-new-svid-overlap \
        --state-dir "$STATE_DIR" >/dev/null || return 1
      ;;
    *) return 1 ;;
  esac
  final_fleet_gate rollback-after-removal-final
}

run_rollback() {
  local branch now_epoch
  if ((ACTIVE_DEADLINE_EPOCH == 0)); then
    now_epoch=$(date -u +%s) || return 1
    ACTIVE_DEADLINE_EPOCH=$((now_epoch + ROLLBACK_BUDGET_SECONDS))
  fi
  branch=$(capture_scalar "$STATE_OPERATION_SECONDS" \
    '^(before-removal|after-removal)$' 14 \
    campaign-state rollback-branch --state-dir "$STATE_DIR") || return 1
  case "$branch" in
    before-removal) rollback_before_removal ;;
    after-removal) rollback_after_removal ;;
    *) return 65 ;;
  esac
}

abort_campaign() {
  local now_epoch
  if ((ACTIVE_DEADLINE_EPOCH == 0)); then
    now_epoch=$(date -u +%s) || return 1
    ACTIVE_DEADLINE_EPOCH=$((now_epoch + ROLLBACK_BUDGET_SECONDS))
  fi
  if ! run_cnfctl "$STATE_OPERATION_SECONDS" campaign-state \
    require-rollback --state-dir "$STATE_DIR" \
    >/dev/null
  then
    withdraw_serving
    return $?
  fi
  if run_rollback; then
    return 0
  fi
  withdraw_serving
}

release_exclusive_lease() {
  local transition_kind=$1 release_status readback_status
  ((LEASE_ACQUIRED == 1)) || return 0
  if run_cnfctl "$STATE_OPERATION_SECONDS" campaign-state \
    release-exclusive-lease --state-dir "$STATE_DIR" \
    --invocation-id "$INVOCATION_ID" --lease-fence "$LEASE_FENCE" \
    --transition-kind "$transition_kind" --idempotent >/dev/null
  then
    release_status=0
  else
    release_status=$?
  fi
  if run_cnfctl_unleased "$STATE_OPERATION_SECONDS" campaign-state \
    readback-exclusive-lease --state-dir "$STATE_DIR" \
    --campaign-id "$CAMPAIGN_ID" --release-digest "$RELEASE_DIGEST" \
    --topology-config-epoch "$TOPOLOGY_CONFIG_EPOCH" \
    --expected-fence "$LEASE_FENCE" --require-released-or-expired >/dev/null
  then
    readback_status=0
  else
    readback_status=$?
  fi
  # A lost release response is harmless only when authoritative readback proves
  # release/expiry. On failure retain the token only long enough for the single
  # recovery state machine to retry; the EXIT trap always clears it afterward.
  if ((readback_status == 0)); then
    LEASE_ACQUIRED=0
    LEASE_EXPIRES_EPOCH=0
    LEASE_TOKEN=
    unset LEASE_TOKEN
    return 0
  fi
  ((release_status == 0)) || return "$release_status"
  return "$readback_status"
}

readback_campaign_complete() {
  run_cnfctl "$STATE_OPERATION_SECONDS" campaign-state \
    readback-complete --state-dir "$STATE_DIR" \
    --invocation-id "$INVOCATION_ID" --lease-fence "$LEASE_FENCE" \
    --require-complete --require-final-status-evidence \
    --require-accounted-negative-probe-total
}

on_secondary_signal() {
  SECONDARY_SIGNAL=1
  printf '%s\n' 'rotation campaign: additional signal deferred during recovery' >&2
}

recovery_entry_boundary() {
  # Deterministic no-op boundary used by the adversarial harness. Production
  # callers cannot configure it; the secondary-signal trap is already active.
  : "$1"
}

recover_failure() {
  local reason=$1 recovery_status=0 release_status=0
  trap on_secondary_signal HUP INT TERM
  recovery_entry_boundary trap-installed
  if ((RECOVERY_ACTIVE == 1 || RECOVERY_ATTEMPTED == 1)); then
    SECONDARY_SIGNAL=1
    return 1
  fi
  RECOVERY_ATTEMPTED=1
  recovery_entry_boundary attempted
  RECOVERY_ACTIVE=1
  recovery_entry_boundary active
  trap - ERR
  set +e
  if ((LEASE_ACQUIRED == 1 && COMPLETION_RECORDED == 0)); then
    run_cnfctl "$STATE_OPERATION_SECONDS" campaign-state mark-interrupted \
      --state-dir "$STATE_DIR" --reason-code "$reason" >/dev/null
  fi
  if ((COMPLETION_RECORDED == 0)); then
    abort_campaign
    recovery_status=$?
    if ((recovery_status != 0 && WITHDRAWAL_ATTEMPTED == 0)); then
      withdraw_serving
      recovery_status=$?
    fi
  fi
  if ((LEASE_ACQUIRED == 1)); then
    release_exclusive_lease recovery
    release_status=$?
    if ((release_status != 0)); then recovery_status=1; fi
  fi
  RECOVERY_FINISHED=1
  RECOVERY_ACTIVE=0
  set -e
  if ((SECONDARY_SIGNAL == 1)); then
    printf '%s\n' 'rotation campaign: recovery completed after deferred signal' >&2
  fi
  if ((recovery_status != 0)); then
    printf '%s\n' 'rotation campaign: recovery failed closed' >&2
    return 1
  fi
  return 0
}

on_error() {
  LAST_ERROR_STATUS=$?
}

on_exit() {
  local status=$? reason=unexpected-exit
  trap - EXIT ERR
  if ((LAST_ERROR_STATUS != 0)); then
    reason=unexpected-error
  fi
  if ((EXIT_WITHOUT_RECOVERY == 0 && CAMPAIGN_COMPLETE == 0 && \
    RECOVERY_FINISHED == 0)); then
    trap on_secondary_signal HUP INT TERM
    if ! recover_failure "$reason"; then status=1; fi
    # An incomplete invocation is never successful, even when its fail-safe
    # rollback/withdrawal and release completed successfully.
    if ((status == 0)); then status=1; fi
  fi
  CAPTURED_OUTPUT=
  LEASE_TOKEN=
  unset LEASE_TOKEN
  exit "$status"
}

on_signal() {
  local signal_name=$1 status=$2
  trap - ERR
  trap on_secondary_signal HUP INT TERM
  recover_failure "signal-$signal_name" || status=1
  exit "$status"
}

MEMBERS=()
declare -A SEEN_MEMBERS=()
load_members() {
  local members_output member expected
  capture_cnfctl_bounded leased "$STATE_OPERATION_SECONDS" 64 \
    campaign-state member-ordinals --state-dir "$STATE_DIR" || return 1
  members_output=$CAPTURED_OUTPUT
  if [[ "$members_output" == *$'\n' ]]; then
    members_output=${members_output%$'\n'}
  fi
  ((${#members_output} <= 64)) || return 65
  MEMBERS=()
  SEEN_MEMBERS=()
  while IFS= read -r member; do
    [[ "$member" =~ ^(0|[1-9][0-9]*)$ ]] || return 65
    [[ -z ${SEEN_MEMBERS[$member]+present} ]] || return 65
    SEEN_MEMBERS[$member]=present
    MEMBERS+=("$member")
  done <<<"$members_output"
  case ${#MEMBERS[@]} in
    3 | 5) ;;
    *) return 65 ;;
  esac
  ((${#MEMBERS[@]} == 10#$EXPECTED_MEMBERS)) || return 65
  for ((expected = 0; expected < ${#MEMBERS[@]}; expected++)); do
    [[ -n ${SEEN_MEMBERS[$expected]+present} ]] || return 65
  done
}

trap on_error ERR
trap on_exit EXIT
trap 'on_signal HUP 129' HUP
trap 'on_signal INT 130' INT
trap 'on_signal TERM 143' TERM

acquire_now_epoch=$(date -u +%s) || exit 1
acquire_minimum_expiry=$((acquire_now_epoch + LEASE_TTL_SECONDS))
if capture_cnfctl_bounded unleased "$STATE_OPERATION_SECONDS" 768 \
  campaign-state initialize-or-verify --state-dir "$STATE_DIR" \
  --namespace "$NS" --workload "$WORKLOAD" --selector "$SELECTOR" \
  --campaign-id "$CAMPAIGN_ID" --release-digest "$RELEASE_DIGEST" \
  --topology-config-epoch "$TOPOLOGY_CONFIG_EPOCH" \
  --invocation-id "$INVOCATION_ID" --expected-members "$EXPECTED_MEMBERS" \
  --old-chain-expected-failure-delta "$OLD_CHAIN_EXPECTED_FAILURE_DELTA" \
  --max-auth-age-seconds "$MAX_AUTH_AGE_SECONDS" \
  --rotation-jitter-seconds "$ROTATION_JITTER_SECONDS" \
  --drain-seconds "$DRAIN_SECONDS" \
  --reconnect-max-seconds "$RECONNECT_MAX_SECONDS" \
  --observation-seconds "$OBSERVATION_SECONDS" \
  --rollback-budget-seconds "$ROLLBACK_BUDGET_SECONDS" \
  --hard-span-seconds "$HARD_SPAN_SECONDS" \
  --forward-campaign-seconds "$FORWARD_CAMPAIGN_SECONDS" \
  --forward-certificate-horizon-seconds \
    "$FORWARD_CERTIFICATE_HORIZON_SECONDS" \
  --acquire-exclusive-lease --no-wait-on-live-holder \
  --minimum-lease-expiry-epoch "$acquire_minimum_expiry" \
  --bounded-expired-holder-takeover \
  --lease-output-format token-tab-sha256-binding-tab-fence-tab-expiry
then
  initialize_status=0
else
  initialize_status=$?
fi
if ((initialize_status == 75)); then
  [[ -z "$CAPTURED_OUTPUT" ]] || exit 65
  EXIT_WITHOUT_RECOVERY=1
  exit 75
fi
if ((initialize_status != 0)); then
  exit 1
fi
lease_output=$CAPTURED_OUTPUT
CAPTURED_OUTPUT=
if [[ "$lease_output" == *$'\n' ]]; then lease_output=${lease_output%$'\n'}; fi
(( ${#lease_output} <= 768 )) || exit 65
[[ "$lease_output" != *$'\n'* && "$lease_output" != *$'\r'* ]] || exit 65
lease_without_tabs=${lease_output//$'\t'/}
(( ${#lease_output} - ${#lease_without_tabs} == 3 )) || exit 65
lease_without_tabs=
IFS=$'\t' read -r LEASE_TOKEN LEASE_BINDING LEASE_FENCE \
  lease_expiry_text lease_extra <<<"$lease_output"
[[ -z ${lease_extra:-} ]] || exit 65
lease_output=
unset lease_output
[[ "$LEASE_TOKEN" =~ ^[A-Za-z0-9_-]{43,256}$ ]] || exit 65
[[ "$LEASE_BINDING" =~ ^sha256:[a-f0-9]{64}$ ]] || exit 65
validate_u64 "$LEASE_FENCE" || exit 65
[[ "$lease_expiry_text" =~ ^(0|[1-9][0-9]{0,18})$ ]] || exit 65
LEASE_EXPIRES_EPOCH=$((10#$lease_expiry_text))
((LEASE_EXPIRES_EPOCH >= acquire_minimum_expiry)) || exit 65
lease_expiry_text=
unset lease_expiry_text
LEASE_ACQUIRED=1

if ! load_members; then
  exit 1
fi
resume_action=$(capture_scalar "$STATE_OPERATION_SECONDS" \
  '^(forward|rollback|complete)$' 8 campaign-state resume-action \
  --state-dir "$STATE_DIR") || exit 1
case "$resume_action" in
  forward) ;;
  rollback)
    trap on_secondary_signal HUP INT TERM
    recover_failure resume-required || true
    exit 1
    ;;
  complete)
    readback_campaign_complete || exit 1
    COMPLETION_RECORDED=1
    release_exclusive_lease completion || exit 1
    CAMPAIGN_COMPLETE=1
    trap - HUP INT TERM ERR EXIT
    exit 0
    ;;
  *)
    exit 65
    ;;
esac

forward_start_epoch=$(date -u +%s) || exit 1
FORWARD_DEADLINE_EPOCH=$((forward_start_epoch + FORWARD_CAMPAIGN_SECONDS))

if ! save_evidence policy-binding preflight policy-binding \
  null null "$HARD_SPAN_SECONDS" "$STATE_OPERATION_SECONDS" \
  assert-policy-and-alerts \
  --state-dir "$STATE_DIR" --alert-rules "$ALERT_RULES" \
  --max-auth-age-seconds "$MAX_AUTH_AGE_SECONDS" \
  --rotation-jitter-seconds "$ROTATION_JITTER_SECONDS" \
  --drain-seconds "$DRAIN_SECONDS" \
  --reconnect-max-seconds "$RECONNECT_MAX_SECONDS" \
  --observation-seconds "$OBSERVATION_SECONDS" \
  --rollback-budget-seconds "$ROLLBACK_BUDGET_SECONDS" \
  --hard-span-seconds "$HARD_SPAN_SECONDS" \
  --forward-campaign-seconds "$FORWARD_CAMPAIGN_SECONDS" \
  --forward-certificate-horizon-seconds \
    "$FORWARD_CERTIFICATE_HORIZON_SECONDS" --require-every-member-match \
  --old-chain-expected-failure-delta "$OLD_CHAIN_EXPECTED_FAILURE_DELTA" \
  --require-counter-saturation-alert --require-reconnect-failure-alert \
  --require-unsilenced-authentication-alert
then
  exit 1
fi

manifest_ordinal=0
for manifest_set in \
  "$PREVIOUS_OVERLAP_MANIFEST_SET" \
  "$NEW_SVID_OVERLAP_MANIFEST_SET" \
  "$FINAL_NEW_ONLY_MANIFEST_SET"
do
  manifest_ordinal=$((manifest_ordinal + 1))
  required_remaining=$(remaining_forward_validity_seconds) || exit 1
  if ! save_evidence "manifest-$manifest_ordinal-validated" preflight \
    manifest-validation null null "$required_remaining" \
    "$VALIDITY_PROBE_SECONDS" validate-manifest-set \
    --state-dir "$STATE_DIR" --manifest-set "$manifest_set" \
    --target-specific --complete-secret --all-members
  then
    exit 1
  fi
done

if ! publish_phase overlap "$PREVIOUS_OVERLAP_MANIFEST_SET" \
  "$PREVIOUS_OVERLAP_MANIFEST_SET"
then
  exit 1
fi
if ! publish_phase renewed "$NEW_SVID_OVERLAP_MANIFEST_SET" \
  "$PREVIOUS_OVERLAP_MANIFEST_SET"
then
  exit 1
fi

required_remaining=$(remaining_forward_validity_seconds) || exit 1
if ! save_evidence overlap-window renewed overlap-window null null \
  "$required_remaining" "$OVERLAP_WAIT_SECONDS" wait-overlap-window \
  --state-dir "$STATE_DIR" --seconds "$HARD_SPAN_SECONDS" \
  --require-fleet-ready-throughout --require-zero-failure-deltas
then
  exit 1
fi

expected_campaign_auth_delta=0
for member in "${MEMBERS[@]}"; do
  required_remaining=$(remaining_forward_validity_seconds) || exit 1
  if ! state_members touched renewed all; then
    exit 1
  fi
  if ! fleet_checkpoint final "$member" "$required_remaining"; then
    exit 1
  fi
  checkpoint=$CURRENT_CHECKPOINT
  checkpoint_id=$CURRENT_CHECKPOINT_ID
  run_cnfctl "$STATE_OPERATION_SECONDS" campaign-state \
    mark-removal-attempted --state-dir "$STATE_DIR" \
    --member-ordinal "$member" >/dev/null || exit 1
  if ! validate_publication_material final "$member" "$checkpoint" \
    "$checkpoint_id" "$FINAL_NEW_ONLY_MANIFEST_SET" \
    "$NEW_SVID_OVERLAP_MANIFEST_SET" "$required_remaining"
  then
    exit 1
  fi
  if ! save_evidence "final-$member-authorized-publication" final publication \
    "$member" "$checkpoint_id" "$required_remaining" "$PUBLICATION_SECONDS" \
    authorize-and-publish-old-trust-removal \
    --state-dir "$STATE_DIR" --checkpoint "$checkpoint" \
    --member-ordinal "$member" --final-manifest-set "$FINAL_NEW_ONLY_MANIFEST_SET" \
    --rollback-manifest-set "$NEW_SVID_OVERLAP_MANIFEST_SET" \
    --hard-span-seconds "$HARD_SPAN_SECONDS" \
    --minimum-expiry-remaining "$required_remaining" \
    --revalidate-target-and-rollback-immediately-before-write \
    --exactly-one-member
  then
    exit 1
  fi
  if ! post_member_gate final "$member" "$checkpoint" "$checkpoint_id" \
    "$required_remaining"
  then
    exit 1
  fi

  # The deliberate negative probe is never hidden from alerting. A fresh
  # checkpoint admits only already-accounted campaign probes, and the post
  # proof requires the exact qualified delta and rejects any concurrent extra.
  required_remaining=$(remaining_forward_validity_seconds) || exit 1
  if ! fleet_checkpoint final "$member" "$required_remaining"; then
    exit 1
  fi
  checkpoint=$CURRENT_CHECKPOINT
  checkpoint_id=$CURRENT_CHECKPOINT_ID
  if ! save_evidence "final-$member-negative-probe-baseline" final \
    negative-probe-baseline "$member" "$checkpoint_id" "$required_remaining" \
    "$POST_GATE_SECONDS" checkpoint-authentication-failure-baseline \
    --state-dir "$STATE_DIR" --checkpoint "$checkpoint" \
    --member-ordinal "$member" --require-complete-series \
    --reject-process-or-counter-reset --require-no-unaccounted-auth-alert \
    --allow-prior-accounted-campaign-probes \
    --expected-campaign-delta "$expected_campaign_auth_delta"
  then
    exit 1
  fi
  baseline_process_binding=$LAST_EVIDENCE_PROCESS_BINDING
  next_expected_campaign_auth_delta=$((
    expected_campaign_auth_delta + 10#$OLD_CHAIN_EXPECTED_FAILURE_DELTA
  ))
  if ! save_old_chain_probe_evidence "$OLD_CHAIN_EXPECTED_FAILURE_DELTA" \
    "$next_expected_campaign_auth_delta" \
    "final-$member-old-chain-rejected" final \
    old-chain-rejection "$member" "$checkpoint_id" "$required_remaining" \
    "$DIRECTED_PROBE_SECONDS" probe-rejected-chain \
    --state-dir "$STATE_DIR" --member-ordinal "$member" \
    --probe "$OLD_CHAIN_PROBE" --both-directions \
    --fresh-full-handshake --reject-resumption \
    --require-all-expected-probe-receipts \
    --expected-member-delta "$OLD_CHAIN_EXPECTED_FAILURE_DELTA" \
    --expected-campaign-delta "$next_expected_campaign_auth_delta" \
    --bind-checkpoint-and-process-incarnations \
    --expected-auth-or-trust-failure-delta \
      "$OLD_CHAIN_EXPECTED_FAILURE_DELTA"
  then
    exit 1
  fi
  probe_operation_id=$CURRENT_OPERATION_ID
  probe_operation_nonce=$CURRENT_OPERATION_NONCE
  probe_receipt_set_binding=$LAST_EVIDENCE_RECEIPT_SET_BINDING
  probe_receipt_count=$LAST_EVIDENCE_RECEIPT_COUNT
  probe_process_binding=$LAST_EVIDENCE_PROCESS_BINDING
  [[ "$probe_process_binding" == "$baseline_process_binding" ]] || exit 1
  expected_campaign_auth_delta=$next_expected_campaign_auth_delta
  if ! save_probe_accounting_evidence "$OLD_CHAIN_EXPECTED_FAILURE_DELTA" \
    "$expected_campaign_auth_delta" "$probe_operation_id" \
    "$probe_operation_nonce" "$probe_receipt_set_binding" \
    "$probe_receipt_count" "$checkpoint_id" "$probe_process_binding" \
    "final-$member-negative-probe-accounted" final \
    negative-probe-accounting "$member" "$checkpoint_id" \
    "$required_remaining" "$POST_GATE_SECONDS" \
    assert-negative-probe-accounting \
    --state-dir "$STATE_DIR" --checkpoint "$checkpoint" \
    --member-ordinal "$member" \
    --expected-probe-operation-id "$probe_operation_id" \
    --expected-probe-operation-nonce "$probe_operation_nonce" \
    --expected-probe-receipt-set-binding "$probe_receipt_set_binding" \
    --expected-probe-process-incarnation-set-binding "$probe_process_binding" \
    --expected-probe-checkpoint-id "$checkpoint_id" \
    --require-all-expected-probe-receipts \
    --expected-member-delta "$OLD_CHAIN_EXPECTED_FAILURE_DELTA" \
    --expected-campaign-delta "$expected_campaign_auth_delta" \
    --reject-any-additional-or-concurrent-delta \
    --require-unchanged-process-incarnations --require-no-counter-reset \
    --require-critical-alert-visible --refuse-alert-silence-or-inhibition
  then
    exit 1
  fi
done

if ! final_fleet_gate final; then
  exit 1
fi
required_remaining=$(remaining_forward_validity_seconds) || exit 1
save_evidence final-status complete campaign-status null null \
  "$required_remaining" \
  "$STATE_OPERATION_SECONDS" campaign-status \
  --state-dir "$STATE_DIR" \
  --expected-accounted-auth-delta "$expected_campaign_auth_delta" \
  --require-no-unaccounted-failures --require-alerts-unsilenced \
  --require-complete || exit 1
run_cnfctl "$STATE_OPERATION_SECONDS" campaign-state mark-complete \
  --state-dir "$STATE_DIR" --idempotent-readback-after-response-loss \
  >/dev/null || exit 1
readback_campaign_complete || exit 1
COMPLETION_RECORDED=1
release_exclusive_lease completion || exit 1
CAMPAIGN_COMPLETE=1
trap - HUP INT TERM ERR EXIT
```

Run `scripts/test-consensus-rotation-runbook.sh` whenever this executable block
changes. The harness extracts the block, checks Bash syntax (and ShellCheck when
installed), and adversarially covers the three-/five-member two-pass budget,
evidence replay and wrong binding/freshness, exact negative-probe deltas,
step-local version/path/success/withdrawal predicates with no-next-action main
paths, status-76 committed-response-loss and initially-uncommitted same-key
retry, failed-readback withdrawal reconciliation, pre-action lease-renewal
failure, ENOSPC-equivalent staging failure after
withdrawal, raw stderr suppression, inherited-descriptor capture deadlines,
atomic concurrent no-replace publication, sync failure, unexpected exit, and
signals at every recovery-entry boundary. These are deterministic
script-contract tests; they do not replace #164/#143's signed deployed-CNF
campaign.

Before signing the evidence, verify each member step independently: its source
and controller are both `Ready`; each lossless decimal-string version advanced
from that member's own immediate checkpoint; every fleet source/controller
remained `Ready`; expiry exceeds the hard span; both ends of every affected path
completed a fresh non-resumed handshake; draining returned to zero; every
expected series remained complete without process/counter reset; all closed
failure deltas are zero except the separately checkpointed and exactly accounted
old-chain negative probe; and the all-member durable probe is fresh and
satisfies both quorum inequalities before the next member. The old-chain probe
is valid only after that member's old trust was removed. It must produce exactly
the configured per-member authentication/trust-failure delta and one bound
failure receipt for every expected directed probe. The accounting gate binds
the probe's one-use operation ID/nonce, requires all receipts, and fails on any
extra or concurrent delta, reset, or process change, and
requires the critical alert to remain visible and unsilenced. A campaign record
is an acknowledgment of the expected qualification event, not an alert silence
or inhibition.

The persistent state directory is required for crash/signal/ambiguous-response
recovery and is not an evidence bundle. Preserve it until the campaign is
signed complete; a resume must acquire a new exclusive lease for the same
campaign state and enter the single recorded rollback state machine before new
forward work. Each rollback member transition has a stable durable key and a
closed `apply`/`complete` outcome. `apply` authorizes at most one fleet mutation;
a lost response is resumed as `complete`, whose path performs semantic readback
and no mutation. The per-invocation recovery guard permits this state machine
exactly once, including a zero-status incomplete `EXIT`; such an incomplete exit
is rewritten to nonzero. `Busy` is the sole no-recovery exit. Completion and
release response loss are resolved through their idempotent readbacks.
Each invocation has a new ID and lease binding; operation IDs remain monotonic
across invocations. Record the
binary/release digest, topology/configuration epoch, bound policy durations,
command exit statuses, and fresh UTC timestamps only through the fixed durable
no-replace evidence schema. Evidence may never contain a lease token, raw
Prometheus responses, Secret
manifests, private material, certificates, identities, scrape labels/targets,
endpoints, material/endpoint hashes, HKMS handles, keys, or session payloads.
TLS rotation does not rotate payload-protection keys and must not change the
encryption/HKMS composition above Openraft.

### 7.3 Forward rotation

1. Confirm all members are durably ready, all directed peer routes are healthy,
   active/draining gauges are understood, and reconnect/authentication failures
   are at baseline. Record the currently admitted material epoch without
   treating its process-local number as cluster identity.
2. One member at a time, publish a trust bundle that accepts both old and new
   issuers/anchors. Gate that member's source generation, controller epoch,
   affected fresh directed paths, metric deltas, and durable readiness before
   changing the next member. Do not continue from `Unavailable`;
   `RetainingLastGood` means the candidate still needs repair.
3. Again one member at a time, publish renewed leaves and keys atomically
   through one member-scoped projected `..data` generation. Preserve the exact
   canonical SPIFFE ID, logical replica, cluster/configuration/epoch, role, and
   consensus scope, and repeat the complete per-member gate.
4. After each member reports a coherent new material epoch, invoke
   `request_reauthentication()` on the controls for its affected outbound peers
   and listeners. The generation is monotonic and process-local; never set it
   back.
5. During the bounded retirement/drain interval, verify no new work enters old
   connections. A material-only change may consume its deterministic jitter;
   the explicit reauthentication in step 4 retires cached lanes immediately.
   Verify transport waits and connection slots end within the hard deadline,
   replacements complete full mutual TLS/application negotiation,
   drain overruns stay zero, and durable readiness remains fresh. An admitted
   supervised mutation may finish after transport closure; treat its outcome as
   ambiguous, never replay it automatically, and use authoritative readback or
   its existing idempotency/fencing contract. Investigate closed metric outcomes
   only; do not add peer identities or certificate text as labels.
6. Prove every directed peer path has established current-material
   authentication. A listener bind, material publication, zero draining gauge,
   or cached capability alone is not proof. Exercise the fresh linearizable
   readiness path and representative traffic on every member.
7. Keep old trust through the maximum authentication age, configured jitter and
   drain bound, observation window, and approved rollback window. Then remove
   old trust atomically from exactly one member after a fresh fleet-wide
   fail-closed gate. Gate that member fully before removing it from the next.
   This is a trust-anchor cutover for later handshakes, not a
   certificate-expiry deadline or selective same-issuer revocation. Trigger
   reauthentication again, and prove every chain depending on the removed old
   trust anchor is rejected on that member while all directed current-material
   paths remain ready.

### 7.4 Rollback

Before old-trust removal, the executable `rollback_before_removal` path first
validates the durably recorded partial overlap/renewed touched set. It then
requires the previous leaf and every presented intermediate to remain valid for
strictly more than the rollback deadline remaining at that instant. The script
sets one immutable deadline from the derived rollback budget, clamps every CNF
timeout to it, recomputes the remaining seconds, and revalidates the exact
selected target and rollback manifest immediately before every publication.
Forward publications use the stronger complete hard span. Exit status `10` is the command's
only closed "previous material is safely unusable" result; malformed evidence
or every other nonzero status fails the rollback. When previous material is
valid, the path converges every member to the previous leaf/key with overlapping
trust. When status `10` is returned—including a post-hard-span crash before the
first removal marker—it instead validates the new SVID and its full chain beyond
the rollback deadline remaining and converges every member to the new-SVID
overlap manifest. This
fallback explicitly covers partial overlap and partial renewed phases. If
neither complete manifest is safe, it mutates nothing further and withdraws
serving. Every publication uses the combined rollback-safety authorization,
fresh quorum proof, and complete fleet-aware post-gate. Never decrement a
material or reauthentication epoch and never count an old retained connection
as rollback proof.

After any old-trust removal *attempt* (including a lost response), the executable
`rollback_after_removal` path first reads removal-attempted ordinals in reverse
order and restores old-and-new trust while retaining the new SVID, one member
and one complete generation at a time. After a fresh fleet-wide overlap gate it
reads renewed touched ordinals in reverse order and executes the second,
previous-leaf-plus-overlap phase only if that leaf and every presented
intermediate remain valid beyond the actual rollback deadline remaining.
Otherwise it deliberately stays
on the new SVID with overlap and requires a valid replacement. Every transition
repeats source/controller version gates, reauthentication at both path ends,
fresh directed handshakes, complete/reset-safe metric deltas, and fresh durable
readiness.

Both rollback branches first preserve/acknowledge the triggering failure and
start a new metric checkpoint; this does not erase the incident. If a fresh
rollback safety gate encounters the one-unavailable-plus-retaining matrix or
cannot prove quorum, it must not mutate another member. The executable
`withdraw-ready-traffic-and-durable-mutations` path then withdraws Ready and
traffic and stops durable mutations. Generic CRL, OCSP, and
certificate/identity denylist revocation are not an alternate rollback state.
Use coordinated recovery rather than enabling plaintext or weakening identity
checks.

#163 provides the in-process bounded-retirement and request/watch continuity
mechanism. The single-host multi-process campaigns now cover trust
overlap/removal plus the exact synthetic fault/expiry recovery slice described
above. #164/#143 still gate production claims on deployed trust/root cutover,
real network/storage partition, broader restart/fault behavior beyond the one
bounded same-disk active-mutator scenario, deployed mixed
traffic/watch/restore under those
real faults, reconnect storms, resource/soak, remote HKMS, deployed CNF, and
signed release evidence. These semantics do not provide production fleet
qualification or close either issue.

## 8. Snapshots, backups, and rollback

`trigger_snapshot()` asks Openraft to build and compact a state-machine
snapshot. It is a forward recovery/catch-up mechanism. Openraft remains the
only authority allowed to select snapshot lineage or truncate logs.

An Openraft snapshot is not the legacy rollback artifact. Before migration,
preserve complete, coherent, untouched backups of the old databases and any
other state required by the old release.

Rollback after a successful authority claim is only:

1. stop traffic and the complete new fleet;
2. preserve the failed/new state for investigation;
3. restore the full pre-migration backup set to clean paths;
4. verify the old release's exact database and consensus identity; and
5. restart the old fleet together under the old release procedure.

There is no supported in-place downgrade. Do not drop `config_raft_*` tables,
delete `config_raft_identity`, translate Openraft logs into legacy rows, or
copy application tables selectively. Writes committed after migration are not
present in the pre-migration backup. Treat their loss or external replay as an
explicit operator/data-owner decision before rollback.

## 9. Verification

Run implementation tests serially when sharing constrained storage resources:

```bash
cargo test --locked -p opc-persist --test consensus_openraft -- --test-threads=1
cargo test --locked -p opc-amf-lite --test config_consensus_encryption
cargo test --locked -p opc-session-net --test consensus_transport
```

The Linux projected-mTLS traffic/resource campaigns are manual and serialized.
Run each alone from a clean host; they are intentionally ignored by the default
workspace suite:

```bash
cargo test --locked -p opc-session-testkit --test qualification_mtls_multiprocess --no-default-features three_process_projected_mtls_traffic_and_resource_bounds -- --ignored --exact --test-threads=1
cargo test --locked -p opc-session-testkit --test qualification_mtls_multiprocess --no-default-features five_process_projected_mtls_traffic_and_resource_bounds -- --ignored --exact --test-threads=1
```

The bounded single-host fault/expiry scenarios are non-ignored. Run their
three- and five-process cases exactly and serially:

```bash
cargo test --locked -p opc-session-testkit --test qualification_mtls_multiprocess --no-default-features three_process_projected_mtls_unavailable_malformed_and_expiry_recovery -- --exact --test-threads=1
cargo test --locked -p opc-session-testkit --test qualification_mtls_multiprocess --no-default-features five_process_projected_mtls_unavailable_malformed_and_expiry_recovery -- --exact --test-threads=1
```

Run the default package contract and formatting check:

```bash
cargo test --locked -p opc-persist
cargo fmt --all --check
```

Verify the temporary engine and distribution boundary before producing an
artifact:

```bash
cargo test --locked -p opc-session-testkit --test qualification_profile
python3 scripts/publish-order.py --check
cargo deny check sources
```

Domain-level leader-loss tests observe the actual leader before stopping it,
require a different survivor at a strictly higher term, then commit session
lease/CAS work or a configuration transaction before restart and convergence.
The current 3- and 5-process foundation separately records a generation read
while the old leader is down; that read is transition evidence outside its
original 15-operation history checker. A follower-only fault, listener bind,
or stale leader observation is not equivalent evidence. This foundation uses
loopback plaintext test transport only and does not satisfy #143's
deployed-network or mTLS acceptance criteria.

Current config tests cover sealed/redacted singleton persistence, direct-write
fencing, fail-closed legacy admission, exact approved-snapshot recovery,
three-node formation, partition/failover/heal, response loss, restart, and
snapshots through in-process shared peer ports. The AMF-lite test composes the
real outer encryption wrapper and qualifies the three-node provider/HKMS
boundary through key rotation plus durable canaries;
the shared transport tests cover bounded retained-connection retirement,
overlapping trust, complete replacement handshakes, and old/wrong-scope trust
rejection. That suite also forms a real three-node config Openraft cluster and
commits/linearizably reads through the loopback mTLS peer/server. The evidence
does not alone qualify remote HKMS, out-of-process/deployed-network
compatibility, restart/rejoin under deployed storage, resource limits, soak,
fleet-scale certificate rotation/soak, or a carrier release. Track that remaining
evidence under `GAP-001-006`.
