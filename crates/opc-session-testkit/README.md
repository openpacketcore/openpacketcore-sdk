# opc-session-testkit

Internal Openraft and restore-evidence fixtures for session-store tests.

## Purpose

`opc-session-testkit` provides reusable test utilities for deterministic clock
skew, controllable in-process consensus paths, and restore-evidence assertions
around `opc-session-store`. It exercises the production
`ConsensusSessionStore` adapter; it does not implement a second quorum,
sequencing, or repair algorithm.

## API Shape

- `SkewableClock::new()` and `with_base` wrap a virtual clock. `set_skew`
  applies checked positive or negative skew, including saturation at timestamp
  limits.
- `ConsensusTestCluster::start(1)` forms an explicit Openraft lab singleton.
  `ConsensusTestCluster::start(3)` forms a descriptor-only, three-member
  Openraft fleet with one distinct file-backed SQLite database per member.
- `store(index)` returns a clone of that member's production
  `ConsensusSessionStore` adapter.
- `set_node_online(index, online)` enables or disables every in-process
  consensus path to and from one member. `wait_node_durable_ready(index)` waits
  for that member to complete a fresh Openraft linearizable barrier.
- `RestoreEvidenceAsserter::new(block_reasons)` exposes fluent assertions for
  stale-owner rejection, traffic blocking, and redaction-safe messages.

```rust,no_run
use opc_session_testkit::ConsensusTestCluster;

async fn partition_and_recover() {
    let cluster = ConsensusTestCluster::start(3).await;

    cluster.set_node_online(2, false);
    let store = cluster.store(0);
    assert_eq!(store.topology().configured_members(), 3);

    cluster.set_node_online(2, true);
    cluster.wait_node_durable_ready(2).await;
}
```

## Relationships

- Builds descriptor-only `ValidatedQuorumTopology` values and supplies each
  node's local SQLite backend and exact remote `SessionConsensusPeer` map
  separately.
- Uses controllable in-process peer adapters, not `opc-session-net`, mTLS, DNS,
  or a second consensus implementation.
- Used by AMF-lite, IPsec ownership, cache, and session-store tests.

## Production-mTLS Candidate Harness

The private `opc-session-quorum-node` binary now has a default production-mTLS
path for qualification work. It loads one coherent Kubernetes-style projected
SVID generation through `ProjectedSvidSource`, pins the configured local SPIFFE
ID in one shared `TlsMaterialController`, and gives the resulting authenticated
client/server configs to
`RemoteSessionConsensusPeer::new_profiled_with_resolver` and
`SessionConsensusServer::new`. The manifest still performs the exact peer
SPIFFE-ID check after certificate-chain authentication.

The candidate build has no default features:

```console
cargo build -p opc-session-testkit --bin opc-session-quorum-node --no-default-features
cargo test -p opc-session-testkit --test qualification_mtls_multiprocess --no-default-features
```

Projected mTLS can use either exact loopback sockets for the existing
single-host tests or `canonical_endpoint_dns` for a deployed fleet. The DNS
profile omits every `dial_addr`, requires each manifest endpoint to already be
its canonical lower-case FQDN, resolves that endpoint for each fresh
connection, and rejects loopback, wildcard, multicast, and broadcast DNS
results. A deployed listener may bind its declared service port on a wildcard
or non-loopback address. The plaintext profile and pinned mTLS test profile
remain exact-loopback only.

`opc-session-kubernetes-manifest` renders a deterministic three- or five-node
Kubernetes foundation with a headless peer Service, required host
anti-affinity, one retained RWO PVC and one distinct projected-SVID Secret
reference per member, and an immutable digest-pinned release image. See
[`qualification/kubernetes/README.md`](qualification/kubernetes/README.md) for
the command and the remaining CNF qualification responsibilities. This
foundation does not constitute deployed evidence and does not change the
experimental profile.

Its strict private node configuration/control schema is version 3. Version 2
is explicitly rejected because it predates the routing-aware optional
`dial_addr` representation; version 1 is also rejected because lifecycle
replies did not carry the fixed `superseded` and `abandoned` terminal
outcomes. Node config accepts `projected_mtls` with an absolute
projected volume root inside the node workspace, normalized relative
certificate/key/bundle names, a bounded polling interval, and a finite
validated connection lifecycle policy. The control protocol exposes only
redaction-safe evidence:
projected-source publication status separately from authoritative TLS-controller
material status and expiries, an explicit reauthentication generation, a
directed fresh authenticated-TLS plus exact manifest-bound consensus-bootstrap
proof, durable readiness, and fixed-cardinality lifecycle counters. Source
`Ready` is never treated as TLS readiness. A directed proof succeeds only after
that path's resolver count has advanced at the requested reauthentication
generation, independently of the generation echoed in the control reply. It
may end in the exact authenticated `Protocol` application result and therefore
does not claim valid private ReadBarrier handler execution. The protocol never
returns material, SPIFFE IDs, routes, or filesystem paths.

The default-feature multiprocess rotation core runs both three- and five-voter
fleets. It publishes complete immutable projected generations through atomic
Kubernetes-style `..data` symlink replacement, uses the production lifecycle
defaults, and treats every member publication as a separate transition. Each
transition requires both source generation and TLS material epoch to advance
to `Ready`, explicitly reauthenticates every process, proves each resolver-fresh
direction touching the changed member, obtains fresh durable readiness from
every voter, and reads an encrypted canary through every voter. Each completed
fleet phase additionally proves all `N*(N-1)` directed paths and advances the
acknowledged lease/CAS canary. The campaign covers trust overlap, leaf renewal,
same-root intermediate rotation and rollback, new-root
forward/rollback/forward, old-root removal, network rejection of stale old-root
clients, overlap-first post-removal rollback, and a final new-only state. After
shutdown it validates every retained exact canary belongs to one fixed
domain-separated qualification prefix, then confirms both prefixes are absent
from each SQLite database/WAL/SHM family; this is a
MemoryKeyProvider wrapper check, not remote-HKMS qualification. Openraft remains
the only commit authority and the `EncryptingSessionBackend` remains outside it.

Two additional non-ignored cases run serialized single-host three- and
five-process fleets through bounded fault and expiry recovery. First, a
test-only consensus-RPC admission gate makes one stable nonzero follower
unavailable while node 0, a different member, atomically publishes malformed
trust. The malformed candidate never perturbs the active controller epoch:
the source reports `RetainingLastGood` with `MalformedTrustBundle`, its fixed
counter advances at no more than the polling bound, and the survivor quorum
retains fresh durable readiness and advances the encrypted canary. The gated
member is then restarted with the exact manifest address and existing backing
state; after catch-up, a valid projected generation repairs node 0 and the
malformed-generation retry counter becomes stable.

Second, a stable nonzero follower receives a same-issuer leaf with a 75-second
remaining-validity/expiry budget. Fresh directed paths, all-voter readiness,
and the encrypted canary are established first, and every path incident to that
member is refreshed below the authenticated idle timeout until the pre-boundary
observation window. The fixed 30-second drain policy sets the soft boundary at
`not_after - 30 seconds`; the test rejects early local or peer leaf-expiry
retirement, then requires both retirement observations on every endpoint by
expiry. At the hard deadline the member must have zero active/draining
connections with every started drain completed, both projected source and TLS
controller must report `Unavailable`/`LastGoodExpired`, the SVID expiry gauge
must be zero, and exactly one SVID expiry outcome must be recorded. The
survivors must remain durably ready and advance the encrypted canary. Publishing
a valid long-lived leaf then advances only the recovered member's explicit
reauthentication generation, proves a fresh resolver/TLS/bootstrap path in both
directions on every edge incident to that member, and restores all-voter
readiness and canary progress without changing that process's PID. Unrelated
survivors must not record an explicit or local-material-epoch retirement from
this member-only recovery. A prepublication common-key survivor pulse primes
conservative 13-second progress checkpoints. The 86-second recovery
clock and 60-second two-stage server idle/handler tail begin only after the
atomic projected-data rename; every publication, existing-generation incident
path, readiness, and canary checkpoint must observe one common active key on
every survivor observer. Requiring that pulse in every half-SLO observation
interval bounds its worst-case actual event gap to the 26-second availability
SLO. A separate 26-second checkpoint requires every active key on every
observer and is never reset by a faster key. The attempt/terminal
ledger must remain unchanged for the final 2.5-second
cold-connect/maximum-reconnect-backoff tail. Each survivor may record at most
one availability episode while the expired member rejoins; that episode must
recover inside the existing 26-second SLO and be fully settled before the
clean baseline. A second or late episode fails closed. The half-SLO pulse
cadence and independent full-key coverage clock resume immediately after
recovery.
Only after bounded fault-era transport/authentication/timeout/reconnect
outcomes have settled does it capture the clean member-scoped reauthentication
baseline. Fault-era new attempts and reconnects retain the fixed 85/161
per-node bound: the ordinary 24/40 allowance, no more than fifteen five-second
refresh rounds over four/eight incident directed paths, and one scheduled
post-hard-expiry survivor-to-expired network-negative attempt per involved
node. The reverse probe fails local material preflight without dialing. Terminal
outcomes may additionally include only the exact attempts already outstanding
at the interval baseline, with interval conservation enforced. The schedule
binds this accounting as `new-attempts-plus-baseline-outstanding/v1`.
Cancellation-classified `abandoned` outcomes, protocol/backend outcomes, and
drain overruns retain a zero budget throughout the fault and clean intervals.
The private Schedule v6 binds this procedure as
`member-scoped-reauth-settled-baseline/v3` with progress profile
`common-key-pulse-all-active-key-coverage/v1`. Every epoch-changing interval
allows `superseded` only up to the existing per-node connection-attempt bound
`8 * (member_count - 1) + 8`; non-epoch intervals require zero. Actual timeout,
transport, protocol, backend, reconnect failure, and `abandoned` deltas remain
zero in the clean scoped-reauthentication interval after the bounded fault-era
ledger has settled.

Recovery continuity polling uses the child process's non-intrusive workload
snapshot, which cannot create or hide a store outcome. The authoritative
`TrafficStatus` path remains fail-closed and is still required when final watch
heads settle against the linearizable replication head.

These controls are qualification-only. Consensus-RPC admission loss is not a
real or deployed network partition. The cases keep bounded mixed lease/CAS
mutation, linearizable-read, watch, complete-restore, readiness, and
connection-recycling traffic active through the exact synthetic fault/expiry
slice. Only typed backend-unavailable or operation-outcome-unavailable results
at completed operation checkpoints may enter recovery. Mutation or lease
outcomes that can make authority ambiguous discard the prior guard, reacquire
same-owner authority at a strictly higher fence, and validate the exact
scheduled record. Read-only get, restore-scan, and readiness outcomes retain
the already-proven guard and validate that same exact record without minting
unnecessary fencing authority. Evidence binds this routing as
`stage-aware-known-authority/v1`. The private schedule drops one successful
release response
per mutator to exercise that path, and is bound to eight outcomes per node, a
fixed 26-second two-election-plus-operation transition envelope per episode,
and a fixed 50 ms retry delay; all three bounds and the
total/recovered/consecutive counters are schedule evidence. Phase completion
requires every interruption to be reconciled. A committed generation recovered
after process restart does not rearm that once-per-logical-mutator synthetic
fault. Lease loss, unexpected state, and invariant failures remain terminal.
After repairing malformed material,
the campaign performs exactly one unclean restart of a stable follower while
its mutation and watch tasks are active. Survivors advance the encrypted
canary and mixed workload during the outage. The same-disk, exact-address
process must then reconcile at most 262,144 committed journal entries, prove
the exact latest generation/owner/fence/payload with a linearizable read, catch
its watch up without a gap, and resume mutation at a strictly higher same-owner
fence under the `same-disk-exact-address-active-mutator/v3` stage-bounded
profile. Its independent bounds are 5 seconds for termination/reaping, 26
seconds for outage/survivor progress, 45 seconds for replacement-child startup,
37 seconds for Openraft recovery and readiness observation (the existing
26-second recovery envelope followed by one reserved 11-second final all-voter
readiness round: 10 seconds for the backend operation and 1 second for bounded
local result delivery), 25 seconds for journal reconciliation, and 26 seconds
for higher-fence mutation resume. Those sequential stages compose to a
164-second crash-to-resume ceiling; each stage still fails at its own bound and
cannot borrow from the total. Schedule v6 binds the count, profile, recovery
envelope, delivery allowance, final observation reserve, six bounds, and total
so old results cannot masquerade as this evidence. This retains the v1
deadline-composition fix and corrects v2's free-running readiness loop, which
could strand the last six seconds without admitting a complete observation
round. This scenario
does not provide a broader
restart/fault matrix, resource or soak qualification, remote-HKMS evidence,
deployed-CNF evidence, deployed production readiness, signed release evidence,
or a new evidence-schema/production-profile claim. These cases change neither
Openraft's sole commit authority nor payload encryption, AAD,
key-provider/HKMS placement, SQLite/Openraft durable formats, or
encryption-at-rest responsibilities.

The deliberate stale-root negative probe is isolated to exactly one connection
attempt: its qualification-only reconnect minimum and maximum equal the whole
cold-connect subdeadline, and a counted resolver must run once. A rejecting TLS
server can surface its client-certificate alert to the client as either an
authentication error or an EOF-derived timeout, so target-process evidence is
authoritative: exactly one authentication failure and no invalid empty Vote
application dispatch. This does not change production retry or
ordinary EOF/reset classification.

The companion traffic/resource cases run the same complete campaign in both
three- and five-process topologies while every process owns one deterministic
mutation loop and one applied-state watch. Watch registration is a fleet-wide
first phase, so no traffic CAS can precede any observer. Each mutation cycle
requires renewal to preserve key, owner, and fence; performs a fenced
generation CAS; reads and restore-scans the exact key, generation, owner,
fence, class, type, no-expiry marker, and plaintext value through the encryption
wrapper; obtains fresh durable readiness; and requires release/reacquire to
preserve key/owner while strictly advancing the fence. After every publication
and resolver-fresh directed-handshake checkpoint, every observer must advance
its gap-free watch sequence, applied-record count, and every topology-ordered
synthetic-key generation before that transition can complete. Final all-voter
reads bind the last acknowledged generation, owner, fence, and value digest;
SQLite/WAL/SHM scans reject both fixed plaintext-canary prefixes after every
retained exact value is assigned to exactly one prefix. Repeated
same-issuer leaf changes
exercise bounded connection rate/backoff before the full overlap,
intermediate/root, trust removal, old-chain rejection, and both rollback paths.
The 90-second per-transition value is a hard fail-safe only: ready material,
fresh directed handshakes, durable/application progress, and complete
connection accounting are the completion conditions. Transport,
authentication/trust (outside the deliberate stale-chain probe), protocol,
backend, timeout, reconnect failure, and `abandoned` outcomes have a zero
budget. An epoch-changing interval may record `superseded` only within the same
mechanically enforced per-node connection-attempt bound; intervals that do not
change material or explicit authentication epoch require zero. A chained
post-formation ledger covers warmup, every interstitial checkpoint, final
generation, and resource settle; authentication failures must equal exactly
the one deliberate removed-root ring probe delivered to each member; all real
connection-failure, reconnect-failure, abandoned, and drain-overrun deltas must
remain zero. An authenticated
server's policy-driven wait for the next request is reported separately as the
fixed `idle_timeout` lifecycle-retirement reason, never as a failed attempt.

Resource evidence is intentionally explicit and Linux-specific. A warmed
`/proc/<pid>` baseline is sampled every 25 ms through the campaign. The checks
bound the sampled total-FD and OS-thread maxima by the configured 128 inbound
slots, two outbound primary/overflow sockets per remote peer, and the unchanged
fixed allowances; `VmHWM` supplies the kernel's process high-water value. These
are sampled regression maxima, not a claim that every instantaneous FD/thread
peak was observed. Completion waits for every started connection drain to
complete and for eight consecutive equal FD/socket/thread samples, then bounds
settled total FDs, socket FDs, and `VmRSS` relative to the warmed process. The
control status also proves the two qualification-owned async tasks reach zero.
It does not claim to enumerate Tokio/Openraft internal tasks, and debug-build
single-host RSS/FD values are regression ceilings rather than CNF resource
requests or deployed-platform capacity evidence. Openraft heartbeat connections
intentionally remain live: connection accounting derives the non-overlapping
`outstanding = attempts - terminal_successes - fixed_failures`, rejects
overflow/underflow, and requires `outstanding <= active + draining`. Requiring
equality against the mixed-direction gauges would double-count successful live
outbound connections. Final settle requires zero draining connections. The
lifecycle gauge counts both sides, so its hard settled bound is four per remote
member: two outbound primary/overflow lanes plus the corresponding two inbound
server lifecycles.

The workload schedule digest also binds the shared `opc-consensus` admission
limit of eight in-flight proposal tasks per Openraft node. Those slots bound
task/memory pipelines; they create no additional connection, socket, or FD
allowance, so the transport resource formulas above remain unchanged. Its
versioned v3 input also binds the 10-second operation timeout, 45-second child
response envelope, 30-second mutation-shutdown SLO, 75-second short-lived SVID
budget, one-second
pre-soft traffic-stop lead, and
`accepted-operation-terminal-checkpoints/v1` cancellation discipline. If a
fleet starts, each already-bound child completes its process-heavy
`Configure`/`Started` exchange before the next child is admitted, under one
shared 45-second deadline; cluster `Initialize` remains concurrent. If a
child response times out, is malformed, or reaches EOF, the parent reports only
the closed pending-command kind, a harness-local monotonic sequence, and the
elapsed send time. Command values, session/lease identities, payloads, and
filesystem paths never enter that diagnostic. Child stderr is reduced to a
closed redacted classification; a restart configuration exit may expose only
the fixed `transport`, `sqlite`, `consensus`, or `listener` startup stage.
Cooperative mutation/watch stop replies reuse
the last successfully proven linearizable replication head and perform no new
backend operation after joining their owned task. Normal status commands remain
authoritative, and a recovered watcher must still reconcile the bounded durable
journal before subscribing at `head + 1`.

Schedule v6 also binds `terminal-stage-elapsed-millis/v1`. If an accepted
recovery operation finishes after its fixed deadline, the campaign remains
failed and reports only the closed deadline code, the terminal operation stage,
and elapsed milliseconds. It does not replace the failure with the earlier
ambiguous outcome or expose backend text, peer/session identity, or payload.

`qualification/v1/session-mtls-candidate-evidence.schema.json` deliberately
requires `experimental = true`, `qualification_complete = false`,
`insecure_test_enabled = false`, and
`counts_for_seamless_tls_rotation = false`. This immutable v1 schema accepts
exactly the earlier three-process formation checkpoint and its six directed
paths, and requires all seven coarse candidate gaps encoded by that checkpoint.
It is not silently widened by the newer multiprocess rotation core. Those seven
gaps are not an exhaustive #164 acceptance inventory, and neither checkpoint is
deployed production evidence.

`qualification/v2/session-mtls-candidate-evidence.schema.json` is a separate,
closed candidate contract for the completed local rotation-core,
fault/expiry-recovery, and traffic/resource campaigns. The typed record binds
the exact source revision and clean/dirty tree state, qualification child
digest, parent harness digest, generated-configuration digest, immutable schema
digest, exact declared phase/orchestration schedule, 3/5-member topology,
ordered `N*(N-1)` directed-path count, and exact campaign-specific coverage.
Source, child, parent, and configuration inputs are captured before execution
and rehashed after the campaign; any change prevents emission. A separate
domain-separated manifest digest binds the ordered publication phase, member,
epoch, and exact public certificate-chain and trust-bundle bytes. It therefore
binds the certificates' public validity, serial, issuer, and public-key facts
without hashing or serializing private keys. Source state includes staged,
modified, and nonignored untracked files. The record never contains certificate
material, keys or key digests, SPIFFE IDs, peer addresses, filesystem paths,
session payloads, or backend text, and every public `Debug` representation
redacts source and digest bindings.

Successful campaigns construct and validate this record in a private temporary
directory through a harness-private successful construction path, so evidence
is ephemeral by default. Public API supports bounded decode, validation, and
read-only inspection, not manufacturing all-success records. Untrusted bytes
must enter through the pre-decode size bound:

```rust
use opc_session_testkit::qualification::SessionMtlsCandidateEvidenceV2;

let evidence = SessionMtlsCandidateEvidenceV2::from_json(document_bytes)?;
```

`from_json` rejects documents larger than
`SESSION_MTLS_CANDIDATE_EVIDENCE_V2_MAX_BYTES` before JSON parsing, rejects
unknown fields or trailing non-whitespace content, and applies the cross-field
validator before returning. Its errors never include input bytes. Setting the
existing absolute `OPC_SESSION_HA_EVIDENCE_DIR` contract preserves only
`evidence.json` and the matching schema. Source files are opened no-follow and
read through a hard
bound; output is written as `0600` files in a held-descriptor `0700` sibling
staging directory, fsynced, and atomically renamed without replacement to the
final campaign name. An error before publication cannot expose a partial final
bundle. The absolute root must itself be `0700`; symlink roots and pre-existing
broader directories are rejected and never chmodded. Node configuration, logs,
metrics payloads, projected material, and SQLite files are never copied. The schema fixes
`experimental = true`, `qualification_complete = false`,
`insecure_test_enabled = false`, and
`counts_for_seamless_tls_rotation = false`; candidate emission fails closed
when the `foundation-insecure` feature is compiled. Real network/storage faults,
deployed CNF/Kubernetes execution, supported-platform soak, remote HKMS, live
metrics/alerts, independent checking/signing, and HA-profile graduation remain
explicitly open. This candidate record does not complete #164 or #158 and does
not replace independent release evidence.

## Concurrent History Candidate

`qualification/v3/session-ha-candidate-evidence.schema.json` is a closed,
immutable candidate contract for the next #143 evidence pipeline. It binds an
exact artifact, source revision, fault schedule, isolated workload schedule,
JSONL history, and independent checker digest. The schema fixes
`experimental = true`, `qualification_complete = false`, and
`counts_for_production = false`; a v3 document cannot graduate the HA profile.

`scripts/check-session-ha-concurrent-history.py` uses only the Python standard
library and imports no SDK code. It accepts overlapping operation intervals and
checks four evidence surfaces together:

- successful and conflicting multi-key batches must admit the claimed
  Openraft-index serialization, preserve real-time order, and apply every
  successful batch atomically;
- each completed watch must contain the exact ordered mutation stream after its
  requested index through its proven completion head;
- each complete restore scan must equal the exact state at its snapshot index;
- every configured process must have a gap-bounded readiness sample sequence;
  a ready sample may not claim authority without expected quorum, may not
  regress term/commit/apply state, and must include every write acknowledged
  before the sample. Its `commit_index` is the index proven by the completed
  Openraft linearizable barrier; `applied_index` is observed afterward and may
  therefore be later, but never earlier.

The checker rejects duplicate fields, non-integer JSON numbers, oversized
inputs, unknown fields, digest mismatches, incomplete operation-kind coverage,
and malformed outcome payloads. Indeterminate or unavailable batch outcomes
remain explicitly inconclusive because watch and restore completeness cannot be
derived through an unknown state transition. Keys, owners, and values cross the
checker boundary only as exact domain-produced SHA-256 digests.

This first v3 slice is bounded to 64 batch invocations, 16 mutations per batch,
4,096 watch events, 4,096 restore records, and a single isolated digest
namespace per history window. It is a contract and synthetic checker fixture,
not deployed evidence. Kubernetes 3/5-node execution, real network/storage and
crash-point faults, migration/rollback, platform soak, remote-HKMS rotation,
live alert verification, and a signed release bundle remain required by #143.

Run the focused contract and checker suite with:

`cargo test --locked -p opc-session-testkit --test qualification_history_v3`.

## Combined HA Candidate Manifest

`qualification/v4/session-ha-profile.json` is an additive candidate profile.
It keeps the v2 workspace, source-build, artifact, platform, topology,
protocol, timing, bound, and provisional-threshold inventory exactly
equivalent at the JSON-value level, while naming both the immutable v1
sequential checker contract and the immutable v3 concurrent checker contract.
It does not replace or widen either older contract.

`qualification/v4/session-ha-candidate-manifest.schema.json` closes the
aggregate boundary. One manifest binds the exact source revision, candidate
profile, binary, optional OCI image, feature inventory, environment,
configuration, fault schedule, logs, metrics, resource results, both histories,
both checker programs, and both canonical checker outputs. It admits only mTLS
three- or five-voter campaigns with independent processes and storage,
canonical SPIFFE identities, and canonical FQDN routes. The typed
`SessionHaCandidateManifestV4::from_json` boundary is size-limited and also
checks cross-field constraints that JSON Schema cannot express, including
ordered timestamps, exact-release source/profile/image rules, conclusive
checker outcomes, and acceptance status/digest pairing. Digests have a
redacted `Debug` representation; manifests contain no certificate, key,
payload, route, peer-identity, log, or metric-label values.

Every v4 document is fixed to `experimental = true`,
`qualification_complete = false`, and `counts_for_production = false`. The
eight acceptance entries are a complete inventory, but attached evidence is
still candidate evidence. This contract neither closes #143 nor makes a
production HA claim. Run its schema, frozen-byte, digest cross-binding,
independent-checker, and tamper tests with:

`cargo test --locked -p opc-session-testkit --test qualification_candidate_v4`.

## Status Notes

- `publish = false`; this crate is test-only.
- Synthetic `.invalid` endpoints and SPIFFE-like IDs are descriptor metadata,
  not live authenticated network membership evidence.
- Node isolation exercises Openraft quorum loss and healing after a fleet has
  formed. The multi-process foundation additionally observes and stops the
  actual leader in 3- and 5-member fleets, requires a different higher-term
  survivor, records a generation read while the old leader is down, and bounds
  same-disk restart/catch-up.
  These loopback plaintext tests do not by themselves qualify cold-start races,
  deployed-network/mTLS behavior, complete crash matrices, multi-node
  restart/rejoin, legacy-fork repair, or carrier failover.
- The production-mTLS rotation core now covers three- and five-process
  projected-material overlap/leaf/intermediate/root transitions, rollback,
  stale old-root client rejection, resolver-fresh reauthentication, durable
  continuous lease/CAS/read/watch/restore/readiness traffic, repeated leaf
  rotations with explicit connection/reconnect limits, Linux process-resource
  regression bounds, and absence of exact test canary bytes from the SQLite
  database family on one host. Separate non-ignored three- and five-process
  cases cover the exact synthetic one-follower consensus-admission-loss plus
  different-member malformed-last-good combination, exact-address restart and
  repair, and a same-issuer leaf with a 75-second remaining-validity/expiry
  budget through soft retirement, hard drain,
  `LastGoodExpired`, survivor progress, and same-process replacement.
  The same bounded continuous lease/CAS/read, watch, restore-scan, readiness,
  and connection-recycling workload remains active through both scenarios;
  restarted watchers reconcile an exact committed journal prefix before
  resubscribing.
  They do not cover a real/deployed network partition, deployed
  Kubernetes/network/storage behavior, a broader restart/fault matrix, external resource
  pressure, supported-platform sizing, soak, remote HKMS, or signed candidate
  evidence. Those cases remain required before #164/#158 can be closed.
- Long-running network, resource, and soak qualification remains #143. Watch
  handoff and bounded replication-log cursor/retention semantics are
  implemented under #145/#171.
- The machine-readable profile remains `experimental` with
  `qualification_complete = false`. Its exact Openraft git pin and 26-crate
  source-build gate may be removed only after an official fixed stable release,
  registry checksum pin, and full #143 requalification.
- Restore assertions panic like normal test assertions.

## Roadmap

- Add fault controls only when a session-store or CNF acceptance test needs a
  specific observable safety property.
- Keep consensus faults at the peer boundary so tests continue to exercise
  Openraft as the only authority.
- Keep the crate unpublished and test-only.

## Verification

- Source checked: `Cargo.toml`, `src/lib.rs`, and dependent session tests.
- Run production-mTLS qualification with:
  `cargo test -p opc-session-testkit --test qualification_mtls_multiprocess --no-default-features -- --test-threads=1`.
- Run the non-ignored three- and five-process fault/expiry cases exactly with:
  `cargo test --locked -p opc-session-testkit --test qualification_mtls_multiprocess --no-default-features three_process_projected_mtls_unavailable_malformed_and_expiry_recovery -- --exact --test-threads=1`
  and
  `cargo test --locked -p opc-session-testkit --test qualification_mtls_multiprocess --no-default-features five_process_projected_mtls_unavailable_malformed_and_expiry_recovery -- --exact --test-threads=1`.
- The Linux traffic/resource cases are manual long-running qualification and
  remain ignored in the default suite. Run them individually from a clean host:
  `cargo test --locked -p opc-session-testkit --test qualification_mtls_multiprocess --no-default-features three_process_projected_mtls_traffic_and_resource_bounds -- --ignored --exact --test-threads=1`
  and
  `cargo test --locked -p opc-session-testkit --test qualification_mtls_multiprocess --no-default-features five_process_projected_mtls_traffic_and_resource_bounds -- --ignored --exact --test-threads=1`.
- Run the historical plaintext foundation explicitly with:
  `cargo test -p opc-session-testkit --features foundation-insecure --test qualification_multiprocess`.

## License

Licensed under the [Apache License, Version 2.0](../../LICENSE).
