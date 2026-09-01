# Persistent consumer transport qualification evidence

This evidence is for the generic SDK transport in issue #695. It is synthetic
loopback qualification only. It does not measure an ePDG call path and does not
claim completion of the downstream ePDG #181 production SLO.

The persistent revision-2 qualification contract is recorded in v7. The
published v6 profile remains the unchanged revision-1 contract. This evidence
exercises `PersistentSessionConsumerClient` as a warm fixed-pool primitive; it
does not qualify #695 production latency. `StatelessSessionConsumerClient`
remains a public,
source-compatible production/compatibility fresh-authentication typed
least-authority surface required by #649, #688, and #691; it is neither hidden,
deprecated, nor test-only.

A stateless clone lineage has family-specific fail-fast caps: 16 `/1`-family
permits shared by general `/1` and an opted-in protected-roster `/3` clone, and
an independent 16 ordinary-fenced `/2` permits (32 request permits in total),
plus a separate 16-watch cap. Ordinary persistent `/1` and `/2` pools share one
aggregate width and may reclaim an idle opposite-protocol lane. A protected
`/3` pool is constructed from the opted-in roster stateless profile, cannot
relabel an ordinary retained lane, and admits only protected-roster operations;
it does not enable ordinary `/1` or `/2` operations. Typed tenant/NF
`open_watch` remains locally `Unsupported` before resolution, TCP, TLS, or
cursor exposure. Independent stateless constructors define independent logical
clients, as independent persistent constructors do.

## Current-main successor audit (2026-08-22)

The closure successor starts exactly at SDK commit
`f2ed1181c85540cc01ea0b4611fa3620891375fd`, tree
`945ceab3870d2c1d2d1396aff29e819288fce76a`. It does not contain, rebase, or
merge the stale qualification branch. Eight focused regressions retained the
following current-main RED evidence before the generic correction:

```text
prewarm_reresolves_and_reauthenticates_all_lanes_after_server_replacement
  resolver calls: observed 2, required 4
persistent_pool_shares_one_recovery_probe_across_twelve_callers
  peak simultaneous resolver calls: observed 12, required 1
pre_staged_future_rejection_after_a_completed_call_is_outcome_unknown
  observed typed Rejected(Unavailable), required OutcomeUnknown
credential_and_material_epochs_supersede_single_blocked_pool_recovery
  lone reauthentication resolver calls without advancing the paused clock: observed 1, required 2
adapter_buffering_above_zero_byte_lower_transport_is_before_write
  observed MayHaveWritten after adapter-only buffering, required BeforeWrite
stale_setup_cannot_publish_old_epoch_reconnect_cooldown
  observed pending old-epoch readmission, required immediate Superseded
current_setup_lifecycle_rejection_retains_reconnect_cooldown
  observed immediate same-authority readmission, required shared cooldown
superseded_setup_drops_losing_io_before_releasing_reconnect_lane
  observed fresh setup admission while losing old-epoch I/O was blocked in Drop,
  required serialized admission only after the losing I/O future was destroyed
```

The causal correction retains tenant-scoped mTLS/SPIFFE/ALPN/Hello authority
and all fixed resource bounds, while adding five generic guarantees:

- explicit prewarm rolls every configured lane through a fresh
  resolver/TCP/TLS/Hello exchange and preserves refreshed plus unprocessed
  healthy lanes after a partial failure;
- all cold request and prewarm setups in one pool share one serialized
  recovery lane and one coalesced exponential backoff deadline for failed setup
  or proven cached-lane loss;
- a newer credential/material epoch cancels the stale serialized
  resolver/TCP/TLS/Hello setup, retains the serialized permit until the losing
  I/O future is destroyed, and only then admits a fresh setup, with no
  old-epoch cooldown publication or setup-deadline wait; ordinary
  same-authority lifecycle rejection retains the shared failure cooldown;
- each connection-local monotonic sequence is paired with a fresh
  unpredictable UUID nonce whose field is serialized only after the complete
  request, and the exact composite value is required in the response; and
- write classification makes positive ciphertext acceptance below TLS
  authoritative: a later outer TLS error remains ambiguous after a positive
  lower write, while adapter-only plaintext buffering over zero lower writes
  remains exactly `NotTransmitted`.

The frozen v8 exact-head schema binds the historical general `/1` transport
revision 5, digest
`sha256:5e3becf5094f3e222b94799e0fb7b6b77c3398aeabae743fc65b409c4cd4adfd`.
The current v9 schema binds `/1` transport revision 6 and application revision
4, digest
`sha256:65d456edc15359e9cbac25a6771822219797c53f03aa6ca5d8837e43a6dbc018`.
The ordinary fenced `/2` wire remains revision 5 and the protected-roster `/3`
wire is independently revision 5; general `/1` is revision 6. When roster
support is enabled, the listener deliberately advertises all three consumer
ALPNs concurrently: `opc-session-consumer/1`, `/2`, and `/3`. This is not a
coordinated no-coexistence cutover. Voter-to-voter consensus remains
`opc-session-consensus/2` at revision 5.

V9 is an exact-head evidence schema, not a latency, ePDG, or production-SLO
claim. A generated V9 record is `experimental:true`; it is
`qualification_complete:true` only after the complete external gate has
succeeded and all strict artifacts validate. This document records the
procedure, not a preclaimed result.

The closed V9 contract binds more than source provenance and artifact digests.
It records the canonical absolute testkit `CARGO_TARGET_DIR`, the canonical
absolute external V9 evidence root, the canonical owner-private fs-verity
snapshot base, and the pair directory derived from the evidence root; each raw
path has its own domain-separated commitment. The snapshot base additionally
commits its descriptor-captured device/inode so a same-path replacement cannot
reuse the release identity. It separately
records the exact normalized absolute Cargo invocation alias (for example, a
rustup-managed `.../cargo`), the canonical backing executable path resolved
from that alias, and a SHA-256 commitment to that backing file's content. The
alias, not the backing path, is the process `argv[0]`, followed by the 14
canonical tail arguments. The normalized recorded vector has exactly 15
elements and begins `cargo`; the POSIX-escaped, environment-prefixed
reproduction command executes the alias. The V1/V9 pair keeps the unchanged
two exact leaves, `batch-release-gate-v1.json` and
`persistent-consumer-v9.json`.

Its symmetric pair run-ID uses domain
`opc-session-ha-persistent-consumer-v9-pair-run/v4\0`. It binds canonical V1,
the existing provenance/invocation fields, and a canonical full V9 claims
preimage in which only `invocation.run_id_sha256` is replaced with
`sha256:` plus 64 zeroes. It therefore does not hash the final,
self-containing V9 bytes. The command digest orders backing path, alias,
backing-content SHA-256, executable mode as unsigned 16-bit big-endian, then
argv. Run-ID v4 binds 20 ordered provenance strings: the prior 16 ending
alias, backing path, backing-content SHA-256, `cargo_profile`, and `opt_level`,
plus the fs-verity snapshot-base path, commitment, device, and inode. It then
binds the u16-BE executable mode, followed by the existing
V1/V9/argv/recipe/canonical-V1/claims-preimage material. Neither leaf can be
transferred to a different qualifying pair.

The `/3` pool is rebound to a readiness-proven live quorum leader after each
recorded loss and restart. Its foreign-tenant bracket requires exactly three
endpoint/authority observations, one from every voter, each returning the
non-oracular typed `Unavailable`. For retained receipt recovery, only
`NotFound` and backend `Unavailable` remain retryable; a typed rejection,
authorization/scope/protocol failure, or durable negative receipt is terminal
for that exact request body.

The current-main successor's bounded GREEN gates were run with all
`opc-session-net` features on 2026-08-22:

```text
cargo test -p opc-session-net --all-features --lib
  279 passed; 0 failed
cargo test -p opc-session-net --all-features \
  --test persistent_consumer_protocol \
  --test persistent_consumer_boundaries \
  --test persistent_consumer_transport
  boundaries: 7 passed; protocol: 26 passed; transport: 30 passed
cargo test -p opc-session-testkit --all-features --test qualification_profile
  19 passed; 0 failed
```

The focused transport fixtures bind one serialized recovery probe across 12
callers, coalesced bounded backoff, zero-time stale-epoch setup cancellation,
rolling fresh prewarm, production mTLS/SPIFFE/ALPN/Hello admission, exact
composite correlation, below-TLS write classification, request cancellation,
and fixed request/physical-admission bounds. They are
correctness evidence;
they do not replace the still-required production three-voter network latency
qualification.

## External exact-head release procedure

This is a local SDK qualification procedure, never an ePDG execution or a
latency/SLO claim. Use one clean, signed, committed exact-HEAD checkout. Before
starting, verify the release signature with the approved keyring, require no
`MERGE_HEAD`, and require empty staged, modified, untracked, ignored, and
submodule state. The wrapper captures this one strict provenance before build
and rechecks it before publication; the V1/V9 pair and store artifact must
bind that same exact provenance rather than mixed qualifying runs.

The host must remain quiet from lease acquisition through evidence completion:
there may be functional tests elsewhere, but no competing Cargo or `rustc` job
may run while this release/latency gate runs. The fixed Git, build, and release
deadlines are correctness boundaries, not latency relaxations. Do not increase
them or use a busy-host observation as a performance claim.

Prepare absolute canonical external paths. The SDK worktree, actual
linked-worktree gitdir, common gitdir, testkit Cargo target, V9 evidence root,
wrapper Cargo target, attestation namespace, store-evidence namespace, lease
leaf, and fs-verity snapshot base must be pairwise disjoint; the V9 pair child
is contained only by its V9 evidence root. One canonical owner-private (mode
`0700`) external fs-verity snapshot base may be shared as a parent authority by
the V9 producer and wrapper, but each creates and descriptor-pins its own fresh
private direct child below that base. Neither producer uses the base itself as
an actual snapshot namespace.
The base must support the fixed fs-verity profile. The testkit and wrapper
Cargo targets, V9 ordinary workspace, and store `tempfile` workspace must be
on filesystems distinct from the snapshot base, so build, SQLite, WAL, socket,
and general scratch I/O remain ordinary. The wrapper target, attestation
namespace, and store-evidence namespace must each be absent and external; no
unpassed wrapper work-root exists. Provision an owner-private external V9 evidence root
whose
`session-ha-persistent-consumer-v9` child is absent; it will become the exact
two-leaf pair. Creating `target/`, evidence, a lease, temporary fs-verity
data, or logs inside the source tree poisons the clean-source gate.

First produce the V9 pair in that owner-private root. The environment prefixes
are part of the invocation environment, not Cargo argv; retain the following
Cargo arguments exactly:

```text
CARGO_TARGET_DIR=/external/testkit-target OPC_SESSION_TESTKIT_V9_EVIDENCE_DIRECTORY=/external/testkit-v9-root OPC_FS_VERITY_QUALIFICATION=required OPC_FS_VERITY_SNAPSHOT_ROOT=/external/testkit-fsverity-snapshots cargo test --locked --release -p opc-session-testkit --test qualification_mtls_multiprocess --no-default-features three_process_projected_mtls_persistent_v2_batch_release_gate -- --ignored --exact --test-threads=1 --nocapture
```

Here `cargo` is the illustrative command token; an actual closed record binds
and replays its exact absolute Cargo invocation alias as `argv[0]`.

Only a complete gate publishes the no-clobber
`/external/testkit-v9-root/session-ha-persistent-consumer-v9` namespace with
exactly `persistent-consumer-v9.json` and `batch-release-gate-v1.json`. Its
compact V2 record and V9 record are accepted only after typed and full-schema
validation of canonical bytes. V9 is `experimental:true` and is
`qualification_complete:true` only after this full gate. The pair is the
external prerequisite for the wrapper; it is never inferred from stdout,
stderr, or an `eprintln!` line.

The V9 record's reproduction field is stricter than the display recipe: it is
the POSIX-escaped command with `CARGO=<absolute-cargo-alias>`, the canonical
target, evidence-root, required fs-verity marker, and snapshot-root environment
prefixes, and that same absolute Cargo alias followed by the 14 canonical tail
arguments; its normalized recorded vector has 15 elements beginning `cargo`.
It does not execute the canonical
backing path. The rendering uses
standard POSIX single-quote escaping, while every bound path rejects control
characters and NUL. Consumers recompute it rather than accepting a look-alike
shell command. This documents only the exact quoting regression; it makes no
general shell-injection claim.

Then run only this released recipe, with an absolute trusted Cargo invocation
alias (the illustrative placeholder below is the executable to invoke, not a
claim that its canonical backing path is invoked):

```text
OPC_FS_VERITY_QUALIFICATION=required OPC_FS_VERITY_SNAPSHOT_ROOT=/external/testkit-fsverity-snapshots /usr/bin/python3 ci/sdk702-release-attest.py --cargo /absolute/trusted/cargo --target-dir /absent/external/wrapper-target --snapshot-root /external/testkit-fsverity-snapshots --attestation-namespace /absent/external/attestation --evidence /absent/external/store-evidence --process-loss-evidence /external/testkit-v9-root/session-ha-persistent-consumer-v9/persistent-consumer-v9.json --lease /external/lease/sdk702.lock
```

The wrapper consumes that exact V1/V9 pair while creating and pinning a fresh
external wrapper target distinct from the producer's testkit target. Its
required canonical `--snapshot-root` must byte-match the ambient
`OPC_FS_VERITY_SNAPSHOT_ROOT`, and the ambient
`OPC_FS_VERITY_QUALIFICATION=required` marker is mandatory. It sets only its
canonical absolute `CARGO_TARGET_DIR` for the build, then creates, pins, and
gives the release child only a fresh deterministic direct child of that
explicit fs-verity root. The release fixture keeps its ordinary
`tempfile` database, WAL, and general scratch paths untouched and routes only
fixed-quorum snapshots through that wrapper-owned root. It builds the exact
release test there, writes a create-new fsynced build attestation, and executes
the pinned test descriptor directly. It deliberately handles libtest
`--nocapture` itself;
there is no obsolete Cargo-output or `eprintln!` extraction path. The store
gate atomically create-new writes and fsyncs canonical V1 evidence plus its
accepted marker in the absent external evidence namespace only after all
assertions, graceful shutdown, provenance rechecks, and typed/schema/canonical
validation; only then is its `qualification_complete:true` meaningful. Preserve
its generated artifacts, wrapper output, raw logs, SHA-256 digests, and exit
status without clobbering any existing path.

V9 deliberately calls `TempDir::keep()` for each random fs-verity campaign
child, and the wrapper preserves its create-new target and deterministic
snapshot child on both success and failure. This prevents an identity-failure
unwind from recursively deleting a replacement pathname. Cleanup is deferred
to trusted loop teardown or operator action only after descriptors and child
processes have closed. Each wrapper rerun therefore needs a fresh target and
the 4G loop can accumulate preserved snapshot children.

The lease is also a pinned-inode contract, not a pathname lock. The Python
wrapper retains the exact nofollow private lease inode through
`/proc/<wrapper-pid>/fd/<fd>` for the direct test child's lifetime, without
passing the raw descriptor to that child. Rust opens and exclusively locks that
exact procfd inode, then revalidates the procfd, parent, name, and canonical
path before evidence-namespace `mkdir`, before publication, and at completion.
Those checks close the A-to-B replacement/split-lock seam; they do not grant
authority over unrelated processes or files.

Validate the generated store artifact with the strict existing-artifact
validator, not an ad-hoc parser:

```text
OPC_QUAL_EVIDENCE_VALIDATE=/absolute/external/store-evidence CARGO_TARGET_DIR=/absolute/external/wrapper-target cargo test --locked -p opc-session-store --release --test fenced_transition_v2_qualification -- --ignored --exact validate_existing_release_evidence_artifact --nocapture
```

Its separately causal ambiguity witness is acknowledged after durable execution
and held past that caller's bounded deadline before pressure starts. The batch
therefore records five held/released responses in all (one causal and four
pressure), twelve status-only ambiguous IDs, and the pressure arithmetic of
four held lanes, sixty-four queued callers, and the typed sixty-ninth
rejection.

The batch record separates normal listener headroom from its bounded capacity
probe: all three listeners prove a seventeenth projected-mTLS/Hello status
connection while the sixteen normal lanes stay open. One named listener then
fills the remaining three admissions (high-water exactly 20), records exactly
zero admission waits and one typed twenty-first rejection from process-local
listener counters, and closes every probe back to sixteen active normal lanes.
Immediately before and after that probe, every retained normal lane performs a
status read and its pool setup/reconnect/active/idle counters are unchanged;
this rules out eviction or replacement. The capacity-phase high-water is
therefore not misreported as ordinary headroom.

Snapshot cleanup/restart evidence has an explicitly limited threat model:
the snapshot directory is a private SDK-owned namespace with cooperative SDK
writers only. Within that contract, the retained descriptor, serialized
namespace lease, bounded survivor capacity, and reclaim behavior support the
claimed cleanup/restart bounds. They do not protect against arbitrary same-UID
namespace forgery, exact-grammar but non-admitted files, or substitution after
final pathname/identity authentication. Do not extend the bounded-capacity or
reclaim claim beyond that cooperative namespace contract.

The historical protocol count above predates the #719 global-cursor
contraction. It is not current Watch evidence: those wire fixtures are
quarantined until an identity-and-scope-bound cursor exists, and the exact
current Watch commands and assertions are listed below.

Paused-clock lifecycle regressions additionally require a cached lane to remain
reusable before its stable directed authenticated-edge material deadline and to
retire exactly at that deadline. Two authenticated edges must produce stable,
distinct deadlines inside the configured jitter bound, while the opaque edge
digest has no raw-byte, serialization, or identifying `Debug` surface. Separate
actual TLS races rotate client and listener material immediately before their
final publication samples and require no request dispatch (and no listener
HelloAck for the server-side race). Explicit-generation invalidation remains
immediate.

## Warm-call method and samples

The measurement was recorded at `2026-08-17T04:58:12Z` on Fedora Linux 44,
Linux 7.1.8 x86-64, an AMD EPYC 9335 host with 128 online logical CPUs, Rust
1.97.1, and Cargo 1.97.1. The shared host was not isolated or CPU-pinned. The
test used an unoptimized Cargo test build, an in-process loopback TLS server and
counting TCP proxy and a fixed three-lane request pool. It prewarmed all three
authenticated lanes, then timed 16 sequential
typed `capabilities` calls with `Instant` at the caller. Connection setup and
prewarm time are intentionally excluded from the per-call samples.

Reproduction command, with the required `opc-heavy` serialization wrapper on
`PATH`:

```text
opc-heavy cargo test --locked -p opc-session-net --all-features --test persistent_consumer_transport prewarm_opens_fixed_lanes_reuses_them_and_keeps_diagnostics_redacted -- --exact --nocapture
```

Bounded raw microsecond samples from the restored implementation:

```text
[558, 397, 390, 411, 389, 400, 380, 385, 402, 383, 411, 386, 385, 394, 381, 399]
```

The bounded sample set has minimum 380 us, median 392.0 us, arithmetic mean
403.188 us, maximum 558 us, and total 6,451 us. The executable assertions require
exactly three physical accepts after prewarm and at least 16 authenticated-lane
reuses; elapsed time is deliberately non-gating on a shared host. These numbers
characterize this synthetic host and method only; they are not a production
benchmark or downstream latency promise. In particular, accept/reuse assertions
gate only this synthetic transport-method evidence; the warm elapsed samples
are explicitly non-gating and are not an SLO.

## Deterministic RED and mutation controls

Before the persistent client existed, this exact characterization command
proved that four typed stateless calls performed four authenticated setups and
accumulated four deterministic 40 ms setup delays; the proposed reuse
expectation was one setup and failed with `left: 4`, `right: 1`:

```text
opc-heavy cargo test --locked -p opc-session-net --all-features --lib stateless_quorum_consumer::stateless_serial_calls_red_require_authenticated_connection_reuse -- --exact --nocapture --test-threads=1
```

The retained stateless characterization is named
`stateless_serial_calls_authenticate_fresh_and_accumulate_setup_delay` and
continues to require four setups and at least 160 ms of injected setup delay.
It is RED characterization of the fresh-authentication baseline and confirms
that the stateless surface remains supported.

For the fix-removal mutation, the successful-call
`return_idle(connection)` was temporarily removed and the warm-call command
above was rerun. It failed because 16 physical connections were accepted
instead of the fixed prewarmed 3 (`left: 16`, `right: 3`). The line was restored
and the same command passed with the raw samples above.

For a distinct adversarial mutation, `exact_correlation` was temporarily made
to accept every nonzero value. This command then failed because a duplicate
late response incorrectly completed the next call instead of producing the
typed protocol error:

```text
opc-heavy cargo test --locked -p opc-session-net --all-features --test persistent_consumer_protocol duplicate_response_poisons_lane_and_next_call_uses_a_new_connection -- --exact --nocapture
```

Exact correlation matching was restored, after which the command passed and
the poisoned lane was replaced with correlation 1 on a new authenticated
connection.

### Persistent-watch transport coverage

The old reconnect fixtures are not production consumer-watch qualification and
must not be invoked as green Watch evidence: the current consumer API rejects
`open_watch` with typed `Unsupported`, because its only cursor is global and
filtering it would reveal foreign tenant/NF activity through sequence movement
and timing. The evidence-producing contract commands are:

```text
cargo test --locked -p opc-session-net --all-features --test persistent_consumer_transport typed_consumer_watch_is_rejected_before_resolution_or_global_cursor_exposure -- --exact
cargo test --locked -p opc-session-store --all-features --lib consumer::tests::authorization_requires_exact_scope_and_denies_global_watch -- --exact
cargo test --locked -p opc-session-store --all-features --test fixed_quorum_authority fixed_scoped_consumer_watch_is_rejected_before_stream_admission -- --exact
```

The first asserts both typed rejection forms plus zero resolver, TCP, TLS,
Hello, service, and Watch admission activity. The latter two assert exact grant
scope and the fail-closed service-side rejection, including cross-tenant and
cross-scope attempts. A future production Watch requires an
identity-and-scope-bound cursor protocol and fresh reconnect evidence.

### Admission, cursor, and idle-replacement regressions

The configured complete-operation deadline begins before a persistent caller
waits for a request lane.  The retained
`pool_admission_consumes_the_original_complete_operation_deadline` regression
holds the only lane past that deadline and requires the queued call to return
`NotTransmitted(Deadline)`: waiting for admission cannot add a second timeout
window.  The fixed pool also preserves semaphore arrival order.  The retained
`queued_lane_waiter_cannot_be_overtaken_by_late_callers` adversarial fixture
queues one caller, starts repeated late callers, releases the held lane, and
requires the already queued request to dispatch first.  Replacing the queued
acquisition with a `try_acquire` path makes that assertion fail.

The retained cursor normalization and reconnect fixtures are protocol harness
coverage only. No production tenant/NF-scoped consumer may open that global
cursor until a scope-bound cursor contract exists.

`expired_prewarmed_idle_lane_is_replaced_before_the_next_logical_call` uses a
normal bounded server idle lifetime and waits for the client's own idle reaper
to retire the prewarmed lane before the next logical call.  It therefore checks
the production replacement contract without racing a paused-clock server EOF
against authenticated prewarm.  The focused restored command passed one test
on 2026-08-17; elapsed time is only a fixture guard, not a widened production
timeout or an SLO claim:

```text
cargo test --locked -p opc-session-net --test persistent_consumer_boundaries expired_prewarmed_idle_lane_is_replaced_before_the_next_logical_call -- --exact --test-threads=1
```

### Downstream handoff

The only downstream ePDG handoff is the externally recorded SDK provenance,
attestation, V9 pair, and accepted store evidence for independent downstream
review. It does not authorize an ePDG call path, configuration, cluster
operation, readiness decision, timeout change, or performance/SLO claim.
