# Persistent consumer transport qualification evidence

This evidence is for the generic SDK transport in issue #695. It is synthetic
loopback qualification only. It does not measure an ePDG call path and does not
claim completion of the downstream ePDG #181 production SLO.

The persistent revision-2 qualification contract is recorded in v7. The
published v6 profile remains the unchanged revision-1 contract. This evidence
qualifies `PersistentSessionConsumerClient` as the required warm fixed-pool
primitive for #695/ePDG latency. Production deployments requiring warm reuse
should use it. `StatelessSessionConsumerClient` remains a public,
source-compatible production/compatibility fresh-authentication typed
least-authority surface required by #649, #688, and #691; it is neither hidden,
deprecated, nor test-only.

A stateless clone lineage shares a fail-fast physical-admission cap of 16
request connections. The retained 16 Watch transport permits are deliberately
unavailable to typed tenant/NF consumer calls: `open_watch` rejects locally
with stable `Unsupported` before resolution, TCP, TLS, or cursor exposure.
Independent stateless constructors define independent logical clients, as
independent persistent constructors do.

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

The causal correction is consumer transport revision 5. It retains the
tenant-scoped mTLS/SPIFFE/ALPN/Hello authority and all fixed resource bounds,
while adding five generic guarantees:

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

The tracked v8 exact-head evidence schema now binds transport revision 6. It
continues to require `experimental=true` and
`qualification_complete=false`; it is a structural wire-binding schema, not a
production qualification certificate. No new latency samples were collected
for this successor, no shared-host latency gate was launched, and no cluster or
ePDG state was changed. The bounded raw distribution below remains the earlier
historical synthetic loopback observation and is not used as closure evidence
or as a production/ePDG SLO claim.

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
opc-heavy cargo test --locked -p opc-session-net --test stateless_quorum_consumer stateless_serial_calls_red_require_authenticated_connection_reuse -- --exact --nocapture --test-threads=1
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
opc-heavy cargo test --locked -p opc-session-net --test persistent_consumer_boundaries expired_prewarmed_idle_lane_is_replaced_before_the_next_logical_call -- --exact --test-threads=1
```
