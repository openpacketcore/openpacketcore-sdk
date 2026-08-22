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

A stateless clone lineage shares fail-fast physical-admission caps of 16 request
connections and 16 watch connections. Permits are acquired before resolve/TCP
and held for the physical connection lifetime, including by persistent clients
derived from the same lineage. Independent stateless constructors define
independent logical clients, as independent persistent constructors do.

## Current-main successor audit (2026-08-22)

The closure successor starts exactly at SDK commit
`f2ed1181c85540cc01ea0b4611fa3620891375fd`, tree
`945ceab3870d2c1d2d1396aff29e819288fce76a`. It does not contain, rebase, or
merge the stale qualification branch. Four focused regressions retained the
following current-main RED evidence before the generic correction:

```text
prewarm_reresolves_and_reauthenticates_all_lanes_after_server_replacement
  resolver calls: observed 2, required 4
persistent_pool_shares_one_recovery_probe_across_twelve_callers
  peak simultaneous resolver calls: observed 12, required 1
pre_staged_future_rejection_after_a_completed_call_is_outcome_unknown
  observed typed Rejected(Unavailable), required OutcomeUnknown
credential_epoch_supersedes_blocked_pool_recovery_without_waiting_for_setup_deadline
  fresh-epoch resolver calls without advancing the paused clock: observed 1, required 2
```

The causal correction is consumer transport revision 5. It retains the
tenant-scoped mTLS/SPIFFE/ALPN/Hello authority and all fixed resource bounds,
while adding five generic guarantees:

- explicit prewarm rolls every configured lane through a fresh
  resolver/TCP/TLS/Hello exchange and preserves refreshed plus unprocessed
  healthy lanes after a partial failure;
- all cold request, watch, and prewarm setups in one pool share one serialized
  recovery lane and one coalesced exponential backoff deadline for failed setup
  or proven cached-lane loss;
- a newer credential/material epoch cancels the stale serialized
  resolver/TCP/TLS/Hello setup before the fresh setup acquires that lane, with
  no old-epoch cooldown publication and no setup-deadline wait;
- each connection-local monotonic sequence is paired with a fresh
  unpredictable UUID nonce whose field is serialized only after the complete
  request, and the exact composite value is required in the response; and
- write classification observes positive ciphertext acceptance below TLS, so
  a later outer TLS error cannot turn a possibly transmitted mutation into an
  automatically replayable `NotTransmitted` result.

The tracked v8 exact-head evidence schema now binds transport revision 5. It
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
  275 passed; 0 failed
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
composite correlation, below-TLS write classification, watch/request
cancellation, and fixed request/watch/physical-admission bounds. They are
correctness evidence;
they do not replace the still-required production three-voter network latency
qualification.

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
counting TCP proxy, a fixed three-lane request pool, and one isolated watch
slot. It prewarmed all three authenticated lanes, then timed 16 sequential
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

### Persistent-watch continuity fix coverage

The retained `persistent_watch_reconnects_at_the_exact_delivered_cursor_after_endpoint_loss`
fixture holds the first watch stream until its resolver has been switched to a
replacement endpoint, then proves delivery of sequence 1 followed by exactly
sequence 2 through a fresh resolver/TLS/Hello path. Its companion
`persistent_watch_reconnects_after_authenticated_rotation` proves the same
1-to-2 boundary after client reauthentication retires an otherwise healthy
watch connection. Removing the persistent reader's reconnect path makes either
fixture terminate after sequence 1; accepting a duplicate, gap, wrong
correlation, unknown frame, or partial frame is intentionally not a recovery
path and remains fail-closed. The focused restored command is:

```text
opc-heavy cargo test --locked -p opc-session-net --test persistent_consumer_transport persistent_watch_reconnects_at_the_exact_delivered_cursor_after_endpoint_loss -- --exact --test-threads=1
opc-heavy cargo test --locked -p opc-session-net --test persistent_consumer_transport persistent_watch_reconnects_after_authenticated_rotation -- --exact --test-threads=1
```

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

The public watch cursor is inclusive and 1-based.  The consumer normalizes a
zero cursor once, before its first wire request, to sequence 1; every reconnect
then starts at the exact next undelivered sequence.  The test fixture no longer
rewrites its emitted sequence to a caller-provided zero value, and retained
`persistent_watch_zero_cursor_normalizes_to_the_first_committed_sequence`
requires `open_watch(0)` to yield sequence 1.  Removing that boundary
normalization makes the reader fail closed on a sequence gap rather than
silently accepting a synthetic sequence zero.

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
