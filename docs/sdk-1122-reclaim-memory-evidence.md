# SDK-1122 bounded V2 retirement

Native durable history retirement shares the existing 128 MiB per-process
verification budget with retained images, live and captured journals, apply and
replay candidates, relocation and codec scratch, and consumer reads. Reclaiming
a full epoch must preserve that budget without exhausting the storage engine.
This is a reservation bound, not a bound on process RSS or deployment memory.

The protocol reclaim batch remains 1,024 ordered receipts. The baseline V2 profile digest remains
`8a0b70b54654c7250cf5469db6e1e545f35e38e9778d5f500fea670696c4bdc3`.
Every identity, predecessor fingerprint, ordinal, lifecycle conservation check,
append readback and recovery audit remains checked. Retirement preserves the
selected profile's receipt outcomes, journal and deletion records, and stored
formats, including the separately selected `V2WithVoid` profile.

## Allocation ownership and admission

Deletion inventories share the immutable ordinal index and each complete
predecessor row allocation. They retain the original content and revision
fingerprints individually; a range is a lossless inventory of identities, not a
count replacing those identities. Transient create-then-delete rows and ordinary
dirty predecessors retain their separate validation. The encoded deletion
inventory remains complete.

Relocation capacity counts only rows that emit replacements: live receipts,
notifications, log rows and roster rows. Deleted rows still participate in
generation counts and verification. Temporary publication vectors have a
separate reservation, released after their allocations are destroyed, including
on errors and unwind. Retained reservations follow the journal into a detached
checkpoint and are released only with its last owner.

The durable owner requests a checkpoint at 8 MiB of live business-journal
reservations. A reclaim candidate is the number of receipts that the shared
lifecycle planner will actually remove, multiplied by the 72-byte before-row
record (one pointer and two 32-byte fingerprints). Rotations, stale expectations
and no-ops reserve zero deletion bytes. The former 2 MiB estimate slack is
removed. If other commands in a mixed delivery change the expected inventory,
its owner reserves the shortfall before allocating the exact vector.

The scheduling allowances derive from the unchanged 128 MiB cap:

| Allowance | Derivation and purpose |
| --- | --- |
| 32 MiB consumer headroom | One quarter of the cap, matching the existing optional journal-read page pool. It is a reserve at retirement admission, not a limit on consumer writes. |
| 16 MiB checkpoint/apply headroom | One eighth of the cap, matching the existing large-log scratch scheduling threshold. Ordinary reclaim work charges an approximately 80 KiB capture, a 512 KiB generation header, two prefix-block buffers and relocation for emitted log rows only. This allowance does not bound arbitrary consumer or roster payloads. |
| 80 MiB admission line | 128 − 32 − 16; the actual process counter plus the candidate must fit atomically. |
| 8 MiB checkpoint trigger | One sixteenth of the cap, about 60 single-command deletion journals of roughly 137 KiB each. |
| 24 MiB live-journal stop | Three trigger units. Two such journals use 48 MiB, leaving 32 MiB for existing images and a candidate below the 80 MiB line. The actual counter enforces admission even when those owners are larger. |
| 64 KiB per inventory range | Covers at most eight copied epoch/vector-root descriptors, four range-slot widths for vector growth and allocator slack. A compile-time type-size assertion checks this envelope; immutable leaves and complete row bodies remain shared resident-state allocations. The aggregate guard outlives the entire range vector. |

For one 1,024-row command, the deletion allocation is
`1,024 × 72 + 65,536 = 139,264` bytes, plus the small publication guard.
All allocations still reserve against the real process counter. These
allowances do not weaken the fail-closed cap or promise that unrelated work
cannot consume the remaining headroom.

The public maintenance boundary polls pressure before consensus ordering,
rechecking leadership and sharing the operation deadline with the proposal.
It may wait until that deadline and return `BackendUnavailable`; callers use
normal retry/status handling. Preflight does not request a checkpoint while a
snapshot is installing. Committed apply waits without retaining State, an
operation permit, captured roots or a candidate. Its inactivity bound is one
shared durable-consensus operation budget, currently 10 seconds. Progress means
a new low in the admission shortfall (`max(used + candidate - 80 MiB, 0)`) or
live-journal size during that pressure episode. A checkpoint or capture counts
only when it provides such relief; completion alone does not renew the bound.
The lowest observed values are retained, so temporary checkpoint allocations
growing and shrinking cannot keep renewing an otherwise stalled wait. A
successful reservation ends the episode; if detached preparation later retries
against a stale predecessor, a new pressure wait gets a fresh budget.
There is no separate total-wait deadline while new lows keep renewing the bound.
A single checkpoint or relocation drain exceeding 10 seconds without observable
relief can still fence a healthy voter on very slow storage. Readiness observed
at the deadline gets a fresh atomic reservation attempt. Persistent pressure
without relief fails through the storage-error/fencing path with
`native retirement admission timed out`.

Polling requests a checkpoint only for a nonempty live business journal whose
release could reach the 80 MiB admission line, or which has reached the 24 MiB
live stop. The predicate is `used - live + candidate <= 80 MiB`; if a completed
capture leaves irreducible pressure, small consumer writes cannot induce
back-to-back admission checkpoints. The ordinary 8 MiB memory trigger remains
independent. An active capture supplies its own completion wakeup.
Shutdown interrupts the wait before joining the state-machine worker, with
`native retirement admission stopped`, without fencing or clearing accepted
WAL work. The WAL then follows its existing drain path. A scheduling-planner
error falls back to authoritative evaluation and its exact hard reservations,
incrementing the saturating `application.retirement_plan_fallbacks` diagnostic
counter once per failed planning attempt without recording command values.
Memory pressure cannot authorize local retirement or change a committed result.
Asynchronous and volatile persistence keep their existing admission lifecycles.

Cold replay prepares eight entries at a time, independently of transport
packaging. It still retains the complete unpublished suffix until the writer
starts; it does not checkpoint while auditing recovery. The dedicated regression
replays the maximum retirement-only suffix over a full 1,048,576-row generation:
128 reclaims, one rotation, then 128 reclaims (257 entries). No further epoch can
retire without new receipt creation: epoch nine is empty and only seven epochs
remain. Its before-row vector totals `262,144 × 72 = 18 MiB`; at most 34 range
charges add 2.125 MiB, and at most 33 publication guards leave the journal below
21 MiB. The real cold-open/replay peak must stay below 64 MiB. The test then
validates and appends the entire recovered journal. Coalesced live delivery still
has one atomic publication; a smaller regression compares full business digests,
applied and committed positions between straight apply and replay.

**Mixed-load limit:** consumer writes can keep growing business, log and roster
journals while a checkpoint is slow. The existing WAL request/byte limits bound
stored input, not its verification expansion; the 8/24 MiB business thresholds
do not stop consumers or account for every log/roster allocation. Consequently,
there is no general under-half-cap bound for an arbitrary mixed suffix or for
multiple stores/images in one process. Such loads can exhaust verification
memory during publication/checkpointing or repeatedly fail cold replay. This
exposure predates the retirement fix. Compact deletion accounting reduces it,
and bounded admission makes retirement pressure observable, but a general
consumer/recovery budget requires a separate change. The retirement-only bound
above must not be read as that broader guarantee.

The scalar planner also does not evaluate receipt bindings from consumer
commands in a mixed delivery. For example, two new bindings followed by a
maintenance entry expecting those two bindings can make the pre-delivery hint
zero even though evaluation removes 1,024 receipts. A lagging follower then
uses the exact fail-closed reservation instead of proactive throttling for that
entry. Modeling arbitrary bindings here would duplicate business validation;
this remains part of the mixed-write budgeting follow-up. A regression checks
the full deletion charge and complete-state parity for this case.

## Void-profile interaction

The #1102 merge extends owned-log copies, request capture and scratch accounting
to both void command variants, including authorized envelopes. Void receipts
use the same charged journal owners and compact deletion inventory as ordinary
V2 receipts. Their terminal error result creates no session, lease, fence or
watch effect. A live void binding emits a replacement receipt row and therefore
uses relocation capacity; retiring it emits no replacement. The immutable
profile remains part of generation validation throughout checkpoint and replay.

The void regressions measure actual retained log-copy allocations, follow a
64-receipt journal's reservation into a captured generation, and verify deleted
void rows through append/readback with deliberate inventory corruption. A mixed
delivery with new void bindings checks the full hard reservation despite the
scalar planner limitation described above. An abrupt child-process exit leaves
42 committed but unapplied entries for cold replay across multiple preparation
cohorts; full business digests and exact receipts preserve first-binding-wins in
both orders. A separate full 131,072-row void epoch reaches the real retirement
pressure fence, exits its failed process, replays its committed maintenance step,
and completes the remaining 127 batches within the existing memory assertions.

Before a void store's first activation, readiness needs every voter's immutable
profile proof unless an exact-scope proof is already cached. The local recovery
and linearizable-barrier gates still run first, so a fenced local owner cannot
become ready through that cache. A running fenced peer can still answer a
capability probe truthfully: its created profile has not changed. If the peer is
unavailable before proof or activation exists, the healthy majority can continue
ordinary work while void readiness and first activation remain unavailable.
Readiness bounds fresh probes to 250 ms within the caller's deadline; activation
uses the existing operation deadline. Repeated attempts can remain unavailable
until the supervisor restarts the absent voter, as required by the existing
terminal-owner contract in #1127. A cached exact-scope proof or replicated
activation lets the healthy quorum proceed. The integration regression exercises
the terminal apply-failure path and these readiness states; the WAL regression
separately produces the fence with actual retirement memory pressure.

The merge changes accounting coverage for the new command variants while
preserving the retirement wait loop. Requalification therefore includes the full
three-voter release proof as well as the ordinary void regressions. The full-scale
proof below uses baseline V2; the dedicated void tests cover the interactions
described here without claiming an arbitrary mixed-load memory bound.

## Required focused regressions

These ordinary, non-ignored unit tests run in the existing required CI library
suite. The cases that need an uncontended process budget run their fixture in a
child process with the real cap.

| Property | Test name suffix |
| --- | --- |
| Publication scratch lifetime, retained ownership and unwind | `native_reclaim_memory_publication_releases_only_destroyed_scratch` |
| Deleted records remain verified without relocation capacity | `native_reclaim_memory_deleted_rows_are_verified_without_relocation_capacity` |
| Exact inventory, ordering and both fingerprints reject corruption | `native_reclaim_memory_compact_capture_rejects_inventory_and_fingerprint_changes` |
| One atomic publication for 128 coalesced reclaim commands | `native_reclaim_memory_coalesced_delivery_preserves_atomic_publication` |
| Replay completes across multiple full transport cohorts | `native_reclaim_memory_replay_multiple_full_transport_cohorts` |
| Rotation/no-op admission preserves reads and exact retries under external pressure | `native_reclaim_memory_noop_admission_keeps_consumers_live` |
| Held checkpoint overlaps consumer work and complete retirement/reopen | `native_reclaim_memory_held_checkpoint_allows_consumer_work_and_finishes` |
| Actual allocation lifetime and exact lower-bound charges | `native_reclaim_memory_staged_allocation_dies_before_refund` |
| Semantic candidate and extra reservation for a shortfall | `native_reclaim_memory_candidate_counts_effects_and_tops_up_shortfall` |
| Full state equivalence between straight apply and replay | `native_reclaim_memory_replay_matches_complete_straight_apply` |
| Commit wait releases its permit and proceeds after relief | `native_reclaim_memory_committed_wait_releases_permit_and_proceeds` |
| Pressure without admission/journal relief fails closed within the bound | `native_reclaim_memory_committed_wait_fails_closed_with_bounded_reason` |
| A checkpoint shrinking the journal extends the commit wait beyond the original deadline | `native_reclaim_memory_progress_extends_committed_wait` |
| Completed checkpoints without relief cannot renew the wait, including temporary allocation oscillation | `native_reclaim_memory_unhelpful_checkpoints_do_not_extend_wait` |
| A smaller shortfall extends the wait even while admission remains closed | `native_reclaim_memory_shortfall_relief_extends_committed_wait` |
| A successful reservation resets the timer before a stale-predecessor retry waits again | `native_reclaim_memory_successful_reservation_resets_wait_after_retry` |
| Shutdown cancels the commit wait and drains queued WAL work | `native_reclaim_memory_shutdown_interrupts_committed_wait` |
| Planner error falls back to authoritative evaluation and increments the value-free counter | `native_reclaim_memory_planner_error_uses_real_evaluation` |
| Preflight avoids checkpoints that cannot relieve admission | `native_reclaim_memory_preflight_avoids_unhelpful_checkpoints` |
| A requested checkpoint actually relieves a commit wait | `native_reclaim_memory_requested_checkpoint_relieves_wait` |
| The 8 MiB live-journal trigger requests a checkpoint | `native_reclaim_memory_eight_mib_journal_requests_checkpoint` |
| Partial refunds run the allocation-lifetime check | `native_reclaim_memory_refund_probe_covers_early_shrink` |
| Split reservations retain their allocation-lifetime check | `native_reclaim_memory_refund_probe_follows_split_owner` |
| Deletion and range buffers die before refund, including captured journals | `native_reclaim_memory_deletion_charges_outlive_allocations` |
| Mixed receipt bindings preserve the complete hard reservation | `native_reclaim_memory_mixed_delivery_retains_full_reservation` |
| Snapshot preflight does not set the checkpoint request | `native_reclaim_memory_preflight_does_not_request_during_install` |
| Full-generation maximum retirement suffix stays below half the cap | `native_reclaim_memory_full_generation_replays_maximum_retirement_suffix` |
| Void and activation log copies, bare and authorized, fit their actual allocation charge | `native_reclaim_memory_void_log_copies_cover_actual_allocations` |
| Void journal charges survive capture and void creates no business effect | `native_reclaim_memory_void_journal_charges_rows_and_retains_capture_ownership` |
| Mixed void bindings retain the exact deletion reservation | `native_reclaim_memory_void_mixed_delivery_retains_full_reservation` |
| Deleted void rows are verified without reserving relocation slots | `native_reclaim_memory_void_deletions_are_verified_without_relocation_capacity` |
| Both first-binding orders survive checkpoint, abrupt process exit and replay cohorts | `native_reclaim_memory_void_checkpoint_and_replay_preserve_first_binding` |
| A full void epoch survives the pressure fence, process exit, replay and complete retirement | `native_reclaim_memory_void_pressure_fence_replays_and_retires_epoch` |
| Fenced local readiness, immutable peer proofs and first activation retain bounded calls | `native_reclaim_memory_void_fenced_voter_keeps_readiness_and_activation_bounded` |

Run the focused memory cases with:

```sh
cargo test --locked -p opc-session-store --all-features --lib \
  native_reclaim_memory -- --test-threads=1
```

## Opt-in full-profile proof

Run on Linux with `TMPDIR` set to a private directory on a disk-backed
filesystem. Keep the ordinary worktree-local Cargo cache. The explicit ignored
test is a release-scale proof and is not part of the ordinary CI shard.

```sh
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
cargo test --locked --release -p opc-session-testkit --features test-control \
  --test qualification_mtls_multiprocess \
  isolated_scale::reclaim_memory::isolated_durable_full_epoch_reclaim_stays_available \
  -- --ignored --exact --test-threads=1 --nocapture
```

The fixture starts three distinct durable voter processes through the public
constructor, with real mTLS consumers and one unmodified verification budget per
voter. It fills seven closed epochs and the active eighth epoch to the complete
1,048,576-binding retained boundary. Only the SDK clock advances to make the
oldest epoch eligible; TLS, scheduling and operation deadlines use real time.

All 128 maintenance commands must complete. Consumer status reads and exact
retries continue during retirement, while a checkpoint is held, while a follower
is dead, and after it rejoins. One follower is killed and reopened at each cut:

| Completed reclaim batch | Crash cut |
| --- | --- |
| 16 | During retirement |
| 40 | After immutable checkpoint capture |
| 56 | Before generation append |
| 72 | After verified generation append |
| 104 | After basis selector rename |
| 116 | After one covered-file unlink, before reclamation completes |
| 128 | Serving leader loss; a replacement serves exact status/replay before the old leader rejoins |

Each reopen uses the same database, WAL, generations and selector, with no
storage edits or cleanup by the harness. The two surviving voters keep serving.
The full-history cold-open hang guard is 120 seconds: the complete selected
history audit takes longer than the ordinary small child fixture's 45-second
startup guard. Public operation deadlines and the checkpoint-cut hold bound
are unchanged. Each completed reopen reports its own elapsed time.
Every recovered voter must report the exact retirement cursor. At completion,
all three voters must be Ready with a running engine and the same fully reclaimed
history. Maintenance then opens epoch nine, a new public operation succeeds,
and the epoch-eight sentinel remains exactly replayable.

The proof reports separate fill and retirement maxima from the actual shared
reservation counter across all voter incarnations, including killed processes
and cold reopen. Retirement must remain below 64 MiB, leaving half the cap free.
The phase counter does not change reservations or reset the lifetime maximum.
Peak diagnostics are enabled explicitly by the durable boundary fixture before
storage opens; ordinary test-control processes keep their existing stderr contract.
Each incarnation must report the unchanged cap and no verification-admission
failure. Failure diagnostics print
the original reservation errors before bounded best-effort process probes.
The final output records total duration, retirement duration and
`fill_peak_bytes`, `retirement_peak_bytes`, and whether memory-trigger or
admission paths engaged. One epoch's 128 single-command deletion journals total
about 17.1 MiB, below the 24 MiB stop; the crash checkpoints shorten that suffix
further. The dedicated pressure tests force the admission line using a real
80 MiB reservation and assert the wait counter, relief, timeout and shutdown.
Retain the exact tested source revision, command, output
and exit status with the run evidence; a result from an older revision does not
qualify a later implementation.

Uncovered cuts are interruption between in-memory relocation steps, during
reopen audit/replay/repair, while committed apply is parked, and leader loss
between commit and reply. These are SIGKILL witnesses, not power-loss tests;
the selector-rename cut precedes directory fsync. The recovery-suffix component
test supplies the larger retirement-only suffix separately.

This proof qualifies retirement and recovery for its synthetic workload. It
does not replace the separate successor-scale rate/latency qualification or
establish deployment RSS sizing.

## Expanded synthetic run

The expanded Linux release proof passed on 2026-10-06 with Rust 1.98.1 against
`3bd21d1e5c7a3caf0b3240ec5f8f2db42c2b1135`. All 128 reclaim batches completed
at the full 1,048,576-binding boundary. Six follower crashes and one serving
leader crash recovered from the original storage. A replacement leader served
exact status/replay while the old leader was down. All three voters finished
Ready with matching history, epoch-nine work succeeded, and the epoch-eight
sentinel remained exactly replayable.

| Observation | Measured value |
| --- | --- |
| Fill reservation peak across voters and incarnations | 46,649,202 bytes (44.49 MiB) |
| Retirement reservation peak, including cold reopen | 44,204,503 bytes (42.16 MiB) |
| Unchanged per-process cap | 134,217,728 bytes (128 MiB) |
| Verification-admission failures / crash-hook timeouts | 0 / 0 |
| Complete proof, including setup and joined shutdown | 832.354 seconds |
| Retirement through recovery, final checks and shutdown | 385.063 seconds |
| Reopen at retirement / capture / before append / after append | 50.088 / 51.587 / 51.616 / 54.598 seconds |
| Reopen at selector / covered-file reclamation / leader loss | 51.547 / 51.578 / 53.026 seconds |

The three current voter logs and seven archived crash logs independently agree
with those peaks and report the unchanged cap. Neither admission waiting nor
the memory checkpoint trigger engaged in this full proof: the scheduled crash
checkpoints kept the live deletion journal below 8 MiB, and even an entire
single-command retirement journal is below the 24 MiB stop. The forced-pressure
regressions separately passed relief, timeout/fencing, shutdown interruption and
no-empty-checkpoint assertions using the real counter and wait statistics.

The full-generation recovery regression also passed on that revision. Its 257
committed maintenance entries reclaimed 262,144 receipts before the writer
started, retaining a 21,059,232-byte journal (20.08 MiB). Total retained
verification reservations were 21,965,368 bytes (20.95 MiB), and the actual
cold-open/replay peak was 22,037,112 bytes (21.02 MiB), below the 64 MiB test
limit. The complete recovered journal then passed checkpoint validation and
append. This test took 24.79 seconds in release mode.

The final gate passed 63 focused store tests in 108.26 seconds, plus that
full-generation recovery test (64 store tests total); the one testkit command
inventory test; warnings-denied Clippy for both touched crates; formatting; and
whitespace checks. The complete gate, including compilation and the full proof,
took 1,331.600 seconds. These measurements identify their exact tested revision.
Remote CI, other platforms, general mixed-write exhaustion, power-loss testing
and fresh independent review are not covered by these local results.

## Initial synthetic run (before review fixes)

The Linux release proof passed on 2026-10-05 with Rust 1.98.1 against the Rust
source committed as `ab14ffe31aeb1db5e8c8530fd4fa2cb09b2ba30e`. All 128 reclaim
batches completed, all three voters agreed on the final history, and the four
crashed voter incarnations rejoined without storage cleanup. Epoch-nine work
and the retained epoch-eight exact retry succeeded.

| Observation | Measured value |
| --- | --- |
| Maximum actual reservation across voters and incarnations | 46,435,194 bytes (44.28 MiB) |
| Unchanged per-process cap | 134,217,728 bytes (128 MiB) |
| Verification-admission failures | 0 |
| Complete proof, including setup and joined shutdown | 712.735 seconds |
| Retirement through recovery, final checks and shutdown | 214.169 seconds |
| Reopen at retirement / capture / append / selection | 51.618 / 51.590 / 54.603 / 53.068 seconds |

The same candidate passed 54 focused store tests covering memory ownership,
change journals, asynchronous recovery, history and reservation accounting;
the testkit command-inventory test; warnings-denied Clippy for both touched
crates; formatting; and whitespace checks. These local results do not substitute
for the repository's remote CI and independent review gates.

## Operations

The change preserves stored formats and permits the ordinary rolling update
policy. A crashed or rescheduled durable voter reopens its own existing storage,
audits recovery and rejoins without a node reboot, manual storage cleanup or
replacement by an operator. A surviving quorum continues serving; durable
committed state is recovered. An interrupted reply retains the existing exact
ID/body retry and status semantics.

Shutdown signals pressure waits before joining consensus/storage owners. A
cancelled wait does not fence or clear the WAL queue: accepted WAL work follows
the existing drain path, and the unapplied committed entry replays on reopen.
Persistent pressure with no new low in admission shortfall or live-journal size
for the ten-second inactivity bound fences storage instead of leaving it
silently parked. Checkpoint completion alone cannot renew that bound. A single
checkpoint or relocation drain longer than ten seconds without observable
relief can still fence a healthy voter on very slow storage. A successful
reservation resets the wait; shutdown and planner errors do not fence.

A storage fence is terminal for the embedding process. Its recovery owner is
the process supervisor: the embedding voter must exit non-zero, then kubelet or
systemd restarts it to re-audit and replay the unchanged durable state. The SDK
currently reports terminal storage/engine failure but does not itself guarantee
that exit, and the test voter keeps its command loop running. That pre-existing
fatal-error supervision gap is tracked separately in
[issue #1127](https://github.com/openpacketcore/openpacketcore-sdk/issues/1127).
This change implements neither a supervisor nor in-process reopen. The crash
proof explicitly respawns each killed voter; it proves recovery after restart,
not automatic restart of a still-running fenced process. No manual cleanup or
operator replacement is part of the required recovery contract.

The implementation adds no voluntary restart or emergency-session termination.
Existing session and emergency-session continuity protections continue to apply;
an unavailable voter relies on the surviving quorum until its supervisor restarts it.
