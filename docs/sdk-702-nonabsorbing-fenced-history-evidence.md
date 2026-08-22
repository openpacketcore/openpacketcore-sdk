# SDK-702 non-absorbing fenced-history qualification

This is the qualification record for V2 epoch-fenced atomic-transition
history. V1 remains frozen and absorbing at 4,096 bindings. V2 is a distinct
schema/capability/receipt namespace; this record does not claim V1 behaviour
was changed.

## Required evidence

Focused deterministic integration tests use actual `ConsensusSessionStore`
proposal and state-machine application paths; focused source tests exercise
the corresponding codec, apply, persistence, snapshot, and recovery seams.
Required qualification coverage is:

- V2 exact-capacity acceptance at 131,072 bindings, deterministic rejection of
  a fresh attempt 131,073 without a lease, record, watch, or second effect,
  and immediate successor rotation while the eight-epoch retained window has
  room;
- the authoritative 1,010,000-operation release workload crossing seven
  successor rotations, with one active plus seven replay epochs, exact
  history state/counters, and 31,072-entry per-epoch headroom observed;
- at the eight-epoch bound, deterministic refusal to open a ninth epoch,
  ordered reclamation of only the oldest eligible replay epoch, and continued
  writes through the existing active epoch during every reclaim batch;
- delayed old retries before, during, and after replicated retirement: exact
  old body is `Retired`, an old full ID with a changed body is conflict, and
  neither executes;
- restart, snapshot install and recovery of a retained V2 receipt/floor;
- mixed current voters and a prospective joining voter refusing V2 until every
  voter reports the exact immutable profile, followed by first-command format
  activation; and
- topology cutover clearing the scope certificate and requiring a fresh exact
  V2 proof before the successor scope activates.

### Existing focused evidence

The ordinary `fenced_transition_v2_consensus` integration target includes
`v2_durable_restart_preserves_exact_replay_and_changed_body_conflict`: it
commits through Openraft, drops the store, reopens the same SQLite and snapshot
directories through the public constructor, then proves exact replay and a
changed-body conflict. This is a real durable restart, not a direct SQLite
receipt assertion.

The focused source suites supply the remaining deterministic persistence and
admission evidence. Their test boundaries are intentional: the SQLite tests
exercise the snapshot database install validator and state-machine apply
directly, while the integration target exercises public Openraft proposal and
restart paths.

| Required property | Existing exact test evidence |
| --- | --- |
| V3 snapshot retains a live V2 receipt, exact replay, and changed-body conflict | `sqlite::consensus::fenced_transition_v2_snapshot_installs_exact_replay_and_rejects_live_omission` |
| Snapshot during reclaim retains retired floor/cursor/remaining state and rejects regression | `sqlite::consensus::fenced_transition_v2_snapshot_during_reclaim_preserves_cursor_and_rejects_regression` |
| Reopen/recovery retains V3 lifecycle branch and rejects lifecycle/profile/receipt corruption | `recovery::tests::current_recovery_inspection_accepts_populated_v3_history_and_reopen_preserves_branch`; `current_recovery_v3_rejects_lifecycle_corruption_and_distinguishes_floor`; `current_recovery_v3_rejects_profile_and_receipt_commitment_corruption` |
| Capacity rotation opens successors while a replay slot is free; at eight epochs retirement advances only the oldest floor, deletes ordered 1,024-row batches, and leaves the active epoch writable | `sqlite::consensus::fenced_transition_v2_capacity_opens_successor_and_bounds_eight_exact_epochs`; `fenced_transition_v2_floor_reclaims_oldest_while_successor_remains_writable`; `fenced_transition_v2_maintenance_exact_empty_or_too_early_is_unit_but_stale_is_not_active` |
| Delayed-ID classification seams: full-ID/body commitment, persisted exact replay/conflict, and retired-floor lifecycle | `fenced_transition::v2_id_is_deterministic_and_commits_the_complete_body`; `sqlite::consensus::fenced_transition_v2_snapshot_installs_exact_replay_and_rejects_live_omission`; `fenced_transition_v2_post_reclaim_deletion_keeps_retired_and_conflict_closed` |
| Exact capacity and no-effect one-over rejection | `sqlite::consensus::fenced_transition_v2_cap_accepts_last_binding_and_rejects_next_without_effect` |
| First activation and reactivation bind an exact scope without resetting durable V2 history | `consensus::store::v2_preproposal_binds_full_id_and_first_activation_scope`; `v2_reactivation_at_active_epoch_is_admitted_and_external_maintenance_rejects`; `sqlite::consensus::revoked_activation_wrapper_after_cutover_is_no_effect_and_does_not_poison_successor` |
| Cutover/snapshot certificate rule: preserve a current exact certificate, but accept a successor scope only without the old certificate | `sqlite::consensus::activated_snapshot_preserves_a_current_certificate_but_accepts_successor_without_one` |
| Current voter V1/profile mismatch and local codec/profile drift fail before V2 advertisement or activation | `consensus::store::v2_probe_rejects_v1_only_and_profile_mismatched_voters`; `v2_local_profile_mismatch_disables_advertisement_probe_and_activation`; `sqlite::consensus::fenced_transition_v2_payload_cap_is_profile_bound_at_follower_and_apply_boundaries` |
| Prospective learner with V1 or mismatched V2 profile fails before learner admission | `consensus::store::membership::durable_v2_history_gates_v1_or_mismatched_learners_before_admission` |
| A live current voter with a mismatched profile blocks activation without a replicated effect; exact replies then activate and apply on every voter | `consensus_openraft::fenced_transition_v2_current_voter_probe_fails_closed_then_activates_on_exact_replies` |
| A real 3-to-5 topology rejects V1 and mismatched prospective voters before learner admission, then clears and reacquires the exact certificate across cutover and restart | `dynamic_membership::v2_history_requires_exact_prospective_learner_and_recertifies_after_cutover_restart` |
| A proposal accepted before caller timeout applies once, returns an ambiguous caller outcome, and exact readback/retry cannot produce a second watch-visible effect | `consensus::store::tests::v2_accepted_proposal_timeout_records_one_effect_and_exact_retry` |
| One-over capacity rejection preserves the complete lease row including expiry, application/watch sequence, record and fence; exact retry and same-ID/different-body conflict remain no-effect | `sqlite::consensus::fenced_transition_v2_cap_accepts_last_binding_and_rejects_next_without_effect`; `fenced_transition_v2_qualification::sustained_131073_unique_v2_transitions_bind_exact_epoch_capacity` |
| Fixed response codec/profile contract | `sqlite::consensus::fenced_transition_v2_response_codec_is_fixed_and_round_trips_all_admitted_results`; `fenced_transition::v2_constants_leave_required_headroom_and_profile_is_fixed` |

The authoritative successor-scale workload may be ignored only when its normal
CI cost is unreasonable. It remains a release qualification: it must run in
the dedicated qualification job with a published command and measured
metrics. Ordinary focused CI covers smaller activation, rotation, exact
replay, changed-body, and oldest-epoch reclamation paths; the complete
eight-epoch/1,010,000-operation check is intentionally part of release
qualification rather than being silently reduced.

`fenced_transition_v2_qualification::sustained_131073_unique_v2_transitions_bind_exact_epoch_capacity`
is retained only as the historical reclaim-then-successor three-voter
artifact. It performed 131,074 unique attempts through Openraft and SQLite apply: 131,072
admitted into epoch 1, one deterministic one-over rejection, and one
successor-epoch commit after all 131,072 bindings were reclaimed in ordered
1,024-row batches. It does not prove
the current active-plus-seven-replay lifecycle; the successor-scale release
gate below is authoritative for that contract. Current immediate rotation
while a replay slot remains free is separate focused evidence from
`fenced_transition_v2_capacity_opens_successor_and_bounds_eight_exact_epochs`;
it is not attributed retroactively to the historical `cc9ac896` run.

The frozen pre-fix V1 RED is preserved separately by
`sqlite::consensus::tests::frozen_v1_history_cap_is_absorbing_after_every_binding_applies`.
It creates all 4,096 unique bindings through production state-machine apply
(no receipt-table seeding), then proves request 4,097, its exact retry, and a
same-ID/different-body retry all remain unbound `HistoryFull` with no business,
lease, fence, application-sequence, or watch-visible effect. The exact command
`cargo test --locked -p opc-session-store --lib --all-features
sqlite::consensus::tests::frozen_v1_history_cap_is_absorbing_after_every_binding_applies
-- --exact --nocapture` passed in 9.30 seconds on the qualification host.

Capability/mixed-membership coverage pins the final published fixed V2 profile
digest through `fenced_transition_v2_profile_digest()`:
`8a0b70b54654c7250cf5469db6e1e545f35e38e9778d5f500fea670696c4bdc3`.

### Retirement qualification arrangement

The workload opens all three fixed durable-quorum voters with the public
`ConsensusSessionStore::open_fixed_durable_quorum_with_clock` constructor and
one shared mutable `Clock`. It advances that clock from fixed `T0` to
`T0 + 24h + 1s`, then calls the public V2 history-state read barrier to commit
logical time before calling `maintain_fenced_transition_v2_history` on the
elected fixed-quorum leader. No LabSingleton authority, direct SQLite change,
private intent, or wall-clock sleep is used.

The fixture resolves the current self-reported, durably ready leader before
every maintenance CAS and every retry. Ordinary application operations may
forward after an election, but the operator maintenance boundary is
deliberately local-leader-only; caching the leader selected before a multi-hour
capacity run would test a stale caller rather than the retirement protocol.

The release fixture also treats a maintenance reply loss as an ambiguous CAS,
not as permission to submit a later batch. It reads the linearized history
state after a transient unavailable or stale-CAS reply: a changed complete
state proves that the attempted batch committed, while an unchanged state
permits a bounded retry of the same expected lifecycle state. Deterministic
`HistoryFull`, `Retired`, `RequestConflict`, and `EpochNotActive` transition
results are never classified as transient.

The continuation makes these linearized assertions, not merely observes row
counts: the first reclaim command advances only the oldest closed epoch's
floor, and every ordered 1,024-row batch preserves the existing active epoch.
A fresh request in that active epoch executes during reclamation. A request
for the not-yet-opened immediate successor reports
`FencedTransitionV2Status::EpochNotActive` until reclamation frees a slot and a
separate full-active maintenance rotation opens it. The delayed old full-ID
exact retry reports `Retired` before, during, and after physical deletion,
while the same full ID with a changed body reports conflict in each phase.

## Mutation matrix

| Seam removed or weakened | Required observation | Test class |
| --- | --- | --- |
| Change V2 max from 131,072, or use `>=` incorrectly | exact bound succeeds; one-over has no effect | consensus apply |
| Omit/full-ID truncate epoch, nonce, or SHA-256 commitment | wrong-body old ID conflicts after row deletion | consensus apply/recovery |
| Consult retired floor before recomputing body commitment | changed body becomes `Retired` instead of conflict | consensus apply |
| Permit local/age-only deletion | restart/follower cannot agree on floor or retry result | recovery/topology |
| Delete rows before advancing floor | old exact retry can become `NotFound` or execute | maintenance apply |
| Make reclamation batch variable or unordered | observed deletion is not exactly the oldest 1,024 rows | maintenance apply |
| Reclaim a non-oldest or unexpired replay epoch | floor advances outside the exact oldest-retention gate | maintenance admission/apply |
| Clear or replace the active epoch during reclaim | active writes stop or target a fabricated successor | maintenance apply |
| Accept a V1 reply, quorum, or mismatched V2 profile | mixed/prospective voter activates V2 | capability probe |
| Preserve a certificate across topology cutover | successor scope does not reprobe | topology apply |
| Separate format/certificate/first receipt from transition | crash/recovery sees partial activation | consensus apply + snapshot |
| Scan receipt rows in memory for counts | capacity/status runtime grows as a full in-memory scan | instrumentation/counter assertion |

### Executed fix-removal mutations

All six mutations were rerun independently against the final candidate's
production source bytes after the successor-epoch, persistent V2 transport,
topology, and ambiguity corrections. Each mutation was one compile-safe
production change, produced the expected semantic RED, and was reversed with
`apply_patch` before the next mutation. Before these documentation-only edits,
the complete candidate diff SHA-256 was
`66938cab08ce35a025cec5163c0a4c1bfb0486ae7834a5e76954455f6a40abdd`
before and after every mutation. The complete pre/post porcelain status was
also identical for every mutation, with SHA-256
`1ef0a114ab1efd3b8cf258619891f2b1fa05c3f4b5155a2cfdc3c77bd5fb984d`.
No mutation artifact was committed.

The PR's frozen-head evidence comment identifies the signed head/tree and
publishes each complete patch, command, RED-output hash, and restored-state
proof. Those exact detectors are rerun after the signed frozen head is created;
runtime evidence never changes the frozen tree.

| ID / seam | Exact mutation and detector | Observed RED | Source SHA-256 before and after restore |
| --- | --- | --- | --- |
| M1 capacity/version gating | In `local_fenced_transition_v2_capability_for_backend_capabilities`, change the exact consensus-schema comparison from `==` to `>=`; run `cargo test --locked -p opc-session-store --lib --all-features consensus::store::membership_tests::v2_local_profile_mismatch_disables_advertisement_probe_and_activation -- --exact --nocapture` | exit 101: a future schema advertised `Some(V2)` instead of `None`; log SHA-256 `f69f2d6580b6aa5be8fa3672eb608fb859d35405c8f80f1ea4daf3d150cbc36e` | `3d1a154a4f203708671eba226b5ed3671d81731fb4fbbda6939d6be9fe4c4d7b` |
| M2 irreversible retirement floor | In `classify_fresh_v2_history_epoch`, change `request_epoch <= floor` to `<`; run `cargo test --locked -p opc-session-store --lib --all-features consensus::store::membership_tests::v2_fresh_recertification_classifies_delayed_predecessor_epochs_by_floor -- --exact --nocapture` | exit 101: epoch equal to the floor returned `Ok(())` instead of terminal `FencedTransitionHistoryEpochRetired`; log SHA-256 `d10822df4226148e96f20611e92a1f435ec19fd83baa941fb14bbaa7d4e96169` | `3d1a154a4f203708671eba226b5ed3671d81731fb4fbbda6939d6be9fe4c4d7b` |
| M3 ordered tombstone reclamation | In `maintain_fenced_transition_v2_history_sync`, change the bounded ordinal selection from ascending to descending; run `cargo test --locked -p opc-session-store --lib --all-features sqlite::consensus::tests::fenced_transition_v2_reclaims_exactly_1024_then_opens_next_epoch -- --exact --nocapture` | exit 101: first reclaim failed closed with `fenced transition V2 reclaim order is invalid`; log SHA-256 `400589bf3873549f7045b947db668fb651fbc3634382e5c877abd6cf56c13c46` | `3c3500322156d14098df598abe1a812f4898bd9b9b11184963e6273393a6b4a0` |
| M4 snapshot preservation/antirollback | Return early for every activated incoming V2 layout in `validate_attached_snapshot_preserves_fenced_transition_v2_history_sync`; run `cargo test --locked -p opc-session-store --lib --all-features sqlite::consensus::tests::fenced_transition_v2_snapshot_during_reclaim_preserves_cursor_and_rejects_regression -- --exact --nocapture` | exit 101: an earlier reclaim snapshot installed instead of being rejected; log SHA-256 `88f91f43372f7e9a1e46893ec38cf062ac4142676c28eb2f8e69647a04a55567` | `3c3500322156d14098df598abe1a812f4898bd9b9b11184963e6273393a6b4a0` |
| M5 follower projection/apply dispatch | Make the plain `SessionMutationIntent::FencedTransitionV2` classifier return `None`; run `cargo test --locked -p opc-session-store --lib --all-features sqlite::consensus::tests::fenced_transition_v2_projection_and_apply_share_fixed_retention_horizon -- --exact --nocapture` | exit 101: projection retained zero V2 bindings instead of one; log SHA-256 `b44b86e5d4f4715cda71b17cf5d32236c7a3684f3d6a640dc09090807d333cdf` | `3c3500322156d14098df598abe1a812f4898bd9b9b11184963e6273393a6b4a0` |
| M6 replay/body conflict | Make a V2 body-commitment mismatch return success from `FencedTransitionV2Request::validate`; run `cargo test --locked -p opc-session-store --lib --all-features fenced_transition::tests::v2_id_is_deterministic_and_commits_the_complete_body -- --exact --nocapture` | exit 101: a changed body under the preserved full ID was accepted instead of `FencedTransitionRequestConflict`; log SHA-256 `495f52843d65a826c947d23d6f5bba964cd5d10ffef88f0e0faf8d51f8f3a329` | `dc710185c6e33a1c5b52c4e1b5c4494f320a365426c04c814084cfb8b1609eac` |

## Commands and results

Results are filled only from actual runs; this record does not fabricate
duration, RSS, snapshot size, or throughput.

```text
ACTUAL (passed, focused evidence):
  public fenced_transition module: 28 / 28
  SQLite V2 persistence/reclamation subset: 19 / 19
  crates/opc-session-store/tests/fenced_transition_v2_consensus.rs: 3 / 3
  fixed three-voter first V2 apply: 1 / 1
  recovery suite: 38 / 38, including current-V3 lifecycle/profile and cap/preflight
  frozen V1 4,096/4,097 apply-path RED: 1 / 1 (9.30 seconds)
  snapshot-install/reclaim/profile/topology cases listed above: passed in their
  owning source suites.

ACTUAL (passed, release scale at `cc9ac896858d64bc6f6a5424b094fb361a57caea`,
tree `fbccc8fd5546c6bdefc6aee54bfe0d36b1012f63`):
  cargo test --locked -p opc-session-store --test fenced_transition_v2_qualification --all-features sustained_131073_unique_v2_transitions_bind_exact_epoch_capacity -- --ignored --exact --nocapture
  unique transition attempts: 131,074
  committed unique transitions: 131,073
  epoch-1 bindings admitted: 131,072
  deterministic one-over rejections without business-state effect: 1
  reclaimed bindings: 131,072 in ordered 1,024-row batches
  successor-epoch transitions committed after reclamation: 1
  transient exact-ID/body retries: 2,214
  database envelope: 2,182,756,256 bytes
  snapshot envelope: 2,077,053,072 bytes
  elapsed: 10,637.78 seconds (2:57:18 wall clock)
  peak RSS: 308,544 KiB
  CPU: 260 percent
  delayed exact retry and same-ID/different-body conflict: passed before,
    during, and after physical reclamation
  process exit: 0
```

The complete 33-line output is retained on PR #704. Its 1,601 bytes have
SHA-256 `910c98af114164cbee5ce740fab69708aef4f0713d6db847280c6af44040afe4`.
The database and snapshot measurements are envelope sizes, not steady-state
resident memory and not a production sizing recommendation. They bound this
unoptimized qualification workload and make its storage cost explicit.

The qualification workload records the machine/CI runner, command, commit,
elapsed time, peak RSS, and the durable counters above. It must not substitute
direct SQLite edits, private state-machine calls, or a fake backend for
consensus proposal/application evidence.

## Successor-scale release gate

The historical 131,073-transition result above is capacity evidence for the
pre-successor arrangement; it is not evidence for the release traffic envelope
or a 1,000 operations/second claim. The authoritative release-scale command is
now:

```text
cargo test --locked --release -p opc-session-store --test fenced_transition_v2_qualification \
  --all-features release_1010000_operation_successor_scale_is_bounded_and_recoverable \
  -- --ignored --exact --nocapture
```

The optimized Cargo `release` profile is part of the evidence contract. The
test fails closed before allocating voter state when `debug_assertions` are
enabled, and its fixed-dimension phase and final summaries record
`cargo_profile=release`. Default unoptimized test-profile output is diagnostic
only and cannot qualify the performance gate.

`release_1010000_operation_successor_scale_is_bounded_and_recoverable` opens
three real fixed durable-quorum OpenRaft voters backed by SQLite. It submits
exactly 1,010,000 public V2 operations: a 50,000-session create preload,
500 operations/second pacing for 30 minutes, and 1,000 operations/second
pacing for 60 seconds. The first activation uses the existing singleton V2
transition; all remaining independent requests use public
`ConsensusSessionStore::fenced_transition_v2_batch` calls with at most 256
items. The unpaced preload uses batches of 256; paced traffic uses batches of
8, giving the 500/s phase a 16 ms maximum formation window before quorum work.
This is physical Raft/SQLite coalescing only, not a caller-visible
all-or-nothing multi-key transaction: every item retains its complete V2 ID,
independent result, and singleton status lookup. Pacing never drops a request
when the quorum falls behind, so the emitted `achieved_ops_per_second` is the
actual measured rate and must be published instead of inferred from the target
rate. Because the last scheduled arrival still has to complete, the finite-run
gate requires at least 99.9% of the offered rate as well as the latency SLO.
The emitted `peak_unjoined_batch_task_slots` is the peak `JoinSet::len()`
after a batch task is submitted: batch task slots not yet joined, including a
task that may already have completed. It remains no greater than production
proposal admission, but does not measure simultaneously executing consensus
calls.
The 1,010,000-ID workload is followed by one separately reported fresh active
epoch write during reclaim, which is lifecycle evidence rather than paced-load
traffic.

Before logical time advances, the test crosses seven successor rotations and
asserts the fixed eight-epoch resource contract (1 writable epoch plus at
most 7 exact-replay epochs, or 1,048,576 receipt bindings). It attests and
replays one exact request from every retained epoch, rejects each altered body,
and restarts all three voters through the public constructors before repeating
those checks. It then advances the injected shared clock by 24 hours plus one
second, advances only the oldest floor, verifies the ordered 1,024-row reclaim
limit, and proves the active successor can still mutate. It retains raw
bounded-batch and per-item scheduled-to-completion latency samples for each
paced phase, emits achieved rate and p99/p99.9, and asserts the item p99 is at
most 25 ms and p99.9 at most 100 ms. It also emits topology, committed count,
rotations, semantic resource bound, retry count, database bytes, snapshot
bytes, and elapsed duration.

The isolated three-voter gate enforces fixed physical regression ceilings in
addition to the 18,469,617,664-byte semantic receipt bound: each voter may use
at most 55,408,852,992 bytes for its SQLite database family and at most
36,939,235,328 bytes for its snapshot directory. The whole in-process
three-voter topology has a Linux `VmHWM` ceiling of 2,097,152 KiB. Per-voter
database and snapshot values are asserted and emitted both before and after
reclaim. These deliberately conservative ceilings cover SQLite page/index and
bounded-WAL overhead in this otherwise empty qualification cluster; they do
not introduce an SDK quota over unrelated session data in a shared production
database.

Runtime results are intentionally head-addressed PR evidence rather than
self-referential source text. Merge requires the PR to identify the exact
signed frozen head/tree, attach this command's complete raw output and SHA-256,
and report all offered/achieved rates, raw-sample counts, p99/p99.9 values,
resource ceilings/measurements, topology, restart/replay/conflict/reclaim
results, and process exit. No artifact may claim 500/s or 1,000/s,
latency-SLO compliance, or resource compliance before that exact frozen-head
command completes successfully.
