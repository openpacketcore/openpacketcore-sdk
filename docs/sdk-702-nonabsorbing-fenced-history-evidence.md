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

- V2 exact-capacity acceptance at 131,072 bindings and deterministic rejection
  of binding 131,073 without a lease, record, watch, or second effect;
- at least 100,000 unique committed V2 transitions, crossing a retirement
  window, with the history state/counters and 31,072-entry headroom observed;
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
| Retirement advances the floor, deletes ordered 1,024-row batches, holds the successor inactive, then opens only the next epoch | `sqlite::consensus::fenced_transition_v2_reclaims_exactly_1024_then_opens_next_epoch`; `fenced_transition_v2_maintenance_exact_empty_or_too_early_is_unit_but_stale_is_not_active` |
| Delayed-ID classification seams: full-ID/body commitment, persisted exact replay/conflict, and retired-to-successor lifecycle | `fenced_transition::v2_id_is_deterministic_and_commits_the_complete_body`; `sqlite::consensus::fenced_transition_v2_snapshot_installs_exact_replay_and_rejects_live_omission`; `fenced_transition_v2_reclaims_exactly_1024_then_opens_next_epoch` |
| Exact capacity and no-effect one-over rejection | `sqlite::consensus::fenced_transition_v2_cap_accepts_last_binding_and_rejects_next_without_effect` |
| First activation and reactivation bind an exact scope without resetting durable V2 history | `consensus::store::v2_preproposal_binds_full_id_and_first_activation_scope`; `v2_reactivation_at_active_epoch_is_admitted_and_external_maintenance_rejects`; `sqlite::consensus::revoked_activation_wrapper_after_cutover_is_no_effect_and_does_not_poison_successor` |
| Cutover/snapshot certificate rule: preserve a current exact certificate, but accept a successor scope only without the old certificate | `sqlite::consensus::activated_snapshot_preserves_a_current_certificate_but_accepts_successor_without_one` |
| Current voter V1/profile mismatch and local codec/profile drift fail before V2 advertisement or activation | `consensus::store::v2_probe_rejects_v1_only_and_profile_mismatched_voters`; `v2_local_profile_mismatch_disables_advertisement_probe_and_activation`; `sqlite::consensus::fenced_transition_v2_payload_cap_is_profile_bound_at_follower_and_apply_boundaries` |
| Prospective learner with V1 or mismatched V2 profile fails before learner admission | `consensus::store::membership::durable_v2_history_gates_v1_or_mismatched_learners_before_admission` |
| Fixed response codec/profile contract | `sqlite::consensus::fenced_transition_v2_response_codec_is_fixed_and_round_trips_all_admitted_results`; `fenced_transition::v2_constants_leave_required_headroom_and_profile_is_fixed` |

The exact-capacity workload may be ignored only when its normal CI cost is
unreasonable. It remains a release qualification: it must run in the dedicated
qualification job with a published command and measured metrics. The ordinary
focused CI tests cover the smaller activation, exact-replay, and changed-body
admission paths; the 131,072/one-over capacity check is intentionally part of
the release qualification rather than being silently reduced.

`fenced_transition_v2_qualification::sustained_131073_unique_v2_transitions_bind_exact_epoch_capacity`
is the ignored three-voter fixed-quorum workload. It performs all 131,073
submissions through Openraft and SQLite apply, checks the exact 131,072 bound,
and records elapsed time plus per-run database and snapshot bytes. It does not
seed receipt rows or call private state-machine functions.

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
`bf2210e09a84b417b7270646821b87a73d1a87503821fc44922db22e04879d15`.

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
counts: after the first reclaim command and
through every intermediate ordered 1,024-row batch, a well-formed request for
epoch `retired + 1` reports `FencedTransitionV2Status::EpochNotActive`; after
the final batch it is the active epoch and its new request is `NotFound` before
submission (then may execute). The delayed old full-ID exact retry must report
`Retired` before, during, and after that sequence, while the same full ID with
a changed body must report conflict in each phase.

## Mutation matrix

| Seam removed or weakened | Required observation | Test class |
| --- | --- | --- |
| Change V2 max from 131,072, or use `>=` incorrectly | exact bound succeeds; one-over has no effect | consensus apply |
| Omit/full-ID truncate epoch, nonce, or SHA-256 commitment | wrong-body old ID conflicts after row deletion | consensus apply/recovery |
| Consult retired floor before recomputing body commitment | changed body becomes `Retired` instead of conflict | consensus apply |
| Permit local/age-only deletion | restart/follower cannot agree on floor or retry result | recovery/topology |
| Delete rows before advancing floor | old exact retry can become `NotFound` or execute | maintenance apply |
| Make reclamation batch variable or unordered | observed deletion is not exactly the oldest 1,024 rows | maintenance apply |
| Reclaim while active epoch exists | maintenance is admitted before close | maintenance admission |
| Open an arbitrary next epoch | final batch does not open `retired + 1` | maintenance apply |
| Accept a V1 reply, quorum, or mismatched V2 profile | mixed/prospective voter activates V2 | capability probe |
| Preserve a certificate across topology cutover | successor scope does not reprobe | topology apply |
| Separate format/certificate/first receipt from transition | crash/recovery sees partial activation | consensus apply + snapshot |
| Scan receipt rows in memory for counts | capacity/status runtime grows as a full in-memory scan | instrumentation/counter assertion |

### Executed fix-removal mutations

All six mutations were run independently against signed checkpoint
`814feb1a0486ccd87f7d9c83ca907a6e515e04c0`. Each mutation was a single
compile-safe production change, produced the expected semantic RED, and was
reversed with `apply_patch`. The post-restore SHA-256 is byte-for-byte equal to
the pre-mutation SHA-256; `git status --porcelain=v1` was empty after every
restore. No mutation artifact was committed.

| ID / seam | Exact mutation and detector | Observed RED | Source SHA-256 before and after restore |
| --- | --- | --- | --- |
| M1 capacity/version gating | In `local_fenced_transition_v2_capability_for_backend_capabilities`, change the exact consensus-schema comparison from `==` to `>=`; run `cargo test --locked -p opc-session-store --lib --all-features consensus::store::membership_tests::v2_local_profile_mismatch_disables_advertisement_probe_and_activation -- --exact --nocapture` | exit 101: future schema advertised V2 instead of V1 (`left: V2`, `right: V1`) | `e12fad4015fa7d4e258ee3d48386cadc224945470118335e44b9ae6f26fc7a1d` |
| M2 irreversible retirement floor | In `classify_fresh_v2_history_epoch`, change `request_epoch <= floor` to `<`; run `cargo test --locked -p opc-session-store --lib --all-features consensus::store::membership_tests::v2_fresh_recertification_classifies_delayed_predecessor_epochs_by_floor -- --exact --nocapture` | exit 101: epoch equal to the floor became `FencedTransitionHistoryEpochNotActive` instead of terminal `FencedTransitionHistoryEpochRetired` | `e12fad4015fa7d4e258ee3d48386cadc224945470118335e44b9ae6f26fc7a1d` |
| M3 ordered tombstone reclamation | In `maintain_fenced_transition_v2_history_sync`, change the bounded ordinal selection from ascending to descending; run `cargo test --locked -p opc-session-store --lib --all-features sqlite::consensus::tests::fenced_transition_v2_reclaims_exactly_1024_then_opens_next_epoch -- --exact --nocapture` | exit 101: first reclaim failed closed with `fenced transition V2 reclaim order is invalid` | `df415df7b6099d510e1b03b6804c70cdd98ac4a16de1963daef8671076676f8d` |
| M4 snapshot preservation/antirollback | Return early for every activated incoming V2 layout in `validate_attached_snapshot_preserves_fenced_transition_v2_history_sync`; run `cargo test --locked -p opc-session-store --lib --all-features sqlite::consensus::tests::fenced_transition_v2_snapshot_during_reclaim_preserves_cursor_and_rejects_regression -- --exact --nocapture` | exit 101: an earlier reclaim snapshot installed instead of being rejected (`earlier reclaim snapshot must not regress V2 history`) | `df415df7b6099d510e1b03b6804c70cdd98ac4a16de1963daef8671076676f8d` |
| M5 follower projection/apply dispatch | Make the plain `SessionMutationIntent::FencedTransitionV2` classifier return `None`; run `cargo test --locked -p opc-session-store --lib --all-features sqlite::consensus::tests::fenced_transition_v2_projection_and_apply_share_fixed_retention_horizon -- --exact --nocapture` | exit 101: projection retained zero V2 bindings instead of one | `df415df7b6099d510e1b03b6804c70cdd98ac4a16de1963daef8671076676f8d` |
| M6 replay/body conflict | Make a V2 body-commitment mismatch return success from `FencedTransitionV2Request::validate`; run `cargo test --locked -p opc-session-store --lib --all-features fenced_transition::tests::v2_id_is_deterministic_and_commits_the_complete_body -- --exact --nocapture` | exit 101: a changed body under the preserved full ID was accepted instead of `FencedTransitionRequestConflict` | `548bc315e9543e63945d5b3b47ccc0f9e2538ec53d768a5bc11634af9ca557bf` |

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
