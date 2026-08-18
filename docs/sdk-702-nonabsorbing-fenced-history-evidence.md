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

Capability/mixed-membership coverage pins the final published fixed V2 profile
digest through `fenced_transition_v2_profile_digest()`:
`0f51db98a66918c0b827f76a5dcfd198230f158fceab0b91e12ee9ca472a084c`.

### Retirement qualification arrangement

The workload opens all three fixed durable-quorum voters with the public
`ConsensusSessionStore::open_fixed_durable_quorum_with_clock` constructor and
one shared mutable `Clock`. It advances that clock from fixed `T0` to
`T0 + 24h + 1s`, then calls the public V2 history-state read barrier to commit
logical time before calling `maintain_fenced_transition_v2_history` on the
elected fixed-quorum leader. No LabSingleton authority, direct SQLite change,
private intent, or wall-clock sleep is used.

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

## Commands and results

Results are filled only from actual runs; this record does not fabricate
duration, RSS, snapshot size, or throughput.

```text
ACTUAL (passed, focused evidence):
  public fenced_transition module: 26 / 26
  consensus/store V2 subset: 43 / 43
  crates/opc-session-store/tests/fenced_transition_v2_consensus.rs: 3 / 3
  fixed three-voter first V2 apply: 1 / 1
  recovery current-V3 lifecycle/profile tests: 2 / 2, plus V2 cap/preflight
  snapshot-install/reclaim/profile/topology cases listed above: passed in their
  owning source suites.

PENDING RELEASE SCALE (not yet run; no outcome or metrics are claimed):
  cargo test --locked -p opc-session-store --test fenced_transition_v2_qualification --all-features -- --ignored --exact sustained_131073_unique_v2_transitions_bind_exact_epoch_capacity --nocapture
PENDING result/metrics: elapsed, peak RSS, committed unique transitions,
                        active/retired epoch, reclaimed rows, database bytes,
                        snapshot bytes, restart/snapshot-recovery result.
```

The qualification workload records the machine/CI runner, command, commit,
elapsed time, peak RSS, and the durable counters above. It must not substitute
direct SQLite edits, private state-machine calls, or a fake backend for
consensus proposal/application evidence.
