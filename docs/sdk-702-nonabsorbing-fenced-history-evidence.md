# SDK-702 non-absorbing fenced-history qualification

This record defines the qualification boundary for V2 epoch-fenced atomic
transition history. V1 remains frozen and absorbing at 4,096 bindings. V2 is a
separate schema, capability, receipt, and consumer-transport namespace; it does
not change V1 behavior.

## Contract under qualification

V2 retains one writable epoch and at most seven closed replay epochs. Each epoch
has a hard maximum of 131,072 bindings, so the V2 ceiling is 1,048,576 bindings.
The active epoch remains writable while eligible reclamation advances the
retired floor and deletes the oldest closed epoch in deterministic 1,024-row
batches. A complete V2 request ID and canonical body commitment are checked
before retired-floor classification:

- an exact delayed retry at or below the retired floor is Retired and does not
  execute;
- a changed body under the retained full ID is a conflict, including after
  receipt-row deletion; and
- an epoch above the floor but not active is EpochNotActive, not Retired.

No node may retire, delete, or open an epoch from a local clock, compaction
cycle, restart, snapshot restore, or memory pressure. Retirement is a replicated
local-leader-only operator CAS; an unavailable reply is ambiguous until a fresh
linearized history-state read establishes whether the complete expected CAS
committed.

V2 activation requires the exact published V2 profile from every current voter
and any prospective joining voter participating in the cutover. A V1 reply, a
quorum-only result, a capability bit, or a V2 reply with another profile is not
activation evidence. The profile digest is
8a0b70b54654c7250cf5469db6e1e545f35e38e9778d5f500fea670696c4bdc3.

## Focused deterministic evidence

Focused tests exercise the deterministic codec, state-machine application,
SQLite persistence, snapshot installation, and recovery seams. The ordinary
fenced_transition_v2_consensus integration target additionally verifies a
durable public-constructor reopen: it commits through the consensus path, drops
the store, reopens the same SQLite and snapshot directories, and checks exact
replay plus changed-body conflict.

The SQLite-focused cases deliberately cover broader delayed-request
classification before, during, and after retirement. They are the evidence for
that detailed classification; the release-scale public gate below does not
claim to replace them.

| Required property | Focused evidence |
| --- | --- |
| Snapshot preserves a live V2 receipt, exact replay, and changed-body conflict | sqlite::consensus::fenced_transition_v2_snapshot_installs_exact_replay_and_rejects_live_omission |
| Snapshot during reclaim preserves retired floor/cursor and rejects regression | sqlite::consensus::fenced_transition_v2_snapshot_during_reclaim_preserves_cursor_and_rejects_regression |
| Reopen/recovery preserves the populated lifecycle branch and rejects corruption | recovery::tests::current_recovery_inspection_accepts_populated_v3_history_and_reopen_preserves_branch |
| Rotation and active-epoch availability at the retained bound | sqlite::consensus::fenced_transition_v2_capacity_opens_successor_and_bounds_eight_exact_epochs; fenced_transition_v2_floor_reclaims_oldest_while_successor_remains_writable |
| Delayed full-ID/body classification before, during, and after retirement | fenced_transition::v2_id_is_deterministic_and_commits_the_complete_body; sqlite::consensus::fenced_transition_v2_post_reclaim_deletion_keeps_retired_and_conflict_closed |
| Exact capacity and no-effect one-over rejection | sqlite::consensus::fenced_transition_v2_cap_accepts_last_binding_and_rejects_next_without_effect |
| Exact profile/voter proof and topology-cutover re-certification | consensus::store::v2_probe_rejects_v1_only_and_profile_mismatched_voters; dynamic_membership::v2_history_requires_exact_prospective_learner_and_recertifies_after_cutover_restart |

The frozen V1 regression remains separately covered by
sqlite::consensus::tests::frozen_v1_history_cap_is_absorbing_after_every_binding_applies.
It proves through production state-machine application that binding 4,097, its
exact retry, and a same-ID/different-body retry remain unbound HistoryFull
without lease, record, fence, application-sequence, or watch-visible effects.

## Retirement gate

The public successor-scale gate must use three fixed durable-quorum voters
opened through the public constructor and a shared injected clock. After the
oldest closed epoch is eligible, it must obtain a fresh linearized V2 history
state and submit maintenance only to the current local leader.

The gate's retirement proof is intentionally narrow and explicit:

1. one reclaim CAS advances only the oldest closed epoch's floor and deletes
   one ordered 1,024-row batch;
2. exactly one intervening write through the existing active epoch succeeds;
3. a second reclaim CAS advances the same oldest epoch by one further ordered
   1,024-row batch; and
4. the active epoch remains writable.

This gate does not claim completion of a historical multi-batch deletion, nor
does it use historical output as current acceptance evidence. The broader
before/during/after exact-retry, changed-body-conflict, and Retired
classification is covered by the focused SQLite cases above.

## Successor-scale release gate

The release qualification target is
release_1010000_operation_successor_scale_is_bounded_and_recoverable in the
ignored fenced_transition_v2_qualification integration suite, run in Cargo's
release profile. It is a three-voter public V2 workload with 1,010,000 logical
operations: a 50,000-session preload, 500 logical operations per second for 30
minutes, and 1,000 logical operations per second for 60 seconds. Its bounded
client task slots are not a claim about simultaneous consensus calls. Public V2
effect-boundary handling permits only same-body NotTransmitted retry;
OutcomeUnknown converges through exact ID/body status and never redispatches the
mutation.

Before clock advancement, the gate must cross seven successor rotations, retain
one writable plus seven replay epochs, and verify the complete request/outcome
binding for every submitted item. The 1,010,000-operation count excludes the
separately reported intervening active-epoch reclaim write. Resource and
latency samples are evidence outputs, not inferred from the offered rate.

The emitted headroom dimensions are intentionally distinct. The
`operational_headroom_transitions` value is 31,072 per active epoch
(131,072 - 100,000): it belongs to the separate active-epoch operational
target qualification. The successor-scale release workload instead has
`retained_envelope_headroom_transitions` of 38,576
(1,048,576 - 1,010,000) within the complete one-active-plus-seven-replay-epoch
retained envelope. Neither value is a substitute for the other.

### Final-head status: pending

No final-head 1.01M result is recorded in this source document. It remains
pending until the target above completes successfully against the final signed
frozen head. The external final record must identify that exact head and tree,
include the complete raw output and its SHA-256, and report actual profile
values, offered and achieved rates, sample counts and p99/p99.9, matched
outcomes, resource measurements, restart/replay/conflict results, the two
reclaim batches, the intervening write, and process exit.

Historical runs, including any prior failures or superseded runs, are neither
acceptance nor substitutes for this final frozen-head execution.

## Real-mTLS boundary

The existing real-mTLS V2 release gate uses 48 normal authenticated lanes and
at most 48 calls in flight. Its 1,000 figure is a rate of logical store
operations per second; it is not 1,000 concurrent actors, 1,000 concurrent
calls, or 1,000 attaches per second. Those lanes remain fixed pooled transport
lanes, not per-subscriber attachments.

The #695 real-mTLS p99 and p99.9 qualification remains open. No #704 evidence
may claim that #695 latency percentile qualification has completed merely
because this V2 gate emits or checks its own bounded samples.

## SDK receiver boundary

V2 uses the SDK-side consumer and store receiver boundary. It does not require
an upstream OpenRaft receiver change, an OpenRaft edit, or an OpenRaft pin
change. OpenRaft remains the existing consensus authority; this qualification
does not authorize a dependency change.
