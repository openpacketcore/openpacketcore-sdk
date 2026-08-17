# Atomic Fenced Transition Evidence

This file retains the reproducible store-side evidence for SDK issue #696.
Commands were run from the repository root through
`/srv/agents/agent-codex/.local/bin/opc-heavy`; no shared target directory or
build-environment override was used.

## Revision and scope

- Assigned branch: `feat/696-atomic-fenced-transition-wm-20260816`
- Published stacked dependency head: `514f2a96d5bf36b8f3e40afccd03a5771655e218`
- Published dependency tree: `d70b02830b87d99765a4a0eefe627df8f310c6e7`
- Included before #695: generic `opc-session-store` model, consensus admission,
  SQLite apply/persistence/recovery, snapshots, documentation, and tests.
- Excluded before #695 publishes: `opc-session-net`, any wire revision, and all
  product/ePDG schema or protocol semantics.

## Retained RED: the old split boundary

`red_696_split_acquire_then_cas_leaves_a_committed_intermediate_boundary`
uses only the pre-existing lease-acquire, CAS, log, watch, and read-only SQLite
surfaces. It proves that the old composition commits two adjacent consensus
entries. After the first entry, the lease/fence is durable while the exact
record is still absent; only the second entry installs it. The journal and
watch likewise expose two separate effects. That observable state is the crash
and competing-owner race boundary removed by the one-entry primitive.

```text
/srv/agents/agent-codex/.local/bin/opc-heavy cargo test --locked \
  -p opc-session-store --test consensus_openraft \
  red_696_split_acquire_then_cas_leaves_a_committed_intermediate_boundary \
  --all-features -- --exact
result: PASS (1 passed)
```

## Fix-removal mutation: OutcomeUnknown

Mutation: remove the fenced-transition disjunct that converts a forwarded
post-transmission failure into the typed unknown outcome. The exact regression
then failed at `consensus_openraft.rs:3067` with
`a possibly delivered transition returns typed ambiguity`. Restoring the
disjunct made the same command pass.

```text
/srv/agents/agent-codex/.local/bin/opc-heavy cargo test --locked \
  -p opc-session-store --test consensus_openraft \
  fenced_transition_does_not_auto_replay_after_forward_write_boundary \
  --all-features -- --exact
mutated result: FAIL (expected RED)
restored result: PASS (1 passed)
```

## Fix-removal mutation: record owner and fence

Mutation: weaken the renew-side record authorization from rejecting either an
owner mismatch or a fence mismatch to rejecting only when both fields differ.
The regression failed at `consensus_openraft.rs:2864` because a still-valid
lease mutated a record whose owner alone differed. Restoring the disjunction
made the exact test pass.

```text
/srv/agents/agent-codex/.local/bin/opc-heavy cargo test --locked \
  -p opc-session-store --test consensus_openraft \
  fenced_transition_renew_rejects_record_owner_or_fence_mismatch \
  --all-features -- --exact
mutated result: FAIL (expected RED)
restored result: PASS (1 passed)
```

## Fix-removal mutation: expected generation

Mutation: accept every present expected generation against every present
record instead of requiring equality. The regression failed at
`consensus_openraft.rs:2740` because the unexpected generation renewed the
lease and replaced the record. Restoring exact equality made the same command
pass.

```text
/srv/agents/agent-codex/.local/bin/opc-heavy cargo test --locked \
  -p opc-session-store --test consensus_openraft \
  fenced_transition_stale_fence_and_generation_rejections_leave_state_unchanged \
  --all-features -- --exact
mutated result: FAIL (expected RED)
restored result: PASS (1 passed)
```

## Fix-removal mutation: durable complete-body binding

Mutation: bypass the persisted request-digest mismatch branch during apply
replay. The exact receipt regression failed closed at
`sqlite/consensus.rs:11901` while processing the different-body request,
instead of returning its committed `RequestConflict`. Restoring the digest
comparison returned the typed no-effect conflict and made the test pass.

```text
/srv/agents/agent-codex/.local/bin/opc-heavy cargo test --locked \
  -p opc-session-store --lib \
  sqlite::consensus::tests::fenced_transition_receipt_replays_conflicts_and_expires_to_a_tombstone \
  --all-features -- --exact
mutated result: FAIL (expected RED)
restored result: PASS (1 passed)
```

## Fix-removal mutation: follower request identity admission

Mutation: bypass the follower-log equality check between the outer consensus
request ID and the typed transition request ID. The regression failed at
`sqlite/consensus.rs:13572` because the mismatched entry entered the follower
log. Restoring the equality check made follower and apply admission reject the
entry again.

```text
/srv/agents/agent-codex/.local/bin/opc-heavy cargo test --locked \
  -p opc-session-store --lib \
  sqlite::consensus::tests::fenced_transition_outer_request_id_mismatch_fails_follower_and_apply_admission \
  --all-features -- --exact
mutated result: FAIL (expected RED)
restored result: PASS (1 passed)
```

## Canonical V1 request commitment

`fenced_transition_v1_request_digest_has_a_pinned_protocol_vector` fixes the
complete canonical request commitment at
`a66db3c2afb0c176d63d2f528f1466e33c7317c81b3a61efb1f3aed5bfe0ce08`.
The same test proves that leader time, outer consensus schema metadata,
forwarding origin, and changing authority identity do not change V1 caller
semantics, while changing one canonical request field does.

```text
/srv/agents/agent-codex/.local/bin/opc-heavy cargo test --locked \
  -p opc-session-store --lib \
  sqlite::consensus::tests::fenced_transition_v1_request_digest_has_a_pinned_protocol_vector \
  --all-features -- --exact
result: PASS (1 passed)
```

## Verification completed before final hardening

These runs established the initial coherent store implementation; every item
is rerun after the retained-result, acquisition-time, and receipt-integrity
hardening lands.

```text
cargo check --locked -p opc-session-store --all-targets --all-features
result: PASS

cargo test --locked -p opc-session-store --lib fenced_transition --all-features
result: PASS (20 passed)

cargo test --locked -p opc-session-store --lib fenced_ --all-features
result: PASS (39 passed)

cargo test --locked -p opc-session-store --test consensus_openraft \
  fenced_transition --all-features
result: PASS (15 passed)
```

The 15-test three-voter filter includes the deterministic before-proposal,
after-proposal/before-commit, after-commit/before-response, leader-transfer,
capability-downgrade, exact replay, and no-auto-replay paths. It also proves
that Acquire+Create and each Renew+Update/RefreshTtl/Delete operation consume
one consensus entry and expose one ordered two-operation application/watch
batch. The absent and exact-record-expiry matrix records `CasConflict` for
Update/RefreshTtl/Delete without renewing the lease or creating a record,
fence, application sequence, or watch effect.

```text
/srv/agents/agent-codex/.local/bin/opc-heavy cargo test --locked \
  -p opc-session-store --lib fenced_ --all-features
result: PASS (49 passed)

/srv/agents/agent-codex/.local/bin/opc-heavy cargo test --locked \
  -p opc-session-store --test consensus_openraft \
  fenced_transition --all-features
result: PASS (15 passed)
```

## Published-#684 recovery compatibility

The additive receipt commitments and persisted lease-acquisition timestamp
remain compatible with the exact published #684 database and snapshot shapes.
Read-only recovery projects the absent acquisition timestamp as an explicit
non-authoritative `NULL`, and only its exact legacy path treats an absent or
empty unpublished receipt table as an empty ledger. Normal runtime, follower,
append, replay, and populated/partial legacy-ledger paths remain fail-closed.

The pinpointed regression and the complete recovery matrix were rerun after
fixing the recovery-only log projection:

```text
/srv/agents/agent-codex/.local/bin/opc-heavy cargo test --locked \
  -p opc-session-store --lib \
  recovery::tests::current_recovery_inspection_accepts_pre_ledger_replica \
  --all-features -- --exact --nocapture
result: PASS (1 passed)

/srv/agents/agent-codex/.local/bin/opc-heavy cargo test --locked \
  -p opc-session-store --lib recovery:: --all-features
result: PASS (38 passed)
```

The 38-test matrix includes exact pre-acquisition lease schema inspection,
conversion, recovery planning, and digest equivalence; absent and empty legacy
receipt-ledger acceptance; and rejection of populated, partial, oversized,
prematurely compacted, malformed, or durable-floor-inconsistent receipts.

The final section will contain the exact post-integration store package, Clippy,
format, documentation, workspace CI, hosted-check, and three-voter transport
results once #695 publishes and is merged normally.
