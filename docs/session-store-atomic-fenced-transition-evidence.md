# Atomic Fenced Transition Evidence

This file retains the reproducible store-side evidence for SDK issue #696.
Commands were run from the repository root through
`/srv/agents/agent-codex/.local/bin/opc-heavy`; no shared target directory or
build-environment override was used.

## Revision and scope

- Assigned branch: `feat/696-atomic-fenced-transition-wm-20260816`
- Original published #684 dependency head:
  `514f2a96d5bf36b8f3e40afccd03a5771655e218`
- Landed #684/main dependency head:
  `0ffb7faed75914d3e99f8f9f1a287fbb6cb14aa7`
- Landed #684/main dependency tree:
  `189d22525fe6feb3f895ca5e5c922d2a6319e0a6`
- Store-hardening preservation checkpoint:
  `fbf0f55429103efbbebad009db0231b57af754fd` (tree
  `8b1bad3dcd5088d9e097476adde988c454019d22`), followed by the
  formatting-only `bd8580c868610ea71eaf34ca1c582dc54b5d1458` (tree
  `147bcb134ae7df1bd348d33c777e56c8c65d1599`). Exact-head audit then
  found that the first removal mutation below had accidentally remained in
  both published commits; the current source restores the typed outcome and
  the restoration digest pinned below before any #695 integration.
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

`red_696_split_renew_then_cas_leaves_a_committed_intermediate_boundary`
retains the corresponding existing-record proof. The legacy renewal durably
extends the exact lease while the record remains at its old generation and
payload; only a later CAS installs the successor. The two ordered application
and watch entries expose the crash/race boundary independently of any internal
logical-time entries that Raft may also commit.

```text
/srv/agents/agent-codex/.local/bin/opc-heavy cargo test --locked \
  -p opc-session-store --test consensus_openraft \
  red_696_split_renew_then_cas_leaves_a_committed_intermediate_boundary \
  --all-features -- --exact
result: PASS (1 passed)
```

## Fix-removal mutation: OutcomeUnknown

Mutation: remove the fenced-transition disjunct that converts a forwarded
post-transmission failure into the typed unknown outcome. The exact regression
then failed at the assertion
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
The regression failed because a still-valid lease mutated a record whose owner
alone differed. Restoring the disjunction made the exact test pass.

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
record instead of requiring equality. The regression failed because the
unexpected generation renewed the lease and replaced the record. Restoring
exact equality made the same command pass.

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
replay. The exact receipt regression failed closed while processing the
different-body request, instead of returning its committed `RequestConflict`.
Restoring the digest comparison returned the typed no-effect conflict and made
the test pass.

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
request ID and the typed transition request ID. The regression failed because
the mismatched entry entered the follower log. Restoring the equality check
made follower and apply admission reject the entry again.

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

## Fresh pre-#695 mutation restoration boundary

All five mutations above were rerun on 2026-08-16 against this coherent
pre-#695 working tree. Each exact test failed at its intended invariant and
passed after the one-line mutation was restored. The restored source digests
were then checked against the values captured before the mutation sequence:

```text
9d06760723aa22bb064d383077b36c2ce062199c8073ccb2c289c1d0c239f519  crates/opc-session-store/src/sqlite/consensus.rs
26f4bc9d530f34573ecf3e6d0250131e41a9b660efde3e834e5105aadfc1f049  crates/opc-session-store/src/consensus/store.rs
```

They are rerun once more after #695 integration at the final exact head; this
pre-integration evidence is intentionally not the final merge gate.

## Restored mutation integrity and final requalification plan

The historical mutation results above are retained evidence, not a substitute
for the final current-head qualification. Exact-head review of the preservation
checkpoint detected that the OutcomeUnknown mutation itself had been retained;
it was restored before continuing. The resulting source digests match the
pre-mutation restoration baseline. After the normal #695/origin-main
integration, run one mutation at a time, immediately restore it, and verify
these source digests before starting the next mutation.

```text
4e090668dd34cfe70564787f4e43980b94fd9e698a0ae50542692ccd1b94107b  crates/opc-session-store/src/sqlite/consensus.rs
298dab3f94c9a182be3e667ce60f0cb61e7ce8cfcb475d440169b8562c795736  crates/opc-session-store/src/consensus/store.rs
```

The five one-line removal mutations and their exact regression commands are:

1. In `consensus/store.rs`, map `FencedTransition` in
   `consensus_outcome_unavailable` to the generic backend-outcome error;
   `fenced_transition_does_not_auto_replay_after_forward_write_boundary` must
   fail, then pass after restoring `FencedTransitionOutcomeUnknown`.
2. In `sqlite/consensus.rs`, weaken the renew record identity check from
   `owner != ... || fence != ...` to `owner != ... && fence != ...`;
   `fenced_transition_renew_rejects_record_owner_or_fence_mismatch` must fail,
   then pass after restoring `||`.
3. In `sqlite/consensus.rs`, bypass the present-record equality guard in the
   expected-generation match;
   `fenced_transition_stale_fence_and_generation_rejections_leave_state_unchanged`
   must fail, then pass after restoring exact equality.
4. In `sqlite/consensus.rs`, bypass only the
   `replay_fenced_transition_receipt_sync` body-digest mismatch branch;
   `sqlite::consensus::tests::fenced_transition_receipt_replays_conflicts_and_expires_to_a_tombstone`
   must fail, then pass after restoring the digest comparison.
5. In `sqlite/consensus.rs`, bypass only the follower-log outer/inner request
   ID equality check in `validate_normal_command`;
   `sqlite::consensus::tests::fenced_transition_outer_request_id_mismatch_fails_follower_and_apply_admission`
   must fail, then pass after restoring that equality check.

Each command uses the exact `opc-heavy cargo test --locked -p
opc-session-store --all-features` invocation already printed in its historical
mutation section above, adding `--nocapture` only when diagnostic output is
needed. No mutation may be retained for a second command, and a restored
source digest mismatch is a hard stop rather than an opportunity to infer a
passing restoration.

## Current focused regressions after deterministic repairs

These are current working-tree results from 2026-08-17; they are not the
remaining aggregate, mutation, Clippy, package, workspace, or post-#695 gates.

```text
production_readiness_requires_fresh_authenticated_topology_and_accepts_refresh
result: PASS (1 passed, 4.81s)

lagging_replica_installs_compacted_snapshot_without_losing_committed_state
result: PASS (1 passed, 57.49s)

fenced_transition_snapshot_install_preserves_exact_replay_without_second_effect
result: PASS (1 passed, 55.74s)

committed_write_with_a_late_forward_result_is_typed_ambiguous_and_applied_once
result: PASS (1 passed, 0.89s)

cargo fmt --all --check && git diff --check
result: PASS (wrapper exit 0)
```

The snapshot tests previously exceeded their five-minute command-batch bound
because the durable append/apply path reconstructed two canonical in-memory
SQLite schemas for every activated-ledger validation. The expected immutable
normalized DDL forms are now initialized once with `OnceLock`; each durable
call still reads and exactly validates the actual marker, `sqlite_master`
definition, receipt table, and index.

The readiness test now acquires its capacity-one fixture permit before minting
its real monotonic-expiry evidence, so evidence cannot expire in the test
queue. Its 250 ms test-only timer-dispatch tolerance is not a production
timeout change: `timeout_at` selects the deadline event, but a host runtime
cannot promise that the task is scheduled at the identical wall-clock instant.
The test proves entry into the delayed peer path and sets 3 s/4 s injected
faults for 1 s/2 s attestation budgets, leaving at least 1.75 s between the
asserted upper bound and a completed peer response. Thus it still detects a
barrier that waits for the peer or the 5 s operation deadline instead of the
attestation deadline.

## Independent store hardening evidence

The current store-only hardening adds and exercises:

- permanent bounded request/body and response commitments, including exact V1
  request-digest parity and corruption/reopen rejection;
- the 4096-entry absorbing history cap and exact 24-hour retention horizon;
- a one-way receipt-ledger activation marker, exact markerless #684 migration,
  exact enumeration of all 12 released lease/operator-recovery/restore schema
  products, an attached-only exact pre-authority Dynamic snapshot exception,
  and rejection of activated missing/weak/partial ledger, identity-marker, or
  historical-hybrid state;
- monotonic snapshot-install floors for logical/application/watch/recovery
  state, including the application and recovery digest chains;
- exact replay after snapshot installation without a second effect;
- legacy postcard ordinal parity for every pre-#696 consensus intent, outcome,
  and `StoreError` variant;
- fixed non-identifying Debug output at command, response, store, transition,
  and replication boundaries; and
- inclusive 1 MiB record, 16 KiB public-outcome, and 2 MiB consensus-RPC
  boundaries with one-over rejection.

On 2026-08-16, before the subsequent activation/snapshot hardening and #695
integration, a coherent store-only checkpoint passed:

```text
/srv/agents/agent-codex/.local/bin/opc-heavy cargo test --locked \
  -p opc-session-store --all-features
result: PASS (complete package: all unit, integration, and doc tests)

/srv/agents/agent-codex/.local/bin/opc-heavy cargo clippy --locked \
  -p opc-session-store --all-targets --all-features -- -D warnings
result: PASS

/srv/agents/agent-codex/.local/bin/opc-heavy cargo fmt --all --check
result: PASS

/srv/agents/agent-codex/.local/bin/opc-heavy cargo test --locked \
  -p opc-session-store --test consensus_openraft \
  fenced_transition --all-features
result: PASS (17 passed)
```

The 17-test three-voter filter includes deterministic before-proposal,
after-proposal/before-commit, after-commit/before-response, leader-transfer,
capability-downgrade, exact replay, no-auto-replay, expired-owner takeover,
and snapshot-install replay paths. It also proves that Acquire+Create and each
Renew+Update/RefreshTtl/Delete operation consume one consensus application
entry and expose one ordered two-operation application/watch batch. The absent
and exact-record-expiry matrix records `CasConflict` for
Update/RefreshTtl/Delete without renewing the lease or creating a record,
fence, application sequence, or watch effect.

These are retained historical store-side gates, not the final exact-head
verification. The hardened pre-#695 work was published early for durability;
its exact heavy-gate rerun remains pending behind the active #695/urgent shared
build queue. Every gate, including all five restored mutations, is rerun after
the normal #695 merge together with workspace CI and least-authority consumer
transport evidence.

## Published-#684 recovery compatibility

The additive receipt commitments and persisted lease-acquisition timestamp
remain compatible with the exact published #684 database and snapshot shapes.
Read-only recovery projects the absent acquisition timestamp as an explicit
non-authoritative `NULL`. Only the exact markerless #684 manifest with no
receipt table is accepted as an empty ledger. Read-only inspection does not
mutate that source; writable open or staged recovery creates the exact empty
ledger and one-way activation marker transactionally. A present empty weak or
unpublished table, as well as any populated, partial, malformed, or activated
missing-ledger layout, remains fail-closed.

Snapshot installation has one narrower historical exception: the exact
pre-authority Dynamic-consensus manifest is accepted only while attached as an
incoming snapshot and only with every later artifact absent. The same file is
rejected as a writable or read-only main database. Focused classifier evidence
also retains the marker, receipt table/index, and `leases.acquired_at` one at a
time and proves that each impossible hybrid is rejected.

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
result: PASS (41 passed)
```

The current 41-test recovery matrix (also covered by the complete
package PASS above) includes exact pre-acquisition lease schema inspection,
conversion, recovery planning, and digest equivalence; exact absent-ledger
#684 acceptance; and rejection of present weak/empty, populated, partial,
oversized, prematurely compacted, malformed, or durable-floor-inconsistent
receipts.

The final section will contain the exact post-integration store package, Clippy,
format, documentation, workspace CI, hosted-check, and three-voter transport
results once #695 publishes and is merged normally.
