# Protected Atomic Roster Evidence

This document records reproducible evidence for SDK issue #707. It covers the
generic SDK boundary only; it does not claim downstream product integration or
end-to-end application latency.

## Deployment activation

Before advertising the revision-five `opc-session-consumer/3` listener as
ready, a fixed-durable deployment calls
`ConsensusSessionStore::activate_protected_roster_profile()` once against the
current exact voter set. The operation obtains unanimous exact-profile proof
and durably installs a voter-set-bound certificate. It is a deployment/startup
transaction, never a per-roster member transaction. Protected admission fails
closed while the certificate is absent, stale, mixed-capability, or bound to a
different voter set. Restart and snapshot promotion reuse the persisted exact
certificate; they do not infer support from the listener or from a generic
capability marker.

The real three-voter fixtures perform this activation before exposing protected
traffic. Their full-process restart path deliberately does not reactivate it,
so every restart/crash test proves that the original certificate survived and
still matches the current exact voter scope. The fresh roster itself therefore
retains exactly two state-changing quorum transactions: PollAdmitted before any
provider effect and one all-or-none Established or Aborted terminal mutation.

## Candidate lineage

The signed semantic candidate immediately before this evidence-only refresh is
`6086d735f55e9f35f8b23cc3b05e1d6dd3716fd6`, tree
`903ba32cd566c1efd385ce1a029b837f2e189b41`. It is based directly on the
normal PR #717 merge at `ff3d41b08b73d987e52c9a87481f3ef7266f760c` and is
published as [draft PR #729](https://github.com/openpacketcore/openpacketcore-sdk/pull/729).
The PR remains a candidate, not a consumable pin: hosted checks and the final
frozen-head review must complete before it leaves draft, and there is no merge
SHA yet. The PR head ref, rather than the self-referential hash in this
committed document, is authoritative for the final documentation-only commit.

## Focused behavior evidence

The following locked tests run through the production revision-five roster
transport. Commands are shown without private paths or credentials.

```text
cargo test --locked -p opc-session-net --test stateless_quorum_consumer \
  persistent_three_voter_protected_roster_commits_maximum_plan_and_result_then_established_terminal \
  -- --exact --nocapture

result: PASS
topology: three real Openraft voters over mTLS ALPN opc-session-consumer/3
shape: six ordered members, maximum plan/checkpoint/result envelopes
assertion: exactly two accepted roster mutations (PollAdmit, Terminalize)
```

```text
cargo test --locked -p opc-session-net --test stateless_quorum_consumer \
  persistent_three_voter_protected_roster_durable_crash_cut_matrix \
  -- --exact --nocapture

result: PASS within the complete 39-test production transport target
topology: three real Openraft voters over mTLS with durable provider journals
cuts: exactly 13 enumerated admission/provider/terminal/publication/ACK cuts
assertion: no blind replay and exactly two accepted mutations on every
           terminal fresh-success path
```

The 13 frozen cuts are:

1. before admission;
2. PollAdmitted before provider work;
3. prepare pending;
4. prepared before run;
5. run OutcomeUnknown;
6. applied before finalize;
7. roster admitted before the sixth effect;
8. sixth durable apply with its reply lost;
9. all six converged before the terminal request;
10. terminal committed with its reply OutcomeUnknown;
11. Established before publication;
12. publication durable before acknowledgement; and
13. exact response bytes retained before a transport-conclusively
    non-transmitted first send, then resent byte-identically after restart.

```text
cargo test --locked -p opc-session-net --test stateless_quorum_consumer \
  persistent_three_voter_protected_roster_not_found_after_outcome_unknown_requires_adoption \
  -- --exact --nocapture

result: PASS
assertion: NotFound is non-exclusionary; no terminal or publication mutation;
           exact same-member adoption is required for a conclusive proof
```

```text
cargo test --locked -p opc-session-net --test stateless_quorum_consumer --all-features \
  persistent_three_voter_protected_roster_established_before_publication_survives_full_restart \
  -- --exact --nocapture

cargo test --locked -p opc-session-net --test stateless_quorum_consumer --all-features \
  persistent_three_voter_protected_roster_publication_published_before_acknowledgement_survives_full_restart \
  -- --exact --nocapture

cargo test --locked -p opc-session-net --test stateless_quorum_consumer --all-features \
  persistent_three_voter_protected_roster_exact_bytes_survive_snapshot_and_full_restart \
  -- --exact --nocapture

result: PASS (all three full-process restart cases)
assertions: higher-fence cross-node recovery; old/expired fence rejection;
            exact checkpoint/result after restart/leader change; Established
            before publication; published-before-ACK and Attempted ambiguity
            do not repeat the external publication effect
```

The three full-fleet restart cases are serialized with a test-only semaphore;
the production timeout is unchanged. This avoids unrelated simultaneous
election fleets competing on the qualification host.

## Retention and snapshot evidence

```text
cargo test --locked -p opc-session-store --all-features --lib \
  fenced_mutation_roster_storage::production_tests::exact_live_combined_and_durable_limits_are_enforced \
  -- --exact --nocapture

cargo test --locked -p opc-session-store --all-features --lib \
  fenced_mutation_roster_storage::production_tests::terminalization_reuses_its_admission_slot_at_capacity \
  -- --exact --nocapture

cargo test --locked -p opc-session-store --all-features --lib \
  fenced_mutation_roster_storage::production_tests::reclaim_is_oldest_bounded_and_never_reclaims_live_or_young_rows \
  -- --exact --nocapture

cargo test --locked -p opc-session-store --all-features --lib \
  fenced_mutation_roster_storage::production_tests::reclaim_compaction_requires_exact_24_hour_boundary_with_nanosecond_precision \
  -- --exact --nocapture

cargo test --locked -p opc-session-store --all-features --lib \
  sqlite::consensus::tests::protected_roster_retirement_uses_a_1024_row_global_prefix_then_final_partial_batch \
  -- --exact --nocapture

cargo test --locked -p opc-session-store --all-features --lib \
  sqlite::consensus::tests::due_protected_roster_maintenance_reclaims_the_oldest_bounded_prefix_only \
  -- --exact --nocapture

result: PASS
assertions: fault rollback is atomic; retention begins at terminalization;
            exact 24-hour eligibility; no live/young reclaim; deterministic
            oldest tie order; each operation removes the oldest
            min(1,024, eligible) rows, including the final partial batch
```

Additional focused store tests cover admission reservation, live-to-retained
conversion without a second capacity charge, snapshot/restart restoration,
local and remote key rotation, terminal record plus receipt atomicity, exact
replay/conflict, successor fencing, and fixed numeric diagnostics.

## Successor gate audit

The 2026-08-26 successor-lineage audit completed these exact local gates at
the signed semantic candidate above:

```text
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
result: PASS

cargo fmt --all -- --check
git diff --check
result: PASS

python3 ci/test-shards.py verify
result: PASS; six shards and seven guarded lanes cover 272 integration targets

python3 scripts/check-management-plane-policy.py --self-test
python3 scripts/check-management-plane-policy.py --check
result: PASS

python3 crates/opc-proto-diameter/fuzz/generate_corpus.py self-test
result: PASS

cargo test --locked -p opc-session-store --lib 'recovery::tests::' -- --nocapture
result: PASS; 44 passed, 0 failed

cargo test --locked -p opc-session-net --test stateless_quorum_consumer \
  -- --nocapture
result: PASS; 40 passed, 0 failed, 2 release-only latency tests ignored
```

The predecessor published checkpoint passed hosted strict Clippy, Rust gates,
MSRV, generated-code drift, the persistence contract,
security/advisory/license scans, and the privileged Linux datapath jobs. The
exact candidate above must rerun every hosted lane and obtain an independent
exact-head review; this document does not claim merge readiness.

## Required final gates

Before publication, rerun on the exact final head:

```text
cargo fmt --all --check
git diff --check
cargo check --locked --workspace --all-targets --all-features
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
python3 ci/test-shards.py verify
python3 scripts/check-management-plane-policy.py --self-test
python3 scripts/check-management-plane-policy.py --check
```

Run the repository CI-equivalent workspace test shards, the affected docs and
feature configurations, the focused real three-voter mTLS suites above, and an
independent frozen-head review. The candidate is ready only with no unresolved
P0/P1/P2 and hosted checks green for the exact non-draft PR head.
