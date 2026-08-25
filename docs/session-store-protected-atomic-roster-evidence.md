# Protected Atomic Roster Evidence

This document records reproducible evidence for SDK issue #707. It covers the
generic SDK boundary only; it does not claim downstream product integration or
end-to-end application latency.

## Candidate lineage

The latest signed pre-dependency preservation checkpoint is
`1f0d9ed2aec17b2e1a7c2d01b525f4c867cea57c`, tree
`b06f29b5e7074653feed7bac6952ef40faf6a466`, based on
`f2ed1181c85540cc01ea0b4611fa3620891375fd`. The complete invariant review was
frozen one additive test commit earlier at
`2441f30205f6369d7bf5de4603b610d4890704b1`, tree
`7f6f99e1f762f25dd0bddfec30b6b614efcfd6bc`, with no P0, P1, or P2 finding.
The final commit adds only the public-shutdown cancellation/retry regression
described below. These commits are development evidence, not consumable pins.
The final head/tree, normal dependency merge base, PR URL, hosted checks,
frozen review, and normal merge SHA must be recorded here only after the #704
successor lands and the minimal #707 delta is ported to that lineage.

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

result: PASS within the complete 32-test production transport target
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
6. effect applied before provider return;
7. applied before finalize;
8. roster admitted before the sixth effect;
9. sixth durable apply with its reply lost;
10. all six converged before the terminal request;
11. terminal committed with its reply OutcomeUnknown;
12. Established before publication; and
13. publication durable before acknowledgement.

```text
cargo test --locked -p opc-session-net --test stateless_quorum_consumer \
  persistent_three_voter_protected_roster_not_found_after_outcome_unknown_blocks_terminalization \
  -- --exact --nocapture

result: PASS
assertion: NotFound is non-exclusionary; no terminal or publication mutation
```

```text
cargo test --locked -p opc-session-net --test stateless_quorum_consumer \
  survives_full_restart -- --nocapture

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
  protected_roster_advance_ -- --nocapture

result: PASS within the complete 551-test store library target
assertions: fault rollback is atomic; retention begins at terminalization;
            exact 24-hour eligibility; no live/young reclaim; deterministic
            oldest tie order; one page is exactly bounded to 1,024 rows
```

Additional focused store tests cover admission reservation, live-to-retained
conversion without a second capacity charge, snapshot/restart restoration,
local and remote key rotation, terminal record plus receipt atomicity, exact
replay/conflict, successor fencing, and fixed numeric diagnostics. The final
lineage qualification must list each exact command and result here.

## Preserved-branch gate audit

The 2026-08-25 development-lineage audit completed these exact gates:

```text
cargo test --locked -p opc-session-net --all-features
result: PASS
detail: 322 library tests, all integration targets, 32/32 real transport tests,
        45/45 three-node quorum tests, and 7 doctests

cargo test --locked -p opc-session-store --all-features
result: PASS
detail: 551 library tests in 348.58 seconds, every integration target, and
        10 doctests

cargo check --locked --workspace --all-targets --all-features
result: PASS

cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
result: PASS

cargo test -p opc-session-store --lib \
  consensus::store::membership_tests::shutdown_retry_after_cancellation_waits_for_detached_snapshot_capture \
  -- --exact
result: PASS; cancelling public shutdown cannot authorize reopen while a real
        detached snapshot capture worker still owns SQLite, and a retry
        completes only after that tracked owner exits

RUSTDOCFLAGS="-D warnings" cargo doc --locked \
  -p opc-session-net -p opc-session-store --no-deps --all-features
result: PASS

mdbook build
result: PASS with the repository-pinned mdBook 0.4.40

cargo deny check bans licenses sources
result: PASS (repository-configured duplicate/version warnings only)

python3 ci/test-shards.py verify
python3 ci/test-shards.py verify-heavy
result: PASS; 269 integration targets are total and disjoint, and all 48
        heavyweight tests are assigned to a guarded lane
```

Default, no-default-feature, and all-feature checks for both affected crates
also pass. The management-policy self-test passes. Its full-tree check reports
only four pre-existing adjacent-`SAFETY` findings in the unchanged
`opc-sqlite-file-control-sys/src/lib.rs` (last changed by `946e4908`); the file
is byte-identical to the preserved branch base and outside #707. The final
successor must rerun the policy and formatter gates against its then-current
normal dependency base rather than claim this baseline exception as a pass.

The host's 2026-08-18 stable rustfmt reports broad mechanical drift in the
stale development lineage, including untouched files. No broad formatter
rewrite is included in the preservation checkpoint. The clean post-dependency
successor must pass `cargo fmt --all --check` before publication.

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
