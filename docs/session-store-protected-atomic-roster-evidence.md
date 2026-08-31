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
traffic. Their full-fleet durable-reopen path drops every process-local fleet
handle and deliberately does not reactivate the profile, so every reopen/crash
test proves that the original certificate survived and still matches the
current exact voter scope. The fresh roster itself therefore retains exactly
two state-changing quorum transactions: PollAdmitted before any provider effect
and one all-or-none Established or Aborted terminal mutation.

The absent-predecessor candidate uses an independent V2 sequence. Every voter
first activates the existing fenced-transition prerequisite, then calls
`ConsensusSessionStore::activate_protected_roster_profile_v2()` against the
exact voter set, and advertises only `opc-session-consumer/4` through
`SessionQuorumConsumerServer::with_roster_v2_ingress`. The real consumer is
constructed once with
`PersistentSessionConsumerClient::from_fenced_mutation_roster_v2_stateless`
and consumed once by
`into_fenced_mutation_roster_v2_provider_adapter`. Tests inspect the persistent
pool counters and provider identity across complete roster rounds; compilation
alone is not treated as activation or composition evidence.

V2 activation advances a clean/current durable replica from format 4 to format
5. A membership cutover clears its exact-scope V2 certificate, and the new
voter set must reactivate unanimously before `/4` traffic. A prospective
learner is independently checked for the exact revision-8 replication schema,
V2 applied-state digest, and format-5 descriptor before `add_learner` whenever
durable V2 history exists.

## Candidate lineage

The absent-predecessor prerequisite is based directly on the reviewed and
merged SDK PR #729 commit
`0e93409e0e83215b3d1a7d0e4ea166f88d758c27`, whose reviewed feature head was
`78d71cc3763dfcfec9f9c66ff5cc2f4ab5ef548d` and tree was
`5a9416d9c385cc28fa0bf63ee0ea282d22d358d4`. It does not copy or reinterpret
the merged #707/#729 present-predecessor implementation. The preserved signed
causal RED commit is `3002720ba7dd8464f64331bd77eb2879c76ccd17`;
the prerequisite PR head and merge SHA will be recorded in the downstream
ePDG dependency contract after exact-head review and merge.

The earlier V1 candidate lineage and evidence below remain the evidence for
merged PR #729. They are not attributed to the additive V2 bytes.

## Focused behavior evidence

The first locked test runs through the additive revision-six
absent-predecessor roster transport. The remaining established-roster tests
below retain the merged revision-five evidence. Commands are shown without
private paths or credentials.

```text
env CARGO_PROFILE_TEST_OPT_LEVEL=1 \
  cargo test --locked -p opc-session-net --all-features --lib \
  stateless_quorum_consumer::persistent_three_voter_protected_roster_creates_absent_record_then_established_terminal \
  -- --exact --nocapture

result: PASS
topology: three real Openraft voters over mTLS ALPN opc-session-consumer/4
shape: absent predecessor, generation-one create, six ordered members,
       maximum plan/checkpoint/result envelopes
assertion: exactly two accepted roster mutations (PollAdmit, Terminalize)
```

```text
cargo test --locked -p opc-session-net --all-features --lib \
  stateless_quorum_consumer::persistent_three_voter_protected_roster_durable_crash_cut_matrix \
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
cargo test --locked -p opc-session-net --all-features --lib \
  stateless_quorum_consumer::persistent_three_voter_protected_roster_not_found_after_outcome_unknown_requires_adoption \
  -- --exact --nocapture

result: PASS
assertion: NotFound is non-exclusionary; no terminal or publication mutation;
           exact same-member adoption is required for a conclusive proof
```

```text
cargo test --locked -p opc-session-net --all-features --lib \
  stateless_quorum_consumer::persistent_three_voter_protected_roster_established_before_publication_survives_full_restart \
  -- --exact --nocapture

cargo test --locked -p opc-session-net --all-features --lib \
  stateless_quorum_consumer::persistent_three_voter_protected_roster_publication_published_before_acknowledgement_survives_full_restart \
  -- --exact --nocapture

env CARGO_PROFILE_TEST_OPT_LEVEL=1 \
  cargo test --locked -p opc-session-net --all-features --lib \
  stateless_quorum_consumer::persistent_three_voter_protected_roster_exact_bytes_survive_snapshot_and_full_restart \
  -- --exact --nocapture

result: PASS (all three full-fleet durable-reopen cases)
assertions: higher-fence cross-node recovery; old/expired fence rejection;
            exact checkpoint/result after restart/leader change; Established
            before publication; published-before-ACK and Attempted ambiguity
            do not repeat the external publication effect; the snapshot case
            rotates the local protection key after admission, then recovers
            through a voter distinct from the admission voter without key
            lookup, reconstruction, reseal, or a new IV draw
```

The three full-fleet restart cases are serialized with a test-only semaphore;
the production timeout is unchanged. This avoids unrelated simultaneous
election fleets competing on the qualification host.

The focused conclusive-Aborted production-path case is:

```text
env CARGO_PROFILE_TEST_OPT_LEVEL=1 \
  cargo test --locked -p opc-session-net --all-features --lib \
  stateless_quorum_consumer::persistent_three_voter_protected_roster_aborted_exact_bytes_survive_snapshot_and_full_restart \
  -- --exact --nocapture

result: PASS
assertions: six SDK-issued NotApplied + Reconciled member proofs commit
            Aborted; a different voter recovers the exact protected
            checkpoint/result before physical snapshot compaction; a full
            three-voter durable reopen returns byte-identical Aborted bytes and
            has no publication authority or publication path; the remote seal
            key rotates after commit and seal/unseal call counts remain frozen
            through cross-voter recovery, snapshot creation, and full restart
```

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

## SQLite writer-handoff reliability evidence

The fixed-profile startup recovery lane first proves with read-only statements
that a durable physical-prune backlog exists. A pristine reopen therefore does
not take SQLite's singleton writer transaction merely to discover an empty
purge floor. When a primary preempts real prune work, interrupt delivery is
serialized with rollback and the secondary connection must be autocommit (or
be dropped) before the primary handoff opens.

```text
cargo test --locked -p opc-session-store --all-features --lib \
  consensus::storage::tests::pristine_fixed_store_prune_recovery_never_takes_sqlite_writer \
  -- --exact --nocapture --test-threads=1

cargo test --locked -p opc-session-store --all-features --lib \
  consensus::storage::tests::fixed_prune_yields_writer_to_later_adapter_append_and_resumes \
  -- --exact --nocapture --test-threads=1

cargo test --locked -p opc-session-store --all-features --lib \
  consensus::storage::tests::fixed_prune_preempts_for_state_machine_apply_without_applied_lag \
  -- --exact --nocapture --test-threads=1

cargo test --locked -p opc-session-store --all-features --lib \
  consensus_log_prune -- --nocapture --test-threads=1

result: PASS; exact cases pass and all 14 prune-lane tests pass
stress: 500/500 pristine fresh processes; 500/500 backlog handoffs;
        200/200 apply + prune + pinned-reader checkpoint processes
assertions: no needless startup writer; no late interrupt during rollback;
            primary apply/append succeeds inside the existing one-second
            bound; physical backlog resumes; pinned PASSIVE checkpoint drains
```

The same bytes pass the affected real topology cases:

```text
cargo test --locked -p opc-session-net --all-features --lib \
  stateless_quorum_consumer::persistent_three_voter_protected_roster_survives_real_os_process_loss \
  -- --exact --nocapture --test-threads=1
result: PASS; 193.86s

CARGO_PROFILE_TEST_OPT_LEVEL=1 \
  cargo test --locked -p opc-session-net --all-features --lib \
  stateless_quorum_consumer::persistent_three_voter_snapshot_maintenance_with_concurrent_read_barriers_keeps_engines_running \
  -- --exact --nocapture --test-threads=1
result: PASS; 36.44s
```

## Successor gate audit

The 2026-08-26 successor-lineage audit first completed the full local behavior
suites at signed semantic checkpoint
`d109854e7e5b46e946bf8bf125de87981c8538a8`, tree
`1a9e2157adf79fdfb38ad048759ee84246cab82f`. Later additive commits close the
bounded SQLite writer handoff and extend the cross-voter key-rotation evidence;
their focused gates and the exact-head hosted lanes are recorded separately so
this document does not attribute an earlier full-suite run to newer bytes.

```text
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

cargo test --locked -p opc-session-net --all-features --lib stateless_quorum_consumer:: \
  -- --nocapture
result: PASS; 43 passed, 0 failed, 2 release-only latency tests ignored
```

At the signed semantic candidate above, focused local strict Clippy for
`opc-session-store` and `opc-session-net`, the production roster transport, and
the Established and Aborted cross-voter key-rotation/restart cases pass. Hosted
run `33031393057` at predecessor semantic SHA `17e9f05d5fa44e463521d2f49eefe6aefae58c55`
passes workspace strict Clippy, Rust gates, MSRV, generated-code drift, the
persistence contract, both integration shards, both heavy shards, docs,
feature powerset, platform checks, and security/advisory/license scans. The
remaining hosted workflows and independent frozen-head review are still
required; this document does not claim merge readiness.

## Required final gates

Before publication, rerun on the exact final head:

```text
cargo fmt --all -- --check
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
