# SDK-982 protected V2 consumer facade evidence

This record lists the evidence for the protected V2 prepared consumer facade
defined in
[Protected V2 prepared consumer facade (#982)](session-store-atomic-fenced-transition.md#protected-v2-prepared-consumer-facade-982)
and RFC 004 §12.5 and §14.1. The facade composes the existing `/2`
operations. V1, the #701 protected V1 composition, the raw V2
protection-wrapper path, and the `/2` wire are unchanged, so no existing
test, validator, or budget was changed to produce this evidence.

## Contract under qualification

- A caller prepares with the V1 `FencedTransitionRequest` shape. Its 16-byte
  ID is the caller-stable recovery identity. The facade names the active
  epoch and a fresh nonce; the caller never chooses either.
- Before a handle can dispatch, the complete sealed V2 request is bound to
  the caller ID in the SDK-owned `FencedTransitionV2RecoveryJournal`. Every
  dispatch reloads, authenticates, and compares that row, and sends only it.
- Only the original affine handle dispatches. A possible send makes it
  receipt-only. Restart recovery is a local journal lookup that returns a
  receipt-only handle and needs no plaintext or key provider.
- The journal's authenticated 4,096-row count is an admission fence, not an
  absorbing lifetime. Rows are removed only by exact compare-and-delete once
  a transition is resolved or provably unbound, so the number of transitions
  over the facade's lifetime is not bounded by the journal.
- Retained V1 journal entries stay status-recoverable through the upgraded
  facade, and one caller ID can never name both a V1 and a V2 transition.
- The linearized V2 history read stays off the per-transition path. A cached
  active epoch is safe because epochs only advance; an epoch or capacity
  rejection invalidates it.

## Focused deterministic evidence

These tests use scripted physical boundaries, so each property is checked
deterministically, including the cases that are impractical to force on real
voters.

### Recovery journal (`opc-session-store`)

All names below are under `fenced_transition_journal::recovery::tests`.

| Required property | Test |
| --- | --- |
| Exact rows survive reopen, and removal is exact compare-and-delete | `recovery_journal_round_trips_exact_rows_across_reopen_and_removal` |
| The journal binds one wrapper scope, and another scope fails closed | `recovery_journal_binds_one_scope_and_fails_closed_for_another` |
| `create_new` and `open_existing` provisioning, and foreign files, fail closed | `recovery_journal_provisioning_and_foreign_state_fail_closed` |
| Offline row deletion, addition, and substitution are detected | `recovery_journal_detects_offline_row_deletion_addition_and_substitution` |
| The 4,096-row admission fence is exact, and removal readmits | `recovery_journal_admission_fence_is_exact_and_not_absorbing` |
| Retired-floor removal and reclamation pages are bounded and ordered | `recovery_journal_retired_floor_and_pages_are_bounded_and_ordered` |

### Protection-wrapper composition (`opc-session-store`)

All names below are under `protected_fenced_transition_v2_recovery_tests`.

| Required property | Test |
| --- | --- |
| Preparation names the active epoch, seals once, journals before dispatch, and dispatches the exact row | `protected_v2_recovery_prepares_in_the_active_epoch_and_dispatches_exact_rows` |
| Restart recovers the exact sealed request without a key provider | `protected_v2_recovery_restart_recovers_exact_sealed_body_without_a_provider` |
| Misconfigured, full-epoch, non-V2, and non-plaintext preparations fail before provider, journal, or dispatch effects, and a removed row is never dispatched | `protected_v2_recovery_fails_closed_before_provider_journal_or_dispatch_effects` |
| A substituted journal row is rejected before dispatch | `protected_v2_recovery_rejects_a_substituted_row_before_dispatch` |
| V1 and V2 compositions reject each other's retained caller IDs | `protected_v2_recovery_and_legacy_v1_reject_each_others_retained_ids` |
| Remote sealing prepares with one seal and unprotects only observations | `protected_v2_recovery_remote_seal_prepares_once_and_observes_unprotected_records` |
| Operation continues past the eight retained epochs with at most two live rows, and no V2 identity executes twice | `protected_v2_recovery_sustains_operation_beyond_retained_epochs_with_bounded_rows` |

### Affine handle and epoch cache (`opc-session-net`)

All names below are under `consumer::prepared_fenced_v2::tests`.

| Required property | Test |
| --- | --- |
| Rotation only after a proven pre-write failure, one attempt per voter, and an unsent row is discarded | `v2_handle_rotates_only_after_proven_pre_write_failure_and_discards_an_unsent_row` |
| A commit after rotation is resolved and releasable | `v2_handle_commit_after_rotation_is_resolved_and_releasable` |
| A possible send is receipt-only; release needs a terminal status | `v2_handle_possible_send_is_receipt_only_until_a_terminal_status` |
| A definitive unbound rejection discards the row | `v2_handle_definitive_unbound_rejection_discards_its_row` |
| Cancellation before dispatch admission keeps dispatch authority | `v2_handle_cancellation_before_dispatch_admission_returns_to_ready` |
| Cancellation after dispatch admission is receipt-only | `v2_handle_cancellation_after_dispatch_admission_is_receipt_only` |
| A missing row prevents any dispatch | `v2_handle_rejects_a_missing_row_before_any_dispatch` |
| The epoch cache serves only a bindable, newest state | `v2_history_cache_serves_only_a_bindable_newest_state` |
| `EpochNotActive`, `Retired`, and `HistoryFull` rejections invalidate the cached epoch | `v2_handle_closed_or_full_epoch_rejection_invalidates_the_cached_epoch` |
| Other rejections keep the cached epoch | `v2_handle_other_rejections_keep_the_cached_epoch` |

## Real three-voter evidence

These tests run in `opc-session-testkit` against three real OpenRaft voters.
Every mutation, status, and history read crosses the production mTLS `/2`
lane into the store-owned quorum service. The fixture decorator only counts
requests and, when armed, withholds one committed response. All names below
are under `authenticated_consumer_fixture::v2_facade_tests`.

| Required property | Test |
| --- | --- |
| Commit, release, and re-preparation of one caller ID | `fixture_v2_facade_commits_releases_and_readmits_one_caller_id` |
| A real lost response is recovered by caller ID with no second mutation | `fixture_v2_facade_recovers_a_real_lost_response_by_caller_id_without_replay` |
| A crash after preparation and before send restarts status-only, and the sweep retains the `NotFound` row | `fixture_v2_facade_crash_after_prepare_before_send_restarts_status_only` |
| An upgrade keeps retained V1 transitions status-recoverable | `fixture_v2_facade_upgrade_keeps_retained_v1_transitions_recoverable` |
| Remote sealing commits through real voters | `fixture_v2_facade_remote_sealing_commits_through_real_voters` |
| The sweep retains `Recorded` and unresolved rows and rejects a zero limit | `fixture_v2_facade_reclaim_sweep_retains_recorded_and_unresolved_rows` |
| Activation performs one history read, transitions perform none, and a sweep refreshes it with one | `fixture_v2_facade_keeps_the_linearized_history_read_off_the_preparation_path` |

## Release qualification

`fixture_v2_facade_sustains_more_transitions_than_one_v1_journal_holds` is
ignored in ordinary runs. It commits 4,160 protected V2 transitions (64 more
than the 4,096 rows a V1 journal or the recovery journal can hold) through
the fixed-durable three-voter fixture. It requires exactly one physical V2
call per transition and no V1 call, a peak of one retained journal row, an
empty journal at the end, and one history read for the whole run.

```sh
cargo test --locked -p opc-session-testkit --all-features --lib -- \
  --ignored --exact --nocapture \
  authenticated_consumer_fixture::v2_facade_tests::fixture_v2_facade_sustains_more_transitions_than_one_v1_journal_holds
```

A durable commit that outlives one physical attempt is a possible send. The
qualification resolves such a transition by recovering it by caller ID and
reading its exact receipt, never by a second mutation, and reports the count.
On the recorded head, a debug build on a shared 128-core Linux host committed
all 4,160 transitions with a peak of one retained row, no transition resolved
by receipt, and one history read, in 109.4 s. That duration describes this
run only; it is not a performance claim.

## Local gates

Recorded on code head `be0dfab71d7a39c3e21b85f1800f3b0f1aa50261`. This
record was added afterwards without code changes. The commands mirror the
hosted `CI` workflow. They ran on a Linux x86_64 host with a private
fs-verity snapshot filesystem and a disk-backed `TMPDIR`, which the workflow
also provisions.

| Gate | Result |
| --- | --- |
| `cargo fmt --all --check`, and `git diff --check` from the merge base | pass |
| `cargo clippy --locked --workspace --all-targets --all-features -- -D warnings` | pass |
| `python3 ci/test-shards.py verify`, `precheck` for every shard, and `verify-heavy`, plus the shard-manifest and performance-plan self-tests | pass |
| Every command of every test shard (`misc`, `quiescent-o1`, `it-0`, `it-1`, `it-2`, `heavy-0`, `heavy-1`) from `python3 ci/test-shards.py plan`, in order | pass (23 commands) |
| `opc-persist` default-feature Clippy and contract tests, and its serial all-features suite | pass |
| `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features` | pass |
| MSRV `cargo +1.89.0 check --workspace --all-targets --all-features`, and `python3 scripts/publish-order.py --check` | pass |
| Reference SMF consumer: formatting, Clippy, and tests | pass |
| Both Go modules: `gofmt`, `go vet`, `go test -race`, and the downstream import check | pass |
| Repository Python gates: management-plane policy, N3IWF fixture contracts, reference vectors, IKE AUTH known answers, the release-attestation wrapper, live-memory validators, and the Diameter corpus self-test | pass |
| `cargo check --target i686-unknown-linux-gnu -p opc-session-net --all-targets --all-features` | pass |
| Default-feature checks of the three changed crates, and `opc-sdk` with `--no-default-features --features session` and with default features | pass |

The Go module tests need a `TMPDIR` outside the repository tree. Otherwise a
bridge test finds, through a relative path, a CLI binary that the Rust shards
built.

These gates were not run locally:

- i686 test execution. The host lacks the 32-bit `libatomic` runtime, so i686
  test binaries cannot link. The i686 type check above passed.
- The macOS and FreeBSD lanes, because no such host was available. The
  recovery journal's `cfg(unix)` paths mirror the #701 journal's.
- The privileged SCTP lane, which needs a root network namespace and kernel
  SCTP.
- Independent NGAP ASN.1 validation, which needs a network package install.
- `actionlint` (no workflow changed), generated-code drift (no generator
  input changed), and the vendored DTLS lane (unchanged).
- The `cargo-hack` feature powerset, because the tool is not installed.
  `opc-sdk` depends only on `opc-session-store`, whose features and `cfg`
  gates are unchanged.
- The Kubernetes manifest and Helm jobs (no manifest or chart changed) and the
  security scans (no dependency changed).

## Not claimed

- Real-voter epoch rotation through the facade. Opening a successor epoch
  needs 131,072 bindings in the active epoch. The facade's rotation behavior
  is covered with scripted history boundaries above, and real rotation and
  retirement are qualified for the store itself by the SDK-702 record. An
  attempt to bind one epoch in bulk through the testkit's fixed-durable
  fixture, using the store's public V2 batch API, stopped at about 10,000
  bindings: the fixture's leader stopped admitting application traffic,
  whatever the batch size or pacing. That fixture behavior is outside this
  change and is not investigated here.
- Host failover, volume loss, or a replicated recovery journal. Restart
  recovery needs the same durable volume, path, journal key, protection mode
  and namespace, local identity, and stable cluster.
- Latency percentiles or throughput. The history cache removes one consensus
  logical-time fence per transition. No latency figure is claimed.
- Downgrade. A binary that predates this facade cannot read the recovery
  journal; release or reclaim every row before rolling back.
