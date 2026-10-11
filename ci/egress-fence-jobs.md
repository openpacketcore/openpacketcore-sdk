# Egress-fence required jobs

The workflow keeps `Root-cgroup egress fence` as the required check. Its
`root-cgroup-egress` job waits for `changes`, `sources`, `oracles`, `installer`,
`host-proofs` and the complete `host-tests` matrix. Every workload must succeed. A failed,
cancelled, missing or unexpectedly skipped workload fails the aggregate.
The only accepted skip is the original successful `changes` decision with
`run == 'false'`, in which case every workload must be skipped.

All five workload definitions retain the original fail-closed changes
condition. The test matrix has `fail-fast: false`, so one failing shard does
not cancel the others. No branch-protection context needs renaming: each new
workload blocks the same existing required check. The workload time limit is
45 minutes; the decision and aggregate jobs have 10-minute limits.

## Original step ownership

This mapping is from the workflow at `eb366eae1`. Qualification commands have
one owner. Runner preparation and cleanup are deliberately repeated wherever
the split requires them; each privileged runner verifies its own cleanup.

| Original step or command | New job |
| --- | --- |
| Checkout; stable Rust; host build cache | Each workload's own runner |
| Install pinned eBPF Rust | `sources` |
| Install pinned kernel build tools: apt packages, bpftool install/version | Each workload's own runner, through `egress-fence-tools.sh` |
| Install pinned kernel build tools: bpf-linker 0.10.3 | `sources` |
| Prepare fs-verity snapshot storage | Each `host-tests` shard and `host-proofs`, on their own runners |
| Gate host sources: workspace fmt, whitespace, six-package all-target/all-feature Clippy | `sources` |
| Gate host sources: six-package all-feature ordinary lib/bin/integration tests | `host-tests`, exact-name partition described below |
| Gate host sources: examples compiled by the original unfiltered Cargo test | `host-tests (1)` |
| Gate host sources: all six packages' doctests | `host-tests (1)` |
| Gate host sources: three isolated `consensus_openraft` proofs | `host-proofs` |
| Gate host sources: three isolated library proofs | `host-proofs` |
| Gate host sources: complete `qualification_profile` suite | `host-tests (1)` |
| Gate host sources: warnings-denied six-package all-feature rustdoc | `sources` |
| Gate host sources: eight isolated O1 SQLite proofs | `host-proofs` |
| Gate every eBPF feature surface: pinned fmt and all four Clippy commands | `sources` |
| Rebuild production and test-only objects: all four independent double builds and production byte comparison | `sources` |
| Build and gate independent host oracles: all bin tests, build, Clippy and redaction check | `oracles` |
| Require the revision-aware host kernel | `oracles` and `installer`, through the unchanged `egress-fence-kernel.sh` body |
| Run actual-object, cleanup-fault, and mutation oracles | `oracles` |
| Run the production installer and adoption proof | `installer` |
| Require complete privileged cleanup | Every workload, with `always()`, through the unchanged `egress-fence-cleanup.sh` body |
| Cache save and checkout post-actions | Each corresponding runner |

The object build, host oracle, privileged oracle and installer commands retain
their arguments and assertions; compatible compilation caches move under the
workspace's `target/` directory. Only `sources` builds eBPF objects; `oracles`
downloads the five outputs from the same workflow run. Cache mappings name the
actual build directories, relative to each workspace. Each ordinary test shard
has its own `egress-fence-tests-N` cache key; `host-proofs` uses the separate
`egress-fence-proofs` key and target directory. Source and installer compilation
retains the `egress-fence-host` key. Each hosted runner has its own writable
copy. The eBPF Clippy and oracle profiles have separate cache keys. Independent
object reproducibility builds retain their separate clean target directories.
Both artifact uploads set `overwrite: true` so reruns replace their artifacts.

## Exact test-name ownership

`egress-fence-tests.py` compiles and lists every lib/bin/integration harness
for the original six packages with `--all-features`. It compares compiled
targets with Cargo metadata and rejects missing or unexpected targets. Each
test identity is `(package, target, target kind, exact libtest name)`. Ordinary
tests use the first eight bytes of SHA-256 of the name, interpreted big-endian,
modulo three. Equal names in different harnesses have the same owner because
Cargo forwards exclusions to every harness.

All 14 isolated proofs instead have owner 3 and execute in the separate
`host-proofs` job. That job lists the same six-package inventory to verify
their identities, then runs only the six ordinary-profile and eight O1 proof
commands, unchanged. Its compilation and execution time is independent of
the three ordinary test shards.

Each shard runs the original Cargo package/feature selection with four test
threads, adding `--tests` and exact-name exclusions for the other shards.
Cargo retains its working-directory and environment setup. Newly added tests
are assigned automatically; prefix siblings cannot be excluded accidentally.
Existing `#[ignore]` status is preserved. This does not import the separate
general-CI real-time exclusion list.

Each ordinary shard uploads `egress-fence-test-map-N`, containing
`egress-fence-test-map.json`: revision, every harness test name, ignored status,
owner (0–2 for ordinary shards or 3 for `host-proofs`) and all four plans.
Generate the same map locally without executing tests with:

```sh
python3 ci/egress-fence-tests.py --inventory-only --output /tmp/egress-test-map.json
```

The following exact names retain their original fresh processes, package
selection and single test thread. The helper requires each to exist exactly
once in its expected harness and to remain enabled.

| Exact test name | Job/profile |
| --- | --- |
| `lagging_replica_installs_compacted_snapshot_without_losing_committed_state` | `host-proofs`, `consensus_openraft` |
| `fenced_transition_snapshot_install_preserves_exact_replay_without_second_effect` | `host-proofs`, `consensus_openraft` |
| `compacted_successor_snapshot_catches_up_predecessor_voter_and_survives_full_restart` | `host-proofs`, `consensus_openraft` |
| `consensus::storage::tests::promoted_mismatch_never_unlinks_a_same_name_replacement` | `host-proofs`, lib |
| `consensus::raft_adapter::tests::raw_fixed_handler_uses_one_durable_authority_check_for_each_engine_family` | `host-proofs`, lib |
| `consensus::store::membership_tests::protected_roster_ingress_has_two_mutations_and_read_only_status_paths` | `host-proofs`, lib |
| `sqlite::consensus::tests::protected_roster_retirement_uses_a_1024_row_global_prefix_then_final_partial_batch` | `host-proofs`, O1 lib |
| `sqlite::consensus::tests::due_protected_roster_maintenance_reclaims_the_oldest_bounded_prefix_only` | `host-proofs`, O1 lib |
| `sqlite::consensus::tests::fenced_transition_v2_capacity_opens_successor_and_bounds_eight_exact_epochs` | `host-proofs`, O1 lib |
| `sqlite::consensus::tests::fenced_transition_v2_floor_reclaims_oldest_while_successor_remains_writable` | `host-proofs`, O1 lib |
| `sqlite::consensus::tests::fenced_transition_v2_post_reclaim_deletion_keeps_retired_and_conflict_closed` | `host-proofs`, O1 lib |
| `sqlite::consensus::tests::fenced_transition_v2_reclaims_exactly_1024_then_opens_next_epoch` | `host-proofs`, O1 lib |
| `sqlite::consensus::tests::fenced_transition_v2_revoked_authority_masks_nonactive_epoch_in_apply_and_projection` | `host-proofs`, O1 lib |
| `sqlite::consensus::tests::fenced_transition_v2_snapshot_during_reclaim_preserves_cursor_and_rejects_regression` | `host-proofs`, O1 lib |

The complete doctest and `qualification_profile` inventories belong to shard
1 without filtering. The oracle binary's `tests::top_level_failure_erases_error_and_path_content`
unit test, its independent redaction script, pressure and delete-fault modes,
and every privileged-detector scenario belong to `oracles`. The detector
still checks cleanup failures after attach, veth and child creation, production
traffic, and both deadline/gate mutations with their exact exit/output checks.
`linux_backend::privileged_tests::production_backend_fresh_expiry_adoption_and_prepared_recovery`
belongs to `installer`, retaining the original default-feature build, exact
ignored-test inventory assertion and privileged invocation. Its ignored entry
in the all-feature host inventory stays ignored, as before.

## Hosted timing estimate

The requested baseline is run
[38076376452, attempt 1](https://github.com/openpacketcore/openpacketcore-sdk/actions/runs/38076376452/attempts/1).
It failed in `Gate host sources` after 45m38s; the later steps were skipped,
so their zero-second entries are not measurements. Setup took about 69s,
Clippy 108s, compilation to the first tests about 253s, and the large store
library process 39m06s before its timing failure.

The same run's
[second attempt](https://github.com/openpacketcore/openpacketcore-sdk/actions/runs/38076376452/attempts/2)
completed that step in 84m02s: the library took 44m26s, ordinary integrations
about six minutes, isolated consensus proofs 6m21s plus about five minutes
of compilation, and the O1 build about 10m47s plus 36s of tests. It also
measured eBPF feature gates at 37s, object rebuilds at 141s, host oracles at
50s and privileged oracles at 34s. The installer was cancelled after 41s,
so its estimate also uses the 95s completed step in
[run 38043827932](https://github.com/openpacketcore/openpacketcore-sdk/actions/runs/38043827932).

Allowing 37–41 minutes for the former shard 2's cold run, removing the
approximately 11-minute O1 build/proofs gives the ordinary-shard estimate
below. The new proof job includes its own cold six-package inventory build,
the separate proof-profile compilation, all 14 executions and cache overhead.

| New job | Estimated hosted wall time | Basis and allowance |
| --- | --- | --- |
| `sources` | 8–12 minutes | Setup, 2m Clippy, 1m rustdoc, 3m eBPF gates/builds, cache/artifact allowance |
| `oracles` | 4–8 minutes | Own setup, host compilation/tests, 34s privileged proofs, artifact/cache allowance |
| `installer` | 4–8 minutes | Own setup and a cold small-package build; completed old step was 95s |
| `host-tests (0)` | 20–28 minutes | Roughly one third of ordinary tests, 5m initial build, setup/cache allowance; six isolated proofs moved out |
| `host-tests (1)` | 23–30 minutes | Roughly one third of ordinary tests, 5m initial build, examples/doctests/profile compilation, setup/cache allowance |
| `host-tests (2)` | 26–32 minutes | Former 37–41m cold estimate less 11m O1 build/proofs, with cache allowance |
| `host-proofs` | 27–35 minutes | 5m inventory build, 5m isolated-profile compilation, 6m21s isolated proofs, 11m O1 build/proofs, setup/cache allowance |
| `root-cgroup-egress` | Under 1 minute | Checkout and aggregate result check |

These estimates include repeated compilation on separate runners and assume
roughly balanced test durations, not just balanced counts. They are not timing
qualification: the hosted train must confirm all three ordinary shards and
the proof job finish comfortably below 45 minutes. Test deadlines,
optimization flags, assertions and ignored-test statuses are unchanged.
