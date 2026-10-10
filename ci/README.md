# CI and real-time qualification

The required **Rust workspace** check aggregates the gates, clippy, and test
shards in [ci.yml](../.github/workflows/ci.yml). Use
`python3 ci/test-shards.py ids`, `plan --shard ID`, and `precheck --shard ID`
to reproduce the shards with the profile and disk setup in
[CONTRIBUTING](../CONTRIBUTING.md#validation-gates).

## Exact, temporary qualification manifest

[realtime-qualification.json](realtime-qualification.json) is the complete list
excluded from required CI for real-time multi-process qualification. Every entry
has an exact libtest name, an issue, and a reason. The initial list contains the
13 active real-I/O tests in `qualification_mtls_multiprocess::isolated_scale`,
the family covered by [#923](https://github.com/openpacketcore/openpacketcore-sdk/issues/923)
and [#1207](https://github.com/openpacketcore/openpacketcore-sdk/issues/1207).
The pure schedule/percentile test remains required. The three existing ignored
full-load tests keep their existing explicit opt-in behavior.

Required shards use exact exclusions. Their live inventory audit fails on
removed, renamed, duplicated, or newly ignored manifest entries, or any overlap
or gap between required shards and qualification. A new sibling or a name with
the same prefix remains required. The qualification runner independently checks
that every name resolves once and every repetition executes the full list with
zero ignored tests. No Rust assertion, timeout, or ignore attribute is changed
by this split.

The separate [Real-time qualification workflow](../.github/workflows/realtime-qualification.yml)
runs once on every PR and ten times nightly on main at 03:23 UTC. Its
**Real-time multi-process qualification (non-required)** job is visible and
fails normally. Keep that job outside required branch checks; it is outside the
Rust workspace aggregator and does not use `continue-on-error`. Repository
rules must keep **Rust workspace** required. Scheduled runs are never cancelled
by newer runs. GitHub may delay scheduled workflows; inspect their actual run
times rather than assuming that the scheduled time proves a run occurred.

To reproduce a measurement after configuring private disk `TMPDIR` and the
fs-verity snapshot storage used by the CI lane:

```bash
export CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
python3 ci/realtime_qualification.py --repetitions 1 --output qualification-results
```

Use a new evidence output directory for each run and reuse the worktree's stable
build cache. The runner preserves workspace feature unification, Cargo's test
environment, four test threads, logs, commands, source revision, and per-run
results. Nightly repetitions measure frequency; a later pass never erases an
earlier failure. Setup errors, partial runs, and missing artifacts are failures.

## Decisions before merging

A red PR qualification job is a review signal that requires classification.
Before merging, the merge operator compares the PR candidate and unchanged main
under matching toolchain, features, profile, storage, contention, and command.
Retain both sets of evidence and identify the known issue for any shared failure.
A failure seen only on the change blocks merging until it is fixed. A green
required check alone does not waive this comparison.

On a failed scheduled main run, a separate job uses its own `GITHUB_TOKEN` with
`issues: write` to open an issue labelled `nightly-qualification`, or comment on
the open issue. It includes the run link, source revision, failing names and
counts when available, and an explicit notice if execution or reporting was
incomplete. PR jobs have no issue-write permission. Successful repetitions and
later green nightlies never close an issue automatically.

**A red nightly stops new merges.** Keep the issue open until every reported
failure is classified, linking either a known flake issue or a verified
regression fix/revert. Include setup, cancellation, and reporting failures in
the classification. Close the issue only after recording that decision for
every failed run it covers. The required Rust gates job fails while any issue
with this label is open, and fails closed on an API error.

An already-green PR check does not change when a later nightly fails. Immediately
before each merge, the merge operator must run this read-only check with an
authenticated GitHub CLI and inspect completed scheduled workflow results:

```bash
python3 ci/nightly_qualification.py check --repository openpacketcore/openpacketcore-sdk
gh run list --repo openpacketcore/openpacketcore-sdk \
  --workflow realtime-qualification.yml --event schedule --branch main
```

Verify that every red nightly since the last classification is accounted for.
If the reporting job could not create/comment on an issue, the red workflow
still holds merges: record and classify it before proceeding. Issue checks
cannot invalidate earlier check results or enforce this operator step at merge
time. These workflow changes do not edit repository branch-protection settings.

## Shrinking the list

Convert tests by pattern: elapsed-time correctness bounds become ordering and
outcome assertions or injected time; sleep-then-check becomes a wait on actual
readiness with only a generous hang guard. Preserve every property assertion.
Each conversion removes its exact manifest entry and returns it to required CI,
with 100 passing runs under CPU and disk contention and a revert proving the
original failure where reproducible. The list may become empty.

Do not add prefixes, wildcards, blanket ignores, retries, or larger correctness
timeouts. Any addition outside the initial family needs its issue, exact name,
reason, and failure evidence from unchanged main under contention. The follow-up
workspace inventory and guard against new wall-clock assertions are separate
work; this split does not implement that guard.
