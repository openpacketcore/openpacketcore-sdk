# CI and real-time qualification

The required **Rust workspace** check aggregates the inventory guard, gates, clippy, and test
shards in [ci.yml](../.github/workflows/ci.yml). Use
`python3 ci/test-shards.py ids`, `plan --shard ID`, and `precheck --shard ID`
to reproduce the shards with the profile and disk setup in
[CONTRIBUTING](../CONTRIBUTING.md#validation-gates).

## Secret scan scope

The [security workflow](../.github/workflows/security.yml) scans a pull request's
exact `base.sha..head.sha` range with the head's `.gitleaksignore`.
Pushes to `main` scan the pushed commit's full reachable history. A commit that
reaches `main` through a pull request against `main` is scanned in that pull
request and again on the push to `main`. The push to `main` is the only scan for
the merge commit GitHub creates, for a direct push, and for commits that were
already on a pull request's base branch when that base was not `main`; changing
a pull request's base does not scan it again. gitleaks reads `git log -p`, which
prints no diff for a merge commit, so text that exists only in a merge commit's
conflict resolution is not scanned by any run.

Scheduled runs (daily at 08:17 UTC) fetch and scan all branch and tag refs with
the `.gitleaksignore` on `main`, including branches without pull requests.
They do not fetch pull request heads; those are scanned by their own runs.
Findings or scan failures open or update a `secret-scan` issue with the run link
and a finding count when available; missing results are never reported as clean.
That issue does not impose a merge hold on unrelated pull requests. Manual runs
scan all refs like the scheduled run, with the dispatched commit's
`.gitleaksignore`, and do not open an issue. Required workflow regressions in
`ci/test-test-inventory.py` pin these scopes and scheduled issue reporting.

A pull request is scanned with its own `.gitleaksignore`, so it can silence a
finding that it adds. Review every change to `.gitleaksignore`, and any new
`.gitleaks.toml`, as a security change: each added line pins one false positive
by commit, file, rule and line and says why the value is not a secret. Do not
add path or rule allowlists. The scan emits a warning when either file changes;
the warning does not fail the scan.

## Test inventory guard

**Test inventory guard** is a dependency of **Rust workspace**, whose aggregate
rejects failed, skipped, and cancelled dependencies. The reusable
[`test-inventory.yml`](../.github/workflows/test-inventory.yml) job also runs on
`train/**` pushes and merge-group events. On a PR it compares the event's head
with the merge base of the event's base/head revisions. On a train push it
compares with the default branch's merge base; on a main push it compares the
event's before/after revisions. A missing revision or parser error fails the job.
Manual `workflow_dispatch` runs use the same comparison as train pushes; a dispatch on the default branch itself passes as an empty comparison.

The guard reads immutable Git blobs. It does not check out either compared tree,
run its generators, compile the workspace, or execute its tests. Rust and Go use
pinned Tree-sitter grammars, Python uses its standard AST parser, and workflow
YAML uses a loader that rejects duplicate keys. Comments and quoted examples do
not count as assertions or test declarations.

The checks are:

| Change kind | What requires a declaration |
| --- | --- |
| `removed` | A Rust test attribute, Python `test_*`, or Go `Test*` function disappears from its full inventory path. Rust module declarations and Cargo target configuration determine reachability. |
| `disabled` | A test gains an ignore, conditional compilation/feature gate, environment-dependent early return, or CI skip/qualification entry. A newly added ignored test is also reported. |
| `assertions-decreased` | A test's assertion count falls, including assertions in resolved local test helpers; or an assertion-bearing scenario helper disappears without a matching relocation or retained assertion expressions. |
| `required-ci-removed` | A job leaves the aggregate's dependency graph, a matrix lane disappears, a required execution platform/container changes, a test command or its literal shell-loop selection changes, or a job/step/trigger gains a condition that can omit its tests. |

Rust counts `assert!`, `assert_eq!`, `assert_ne!`, `assert_matches!` and their
`debug_assert*` forms, including invocations inside other macros. Result
`unwrap`/`expect` and their error-result forms count too; a diagnostic
`unwrap_or_else` that panics retains that check. Fixture mutex poison handling
does not count as a result-under-test assertion. An inline fallible callback
whose enclosing call checks success can express checks with `?` and conditional
`return Err(...)`; those checks retain their count. Discarded callback results
do not. As with other closure assertions, review must verify that a custom
wrapper actually invokes the callback and propagates its errors.
Python counts `assert`,
assertion methods, exception/warning assertions, and explicit failure calls.
Go counts testing failure calls and `assert`/`require` calls. Local checked
helpers are followed within a test target/package when their names resolve
unambiguously. Rust distinguishes free functions, qualified calls, and methods;
explicit receiver types, declared factory return types, simple constructors and
`self` identify fixture methods.
Unknown receiver types are limited to the same lexical module. Standard atomic
operations and result assertions do not resolve to unrelated fixture methods.
Moving assertions into a resolved helper preserves their count. A removed
helper can relocate under the same method name with at least as many checks,
or preserve its named expectations/assertion expressions in reachable helpers.
Other removed checked helpers remain visible even if unrelated checks are added.

In Rust, Python, and Go, assertions in a constant-false branch or an unreachable
side of a constant conditional do not count. Trivially successful checks such
as `assert!(true)`, `assert_eq!(value, value)`, Python `assert True`, or Go
`require.Equal(t, value, value)` do not count either. This recognizes literal
conditions and obvious self comparisons; it does not solve arbitrary predicates.
Repeated function calls are not treated as the same value.

Locally stored closures contribute checks only when called or passed as
callbacks to a reachable call. A closure called only from a dead branch or
another unused closure contributes nothing. Ordinary Rust expressions and
braced blocks inside macro token trees receive the same checks. Custom macro
expansion and whether an arbitrary callback consumer invokes a closure still
require review. Ordinary assertion edits use counts, without comparing assertion
text across revisions; reviewers must assess changes to the checked property.

Repeated required commands retain their execution counts. Moving a command
between required jobs preserves coverage automatically only in the same
execution environment with an unconditional destination step; an existing run
on another platform cannot replace a deleted run.
New platform-specific or child-process tests add coverage and do not require a
declaration merely for their initial scope; explicit ignores/skips still do.
The checked child-process idiom must launch the same exact libtest name, set
its recursion marker, and assert the child's successful exit. A plain
environment-dependent early return still requires a declaration.

### Declarations

`ci/test-changes.json` has version `1` and a `changes` array. Each entry contains
exactly one `test` or `job` identity printed by the guard, `kind`, a nonempty
`reason`, and a positive integer `issue`. The issue must exist in this GitHub
repository; pull requests do not substitute for issues. API failures fail the
guard rather than waiving validation. Every flagged change is printed with its
file and line, including declared changes and their reason/issue.

```json
{
  "version": 1,
  "changes": [
    {
      "test": "rust:crates/example::test=contract::checks::old_name",
      "kind": "removed",
      "reason": "Renamed to checks::new_name to match the supported contract.",
      "issue": 1234,
      "renamed_to": "rust:crates/example::test=contract::checks::new_name"
    }
  ]
}
```

`renamed_to` must identify an existing head test. The renamed test is still
compared for fewer assertions or new gates, which need their own declarations.
Every removal needs a reason and an existing issue. When the tested behavior
still exists, use `replacements` to list its exact replacing head test identities
(or `renamed_to` for a rename). Every named replacement must exist at the head.
When the behavior was deleted, explicitly set `behavior_deleted` to `true` and
cite the deleting commit, PR, or source change in a nonempty `deleting_change`:

```json
{
  "test": "rust:crates/example::test=contract::checks::legacy_adapter",
  "kind": "removed",
  "reason": "The legacy adapter and its supported behavior have been deleted.",
  "issue": 1234,
  "behavior_deleted": true,
  "deleting_change": "This PR: crates/example/src/legacy.rs removes the legacy adapter."
}
```

This form needs no replacement test. The two deleted-behavior fields are valid
only together on a removed test and cannot be combined with replacement or
rename fields. Reviewers verify that replacing tests cover the retained behavior,
or that the cited change actually deletes it. A required job/lane entry uses `job` in place of `test`,
for example `ci:.github/workflows/ci.yml::rust-tests[shard=it-2]`.

The file is a permanent, append-only record. The head's `changes` array must
start with every base entry unchanged and in the same order. Editing, deleting,
or reordering history fails the guard; JSON formatting and object-key order
may change. Historical entries match nothing, produce no error or warning, and
need no repeat issue or replacement-target lookup. An unrelated later PR passes
with this history present.

Only entries appended after that unchanged prefix can declare the current PR's
changes. To declare another reduction of the same test or job later, append a
new entry. Duplicate subject/kind pairs within the new entries, unused or
misspelled new entries, and wildcards are rejected. The initial file contents
are `{"version": 1, "changes": []}`; keep all records after their changes land.

### Local validation and boundaries

Use Python 3.11–3.14 on Linux and a stable worktree-local environment:

```bash
python3 -m venv target/test-inventory-venv
target/test-inventory-venv/bin/pip install --require-hashes --only-binary=:all: \
  -r ci/test-inventory-requirements.txt
target/test-inventory-venv/bin/python ci/test-test-inventory.py
target/test-inventory-venv/bin/python ci/test-inventory.py \
  --json test-inventory-report.json
```

Outside GitHub Actions, the default comparison is `git merge-base HEAD
origin/main` to `HEAD`. Fetch the remote history first; a missing `origin/main`
fails with guidance to fetch it. An explicit `--base` must be an ancestor of
both the checked-out `HEAD` and `origin/main`. For example, `--base HEAD` is
rejected on a branch with unmerged commits. A main-only or unrelated base is
also rejected. This applies even when `--head` is supplied.
When both `--base` and `--head` are explicitly supplied, they must resolve to
different commits, including when different refs name the same commit.
Default, base-only and event comparisons with identical revisions pass as
"nothing to compare", including local runs on unchanged main and train pushes
at main's tip. Their JSON report sets `nothing_to_compare` to `true` and uses
null inventory counts because no inventory comparison is needed.

Commit the candidate before comparing: the guard reads committed trees, not the
working tree. For a historical proof, supply both `--base BASE` and `--head HEAD`;
the base must also be an ancestor of that comparison head. The selected revisions
are printed so a historical result can be distinguished from validation of the
checked-out candidate. GitHub Actions uses its event revisions and verifies
that the event head is in the checked-out history.

Set `GH_TOKEN` when declarations need authenticated issue lookup;
the token is used only for read-only issue requests. No issue request is needed
when there are no newly appended declarations.

These are static structural checks, not semantic equivalence proofs. They do
not expand arbitrary user-defined Rust macros, perform compiler type inference,
resolve dynamic Python imports, or prove what an arbitrary shell command runs.
The guard follows the repository's explicit test targets, common test attributes,
local helpers, required workflow dependencies and literal skip selections.
Review still has to establish that changed conditions, values, or helper behavior
preserve the property under test. The separate policy on wall-clock assertions
continues to apply; this guard does not replace it.

## Privileged regression coverage

The **Rust SCTP cold multihoming** lane in [ci.yml](../.github/workflows/ci.yml)
runs both pending-blackhole connection-progress tests in a fresh network
namespace. The **Privileged Linux GTP-U and route regressions** job in
[gtpu-privileged.yml](../.github/workflows/gtpu-privileged.yml) runs the three
empty historical hierarchy normalization tests on a private bpffs mount, plus
the route-steering tests for distinct IPv4/IPv6 mark-only rules and locked-MTU
ICMP signaling in both families. The required **Privileged Linux GTP-U** check
requires both this job and the datapath job to succeed. Both workflows run on
PRs and main pushes.

These commands select exact ignored names and require their exact executed
counts with zero ignored tests. Normalization and locked-MTU tests must also
emit their success markers, so an unset privileged flag cannot produce a
passing gate without exercising the kernel. Build as the ordinary user, then
run the resulting test binary with the namespace privileges it needs.

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

The [CNF performance workflow](../.github/workflows/performance.yml) separately
runs all five latency profiles nightly on main at 04:41 UTC, without requiring
`OPC_PERFORMANCE_GATES`. That variable enables additional push runs. The original
100 ms protected-request and one-second selector limits remain unchanged.
Any failed, cancelled or incomplete scheduled matrix uses the same classification
hold below, including failures that leave no result artifact.

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
gh run list --repo openpacketcore/openpacketcore-sdk \
  --workflow performance.yml --event schedule --branch main
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
