# CI and real-time qualification

The required **Rust workspace** check aggregates the inventory guard, gates, clippy, and test
shards in [ci.yml](../.github/workflows/ci.yml). Use
`python3 ci/test-shards.py ids`, `plan --shard ID`, and `precheck --shard ID`
to reproduce the shards with the profile and disk setup in
[CONTRIBUTING](../CONTRIBUTING.md#validation-gates).

The hosted `misc` runner uses `plan --shard misc --split-libraries` for binary
unit tests, example compilation, doctests and the heavy-target remainder. Its
library phase runs on three required `Rust library tests` runners, with the same
workspace package selection, features, ordinary profile and four test threads.
Each runner compiles/lists every library and verifies that its compiled targets
match Cargo metadata. Exact-name exclusions partition the live inventory using
the first eight SHA-256 bytes modulo three. Duplicate names in different libraries
share an owner; new tests are assigned automatically. The uploaded mapping
records the revision, identities, ignored status and exact commands. The logical
`plan --shard misc` remains available to reproduce the complete unsplit phase.

Five integration runners pack target runtime estimates after reserving their
fixed library work. The `recovery_profile` target has an exact named group on
`it-4` and a complementary remainder assigned by the planner. Future tests
automatically belong to the remainder. Both owners compile/list the real target
and verify that the group and remainder cover every test exactly once before
execution. The named tests must resolve exactly once and remain enabled.
Filters for a split target never apply to another target's same-named tests.
All invocations retain the workspace features, ordinary profile and four test
threads; the existing isolated timing contracts retain their serial commands.
The 60-minute job limits are unchanged. Runtime weights are estimates rather
than deadlines and should be refreshed as the hosted workload changes.

The scope-payload decode regression and the three-large-child observation refusal
test each run in a fresh serial process first on library shard `0` and egress
shard `1`, followed by that runner's parallel suite. Exact exclusions prevent
duplicate execution. Live inventories reject missing, ignored or ambiguous names.
The tests retain their four Tokio workers, all assertions and ten-second bounds.
Successful runs print elapsed time and decode/audit counts for hosted validation.

The full-bound native log and receipt-history proofs listed in
[`native_log_bound.py`](native_log_bound.py) each have a dedicated parallel runner:

| Proof | Core shard | Egress shard |
| --- | --- | --- |
| Leader idempotent request and reopen | `native-log-0` | `4` |
| Durable snapshot, purge and restart | `native-log-1` | `5` |
| Async snapshot, purge and restart | `native-log-2` | `6` |
| Native abandoned deferral beyond the full retained window | `native-log-3` | `7` |
| SQLite abandoned deferral beyond the full retained window | `native-log-4` | `8` |
| Native grouped retirement with a surviving resolution | `native-log-5` | `9` |
| Native rejection of unexpired removed and surviving receipts | `native-log-6` | `10` |
| Native closed epoch after completion or abandonment | `native-log-7` | `11` |
| Native grouped resolution and retirement | `native-log-8` | `12` |
| Native separate resolution and retirement | `native-log-9` | `13` |
| Catalog grouped apply and checkpoint | `native-log-10` | `14` |
| Catalog separate apply, one checkpoint | `native-log-11` | `15` |
| Catalog separate checkpoints | `native-log-12` | `16` |
| Catalog rejection of false deletion witnesses | `native-log-13` | `17` |

Each runs in its own serial test process at test O1, with debug assertions and
overflow checks enabled, preserving the original package/feature selection.
Live prechecks resolve the exact enabled name in that profile. All million-entry
inputs, persistence operations and assertions remain intact; the default
three-cycle regressions stay in the ordinary library partition.

Core proof runners retain their 90-minute job budget. The egress leader proof
on shard 4 has 120 minutes; the Durable and Async proofs on shards 5 and 6 retain
75 minutes. In [egress run 38801737477](https://github.com/openpacketcore/openpacketcore-sdk/actions/runs/38801737477/job/116652422946),
the leader reached 917,504 of 1,056,768 proposals in 3,465.5 seconds before its
75-minute job budget expired. The slowest measured 65,536-proposal interval took
298.48 seconds, projecting 80.2 minutes for all proposals. Adding the observed
12.8-minute precheck gives about 93 minutes before setup and reopen. A 120-minute
budget leaves about 27 minutes for those steps and runner variation.

This changes only the leader's job budget. The whole proof, reopen, test deadlines
and assertions remain intact. A hosted run must confirm the resulting margin.
The dedicated matrices compile only their proof profile; ordinary heavy-1 and
egress shards do not pay for that compilation.

The eleven lease-deferral proofs use the full 1,048,576-entry history, including
the grouped/separate retirement and checkpoint cases. They follow the same
one-proof-per-runner O1 plan. Their core jobs retain 90 minutes and their egress
jobs use the existing 75-minute proof budget; no existing budget changes.
In [egress job 117733900399, attempt 2](https://github.com/openpacketcore/openpacketcore-sdk/actions/runs/39142587245/job/117733900399),
the ordinary shard 0 store harness started at 17:03:44Z and was still running
when the job was cancelled at 17:43:12Z. Its live map assigned five of these
million-entry proofs to shard 0, with the SQLite counterpart on shard 1 and the
remaining proofs on shards 1 and 2. Moving all eleven to exact dedicated owners
removes that work from the ordinary shards without reducing their inputs,
maintenance batches, persistence operations, assertions or deadlines. The hosted
rerun must establish the resulting margin; the cancelled log does not provide
individual completion times for these proofs.

The required i686 matrix separates session-net library tests from executable
unit tests, integration tests and doctests. The integration runner exercises the
workflow selectors against a fixture with a newly discovered executable and a
new integration target. The required manifest audit rejects other test-enabled
target kinds until a shard explicitly covers them; future targets cannot silently
fall outside the split. Both ordinary shards and the isolated contracts remain
required by the same aggregate.

## Borrowed-descriptor Clippy guard

Run `cargo fetch --locked` before `python3 ci/test-clippy-fd-guard.py` on a
cold checkout. The guard compiles offline; its rustix fixture also uses
`--locked` and the committed `fixtures/clippy-fd-guard/Cargo.lock`. That
lockfile keeps the workspace's rustix version and transitive dependency
versions and checksums. The guard checks that they still match the workspace,
so update the fixture lockfile alongside changes to those workspace pins.
After a Dependabot bump and `cargo fetch --locked`, recreate the guard's temporary
rustix fixture with its manifest and source, seed it with the workspace
`Cargo.lock`, run `cargo metadata --offline --format-version 1` there, and copy
the pruned lockfile back to `ci/fixtures/clippy-fd-guard/Cargo.lock`.

The `nix::unistd::dup` entry intentionally keeps Clippy's unreachable-function
warning when nix is built without `fs`. That build cannot call `dup`; keeping
the warning also preserves diagnostics for a misspelled path when `fs` is on.

## Secret scan scope

The [security workflow](../.github/workflows/security.yml) scans a pull request's
exact `base.sha..head.sha` range with the head's `.gitleaksignore`.
Pushes to `main` scan the pushed commit's full reachable history. A commit that
reaches `main` through a pull request against `main` is scanned in that pull
request and again on the push to `main`.
A pull request run scans only what its base branch does not already contain,
and it does not run again when the base is changed. So three things are first
scanned outside any pull request: the merge commit GitHub creates, a direct
push, and commits already on a base branch other than `main` that has no pull
request of its own. The push to `main` scans all of them; the daily scan covers
branches.

Each run makes two passes with the same pinned scanner. The primary pass reads
`git log -p` over the pull request's exact range, the pushed commit's full
reachable history, or all fetched refs; it covers ordinary commits and side
branches. A second merge-only pass (`--merges -m --first-parent`) diffs merge
commits against their first parent, so text that exists only in a merge
commit's conflict resolution is scanned even though `git log -p` prints no diff
for a merge commit. Both passes must complete cleanly, or report a findings
count, for the scan to pass; a scan that did not complete is never clean. The
merge-only pass adds coverage after a clean primary pass, and its report is
`gitleaks-merge-report.json` in the runner temp directory.

Scheduled runs (daily at 08:17 UTC) fetch and scan all branch and tag refs with
the `.gitleaksignore` on `main`, including branches without pull requests.
They do not fetch pull request heads; those are scanned by their own runs.
Findings or scan failures open or update a `secret-scan` issue with the run link
and, when available, the number of findings; without a count the issue says that
the result is not clean. gitleaks 8.30.1 exits 0 when its `git log` fails, so the
scan step also fails when the scanner logs an error or does not log `no leaks found`.
That issue does not impose a merge hold on unrelated pull requests. Manual runs
scan all refs like the scheduled run, with the dispatched commit's
`.gitleaksignore`, and do not open an issue. Required workflow regressions in
`ci/test-test-inventory.py` pin these scopes, the merge-commit diff pass, the
merge-only-text fixture, and scheduled issue reporting.

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

The informational `clock-source-changed` kind records a functional test's
conversion between real and controlled time. It uses only `test`, `kind`,
`reason`, and `issue`; the exact head test must exist and its source file must
change. This also permits recording a conversion made while a new test is
still under review. It never authorizes fewer assertions, a new gate, removal,
or another coverage reduction: those findings remain independent. Review must
check every numeric deadline, hold, mutation bound and assertion, the pre-fix
RED, and the retained real-time qualification. Static inventory cannot prove
that two time sources preserve a test's meaning.

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
also rejected. This applies even when `--head` is supplied, except for the
explicit backlog-target comparison below.
When both `--base` and `--head` are explicitly supplied, they must resolve to
different commits, including when different refs name the same commit.
Default, base-only and event comparisons with identical revisions pass as
"nothing to compare", including local runs on unchanged main and train pushes
at main's tip. Their JSON report sets `nothing_to_compare` to `true` and uses
null inventory counts because no inventory comparison is needed.

For a pull request into the integration branch, run
`ci/test-inventory.py --base origin/backlog --head HEAD`. This narrowly named
mode resolves the fetched `refs/remotes/origin/backlog` ref, requires it to be
an ancestor of the comparison head, and requires that head to be in the
checked-out history, as PR CI does. The full ref name is also accepted. Equal
revisions, bare branch-only SHAs, other branch names and base-only invocations
do not gain this exception. This qualifies the delta into `backlog`; the
default main comparison remains necessary when landing that branch on main.

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
ICMP signaling in both families. It also runs the 14 eBPF library proofs for
kernel program identity, historical recovery and retirement races, and the
three native control-queue and injection contracts. These reuse the library
binary built for normalization. Their counts, anti-skip checks, success markers
and native control artifacts remain mandatory. Workflow regressions pin the
library's 14-test count, all 14 provenance markers and skip rejection, and verify
that incomplete evidence fails the gate.

The **Privileged Linux GTP-U datapath** job keeps the host parser tests,
map-in-map reader-grace proof, Linux GTP-U integration suite and 60 eBPF
integration tests. The **Privileged Linux GTP-U workload resets** job runs the
remaining 21 eBPF tests in the `workload_strict_reset_` and
`workload_exclusive_reset_` families in a fresh network namespace with the same
kernel prerequisites. Both integration partitions require source-derived counts
and reject skips; every existing proof assertion and evidence check is retained.
The workflow regressions also pin the 13 strict and 8 exclusive reset tests,
their combined 21-test count and skip rejection. All 148 native test executions
occur exactly once across the three jobs.

The existing jobs retain their 30-minute datapath and 20-minute regression
budgets; the new reset job has a 20-minute budget. The datapath and regression
jobs each build in `target/gtpu-native`, and the reset job builds in
`target/gtpu-resets`. Each target is also its job's explicit Rust cache target;
each hosted job has its own checkout and job-specific cache key. Cache misses
still compile and execute the complete selection. All three native jobs save
caches only on `main`; pull requests still restore them. This limits additional
PR-scoped archives in the repository's shared cache budget. The required
**Privileged Linux GTP-U** check requires all three native jobs to succeed. A
failed, cancelled or skipped native job fails that check. This adds one job per
CI run. Both workflows run on PRs and main pushes.

The normalization, route and native control commands select exact ignored names
and require their exact executed counts with zero ignored tests. Normalization
and locked-MTU tests must also emit their success markers, so an unset privileged
flag cannot produce a passing gate without exercising the kernel. Build as the ordinary user, then
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
