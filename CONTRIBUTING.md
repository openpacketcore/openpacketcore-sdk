# Contributing to OpenPacketCore SDK

Thank you for your interest in contributing to the OpenPacketCore SDK. This document describes the development workflow, validation gates, and conventions we follow.

## Development setup

Linux is the only supported development and runtime platform. Hosted CI runs
Linux builds and tests; macOS and FreeBSD are outside the supported platform set.

### Required toolchain

- **Rust** ≥ 1.89 (install via [rustup](https://rustup.rs/))
- **Go** ≥ 1.26.9
- **kubectl**
- **kustomize**
- **helm** ≥ 3
- **cargo-fuzz** (optional; requires nightly Rust)

### Clone, build, and test

```bash
git clone https://github.com/openpacketcore/openpacketcore-sdk.git
cd openpacketcore-sdk

# Rust workspace
cargo build --workspace --all-features
cargo test --workspace --all-features -- --test-threads=4

# Go reference operator
( cd operators/sdk-reference-operator && go vet ./... && go test ./... )

# Kubernetes manifests
kubectl kustomize operators/sdk-reference-operator/config/default > /dev/null
```

### Reusing development build caches

Keep one stable build directory per worktree and compatible build profile during
development. The default worktree-local `target/` is suitable for ordinary Cargo
commands. If a lane requires `CARGO_TARGET_DIR`, choose a stable path within that
worktree, such as `target/core-tests` or `target/unsupported-selector`, and reuse
it across source edits. Do not suffix development cache paths with a commit,
source digest, timestamp, or attempt number, and do not share a writable target
directory between independently active worktrees.

Cargo tracks changed inputs and rebuilds affected crates. Run focused tests
during iteration, then the required validation gates on the final candidate.
Record source revision (and any uncommitted changes), toolchain, profile, command
and result separately from the cache path. Reused compilation does not allow a
passing test result from an earlier revision to count for the current one.

Preserve the CI and performance profiles below. In particular,
`CARGO_INCREMENTAL=0` disables per-crate incremental compilation; it does not
require clearing compiled dependencies. Do not run `cargo clean` or allocate a
fresh cache as a routine retry. Use an isolated clean build when qualification
explicitly requires one or when investigating a demonstrated cache problem.
Keep evidence outside disposable caches and check active users before cleanup.

## Validation gates

All pull requests must be green on the following commands before review:

On Linux, set `TMPDIR` to an existing private directory on disk before running
the test gates. Check its filesystem with `findmnt -T "$TMPDIR"`. The selector's
one-second durable request test rejects `tmpfs` and `ramfs`: file-backed databases
on those filesystems do not exercise disk-sync latency. Setting
`OPC_FS_VERITY_SNAPSHOT_ROOT` places immutable snapshots only; it does not move
the mutable databases or WALs out of `TMPDIR`.

For required fs-verity qualification, run the gate inside the filesystem owner:

```bash
mkdir -p "$PWD/.ci-scratch"
chmod 0700 "$PWD/.ci-scratch"
RUNNER_TEMP="$PWD/.ci-scratch" bash ci/setup-fsverity-tmp.sh -- <gate-command> [arguments...]
```

Each checkout keeps this one stable scratch root, `$PWD/.ci-scratch`, outside
Cargo's `target/` so build-output cleanup preserves its recovery records.
Reuse the directory across runs without deleting or replacing it: recovery
records match its directory identity, so a later sweep must use the same parent.
The wrapped command retains the caller's soft and hard file-descriptor limits
and umask. Privileged namespace setup must not replace the storage workload's
descriptor budget or its ordinary file-creation permissions.

The owner sets `OPC_FS_VERITY_SNAPSHOT_ROOT` and
`OPC_FS_VERITY_QUALIFICATION=required` for that command, then unmounts and removes
its private image. It also cleans up on interruption, including a killed
launcher. Startup reclaims only this checkout's marked, unlocked, current-user,
mode-0700 `opc-sdk-fsverity-runtime.*` directories containing exactly `ext4.img`
and an empty `tmp/`, with no loop or mount attachment. The root/runtime locks
serialize attachment with deletion; an exclusive backing-file lease also
excludes concurrent opens during inventory and removal. Legacy `opc-fsverity.*`
and other tools' `fs-verity-runtime.*` directories are always preserved.
Inventory or cleanup errors fail the gate.
The scratch parent must be owned and writable by the caller, and its filesystem
must support `user.*` xattrs and file leases. This can exclude older tmpfs
implementations. Creation and removal use a root-only staging directory under
a root-owned, non-writable or sticky ancestor on that same filesystem; if none
exists the gate fails closed. Removal freezes the pinned directory inodes,
moves the runtime into that protected namespace, verifies its identity there,
and only then removes its checked entries. Failed identity checks preserve the
objects and restore their ownership.
The helper keeps a small, root-owned recovery metadata directory for this
checkout and caller in that protected ancestor (for example `/home` or `/tmp`).
If its usual name is occupied by an untrusted object, it preserves that object
and uses an authenticated directory with a random suffix. Later sweeps resume
transactions in every authenticated fallback directory. Empty metadata
directories are removed when the last transaction or sweep finishes; helpers
waiting on a removed directory retry with a newly checked anchor.
Each staging transaction records its caller, checkout, parent and object
identities and helper process identity before taking ownership. Startup resumes
dead transactions, including frozen runtimes still in the scratch parent and
partly created or removed runtimes in staging. Live, locked, open or attached
resources are preserved for a later sweep; no manual root cleanup is needed.
The five-second loop-autoclear bound remains separate from inventory and the
bounded privileged create/remove round trips.
The privileged helper sets umask 0077 on entry so every new staging directory
starts private and searchable, independently of the caller's umask.
Mounts use a separate namespace with slave propagation: owner mounts cannot
reach other jobs. Host unmounts propagate into the owner when the upstream host
mount is shared, as on the hosted runners and standard systemd hosts; a private
upstream mount cannot provide that propagation. Setup requires
passwordless `unshare` and `setpriv`; commands retain the caller's identity,
environment, stdin and inherited ownership locks.
GitHub steps use `shell: bash ci/setup-fsverity-tmp.sh -- bash --noprofile --norc -e -o pipefail {0}`
so the runner resolves `bash` on PATH. Running setup in an earlier step no longer
exports a filesystem for subsequent steps. Replace split setup/export/EXIT-trap
recipes with the `-- <gate-command> [arguments...]` form before using this helper.
The real mount and
interruption regressions are `python3 ci/test-fsverity-runtime.py -v` on Linux
with the same passwordless namespace, mount, chown, umount and losetup privileges.
The narrow privileged Python helper also requires passwordless sudo: it passes
pinned loop descriptors, creates/removes verified caller-owned runtimes in a
protected namespace, and disposes only of verified caller-owned descendants.

```bash
cargo fmt --all --check
git diff --check
python3 ci/check-xfrm-dependency-contract.py
cargo clippy --locked -p opc-ipsec-xfrm --lib --no-default-features -- -D warnings
cargo clippy --locked -p opc-persist --all-targets --no-default-features -- -D warnings
cargo test --locked -p opc-persist --no-run
cargo test --locked -p opc-persist \
  --test break_glass_tests \
  --test security_policy_tests \
  --test security_policy_stress_tests \
  --test security_policy_empirical_tests \
  -- --test-threads=1
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features --quiet -- --test-threads=4
( cd operators/sdk-reference-operator && go vet ./... && go test ./... )
kubectl kustomize operators/sdk-reference-operator/config/default > /dev/null
```

For CI qualification, replace the broad workspace test command above with
`cargo test --locked -p opc-persist --all-features --quiet -- --test-threads=1`
and all CI shard plans. This preserves CI's test isolation and profile choices.
Run the commands produced by
`python3 ci/test-shards.py plan --shard ID` for every ID from
`python3 ci/test-shards.py ids`; first run `precheck --shard ID` for each shard.
General CI lanes follow the latest stable Rust release; the separate MSRV
lane checks Rust 1.89. Use the same Rust version as the CI run and set
`CARGO_INCREMENTAL=0`,
`CARGO_PROFILE_DEV_DEBUG=0`, and `CARGO_PROFILE_TEST_DEBUG=0`.

Required CI excludes only the exact real-time multi-process test names in
[`ci/realtime-qualification.json`](ci/realtime-qualification.json). A separate,
visible **Real-time multi-process qualification (non-required)** job runs them
on every PR, and scheduled main qualification runs ten repetitions. Any failed
repetition keeps that run red. The manifest is temporary and must shrink as
ordering/outcome assertions, injected time, and readiness waits replace
host-clock correctness checks. Assertions must be preserved.

A qualification failure still needs a decision before merging. Compare the PR
and unchanged main with the same toolchain, features, storage, load, and command;
a failure unique to the change blocks it. A red nightly stops new merges until
every failure is classified in its `nightly-qualification` issue, with a known
flake issue or a verified fix/revert. Check the hold again immediately before
merging; an earlier green PR check cannot establish the current nightly state.
See the [CI qualification policy](ci/README.md) for the exact selection,
reporting, merge checks, and requirements for returning tests to required CI.

The native IPsec, i686 session-net, and egress host-source jobs are separate
profiles: use `CARGO_INCREMENTAL=0` and their workflow commands, but leave
`CARGO_PROFILE_DEV_DEBUG` and `CARGO_PROFILE_TEST_DEBUG` unset, as those jobs do.
Run the protected prepared-transition functional test alone with
`CARGO_PROFILE_TEST_OPT_LEVEL=1` in the core, native, and i686 lanes. Debug
assertions and overflow checks remain enabled. The selector functional test
retains its ordinary test profile.

The full-bound native log and receipt-history reclamation proofs also use
`CARGO_PROFILE_TEST_OPT_LEVEL=1`, with debug assertions and overflow checks
enabled. Each proof has a dedicated parallel core shard (`native-log-0` through
`native-log-13`) and egress shard (`4` through `17`).
Both plans preserve their package and feature selection and precheck the exact
enabled names in the execution profile. The default three-cycle regressions
retain the ordinary test profile. All entry counts, persistence operations,
assertions and test deadlines remain unchanged. Core proof jobs have 90-minute
budgets. The egress leader proof on shard 4 has a 120-minute budget; the Durable
and Async proofs on shards 5 and 6 and the receipt-history proofs on shards
7 through 17 have 75 minutes, including compilation.
See the [CI layout](ci/README.md) for the hosted sizing evidence and the ordinary
library partition.

The separate **Rust GTP-U unsupported-platform cfg** job in
[ci.yml](.github/workflows/ci.yml) runs on Linux with
`RUSTFLAGS="--cfg opc_linux_gtpu_sys_force_unsupported"` and
`--no-default-features` to exercise behavior when the Linux GTP-U backend is
unavailable. The ordinary workspace run does not cover that profile.
Its selector functional test must resolve exactly once and run alone after
the other cfg tests finish. Use a separate `CARGO_TARGET_DIR` for this profile,
as the workflow does.

### Non-Linux compile checks

The required **Rust clippy** job in [ci.yml](.github/workflows/ci.yml) also
checks selected retained non-Linux code with default features. These checks
compile code and tests but do not execute them on non-Linux hosts:

```bash
rustup target add x86_64-unknown-freebsd aarch64-apple-darwin
cargo clippy --locked \
  -p opc-gtpu-dataplane -p opc-linux-gtpu-sys -p opc-session-store \
  -p opc-fs-verity-sys -p opc-sqlite-file-control-sys \
  -p opc-session-testkit -p opc-persist -p opc-peer-discovery \
  --all-targets --target x86_64-unknown-freebsd -- -D warnings
# The other five crates above need an Apple C toolchain for bundled
# SQLite and/or ring. Check the sys crates and DNS client on Apple too.
cargo clippy --locked -p opc-linux-gtpu-sys -p opc-fs-verity-sys -p opc-peer-discovery \
  --all-targets --target aarch64-apple-darwin -- -D warnings
# Runtime test targets pull in AWS-LC through opc-sbi and need a
# target C toolchain. Its library can be checked on both targets.
for target in x86_64-unknown-freebsd aarch64-apple-darwin; do
  cargo clippy --locked -p opc-runtime --lib --target "$target" -- -D warnings
done
```

### Exact local kernel lifecycle qualification

The **Privileged local kernel lifecycle** job in
[ci.yml](.github/workflows/ci.yml) runs the required cases in
`ci/local-kernel-lifecycle-cases.json` on its own runner. It blocks the existing
**Rust workspace** aggregate and has its own kernel preflight and cleanup
verification. See the [job mapping and time estimate](ci/local-kernel-lifecycle-job.md).
After the workflow's kernel module setup, run that same manifest and cleanup
check locally with the worktree's existing Cargo cache. Create the evidence
directory as the build user; only inventory and native tests require root:

```bash
mkdir -p target/lifecycle-evidence/run-01/cleanup
sudo -n python3 ci/check-local-kernel-lifecycle-cleanup.py snapshot \
  target/lifecycle-evidence/run-01/cleanup
python3 ci/check-local-kernel-lifecycle-cleanup.py run \
  target/lifecycle-evidence/run-01/cleanup -- \
  python3 ci/qualify-local-kernel-lifecycle.py \
    --evidence-dir target/lifecycle-evidence/run-01/qualification
# Run this final verification even when qualification fails.
sudo -n python3 ci/check-local-kernel-lifecycle-cleanup.py verify \
  target/lifecycle-evidence/run-01/cleanup
```

This needs Linux BPF/XFRM support, iproute2, Python 3, `libseccomp.so.2`, `unshare`, `timeout`,
and root or noninteractive sudo. Every case gets a fresh network namespace
and private bpffs mount. BPF program/map ID enumeration and reopen terminate
the case. Lifecycle readback must use exact tc entries and already-held load
or private-pin descriptors, without node-global ID inspection privileges.
Missing tests, skips, unsupported capabilities,
timeouts and changed source/binaries fail qualification. The evidence records
the compiler, source digest, emitted binaries, kernel and exact case results;
use a new evidence directory on a repeat run, while reusing the build cache.
Wrap any namespace-creating preflight in the same cleanup `run` mode after the
snapshot. Its process ownership evidence rejects leaked qualification namespaces
and unfinished descendants while allowing unrelated host services to come and
go. Host-visible pins, mounts, named namespaces and interfaces must still match
the baseline. Missing ownership or incomplete inventories fail cleanup.
After recording attribution, the owner terminates and reaps its remaining
descendants, including privileged children. Disposal uses verified process
identities and pidfds, with a two-second SIGTERM grace followed by up to three
seconds for SIGKILL. SIGTERM, SIGINT and SIGHUP keep the owner alive through disposal.
Original leaks and interruptions remain failures after disposal; the evidence
retains both the original attribution and the disposal result.
`--toolchain` chooses an installed Rust toolchain. Repeated `--case` arguments
select exact cases for development and explicitly produce a partial result.

This is a functional lifecycle gate on the actual host kernel. The pinned
Rocky 9.4 enterprise lane also runs the complete lifecycle manifest from a
verified static bundle on its `5.14.0-427.x.el9_4` kernel. The separate pinned
Linux 6.8 guest still needs a lifecycle manifest run before its existing
datapath qualification can be extended to this API.

### CNF performance qualification

Required CI checks durable completion, exact receipts/readback, quorum and
wire-call counts, recovery, and authority expiry. The two composed latency
scenarios also have explicit performance tests: the protected prepared
transition must complete within **100 ms**, and the complete selector request
within **one second**. Their functional counterparts run the same scenario
with a ten-second hang guard; passing those tests does not qualify latency.
Production deadlines, lease bounds, disk syncs, and durability checks are
unchanged. Deadline-accounting and cancellation regression tests still run in
required CI.

The latency tests are marked `#[ignore]` so ordinary Cargo and required CI runs
do not depend on shared-runner performance. Run them explicitly with:

```bash
python3 ci/performance-tests.py --profile core-protected
python3 ci/performance-tests.py --profile core-selector
python3 ci/performance-tests.py --profile native-protected
python3 ci/performance-tests.py --profile i686-protected
python3 ci/performance-tests.py --profile unsupported-selector
```

Use a separate `CARGO_TARGET_DIR` per profile and the same toolchain/storage
setup as its CI lane; i686 also needs the 32-bit target and system toolchain.
The script selects each ignored test exactly once, retains the original
deadline, and fails on any failed measurement. Logs and a JSON result are
written under `target/performance/PROFILE` (or `--output DIRECTORY`).

The **CNF performance** workflow runs every night on main at 04:41 UTC,
independently of repository variables, and can also run manually in Actions.
It defaults to the existing GitHub-hosted `ubuntu-latest` runners. Set repository variable
`OPC_PERFORMANCE_RUNNER` to an available Linux x64 runner label to qualify a
different runner; the manual `runner` input overrides that variable. Set
`OPC_PERFORMANCE_GATES=true` to add qualification after pushes to `main`.
It is separate from required PR checks and fails normally when a limit is missed.
Each profile uploads its raw logs, host details, and result. A failed or incomplete
nightly opens or updates the same `nightly-qualification` classification issue
as real-time qualification. The Rust gates hold merges until every failure is
classified; a later green nightly does not clear that hold.

Do not replace the performance deadlines or use RAM-backed database storage.
A local timing pass qualifies only that local host/storage observation; it does
not establish that the GitHub-hosted runner meets the limit.

Functional consensus fixtures wait for actual publication with a separate
wall-clock watchdog. Use the shared controlled clock for successful operations
that must not expire merely because disk work or another runtime was delayed.
Keep stores and their Raft/transport tasks on the caller's runtime, and join
accepted work before the controlled runtime exits. Deadline, interrupted-election,
and latency tests must retain or explicitly advance their protocol clock.
For bounded public APIs such as reclamation, continue partial progress within
the same absolute caller deadline and preserve each report's safety assertions;
do not give every retry a fresh budget.

If the pull request touches operator-sdk-go or the Helm chart, also run:

```bash
( cd operators/operator-sdk-go && go vet ./... && go test ./... )
helm lint operators/helm/sdk-reference-operator
helm template test operators/helm/sdk-reference-operator > /dev/null
```

## Declaring changes to test coverage

The required **Rust workspace** check includes **Test inventory guard** on every
pull request. The same guard runs on every `train/**` push. It compares Git
revisions without building or executing the changed tests, and reports:

- Removed or renamed Rust, Python, and Go tests.
- Added ignores, feature/configuration or environment gates, and CI skip entries,
  including tests introduced with an ignore already present.
- Decreased assertion counts, including assertions in local test helpers, and
  removed assertion-bearing scenario helpers. Assertions in constant-false
  branches, trivially successful checks, and unused closures do not count.
- Removed required jobs, matrix lanes, or required test commands, including
  moving their execution outside the **Rust workspace** aggregate.

An intentional reduction needs an entry in `ci/test-changes.json`, with the exact
name printed by the guard, a change kind, a reason, and an existing GitHub issue
number in this repository. Reviewers see the finding even when it is declared.
Do not use a pull-request number in place of an issue. For example:

```json
{
  "version": 1,
  "changes": [
    {
      "test": "rust:crates/example::test=contract::checks::records_value",
      "kind": "assertions-decreased",
      "reason": "The obsolete cache assertion is replaced by the durable-read contract.",
      "issue": 1234
    }
  ]
}
```

The file is a permanent, append-only record. Keep the base's entries unchanged
and in order; editing, deleting, or reordering them fails the guard. Historical
entries are ignored without warnings and cannot authorize a new reduction.
Only newly appended entries declare the current change. If the same test needs
another declaration later, append a new entry rather than editing its history.
A removal always needs a reason and an existing issue. When the behavior still
exists, name its replacing head tests in `replacements`; a rename instead uses
`renamed_to` naming the test at the head. When the behavior was deleted, set
`behavior_deleted` to `true` and cite the deleting commit, PR, or source change
in `deleting_change`. Deleted behavior needs no unrelated replacement test.
A rename does not waive a separate assertion decrease or new gate.

Local runs default to the merge base of `HEAD` and `origin/main`. An explicit
base must be an ancestor of both, so a branch-only base cannot hide the change.
Fetch the remote history and commit the candidate before running the guard.

See [the inventory guard documentation](ci/README.md#test-inventory-guard) for
the declaration format, local command, and parsing boundaries. A passing static
inventory is evidence about the listed structural checks, not a proof that two
tests exercise the same behavior. Keep reviewing the tested properties.
Ordinary assertion edits are compared by count, not by assertion text.

## Commit conventions

We use [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `docs:`, `ci:`, `chore:`, `refactor:`, `test:`). The scope should be the crate name without the `opc-` prefix where sensible (e.g., `feat(runtime):`, `fix(sbi):`).

Recent examples from the repository:

```
chore: harden SDK for public release
feat(alarm): resolve PRD-007 by implementing taxonomy versioning, bounded sinks, testkit, and k8s/yang projections
fix(session-cache): enforce coherent cache reads
```

## Developer Certificate of Origin (DCO)

By contributing to this project, you agree to the [Developer Certificate of Origin](https://developercertificate.org/) and certify that you have the right to submit the work under the Apache-2.0 license.

Every commit must contain a `Signed-off-by` line. Use `git commit -s` to add it automatically.

## Pull request checklist

Before requesting review, please confirm:

- [ ] Tests added or updated for the change.
- [ ] Documentation updated (`README.md`, crate-level rustdoc, or `docs/` as appropriate).
- [ ] No new dependencies without justification in the PR description (must be Apache-2.0/MIT/BSD-compatible and build on Rust 1.89).
- [ ] RFC or ADR updated if the change alters a behavior contract.
- [ ] All validation gates pass locally.
- [ ] Commits are signed-off (`git commit -s`).

## Where to start

- New contributors should read [`docs/quickstart.md`](docs/quickstart.md) for a guided first build.
- Architectural context is in [`docs/rfc/`](docs/rfc/).
- Check the [gap register in `docs/implementation-status.md`](docs/implementation-status.md) for current open items.

## Code style

- `#![forbid(unsafe_code)]` is enforced workspace-wide; do not use `unsafe`.
- No `unwrap()`, `expect()`, or `panic!()` in non-test code. Use `thiserror`-based error enums.
- Public items must have rustdoc comments.
- Follow the builder patterns and error-enum conventions already established in the target crate.

## Releasing

### Cutting a release

1. Bump the workspace version in `Cargo.toml` (`[workspace.package]`) and the
   intra-workspace `version` keys on path dependencies, including the
   `examples/smf-reference` workspace; refresh both `Cargo.lock` files. The
   `opc-yanggen` golden fixture
   (`crates/opc-yanggen/tests/fixtures/deterministic-emitter.txt`) embeds the
   generator version and must be updated to match.
2. Roll the `[Unreleased]` section of `CHANGELOG.md` into a dated version
   section and update the comparison links.
3. Run the full validation gates, then tag `vX.Y.Z` and push the tag. The
   current `Release Validation` workflow runs a subset of repository checks and
   uploads Cargo metadata, rendered manifests, the Git revision, and Rust/Go
   SBOMs. It does not yet emit or enforce the complete RFC 006 VEX, provenance,
   conformance/gap, performance, and signed-bundle evidence set; its artifact
   upload is not a signed release attestation.
4. crates.io publishing is staged in `.github/workflows/release.yml` as a
   commented-out `publish` job; enabling it requires a `CARGO_REGISTRY_TOKEN`
   repository secret. Until it is enabled, the automated path validates a tag
   and uploads workflow artifacts; it does not publish crates or create a
   GitHub Release.

### Cargo publication eligibility

Cargo publication eligibility is release mechanics, not a production-maturity
or support declaration. Packages that omit `publish` or set `publish = true`
are Cargo-publishable; packages with `publish = false` are held.
`scripts/publish-order.py --check` validates the eligible dependency graph and
required version keys, but it does not require every manifest to declare an
explicit boolean.

The authoritative current publication list is generated rather than duplicated
here:

```bash
python3 scripts/publish-order.py --names
```

Eligible crates must be published in the generated topological order because
Cargo resolves registry dependencies while verifying each package. Every
dependency must be live before its dependent can be published.

The following table records selected explicitly experimental crates with
documented graduation requirements. It is intentionally not the complete set
of held packages: internal adapters, testkits, platform-specific crates, and
reference components may remain unpublished without being graduation
candidates. Cargo metadata and each package manifest are authoritative for
eligibility.

| Crate | Status | Graduation requirement |
|:------|:-------|:-----------------------|
| `opc-session-net` | experimental | A stable wire-format contract with a documented compatibility policy and soak evidence across at least one minor version bump. See `crates/opc-session-net/README.md`. |
| `opc-sa-mirror` | experimental | A stable keymat wire-format contract with a documented compatibility policy (graduation criteria decided together with `opc-session-net`'s), plus downstream CNF evidence that a live-mirrored takeover passes the fenced re-pin on real owner loss. See `docs/rfc/015-live-sa-mirror.md`. |
| `opc-key-vault` | experimental | A production-readiness review covering Vault policy scoping, secret-zero handling, lease rotation, and an integration test against a real or containerized Vault Transit instance. |
| `opc-gtpu-dataplane` N3 module | experimental packet/intent subset | Qualified N3 forwarding, exact selector-authority integration, control-datagram lifecycle ordering and independent live-peer evidence. All shipped N3 capability results remain `Missing`; see `crates/opc-gtpu-dataplane/CONFORMANCE.md`. |
| `opc-proto-nas` | experimental | Structured parsing of the remaining 5GMM and 5GSM message bodies listed as out-of-scope in `crates/opc-proto-nas/CONFORMANCE.md`, with spec-byte fixtures for each message. |
| `opc-proto-gre` | experimental NWu profile | Independent review, peer interoperability, and downstream evidence for authenticated session/direction scoping and caller-owned SA selection. See `crates/opc-proto-gre/CONFORMANCE.md`. |
| `opc-proto-ngap` | experimental | A working canonical (typed) APER encoder path, verified by external fixtures for `NGSetupResponse` and `NGSetupFailure`, after the upstream `rasn` APER encoder misalignment is resolved or replaced. See `crates/opc-proto-ngap/CONFORMANCE.md`. |
| `opc-proto-gtpv2c` | experimental S2b subset | Independent-peer interoperability and completion of the declared compatibility and negative-evidence matrix. Any future coverage expansion must also add mandatory-IE validation and spec-authored fixtures. See `crates/opc-proto-gtpv2c/CONFORMANCE.md`. |
| `opc-proto-diameter` | experimental base + Rf/SWm dictionaries | ADR 0015 conformance claim for the base header/AVP layer, typed helpers and independently sourced fixtures for at least the remaining `app-gx`, `app-s6a`, `app-s6b`, and `app-swx` skeleton dictionaries, and downstream product integration evidence. See `crates/opc-proto-diameter/CONFORMANCE.md`. |
| `opc-proto-ikev2` | experimental typed mechanisms | Broader remaining payload-body coverage, independent-peer interoperability evidence, and downstream product integration evidence for the IKE SA/EAP-AKA/Child SA policy boundary. Typed executable IKE-SA profiles, RFC 7383 protection/framing, and their current vector evidence are recorded in `crates/opc-proto-ikev2/CONFORMANCE.md`. |
| `opc-api-nnrf` | experimental | Client/server stub generation and expanded OpenAPI operation coverage, plus generator stability across regenerated `types.rs` from the same pinned 3GPP YAML. See `crates/opc-api-nnrf/CONFORMANCE.md`. |

Changing Cargo eligibility requires updating `publish` in the package manifest.
Changing maturity additionally requires the crate's documented graduation
evidence and an independent review; the next release section in `CHANGELOG.md`
must record either change.

### Publishing a release

```bash
python3 scripts/publish-order.py            # prints the cargo publish sequence
python3 scripts/publish-order.py --check    # CI gate: graph acyclic, version keys present
```

Before tagging a release: run the full validation gates above, update
`CHANGELOG.md` (move `[Unreleased]` into a version heading), and publish in
the printed order, waiting for each crate to be live before the next.
