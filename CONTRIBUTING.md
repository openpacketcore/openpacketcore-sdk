# Contributing to OpenPacketCore SDK

Thank you for your interest in contributing to the OpenPacketCore SDK. This document describes the development workflow, validation gates, and conventions we follow.

## Development setup

### Required toolchain

- **Rust** ≥ 1.89 (install via [rustup](https://rustup.rs/))
- **Go** ≥ 1.26.6
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

## Validation gates

All pull requests must be green on the following commands before review:

On Linux, set `TMPDIR` to an existing private directory on disk before running
the test gates. Check its filesystem with `findmnt -T "$TMPDIR"`. The selector's
one-second durable request test rejects `tmpfs` and `ramfs`: file-backed databases
on those filesystems do not exercise disk-sync latency. Setting
`OPC_FS_VERITY_SNAPSHOT_ROOT` places immutable snapshots only; it does not move
the mutable databases or WALs out of `TMPDIR`.

```bash
cargo fmt --all --check
git diff --check
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
Use the same Rust version as the CI run and set `CARGO_INCREMENTAL=0`,
`CARGO_PROFILE_DEV_DEBUG=0`, and `CARGO_PROFILE_TEST_DEBUG=0`.

The native IPsec, i686 session-net, and egress host-source jobs are separate
profiles: use `CARGO_INCREMENTAL=0` and their workflow commands, but leave
`CARGO_PROFILE_DEV_DEBUG` and `CARGO_PROFILE_TEST_DEBUG` unset, as those jobs do.
Run the protected prepared-transition functional test alone with
`CARGO_PROFILE_TEST_OPT_LEVEL=1` in the core, native, and i686 lanes. Debug
assertions and overflow checks remain enabled. The selector functional test
retains its ordinary test profile.

The separate **Rust GTP-U unsupported-platform cfg tests** job in
[ci.yml](.github/workflows/ci.yml) also uses
`RUSTFLAGS="--cfg opc_linux_gtpu_sys_force_unsupported"` and
`--no-default-features`. The ordinary workspace run does not cover that profile.
Its selector functional test must resolve exactly once and run alone after
the other cfg tests finish. Use a separate `CARGO_TARGET_DIR` for this profile,
as the workflow does.

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

Run the **CNF performance** workflow manually in Actions. It defaults to the
existing GitHub-hosted `ubuntu-latest` runners. Set repository variable
`OPC_PERFORMANCE_RUNNER` to an available Linux x64 runner label to qualify a
different runner; the manual `runner` input overrides that variable. Set
`OPC_PERFORMANCE_GATES=true` to run qualification automatically after pushes to
`main`. It is separate from required PR checks and fails normally when a limit
is missed. Do not make it a required merge check until the chosen runner is
qualified. Each profile uploads its raw logs, host details, and result.

Do not replace the performance deadlines or use RAM-backed database storage.
A local timing pass qualifies only that local host/storage observation; it does
not establish that the GitHub-hosted runner meets the limit.

If the pull request touches operator-sdk-go or the Helm chart, also run:

```bash
( cd operators/operator-sdk-go && go vet ./... && go test ./... )
helm lint operators/helm/sdk-reference-operator
helm template test operators/helm/sdk-reference-operator > /dev/null
```

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
