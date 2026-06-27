# Contributing to OpenPacketCore SDK

Thank you for your interest in contributing to the OpenPacketCore SDK. This document describes the development workflow, validation gates, and conventions we follow.

## Development setup

### Required toolchain

- **Rust** ≥ 1.88 (install via [rustup](https://rustup.rs/))
- **Go** ≥ 1.26
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

```bash
cargo fmt --all --check
git diff --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features --quiet -- --test-threads=4
( cd operators/sdk-reference-operator && go vet ./... && go test ./... )
kubectl kustomize operators/sdk-reference-operator/config/default > /dev/null
```

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
- [ ] No new dependencies without justification in the PR description (must be Apache-2.0/MIT/BSD-compatible and build on Rust 1.88).
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
   `Release Validation` workflow re-runs the gates and uploads SBOMs and
   release evidence.
4. crates.io publishing is staged in `.github/workflows/release.yml` as a
   commented-out `publish` job; enabling it requires a `CARGO_REGISTRY_TOKEN`
   repository secret. Until it is enabled, releases are source releases
   (git tag + GitHub release) only.

### Publish tiers

The workspace is split into two publish tiers. `scripts/publish-order.py --check`
verifies that every crate declares its tier consistently (`publish = true` or
`publish = false`) and that the dependency graph has no cycles.

- **Tier 1 — publish now.** These crates are produced by
  `scripts/publish-order.py` and are published to crates.io in topological
  dependency order. cargo verifies each crate's dependencies against the
  registry at publish time, so every dependency must be live before the
  dependent is published.
- **Tier 2 — held/experimental.** These crates carry `publish = false` in their
  `Cargo.toml`. They are built and tested with the workspace but are not
  published until they graduate to Tier 1.

The publishable crates are:

| Crate | Status |
|:------|:-------|
| `opc-proto-pfcp` | publishable |

The current held crates and their graduation requirements are:

| Crate | Status | Graduation requirement |
|:------|:-------|:-----------------------|
| `opc-session-net` | experimental | A stable wire-format contract with a documented compatibility policy and soak evidence across at least one minor version bump. See `crates/opc-session-net/README.md`. |
| `opc-key-vault` | experimental | A production-readiness review covering Vault policy scoping, secret-zero handling, lease rotation, and an integration test against a real or containerized Vault Transit instance. |
| `opc-proto-nas` | experimental | Structured parsing of the remaining 5GMM and 5GSM message bodies listed as out-of-scope in `crates/opc-proto-nas/CONFORMANCE.md`, with spec-byte fixtures for each message. |
| `opc-proto-ngap` | experimental | A working canonical (typed) APER encoder path, verified by external fixtures for `NGSetupResponse` and `NGSetupFailure`, after the upstream `rasn` APER encoder misalignment is resolved or replaced. See `crates/opc-proto-ngap/CONFORMANCE.md`. |
| `opc-proto-gtpv2c` | experimental S2b subset | Expanded S2b procedure and IE coverage beyond the current typed subset, with mandatory-IE validation and spec-authored byte fixtures for every newly claimed GTPv2-C message/IE. See `crates/opc-proto-gtpv2c/CONFORMANCE.md`. |
| `opc-api-nnrf` | experimental | Client/server stub generation and expanded OpenAPI operation coverage, plus generator stability across regenerated `types.rs` from the same pinned 3GPP YAML. See `crates/opc-api-nnrf/CONFORMANCE.md`. |

To change a crate's tier, update `publish` in its `Cargo.toml` and move its row
from the held table to the publishable list; the next release section in
`CHANGELOG.md` must note the graduation.

### Publishing a release

```bash
python3 scripts/publish-order.py            # prints the cargo publish sequence
python3 scripts/publish-order.py --check    # CI gate: graph acyclic, version keys present
```

Before tagging a release: run the full validation gates above, update
`CHANGELOG.md` (move `[Unreleased]` into a version heading), and publish in
the printed order, waiting for each crate to be live before the next.
