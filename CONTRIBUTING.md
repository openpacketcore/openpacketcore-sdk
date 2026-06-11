# Contributing to OpenPacketCore SDK

Thank you for your interest in contributing to the OpenPacketCore SDK. This document describes the development workflow, validation gates, and conventions we follow.

## Development setup

### Required toolchain

- **Rust** ≥ 1.81 (install via [rustup](https://rustup.rs/))
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
- [ ] No new dependencies without justification in the PR description (must be Apache-2.0/MIT/BSD-compatible and build on Rust 1.81).
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

Publishable crates must reach crates.io in topological dependency order —
cargo verifies each crate's dependencies against the registry at publish
time. The order is computed from the workspace metadata:

```bash
python3 scripts/publish-order.py            # prints the cargo publish sequence
python3 scripts/publish-order.py --check    # CI gate: graph acyclic, version keys present
```

Before tagging a release: run the full validation gates above, update
`CHANGELOG.md` (move `[Unreleased]` into a version heading), and publish in
the printed order, waiting for each crate to be live before the next.
