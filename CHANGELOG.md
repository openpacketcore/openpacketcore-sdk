# Changelog

All notable changes to the OpenPacketCore SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Community and governance files: `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`, `GOVERNANCE.md`, `MAINTAINERS.md`, `NOTICE`, and `.github/CODEOWNERS`.
- GitHub issue and pull-request templates.
- `CHANGELOG.md` tracking release changes.
- `opc-sdk` facade crate with feature-gated re-exports, a `prelude`, the
  `minimal_cnf` end-to-end example, and an integration smoke test.
- `docs/quickstart.md` — guided first build of a minimal CNF.
- `opc-key-vault` (experimental): HashiCorp Vault Transit `KeyProvider` adapter
  using the wrapped-data-key envelope pattern.
- `opc-session-net` (experimental): networked session replication transport
  (length-prefixed, version-handshaked wire protocol; mTLS via `opc-tls`;
  deadline-bounded remote backend client composing into `QuorumSessionStore`).
- `FileSvidSource` in `opc-identity`: file-based SPIFFE SVID loading with
  rotation polling and fail-closed handling, for cert-manager-mounted secrets.
- Rust↔Go contract versioning for `operator-lifecycle-cli` (`CONTRACT_VERSION`,
  `version` subcommand, `contractVersion` response envelopes) with matching
  validation and `ErrContractMismatch` in the Go reference operator bridge.
- CI hardening: MSRV (1.81) job, `cargo-deny` license/advisory gate with
  `deny.toml`, CycloneDX SBOM generation in releases, scheduled fuzz workflow,
  and a `RUSTDOCFLAGS="-D warnings"` docs gate.
- `docs/adr/0013-ngap-asn1-strategy.md` and `docs/design/openapi-codegen-plan.md`.

### Changed
- crates.io publishing metadata (description, keywords, categories,
  documentation, readme) and per-crate READMEs for all publishable crates;
  intra-workspace path dependencies now carry `version` keys.
- README claims corrected: the SDK is 5G-centric (GTP-U is the only EPC-shared
  component) and in-process quorum semantics are distinguished from the
  experimental networked replication in `opc-session-net`.
- `#![deny(missing_docs)]` adopted in `opc-types`, `opc-protocol`, and
  `opc-proto-gtpu`.
- `operator-sdk-go` Go module: `conditions`, `bridge`, `drain`, `workload`,
  `opmetrics`, and `testing` packages for CNF operator construction.
- Reference operator finalizer + drain orchestration (`lifecycle.openpacketcore.io/drain`)
  with 5-minute timeout and graceful shutdown via `opc-runtime` admin endpoint.
- `workload.RenderDeployment` with deterministic, golden-file-tested manifest
  synthesis for control-plane, AF_XDP fast path, and SR-IOV fast path profiles.
- RFC 009 §17 Prometheus metrics (`opc_operator_reconcile_total`,
  `opc_operator_reconcile_duration_seconds`, `opc_operator_drain_total`, etc.)
  registered on controller-runtime's registry; event-recorder wiring for phase
  transitions, drain outcomes, and contract skew.
- Helm chart `operators/helm/sdk-reference-operator/` (v0.1.0) with cert-manager
  and manual certificate modes, ServiceMonitor toggle, and workload-synthesis
  opt-in flag.
- `docs/building-a-cnf-operator.md` — downstream-team operator guide (313 lines).
- `opc-proto-pfcp` (experimental v0): PFCP header + IE TLV layer with raw
  preservation; Heartbeat Request/Response; fuzz target + seed corpus.
- mdbook docs site (`book.toml`, `docs/SUMMARY.md`, `docs/introduction.md`) with
  GitHub Pages deployment workflow.
- `opc-proto-nas` (experimental v0): NAS-5GS plain 5GMM/5GSM headers,
  security-protected envelope recognition (no crypto), 5GS mobile identity
  decoding (SUCI/5G-GUTI structured views), and message-type registries,
  with spec-byte fixtures, fuzz target, and CONFORMANCE scope.
- `scripts/publish-order.py`: topological crates.io publish order with a
  `--check` CI gate (graph acyclic, version keys, no publishable→internal
  dependencies); CONTRIBUTING gains a Releasing section.
- Rustdoc for the entire public API of `opc-runtime`, `opc-sbi`,
  `opc-config-bus`, `opc-session-store`, and `opc-alarm`, now enforced with
  `#![deny(missing_docs)]` across all eight core crates.
- `opc-proto-pfcp` typed IE layer: decode/encode for Cause, Node ID, F-SEID,
  F-TEID, PDR/FAR/QER/URR ID, Precedence, Apply Action, Source/Destination
  Interface, Network Instance, UE IP Address, Outer Header Creation/Removal,
  Recovery Time Stamp; grouped-IE recursion (Create/Created PDR, PDI, Create
  FAR, Forwarding Parameters, Create QER, Create URR) with configurable
  `max_depth` enforcement; unknown and vendor IEs preserved byte-exact via
  `TypedIe::Raw`. 54 conformance tests with hand-authored spec-byte fixtures
  citing TS 29.244 section numbers; negative tests for truncation, wrong
  length, and depth exceedance. Fuzz target extended with typed-IE decode loop.
- `opc-api-nnrf` (experimental): generated Rust types for 3GPP TS 29.510
  `NfProfile` and `NfService` from official OpenAPI YAML. Python generator
  `scripts/generate-api-nnrf.py` resolves `$refs`, maps primitives to Rust,
  and emits serde-friendly structs with extensible string enums
  (`NfType`, `NfStatus`, `NfServiceStatus`). `make generate-api` target
  produces deterministic output.
- `operator-sdk-go/rollout`: RFC 009 §12 rollout strategy policy evaluation.
  `AllowedStrategies` and `Evaluate` decide safe strategies from NF
  characteristics; `BuildDeploymentStrategy` synthesises Kubernetes
  `DeploymentStrategy` for rolling, partitioned, canary, blue-green, and
  manual strategies. Integrated into `workload.RenderDeployment`. Envtest
  coverage verifies strategy fields are persisted correctly on a real
  API server.

### Fixed
- `opc-proto-pfcp` wire format corrected to TS 29.244: octet-1 flag layout
  (S = bit 1, MP = bit 2, FO = bit 3, spare = bits 5–4 — previously scrambled),
  message priority encoded/decoded in the final header octet's high nibble
  (previously dropped on encode and always zero on decode), vendor-specific IE
  Length semantics per §8.1.1 (the field counts the 2-octet Enterprise ID;
  round-trip was previously broken), and the header Length field is now
  honored with trailing bytes returned to the caller. Verified by
  hand-authored spec-byte tests, byte-exact round-trip assertions, and a
  quickcheck property; corpus seeds regenerated; `BorrowDecode`/`OwnedDecode`/
  `Encode` trait implementations added; `opc-proto-pfcp` registered in the
  fuzz CI workflow (the committed fuzz target previously failed to compile).
- Reference-operator `sdkbridge` now threads the reconcile/webhook
  `context.Context` into the CLI bridge instead of `context.Background()`,
  so cancellation propagates to the subprocess.
- gofmt violations in three Go files fixed; gofmt check gates added to both
  Go CI jobs.
- Flaky test root causes fixed: the `opc-sdk-integration` observability
  tests raced each other on the process-global metrics registry (now
  serialized with a shared test mutex; was failing ~1 in 4 runs), and the
  `opc-persist` split-brain e2e post-heal poll window was widened to a
  bound that only genuine convergence failures can trip.
- `opc-testbed` could not be published: it depends on `opc-schema-validate`,
  which was marked `publish = false`; the dependency crate is now
  publishable (caught by the new publish-order graph gate).

## [0.1.0] — 2026-06-09

### Added
- Initial public release of the OpenPacketCore SDK.
- Rust workspace with runtime chassis, protocol framework, config bus, session store, security substrate, alarm substrate, and testbed.
- Go reference operator demonstrating lifecycle management.

[0.1.0]: https://github.com/openpacketcore/openpacketcore-sdk/releases/tag/v0.1.0
