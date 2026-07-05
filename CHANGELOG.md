# Changelog

All notable changes to the OpenPacketCore SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `opc-proto-diameter` (experimental): RFC 6733 header/AVP framing, dictionary
  metadata, feature-gated base peer procedures (CER/CEA, DWR/DWA, DPR/DPA),
  registered fuzz targets, and initial Rf/SWm 3GPP application dictionaries;
  consumed as a direct protocol dependency rather than through the `opc-sdk`
  default facade/prelude.
- `opc-proto-gtpv2c` (experimental): S2b typed subset, consumed as a direct
  protocol dependency rather than through the `opc-sdk` default facade/prelude.
- `opc-proto-pfcp`: typed IE coverage for the Session Modification lifecycle
  (Update PDR/FAR/URR/QER, Update Forwarding Parameters, Remove PDR/FAR/URR/QER)
  and the Session Report / usage-reporting flow (Report Type, Measurement
  Method, Reporting Triggers, Volume/Time Threshold, Volume/Time Quota,
  Monitoring Time, Offending IE, Usage Report Trigger, Volume Measurement,
  Duration Measurement, UR-SEQN, and grouped Usage Report).
- `opc-proto-pfcp`: message builders for Session Modification Request, Session
  Report Request, and Session Report Response.
- `examples/smf-reference`: end-to-end N4 exercise that has the SMF send a
  typed Session Modification Request (Update FAR + Remove PDR) and the fake UPF
  send a typed Session Report Request (Usage Report with Report Type and
  volume/duration measurements), with field and wire-byte assertions.
- `opc-mgmt-limits`: `MgmtLimits::min_sample_interval` (default 100 ms), the
  server-side floor for gNMI SAMPLE `sample_interval` and `heartbeat_interval`.
- `operator-sdk-go`: `bridge.ErrorKind` implements `fmt.Stringer`, so wrapped
  bridge errors log a named kind instead of a bare integer.
- CI: Go race-detector and golangci-lint gates, a generated-code drift check
  for the NGAP/NNRF bindings, an `opc-sdk` depth-2 feature-powerset check, a
  pinned checksum-verified gitleaks secret scan, a PR smoke-fuzz lane
  (60 s/target) alongside the scheduled run raised to 600 s/target, and
  committed fuzz corpora for the GTP-U, NAS, Diameter, and IKEv2 targets.

### Changed
- `opc-proto-pfcp` graduated from experimental to publishable
  (`publish = true`); moved from the held-experimental tier to the publishable
  tier in `CONTRIBUTING.md`.

### Security
- `opc-sbi`: bind the validated JWT-SVID to the mTLS peer identity. The
  validator now rejects a token whose subject does not match the transport
  peer (`TokenBindingMismatch`) and, in production, a request that carries no
  peer identity (`MissingPeerBinding`). Previously the authorized identity was
  derived solely from the token's `sub`, so a valid token obtained by another
  workload could be replayed over its own mTLS channel and accepted as the
  token's subject (confused-deputy / token replay).
- `opc-sbi`: enforce the OAuth2 scope against the requested service. A token is
  now denied when it lacks the scope for the SBI service it invokes, so a token
  granted only `nnrf-disc` can no longer call `nnrf-nfm`.
- `opc-tls`: document that an unconstrained `PeerPolicy` authorizes any trusted
  peer (authentication without authorization) and add `is_unconstrained` so
  configuration layers can fail closed.
- `opc-evidence`: bind embedded bundle blobs (SBOM, VEX, conformance report,
  provenance, ...) to the bundle signature; they could previously be swapped
  without invalidating it.
- `opc-node-resources`: run the structural BPF checks (program type, attach
  point, capability bound) in every environment, gating only the strict
  signing/digest provenance on Production.
- `opc-privacy`/`opc-data-governance`: enforce an absolute singleton-cohort
  floor even when k-anonymity enforcement is disabled, and block the
  destructive `Anonymize` disposal action under a legal hold.
- `opc-session-net`: bound server-side frame reads with a configurable idle
  timeout so a stalled peer is reaped instead of exhausting connection slots
  (slowloris).
- `opc-gnmi-server`: Subscribe rejects SAMPLE `sample_interval` and
  `heartbeat_interval` below `MgmtLimits::min_sample_interval`; previously any
  nonzero interval was accepted, so a single 1 ns subscription drove the whole
  stream's tick (authenticated-client CPU DoS).

### Fixed
- `opc-yanggen`: generated Rust artifacts now use fully prefix-qualified
  schema-node paths for every segment across schema registry metadata, gNMI,
  NETCONF, NACM, and audit-facing path attribution while preserving
  unambiguous relaxed lookup compatibility.
- `opc-persist`: a committed `MarkConfirmed`/`CreateRollbackPoint` whose target
  `tx_id` is absent on a node (compacted away, or restored from an older
  snapshot) no longer aborts the consensus apply transaction. Applying a
  committed entry is now a deterministic no-op in that case instead of freezing
  `applied_index` and wedging the node's state machine.
- `opc-persist`: the durability preflight no longer reports `same_filesystem`
  and `locking_compatible` as unconditionally true; they are derived from real
  checks (device-id comparison and the network-filesystem safety check).
- `opc-proto-ngap`: reject trailing bytes after a decoded NGAP PDU instead of
  silently discarding them and re-emitting them on encode.
- `opc-alarm`: the persist audit sink runs its append on a worker thread with
  its own runtime, decoupling fail-closed audit from the caller's runtime
  flavor and lifecycle, and maps a DB-path panic to a meaningful reason.
- `sdk-reference-operator`: a failed drain during deletion now retains the
  finalizer and requeues instead of removing it unconditionally; only a
  completed or timed-out drain releases it, so sessions are not cut.
- `opc-api-nnrf`: `PlmnId` and S-NSSAI are generated with TS 29.571 object-form
  serde (`{mcc,mnc}` / `{sst,sd}`) so the types interoperate with conformant
  NRF peers. The committed generated types now match the generator output
  (`NfProfile`, `NfService`, and `SubscriptionData` PLMN/S-NSSAI fields use the
  object-form wrappers), and CI regenerates both NNRF and NGAP bindings to
  fail on any future drift.
- `opc-config-bus`: the commit-confirmed rollback deadline is armed on the
  monotonic tokio clock instead of the wall clock, so an NTP step no longer
  stretches or shortens the safety-rollback window; the durable marker still
  records wall-clock time for restart re-arm.
- `sdk-reference-operator`: bridge and drain call errors now preserve the
  underlying cause chain (`errors.As`/`errors.Is` recover the typed bridge
  error) while keeping the CLI path out of messages, and child Deployment
  owner references set `BlockOwnerDeletion` so foreground cascade deletion
  waits on the child.

## [0.2.0] — 2026-06-12

### Added
- Behaviour-pinning tests for randomness usage in `opc-crypto`, `opc-sbi`, and
  `opc-persist` ahead of the rand 0.10 migration.
- JWT-SVID validation verdict tests in `opc-sbi` covering valid tokens, expiry,
  audience/issuer mismatch, future `nbf`, missing/unknown `kid`,
  HS256/RS256 key-confusion rejection, and the dev bypass path.
- An on-disk SQLite fixture database and compatibility test in `opc-persist`
  that guard the stored format across rusqlite version changes.
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
- Workspace dependency `rand` 0.8 → 0.10, with direct callers migrated to the
  new API. `opc-crypto` continues to source nonce entropy from the OS via
  `getrandom::SysRng`.
- `opc-sbi` dependency `jsonwebtoken` 9.3.1 → 10.4.0, using the `aws_lc_rs`
  backend with PEM support. No source changes were required because the JWT
  validation API remained compatible; the `aws_lc_rs` backend avoids the
  `rsa` crate and the RUSTSEC-2023-0071 advisory that the `rust_crypto`
  backend would pull in, keeping `cargo audit`/`cargo deny` clean without a
  standing exception. The cost is the `aws-lc-sys`/`cmake` build dependency,
  reconciled in ADR 0014 point 9; a future migration to `rust_crypto` is
  planned once `rsa` ships a constant-time release.
- crates.io publishing metadata (description, keywords, categories,
  documentation, readme) and per-crate READMEs for all publishable crates;
  intra-workspace path dependencies now carry `version` keys.
- Workspace publish tiering: six experimental crates (`opc-session-net`,
  `opc-key-vault`, `opc-proto-pfcp`, `opc-proto-nas`, `opc-proto-ngap`,
  `opc-api-nnrf`) are now marked `publish = false` and documented in
  `CONTRIBUTING.md` with per-crate graduation requirements.
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
- `examples/smf-reference/`: first standalone, outside-the-workspace
  reference consumer of the SDK — a deliberately bounded reference SMF
  proving runtime startup, NRF registration/heartbeat/deregistration via
  `opc-sbi`, real PFCP/N4 bytes over UDP via `opc-proto-pfcp`, and session
  state in `opc-session-store`. Includes a fake UPF end-to-end test over
  loopback UDP and its own CI job.
- `opc-proto-pfcp` typed IE layer: decode/encode for Cause, Node ID, F-SEID,
  F-TEID, PDR/FAR/QER/URR ID, Precedence, Apply Action, Source/Destination
  Interface, Network Instance, UE IP Address, Outer Header Creation/Removal,
  Recovery Time Stamp, QFI, Gate Status, MBR, and GBR; grouped-IE recursion
  (Create/Created PDR, PDI, Create FAR, Forwarding Parameters, Create QER,
  Update QER, Create URR) with configurable `max_depth` enforcement; unknown
  and vendor IEs preserved byte-exact via `TypedIe::Raw`. Conformance tests
  with hand-authored spec-byte fixtures citing TS 29.244 section numbers;
  negative tests for truncation, wrong length, and depth exceedance. Fuzz
  target extended with typed-IE decode loop.
- Diagnosed a `rasn` 0.28 APER encoder alignment bug that prevents
  `opc-proto-ngap` from re-encoding typed NGSetupRequest values; a
  self-contained repro has been prepared for an upstream issue. The
  affected re-encode path is documented in the crate's CONFORMANCE notes.
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
- `opc-proto-ngap` (experimental v0): NGAP (3GPP TS 38.413) codec built on
  `rasn` per ADR 0013 Option A. NGAP-PDU framing for all three outcome
  classes with outcome-aware dispatch, typed APER decoding of
  NGSetupRequest (field-level external `asn1c`/libngap fixture) and
  InitialUEMessage, and raw-preserving encode so decode->encode
  round-trips byte-exactly. NGSetupResponse/NGSetupFailure are surfaced
  raw until external fixtures exist for them, and typed (canonical)
  encoding is out of scope for v0 — see the crate's CONFORMANCE.md.
  Offline generator `scripts/generate-ngap.py` (Wireshark ASN.1 +
  `rasn-compiler`) and `make generate-ngap`; fuzz target `decode_ngap`
  with seed corpus and CI registration.
- `opc-sbi`: `NrfClient` now implements `NrfDeregNotifier` so consumers can
  wire a real NRF client directly into `NrfDrainHook` without a wrapper.
- `opc-session-store`: add `SessionStore<B>` facade that bundles a
  `SessionBackend` and `SessionLeaseManager` into one handle, constructible
  from any backend implementing both traits. `FakeSessionBackend` and
  `opc_session_net::RemoteSessionBackend` both slot in.
- `opc-proto-pfcp`: add `TypedIe::encode_value()` for value-only encoding and
  `InformationElement::from_typed()` to build raw IEs directly from typed IEs.
  The reference SMF response path now uses typed IEs end-to-end instead of
  hand-building raw value bytes.
- `opc-session-store`: add `OwnedSession` helper that bundles a key, lease, and
  background renewal task for single-owner records, with renewal failures
  surfaced through a `tokio::sync::watch` channel. The reference SMF ownership
  marker no longer uses a hand-rolled renewal loop.
- `opc-types`: add `from_static()` constructors for `TenantId`,
  `NetworkFunctionKind`/`NfKind`/`NfType`, and `opc_session_store::StateType`
  so deterministic literals no longer need `Result` plumbing.
- `opc-types`: add `Snssai::with_sd()` and `Snssai::without_sd()` with strict
  six-digit-hex SD validation and rustdoc examples.
- `opc-types` and `opc-sbi`: add typed constructors for standard NF kinds
  (`amf`, `smf`, `upf`, `nrf`, `ausf`, `udm`, `pcf`, `nssf`, `nef`, `smsf`)
  and a standard SBI service-name constants module so NRF profile building no
  longer relies on free strings.
- `opc-sbi`: add `NrfClient::with_default_client()` convenience constructor
  for plain-HTTP NRF clients.
- `opc-protocol`: confirm `EncodeError::code()` and `DecodeError::code()`
  accessors and re-export `EncodeErrorCode`/`DecodeErrorCode` from the crate
  root; no consumer changes required.
- `opc-api-nnrf` (experimental): expanded generated TS 29.510 types to cover
  the NRF NFManagement payloads used for registration, heartbeat, and
  subscription/notification exchanges: `SubscriptionData`, `NotificationData`,
  `NotifCondition`, `NotificationEventType`, and `ConditionEventType`.
  Added `tests/compat_sbi.rs` demonstrating that an `opc-sbi::nrf::NfProfile`
  serializes into the generated `opc_api_nnrf::NfProfile` at the serde value
  level after casing normalization.
- `opc-proto-nas` (experimental v1): IE-level decoding for 5GMM
  Registration Request (§8.2.6) and Registration Accept (§8.2.7), including
  structured mandatory fields, ngKSI, 5GS mobile identity reuse, and
  optional-IE iteration with raw preservation of unknown IEs. Added BCD
  unpacking for PLMN (MCC/MNC with 2- and 3-digit MNC), routing indicator,
  and IMEI/IMEISV with spec-byte fixtures for filler nibbles, odd digit
  counts, and MNC padding. Integration tests, extended fuzz target, and
  regenerated/added corpus seeds cover byte-exact round-trips.

### Changed
- `opc-session-net` (experimental): `RemoteSessionBackend` now keeps a single
  persistent TCP/TLS connection per backend instance (one in-flight request at
  a time) instead of opening a fresh connection per request. Lost connections
  are re-established with the existing backoff retry, still bounded by the
  per-call deadline. `ServerHandle::abort()` now also aborts in-flight
  connection handlers so tests can simulate server crashes. Added integration
  tests for transparent reconnect after restart and for surfacing a
  backend-unavailable error within deadline when a request is in flight during
  disconnect.

- ADR 0014 (dependency and toolchain policy) and ADR 0015 (protocol codec
  conformance policy); ADR 0013 amended with the outcome of the first NGAP
  codec attempt.

### Fixed
- MSRV raised from 1.81 to 1.88, the measured floor of the resolved
  dependency graph (transitive dependencies had silently drifted past the
  declared version, so the previous MSRV claim was untrue); the CI gate now
  compiles the full workspace on exactly the declared version.
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
- The consensus e2e harness deadlocked on Linux when reaping killed cluster
  nodes: teardown awaited a child's exit on a second tokio runtime, but
  Linux child-exit notifications (SIGCHLD) dispatch through the runtime
  that spawned the child, which was parked at that moment. Teardown now
  reaps synchronously with bounded `try_wait` polling; macOS was unaffected
  (kqueue process events) which is why the suites only hung in CI.

## [0.1.0] — 2026-06-09

### Added
- Initial public release of the OpenPacketCore SDK.
- Rust workspace with runtime chassis, protocol framework, config bus, session store, security substrate, alarm substrate, and testbed.
- Go reference operator demonstrating lifecycle management.

[Unreleased]: https://github.com/openpacketcore/openpacketcore-sdk/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/openpacketcore/openpacketcore-sdk/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/openpacketcore/openpacketcore-sdk/releases/tag/v0.1.0
