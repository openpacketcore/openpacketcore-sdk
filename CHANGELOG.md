# Changelog

All notable changes to the OpenPacketCore SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `opc-session-store`: `probe_durable_readiness` and stable readiness report
  types for fresh, deadline- and log-work-bounded quorum evidence. Reports
  distinguish `Ready`, `NoQuorum`, `TopologyInvalid`, and `RecoveryRequired`;
  expose configured, freshly reachable, agreeing, and required voter counts
  plus the majority-visible prefix; and use typed, redaction-safe replica
  failure classes instead of raw errors. Capability declarations and
  `SessionStorePlatformProfile::Quorum` remain admission evidence only.
- `opc-session-store`: immutable replica descriptors and
  `ValidatedQuorumTopology` admission with distinct logical ID, canonical
  endpoint, expected TLS identity, failure domain, backing identity, and exact
  local-self selection. An explicit lab singleton reports `single-replica`,
  never quorum HA.
- `opc-session-store`/`opc-session-net`: redaction-safe authenticated peer
  bindings connect each remote adapter to the local and remote descriptor
  fingerprints, exact TLS identity, configured member count, and one immutable
  cluster/configuration scope during topology admission.
- `opc-sa-mirror` (RFC 015): experimental live SA keymat mirroring for
  near-hitless IPsec failover in which keys never persist — producer/sink/
  takeover ports, an in-memory standby holder with epoch anti-rollback and
  fail-closed capacity, an mTLS-only keymat transport with zeroizing frame
  buffers, and takeover output pre-validated as
  `SameSpiResume { key_source: LiveMirrored }` for the fenced re-pin.
- `opc-proto-ikev2`: a seedable responder Message-ID replay window, the full
  RFC 7296 error-notify registry, public nonce encoding, and stricter
  CREATE_CHILD_SA rekey proposal/KE validation.
- `opc-ipsec-xfrm`: non-zero request IDs and wildcard-SPI policy templates so
  old and replacement Child SAs can overlap under one stable policy contract.
- `opc-ipsec-lb`: clone-shared tagged-SPI reservations; allocation and rekey
  now skip SPIs restored by another session owner.
- `opc-proto-gtpv2c`: a bounded TS 24.008 PCO container codec for P-CSCF and
  DNS address requests/responses, including repeated response containers and
  accepted-session PCO access.
- `opc-dataplane-testkit`: a bounded multi-session GTP-U reflector keyed by
  inbound local TEID, with idempotent registration and conflict detection.
- `opc-ipsec-lb`: `SessionStoreOwnershipFencer`, an ownership
  promotion adapter that acquires the session-store lease, commits a
  generation-guarded owner change, and projects the committed store fence into
  the re-pin grant; production HA wiring requires durable majority authority,
  which the current session quorum prototype does not establish before #127.
- RFC 014 and `opc-mgmt-command`: the model-driven interactive operational
  console contract plus a transport-neutral, bounded command catalog with
  schema-validated reads, subscriptions, allowlisted actions, presentation
  metadata, and deterministic registry freeze.
- `opc-nacm`/`opc-nacm-config`/`opc-mgmt-authz`/`opc-persist`/
  `opc-mgmt-principal`: RFC 8341-style NACM rule-lists scoped to signed
  principal groups, principal-aware policy selection, a typed `/nacm` datastore
  model with SPIFFE group selectors, encrypted persistence round-trip support
  for rule-lists, and a signed-grant source boundary for populating
  `TrustedPrincipal.groups`.
- `opc-route-steering` and `opc-linux-route-sys`: experimental safe/mock/Linux
  route and rule steering backend with rtnetlink `RTM_NEWROUTE/DELROUTE` and
  `RTM_NEWRULE/DELRULE` support, redaction-safe errors, and probe coverage.
- `opc-ipsec-xfrm`: `query_sa` plus `SaState`/`SaReplayState` for replay and
  sequence-counter continuity, including Linux `XFRM_MSG_GETSA` decode and
  legacy/ESN replay restore attrs on SA install/rekey.
- `opc-gtpu-dataplane`: `resolve_device(name)` to inspect/adopt an existing
  Linux `gtp` netdevice by name without changing exclusive create behavior.
- `opc-key`: `KeyPurpose::IpsecSa` for sealed IPsec SA traffic-key records.
- `opc-proto-diameter` (experimental): RFC 6733 header/AVP framing, dictionary
  metadata, feature-gated base peer procedures (CER/CEA, DWR/DWA, DPR/DPA),
  registered fuzz targets, and initial Rf/SWm 3GPP application dictionaries;
  consumed as a direct protocol dependency rather than through the `opc-sdk`
  default facade/prelude.
- `opc-proto-gtpv2c` (experimental): S2b typed subset, consumed as a direct
  protocol dependency rather than through the `opc-sdk` default facade/prelude.
- `opc-proto-ikev2`: SDK helpers for IKEv2 SA lifecycle handling, including
  Delete payload encoding, `REKEY_SA` Child-SA rekey payload assembly,
  initiator Message-ID window tracking, and protected INFORMATIONAL coverage.
- `opc-proto-ikev2`: `Ikev2SaInitKeyMaterial::from_established_keys` for
  rebuilding established IKE SA key material from sealed `SK_*` bytes, plus a
  monotonic AES-GCM explicit-IV counter for HA restore without outbound nonce
  reuse.
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
- **BREAKING — `opc-session-store`:** the deprecated raw-vector
  `QuorumSessionStore::new` remains source-compatible but is now deliberately
  non-operational: it advertises `unknown`, masks capabilities, and rejects
  operations. Migrate HA callers through `QuorumTopologyConfig` and
  `ValidatedQuorumTopology`; migrate one-replica tests/labs through
  `try_new_lab_singleton`. AMF-lite and the session testkit now require an
  explicit validated local member and preserve topology while wrapping
  backends. External backend adapters used as votes must return
  `Some(BackendInstanceIdentity)`; forwarding wrappers must delegate it, and
  the default `None` fails topology admission.
- **BREAKING — `opc-session-net`:** the wire contract is now v3 for remote
  restore scans and authenticated replica identity. Production constructors
  accept opaque authenticated TLS configs plus bindings derived from one
  immutable manifest; the manifest hashes the cluster ID, explicit generation,
  and complete descriptor set. The exact v3 ALPN and handshake have no v2
  fallback, so all clients and servers require a coordinated upgrade and mixed
  v2/v3 rolling upgrades are unsupported. Public `Request`/`Response` enums
  gain handshake and restore-scan variants, while `StoreError` gains
  restore-scan, `InvalidReplicationSequence`, and `InvalidSessionTtl` variants,
  and `LeaseError` gains `InvalidSessionTtl`; external exhaustive matches must
  add arms for them. The new validation errors are serialized on v3 only in
  response to malformed replication metadata or oversized TTLs. Valid v3
  traffic is unchanged, but older v3 peers cannot decode a newly returned
  variant and must be upgraded in the coordinated fleet rollout.
- Documentation and package metadata now distinguish scoped implementation
  evidence, Cargo publication eligibility, and production maturity. Historical
  status snapshots, release-evidence primitives, and conditional
  session/protocol profiles no longer imply current production approval.
- **BREAKING — `opc-ipsec-xfrm`:** XFRM SA requests, policy templates, and
  decoded SA state now carry an optional `XfrmRequestId`; callers using public
  struct literals must initialize the new field.
- **BREAKING — `opc-ipsec-lb`:** same-SPI failover callers must migrate
  `AntiReplayResume` struct literals to either `ExactWindowRestore` or
  `BoundedReopening`, rename the checkpoint field to
  `checkpointed_send_iv_next`, and supply protocol-typed
  `send_iv_forward_jump` evidence. ESP ESN counter-mode evidence must include
  the caller-attested maximum peer receive-sequence lag; IKE IV64 evidence is
  unchanged. Custom `OwnershipFencer` implementations must support exact
  retry-proof validation and read-only committed-grant recovery. Re-pin
  requests now carry a deployment-unique transition ID and the exact
  predecessor fence; custom `OwnershipSource` implementations must return an
  authoritative SA owner/fence snapshot. `RePinCoordinator` now also requires
  an `OwnershipSource` and returns `RePinError`. Its recovery partial is
  intentionally single-use and no longer `Clone`; retain and replay the
  original request after cancellation, or pass a returned partial to
  `RePinCoordinator::retry`. Identical steering installs and re-pin audit
  events are now required to be idempotent so ambiguous acknowledgements
  converge without duplicate side effects.
- **BREAKING — `opc-ipsec-lb`:** session-store ownership records must use the
  exact resolver key, `AuthoritativeSession` class and `ipsec-lb-ownership`
  state/key types, a non-zero fence, no expiry, a valid `OwnerId`, and a
  plaintext payload. Birth/pre-transition records use an empty payload;
  promoted records carry the SDK's versioned transition ID and request
  fingerprint metadata. Existing TTL-bearing records and records with any
  other payload shape must be migrated before adopting the stricter
  source/fencer boundary.
- `opc-proto-pfcp` changed Cargo publication eligibility to `publish = true`.
  Publication eligibility is not a production-maturity graduation; its
  `Production Profile v1` name remains a compatibility identifier for a
  conditional codec candidate.

### Security
- `opc-session-net`: bind every production connection's live certificate
  SPIFFE URI to the claimed stable `ReplicaId`, expected opposite replica,
  cluster, and complete-manifest configuration ID before backend dispatch; the
  client verifies its fresh challenge is echoed by the server. DNS/FQDN/IP
  aliases and resolver overrides remain routing
  only. Wrong, ambiguous, malformed, cross-cluster, and stale-configuration
  identities fail closed, while raw Rustls configs can no longer enter the
  production session client/server constructors. Session caches, tickets,
  resumption, early data, and 0-RTT are disabled so reconnects revalidate live
  SVIDs instead of cached certificates. This closes #125 identity
  binding only; it does not provide consensus, durable commit authority, or
  fork recovery. It also does not yet qualify seamless certificate/trust-bundle
  rotation without service interruption; long-lived connection retirement,
  trust overlap/revocation, reconnect storms, and maximum authentication age
  remain distributed production evidence in #143. Session TTL is unrelated to
  certificate or trust lifetime.
- `opc-ipsec-lb`: require an RFC 6311-style outbound IV forward-jump for both
  persisted and live-mirrored same-SPI failover state, with protocol-matched
  64-bit counter evidence, explicit ESP peer receive-lag bounds, checked
  RFC 4303 ESN reconstruction arithmetic, non-zero resumed SA identifiers,
  exact restored-counter validation, and SA-to-steering-key binding before
  ownership is mutated.
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
- `opc-session-store`/`opc-session-net`/`opc-session-cache`/
  `opc-session-testkit`: all public `Duration` inputs used for session refresh
  and lease TTLs now use `MAX_SESSION_TTL` (exactly 365 days) and exact checked
  deadline arithmetic.
  Zero remains valid as immediate expiry and the exact maximum is accepted;
  larger values return redaction-safe `StoreError::InvalidSessionTtl` or
  `LeaseError::InvalidSessionTtl` before direct, batch, nested replication,
  wrapper, cache, quorum, Fake/SQLite, database, log, watch, or
  cryptographic-provider effects. Clients reject before resolution/dialing;
  authenticated servers reject after receiving the request but before backend
  dispatch and can keep the connection usable. This closes #137's
  panic/input-safety boundary only, not the durable consensus or production-HA
  work in #127/#143.
  Before upgrading persisted state, audit legacy replication logs for
  TTL-bearing entries above 365 days: they now fail closed during
  replay/rebuild and are not silently clamped or rewritten. Cross-field
  replication validation admits at most one microsecond of positive deadline
  drift solely for legacy `seconds_f64` rounding; new deadlines remain exact,
  the TTL maximum is unchanged, and larger mismatches fail closed.
  Caller-authored absolute record expiry remains #148; recursively protecting
  CAS payloads below multiple replicated-batch levels remains #147.
- `opc-session-store`/`opc-session-net`/`opc-session-cache`: replication-log
  entries now reject sequence zero with the typed, redaction-safe
  `StoreError::InvalidReplicationSequence` before quorum assessment, state
  mutation, cryptographic provider work, database access, cache invalidation,
  or network I/O. Rebuild sequence prefixes are fully validated before
  replacement; sequence increments are checked; SQLite rejects signed-range
  overflow, invalid positions when read, and row/payload disagreement; and
  authenticated servers return the typed wire error without dropping the
  connection. Direct,
  wrapper, cache, SQLite-corruption, quorum, and real-mTLS regressions cover
  zero, one, exact and forged duplicates, gaps, and `u64::MAX`. This closes the
  malformed-sequence boundary tracked by #138; it does not provide the durable
  sequence/commit authority still required by #127.
- `opc-runtime`: wildcard-bound UDP listeners can now pair
  `recv_from_with_destination` with `send_to_from` so Linux/Android replies use
  the exact concrete destination address observed on receive as their source.
  The bounded packet-info send rejects invalid family, port, source-address,
  and payload selections; platforms without ancillary source selection fail
  explicitly unless a concrete bind already guarantees the requested source.
  This supplies the SDK primitive tracked by #141; each consuming CNF must
  still thread the observed destination through every reply path and prove the
  peer observes its floating VIP as the source.
- `opc-session-store`/`opc-amf-lite`: durable readiness no longer succeeds from
  a bound server or cached capabilities while real quorum operations fail.
  Probes and operations use one store-level policy and the same fresh
  fail-closed majority assessment; adaptive bounded paging keeps log evidence
  usable when the aggregate log exceeds one wire frame;
  strict shorter prefixes are caught up by append only, while conflicts and
  longer minority tails return `RecoveryRequired` without destructive rebuild.
  AMF-lite now keeps traffic readiness behind a continuously supervised
  session-store gate, and low-cardinality metrics expose probe outcomes,
  configured/freshly-reachable/agreeing/required counts, the majority-visible
  prefix, and bounded failure reasons. This closes #124 only; durable authority
  and operator-safe fork recovery (#127–#129), majority-authoritative restore
  (#133), and wire/model hardening (#134/#135) remain production blockers.
  Checked TTL and replication-sequence rejection are closed above under
  #137/#138; production qualification remains #143.
- `opc-session-store`: quorum construction now rejects empty/undersized/even HA
  membership, missing or ambiguous self, duplicate logical IDs, canonical
  endpoints, declared TLS identities, failure domains, backing identities, and
  duplicate process-local adapter instances before I/O. The denominator is
  immutable validated membership and result accounting is keyed by `ReplicaId`,
  so one conforming SDK backend instance cannot be wrapped into multiple votes.
  Declared backing identity and authenticated peer binding remain separate
  requirements. A real
  mTLS SQLite regression proves that bare logical self is independent from FQDN
  endpoints. This closes #123 configured-topology admission only. Fresh
  durable readiness was scoped separately to #124 and is described above;
  #127–#129 and #133–#135 remain production blockers; #137/#138 input bounds
  are closed above and the full qualification remains #143.
- `opc-session-net`: remote backends and replication servers now carry
  validated cursor-paged restore scans, shorten multi-record pages to the
  effective client/server frame limit, and return a typed error when one
  record cannot fit. This implements the transport parity tracked by #126; it
  does not implement bounded majority-authoritative restore (#133), fixed-width
  wire stabilization (#134), invariant-safe model decoding (#135), or session
  HA qualification (#127–#129).
- `opc-persist`: standalone default-feature test builds no longer depend on
  fault-injection symbols that exist only with `dangerous-test-hooks`; CI now
  compiles the default package contract before workspace all-feature unification
  can mask it.
- `opc-proto-diameter`: the SWm DEA parse now matches vendor-specific AVPs by
  (vendor-id, code) instead of routing every vendor AVP to the unknown-AVP
  rejection path, so a conformant DEA carrying mandatory 3GPP subscription
  AVPs (TS 29.273) no longer fails to parse; genuinely unknown mandatory AVPs
  remain fail-closed. The DEA additionally gains a typed, redaction-safe
  decode/encode surface for `Service-Selection` (RFC 5778) and
  `APN-Configuration` (TS 29.272 §7.3.35) with `Context-Identifier`,
  `PDN-Type`, `EPS-Subscribed-QoS-Profile`, and `AMBR` children.
- `opc-proto-gtpv2c`: S2b F-TEIDs now use the standardized ePDG/PGW data-plane
  interface type 31; the control-plane constants remain 30 and 32.
- `opc-ipsec-xfrm`: XFRM policy templates now encode all-ones algorithm
  masks (`aalgos`, `ealgos`, `calgos`) instead of zero masks, so installed
  policies can be satisfied by negotiated ESP SAs instead of dropping inbound
  packets with `XfrmInTmplMismatch`.
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
