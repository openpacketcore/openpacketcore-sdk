# Operator Readiness Notes

This note is the operator-facing handoff for the foundation hardening pass
`T-9be95f92` on May 30, 2026, updated on June 6, 2026 for the follow-on
session-store, runtime drain, and ConfigBus authorization seams, and on June 28,
2026 for the final EPC/untrusted-access SDK hardening pass `T-8c57ecee`, with a
July 11, 2026 addendum for checked session-TTL admission and upgrade handling. It
summarizes what the current SDK foundation can support, what was validated, and
what must not be claimed as implemented, since the Go operator remains a
reference-only harness and production-grade controllers are the responsibility
of downstream CNF teams.
Durable architecture decisions for the completed hardening work are recorded in
[`docs/adr/`](adr/).

The task closures below are historical, scope-specific records. They are not a
current production-profile approval or a signed release attestation.

## Historical final validation scope

The final pass ran after these hardening seams closed:

- `T-a2ed9b0f` — shared `opc-crypto`/`opc-key` envelope helpers are wired into
  config-bus persistence and session-store persistence.
- `T-01342432` — the shared `opc-alarm` manager is wired into runtime fatal-task
  failures and config-bus commit/startup failure paths.
- `T-099afa77` — `opc-runtime` has SIGTERM-triggered graceful shutdown and an
  NRF deregistration drain-hook extension point.
- **ConfigBus Authorization Seam** — `opc-config-bus` now enforces first-class
  authorization via the `ConfigAuthorizer` trait at the admission boundary.
  Production-facing constructors require an explicit authorizer; allow-all
  construction is limited to clearly named dev/test helpers.
- **Session Store Semantics** — session TTL expiry, backend profile validation,
  injectable clocks, and handover transition helpers are implemented and covered
  for fake and SQLite-backed paths.
- **Runtime Drain Visibility** — drain hook timeouts and returned hook errors
  raise drain-incomplete alarms, and production AMF/SMF/UPF profiles require
  the NRF drain hook unless explicitly changed by carrier integration.
- `T-bdfee7cb` — the remaining cross-epic seam bucket is resolved or recorded as
  an explicit SDK/profile boundary in the status matrix.

Validation commands for this pass:

```text
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo test --workspace --all-features
```

All five commands passed for the June 2026 cleanup baseline.

### Final hardening validation status — `T-8c57ecee`

The final EPC/untrusted-access pass re-ran the core Rust hygiene gates in the
worker pane. The following gates passed:

- `cargo fmt --all --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- `cargo +1.88 check --workspace --all-targets --all-features`
- `cargo audit --no-fetch`
- `cargo deny check bans` / `licenses` / `sources`
- `cargo test --workspace --exclude opc-persist --all-features -- --test-threads=4`
- `cargo test -p opc-persist --all-features -- --test-threads=1`
- `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features`
- Kustomize/Helm rendering checks for the reference operator

Final validation for this historical snapshot was **not complete**: its
`cargo-deny` advisories gate was environment-limited and supervisor-waived.
Evidence source: the supervisor decision recorded for `T-8c57ecee`. Current CI
includes `cargo-deny` advisories, bans, licenses, and sources checks; every
candidate must rely on its own current results. This historical waiver is not
current release evidence or production/carrier-acceptance approval.

Go operator verification was re-run on July 3, 2026 with Go 1.26.4 for both
`operators/sdk-reference-operator` and `operators/operator-sdk-go`: `gofmt -l`,
`go vet ./...`, `go test ./...`, `go test -race ./...`, and `govulncheck ./...`
passed. The reusable Go SDK downstream-import smoke also passed through the
local `go.work` fixture.

| Gate | Status | Evidence / limitation |
|:---|:---|:---|
| `cargo deny check advisories` | Deferred (environment-limited), supervisor-waived | The installed `cargo-deny` 0.17.0 cannot parse a CVSS 4.0 entry in the cached advisory database (`RUSTSEC-2026-0146`), so the advisories check fails before scanning the local lockfile. `cargo audit --no-fetch` of the same lockfile passes. |

At that snapshot the deferred gate still required a compatible
`cargo-deny`/advisory-db environment. It does not describe the status of a
current candidate.

## EPC/untrusted-access final hardening addendum

The final EPC/untrusted-access pass is recorded in
[`docs/refactoring/epdg-sdk-final-hardening-triage.md`](refactoring/epdg-sdk-final-hardening-triage.md)
and follows the ADR 0018 mechanism/policy boundary. Operators may consume the
new packet-core surfaces as reusable SDK mechanisms, but must not treat them as
a product ePDG, EPC core, or carrier-readiness claim.

| Surface | Operator-facing use | Boundary |
|:---|:---|:---|
| Experimental protocol crates | `opc-proto-gtpv2c`, `opc-proto-diameter`, and `opc-proto-ikev2` provide bounded codec scaffolds, typed Rf/SWm and IKE_AUTH helper subsets, RFC 7383 SKF structure checks, conformance notes, hostile-input checks, and fuzz targets that downstream product tests can call before entering simulator or operator policy paths. | The crates do not provide UDP peer lifecycle, realm routing, AAA/HSS/CDF behavior, IKE SA/EAP-AKA/Child SA policy, or carrier acceptance evidence. They are not default `opc-sdk` facade exports. |
| XFRM/IPsec backend | `opc-ipsec-xfrm` provides safe XFRM request models, a Linux backend, a deterministic mock backend, rollback-aware SA+policy composites, and an opt-in IKEv2 Child SA to XFRM request mapper. | Products still own key derivation, algorithm/profile choices, namespace and privilege rendering, live kernel rollout, traffic readiness, and Child SA lifecycle policy. |
| EPC/ePDG testbed simulators | `opc-testbed` exposes PGW S2b and Diameter peer simulator skeletons plus an ePDG SDK composition harness so downstream tests can bridge decoded protocol messages into deterministic SDK scenarios. | Raw protocol bytes must be decoded by protocol crates first. Product ePDG attach orchestration, APN/PLMN/realm policy, charging, LI, and deployment defaults remain downstream. |
| Packet-core evidence packs | `opc-evidence` validates experimental packet-core evidence schemas with schema-version drift guards and redaction checks for IP, IMSI/SUPI-style identifiers, realm/NAI markers, keys, SPIs, and paths. | Packet-core packs require explicit experimental marking and are evidence formatting/validation mechanisms only; carrier-readiness sign-off remains a downstream release decision. |
| Go operator helpers | `operators/operator-sdk-go` includes product-neutral helpers for runtime gates, UDP/SCTP ports, Multus/SR-IOV annotations, rollout/drain checks, and fake-client tests. | Product CRDs, Helm/RBAC values, Multus `NetworkAttachmentDefinition` objects, XFRM/IPsec privileges, readiness thresholds, and traffic-shift policy stay outside the SDK helper package. |

For downstream operator authors, the practical rule is unchanged: use the Rust
policy CLI and Go helper packages as auditable building blocks, then add
product-specific CRDs, deployment privileges, network attachments, integration
tests, and release evidence in the downstream CNF operator repository.

## HA hardening scope

The June 8 review closed the listed algorithmic and test-harness tasks, not
carrier HA qualification. `ConsensusConfigStore` remains a durable
config-consensus prototype. `QuorumSessionStore` provides in-process quorum
coordination; its production network path depends on the experimental
`opc-session-net` transport. Neither is a production-profile claim until its
documented graduation requirements and downstream distributed/soak gates pass.

### Session topology admission

Construct HA-shaped session stores only from `ValidatedQuorumTopology`. The SDK
rejects membership outside the odd 3-through-31 bound, missing/ambiguous local
self, duplicate logical IDs/endpoints/TLS identities/failure domains/backing
identities, and duplicate process-local adapter instances before server readiness. The quorum
denominator is the admitted configured membership, not current reachability.

`ValidatedQuorumTopology::try_new_lab_singleton` is an explicit lab path and
advertises `single-replica`. The deprecated raw-vector constructor advertises
`unknown` and is non-operational. Logical self must be configured explicitly;
do not derive it by shortening an FQDN or comparing endpoint strings.

For production network adapters, build one immutable
`SessionReplicationManifest` from the cluster ID, an operator-controlled
configuration generation, and the complete descriptor set. Derive all local
and remote bindings from that manifest. Topology admission verifies each
remote adapter's local/remote IDs, expected TLS identity, descriptor
fingerprints, configured member count, and shared configuration scope. A local
in-process backend may remain unbound.

This admission result is not a durable-ready signal. Capability declarations
and `SessionStorePlatformProfile::Quorum` are also admission evidence only. A
production operator must separately require fresh durable readiness before
traffic readiness.

### Session TTL admission and upgrade

The SDK now applies one public limit to `Duration`-based session refresh and
lease TTL inputs:
`MAX_SESSION_TTL`, exactly 365 days. Zero is accepted as immediate expiry and
the exact maximum is accepted. A larger duration returns the redaction-safe
`StoreError::InvalidSessionTtl` or `LeaseError::InvalidSessionTtl`. Deadline
calculation uses exact checked integer conversion and checked timestamp
addition; it does not use floating-point conversion or panic on an oversized
duration.
A zero-duration acquire may still consume a fence, credential, and log
position; use explicit release for revocation rather than zero TTL as rollback.

The rule is repeated across direct calls, nested batch and replication
operations, wrappers, quorum dispatch, Fake/SQLite backends, and session-net
client/server admission. Rejection occurs before lease/record/log/watch,
cryptographic-provider, database, or other application/backend effects. The
client rejects before resolution or dialing; the server necessarily receives
the request, then rejects before backend dispatch and may send the typed error
on the same connection. This closes an input-validation and
process-availability boundary only; it does not add durable commit authority,
consensus, fork recovery, or production HA.

Before rolling this change onto a store written by an older SDK, audit every
persisted replication-log operation that carries a TTL. Values above 365 days
now fail closed during replay or rebuild and are never silently clamped. Stop
the rollout and use an audited product recovery/migration procedure if such an
entry exists; do not truncate or rewrite presumed history ad hoc. Replicated
deadline validation accepts at most one microsecond above the exact
`entry.timestamp + ttl` for legacy `seconds_f64` rounding only. New deadlines
remain exact, this does not enlarge the 365-day bound, and larger mismatches
fail closed.

The two new public error variants also extend protocol-v3 serialized errors.
Update exhaustive matches and upgrade all session-net participants as one
coordinated same-v3 compatibility unit before relying on the typed response;
an older v3 decoder cannot consume a newly returned variant. Valid v3 traffic
is otherwise byte/shape compatible.

### Session durable readiness

`QuorumSessionStore::probe_durable_readiness` performs a fresh, bounded
point-in-time assessment without consulting cached capabilities. Require
`DurableReadinessState::Ready`; the other stable states are `NoQuorum`,
`TopologyInvalid`, and `RecoveryRequired`. The report includes
`configured_voters`, `fresh_reachable_voters`, `agreeing_voters`,
`required_quorum`, an optional `majority_visible_prefix_index`, and per-replica
typed observations.

Configure timeout and log-work limits once with
`with_durable_readiness_options`; probes and authoritative operations share
that exact policy. Log evidence is fetched in bounded adaptive pages rather
than requiring the complete log to fit one wire frame.

The bounded failure classes are `Transport`, `Authentication`, `Timeout`,
`Protocol`, `Backend`, `LogUnavailable`, `Divergent`, `RepairFailed`, and
`ProbeBudgetExceeded`.
Do not log raw peer errors or turn replica IDs/endpoints into metric labels.
The exported metrics intentionally use only fixed names and bounded reasons for
probe outcome, current readiness,
configured/freshly-reachable/agreeing/required voter counts, majority-visible
prefix, and bounded
timeout/authentication/transport/divergent/recovery-required failures.
The only labels on this readiness surface are bounded `status` values
(`success`/`failure`) and bounded `reason` values (`timeout`, `authentication`,
`transport`, `divergent`, and `recovery_required`); its gauges carry no identity
labels.

Readiness evidence can become stale immediately. AMF-lite therefore starts
with its session-store gate closed, probes immediately and continuously, and
keeps both the health gate and supervised-task readiness closed whenever the
fresh report is not `Ready`. Each authoritative store operation independently
repeats the same assessment. Downstream CNFs must apply the same continuous
traffic-readiness pattern rather than opening traffic permanently after one
successful startup probe.

Ownership publication is part of that gate, not a separate optimistic path.
Do not publish or renew shard/session ownership, claim a floating VIP, or
advertise service traffic until the report is `Ready`. On later quorum loss,
stop new ownership publication and traffic advertisement immediately and enter
the product's fenced relinquish/handoff workflow; a prior readiness report is
not an ownership lease.

### Tested HA algorithm and prototype features

1. **Persisted Ordered-Log Prototype**: Exercises replication of mutations (lease acquire, renew, release, compare-and-set, delete, TTL refresh, and batch operations) across replicas using a sequence-numbered log. Durable sequence/commit authority remains #127.
2. **Local Idempotency & Replay Checks**: Fixtures exercise duplicate handling by log position, generation, fence, and transaction identity without wall-clock last-writer-wins. Cross-partition authority remains conditional on #127/#128.
3. **Resume Cursors**: Exposes change-stream watches backed by the ordered log, allowing client streams to resume and catch up after disconnects.
4. **Stale Replica Recovery Heuristic**: The readiness/operation assessment may append a missing suffix only when a replica's complete log is a strict prefix of the majority-visible log. Conflicts and longer minority tails yield `RecoveryRequired` without truncation or destructive rebuild. This is still not commit-proven recovery; #127/#128 must prevent a later majority from omitting a previously acknowledged entry.
5. **Declared Feature Envelope**: `QuorumSessionStore` advertises `ordered_replication_log = true` and `watch = true`, while standalone SQLite reports `false`. These bits describe available methods, not fresh peer-quorum evidence or production qualification. Use `probe_durable_readiness` for the current point-in-time result.

### Session transport v3 rollout boundary

`opc-session-net` v3 carries cursor-paged remote restore scans and authenticated
replica identity. Production constructors accept only opaque authenticated TLS
configs. Both sides extract the canonical SPIFFE URI from the live peer
certificate and require an exact match with the manifest's claimed stable
`ReplicaId`, expected opposite replica, cluster, and configuration ID before
backend dispatch. The client verifies its fresh challenge is echoed by the
server. The configuration ID digests the cluster,
explicit generation, and complete descriptor set.
Session-net deliberately disables TLS resumption, session tickets, early data,
and 0-RTT; budget every reconnect as a full mutual-TLS handshake so the live
SVID is revalidated after rotation.

Full handshakes make renewed credentials observable, but they are not proof of
seamless rotation. A production CNF/operator profile must rotate certificates
and trust bundles without interrupting session service, including overlap of
old/new trust, revocation, retirement of long-lived connections, reconnect
storms, and a documented maximum authentication age. That distributed
qualification remains #143. `MAX_SESSION_TTL` controls session/lease state
only; it does not define certificate expiry, trust-bundle validity, or
authentication age.

A successful restore page may be shorter than requested to fit the effective
client/server frame limit; follow `next_cursor` until `complete`. A single
record that cannot fit returns `RestoreScanResponseTooLarge`.

The Hello handshake and ALPN require an exact version match. Treat v2-to-v3 as a
coordinated outage: drain session traffic and writers, stop every session-net
participant, upgrade them together, verify v3 authenticated handshakes and
empty/multi-page scans on each replica, then restore traffic. There is no
production v2 fallback; do not perform a mixed-version rolling upgrade.

DNS, FQDN, IP, and resolver aliases control only the dial address. They must
not be used to derive or rewrite the logical `ReplicaId` or expected SPIFFE
identity. Rotate a certificate only to another SVID carrying the same exact
manifest identity. A descriptor change produces a new configuration ID; bump
the generation for security-relevant configuration outside the descriptor set.
Either scope change requires another coordinated rollout.

This is not production HA qualification. Do not infer readiness from bind
success, static profiles, or cached capabilities; use the fresh bounded probe
and continuous gate. Do not use quorum restore as authority before
#127/#133, treat current divergence repair as authoritative before #128, or
auto-resolve a legacy fork before #129. Protocol v3 identity binding is not
consensus or fork recovery. Fixed-width wire DTOs and invariant-safe model
decoding remain #134/#135. Checked TTL and sequence boundaries now fail closed
under #137/#138. Watch handoff, nested protected-payload traversal, and
absolute-record-expiry admission remain #145/#147/#148; seamless
certificate/trust rotation and the remaining distributed production evidence
stay open in #143.

## Operator-facing SDK surfaces available now

| Surface | Current operator contract | Evidence |
|:---|:---|:---|
| Runtime profile and bootstrap | `RuntimeProfile` defaults to production mode. `BootstrapConfig::from_env` reads `NF_KIND`, `INSTANCE_ID`, `RUNTIME_MODE`, `ADMIN_BIND`, `LOG_LEVEL`, and `CONFIG_SOURCE`; `BootstrapConfig::apply_fail_closed` rejects production startup without an explicit config source. | `crates/opc-runtime/src/profile.rs`, `crates/opc-runtime/src/bootstrap.rs`, `docs/rfc/008-cnf-runtime-chassis.md` |
| Health and readiness model | The SDK provides the RFC 008 health model for `/livez`, `/readyz`, and `/startupz` semantics, along with gated debug/admin routes `/debug/runtime`, `/debug/tasks`, and `/debug/config-version`. The HTTP admin/probe/debug routes are fully authorized under token authorization in Production/Lab mode. | `crates/opc-runtime/src/health.rs`, `crates/opc-runtime/src/admin.rs`, `docs/implementation-status.md#known-gaps` (`GAP-008-002`) |
| Config authorization & apply example | `opc-config-bus` implements `ConfigAuthorizer` checking at the admission boundary, and the toy config integration registers a custom `NacmAuthorizer` hook to enforce NACM policy before validation, persistence, or subscriber notification. | `crates/opc-config-bus/src/lib.rs`, `crates/opc-config-fixture/tests/config_fixture_commit.rs` |
| Config persistence encryption and audit integrity | `EncryptingManagedDatastore` seals persisted config records with shared envelope helpers and AAD-bound tenant/schema/version metadata. Durable `SqliteBackend` opens require an explicit non-zero `AuditKey`, and stored audit chains are verified on load after sensitive audit values are redacted before storage. | `crates/opc-config-bus/src/lib.rs`, `crates/opc-config-bus/tests/encryption.rs`, `crates/opc-persist/src/backend.rs`, `crates/opc-persist/tests/persist.rs` |
| Alarm admin authorization & auditing | `opc-alarm` provides `NacmAlarmAuthorizer` and `PersistAlarmAuditSink` adapters to authorize alarm ack/suppress actions against NACM policy and an explicit operator-principal allowlist, then log audit events durably to the persistence SQLite database with automatic sensitive data redaction. | `crates/opc-alarm/src/nacm_adapter.rs`, `crates/opc-alarm/src/persist_adapter.rs`, `crates/opc-alarm/tests/adapters.rs` |
| Session persistence encryption | `EncryptingSessionBackend` wraps a durable SQLite backend (`SqliteSessionBackend`) or `FakeSessionBackend`. It seals session payloads, decrypts reads and CAS conflicts, preserves legacy migration markers, and fails closed on corrupt envelopes. | `crates/opc-session-store/src/backend.rs`, `crates/opc-session-store/src/sqlite.rs`, `crates/opc-session-store/tests/sqlite.rs` |
| Runtime alarms | `SharedAlarmManager` is used by runtime supervision and config-bus failure paths; toy NF integration uses the runtime-owned manager rather than separate toy glue. | `crates/opc-runtime/src/supervisor.rs`, `crates/opc-config-bus/src/lib.rs`, `crates/opc-sdk-integration/tests/toy_runtime.rs` |
| Graceful drain | `DrainHook` and `NrfDrainHook` provide the shared SIGTERM/NRF drain integration point. Hook timeouts and hook errors raise drain-incomplete alarms, and `NrfRuntimeBuilderExt` gives first NF adopters a one-call registration path. | `crates/opc-runtime/src/shutdown.rs`, `crates/opc-sbi/src/nrf/mod.rs`, `crates/opc-runtime/tests/graceful_shutdown.rs` |
| Evidence format | `opc-evidence` provides tested RFC 006 record, manifest, gap, SBOM/VEX, provenance, performance, bundle, and policy-evaluation library primitives. Embedded bundle blobs are signature-covered, but separately supplied `GateEvaluator` artifact arguments are not cross-checked against that verified bundle. Repository workflows do not yet invoke the evaluator or wire a production signer/verifier and complete artifact set. | `crates/opc-evidence/src/extract.rs`, `crates/opc-evidence/src/sbom.rs`, `crates/opc-evidence/src/vex.rs`, `crates/opc-evidence/src/provenance.rs`, `crates/opc-evidence/src/bundle.rs`, `crates/opc-evidence/src/performance.rs`, `crates/opc-evidence/src/policy.rs`, `crates/opc-evidence/tests/evidence_bundle.rs`, `crates/opc-evidence/tests/evidence_policy.rs`, `docs/implementation-status.md#known-gaps` (`GAP-006-*`) |
| Data governance and privacy | Provides support-bundle redaction API scrubbing SUPI, secrets, IPs, and paths (`opc-redaction`), declarative `RetentionPolicy` models with legal hold enforcement (`opc-data-governance`), classification-preserving export metadata validation (`opc-export`), k-anonymity validation and cohort binning (`opc-privacy`), and data governance evidence gates (`opc-evidence`). | `crates/opc-redaction/src/support_bundle.rs`, `crates/opc-data-governance/src/retention.rs`, `crates/opc-export/src/lib.rs`, `crates/opc-privacy/src/lib.rs`, `crates/opc-evidence/src/data_governance.rs`, `crates/opc-sdk-integration/tests/privacy_governance.rs` |


## Minimum configuration handoff for first NF adopters

A first CNF adopter should wire the shared foundation instead of inventing local
operator glue:

1. Build the binary around `opc_runtime::Builder` or `opc_runtime::run` with a
   production `RuntimeProfile` for real deployments.
2. Set `RUNTIME_MODE=production`, `NF_KIND`, `INSTANCE_ID`, and an explicit
   `CONFIG_SOURCE` (`/path/to/config`, `configmap`, `http://...`, or
   `https://...`) before production startup.
3. Keep `ADMIN_BIND` on a controlled interface and secure HTTP debug/admin/probe/debug
   routes `/metrics`, `/livez`, `/readyz`, `/startupz`, `/debug/runtime`, `/debug/tasks`, and `/debug/config-version` using an authorization token (`GAP-008-002`, fully closed).
4. Use `EncryptingManagedDatastore` for durable config records and
   `EncryptingSessionBackend` for durable session records. When opening a
   durable `SqliteBackend`, load a deployment-owned 32-byte audit HMAC key from
   secret management and pass it through `AuditKey::new` and
   `SqliteBackend::open_with_audit_key`; `SqliteBackend::open` is limited to
   ephemeral/test use unless the path is `:memory:`.
   For envelope encryption keys, use `KmsKeyProvider` with an mTLS TCP KMS
   endpoint or a local Unix-socket KMS agent; unauthenticated TCP KMS endpoints
   fail closed. `MemoryKeyProvider` remains a deterministic test/conformance
   adapter, not a production key source.
5. Reuse `SharedAlarmManager` from the runtime/config-bus path for NF-specific
   alarms when CNF crates land.
6. Register `DrainHook` implementations, including `NrfDrainHook` or
   `NrfRuntimeBuilderExt::with_nrf_drain_hook` where the NF registers with NRF,
   so SIGTERM drains are shared and testable. Production AMF/SMF/UPF profiles
   fail closed if the required NRF hook is missing.
7. Use `RuntimeProfile::conformance` only for deterministic tests and evidence
   generation; do not ship lab/conformance behavior as production policy.
8. **Install a production-profile `ConfigAuthorizer`**: Production NFs must
   install a valid authorizer (for example, enforcing NACM policies or specific
   security claims) via `ConfigBus::new`, `ConfigBus::with_queue_capacity`,
   `ConfigBus::new_with_alarm_manager`, `ConfigBus::restore_or_new`, or
   `ConfigBus::restore_or_new_with_alarm_manager`. The allow-all path is now
   exposed only through `*_dev_only` constructors and is **not production-ready**.
9. **Configure Alarm Administration Authorization and Auditing**: To protect administrative alarm operations (acknowledgement and suppression), NF integrations should wire a `NacmAlarmAuthorizer` and a `PersistAlarmAuditSink` when calling `acknowledge_with_policy` and `suppress_with_policy` on `AlarmManager`.
   - Construct `NacmAlarmAuthorizer` with `with_allowed_principals` after mapping the authenticated operator identity into stable principal strings. `new` starts with no admitted principals, so a path allow rule alone is not sufficient for alarm administration.
   - The `NacmAlarmAuthorizer` maps actions to stable paths (`/ietf-alarms:alarms/alarm-list/alarm/acknowledge-alarm` and `/ietf-alarms:alarms/alarm-list/alarm/suppress-alarm`), default-denies, and enforces default-deny security-critical overrides via path `/ietf-alarms:alarms/alarm-list/alarm/security-critical-suppression`.
   - The `PersistAlarmAuditSink` logs administrative alarm events durably to the persistence layer's `alarm_audit` SQLite table, using standard redaction (scrubbing 8+ digits and IP addresses) to prevent sensitive customer data leakage.

## HA Persistence & Replication Adapters

The SDK includes a config-store consensus hardening prototype (`ConsensusConfigStore` in crate `opc-persist`), an ordered-log quorum replicated session store (`QuorumSessionStore` in crate `opc-session-store`), and a session chaos simulation testkit (`opc-session-testkit`).

The standard SQLite-backed config and session store profiles (`SqliteBackend` and `SqliteSessionBackend`) are single-node only. They are acceptable only for development, conformance, lab, or explicitly accepted edge/single-replica deployments, and must not be used to claim carrier HA without a production consensus/replication layer.

- **Config Store Consensus Hardening**: `ConsensusConfigStore` provides durable membership, TCP RPC framing over real mTLS transport with SPIFFE identity verification bound to the configured workload profile and active membership, election/heartbeats, no-op commit safety, snapshot HMAC verification, controlled TCP server lifecycle (bounded concurrency/timeout/oneshot shutdown), membership-change guardrails, and consensus metrics dump hooks. Checked via the out-of-process multi-process campaigns, failovers, network partitioning, and pending commits surviving restarts.
- **Session Store Quorum Replication Prototype**: `QuorumSessionStore` exercises session leases and CAS mutations across a majority of replicas using an ordered log with watch/change-stream resume cursors, strict-prefix catch-up, and partial-write fail-closed fixtures. Durable authority and repair claims remain conditional on #127/#128.
- **Session Topology, Identity, and Readiness**: HA-shaped construction requires an immutable validated set of distinct declared votes and exactly one explicit local member. Protocol v3 derives authenticated peer bindings from one cluster/configuration manifest and requires the live certificate SPIFFE identity to match the stable `ReplicaId`; DNS aliases remain routing only. The lab singleton reports `single-replica`; raw unvalidated construction reports `unknown` and refuses operations. Topology, identity binding, and capabilities are admission evidence. `probe_durable_readiness` separately provides fresh bounded majority evidence.
- **Fault Coverage**: Reusable chaos test fixtures and tests cover split-brain, stale leader writes, replication lag, stale fences, restart/rejoin behavior, divergent read fail-closed behavior, clock skew, and multi-writer rejection. They also cover session-store durable rejoin/catch-up, strict-prefix append, ordered-log replay, duplicate delivery, partial-write fail-closed behavior, and no-destructive-repair evidence for an already-visible ambiguous tail. This is not proof of automatic fork reconciliation or failed-write resurrection safety before #127/#128.
- **SQLite Writer Envelope**: Each replica still serializes local durable writes through SQLite. `ConsensusConfigStore` and `QuorumSessionStore` provide the tested consensus and ordered-replication mechanisms described above; neither constitutes production HA qualification, and standalone SQLite is not HA.
- **Capability Envelope**: `SqliteSessionBackend` reports CAS, fencing, TTL, lease-expiry, and batch support without `watch` or `ordered_replication_log` support. `QuorumSessionStore` reports `watch = true` and `ordered_replication_log = true`, but those feature declarations remain static admission evidence. Use `validate_backend_for_profile` or `StateClass::required_profile()` before binding a backend, and use `probe_durable_readiness` plus continuous traffic gating for current quorum evidence.
- **Payload Bound**: The backend enforces a 1 MiB payload limit through `BackendCapabilities::max_value_bytes`; state types that need larger values require an explicit profile decision.
- **Storage Fault-Injection**: Reusable `FaultInjectingStore` and `FaultType` adapters under `opc-persist` allow injecting disk-full, fsync/write failure, corrupt database/WAL, failed rollback target load, failed rollback point creation, audit-chain corruption, and startup recovery fencing. These hooks are compiled only with the `dangerous-test-hooks` feature and must not be enabled in production profiles. They cover all RFC 001 §14.3 failures, asserting fail-closed config publication/notifications, redacting SQL internals/raw paths/secrets from client-visible errors, raising alarms, and updating metrics.

## Machine-Readable Compatibility Policy Contract

The SDK includes a compatibility-policy foundation under `operator-lifecycle`
and `operator-controller` for rules across operator version, SDK version, NF
kind/version, CRD API version, config/state schema version, features, runtime
mode, persistence profiles, and migration paths. Production use remains
conditional on boundary hardening, real rollback capability, bounded inputs and
deadlines, and downstream controller integration.

### Core Policies:
1. **Strict Serde Boundaries**: All compatibility structures use `#[serde(deny_unknown_fields)]` to reject malformed or unknown fields.
2. **Fail Closed**: Unknown versions, malformed versions, missing required fields, or NF kinds not declared by the loaded compatibility matrix fail closed immediately.
3. **Admission Enforcement**: Preflight admission webhooks reject incompatible CRD API versions, config/state schema versions, and unsupported operator/NF/version combinations. Rejects missing required capabilities (`ConsensusConfigBackend`, `QuorumSessionBackend`, `Kms`, `Spiffe`, `ResourceProfile`) when required by the policy.
4. **Config Apply Enforcement**: Block upgrades when the target NF/config/state version is unsupported. Block downgrades/rollbacks unless the policy explicitly permits rollback and the target is a confirmed history point. Block config apply while a required migration path is missing or unsafe.
5. **CRD Conversion Enforcement**: Reject conversions involving unsupported source/target CRD API versions, while preserving semantic fields, lifecycle status, and conditions.
6. **Migration Orchestration**: Validate migration plans against source-to-target allowed paths. Reject unsafe or high-risk steps unless explicitly allowed by the policy and rollback constraints are satisfied. Non-empty evidence IDs are strictly required and must be present in the admission compatibility evidence.
7. **Aggregated Status Visibility**: Propagate compatibility-blocked states in multi-cluster rollouts to prevent healthy clusters from masking failure.

## Platform Preflight Contract (GAP-011-003 through GAP-011-007)

The SDK provides a platform-preflight model and pure validation layer. It
compares supplied node capabilities with a CNF workload specification for
admission and rollout policy. `RuntimeMode::Production` selects fail-closed
validation rules; it is a configuration mode, not production-readiness or
deployment approval. In Lab mode, violations trigger degraded states or
warnings and may allow explicit fallback.

### Preflight Contract Elements:
1. **CPU & NUMA Layout (GAP-011-003)**:
   - Verifies that control-plane, signaling, and data-plane cores do not overlap.
   - Enforces exclusive core allocation for accelerated profiles (e.g., AF_XDP/SR-IOV).
   - Validates node topology manager and CPU manager policies (requires `static` CPU policy and `SingleNumaNode`/`Restricted` topology policy for fast paths).
   - Enforces NUMA alignment between pinned CPUs, memory pools, and network interfaces.
2. **Hugepage Allocation (GAP-011-003)**:
   - Validates that requested hugepages are present on the correct NUMA node and match the configured page size (e.g. 2Mi, 1Gi).
3. **NIC & CNI Attachment (GAP-011-003)**:
   - Verifies that interfaces specified in the network attachments exist on the node.
   - For AF_XDP, checks that the NIC supports the required XDP modes.
   - For SR-IOV, verifies that active virtual functions (VFs) are available.
4. **BPF Governance (GAP-011-004)**:
   - Restricts eBPF programs to digest-pinned artifacts and verifies trusted signatures.
   - Checks that program type and attach points conform strictly to the profile.
   - Restricts capability escalation: `CAP_SYS_ADMIN` is strictly forbidden in Production mode; only minimal capabilities (`CAP_BPF`, `CAP_NET_ADMIN`, `CAP_NET_RAW`) are permitted.
5. **Minimal Pod Security Exceptions (GAP-011-005)**:
   - Renders and checks minimal security profiles per workload.
   - Forbids broad `privileged` access, generic `CAP_SYS_ADMIN`, and unapproved `hostPath` mounts outside controlled bpffs/socket namespaces.
   - All exceptions must be linked to valid external evidence IDs.
6. **Data-Plane Readiness Integration (GAP-011-006)**:
   - Returns a structured `DataPlanePreflightReport` from the validation layer.
   - Integrated into `evaluate_admission` (admission webhook) and `evaluate_config_apply` (config rollout readiness) to block rollout if preflight checks fail.
7. **Lab Fallback Gating (GAP-011-007)**:
   - Fallback policies (e.g., generic XDP, veth networks, software packet path) are explicitly defined.
   - Production environment mode rejects all lab/dev fallback paths, ensuring they cannot be silently promoted.

## Runtime Resource Budget & Hardening Contract (GAP-008-003 and GAP-008-004)

The SDK exposes runtime-budget declarations, a Tokio-runtime construction
helper, and selected admission and supervisor checks in `opc-runtime`. These
mechanisms do not guarantee complete runtime stability or resource isolation.
In `RuntimeMode::Production`, bootstrap fails closed when required SDK budget
limits are absent or invalid; the mode name is not a maturity designation.

### Hardening & Resource Contracts:
1. **Explicit Budget Mandate (GAP-008-003)**:
   - Starting `opc-runtime` in `RuntimeMode::Production` requires an explicit, valid `ResourceBudget` configured in `profile.budget`.
   - If the budget is omitted or invalid (e.g. invalid task count bounds, memory size ranges, or open file descriptors), bootstrap via `Builder::build()` fails closed immediately.
2. **Tokio Runtime Configuration (GAP-008-003)**:
   - CNF binaries that let the SDK own Tokio runtime creation must use `RuntimeProfile::tokio_runtime_builder()`, which validates profile limits and maps `async_workers` / `blocking_threads` into `tokio::runtime::Builder`.
   - `opc_runtime::Builder::build()` is still the async in-runtime chassis builder. It cannot resize an already-created Tokio runtime, so binaries using `#[tokio::main]` must configure worker counts at that entrypoint before calling into `opc-runtime`.
3. **SDK-Level Admission & Supervision Limits (GAP-008-003)**:
   - **Task Count Bounds**: The `Supervisor` tracks registered supervised tasks. Registering or spawning a task that exceeds `max_tasks` is blocked at admission and fails closed.
   - **Queue Limits**: Queue-owning SDK components must allocate bounded queues. `opc-config-bus` enforces bounded commit/subscriber queues; `ResourceBudget::max_queue_bytes` is a validated contract value for components that allocate byte-accounted queues.
   - **Safe Redacted Errors**: Any task spawn or registration failures produce redacted, client-safe error messages free of internal paths, secrets, or backtraces.
   - **Metric & Alarm Integration**: Budget exhaustions raise a critical `budget.exhausted` alarm and increment `opc_runtime_budget_exhausted_total`.
4. **Hung-Task Detection & Fencing (GAP-008-004)**:
   - **Heartbeat Monitoring**: Tasks with configured heartbeat timeouts are checked by runtime readiness evaluation. A task failing to make progress within its designated window is terminated and readiness drops.
   - **Shutdown Grace Period**: Tasks that hang during graceful shutdown and exceed the `drain_timeout` are forcefully aborted.
   - **Restart Loop Policy**: Tasks entering restart storms are bounded by supervisor policy, raising alarms and transitioning the runtime to a degraded or `NotReady` state.
5. **Memory-Budget Pressure Gating (GAP-008-004)**:
   - Memory allocation pressure is modeled via a deterministic watchdog limiter (`MemoryLimiter`).
   - Under memory budget exhaustion, the runtime blocks new task registration/spawning, transitions readiness to `NotReady`, and raises a critical `budget.exhausted` alarm.

## Alarm Subsystem, Projections, and Per-CNF Adoption Contract

The SDK provides a hardened alarm management subsystem (`opc-alarm`) that standardizes fault management, severity ranking, and external sink delivery, complemented by Kubernetes and YANG projections, a deterministic testing kit, and a per-CNF adoption contract.

### 1. Alarm Taxonomy Versioning & Compatibility
The taxonomy of severities and probable causes is versioned (`TAXONOMY_VERSION = "1.0.0"`) and governed by strict compatibility contracts:
* **Backwards-Compatible Changes**: Adding a new enum variant to `Severity` or `ProbableCause` is non-breaking.
* **Breaking Changes**: Modifying serialization names, removing variants, or shifting the semantic meaning of existing variants requires a major version bump.
* **Extensibility**: Non-standard or NF-specific causes must use `ProbableCause::Other(String)` and carry the `other:<nf>.<cause>` prefix format.

### 2. Bounded Sink Delivery & Fail-Closed Backpressure
To prevent external alarm reporting from blocking fast paths or leaking resources:
* **Async AlarmSink**: The `AlarmSink` trait defines the delivery abstraction.
* **Bounded Buffering**: `BoundedAlarmSink` wraps any sink with a bounded queue (`mpsc::channel`).
* **Fail-Closed Semantics**:
  - If the queue is full, write requests fail immediately with `AlarmSinkError::QueueFull`.
  - Downstream sink failures trigger retries with backoff. If `max_retries` is exhausted, the sink shifts to `Failed` status and subsequent operations fail closed with `AlarmSinkError::RetryExhausted`.
  - During shutdown, already accepted queue entries continue draining asynchronously and new writes return `AlarmSinkError::Shutdown`.
* **Standard Sinks**: Includes `RecordingSink` (in-memory for unit tests) and `TracingSink` (production-shaped logging of serialized JSON).

### 3. Kubernetes & YANG Projections
* **Kubernetes (`opc-alarm-k8s`)**: Projects active alarms to standard `K8sCondition` and `K8sEvent` records. Event types map major/critical alarms to `Warning` and others to `Normal`.
* **YANG (`opc-alarm-yang`)**: Exposes the static `YANG_ALARM_SCHEMA` module (compatible with RFC 013 model) and converts alarms to standard RFC 7951 YANG JSON representation.

### 4. Deterministic Alarm Testkit (`opc-alarm-testkit`)
Provides fluent test asserters (`AlarmAsserter` and `AuditAsserter`) and asynchronous polling helper functions to verify that alarms are eventually raised, cleared, or deduplicated. It also includes an `assert_redacted` scanner that panics if subscriber identifiers (such as IMSIs, SUCIs, GPSIs, MSISDNs, PEIs, GUTIs) or raw secrets (like JWTs) appear in the alarm's text, affected object, tenant, or details.

### 5. Per-CNF Alarm Adoption Contract
Any future CNF crate integrating into the OpenPacketCore ecosystem must adhere to the following contract:
1. **Manager Sharing**: CNFs must not instantiate separate alarm manager instances. They must fetch and share the runtime-owned `SharedAlarmManager` obtained from the active `opc-runtime` context.
2. **NF Namespace Isolation**: Custom alarm probable causes must be constructed using `ProbableCause::Other(format!("cnf.{nf_kind}.{cause}"))` to keep the core namespace clean.
3. **Mandatory Redaction**: All alarm message texts must be passed through `RedactedText::new` after stripping any tenant, subscriber, or network identity secrets.
4. **Test Verification**: CNFs must write tests utilizing `opc-alarm-testkit` to assert that:
   - Alarms are correctly updated/deduplicated rather than creating duplicate active records.
   - All raised alarms pass `opc_alarm_testkit::assert_redacted` validation.

## Go SDK Reference Operator Harness

To demonstrate how the Rust SDK policy contracts are consumed by a Go operator, a minimal `controller-runtime` reference operator harness has been implemented under `operators/sdk-reference-operator/`.

* **Reference Nature**: The harness is explicitly **not a production CNF operator** (such as a production AMF/SMF/UPF operator) and does not encode any CNF-specific reconciliation behavior. Real CNFs must build their own production operators wrapping these SDK contracts.
* **Ownership Split**: Rust remains the owner of the core policy decision logic (compatibility validation, preflight evaluations, and upgrade/drain planning). Go owns the Kubernetes integration layer (CRD APIs, managers, reconciling controllers, and validating/conversion webhooks).
* **Live Plumbing**: This harness provides the first concrete example of Kubernetes webhook and controller deployment plumbing (CRDs, validating/conversion webhook configurations, cert-manager integration, RBAC, and leader-election deployment manifests), proving that Go operators can cleanly delegate policy decisions to the Rust SDK via a CLI JSON boundary.
* **Packaging Contract**: Any reference or downstream manager image must include both the Go manager binary and the Rust `operator-lifecycle-cli` binary, with `OPERATOR_LIFECYCLE_CLI_PATH` set to the CLI location or the CLI available on `PATH`.
* **Validation Boundary**: The SDK repository validates this harness with Go unit tests, fake-client controller/webhook tests, Rust CLI contract tests, and rendered Kustomize manifests. Product CNF operators must add envtest, kind, and real-cluster end-to-end suites around their own reconciliation behavior.

## Production readiness and reference boundaries

The dated hardening tasks documented here are closed within their stated
SDK/library scopes. That does not establish closure of every current P0
production-readiness blocker or make the workspace universally
carrier-production-ready. Production readiness must be assessed for a named
feature, persistence, platform, and deployment profile using current
candidate-specific evidence. The Go SDK reference operator is a reference
harness and is not Kubernetes-operator-ready as a production product;
downstream teams must add their own controller behavior and envtest, kind, and
cluster validation.

The SDK provides peer-simulator and testkit primitives, dry-run runners, and
evidence schema/policy primitives. The repository does not yet generate and
enforce the complete signed RFC 006 release bundle, and the SDK is neither a
production CNF nor a production Kubernetes operator. Live hardware and
downstream product validation remain deployment responsibilities.

The first in-tree NF proof is `opc-amf-lite`, an AMF-oriented N2/N1 control-plane
slice. IKEv2/IPsec, ESP/xfrm orchestration, and N3IWF/NWu procedure crates are
not part of this SDK foundation boundary. `IpsecGateway` in
`opc-node-resources` is a resource/admission profile, not a claim that this
repository implements an untrusted-access/IPsec product stack.

Likewise, `AfXdpFastPath` in `opc-node-resources` models node/resource admission
and BPF artifact governance only; it is not a claim that this repository ships
AF_XDP socket, UMEM, ring, or packet I/O runtime support.

The following items are updated in `docs/implementation-status.md`:

- **Closed / Hardened Foundation** (June 2026):
  - `GAP-K8S-001` (Go SDK reference operator harness demonstrating admission, conversion, and reconciliation).
  - `GAP-K8S-002` (Live Kubernetes webhook and controller deployment plumbing).
  - `GAP-009-001` (Operator/NF/version compatibility policy engine implemented and enforced across admission, config apply, CRD conversion, and migration orchestration).
  - `GAP-009-002` (Stable lifecycle phases and conditions implemented with monotonic transitions).
  - `GAP-009-003` (Operator config-apply decision logic implemented enforcing commit-confirmed timeouts).
  - `GAP-009-004` (CRD conversion webhook helpers implemented under `operator-controller` with Kubernetes-style JSON names and strict unknown-field rejection).
  - `GAP-009-005` (YANG/state migration orchestration implemented under `operator-controller` with static plan validation and fail-closed execution).
  - `GAP-009-006` (Out-of-process drain execution client implemented under `operator-controller` with deadline bounds and empty-plan fail-closed behavior).
  - `GAP-009-007` (Rollback target evaluator choosing only confirmed configurations).
  - `GAP-009-008` (Multi-cluster rollout status aggregation model implemented under `operator-controller` with generation/resource-version monotonicity and cluster identity checks).
  - `GAP-011-001` (Structured `opc-node-resources` resource profile and node capability model).
  - `GAP-011-002` (Preflight admission check implemented validating HA config/session backends, tokens, KMS/SPIFFE, and CPU/resource profiles).
  - `GAP-011-003` (Explicit CPU, NUMA, hugepage, NIC, and CNI validation modeling).
  - `GAP-011-004` (Signed/digest-pinned eBPF/AF_XDP program artifact governance).
  - `GAP-011-005` (Minimal and evidence-linked pod security exception validation).
  - `GAP-011-006` (Data-plane readiness preflight report and rollout integration).
  - `GAP-011-007` (Strict lab fallback gating in Production mode).
  - `GAP-008-003` (Tokio runtime builder profile mapping and runtime budget validation).
  - `GAP-008-004` (Hung-task and memory-budget fault injection verification).
  - `GAP-006-001` through `GAP-006-006` at library-API scope (RFC 006 extraction, SBOM/VEX, provenance, bundle/signing traits, performance, and gate-policy primitives). End-to-end workflow integration remains open as `GAP-006-007`.
  - `GAP-012-001` (Procedure-faithful AMF, SMF, and UPF simulator state machines with deterministic chaos/failure/clock injection).
  - `GAP-012-002` (First reusable per-NF testkit crate `opc-amf-lite-testkit` and documented testkit adoption pattern).
  - `GAP-012-003` (Local in-process runner, Kubernetes `kind` dry-run manifest runner, and `hardware-lab` dry-run preflight validation runner).
- **Narrowed / Partial**:
  - RFC 001 config consensus has extensive prototype evidence, but carrier HA
    qualification remains open.
  - RFC 004 ordered-quorum semantics are tested in process, but networked
    session HA is not graduated.
  - RFC 006 evidence primitives are implemented as library APIs, but the full
    candidate artifact set, production signer/verifier wiring, cross-checking
    of separately supplied policy artifacts against the verified bundle, and
    workflow enforcement are incomplete.
- **Open / Remaining Gaps**:
  - `GAP-001-006` (config-store carrier HA qualification).
  - `GAP-004-004` (production networked session HA qualification).
  - `GAP-006-007` (end-to-end RFC 006 PR/release workflow integration).

Operators can use the new `operator-lifecycle` library, the `operator-controller` execution layer, and the `operators/sdk-reference-operator` Go harness to model state, run webhooks, perform platform preflights, and aggregate fleet statuses. However, product-specific logic for real CNF deployments remains the responsibility of individual CNF teams.
