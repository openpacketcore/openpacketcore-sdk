# Operator Readiness Notes

This note is the operator-facing handoff for the foundation hardening pass
`T-9be95f92` on May 30, 2026, updated on June 6, 2026 for the follow-on
session-store, runtime drain, and ConfigBus authorization seams, and on June 28,
2026 for the final EPC/untrusted-access SDK hardening pass `T-8c57ecee`, with a
July 11, 2026 addendum for checked session-TTL admission and upgrade handling,
and a July 12, 2026 addendum for the #127 Openraft session-store authority. It
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
| XFRM/IPsec backend | `opc-ipsec-xfrm` provides safe XFRM request models, a Linux backend, production fixed outer-DSCP stamping through a validated XFRM output-mark/tc companion, a deterministic mock backend, rollback-aware SA+policy composites, and an opt-in IKEv2 Child SA to XFRM request mapper. | Products still own key derivation, algorithm/profile choices, namespace and privilege rendering, the globally reserved seven-bit skb-mark window, complete SWu egress-interface configuration, live kernel rollout, traffic readiness, and Child SA lifecycle policy. |
| EPC/ePDG testbed simulators | `opc-testbed` exposes PGW S2b and Diameter peer simulator skeletons plus an ePDG SDK composition harness so downstream tests can bridge decoded protocol messages into deterministic SDK scenarios. | Raw protocol bytes must be decoded by protocol crates first. Product ePDG attach orchestration, APN/PLMN/realm policy, charging, LI, and deployment defaults remain downstream. |
| Packet-core evidence packs | `opc-evidence` validates experimental packet-core evidence schemas with schema-version drift guards and redaction checks for IP, IMSI/SUPI-style identifiers, realm/NAI markers, keys, SPIs, and paths. | Packet-core packs require explicit experimental marking and are evidence formatting/validation mechanisms only; carrier-readiness sign-off remains a downstream release decision. |
| Go operator helpers | `operators/operator-sdk-go` includes product-neutral helpers for runtime gates, UDP/SCTP ports, Multus/SR-IOV annotations, rollout/drain checks, and fake-client tests. | Product CRDs, Helm/RBAC values, Multus `NetworkAttachmentDefinition` objects, XFRM/IPsec privileges, readiness thresholds, and traffic-shift policy stay outside the SDK helper package. |

For downstream operator authors, the practical rule is unchanged: use the Rust
policy CLI and Go helper packages as auditable building blocks, then add
product-specific CRDs, deployment privileges, network attachments, integration
tests, and release evidence in the downstream CNF operator repository.

## HA hardening scope

The June 8 review closed scoped algorithms and test harnesses, not carrier HA
qualification. #127 and #177 now place session and config distributed
persistence behind the workspace's single exact-pinned Openraft engine.
`QuorumSessionStore` remains only a compatibility alias to
`ConsensusSessionStore`; the custom config Raft and majority config wrapper are
removed. Each domain retains its own state machine and production evidence
gates.

The current exact pin is the immutable `openpacketcore/openraft` revision
`f607e636406b16bd0ad7925dbb631da1b7a4cd96`, not registry 0.9.24. Both domains
consume one fixed runtime profile from `opc-consensus`, including fresh
per-campaign `[5,000 ms, 8,000 ms)` election-timeout sampling, a 2,000 ms
heartbeat/AppendEntries ceiling, and the shared 10,000 ms operation default.
This temporary git source makes the mechanically derived 26-crate normal
reverse-dependency
closure source-build-only and `publish = false`. Keep that boundary until an
official stable Openraft release contains the fix, an exact registry
pin/checksum replaces it, and #143 is requalified. This restriction does not
move payload sealing, AAD, HKMS/KMS operations, or key custody into consensus.

### Config Openraft, migration, and shared transport contract

For `opc-persist`, the authority path is:

```text
application -> HKMS-backed encryption -> ConsensusConfigStore
            -> Openraft -> SQLite and Openraft snapshots
```

Only a config envelope carrying one-shot evidence from the real encryption
adapter may cross into Openraft; the evidence is consumed before serialization.
Sealed ciphertext, deterministic metadata, and redacted finalized audit records
are replicated. Plaintext, providers, key handles, and raw key material stay
above the consensus boundary. Creating the Openraft
authority marker and checking or importing legacy state is one immediate
per-database SQLite transaction; direct standalone mutations then fail closed.

The config voter set is exact and immutable within one topology epoch. A
subset/superset is never an admissible degraded mode; a reviewed topology
change uses a coordinated new epoch.

Configure one complete config operation timeout greater than zero and no more
than 60 seconds. It bounds leader routing, the linearizable barrier, quorum
commit, and local apply. Network call deadlines, retries, framing, mTLS, and
authentication belong to the shared `opc-consensus`/`opc-session-net`
transport contract; do not translate removed config TCP timeout or metric
settings into the Openraft adapter.

Install `ConsensusConfigStore::rpc_handler()` on the authenticated shared
listener before cluster initialization, and require
`probe_durable_readiness()` before traffic. Listener bind, TLS setup, cached
capabilities, status observation, or a local SQLite read is not durable
readiness. Retain each mutation's request ID across response loss so a retry
within the newest 4,096 outcomes recovers the original durable result rather
than creating a second write. After that finite horizon, use a fresh
authoritative read.

Nonempty legacy authority must be migrated offline. Preserve untouched
pre-migration backups, select one externally proven applied SQLite snapshot,
checkpoint it, and bind its exact SHA-256, latest transaction ID/version, and
the explicit `DiscardUnknownAppendedSuffix` decision. Unknown target suffixes
are discarded; they are never inferred committed. Recovery opens the source
without following symlinks and binds verification/consumption to the same file
descriptor while rechecking the path identity and offline WAL state. Atomicity
is per database,
so the fleet must be drained and coordinated. Rollback is only a full restore
from the preserved pre-migration backups; deleting `config_raft_*` state or
reconstructing the removed engine is prohibited.

`opc-persist` contains no replacement TCP listener, certificate parser, or
rotation API. Production mTLS and certificate/trust-bundle rotation remain the
existing `opc-session-net`/CNF responsibility. Preserve trust overlap, force
fresh authentication, drain old connections, and gate on fresh readiness.
Shared real-mTLS tests qualify a renewed SVID on a subsequent new call/full
handshake and wrong-scope rejection. They do not prove seamless old-connection
retirement across a fleet. The suite also forms a real three-node
`ConsensusConfigStore` and commits/linearizably reads through the existing mTLS
adapter. This migration
does not by itself supply out-of-process/deployed-network, multi-process/soak,
or the complete fleet trust lifecycle.

### Session topology admission

Construct HA-shaped session stores only from `ValidatedQuorumTopology` created
from `QuorumTopologyConfig::new_consensus`. The SDK
rejects membership outside the odd 3-through-31 bound, missing/ambiguous local
self, duplicate logical IDs/endpoints/TLS identities/failure domains/backing
identities, a missing or zero consensus epoch, configuration-digest mismatch,
and stable-node-ID collision before server readiness. The quorum denominator is
the admitted configured membership, not current reachability.

`ValidatedQuorumTopology::try_new_consensus_lab_singleton` is an explicit lab
path and advertises `single-replica`. Logical self must be configured explicitly;
do not derive it by shortening an FQDN or comparing endpoint strings. For
example, logical self `epdg-app-0` can identify a descriptor whose dial route is
`epdg-app-0.epdg-app-quorum.epdg-gateway.svc.cluster.local:7443`: the explicit
`ReplicaId` selects self, while the FQDN is only the endpoint. The stable
Openraft node ID is derived from cluster identity plus that logical
`ReplicaId`, never from DNS ordering or endpoint spelling.

Build one immutable `ConsensusIdentity` from the cluster ID, a positive
monotonic configuration epoch, and the exact order-independent configuration
digest over that cluster, epoch, and complete descriptor-fingerprint set.
The topology contains only those member descriptors. Supply the node's one
local SQLite backend separately to `ConsensusSessionStore::open`, and build
the exact consensus-peer map plus `SessionReplicationManifest` bindings from
the same admitted data; remote votes require no dummy or legacy backend.
Topology and transport admission verify each local/remote logical ID, stable
node ID, expected TLS identity, descriptor fingerprints, configured member
count, cluster, configuration digest, and epoch. Route aliases remain outside
this identity.

This admission result is not a durable-ready signal. Capability declarations
and `SessionStorePlatformProfile::Quorum` are also admission evidence only. A
production operator must separately require fresh durable readiness before
traffic readiness.

### Session identity admission and #135 upgrade

#135 makes owner and custom session-key identities structural and fail-closed.
`OwnerId` and each deployment-specific `SessionKeyType` name must contain 1
through 128 UTF-8 encoded bytes; this is a byte limit, not a character limit.
The reserved names `subscriber-context`, `pdu-session`, `teid-mapping`,
`pfcp-seid`, and `handover-transaction` always decode to the corresponding
well-known variants and cannot be represented as custom values. Known and
custom key types serialize and sort by that canonical persisted string.

The same validation runs at public constructors and Serde decode, SQLite
record/restore/lease/fenced-mutation/log hydration, and session-net request and
response decoding. A malformed persisted owner or key type fails before the
operation mutates the store; nested replication-log identities are validated
as part of the complete entry. Diagnostics are fixed or fieldless and do not
contain the rejected value. Newly written handover envelopes carry an exact
`OPCH` magic/version header. Original envelopes remain readable only with a
complete phase of at most `HANDOVER_PHASE_HEADER_MAX_BYTES` (1,024 bytes) that
is valid under the current model. Non-`OPCH` bare compatibility is governed by
the exact classifier below; it is not a promise for arbitrary historical bytes.

Valid owner/key-type values keep their protocol-v4 JSON string shape. That is
shape compatibility only: `SessionKeyType::Other(String)` changing to
`Other(CustomSessionKeyType)` and the fallible `SessionKeyType::other` are Rust
source breaks, while the new rejection of empty/oversized input is a semantic
wire-admission break. An older v3 participant can send a value v4 rejects.
Do not roll mixed versions. Protocol v4 now binds #135 in its exact fixed-width
contract; use a coordinated stop/upgrade/start for every session-net client,
server, and protection wrapper and every NF/product handover reader or writer.

For every existing SQLite replica, the operator sequence is:

1. Close the traffic/readiness gate, drain session traffic and all writers, and
   take the product's normal backup or replacement checkpoint.
2. Run the audit against the resulting point-in-time database with explicit
   budgets:

   ```text
   opc-session-store-audit identity-invariants \
     --database /path/to/session-store.db \
     --max-rows N \
     --max-entry-json-bytes N \
     --max-total-json-bytes N \
     --expiry-reference 2026-07-13T18:00:00Z
   ```

3. Require all three numeric budgets to be non-zero and require the per-entry
   JSON budget not to exceed the total JSON budget or SQLite's signed `i64`
   length range. Size `--max-rows` for the
   combined row count across `session_records`, `leases`, `key_fences`, and
   `session_replication_log`, not per table.
4. Record the RFC 3339 expiry reference for the migration campaign. Accept only
   report schema version 4 with that exact `expiry_reference`,
   `status = compliant`, and process
   exit 0. This means the complete drained snapshot fit the budgets and had no
   observed invariant violations; it says nothing about quorum, commit
   authority, or a different snapshot.
5. Treat `violations_found` (stdout JSON, exit 1), `incomplete` (stdout JSON,
   exit 2), and `error` (stderr JSON, exit 2) as upgrade blockers.
6. Separately preflight every drained, decrypted handover payload through the
   new `unpack_raw_with_format` or typed `unpack_json_with_format` path. Cover
   live records plus recursively nested replication-log/snapshot records,
   restore/rebuild sources, and every retained copy that can be replayed. Check
   syntactic format against snapshot provenance and product payload semantics;
   decoder success alone is not sufficient. Migrate or replace every value
   whose classification cannot be proven.
7. Upgrade every session-net client/server/protection wrapper and every
   NF/product handover reader/writer together. Verify the new binaries,
   authenticated v5 handshakes, restore/log reads, and fresh quorum gate, then
   restore traffic.

Run this command against the live SQLite file and every retained SQLite
snapshot that could become a restore/rebuild source. The command opens only an
existing database in read-only/query-only mode and scans one consistent
snapshot in fixed 256-row pages. `--max-rows` bounds all
audited rows; `--max-entry-json-bytes` and `--max-total-json-bytes` bound strict
decode of the individual and cumulative replication JSON. Version-4 output is
count-only: supplied limits, the expiry reference, per-table scanned counts,
invalid-owner, invalid-key-type, invalid-stable-ID,
invalid-replication-transaction-ID, invalid-replication-entry, and
invalid-record-expiry counts, plus an optional bounded incomplete reason.
Relational expiry is checked against the reported reference; nested legacy CAS
expiry is checked against its replication-entry timestamp. Relational stable
IDs are inspected by SQLite type and length only. It does not print the database
path, row IDs, tenant, owner, key type, stable ID, transaction, payload,
rejected row timestamp, or raw JSON. Omitting `--expiry-reference` uses current
UTC, but do not omit it for a reproducible migration.

An incomplete reason is one of `row_budget_exceeded`,
`entry_json_budget_exceeded`, `total_json_budget_exceeded`,
`unsupported_schema`, `database_read_failed`, or `counter_overflow`. Increase
budgets and rerun when safe; for a violation, use a separately reviewed,
product-owned migration that preserves identity and authoritative-history
semantics, or replace the store and follow the product recovery procedure.
Neither the audit nor runtime automatically truncates, renames, normalizes,
deletes, repairs, or rewrites invalid state. Re-audit the final snapshot before
starting the new SDK.

For an expiry violation, follow
[`session-store-record-expiry-migration.md`](session-store-record-expiry-migration.md).
Do not clamp a timestamp or edit OpenRaft rows, logs, snapshots, membership, or
applied indexes in place. Product-aware re-authoring and supported whole-fleet
rebootstrap are required; preserve the immutable backup as the rollback source.

The identity audit scans identity columns and replication JSON, but never
classifies live payloads or payload bytes inside nested CAS log operations; its
`compliant` result cannot certify handover compatibility. The separate
provenance-aware preflight must apply this exact non-`OPCH` classifier to the
complete live and replayable payload population:

- fewer than four bytes are bare `Stable`;
- a zero first-word, or a big-endian phase length from 1 through 1,024 that is
  truncated, is `InvalidHeader`;
- a complete in-bound phase is an original envelope only if it decodes as the
  current `HandoverPhase`; JSON-looking invalid phase bytes are `InvalidPhase`,
  while non-JSON-looking bytes fall back to bare `Stable`; and
- a length above 1,024 is `InvalidHeader` if the remainder begins, after ASCII
  whitespace, like JSON, and otherwise falls back to bare `Stable`.

The fail-closed classifier intentionally rejects some ambiguous historical bare
bytes and some envelopes accepted by the old unbounded reader. Successful
syntax detection can also collide: for a checkpoint proven to predate `OPCH`, a
`VersionedV1` result is historical bare data, and every
`OriginalLengthPrefixed` result requires product/provenance confirmation. A
product that can authoritatively identify a value as bare `Stable` may
explicitly wrap the complete original value in `OPCH`; otherwise it must use a
reviewed semantic migration or store replacement. Preserve generation, fencing,
encryption, and NF payload meaning.

The first new transition can persist `OPCH`. From then on this is a one-way
format migration: an older SDK silently treats `OPCH` as an opaque bare
`Stable` payload. Binary rollback is forbidden unless the drained fleet restores
one coherent fleet-wide pre-upgrade checkpoint—accepting or reconciling loss of
all post-checkpoint mutations—or reverse-migrates every affected live and
replayable payload, including nested logs/snapshots/restore sources, under a
reviewed procedure. The v4 handshake does not make the opaque format backward
readable, and every handover reader/writer—not only session-net members—must be
upgraded together.

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
process-availability boundary only; it is not evidence for Openraft commit
authority, fork recovery, or production HA.

Before rolling this change onto a store written by an older SDK, audit every
persisted replication-log operation that carries a TTL. Values above 365 days
now fail closed during replay or rebuild and are never silently clamped. Stop
the rollout and use an audited product recovery/migration procedure if such an
entry exists; do not truncate or rewrite presumed history ad hoc. Replicated
deadline validation accepts at most one microsecond above the exact
`entry.timestamp + ttl` for legacy `seconds_f64` rounding only. New deadlines
remain exact, this does not enlarge the 365-day bound, and larger mismatches
fail closed.

The two new public error variants require exhaustive matches to be updated.
Protocol v5 retains their private fixed-width DTOs and carries the current error
revision 8; an error-revision-7 or older peer is rejected during exact
negotiation. Use the coordinated v5 rollout below before relying on typed
responses.

### Absolute record expiry admission and upgrade

Caller-authored `StoredSessionRecord::expires_at` is now independently bounded.
At one mutation-authority reference timestamp, past and immediate deadlines are
valid, the exact `reference + MAX_SESSION_TTL` deadline is valid, and one
nanosecond more returns the fieldless `StoreError::InvalidRecordExpiry`.
Timestamp-range extremes cannot panic. `MAX_RECORD_EXPIRY_CLOCK_SKEW` is zero,
so keep coordinator clocks synchronized; the SDK does not turn clock skew into
extra retention.

`expires_at = None` is intentional non-expiring state for
`AuthoritativeSession`, `DataplaneLookup`, `ReplicatedDr`, and
`TelemetryDerived`. It is invalid for `EphemeralProcedure`, whose profile
requires expiry for abandoned-procedure collection. Products may impose a
shorter finite horizon or disallow non-expiring state more broadly.

Standalone Fake/SQLite operations capture their injected backend clock once
for an entire CAS/batch preflight. Compatibility replication uses the immutable
entry timestamp. Production OpenRaft uses the leader-authored command logical
time and repeats the same deterministic verdict at apply/replay; follower wall
clocks do not decide admission. Forwarding clients and wrappers never invent a
local reference. A wrapper above remote/consensus authority MUST obtain the
bounded payload-free authority preflight before cache invalidation,
provider/HKMS work, sealing, or backend dispatch. The authenticated CAS/batch
path repeats it before idempotency admission. Invalid input and preflight
timeout/unavailability perform no provider work or requested mutation; caller
retry is safe because only a consensus logical-time floor may have committed.
This does not change payload envelopes, AAD, key lookup, HKMS/KMS placement,
or encryption at rest.

Before upgrade, use the version-4 count-only audit with a recorded
`--expiry-reference` on every drained live/retained SQLite source. Do not start
on any `invalid_record_expiry_fields`, invalid nested replication entry, or
incomplete result. Follow the complete backup, re-authoring, OpenRaft recovery,
verification, and fleet-wide rollback procedure in
[`session-store-record-expiry-migration.md`](session-store-record-expiry-migration.md).
The compatibility profile moves to `opc-session-net/5`, wire revision 6,
error revision 8; consensus moves to `opc-session-consensus/2`, transport/wire
revision 2, error revision 4. Both are coordinated drained upgrades, not
rolling changes.

### Nested replication payload admission and upgrade

Replication trees now have two public per-entry limits:
`MAX_REPLICATION_OPERATION_DEPTH = 16` and
`MAX_REPLICATION_OPERATIONS_PER_ENTRY = 256`. The root is depth 1; each child
increments depth; and every operation node, including each `Batch`, counts
toward the total. Validation and transformation are iterative. An over-limit
entry returns the fieldless, redaction-safe
`StoreError::ReplicationOperationLimitExceeded`.

Complete entries and rebuild prefixes are preflighted before provider/backend
work, and complete returned pages are preflighted before transformation or
caller exposure. Encryption and remote-sealing wrappers protect every nested
CAS on replicate/rebuild and unprotect every nested CAS on log/watch reads.
Provider calls are sequential. If a late provider call fails, earlier provider
calls may already have occurred, but no write is delegated to the backend and
no partially transformed entry/page is exposed. An earlier independent watch
item may already have been delivered.

Treat this as a coordinated fleet migration, not a rolling upgrade. An older
v3 peer cannot decode the new error and an older wrapper may forward a deeply
nested CAS as plaintext/unsealed data. Protocol v4 rejects the older wire
participant and pins the limits/error revision, but cannot attest that the
product actually installed a protection wrapper. Drain traffic and writers,
upgrade every client, server, and wrapper participant together, verify the
composition, and only then restore service.

Before rollout, audit persisted replication-log tree shape and payload encoding
offline without emitting payloads in logs or metrics. The SDK does not
automatically discover or scrub historical nested plaintext. An affected entry
within the 16/256 limits may be rewritten/rebuilt through the configured
encryption/sealing wrapper. An over-limit historical entry fails before
transformation and cannot be ingested unchanged: use a separately reviewed
offline migration that preserves atomic semantics, or replace the store under
an explicit audited recovery procedure before starting the new SDK. Do not
clamp/split entries ad hoc or use the raw inner backend as protection.

This closes the #147 traversal/confidentiality gap only. It does not qualify
networked session HA. #143 and the remaining dependencies still block the
experimental profile. A renewed SVID on a subsequent new call/full handshake
and wrong-scope rejection have scoped real-mTLS qualification; fleet-scale
seamless connection retirement, payload-protection key rotation, and the
complete trust-overlap/removal, short-lived-SVID expiry/root-cutover,
authentication-age, multi-process, and soak lifecycle remain separate mandatory
production gates. Immediate generic CRL/OCSP/certificate-or-identity-denylist
revocation is not implemented.

### Session durable readiness

`ConsensusSessionStore::probe_durable_readiness` (and the compatibility alias
`QuorumSessionStore::probe_durable_readiness`) performs a fresh, bounded
Openraft linearizable-read barrier. It discovers or follows the current leader,
runs `ensure_linearizable` against the admitted voting configuration, and does
not return `Ready` until the local state machine has applied through the
barrier's log index. This is the same authority path used by real linearizable
reads; listener bind, successful TLS setup, cached capabilities, and a local
SQLite read cannot satisfy it.

Require `DurableReadinessState::Ready`; a barrier, leader-discovery, peer RPC,
or local-apply timeout reports `NoQuorum`. `TopologyInvalid` and
`RecoveryRequired` remain stable compatibility states for admission/recovery
failures. The report retains its bounded compatibility fields, including the
configured and required voter counts and an optional index accessor historically
named `majority_visible_prefix_index`; under `ConsensusSessionStore` that index
is Openraft barrier/committed-apply evidence, not a custom majority-log-prefix
calculation. Do not reconstruct authority from the individual report counters
or observations.

The same report exposes `recovery_progress()` with a closed state set:
`synchronized`, `catching_up`, `awaiting_quorum`, or `recovery_required`, and
optional local log/applied/snapshot/purged indexes. These are redaction-safe
progress counters, not branch-selection evidence and not authorization to
truncate, rebuild, or serve traffic.

The store's one bounded operation deadline applies to the complete leader,
network, barrier, and local-apply path. Do not log raw peer errors or turn
replica IDs, endpoints, DNS names, or SPIFFE identities into metric labels.

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

For a converged shared-L2 product where that floating VIP itself delivers
packets, report `SteeringProbe::vip_delivered()` rather than a testkit mock.
Its `mutation_ready` state means the product adapter intentionally accepts
steering mutations as no-ops because VIP delivery already satisfies the
contract. It does not evidence Host-XDP, VF-XDP, NIC offload, datapath rule
programming, key custody, VIP ownership, or packet-flow correctness; those
claims still require their own current product evidence. Default and unknown
steering selection remains fail-closed as `Unsupported`.

### Tested session Openraft features

1. **One Consensus Authority**: `ConsensusSessionStore` delegates election,
   voting, log matching, commitment, membership, snapshot coordination, and
   linearizable-read authority to the shared, pinned Openraft engine. The old
   majority-visible-prefix coordinator is not an alternate production path.
2. **Deterministic Session State Machine**: Committed commands drive lease,
   compare-and-set, delete, TTL, batching, fencing, logical expiry time,
   idempotent request outcomes, journal, and watch-cursor state. Application
   state is exposed only after committed apply.
3. **Ambiguous-Response Idempotency**: A delivered mutation whose response is
   lost can be retried with the same request identity; the durable outcome is
   returned once, while reuse of that identity for a different semantic intent
   fails closed.
4. **No Parallel Raw Authority**: Production consensus rejects caller-selected
   replication append, whole-state rebuild, and lease sequencing. The dedicated
   network listener can dispatch only authenticated consensus RPCs.
5. **Bounded Snapshots and Logs**: SQLite-backed Openraft storage persists vote,
   log, committed/applied/purged positions, membership, request outcomes, and
   the application chain; bounded checksummed snapshots carry only one coherent
   sealed state-machine image.
6. **Observed-Leader Foundation Evidence**: The 3- and 5-process harness
   coherently observes the actual leader, stops that process, requires a
   different survivor at a strictly higher term, performs a generation read
   while the old leader is down, restarts the same durable node, and waits for
   convergence. The retained original 15-operation history is independently
   checked; the added outage read is separately identified as transition
   evidence. Separate domain-level tests commit session lease/CAS work and a
   configuration transaction after isolating the old leader. This is loopback
   plaintext test transport, not deployed-network or mTLS qualification.
7. **Remaining Qualification**: #128 makes current-format repair exclusively
   Openraft-owned, rejects committed/applied truncation and stale snapshots,
   validates restart artifacts, and qualifies divergent-tail/snapshot recovery.
   #129 provides the default-deny offline whole-fleet procedure documented in
   the [legacy recovery runbook](session-store-legacy-recovery.md). #133 bounds
   restore scans over the barrier-confirmed local applied state; method
   availability still is not readiness evidence. #143 must supply distributed
   partition/restart/resource/soak and payload-key qualification. Until that
   lands, this is implemented commit and recovery authority, not
   production HA qualification.

### Current-format follower recovery runbook

1. Close traffic, ownership publication, VIP advertisement, and new lease
   acquisition unless the fresh report is `Ready`.
2. For `catching_up` or `awaiting_quorum`, verify the exact admitted peer set,
   bidirectional authenticated consensus reachability, and durable volume
   availability. Restore connectivity and allow Openraft to reconcile. Do not
   copy rows, call raw rebuild APIs, or delete a PVC.
3. Confirm progress through the bounded local indexes only. Recovery is
   complete only when a fresh barrier reports `Ready` and `synchronized`.
4. On `recovery_required`, preserve the SQLite database, WAL/SHM if present,
   snapshot directory, deployment identity/configuration/epoch, and the
   redacted readiness report. Do not edit or retry around a corrupt referenced
   snapshot; replace/recover the member only from an approved committed source.
5. If storage predates Openraft or startup reports legacy recovery required,
   stop. Use the [audited #129 workflow](session-store-legacy-recovery.md);
   current-format automatic recovery cannot infer a committed branch from
   legacy rows.

The adapter removes bounded SDK-named interrupted staging files on restart but
does not delete unknown operator files. A missing/corrupt referenced snapshot,
directory above 8,192 entries, cross-identity image, or snapshot behind the
committed/applied floor fails closed before service admission. Covered-log
purge waits at most ten seconds for asynchronous snapshot apply to advance the
durable floor; timeout stops the Openraft node rather than deleting unapplied
history.

### Replication-log range cursor operations

Replication-log positions are inclusive and 1-based. `start = 0` is only the
empty-head read sentinel and aliases sequence one; `limit = 0` returns before
I/O. Every non-empty page must start at the exact normalized cursor, remain
contiguous, and stay within the checked request interval of at most 65,536
entries. Empty, terminal, and future cursors return an empty page. A request
whose interval overflows, exceeds the page maximum, or names compacted history
returns a distinct typed outcome. Frame-budget shortening leaves the first
unsent entry as the next request; do not add one twice or infer progress from
the requested limit.

On `ReplicationLogCursorCompacted { resume_from }`, stop incremental replay.
The resume point identifies the first position after the compacted floor; it is
not evidence that the missing history was applied and is not authorization to
skip it. Install a coherent Openraft snapshot or complete the approved
operator recovery/rebuild path, verify fresh durable readiness, and only then
resume at that point. Never splice pages from different replicas or select the
largest resume point. The production store performs a linearizable barrier and
reads one local applied state; replicas with temporarily different compaction
floors return their own typed outcomes and cannot be unioned into a synthetic
page.

For the quarantined legacy session-net path, a page before or after the exact
request is a peer contract violation. The client closes that connection and
clears cached capabilities before re-handshake. Error-set revision 4 was an
exact-profile transition: drain and stop every compatibility client/server,
upgrade them together, verify exact and shortened-page pagination plus typed
compaction recovery, then restore traffic. This change does not alter
Openraft commit authority, restore/watch cursors, payload envelopes, AAD,
HKMS/KMS placement, or encrypted-at-rest composition.

### Session payload protection boundary

The required production composition places protection above consensus:

```text
application -> EncryptingSessionBackend / RemoteSealingSessionBackend
            -> ConsensusSessionStore -> Openraft -> SQLite/snapshots
```

The wrapper seals a payload before `client_write`. Openraft log replication,
follower apply, replay, request-outcome persistence, and snapshot build/install
therefore handle opaque RFC 003 envelope bytes; they do not receive plaintext,
an HKMS/KMS provider, raw key material, or a key handle. Reads cross the wrapper
in the opposite direction, and historical envelopes select their decryption
key by key ID. A provider outage blocks new plaintext protection or decryption,
but it must not move provider calls into deterministic Raft apply or make sealed
log replay depend on provider availability.

This is payload-envelope encryption, not full-database encryption. Session
payload bytes are sealed, while host-visible SQLite/Openraft metadata includes
membership, terms and indexes, request and key routing fields, tenant/owner,
generation/fence, timestamps, and envelope key IDs. A product requiring
metadata or full-file encryption must add an approved database/volume layer and
qualify it without bypassing the wrapper. Exact remote-seal historical-key
selection is implemented; #143 owns distributed payload-protection evidence,
and the transport certificate rotation chain is separate.

### Remote-seal key rotation runbook

1. Inventory every live store, Raft log/snapshot, backup, restore source, and
   rollback checkpoint that may contain the old envelope key ID. An unbounded
   record or unknown source makes the retirement proof incomplete.
2. Upgrade every reader, writer, and custom remote provider while the old key
   remains active. Stop or drain old binaries, wait for upgraded readiness, and
   prove every active process can unseal by the exact envelope key ID. Do not
   publish a new active ID before this fleet gate completes.
3. Provision the new remote key in KMS/HKMS and prove exact-ID encrypt/decrypt
   for the expected purpose and tenant before publishing it to any CNF. Keep
   the old key enabled for decrypt.
4. Publish the new key through the `RemoteSealMaterialController` in each
   process. Cloned controllers share publication only inside that process; the
   controller is not a cross-pod watcher or durable coordinator, and its opaque
   epoch cannot be compared across processes. Publication affects only future
   seals. A request already in flight continues using its captured old ID but
   can still timeout, encounter revocation, or fail. Mixed old/new fleet writes
   remain readable while KMS retains both envelope IDs.
5. Verify new writes use the new envelope ID and both old/new records restore
   through the current provider configuration. Missing/revoked keys, provider
   outage, wrong tenant/AAD, or malformed history must return only coarse,
   redacted crypto errors. Do not log provider responses, endpoints, tenants,
   key IDs, or payloads.
6. Run a separately implemented bounded, restartable rewrap campaign if the
   deployment requires early retirement. After the final write fence, use a
   bounded snapshot-bound live-state scan to verify the resulting live state.
   Independently compact, expire, or inspect retained logs and snapshots, and
   inspect then rewrap, delete, or retain backups, restore inputs, and rollback
   artifacts. The SDK does not supply the rewrap campaign or a composite
   dependency-proof object; a restore scan alone does not prove retained
   artifacts. A partial page, stale cursor, concurrent write, unavailable
   source, or remaining dependency blocks retirement. A finite TTL/retention
   proof is acceptable only when it covers every source and no record is
   unbounded.
7. Retire or revoke the old key at KMS/HKMS only after the operator-controlled
   proof and gate succeed. The SDK has no retirement API or enforcement gate
   and cannot prevent external KMS retirement. Emergency revocation is fail
   closed and can intentionally make dependent records unreadable.

For material rollback, first verify that KMS can encrypt/decrypt with the old
ID and decrypt with the new ID. Republish the old ID on every upgraded process,
verify new writes use it and both key epochs remain readable, and retain the new
ID while any artifact depends on it. A pre-change binary cannot safely read
mixed-key state: binary rollback is safe only before publishing the new ID, or
after a complete rewrap/artifact proof returns all dependencies to one key.
Otherwise restore a coherent pre-publication checkpoint. The
`RemoteSealProvider::unseal(&KeyId, ...)` source-API change requires custom
providers and callers to upgrade together. Envelope, session-net, Openraft, and
KMS framing/schema are unchanged; decrypt request contents now select the
historical envelope ID.

### Session consensus transport and identity

The production #127 path uses `SessionConsensusServer` and
`RemoteSessionConsensusPeer` on the exact `opc-session-consensus/2` ALPN. This
listener owns only a `SessionConsensusRpcHandler`: it cannot dispatch direct
session-backend mutation, raw replication-log append, restore rebuild, or lease
sequencing. Legacy `opc-session-net/5` direct-backend networking is a
non-default compatibility feature and must not share the production consensus
listener.

Each directed peer keeps at most one authenticated, single-in-flight
connection. Every initial or replacement connection performs a fresh
mutual-TLS handshake. Before an Openraft RPC is dispatched, both sides bind the
canonical certificate SPIFFE URI, logical `ReplicaId`, derived stable node ID,
expected opposite peer, cluster ID,
configuration digest, configuration epoch, consensus role, exact transport
profile, and a fresh challenge. The authenticated sender in the outer request
must also match the sender encoded in the bounded Openraft payload. DNS, FQDN,
short hostname, IP, and resolver aliases select only the dial route. They never
select self, a vote, or a certificate identity.

Each call's absolute family deadline begins before admission/gate acquisition
and covers bounded encoding, write, and response read. When a connection is
needed, resolution, TCP, mTLS, identity admission, and bootstrap receive at
most 1,500 ms inside that family deadline; they do not add time. AppendEntries
and Openraft read-index use 2,000 ms, Vote 5,000 ms, and
InstallSnapshot/ForwardMutation/consumer ReadBarrier 10,000 ms. Only a complete,
correlated, validated success is cached; every uncertain stream position or
typed failure evicts it. Authentication or identity mismatch fails before
engine dispatch. The outer consensus frame is bounded for the shared compact
Openraft payload; transport code does not decode commands or make consensus
decisions.

#161 atomic identity/trust reload, #162 bounded material epochs, and #163 finite
peer reauthentication are implemented. Clients and listeners retain exact
handshake epoch and local/peer effective presented-chain-expiry evidence, stop
new admission at the soft retirement boundary, bound transport waits and
connection slots by the hard deadline, and repeat the complete
mutual-TLS/application handshake on replacements. Every certificate configured
in the local SVID chain and every certificate actually presented by the peer
contributes to the deadline; a redundantly presented root therefore bounds it.
A root present only in a configured trust bundle is not independently scanned,
and anchor removal time is not an expiry deadline. Production SVID chains
should omit the trust anchor. A supervised backend mutation may finish after
its caller future is dropped; retirement therefore preserves typed ambiguity,
forbids automatic replay, and requires authoritative readback or the existing
operation-bound idempotency/fencing contract.

Use short-lived SVID expiry as the bounded same-issuer
credential-compromise/revocation response. Rotation and reauthentication move
cooperative participants but do not revoke an old certificate/key: its holder
can reconnect until the earliest expiry in that presented chain while its
issuer remains trusted. Immediate generic CRL, OCSP,
certificate/identity-denylist, and other selective same-issuer revocation are
unsupported. Root removal is instead a trust-anchor cutover for every chain
that depends on it; it is not an expiry deadline.

Legacy watches resume from the exact caller-delivered sequence. #164 still
owns fleet rotation qualification under umbrella #158; a production CNF must
qualify old/new trust overlap and removal, short-lived-SVID expiry and root
cutover, reconnect storms, and multi-process/soak continuity. The unsupported
generic-revocation limitation remains part of that acceptance decision. #143
owns the wider distributed qualification.

When TLS material is mounted as a Kubernetes projected Secret, construct
`ProjectedSvidSource` with the mount root and relative Secret-key paths. Do not
point the independent-file source at the user-facing `tls.crt`, `tls.key`, and
bundle symlinks: those links can cross generations during `..data` replacement.
Treat source `Ready` and a non-empty identity state only as source-publication
prerequisites. A `RetainingLastGood` status permits existing unexpired material
to remain active while the candidate is repaired; source `Unavailable` must
gate new traffic. Never retain source-level last-good material past its leaf
expiry. This projected source's ongoing expiry monitor schedules clearing from
the leaf expiry; it is not the authority for an earlier intermediate expiry.
Source `Ready` alone is therefore not TLS readiness.

Alert on the fixed projected reload reason codes, not the legacy free-form
event field. Generation numbers are process-local evidence: rollback advances
the number, and process restart resets it. Do not use them as a persisted
cluster epoch or membership identity. Page on `generation_retry_limit`,
`read_attempt_timeout`, and `last_good_expired`; the last reason stays active
until a validated replacement is published.

Construct one shared `TlsMaterialController` from the identity source and pass
clones through `TlsConfigBuilder::from_material_controller`. Pin the expected
local SPIFFE ID explicitly when configuration already knows it; otherwise the
first valid state becomes the process-lifetime pin. Gate startup and new TLS
traffic on controller `Ready`, not source status alone. The controller pre-scans
every configured SVID-chain certificate, marks material unavailable at the
earliest expiry, and exposes both leaf and effective chain expiry. Use
`run_handshake` for the complete TLS plus application bootstrap and retain its
admitted epoch, leaf expiry, and effective configured/presented-chain expiry
with the connection. A raw `rustls_config()` call is compatibility-only and does
not supply epoch-current application admission.

Every readiness evaluation must call `material_status()` or
`TlsMaterialController::status()` so wall-clock expiry is reconciled at that
evaluation. Do not cache a previously borrowed watch value as current
readiness: status subscriptions wake on reconciled/source activity and are not
an independent wall-clock timer for an earlier intermediate expiry.

Alert on `local_identity_changed`, `last_good_expired`,
`material_limit_exceeded`, and `epoch_retry_limit` without attaching identity
or parser text. An invalid candidate leaves a prior epoch usable only while its
effective configured/presented chain remains unexpired; expiry of any
configured chain certificate gates new connections. Epochs reset with the
process and must never be used as cluster membership/configuration epochs.
Configure the same finite `ConnectionLifecyclePolicy` on peers and listeners
and share a `SessionReauthenticationControl` for CNF orchestration. Defaults are
a 15-minute maximum authentication age, 30-second drain, 50 ms through 1 second
reconnect backoff, and at most 30 seconds of directed stable jitter. Use the
forward and reverse trust/leaf procedure in
[`consensus-operator-runbook.md`](consensus-operator-runbook.md#7-shared-mtls-certificate-rotation).

Alert on the fixed connection retirement, active/draining, drain-overrun,
connection-outcome, reconnect, and watch-slow-consumer metrics. Do not add
endpoint, SPIFFE ID, certificate, key, transaction, or payload labels. A zero
draining gauge does not prove current-material authentication; require fresh
durable readiness and exercise every directed peer path before old-trust
removal.

### Legacy direct-backend session-net v5 rollout boundary

The opt-in legacy `opc-session-net` v5 surface carries cursor-paged remote
restore scans and authenticated replica identity. Its authenticated constructors
accept opaque TLS configs. Both sides extract the canonical SPIFFE URI from the live peer
certificate and require an exact match with the manifest's claimed stable
`ReplicaId`, expected opposite replica, cluster, and configuration ID before
backend dispatch. The client verifies its fresh challenge is echoed by the
server. The configuration ID digests the cluster,
explicit generation, and complete descriptor set.
Session-net deliberately disables TLS resumption, session tickets, early data,
and 0-RTT; budget every reconnect as a full mutual-TLS handshake so the live
SVID is revalidated after rotation.

Bounded retained-connection retirement and full-handshake reauthentication are
implemented under #163. #164/#143 fleet evidence still applies before this
compatibility surface could be admitted to a production migration.
`MAX_SESSION_TTL` controls session/lease state only; it does not define
certificate expiry, trust-bundle validity, or authentication age. The direct
wire-schema revision-6 upgrade remains a coordinated drained
stop/upgrade/start; only subsequent credential rotations within a uniform
revision-6 fleet use seamless lifecycle recycling.

A successful restore page may be shorter than requested to respect the backend
4 MiB payload, 8 MiB retained-page, 8 MiB examined key/filter metadata, or
4,096 examined-candidate budget; a narrow scope may yield an empty page with
an advancing cursor. Follow the confidential authenticated `next_cursor` until
the issuer reports `complete`. Compatibility peer validation checks bounds,
order, scope, cursor shape, and claimed progress; it cannot prove that an
authenticated server did not omit a record or falsely report completion.
Production completeness comes only from scanning the barrier-confirmed local
Openraft-applied state. A page that
cannot fit the effective wire frame returns `RestoreScanResponseTooLarge` and
is retried from the same cursor with a smaller record limit.

Wire-schema revision 3 retains revision 2's negotiated response budget and
adds the AES-256-GCM-SIV snapshot-bound cursor, explicit durable-page profile,
and typed stale/work-budget outcomes. Offset cursors from the local fake are
rejected on this remote surface. The client
Hello requests its response-frame limit; HelloAck returns the accepted
client/server minimum and the server's separate request-frame limit. All three
values are checked `u32` values of at least
`MIN_NEGOTIATED_FRAME_SIZE` (8 KiB, or 8,192 bytes) and at most
`MAX_NEGOTIATED_FRAME_SIZE` (16 MiB, or 16,777,216 bytes).
`MIN_RESTORE_SCAN_RESPONSE_FRAME_SIZE` aliases that minimum. Configure each side
for its real receive capacity; unequal limits are supported and must not be
silently treated as symmetric. The server first allows one configured idle
timeout to receive and decode a complete frame. Backend admission and work then
use `with_backend_operation_timeout`; the server reserves a second idle-timeout
interval for response preparation and delivery. Checked addition of the latter
two forms the post-decode lifetime, while full connection-slot occupancy has
all three bounded phases. Configure `with_backend_operation_concurrency` from measured
backend capacity. Reads, mutations, leases, and watch setup have independent
pools, so pressure in one family cannot consume another family's admission.
Server startup rejects invalid resource configuration before bind/spawn:
frame limits outside 8 KiB..=16 MiB, zero/unsupported connection-slot
counts, and unrepresentable idle/restore timeouts return `InvalidInput`. Zero
timeouts are valid immediate-fail settings.

Every response and watch item is fully bounded-encoded before the prefix is
written. Common non-pageable and complete-page successes use one bounded encode
without a sizing preflight. An oversized pageable direct attempt emits no
prefix; bounded logarithmic sizing probes and the final encode reuse the same
absolute deadline established before the first encode/probe and continuing
through socket delivery. This SDK uses lazy exact-length boxed chunks without a
coalescing copy; retained encoded-JSON byte storage stays within the negotiated
cap, while chunk metadata and allocator slab/RSS overhead remain separate.
Storage/sizing sinks check deadline and server-abort cancellation cooperatively
between serializer writes/chunks; one bounded synchronous serializer callback
is not asynchronously preemptible.
Operationally:

- never expect get/CAS records or positional batch results to be truncated;
- continue restore pages by `next_cursor` and log pages by the next contiguous
  sequence when the server returns a shortened complete prefix;
- treat an over-limit watch item as a stream-ending gap, reconnecting from the
  last delivered sequence rather than skipping it; and
- treat a fixed SDK-owned fallback or a connection close as fail-closed. If a
  fallback cannot fit, the server emits no oversized/partial frame.

Capabilities clamp `max_value_bytes` to the backend maximum and
`(frame - 8192) / 8` for both the accepted response and server request frames.
The reserve and factor cover the record/key/error envelope, worst-case JSON
byte-array expansion, and equal escaping/metadata headroom. Admission tests must
prove a value at exactly the advertised maximum can be written and read across
unequal limits. At the exact 8 KiB minimum the conservative payload maximum is
zero; use a larger configured frame for payload-bearing traffic. Raw frame size
is not an acceptable payload-capability value. The 1 MiB default advertises
130,048 bytes and the 16 MiB ceiling advertises 2,096,128. SQLite's full 1 MiB
limit needs at least 8,396,800 frame bytes, so configure 16 MiB for that
profile. This is a per-frame limit: at the server's default 128 connection
slots, simultaneous ceiling-sized encodes can retain about 2 GiB before
metadata/TLS/runtime overhead. The aggregate scales with
`with_max_connections`; #143 owns aggregate byte permits and distributed
resource/soak qualification.

The exact `opc-session-net/5` ALPN, version, and contract profile have no
fallback or highest-common-version downgrade. Treat the v5 transition as a coordinated
outage: drain session traffic and writers; run the identity audit and complete
handover/nested-payload preflights; stop every session-net client, server, and
protection wrapper plus every product handover reader/writer; upgrade them
together; verify v5 authenticated handshakes, empty/multi-page restore scans,
an empty advancing page across more than 4,096 excluded candidates, modified-
cursor rejection, cursor restart after mutation, resume after process restart,
bounded maximum-payload get/CAS/batch/log/restore/watch traffic, slow-reader slot
recovery, and fresh quorum evidence on each replica; then
restore traffic. Do not perform a mixed-version rolling upgrade.

Public `Request`/`Response` remain, but `Hello`/`HelloAck` gain optional
`contract_profile` and `configuration_epoch`; `HelloAck` adds
`cas_idempotency_epoch`, and direct CAS adds `idempotency_epoch`. Exhaustive
construction and matching must account for the fields. Private v5 DTOs use
`u32` for restore/log request limits and the
client restore response budget; a confidential authenticated restore cursor;
`u64` for
excluded counts, `max_value_bytes`, and size-bearing store errors; and checked
conversion before dispatch/exposure. Restore `loaded_count` and `complete` are
recomputed rather than trusted from the peer. Independent limits are 256 batch
operations, 1,024 restore records, 4 MiB of restore payload and 4,096 examined
live candidates per page, 65,536 log entries, and 65,536 rebuild entries; the
configured frame bound remains
separate. #159 now enforces that negotiated bound and one
absolute write deadline across every ordinary response/watch item. The profile
pins wire-schema revision 6, error-set revision 8,
`max_restore_scan_examined_rows = 4096`,
`min_frame_size = 8192`, `max_frame_size = 16777216`, 128-byte
owner/custom-key/state-type bounds,
`stable_id_max_bytes = 64`, `replication_tx_id_max_bytes = 128`,
`cas_request_id_bytes = 36`, the 31,536,000-second TTL maximum, and
depth-16/256-node trees. Stable IDs contain 1 through 64 bytes, replication
transaction IDs contain 1 through 128 UTF-8 bytes, and CAS request IDs, when
present, are canonical lowercase hyphenated UUIDs with the exact 36-byte encoding. A
revision-4/error-revision-7 or older participant is incompatible, so that
profile transition also requires the coordinated
stop/upgrade/start above. `ContractProfile::max_frame_size` is a public Rust
source break for external struct literals/destructuring and must be updated in
that same transition.

Opening an existing SQLite store adds only the 32-byte
`restore_scan_state.cursor_key` metadata field and does not backfill session
records. Verify that O(1) migration on every replica before traffic admission.
A consensus snapshot created before revision 3 lacks the cursor key and is not
an installable revision-3 repair source; after the coordinated upgrade, take
and validate a fresh coherent snapshot before declaring rollback/recovery
coverage.

Restore cursors are backend-incarnation/node-bound. A same-PVC process restart
retains the cursor key and epoch and can resume a page. Another node or an
installed snapshot has a different cursor incarnation and returns typed
`RestoreScanCursorStale`; the operator/CNF must discard partial pagination and
restart from the first page. Do not merge pages across nodes or snapshots.
The model-wide 64-byte stable-ID bound keeps the complete hex cursor below
2 KiB, so it fits session-net's minimum frame. The compatibility server still
returns typed `RestoreScanResponseTooLarge` without writing a partial frame for
an otherwise oversized page.

A mutation may commit before response encoding or delivery fails. A disconnect,
oversize fallback, or write timeout is an ambiguous result, not rollback proof.
The same rule applies to backend execution timeout or client cancellation after
request transmission. `BackendOperationOutcomeUnavailable` and lease
`OperationOutcomeUnavailable` are non-retryable: re-read authoritative state,
treat lease authority as lost, and derive a new action. A pre-transmission
connect/handshake failure remains known not applied. Never configure an outer
client retry layer to replay delete, refresh, mutating batch,
replication/rebuild, acquire, renew, or release.
For direct CAS on the quarantined compatibility transport, the server binds the
canonical UUID to the authenticated logical peer, complete operation,
cluster/configuration identity and monotonic epoch, and the process-scoped
`cas_idempotency_epoch` returned by `HelloAck`. Exact success/conflict retries
inside the bounded window replay once; mismatched reuse is
`CasIdempotencyConflict`. Restart, retention rotation, pressure, or cancelled
execution is `CasIdempotencyOutcomeUnavailable` before any historical request
can be treated as new. The public client never automatically resubmits an
ambiguous CAS. CNFs must authoritatively re-read and derive a new mutation;
blindly replaying the operation under the old or a fresh UUID is unsafe.

The server bounds the cache to 4,096 entries and 32 MiB total, 512 entries and
8 MiB per authenticated peer, and 64 cleanup inspections per request. Results
remain replayable for five minutes, then become ambiguous tombstones; after a
further ten minutes the process epoch rotates and cleanup clears the cache only
with no CAS in flight. One peer cannot evict another peer's active window.
These are compatibility-transport safeguards, not a substitute for Openraft's
atomically persisted production request outcomes.
Direct-CAS rejection diagnostics are limited to `stale_epoch`,
`identity_reuse`, `ambiguous`, and `capacity`. They must not carry peer or
certificate identity, request UUID, digest, key, owner, lease, record, or
payload fields.

Alert and metric dimensions for outbound delivery must use the finite response
families and fixed reasons `frame_too_large`, `page_shortened`, `write_timeout`,
`transport`, and `encoding`. Do not log or label keys, payloads, owners,
transaction/request IDs, SPIFFE IDs, backend error strings, or peer-controlled
text. Qualification must demonstrate repeated
oversize and authenticated slow-reader campaigns keep memory, tasks, file
descriptors, CPU, and connection slots bounded and that shutdown barriers still
complete.
Also alert on
`opc_session_net_backend_lifetime_events_total{event="execution_timeout"}` and
`{event="ambiguous_outcome"}`. Queue timeout, cancellation, and peer-disconnect
events are fixed labels in that same family; no key, owner, peer, request ID, or
backend text is permitted.

Restore runbook evidence must record low-cardinality counters/histograms for
page outcome, `cursor_profile`, `complete`, loaded records, excluded/examined
candidates, payload bytes, elapsed time, and typed restart reason
(`stale_cursor`, `work_budget`, `response_too_large`, `cancelled`). Alert when
stale/work-budget restarts repeat, a scan makes no cursor progress, or restore
latency consumes the CNF RTO. An empty page is healthy only when it carries a
different durable cursor and the examined count is nonzero. On a stale cursor,
discard all partial restore results and restart at page one after fresh
Openraft readiness; never splice snapshots. On cancellation or deadline, wait
for the SDK call to finish releasing its SQLite worker before retrying. SQLite
admits one clone-shared blocking restore worker per backend before
`spawn_blocking`; a timed-out waiter spawns no worker, while the admitted worker
retains its permit until its cancellation callback exits. These
labels must never contain cursor bytes, tenant/NF/key fields, owner, payload,
database path, peer text, or certificate identity.

A fresh version/profile/authentication or malformed-handshake failure clears
the capability cache and reports every boolean false with
`max_value_bytes = 0`. A cache retained after transient transport loss is
descriptive only and cannot authorize an operation, readiness, or traffic.

DNS, FQDN, IP, and resolver aliases control only the dial address. They must
not be used to derive or rewrite the logical `ReplicaId` or expected SPIFFE
identity. Rotate a certificate only to another SVID carrying the same exact
manifest identity. A descriptor change produces a new configuration ID; bump
the generation for security-relevant configuration outside the descriptor set.
Either scope change requires another coordinated rollout.

This is not production HA qualification. Do not infer readiness from bind
success, static profiles, or cached capabilities; use the fresh bounded probe
and continuous gate. #127 now provides Openraft commit authority and #133
provides bounded snapshot-bound applied-state restore. Do not treat divergence
repair outside #128's current-format rules or apply those rules to a legacy
fork. Use only #129's
[explicit offline procedure](session-store-legacy-recovery.md). Protocol
identity/fixed-width binding is not fork recovery. #135's invariant-safe model decoding
and bounded offline identity audit and #134's fixed-width DTOs are implemented.
Checked TTL and sequence boundaries now fail closed under #137/#138, and
bounded nested protected-payload traversal is implemented under #147. Absolute
record expiry is bounded under #148 with coordinator-authored time and a
versioned offline audit/migration path. Watch handoff is implemented. Outbound
slow-reader and response-frame enforcement is implemented
under #159. #167 now makes the 1..=64-byte stable-ID invariant structural across
the complete model/store/network stack and supplies the privacy derivation plus
current version-4 count-only migration audit; use
[`session-store-stable-id-migration.md`](session-store-stable-id-migration.md)
before rollout. #168 implements the bounded durable `ReplicationEntry`
transaction-ID type, canonical 32-byte coordinator mint, exact legacy
preservation, and relational/JSON consistency audit. Follow the
[`transaction-ID migration runbook`](session-store-replication-tx-id-migration.md)
and coordinate cutover with #127/#128/#143. The shared
session-net call deadline and `ConsensusConfigStore`'s complete
routing/quorum/commit/apply operation deadline remain separate bounded layers;
the removed private config TCP timeout is not a production setting. A renewed
SVID rotation has scoped real-mTLS qualification. #161 atomic reload, #162
coherent material epochs, and #163 finite connection retirement are
implemented; complete fleet trust removal, short-lived-SVID expiry/root-cutover,
reconnect-storm, and multi-process continuity evidence remains #164 under
umbrella #158. Immediate generic CRL/OCSP/certificate-or-identity-denylist
revocation remains unsupported. The remaining distributed/payload-key
production evidence stays open in #143.

#167 does not rewrite persisted session-store bytes. In-profile stable IDs need
no format conversion, but a retained empty/over-64-byte/non-BLOB stable ID or
empty/over-128-byte UTF-8 transaction ID cannot cross strict revision-2
transport. Before startup, quiesce writers and inventory all records, logs,
snapshots, restore sources, and replay sources. Any violation needs a
decoder-first, product-aware migration or coherent store replacement under the
#167 runbook and #168: the migration reader must decode the legacy representation before
rewrite, must not truncate/hash/rename durable identities, and the strict
decoder must verify the result before writers restart. Rollback must first
install a decoder capable of reading the retained target representation, or use
a coherent checkpoint/reviewed reverse migration. Every session-net participant
still returns together to one exact current profile; mixed revisions fail
closed. Rollback across `OPCH`/#135 retains its independent checkpoint/reverse-
migration requirement.

## Operator-facing SDK surfaces available now

| Surface | Current operator contract | Evidence |
|:---|:---|:---|
| Runtime profile and bootstrap | `RuntimeProfile` defaults to production mode. `BootstrapConfig::from_env` reads `NF_KIND`, `INSTANCE_ID`, `RUNTIME_MODE`, `ADMIN_BIND`, `LOG_LEVEL`, and `CONFIG_SOURCE`; `BootstrapConfig::apply_fail_closed` rejects production startup without an explicit config source. | `crates/opc-runtime/src/profile.rs`, `crates/opc-runtime/src/bootstrap.rs`, `docs/rfc/008-cnf-runtime-chassis.md` |
| Health and readiness model | The SDK provides the RFC 008 health model for `/livez`, `/readyz`, and `/startupz` semantics, along with gated debug/admin routes `/debug/runtime`, `/debug/tasks`, and `/debug/config-version`. The HTTP admin/probe/debug routes are fully authorized under token authorization in Production/Lab mode. | `crates/opc-runtime/src/health.rs`, `crates/opc-runtime/src/admin.rs`, `docs/implementation-status.md#known-gaps` (`GAP-008-002`) |
| Config authorization & apply example | `opc-config-bus` implements `ConfigAuthorizer` checking at the admission boundary, and the toy config integration registers a custom `NacmAuthorizer` hook to enforce NACM policy before validation, persistence, or subscriber notification. | `crates/opc-config-bus/src/lib.rs`, `crates/opc-config-fixture/tests/config_fixture_commit.rs` |
| Config persistence encryption and audit integrity | `EncryptingManagedDatastore` seals persisted config records with shared envelope helpers and AAD-bound tenant/schema/version metadata. Durable `SqliteBackend` opens require an explicit non-zero `AuditKey`, and stored audit chains are verified on load after sensitive audit values are redacted before storage. | `crates/opc-config-bus/src/lib.rs`, `crates/opc-config-bus/tests/encryption.rs`, `crates/opc-persist/src/backend/mod.rs`, `crates/opc-persist/tests/persist_sqlite.rs`, `crates/opc-persist/tests/persist_ops.rs`, `crates/opc-persist/tests/persist_audit.rs` |
| Alarm admin authorization & auditing | `opc-alarm` provides `NacmAlarmAuthorizer` and `PersistAlarmAuditSink` adapters to authorize alarm ack/suppress actions against NACM policy and an explicit operator-principal allowlist, then log audit events durably to the persistence SQLite database with automatic sensitive data redaction. | `crates/opc-alarm/src/nacm_adapter.rs`, `crates/opc-alarm/src/persist_adapter.rs`, `crates/opc-alarm/tests/adapters.rs` |
| Session persistence encryption | `EncryptingSessionBackend` or `RemoteSealingSessionBackend` must wrap `ConsensusSessionStore`, so payloads are sealed before Openraft submission and decrypted only above consensus. Remote unseal selects the exact validated envelope key ID; process-local active publication changes only future seals, while KMS/HKMS owns historical retention/revocation. The SDK has no retirement API or enforcement gate. Raft logs, state, outcomes, peer frames, and snapshots carry opaque envelopes; HKMS/KMS provider calls and key handles stay outside deterministic apply. This is payload-envelope protection, not full SQLite metadata/file encryption. | `crates/opc-key/src/remote.rs`, `crates/opc-key/src/kms.rs`, `crates/opc-session-store/src/backend.rs`, `crates/opc-session-store/src/consensus/store.rs`, `crates/opc-session-store/src/sqlite/consensus.rs`, `crates/opc-session-store/tests/encryption.rs`, `crates/opc-session-store/tests/consensus_openraft.rs`, `crates/opc-session-store/src/consensus/store/encryption_tests.rs` |
| Runtime alarms | `SharedAlarmManager` is used by runtime supervision and config-bus failure paths; toy NF integration uses the runtime-owned manager rather than separate toy glue. | `crates/opc-runtime/src/supervisor/mod.rs`, `crates/opc-config-bus/src/lib.rs`, `crates/opc-sdk-integration/tests/toy_runtime.rs` |
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

The SDK includes Openraft-backed config and session adapters:
`ConsensusConfigStore` in `opc-persist` and `ConsensusSessionStore` in
`opc-session-store` (`QuorumSessionStore` is its compatibility alias). They
have distinct deterministic state machines but one consensus authority through
`opc-consensus`; neither domain retains a custom quorum engine.

The standard SQLite-backed config and session store profiles (`SqliteBackend` and `SqliteSessionBackend`) are single-node only. They are acceptable only for development, conformance, lab, or explicitly accepted edge/single-replica deployments, and must not be used to claim carrier HA without a production consensus/replication layer.

- **Config Store Commit Authority**: `ConsensusConfigStore` uses Openraft for
  election, term/vote persistence, log matching, quorum commit, membership,
  linearizable reads, and snapshots. Its SQLite adapter admits only sealed
  config envelopes and redacted finalized audit, fences every standalone write
  after an atomic authority claim, persists idempotent outcomes, and supports
  exact offline legacy recovery by checksum, applied head, and explicit
  unknown-suffix discard. In-process tests cover formation, partition/heal,
  failover, response loss, snapshots, and migration; an AMF-lite integration
  adds provider-backed outer encryption, key rotation, follower/snapshot/restart
  isolation, and durable plaintext/raw-key/provider canary scans.
  This qualifies the three-node HKMS boundary. `GAP-001-006` remains open for
  remote-HKMS, out-of-process/deployed-network compatibility, multi-process
  restart/rejoin, resource, soak, seamless fleet trust-lifecycle, and release
  evidence. In-process three-node real-mTLS config formation, commit, and
  linearizable-read integration is present through the shared transport.
- **Session Store Commit Authority**: `ConsensusSessionStore` uses the shared
  Openraft engine for elections, voting, log matching, committed membership,
  snapshot coordination, and linearizable reads. Its SQLite state machine owns
  deterministic session semantics and exposes journal/watch changes only after
  apply. #127, #128, #129, and #133 are implemented; #143 remains the
  distributed-qualification gate.
- **Session Topology, Identity, and Readiness**: HA construction requires one
  immutable descriptor set, explicit logical self, configuration digest, and
  positive epoch. Stable node IDs derive from cluster plus logical
  `ReplicaId`; endpoints and FQDNs are routing only. The dedicated
  `opc-session-consensus/2` mTLS profile binds SPIFFE, logical/stable IDs,
  cluster/configuration/epoch, peer role, and nonce. `probe_durable_readiness`
  uses an Openraft linearizable barrier and local-apply wait, not bind or cached
  capability evidence. Its exact profile uses transport/wire-schema revision 2
  and error-set revision 4, including the bounded payload-free expiry
  authority preflight and `RecordExpiryPreflightLimitExceeded`.
  Revision-1/error-revision-3-or-older peers fail before dispatch and all
  consensus members must be upgraded together while traffic is drained.
- **Fault Coverage**: Tests cover concurrent pristine formation, cross-node
  lease/CAS visibility, follower linearizable reads, partition-bounded failure
  and rejoin, restart, delivered-but-lost response idempotency, replacement of
  repeated uncommitted tails above an immutable committed prefix, stale and
  cross-identity snapshot rejection, corrupt-snapshot restart, and interrupted
  staging cleanup. File-backed recovery tests additionally cover #129's
  two-branch/three-branch legacy campaigns, full-fleet backup-before-mutation,
  failpoint resume, pending-epoch fencing, and legacy cursor invalidation.
  These are not #143 distributed production qualification.
- **SQLite Writer Envelope**: Each node persists Openraft vote/log/membership,
  committed/applied positions, deterministic state, outcomes, and bounded
  snapshots in its own SQLite-backed store. Standalone `SqliteSessionBackend`
  remains single-node and is not HA.
- **Capability Envelope**: Static backend feature declarations remain
  admission evidence only. Require the Openraft readiness barrier plus
  continuous traffic gating; do not derive authority from `capabilities()` or
  the availability of a restore-scan method.
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
  - RFC 001 config consensus has one Openraft authority, atomic local migration,
    encryption-boundary, and in-process failure evidence, but carrier HA
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
