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
carrier HA qualification. `ConsensusConfigStore` remains a separate durable
config-consensus prototype. For session state, #127 replaces the former custom
majority-visible-log coordinator with `ConsensusSessionStore`, backed by the
workspace's shared Openraft engine; `QuorumSessionStore` is a compatibility
type alias for that implementation, not a second authority path. This closes
the durable sequencing/commit-authority implementation gap, but it is not a
production-profile claim until the recovery, restore, lifecycle, and
distributed qualification gates listed below pass.

### Config consensus RPC and identity-lifecycle contract

For `opc-persist` config consensus, configure every `TcpPeer` timeout (or the
test-node `--rpc-timeout` value) as one end-to-end logical RPC deadline. The
same absolute budget covers local authentication/TLS setup locks, bounded
cooperative serialization, TCP connect, mTLS, request write, response
length/body reads and decode, all attempts, and 50/100 ms retry backoff. Zero
expires before I/O; an unrepresentable monotonic-clock duration fails closed.
Do not multiply this value by transport stages or retries when sizing an
election: voting-peer requests fan out concurrently. Do budget as much as
`128 * rpc-timeout`, plus local database/scheduling overhead, for one lagging
peer's bounded catch-up pass: there are 64 rounds and a rejected snapshot can
fall through to one append in the same round. A later trigger resumes from
`next_index` after the 64-round ceiling.

Treat this as a coordinated upgrade setting. Earlier SDKs reset the configured
timeout for each I/O stage; the same numeric value can therefore produce a much
shorter failure window after this change. Retune it as an end-to-end budget,
update election/failover/drain thresholds, and roll out the selected value
coherently across cluster members. Rust integrations that exhaustively match
the public `PersistErrorKind` must add `ConsensusRpcTimeout`.

Retries preserve the request's safety semantics. RequestVote, AppendEntries,
InstallSnapshot, LoadLatest, and LoadRollback may replay after ambiguous
delivery. TimeoutNow may already have launched a campaign, so it is not replayed
after any bytes may have reached the peer. Invalid local identity/TLS setup and
certificate-verification failures are permanent for the call and must not be
reported as logical timeouts.

Operators should alert from `rpc_timeouts` and its fixed
`rpc_timeouts_by_family`/`rpc_timeouts_by_stage` dimensions. Those maps use
bounded request-family and stage keys; do not add replica IDs, endpoints,
SPIFFE identities, tenants, or request fields as labels. A timeout on the
client closes that attempt, but it does not create a server-wide post-handshake
I/O deadline. `TcpRpcServer` currently applies five seconds only to TLS
acceptance; request reads and response writes are frame-bounded and need a
separate server-side slow-client bound before that property can be claimed.

A production CNF must also own seamless identity rotation. Watch the live SVID
and trust bundle and call `set_identity`; the `opc-consensus-node` test binary
loads PEM files only at startup. Roll out old/new trust overlap first, then
rotate leaves while preserving the exact SPIFFE workload profile and node
instance, drain old connections, verify fresh handshakes across the quorum, and
remove old trust only after the maximum authentication age. Gate traffic and
readiness through the transition and bound reconnect storms. Replacing leaf and
trust material simultaneously without overlap is not a supported seamless
rotation procedure.

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
     --max-total-json-bytes N
   ```

3. Require all three numeric budgets to be non-zero and require the per-entry
   JSON budget not to exceed the total JSON budget or SQLite's signed `i64`
   length range. Size `--max-rows` for the
   combined row count across `session_records`, `leases`, `key_fences`, and
   `session_replication_log`, not per table.
4. Accept only report schema version 1 with `status = compliant` and process
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
   authenticated v4 handshakes, restore/log reads, and fresh quorum gate, then
   restore traffic.

The command opens only an existing database in read-only/query-only mode and
scans one consistent snapshot in fixed 256-row pages. `--max-rows` bounds all
audited rows; `--max-entry-json-bytes` and `--max-total-json-bytes` bound strict
decode of the individual and cumulative replication JSON. Version-1 output is
count-only: supplied limits, per-table scanned counts, invalid-owner,
invalid-key-type, and invalid-replication-entry counts, plus an optional bounded
incomplete reason. It does not print the database path, row IDs, tenant, owner,
key type, stable ID, transaction, payload, or raw JSON.

An incomplete reason is one of `row_budget_exceeded`,
`entry_json_budget_exceeded`, `total_json_budget_exceeded`,
`unsupported_schema`, `database_read_failed`, or `counter_overflow`. Increase
budgets and rerun when safe; for a violation, use a separately reviewed,
product-owned migration that preserves identity and authoritative-history
semantics, or replace the store and follow the product recovery procedure.
Neither the audit nor runtime automatically truncates, renames, normalizes,
deletes, repairs, or rewrites invalid state. Re-audit the final snapshot before
starting the new SDK.

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
Protocol v4 encodes them through private fixed-width DTOs under error revision
1; an older v3 decoder is rejected during exact negotiation. Use the coordinated
v4 rollout below before relying on typed responses.

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
experimental profile. Seamless SVID rotation, payload-protection key rotation,
and trust-bundle rotation remain separate mandatory production gates.

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

### Tested HA algorithm and prototype features

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
6. **Remaining Qualification**: #128 must reconcile a diverged replica from
   committed authority; #129 must provide operator-safe legacy-fork recovery;
   #133 must make restore scans bounded and majority-authoritative; and #143
   must supply distributed partition/restart/resource/soak and payload-key
   qualification. Until those land, this is implemented commit authority, not
   production HA qualification.

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
qualify it without bypassing the wrapper. #179 owns seamless remote-seal
historical-key selection; #143 owns distributed payload-protection evidence;
the transport certificate rotation chain is separate.

### Session consensus transport and identity

The production #127 path uses `SessionConsensusServer` and
`RemoteSessionConsensusPeer` on the exact `opc-session-consensus/1` ALPN. This
listener owns only a `SessionConsensusRpcHandler`: it cannot dispatch direct
session-backend mutation, raw replication-log append, restore rebuild, or lease
sequencing. Legacy `opc-session-net/4` direct-backend networking is a
non-default compatibility feature and must not share the production consensus
listener.

Every connection performs a fresh mutual-TLS handshake. Before an Openraft RPC
is dispatched, both sides bind the canonical certificate SPIFFE URI, logical
`ReplicaId`, derived stable node ID, expected opposite peer, cluster ID,
configuration digest, configuration epoch, consensus role, exact transport
profile, and a fresh challenge. The authenticated sender in the outer request
must also match the sender encoded in the bounded Openraft payload. DNS, FQDN,
short hostname, IP, and resolver aliases select only the dial route. They never
select self, a vote, or a certificate identity.

Each call has one absolute deadline covering admission, resolution, connect,
TLS, handshake, bounded encoding, write, and response read. Authentication or
identity mismatch fails before engine dispatch. The outer consensus frame is
bounded for the shared compact Openraft payload; transport code does not decode
commands or make consensus decisions.

Fresh handshakes make renewed credentials observable, but seamless operation
during rotation is not yet qualified. The remaining dependency order is #162
(bounded material epochs), #161 (atomic identity/trust reload), #163 (peer
reauthentication across an epoch), #158 (seamless rotation), and #164
(rotation qualification). A production CNF must keep old/new trust overlapped,
retire old connections, enforce revocation and maximum authentication age, and
bound reconnect storms; #143 still owns the wider distributed qualification.

### Legacy direct-backend session-net v4 rollout boundary

The opt-in legacy `opc-session-net` v4 surface carries cursor-paged remote
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

Full handshakes make renewed credentials observable, but they are not proof of
seamless rotation. The #162 -> #161 -> #163 -> #158 -> #164 rotation chain and
#143 distributed qualification apply before this compatibility surface could
be admitted to a production migration. `MAX_SESSION_TTL` controls
session/lease state only; it does not define
certificate expiry, trust-bundle validity, or authentication age.

A successful restore page may be shorter than requested to fit the effective
client/server frame limit; follow `next_cursor` until `complete`. A single
record that cannot fit returns `RestoreScanResponseTooLarge`.

Wire-schema revision 2 negotiates the response budget explicitly. The client
Hello requests its response-frame limit; HelloAck returns the accepted
client/server minimum and the server's separate request-frame limit. All three
values are checked `u32` values of at least
`MIN_NEGOTIATED_FRAME_SIZE` (8 KiB, or 8,192 bytes) and at most
`MAX_NEGOTIATED_FRAME_SIZE` (16 MiB, or 16,777,216 bytes).
`MIN_RESTORE_SCAN_RESPONSE_FRAME_SIZE` aliases that minimum. Configure each side
for its real receive capacity; unequal limits are supported and must not be
silently treated as symmetric. The server's configured idle timeout is one
absolute deadline for response preparation and delivery.
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

The exact `opc-session-net/4` ALPN, version, and contract profile have no v3
fallback or highest-common-version downgrade. Treat v3-to-v4 as a coordinated
outage: drain session traffic and writers; run the identity audit and complete
handover/nested-payload preflights; stop every session-net client, server, and
protection wrapper plus every product handover reader/writer; upgrade them
together; verify v4 authenticated handshakes, empty/multi-page restore scans,
bounded maximum-payload get/CAS/batch/log/restore/watch traffic, slow-reader slot
recovery, and fresh quorum evidence on each replica; then
restore traffic. Do not perform a mixed-version rolling upgrade.

Public `Request`/`Response` remain, but `Hello`/`HelloAck` gain an optional
`contract_profile`, so exhaustive construction and matching must account for
the field. Private v4 DTOs use `u32` for restore/log request limits and the
client restore response budget; `u64` for restore cursors/excluded counts,
`max_value_bytes`, and size-bearing store errors; and checked conversion before
dispatch/exposure. Restore `loaded_count` and `complete` are recomputed rather
than trusted from the peer. Independent limits are 256 batch operations, 1,024
restore records, 65,536 log entries, and 65,536 rebuild entries; the configured
frame bound remains separate. #159 now enforces that negotiated bound and one
absolute write deadline across every ordinary response/watch item. The profile
pins wire-schema revision 2, error-set revision 1,
`min_frame_size = 8192`, `max_frame_size = 16777216`, 128-byte
owner/custom-key/state-type bounds,
`stable_id_max_bytes = 64`, `replication_tx_id_max_bytes = 128`,
`cas_request_id_bytes = 36`, the 31,536,000-second TTL maximum, and
depth-16/256-node trees. Stable IDs contain 1 through 64 bytes, replication
transaction IDs contain 1 through 128 UTF-8 bytes, and CAS request IDs, when
present, are canonical lowercase hyphenated UUIDs with the exact 36-byte encoding. A
revision-1 v4 participant is incompatible despite
sharing the same ALPN, so that profile transition also requires the coordinated
stop/upgrade/start above. `ContractProfile::max_frame_size` is a public Rust
source break for external struct literals/destructuring and must be updated in
that same transition.

A mutation may commit before response encoding or delivery fails. A disconnect,
oversize fallback, or write timeout is an ambiguous result, not rollback proof.
CNFs must recover through request-ID/idempotency and fencing semantics, then
authoritatively re-read before retrying; blindly replaying lease or mutation
requests is unsafe.

Alert and metric dimensions for outbound delivery must use the finite response
families and fixed reasons `frame_too_large`, `page_shortened`, `write_timeout`,
`transport`, and `encoding`. Do not log or label keys, payloads, owners,
transaction/request IDs, SPIFFE IDs, backend error strings, or peer-controlled
text. Qualification must demonstrate repeated
oversize and authenticated slow-reader campaigns keep memory, tasks, file
descriptors, CPU, and connection slots bounded and that shutdown barriers still
complete.

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
and continuous gate. #127 now provides Openraft commit authority, but do not use
restore results as majority authority before #133, treat divergence repair as
implemented before #128, or auto-resolve a legacy fork before #129. Protocol
identity/fixed-width binding is not fork recovery. #135's invariant-safe model decoding
and bounded offline identity audit and #134's fixed-width v4 DTOs are implemented.
Checked TTL and sequence boundaries now fail closed under #137/#138, and
bounded nested protected-payload traversal is implemented under #147. Watch
handoff and absolute-record-expiry admission remain
#145/#148. Outbound slow-reader and response-frame enforcement is implemented
under #159, but its stable-ID and transaction-ID limits are wire containment
only. The production stable-ID model/persistence/privacy/audit/migration remains
#167; the canonical durable `ReplicationEntry` transaction-ID type and migration
remain #168 and must be coordinated with #127/#128/#143. Session-net's response
deadline is independent of `opc-persist`'s already-implemented #169
`TcpPeer::timeout` contract: one atomic end-to-end logical-RPC deadline covers
its attempts and backoff, with safe retry and bounded metrics. Seamless
SVID/trust-bundle lifecycle remains
#162 -> #161 -> #163 -> #158 -> #164, while the remaining
distributed/payload-key production evidence stays open in #143.

#159 does not rewrite persisted session-store bytes. In-profile stores need no
format conversion, but a retained empty/over-64-byte stable ID or
empty/over-128-byte UTF-8 transaction ID cannot cross strict revision-2
transport. Before startup, quiesce writers and inventory all records, logs,
snapshots, restore sources, and replay sources. Any violation needs a
decoder-first, product-aware migration or coherent store replacement under
#167/#168: the migration reader must decode the legacy representation before
rewrite, must not truncate/hash/rename durable identities, and the strict
decoder must verify the result before writers restart. Rollback must first
install a decoder capable of reading the retained target representation, or use
a coherent checkpoint/reviewed reverse migration. Every session-net participant
still returns together to one exact revision-1 profile; mixed revisions fail
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
| Session persistence encryption | `EncryptingSessionBackend` or `RemoteSealingSessionBackend` must wrap `ConsensusSessionStore`, so payloads are sealed before Openraft submission and decrypted only above consensus. Raft logs, state, outcomes, peer frames, and snapshots carry opaque envelopes; HKMS/KMS provider calls and key handles stay outside deterministic apply. This is payload-envelope protection, not full SQLite metadata/file encryption. | `crates/opc-session-store/src/backend.rs`, `crates/opc-session-store/src/consensus/store.rs`, `crates/opc-session-store/src/sqlite/consensus.rs`, `crates/opc-session-store/tests/consensus_openraft.rs`, `crates/opc-session-store/src/consensus/store/encryption_tests.rs` |
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

The SDK includes a config-store consensus hardening prototype
(`ConsensusConfigStore` in crate `opc-persist`) and an Openraft-backed session
authority (`ConsensusSessionStore` in crate `opc-session-store`;
`QuorumSessionStore` is its compatibility alias). These are currently distinct
authority implementations; migrating config HA to the shared `opc-consensus`
engine is tracked separately and must be completed before claiming a
workspace-wide one-engine production profile.

The standard SQLite-backed config and session store profiles (`SqliteBackend` and `SqliteSessionBackend`) are single-node only. They are acceptable only for development, conformance, lab, or explicitly accepted edge/single-replica deployments, and must not be used to claim carrier HA without a production consensus/replication layer.

- **Config Store Consensus Hardening**: `ConsensusConfigStore` provides durable
  membership, TCP RPC framing over real mTLS transport with SPIFFE identity
  verification bound to the configured workload profile and active membership,
  one absolute client logical-RPC deadline, request-aware retry ambiguity
  handling, concurrent peer fan-out, bounded/resumable 64-round per-peer
  catch-up (at most two RPCs per round), no-op commit safety, snapshot HMAC
  verification, a server lifecycle with 100-handler concurrency and a
  five-second TLS-accept timeout, membership-change guardrails, and
  fixed-family/stage timeout metrics. Post-handshake server reads/writes remain
  frame-bounded without an independent server I/O deadline, and production
  CNFs must supply live identity watching plus trust-overlap rotation. Checked
  via out-of-process campaigns, failovers, network partitioning, pending
  commits surviving restarts, deterministic transport stalls/cancellation, and
  catch-up resume tests.
- **Session Store Commit Authority**: `ConsensusSessionStore` uses the shared
  Openraft engine for elections, voting, log matching, committed membership,
  snapshot coordination, and linearizable reads. Its SQLite state machine owns
  deterministic session semantics and exposes journal/watch changes only after
  apply. #127 is implemented; #128/#129/#133/#143 remain qualification and
  recovery gates.
- **Session Topology, Identity, and Readiness**: HA construction requires one
  immutable descriptor set, explicit logical self, configuration digest, and
  positive epoch. Stable node IDs derive from cluster plus logical
  `ReplicaId`; endpoints and FQDNs are routing only. The dedicated
  `opc-session-consensus/1` mTLS profile binds SPIFFE, logical/stable IDs,
  cluster/configuration/epoch, peer role, and nonce. `probe_durable_readiness`
  uses an Openraft linearizable barrier and local-apply wait, not bind or cached
  capability evidence.
- **Fault Coverage**: Tests cover concurrent pristine formation, cross-node
  lease/CAS visibility, follower linearizable reads, partition-bounded failure
  and rejoin, restart, and delivered-but-lost response idempotency. These are
  implementation tests, not #143 distributed production qualification, and
  they do not implement #128 divergence repair or #129 legacy-fork recovery.
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
