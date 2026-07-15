# OPC-SDK-RFC-004: High-Performance Session Store

**Status**: Draft; commit authority implemented, production qualification pending<br>
**Version**: 2.1.0<br>
**Date**: 2026-07-14<br>
**Audience**: SDK implementers, NF owners, data-plane engineers, reliability engineers

## 1. Abstract

This RFC defines `opc-session-store`, the SDK substrate for high-rate network
function state such as PDU sessions, PFCP associations, TEID mappings, QoS flow
state, handover coordination metadata, and data-plane derived counters that
need controlled persistence.

The initial draft correctly identified the need for partitioning, local-first
operation, and distributed leases. It was not strict enough for 5G continuity:
last-writer-wins based on synchronized clocks is not safe for authoritative
session state. This version requires monotonic fencing tokens, compare-and-set
updates, owner epochs, explicit handover state transitions, and a documented
consistency model per data class.

The #127 implementation uses one shared Openraft engine for intra-cluster
election, voting, log matching, commitment, membership, snapshots, and
linearizable-read authority. `ConsensusSessionStore` is the operational store;
`QuorumSessionStore` is a compatibility alias, not a second quorum algorithm.
This RFC does not claim production qualification: #128 supplies
current-format recovery and #129 supplies the audited offline legacy-fork
campaign, while #133 supplies bounded restore from the Openraft-applied state
without becoming readiness evidence by itself. Connection reauthentication and
retained-connection continuity are implemented under #163. Distributed fleet
qualification (#164/#143) remains a gate. Single-host three- and five-process
tests cover trust overlap/removal and one bounded synthetic
admission-loss/malformed-last-good plus short-lived-SVID-expiry recovery slice
under mixed lease/CAS mutation, linearizable-read, watch, complete-restore,
readiness, and connection-recycling traffic. Only typed backend-unavailable or
operation-outcome-unavailable terminal results may enter qualification
recovery. Mutation or lease outcomes that can make authority ambiguous discard
the prior guard, reacquire same-owner authority at a strictly higher fence, and
validate the exact scheduled record. Read-only get, restore-scan, and readiness
outcomes retain the already-proven guard and validate that same exact record
without minting unnecessary fencing authority. Evidence binds this routing as
`stage-aware-known-authority/v1`. The fixed
schedule drops one successful release response per mutator, allows eight
outcomes per node, 8 seconds per recovery episode, and a 50 ms retry delay;
phase completion requires every interruption to be reconciled. Lease loss,
unexpected state, and invariant failures fail closed. The exact-address restarted
member is watcher-only before exit and joins the mutator set only after bounded
journal reconciliation, so active-mutator crash/restart remains unqualified.
The tests do not cover deployed partitions, a broader restart/fault matrix,
resource/soak, remote HKMS, deployed CNFs, or signed release evidence. Generic
CRL/OCSP/denylist revocation is not implemented.

## 2. Scope

### 2.1 In Scope

- Per-session control-plane state needed by AMF, SMF, UPF, and related NFs.
- Data-plane lookup state that can be safely snapshotted or reconstructed.
- Lease and fencing mechanisms for single-owner session mutation.
- Local cache and distributed backend abstraction.
- Geo-redundant replication for disaster recovery and warm standby.
- Serialization, encryption, integrity, TTL, metrics, and fault injection.

### 2.2 Out of Scope

- Configuration management. See RFC 001.
- Packet parsing and protocol codecs. See RFC 005.
- Full 3GPP procedure implementation. This RFC provides storage primitives and
  state-machine support used by NF-specific procedure logic.
- Hard real-time packet forwarding in the remote store. Packet fast paths must
  use local data-plane structures.

## 3. Design Goals

### 3.1 Security

- Encrypt session state before it leaves process memory unless the backend is
  explicitly trusted by profile.
- Bind encrypted records to tenant, NF kind, session key, generation, and state
  type through AEAD AAD.
- Prevent stale owners from overwriting newer session state.
- Prevent cross-tenant key collision or data exposure.
- Redact SUPI/GPSI and other subscriber identifiers in logs by default.

### 3.2 Performance

- Keep packet forwarding off the remote store path.
- Support 100,000+ session updates/second per NF replica for local in-memory or
  batched backend profiles.
- Keep hot read p99 below 1 ms for local-cluster operations where the selected
  backend can meet it.
- Provide bounded allocation and zero-copy or low-copy decode for common
  session reads.
- Support batching, pipelining, and async replication without sacrificing
  fencing correctness.

### 3.3 Maintainability

- Separate storage API, lease API, serialization, encryption, and replication.
- Require backend capability declarations so NF code does not assume semantics a
  backend cannot provide.
- Use typed session records instead of arbitrary blobs at module boundaries.
- Provide a deterministic testkit for split-brain, failover, and handover races.

### 3.4 Functionality

- Support create, get, update, delete, compare-and-set, TTL refresh, lease,
  renew, release, snapshot, and replication.
- Support session handover prepare/activate/abort flows.
- Support backend implementations for in-memory, Redis, Aerospike, and optional
  strongly consistent stores.
- Support region-aware replication and recovery.

## 4. State Classes

The SDK distinguishes state by consistency need:

| Class | Examples | Consistency Requirement |
| :--- | :--- | :--- |
| `authoritative-session` | PDU session owner, AMF/SMF ownership, handover phase | Single writer with fencing |
| `dataplane-lookup` | TEID to session mapping, FAR/QER/PDR snapshots | Local atomic snapshot, rebuildable |
| `replicated-dr` | Warm standby copy of session records | Async, ordered by generation |
| `telemetry-derived` | Counters, rates, last seen timestamps | Mergeable or lossy |
| `ephemeral-procedure` | Temporary handover transaction state | TTL, fenced owner |

Only `telemetry-derived` state may use last-writer-wins based on timestamps.
Authoritative session state MUST NOT use wall-clock LWW.

## 5. Session Identity

Session keys MUST be tenant-scoped and type-scoped:

```rust
pub struct SessionKey {
    pub tenant: TenantId,
    pub nf_kind: NetworkFunctionKind,
    pub key_type: SessionKeyType,
    pub stable_id: StableId,
}
```

Examples:

- SUPI-derived subscriber context key.
- PDU session ID plus SUPI hash.
- TEID mapping key.
- PFCP session SEID key.
- Handover transaction key.

`StableId` has a structural `1..=64`-byte invariant shared by every local,
SQLite, cache, quorum, restore, replication, watch, and session-net boundary.
Valid pre-existing bytes retain their exact wire and SQLite representation.
Empty or wider legacy values are not silently truncated or hashed; they fail
the mandatory pre-upgrade audit and hydration.

Raw SUPI/GPSI MUST NOT be used directly as a backend key in production.
Subscriber-derived keys MUST use `StableId::derive_hmac_sha256` with a
16-through-64-byte tenant-specific KMS/HSM privacy key and one product-defined
1-through-256-byte canonical subject representation. The canonical profile is
full-width 32-byte HMAC-SHA256 over
the SDK domain followed by unsigned 64-bit big-endian length-prefixed tenant
and subject bytes. Truncated keyed digests are not supported.

See `docs/session-store-stable-id-migration.md` for the required count-only
audit, coordinated remediation, snapshot handling, and rollback procedure.

### 5.1 Owner and Session-Key Type Invariants

An `OwnerId` and the name of a deployment-specific `SessionKeyType` MUST each
contain 1 through 128 UTF-8 encoded bytes. The limit applies to encoded bytes,
not characters. Empty and oversized values MUST be rejected at construction
and decode boundaries without including the raw value in an error.

`SessionKeyType::Other` MUST contain a structurally validated
`CustomSessionKeyType`; callers MUST use the fallible
`SessionKeyType::other` for runtime custom names. These canonical persisted
strings are reserved for the corresponding well-known variants and MUST NOT be
constructible as custom values:

- `subscriber-context`
- `pdu-session`
- `teid-mapping`
- `pfcp-seid`
- `handover-transaction`

Parsing a reserved string MUST produce the well-known variant. Display,
serialization, SQLite identity, key-digest input, and ordering MUST use the
same canonical string; ordering MUST therefore be string ordering across known
and custom values, not enum declaration order.

The invariant MUST be applied by Serde, SQLite record and restore hydration,
active-lease reads before acquire/renew/release/fenced mutation,
replication-log hydration including nested operations, and session-net request
and response decode. Invalid persisted or remote data MUST fail closed before
mutation or caller exposure. Diagnostics MUST be fieldless or fixed and MUST
NOT expose the owner, key type, stable ID, row, transaction, or raw entry.

Valid protocol-v4 values retain their JSON byte-array shape. This does not make
the change rolling-compatible: replacing `SessionKey::stable_id: Bytes` with
`StableId` and replacing `Other(String)` with
`Other(CustomSessionKeyType)` and making `SessionKeyType::other` fallible is a
Rust source break. Both `HandoverEnvelope::unpack_raw` and
`HandoverSessionRecord::unpack_raw` now return a typed `Result`; both public
`unpack_json` methods change their error type, and `HandoverError` adds an
`InvalidEnvelope` variant. Packers now write the versioned `OPCH` form while
readers retain a bounded original/bare migration path. Rejecting values an
older v3 peer could emit is also a semantic-admission break. Protocol v4 now
binds that rule in its exact fixed-width DTO and handshake profile. Operators
MUST stop, upgrade, and restart every session-net
client, server, and protection wrapper plus every NF/product handover reader or
writer as one coordinated unit. The v4 handshake does not make persisted
`OPCH` bytes readable by old code.

### 5.2 Bounded Legacy SQLite Audit

Before a new binary opens persisted SQLite state written by an older SDK, the
operator MUST drain all writers and run:

```text
opc-session-store-audit identity-invariants \
  --database PATH \
  --max-rows N \
  --max-entry-json-bytes N \
  --max-total-json-bytes N \
  --expiry-reference 2026-07-13T18:00:00Z
```

All limits MUST be explicit and non-zero, and the per-entry JSON-byte limit
MUST NOT exceed the total JSON-byte limit or SQLite's signed `i64` length
range. The command opens an existing
database read-only/query-only, reads one consistent snapshot in fixed 256-row
pages, applies the row budget across `session_records`, `leases`,
`key_fences`, and `session_replication_log`, and bounds individual and
cumulative replication JSON before strict typed decode and domain validation.

Report schema version 4 is count-only. It contains the supplied limits, the
expiry reference, per-table scanned counts, counts for invalid owner fields,
invalid session-key type fields, invalid stable-ID fields, invalid replication
transaction-ID fields, invalid replication entries, and invalid relational
record-expiry fields, and at most one bounded incomplete reason. Relational
expiry MUST be classified against the reported reference; each nested legacy
CAS expiry MUST be classified against its immutable replication-entry
timestamp. Relational stable-ID checks read only SQLite type and length. It
MUST NOT contain the database path, row identity, tenant, owner, key type,
stable ID, payload, transaction, rejected row timestamp, or raw JSON. Omitting
`--expiry-reference` selects current UTC, but a migration campaign MUST record
and pass one explicit RFC 3339 reference so repeated audits are reproducible.
The stable command outcomes are:

- `compliant` on stdout with exit 0;
- `violations_found` on stdout with exit 1;
- `incomplete` on stdout with exit 2; or
- redacted `error` on stderr with exit 2.

Only `compliant` after a complete snapshot inspection permits the identity
portion of the upgrade to continue. `violations_found`, `incomplete`, and
`error` MUST block startup. An incomplete audit reports one of
`row_budget_exceeded`, `entry_json_budget_exceeded`,
`total_json_budget_exceeded`, `unsupported_schema`, `database_read_failed`, or
`counter_overflow`. The operator MAY increase budgets and re-audit, but the SDK
and audit MUST NOT truncate, rename, normalize, delete, repair, or rewrite
invalid identity or replication state automatically. A violation requires a
separately reviewed product migration that preserves authoritative identity and
history, or audited store replacement, followed by another complete audit.
Every retained SQLite snapshot or restore/rebuild image that can become
authoritative MUST pass the same audit. The identity procedure is
`docs/session-store-stable-id-migration.md`; absolute-expiry re-authoring,
OpenRaft recovery, and rollback are defined by
`docs/session-store-record-expiry-migration.md`.

The identity audit MUST NOT be treated as a handover-payload preflight. It does
not classify live payloads or payload bytes inside nested CAS log operations,
so `compliant` says nothing about legacy envelope/bare compatibility. Every
product using `HandoverEnvelope` MUST separately preflight the complete drained
and decrypted replay population: live records, recursively nested replication
log and snapshot records, restore/rebuild sources, and every retained copy that
can become authoritative. It MUST use `unpack_raw_with_format` or typed
`unpack_json_with_format` and verify the syntactic result against snapshot
provenance and product payload semantics; decoder success alone is insufficient.
A rejected or unprovable value MUST be resolved by a reviewed product migration
or store replacement before startup; automatic guessing/truncation is forbidden.

This bounded identity admission closes #135's scoped model/persistence
boundary. Protocol-v4 fixed-width wire admission is implemented under #134,
and #127 now supplies Openraft durable commit authority. #128 supplies
current-format divergence recovery and #129 supplies explicit offline
legacy-fork recovery. #133 supplies bounded snapshot-bound applied-state
restore; production qualification (#143) remains open. #161 atomic reload,
#162 coherent material epochs, and #163 connection reauthentication are
implemented; #164 fleet qualification remains under umbrella #158;
payload-protection-key rotation and distributed production evidence remain
#143.

## 6. Backend Capability Model

The initial `get/set/delete` trait is too weak. Backends MUST declare
capabilities:

```rust
pub struct BackendCapabilities {
    pub atomic_compare_and_set: bool,
    pub monotonic_fencing_token: bool,
    pub per_key_ttl: bool,
    pub server_side_lease_expiry: bool,
    pub ordered_replication_log: bool,
    pub batch_write: bool,
    pub watch: bool,
    pub max_value_bytes: usize,
}
```

Carrier profiles MUST reject a backend for `authoritative-session` state unless
it supports atomic compare-and-set and monotonic fencing tokens or an adapter
can provide equivalent semantics.

## 7. Storage API

```rust
#[async_trait::async_trait]
pub trait SessionBackend: Send + Sync {
    async fn capabilities(&self) -> BackendCapabilities;

    async fn get(&self, key: &SessionKey)
        -> Result<Option<StoredSessionRecord>, StoreError>;

    async fn compare_and_set(&self, op: CompareAndSet)
        -> Result<CompareAndSetResult, StoreError>;

    async fn delete_fenced(&self, key: &SessionKey, fence: FenceToken)
        -> Result<(), StoreError>;

    async fn refresh_ttl(&self, key: &SessionKey, fence: FenceToken, ttl: Duration)
        -> Result<(), StoreError>;

    async fn batch(&self, ops: Vec<SessionOp>)
        -> Result<Vec<SessionOpResult>, StoreError>;
}
```

`set` without fencing is allowed only for state classes that explicitly do not
require authoritative ownership.

### 7.1 TTL Admission and Deadline Arithmetic

The SDK-wide maximum for a session or lease TTL is the public
`MAX_SESSION_TTL`, exactly 365 days. `Duration::ZERO` MUST be accepted and means
immediate expiry. The exact maximum MUST be accepted. Any larger value MUST be
rejected with `StoreError::InvalidSessionTtl` for store operations or
`LeaseError::InvalidSessionTtl` for lease operations.

A zero-duration acquire MAY consume a fence, credential, and replication-log
position before the lease is observed expired. Callers MUST use explicit
release for revocation and MUST NOT treat a zero TTL as transaction rollback.

The ceiling accommodates long-lived packet-core sessions and planned
maintenance or disaster-recovery windows while preventing a malformed value
from creating an effectively permanent lease. A product profile MAY enforce a
smaller operational limit.

This section bounds `Duration` inputs. Caller-authored absolute record expiry
has the related but distinct authority contract in §7.2.

`validate_session_ttl` defines the duration check and
`checked_session_deadline` defines conversion and deadline calculation.
Implementations MUST convert seconds and subsecond nanoseconds using checked
integer arithmetic and MUST use checked timestamp addition. Floating-point
duration conversion, saturating/clamping an invalid input, and panicking
timestamp arithmetic are forbidden.

Validation MUST occur before any application/backend effect for direct
acquire, renew, or TTL-refresh calls; each TTL-bearing operation nested in a
batch or replication entry; forwarding, encryption, cache, or quorum adapters;
local Fake/SQLite backends; and session-net client/server admission. A client
MUST reject before resolver or network work. A server necessarily receives and
decodes the request, but MUST reject before backend dispatch and MAY return the
typed error on that authenticated connection. Repeating the check at each
public or trust boundary is intentional: direct callers and older peers must
fail closed even if an outer layer omitted validation.

The new errors are public enum variants, so external exhaustive matches MUST be
updated. Protocol v4 introduced their private fixed-width DTOs in error
revision 1; current v5 error revision 8 retains those encodings and adds the
bounded expiry-preflight outcome. An error-revision-7 or older decoder is rejected
during the exact handshake;
deployments MUST use the coordinated v5 rollout in §12.3.

### 7.2 Absolute Record Expiry Authority

For a mutation with authority reference `T`, a finite
`StoredSessionRecord::expires_at` MUST be accepted when it is in the past,
equal to `T`, or no later than `T + MAX_SESSION_TTL`. The exact upper bound
MUST be accepted and one nanosecond later MUST be rejected. Addition near the
timestamp range maximum MUST saturate for comparison and MUST NOT unwind.
`MAX_RECORD_EXPIRY_CLOCK_SKEW` is zero; an implementation MUST NOT silently
extend retention to accommodate caller/coordinator clock skew. Deployments MUST
synchronize coordinator clocks and a product MAY impose a smaller horizon.

`expires_at = None` is intentional non-expiring state. It MUST be accepted for
`AuthoritativeSession`, `DataplaneLookup`, `ReplicatedDr`, and
`TelemetryDerived`. It MUST be rejected for `EphemeralProcedure`, because that
profile requires per-key expiry to collect abandoned procedure state. A
violation MUST return the fieldless `StoreError::InvalidRecordExpiry` without
the record, timestamp, key, or peer-controlled detail.

A direct Fake or SQLite backend MUST capture its injected clock once before a
CAS or whole-batch preflight. All CAS slots MUST be checked before any slot can
mutate. A forwarding, cache, or crypto wrapper MAY delegate an inner backend's
explicit reference; it MUST NOT invent one from its own process clock. A remote
or consensus client without coordinator authority MUST perform the
time-independent `None`/state-profile check and leave the finite verdict to the
authenticated mutation coordinator.

A legacy `ReplicationEntry` MUST validate every nested CAS against the entry's
immutable `timestamp`, including replay and rebuild before mutation. This is a
reproducible compatibility reference, not production consensus authority. The
production OpenRaft leader MUST capture the command logical time, validate the
CAS before proposal, and commit that same time with the command. Admission,
state-machine apply, replay, follower apply, and journal publication MUST repeat
the deterministic check against committed command metadata. A follower's wall
clock MUST NOT alter the verdict. Authenticated cluster/configuration identity,
leader term/membership, commitment, and applied index supply the coordinator
authority described in §12.4.

Profile rejection MUST precede cache invalidation, provider work, or backend
dispatch. A wrapper above remote/consensus authority MUST obtain a bounded,
payload-free authenticated authority preflight before cache invalidation,
provider/HKMS work, sealing, or backend dispatch. The authenticated CAS/batch
dispatcher MUST repeat the preflight before idempotency admission. Invalid
input and preflight timeout/unavailability perform no provider work or
requested mutation; retry is safe because only a consensus logical-time floor
may have committed. This rule does not change payload encoding, AAD, key
selection, HKMS/KMS placement, or encryption at rest.

Existing valid row and JSON representations are unchanged. Legacy admission,
product-aware re-authoring, OpenRaft recovery, and rollback MUST follow
`docs/session-store-record-expiry-migration.md`. The audit MUST be run over a
drained snapshot with one recorded `--expiry-reference`; runtime and audit MUST
NOT guess intent, clamp a far-future value, or edit OpenRaft history in place.

## 8. Record Format

```rust
pub struct StoredSessionRecord {
    pub key: SessionKey,
    pub generation: Generation,
    pub owner: OwnerId,
    pub fence: FenceToken,
    pub state_class: StateClass,
    pub state_type: StateType,
    pub expires_at: Option<Timestamp>,
    pub payload: EncryptedSessionPayload,
}
```

`generation` is a monotonic per-session version. Every authoritative update
MUST increment it atomically.

## 9. Lease and Fencing

### 9.1 Lease API

```rust
#[async_trait::async_trait]
pub trait SessionLeaseManager: Send + Sync {
    async fn acquire(&self, key: &SessionKey, owner: OwnerId, ttl: Duration)
        -> Result<LeaseGuard, LeaseError>;

    async fn renew(&self, lease: &LeaseGuard, ttl: Duration)
        -> Result<LeaseGuard, LeaseError>;

    async fn release(&self, lease: LeaseGuard)
        -> Result<(), LeaseError>;
}

pub struct LeaseGuard {
    pub key: SessionKey,
    pub owner: OwnerId,
    pub fence: FenceToken,
    pub acquired_at: Timestamp,
    pub expires_at: Timestamp,
}
```

### 9.2 Fencing Rules

Every successful lease acquisition MUST produce a monotonic fencing token for
that session key. Backends MUST reject any write with a token lower than the
current recorded token.

This prevents an old owner whose lease expired during a pause or partition from
overwriting a newer owner after it resumes.

### 9.3 Lease Expiry

Lease expiry alone is not correctness. It is only a liveness mechanism. Safety
comes from fencing.

Rules:

- Lease TTLs MUST satisfy the 365-day bound in §7.1; zero is API-valid and
  creates a guard whose deadline is immediate, but does not satisfy the
  operational sizing rule below for an active owner.
- Lease TTL MUST be longer than worst-case expected procedure pause plus backend
  failover detection time.
- Renewals MUST happen before 50 percent of TTL elapsed by default.
- A failed renewal MUST stop authoritative writes immediately.
- Owners MUST treat unknown lease state as lost.
- Stale writes MUST fail with a distinct `StaleFence` error.

### 9.4 Backend Notes

- Redis implementations MUST use atomic Lua scripts or equivalent server-side
  transactions for acquire, renew, and fenced CAS. Redis deployments that can
  lose acknowledged writes during failover MUST NOT be used for strict
  authoritative state without an external consensus/fencing source.
- Aerospike implementations SHOULD use generation checks and record UDF or
  transaction mechanisms where available.
- In-memory backend is for single-process tests or single-replica development
  unless paired with a consensus lease manager.
- Strongly consistent stores may be used for leases even when bulk state is in a
  faster backend.

## 10. 3GPP Session Continuity and Handover

### 10.1 Storage Guarantees Needed by Handover

5G handover procedures require avoiding duplicate authoritative writers while
preserving continuity of PDU session and bearer/QoS state. The store must
support:

- Idempotent procedure steps.
- Prepared-but-not-active state.
- Activation with a fencing token.
- Abort/rollback of prepared handover.
- Recovery after source or target NF restart.
- Detection of stale source updates after target activation.

A lease mechanism without fencing is not sufficient.

### 10.2 Handover State Machine

The SDK provides generic storage states:

```rust
pub enum HandoverPhase {
    Stable,
    Preparing { tx: HandoverTxId, target: OwnerId },
    Prepared { tx: HandoverTxId, target: OwnerId },
    Activating { tx: HandoverTxId, target: OwnerId },
    Active { owner: OwnerId },
    Aborting { tx: HandoverTxId },
}
```

NF-specific AMF/SMF/UPF logic maps 3GPP procedure messages to these states.

### 10.3 Procedure Rules

The session store MUST support these generic steps:

1. Source owner holds a valid lease.
2. Source creates `Preparing` record with current generation.
3. Target acquires or is assigned a higher fence for activation.
4. Target writes `Prepared` with expected generation.
5. Activation performs a fenced CAS to `Active { owner: target }`.
6. Source updates with old fence are rejected.
7. Abort performs a fenced CAS back to `Stable` if activation did not complete.

All steps MUST be idempotent by `HandoverTxId`.

New handover envelopes MUST start with the `OPCH` magic, an exact format
version, a bounded phase length, and the typed JSON phase. Every versioned
header and phase is decoded strictly. For non-`OPCH` input, readers MUST apply
this exact migration classifier:

1. Fewer than four bytes are an unframed `Stable` payload.
2. The first four bytes are a big-endian potential phase length. Zero, or a
   value from 1 through `HANDOVER_PHASE_HEADER_MAX_BYTES` (1,024) whose phase
   slice is truncated, is `InvalidHeader`.
3. A complete phase slice within that bound is an original envelope only when
   it decodes as the current `HandoverPhase`. A JSON-looking invalid slice is
   `InvalidPhase`; a non-JSON-looking slice falls back to unframed `Stable`.
4. A length above 1,024 is `InvalidHeader` when the bytes after the first word
   begin, after ASCII whitespace, like JSON. Otherwise it falls back to
   unframed `Stable`.

This bounded rule intentionally rejects ambiguous historical bare bytes and
original envelopes whose phase is oversized or invalid under the current
model. Syntax can also produce false positives: in a checkpoint known to
predate `OPCH`, `VersionedV1` is a bare-prefix collision, and an
`OriginalLengthPrefixed` result MUST be confirmed from product provenance and
payload meaning. Products MUST run the complete live/replay payload preflight in
§5.2 and explicitly wrap the complete bytes of an authoritatively identified
bare `Stable` value, or perform a reviewed semantic migration/store replacement.
A successful transition writes the versioned form.

Writing the first `OPCH` record is a one-way migration barrier. A pre-`OPCH`
reader silently interprets that record as opaque bare `Stable` data. Operators
MUST NOT roll back binaries after the barrier unless the fleet remains drained
and either one coherent fleet-wide pre-upgrade checkpoint is restored (with
post-checkpoint mutations explicitly lost or reconciled) or every affected live
and replayable payload—including nested logs, snapshots, and restore/rebuild
sources—is reverse-migrated under a reviewed procedure. Every NF/product
handover reader and writer MUST cross the barrier together; protocol negotiation
alone cannot make the persisted payload backward-readable.

### 10.4 Packet Continuity

The session store does not itself guarantee zero packet loss. It provides the
state consistency needed by NFs to implement make-before-break, buffering, or
tunnel switching. NF-specific procedures MUST state their packet continuity
behavior and evidence in RFC 006 reports.

## 11. Geo-Redundancy

### 11.1 Corrected Consistency Model

Asynchronous geo-replication is suitable for disaster recovery and warm standby.
It is not sufficient for strict active/active mutation of the same
authoritative session unless a higher-level single-owner protocol is used.

Authoritative state MUST use one of:

- Home-region ownership per session.
- Explicit ownership transfer with fencing.
- A strongly consistent multi-region backend, if the deployment accepts the
  latency cost.

Wall-clock last-writer-wins is forbidden for authoritative session state.

### 11.2 Replication Log

Backends SHOULD expose an ordered replication log:

```rust
pub struct ReplicationEvent {
    pub key: SessionKey,
    pub generation: Generation,
    pub fence: FenceToken,
    pub state_class: StateClass,
    pub payload_digest: Sha256Digest,
    pub encrypted_payload: EncryptedSessionPayload,
}
```

Replication positions are 1-based and gap-free. Sequence zero is reserved for
the empty-log head and MUST be rejected as an entry before mutation, external
provider work, persistence, or transport dispatch. Rebuild input MUST be
validated as one complete contiguous prefix before existing state is replaced.
Sequence arithmetic and persistence-width conversions MUST be checked and
fail closed without exposing entry contents in diagnostics.

Application of one replication entry is all-or-nothing across its complete
operation tree. A failure in any later child MUST leave records, leases,
fence/credential high-water marks, the log head and retained log, compaction
state, and watcher-visible state exactly as they were before the entry. A
successful compound entry MUST preserve child order, append the submitted outer
entry once, and publish that outer entry to each eligible watcher only after the
local backend transaction or atomic swap succeeds.

Whole-state rebuild MUST replay into an isolated stage or database transaction
and replace prior state only after every supplied entry succeeds. Replay
failure MUST preserve the complete prior state and established watch
subscriptions. A successful rebuild MUST preserve those subscriptions but MUST
NOT publish replayed history as new live append events; later locally
successful appends remain observable normally. These are
backend-local atomicity requirements. In the production HA profile, a caller
MUST NOT invoke rebuild or append as an alternative authority path; only an
Openraft-committed command or snapshot installation may replace authoritative
state. #127 supplies that commit gate, #128 owns current-format reconciliation,
and #129 provides the offline operator-directed legacy campaign documented in
the [recovery runbook](../session-store-legacy-recovery.md).

An operator upgrading persisted state from an older SDK MUST audit every
TTL-bearing replication entry before rollout. A legacy entry above 365 days
fails closed during replay or rebuild under this contract; implementations MUST
NOT silently clamp, discard, or rewrite it. Recovery or migration must follow a
product-owned, audited procedure that preserves the authoritative-history
contract.

For migration compatibility only, replicated absolute-deadline cross-field
validation MAY admit at most one microsecond above the exact
`entry.timestamp + ttl` result produced by an older `seconds_f64` conversion.
New deadline construction MUST remain exact. This tolerance does not increase
`MAX_SESSION_TTL`; a larger mismatch MUST fail closed.

#### 11.2.1 Bounded Protected Operation Trees

Each `ReplicationEntry` MUST contain at most
`MAX_REPLICATION_OPERATIONS_PER_ENTRY` (256) operation nodes and MUST NOT exceed
`MAX_REPLICATION_OPERATION_DEPTH` (16). The root operation is depth 1, and each
child increases depth by one. Every node counts once toward the total,
including each `Batch` container and every leaf operation. These rules apply to
all variants, not only `Batch` and `CompareAndSet`.

Validation of an outbound entry or complete rebuild prefix MUST be iterative
and MUST finish before payload transformation or backend dispatch. Validation
of a complete returned page or item MUST finish before read-side transformation
or caller exposure; the backend has necessarily already produced that read. A
limit violation MUST return the fieldless
`StoreError::ReplicationOperationLimitExceeded`; diagnostics MUST NOT reveal
the observed count, depth, record, key, payload, provider detail, or tree shape.
By-value public/wire boundaries MUST also dismantle rejected trees iteratively
so the error path cannot recurse while dropping hostile nesting.

An encryption or remote-sealing wrapper MUST transform every
`CompareAndSet.new_record.payload` at every permitted depth. Replicate and rebuild
paths MUST stage the complete transformed entry or prefix before delegating to
the backend. Replication-log and watch paths MUST decrypt or unseal each
complete entry before exposing it. Traversal and reconstruction MUST be
iterative and MUST preserve operation order and every non-payload field
exactly.

Provider calls MUST run sequentially. If a late write-side provider call fails,
earlier provider calls MAY already have occurred, but the wrapper MUST NOT
delegate any part of the entry/prefix to its backend. If a read-side provider
call fails, the wrapper MUST return an error without exposing a partially
transformed entry or page; earlier provider calls, and earlier independent
watch items already yielded, MAY have occurred.

This contract changed confidentiality semantics before the v4 boundary. A v3
peer built before this rule cannot decode the new error and its wrapper may
forward a deeply nested CAS in plaintext/unsealed form. Protocol v4 rejects the
older wire participant and pins both tree limits and error revision, but the
handshake cannot attest that the product actually installed a protection
wrapper. Operators MUST drain and upgrade every client, server, and
protection-wrapper participant as one coordinated fleet and MUST verify wrapper
composition before restoring traffic.

Persisted historical nested plaintext/unsealed payloads are not detected or
scrubbed automatically. Before upgrade, an operator MUST audit operation-tree
shape and payload encoding offline without emitting payloads into diagnostics.
An affected entry already within the 16/256 limits MAY be explicitly rewritten
or rebuilt through the configured encryption/sealing wrapper. An over-limit
historical entry MUST fail before wrapper transformation and MUST NOT be fed to
the new SDK unchanged, silently clamped, discarded, or split. It requires a
separately reviewed offline migration that preserves the original atomic
semantics, or store replacement under an audited product recovery procedure,
before the new SDK reads the log. Rebuilding through the raw inner backend does
not satisfy this requirement.

#### 11.2.2 Intra-Cluster Consensus Authority

`ConsensusSessionStore` MUST be the only session-store implementation allowed
to claim the quorum platform profile. `QuorumSessionStore` MAY remain as a
source-compatibility type alias to that exact implementation, but MUST NOT own a
parallel coordinator. Openraft, imported through the shared `opc-consensus`
crate, owns election, voting, log matching, commit, membership, snapshot
coordination, and linearizable-read authority. The SDK state machine owns only
deterministic session semantics.

HA topology admission MUST start from the complete descriptor set and one
explicit logical self `ReplicaId`. It MUST bind a cluster ID, the exact
order-independent configuration digest over the cluster, epoch, and complete
descriptor-fingerprint set, and a positive monotonic configuration epoch.
Stable non-zero node IDs MUST be derived from cluster identity and the
logical `ReplicaId`, and derived collisions MUST fail admission. Endpoints are
routing data: a short logical ID such as `epdg-app-0` can select a member whose
endpoint is the FQDN
`epdg-app-0.epdg-app-quorum.epdg-gateway.svc.cluster.local:7443`. No code may
identify self, derive a vote, or rewrite a logical ID by comparing or shortening
those endpoint strings.

The durable storage adapter MUST persist the Openraft vote and log,
committed/applied/purged positions, membership, deterministic state-machine
chain and logical time, and idempotent request outcomes. Application journal
and watch events MUST become visible only after committed apply. A request ID
MUST bind the semantic mutation intent; retry after ambiguous response delivery
MUST return the original durable outcome, while reuse with different intent
MUST fail closed. Caller-selected raw replication entries, whole-state rebuild,
and lease sequencing MUST be rejected by this production adapter.

Snapshots MUST be bounded, checksummed, tied to the exact consensus identity,
and installed atomically as one coherent state-machine image. They MUST contain
only payloads already admitted by the protection wrapper described in §14.1.
Automatic current-format reconciliation is supplied by #128. Pre-#127
persisted forks use #129's full-fleet, backup-before-mutation procedure and
remain readiness-fenced until Openraft commits the recovery epoch.

`probe_durable_readiness` MUST use the same bounded authority path as an
authoritative read: discover or follow the current leader, execute Openraft's
linearizable-read barrier against the admitted voting configuration, and wait
until the local state machine has applied through the returned log index. A
bound listener, completed TLS handshake, cached capability set, local SQLite
availability, or successful single-node restore scan MUST NOT produce `Ready`.
The readiness result is point-in-time evidence, never an ownership lease.
Products MUST continuously gate ownership publication, VIP/service
advertisement, and traffic on fresh readiness. Restore scans MUST execute only
after the Openraft barrier and local apply. One absolute deadline MUST begin at
the public restore entry and cover the barrier/apply path, blocking-worker and
asynchronous connection admission, SQLite progress, and blocking-task join.
Each page MUST examine no more than 4,096 live candidates plus one non-decoded
lookahead, return no more than 1,024 records, 4 MiB of payload, or 8 MiB of
retained record/key/metadata/payload/cursor bytes, examine no more than 8 MiB
of key/filter metadata, and obey the SQLite VM-step, wall-time, and cancellation
budgets. Candidate/lookahead SQL MUST NOT select payload blobs; admitted
records are fetched by exact primary key inside the same transaction. Scope
filtering occurs inside the backend over that
bounded candidate window, so an empty page is valid only with a different
durable cursor and nonzero excluded/examined count. Pagination MUST seek the
existing composite primary key; it MUST NOT use `OFFSET` or add a digest-order
authority. The cursor MUST confidentially and authentically bind that seek key,
backend epoch, record revision, logical-time snapshot, scope, and examined
progress. Any edit or mismatch MUST return `RestoreScanCursorStale` before the
record query rather than skip, merge, or guess. Restore method availability
alone is not readiness evidence.

#### 11.2.3 Replication-Log Range Cursors

`get_replication_log(start, limit)` MUST define one checked inclusive range.
Sequence zero is a read-side empty-log sentinel and MUST normalize to inclusive
sequence one; it remains invalid as an entry. A zero limit MUST return an empty
page before backend I/O, provider work, an Openraft barrier, resolution, or
network dispatch. A non-zero range begins at `max(start, 1)` and ends at that
value plus `limit - 1`. The SDK-wide page limit MUST be 65,536 entries. A
larger limit MUST return `ReplicationLogPageTooLarge`; interval overflow MUST
return `InvalidReplicationLogRange`. `start = u64::MAX, limit = 1` is valid,
while any larger non-zero interval from that start MUST fail overflow. An empty
log, the terminal cursor immediately after the head, or a future cursor MUST
return an empty page.

A non-empty page MUST begin at the normalized first sequence, remain internally
contiguous, and end no later than the checked last sequence. It MAY be shorter
only at the current head or an outer response-frame boundary. Frame shaping
MUST emit only the largest complete exact prefix and MUST leave the first
unsent sequence as the next cursor. A backend or peer page wholly before or
after the requested interval MUST fail with `InvalidReplicationSequence`
before caller exposure. An authenticated compatibility client observing such
a wire violation MUST discard both the connection and its cached capabilities
before a later request re-handshakes.

If compaction has removed the requested first sequence, the backend MUST return
`ReplicationLogCursorCompacted { resume_from }`, where `resume_from` is the
first sequence after the compacted floor. It MUST NOT silently substitute the
first retained entry. The caller MUST install a coherent snapshot or rebuild
through its existing authority before using that resume point; the error is not
permission to discard missing history. A zero-limit request MUST NOT consult
the compaction floor.

After its linearizable barrier, `ConsensusSessionStore` MUST read one local
applied state. It MUST NOT collect or union replication-log pages or compaction
floors across replicas. Differing replica floors therefore yield typed local
outcomes and cannot synthesize a page that skips committed history. This range
contract does not create sequencing, commit, snapshot, restore, or watch
authority and does not change payload envelopes, AAD, HKMS/provider placement,
or encryption-at-rest boundaries.

#### 11.2.4 Replication-Watch Cursors and Atomic Handoff

`watch(start_sequence)` MUST use one inclusive 1-based cursor contract.
Sequence zero MUST normalize to one. Existing, future, and terminal
`u64::MAX` positions are valid and MUST NOT receive a lower sequence. A watch
that delivers `u64::MAX` MUST deliver it once and close because a reconnect
successor cannot be represented. Otherwise a reconnect MUST use the checked
successor of the last processed entry.

Backlog capture and live registration MUST be atomic with append/apply
notification, or use an equivalent checked handoff that cannot lose or
duplicate an entry. Every registration MUST retain its next eligible sequence.
A notification below that sequence MAY be ignored when it is either below a
requested future cursor or the atomic handoff proves it is already present in
that watch's backlog. A position above the next eligible sequence is an
integrity gap and MUST close the watch.
Backlog and live state MUST each have fixed finite bounds. This SDK admits at
most 64 captured backlog entries and 64 queued live entries per watch. More
retained backlog MUST return `ReplicationWatchCatchUpRequired` without a skip
cursor. The caller MUST invalidate dependent state, perform a coherent
snapshot or full-cache catch-up, and reconnect from the position that procedure
proves. Blind retry is forbidden. A compacted cursor remains the distinct
`ReplicationLogCursorCompacted { resume_from }` result and MUST NOT use its
resume point until a coherent snapshot covers the missing interval. Live
channel overflow MUST evict the slow consumer; cancellation and stream close
MUST NOT permit registrations to accumulate without bound.

The production Openraft adapter MUST complete its linearizable barrier before
the atomic local handoff and MUST publish only application-journal entries
emitted by state-machine apply. An uncommitted or merely log-appended local
entry MUST NOT be observable. Raw append/rebuild beside Openraft remains
forbidden. The legacy session-net client MUST complete watch setup within its
absolute deadline before returning: an initial typed store rejection is
returned exactly, not converted into disconnect/retry ambiguity. After
acceptance it MUST require every authenticated-peer item to equal the next
inclusive sequence and MUST terminate the dedicated connection on duplicate,
gap, invalid, or otherwise corrupt metadata before an outer encryption wrapper
performs provider work. Errors and diagnostics MUST be redaction-safe, and a
subsequent independent request MUST use a usable freshly authenticated
connection.

`ReplicationWatchCatchUpRequired` advances the quarantined protocol-v4 error
set from revision 5 to revision 6. The wire schema remains revision 4. All
legacy compatibility peers MUST be drained and upgraded together; this is not
a rolling mixed-profile transition. The Openraft consensus profile, persisted
SQLite/journal/snapshot format, payload envelopes, AAD, and HKMS/provider
placement are unchanged.

Replicas MUST apply events only if `generation` and `fence` are newer according
to the state class rules.

### 11.3 RPO and RTO

Every deployment profile MUST publish:

- Recovery point objective for session state.
- Recovery time objective for session service.
- Maximum tolerated replication lag.
- Which state classes are replicated.
- Which state classes are rebuildable.

## 12. Serialization

Rust has no garbage collector, so the goal is allocation, CPU, and cache
efficiency rather than "GC pressure" reduction.

### 12.1 Formats

Allowed formats:

- FlatBuffers for read-mostly zero-copy records.
- Prost/Protobuf for compatibility, with careful allocation profiling.
- Postcard or bincode-like formats only for internal state with stable version
  policy.

Each state type MUST define:

- schema version
- compatibility policy
- max encoded size
- fuzz target
- migration path

### 12.2 Decode Rules

Decoders MUST:

- Validate length prefixes and offsets.
- Reject trailing garbage unless explicitly allowed.
- Avoid borrowing data beyond the lifetime of the source buffer.
- Avoid panics on corrupt data.
- Support partial decode for lookup keys where useful.

### 12.3 Legacy Direct-Backend Session-Net Protocol v5

The direct `SessionBackend` protocol is retained only behind the non-default
`legacy-session-net-compat` feature for controlled migration and compatibility
testing. It MUST NOT be enabled on a production consensus node or served on the
consensus endpoint. When used for migration, it MUST use the exact
`opc-session-net/5` ALPN, contract version, and contract profile. It MUST NOT
negotiate down or select a highest-common version. A mismatch MUST fail
before backend dispatch, close the connection, and be non-retryable for that
request.

The public semantic `Request` and `Response` types remain available, but their
Serde boundary MUST delegate to private fixed-width v5 DTOs. `Hello` and
`HelloAck` add an optional `contract_profile`; `HelloAck` also carries the
server's optional `cas_idempotency_epoch`, and direct CAS carries an optional
`idempotency_epoch`. Exhaustive Rust construction and matching MUST account for
the new fields. The profile pins wire-schema revision 6 and error-set revision
8; owner, custom-key, and state-type
bounds of 128 UTF-8 bytes; `min_frame_size = 8192`;
`max_frame_size = 16777216`;
`stable_id_max_bytes = 64`; `replication_tx_id_max_bytes = 128`;
`cas_request_id_bytes = 36`; the 31,536,000-second session TTL maximum;
restore-page maximum 1,024; and the depth-16/256-node replication-tree rules.
Every transported stable ID MUST contain 1 through 64 bytes. Every transported
replication transaction ID MUST contain 1 through 128 UTF-8 bytes and MUST be
represented by the bounded `ReplicationTxId` domain type before mutation or
durable sequence allocation. New committed coordinator writes MUST encode the
16-byte consensus request ID as exactly 32 lowercase hexadecimal bytes. A
reader MUST preserve any valid legacy representation byte-for-byte and MUST
NOT trim, case-fold, parse, or normalize it; exact equality remains idempotent
redelivery and any distinct representation remains divergent. Every CAS
request ID that is present MUST use the canonical lowercase hyphenated UUID
representation and therefore contain exactly 36 bytes.
The public profile's `max_frame_size` addition is a Rust source break for
external struct literals and exhaustive destructuring and MUST be deployed in
the same coordinated revision-2 fleet transition.

The fixed-width mapping is:

- Hello `requested_response_frame_size`, HelloAck
  `accepted_response_frame_size`, and HelloAck `server_request_frame_size`:
  `u32`;
- restore/log request limits and the client restore-response budget: `u32`;
- restore request/response cursors and restore excluded count: `u64`;
- backend `max_value_bytes`: `u64`; and
- `PayloadTooLarge.actual/max`, `RestoreScanPageTooLarge.requested/max`,
  `ReplicationLogPageTooLarge.requested/max`, and
  `RestoreScanResponseTooLarge.max_bytes`: `u64`, including errors nested in
  batch results.

The restore wire page MUST omit `loaded_count` and `complete`; the receiver MUST
derive them from the record vector and `next_cursor`. Conversion to or from a
domain `usize` MUST be checked, and a non-representable value MUST fail before
backend dispatch or caller exposure. Collection work MUST be bounded
independently from encoded frame size: at most 256 batch operations, 1,024
restore records, 65,536 replication-log entries, and 65,536 rebuild entries.
The configured frame limit remains a separate encoded-byte bound. Log requests
and returned pages MUST also satisfy the exact range contract in §11.2.3 before
dispatch or caller exposure.

Wire-schema revision 2 MUST negotiate directional frame budgets during the
frozen bootstrap. The client's requested response size, the server's accepted
response size, and the server's request size MUST each be at least
`MIN_NEGOTIATED_FRAME_SIZE` (8 KiB, or 8,192 bytes), at most
`MAX_NEGOTIATED_FRAME_SIZE` (16 MiB, or 16,777,216 bytes), and representable as
`u32`. Their public bootstrap fields are `Option<u32>` so a revision-2 decoder
can classify an otherwise decodable legacy minimal bootstrap. This MUST NOT be
treated as bidirectional mismatch negotiation: a revision-1 decoder MAY reject
unknown revision-2 fields by closing without a typed response. Revision-2
admission MUST require all three as `Some`. The accepted
response size MUST be no greater than either the client's receive limit or the
server's configured frame limit. The server request size independently states
the maximum operation frame the server will accept. Peers MUST use these values
for the lifetime of that connection and MUST NOT infer equal limits in both
directions.
`MIN_RESTORE_SCAN_RESPONSE_FRAME_SIZE` MUST alias
`MIN_NEGOTIATED_FRAME_SIZE`; it is not a second negotiable minimum.
The restore request's existing `max_response_frame_size` MUST remain an
additional per-call cap and MUST NOT enlarge the negotiated response budget.
Before binding or spawning, a server MUST reject a configured frame size below
8 KiB or above 16 MiB, a zero/runtime-unrepresentable connection-slot count,
or an unrepresentable idle/restore timeout with `InvalidInput`. A zero timeout
MAY remain an intentional immediate-fail policy.
Before DNS, socket allocation, or watch-task spawning, a client MUST reject a
configured frame size outside the same range. Bootstrap output MUST use the
separate 8 KiB `MAX_HANDSHAKE_FRAME_SIZE` cap.

Every post-bootstrap response and watch item MUST be fully bounded-encoded into
retained byte storage capped at the accepted response size before a length
prefix is written.
The common non-pageable and complete-page success path MUST perform one bounded
encode without a separate sizing serialization. If the complete pageable
response is oversized, that direct encode MUST emit no prefix; prefix selection
MAY then perform bounded logarithmic sizing probes followed by one final bounded
encode. No retained encoded-JSON byte storage may exceed the negotiated cap.
The retained/requested encoded-JSON byte storage MUST remain no greater than the
cap, including for non-power-of-two budgets. An implementation MUST NOT
coalesce or create a temporary payload buffer when doing so would exceed that
bound. This SDK satisfies the contract with lazy exact-length boxed chunks and
no coalescing copy. Chunk-pointer metadata and allocator slab/RSS overhead are
not encoded JSON bytes and MUST be accounted for separately by runtime resource
qualification.
One absolute deadline MUST be established before the first direct encode or
sizing probe and reused through every probe, the final encode, length prefix,
complete payload, and flush. Implementations MUST NOT restart the deadline per
probe, phase, write, or chunk. Deadline expiry MUST terminate the connection and
release its task and connection permits.
Synchronous storage and sizing sinks MUST check the deadline and the server's
abort cancellation signal cooperatively between serializer writes and retained
chunks. Task abortion cannot preempt one synchronous serializer callback;
therefore every wire field and collection processed between checks MUST remain
bounded, and shutdown claims MUST include that finite callback interval.

Outbound behavior is family-specific:

- The fixed-width Capabilities envelope MUST fit within the 8 KiB protocol
  minimum; an encoding failure MUST close without emitting an oversized frame.
  Scalar mutation results, replication/rebuild acknowledgements, and lease
  results MUST use an SDK-owned fixed, redaction-safe fallback when a
  backend-provided result cannot fit. If the fallback cannot fit, the connection
  MUST close without emitting an oversized frame.
- Get results and CAS conflicts MUST NOT truncate a record. They MUST replace
  the complete record-bearing result with the fixed fallback or close.
- Batch results MUST preserve exact request cardinality and order. They MUST NOT
  be truncated; an oversized complete result becomes one fixed batch error or a
  connection close.
- Restore results MAY return a complete record prefix that fits, but
  MUST preserve `next_cursor` and excluded-count semantics. A record MUST NOT be
  split. When the first record cannot fit, the server MUST return the fixed
  restore-size error if representable or close.
- Replication-log results MAY return only the largest complete contiguous entry
  prefix that fits. An entry MUST NOT be split, reordered, or skipped. If no
  requested entry fits, the server MUST use its fixed fallback or close.
- Watch acknowledgement and each watch item MUST be bounded independently. The
  server MUST NOT skip an oversized entry because that would conceal a sequence
  gap. It MUST send a fixed error item when representable and then terminate the
  stream/connection, or close immediately when the fallback cannot fit.

Fallback text MUST be static SDK-owned text. It MUST NOT contain a key, owner,
payload, transaction/request ID, peer identity, backend error string, or other
peer-controlled text. Consuming rejection of nested replication operations MUST
retain iterative disposal and the existing depth/node work bounds.

`BackendCapabilities::max_value_bytes` transported over session-net MUST be no
greater than the backend limit,
`conservative_payload_budget(accepted_response_frame_size)`, or
`conservative_payload_budget(server_request_frame_size)`. That function MUST
compute `frame_size.saturating_sub(8192) / 8`: the 8 KiB block reserves the
record/key/error envelope, while the factor of eight covers four-byte worst-case
JSON byte-array expansion plus equal escaping/metadata headroom. The advertised
maximum MUST complete a real write/read round trip under unequal limits.
At exactly 8 KiB, the conservative payload budget is zero: that minimum MUST
fit maximum-profile metadata/envelopes but does not promise a non-zero
application payload. Capability evidence remains descriptive and MUST NOT
authorize quorum or traffic readiness.
The 1 MiB default yields 130,048 payload bytes and the 16 MiB ceiling yields
2,096,128. Advertising SQLite's full 1 MiB value limit requires at least
8,396,800 frame bytes; 16 MiB is the recommended configured frame size for that
profile. This is a per-frame limit, not aggregate admission: at the server's
default 128 connection slots, simultaneous ceiling-sized encoded stores can
retain about 2 GiB before chunk metadata, TLS, and runtime overhead. The
aggregate scales with the configured connection limit. #143 owns aggregate
byte permits and distributed resource/soak qualification.

Backend mutation and response delivery are not one transaction. A mutation MAY
commit before response encoding, write, or flush fails. Direct CAS idempotency
MUST be keyed by the authenticated logical peer plus canonical request UUID and
MUST bind a redaction-safe digest of the complete operation, cluster and
configuration identity, monotonic configuration epoch, and server-issued
process epoch. Same-scope exact duplicates MUST share one in-flight execution
and replay the exact success or conflict. Reuse by another peer or operation
MUST return `CasIdempotencyConflict` before backend dispatch. Cancellation MUST
leave a tracked ambiguous tombstone, never an untracked in-flight entry.

The compatibility cache MUST bound total and per-peer entries and bytes,
retention age, and cleanup work. One peer MUST NOT evict another peer's active
retry window. Restart or retention cleanup MUST rotate the process epoch, and
an old epoch MUST return `CasIdempotencyOutcomeUnavailable` before mutation.
Pressure that cannot retain a result MUST return the same typed unavailable
outcome rather than evicting an active result and treating its UUID as new.
The public client MUST NOT automatically resubmit a CAS after any ambiguous
transport boundary. A caller that receives no valid response or the typed
unavailable outcome MUST perform an authoritative re-read and derive a new
mutation; it MUST NOT infer rollback or replay the historical operation under
either the old or a fresh UUID.

Every authenticated request MUST have three bounded phases: one inbound
idle-timeout to receive and decode a complete frame, one backend admission/work
deadline started after decode, and one reserved bounded response interval. The
checked sum of the latter two is the post-decode dispatch/response lifetime;
full connection-slot occupancy includes the inbound phase as well.
Reads, mutations, lease mutations, and watch setup MUST have independent
fixed-size admission pools; restore MAY retain a stricter dedicated pool.
Queue expiry before backend polling is known not applied. Read execution MUST
be cancellable and release resources. Once a non-CAS or lease mutation has
been polled, deadline, disconnect, cancellation, or response loss MUST either
recover a durable operation-bound outcome or return the non-retryable
`BackendOperationOutcomeUnavailable` /
`LeaseError::OperationOutcomeUnavailable` class. The public legacy client MUST
NOT reconnect and resubmit such a mutation. A transport failure proven to have
occurred before the first request write remains known not applied and MAY be
retried. CAS continues to use its stronger operation-bound idempotency outcome.
Code that itself drops a polled mutation future receives no result and MUST
treat that cancellation as the same unknown-outcome class.

The production Openraft adapter MUST create one durable request identity before
leader selection and retain it across internal forwarding retries. A local
failure before proposal submission MAY remain retryable. Once Openraft accepts
the proposal into its client-write channel, loss of the result receiver,
deadline expiry, or an unvalidated forwarded result MUST return
`CasIdempotencyOutcomeUnavailable` for direct CAS and
`BackendOperationOutcomeUnavailable` for every other mutation (mapped to
`LeaseError::OperationOutcomeUnavailable` at the lease API). It MUST NOT return
a generic retryable availability error. Durable state-machine request outcomes
MUST make retry of the same internal identity idempotent.

The production adapter MUST use the shared fixed eight-slot proposal-admission
pool for both normal mutations and finite-expiry logical-time-floor proposals.
It MUST acquire a slot within the operation's original absolute deadline. Once
`client_write_ff` returns the accepted proposal's result receiver, a detached
supervisor MUST retain that slot until the receiver resolves; caller drop,
peer EOF, and response timeout MUST NOT release it early. Saturation MUST fail
closed before another proposal is submitted. A finite-expiry preflight MUST
validate its descriptors against the logical time returned by its committed
floor command before reporting success.

Every fresh read-index and mutation preflight MUST use one shared
linearizability supervisor per Openraft node. Exactly one supervisor-owned
`ensure_linearizable` call may be in flight, with at most 64 total admitted
callers across the active and waiting cohorts. Only callers collected before
dispatch may share that exact Openraft result; later callers require a later
check. Caller cancellation or deadline expiry MUST NOT cancel a dispatched
check, release its admission early, or start an overlapping check. The
supervisor is a resource bound only: Openraft remains the sole source of
leadership, quorum, read-index, and applied-state authority.

After a legacy request is transmitted, a malformed or wrong-family response,
or a same-family response that violates request-bound key, owner, fence,
credential, ordering, or cardinality semantics, MUST use the same typed
ambiguous-outcome classification. Direct-CAS retry caches MUST NOT retain a
backend availability result as a completed retryable outcome; they MUST retain
an ambiguous tombstone instead.

Server cancellation and peer EOF MUST race pending backend work and idle watch
streams. Backend adapters MUST treat future drop as a cancellation signal and
retain bounded admission/supervision until underlying work exits. Read
resources are released after bounded cancellation completes. A mutation may
finish after its caller drops, but that caller MUST treat the outcome as
unknown and re-read authoritative state. Durable operation-bound replay is
Openraft/direct-CAS-specific, not a generic adapter promise. No timeout or
shutdown path may create unbounded detached work. Static capabilities MUST fail
closed when backend admission cannot be obtained and MUST NOT substitute for
fresh readiness.

Outbound diagnostics SHOULD expose only bounded `response_family` categories
and fixed reasons such as `frame_too_large`, `page_shortened`, `write_timeout`,
`transport`, and `encoding`. They MUST NOT label or log session keys, payloads,
transaction IDs, owners, SPIFFE IDs, backend/peer-controlled error text, or
other high-cardinality identifiers. The fixed metric family
`opc_session_net_backend_lifetime_events_total` MAY expose only
`queue_timeout`, `execution_timeout`, `cancellation`, `peer_disconnect`, and
`ambiguous_outcome`; it MUST NOT contain dynamic labels.

A fresh version/profile/authentication or malformed-handshake failure MUST clear
the cached capabilities and report all capability booleans false with
`max_value_bytes = 0`. A cache retained after transient transport loss is
descriptive only and MUST NOT authorize a store operation, durable readiness,
or traffic admission. A cache MUST be keyed by the exact profile and negotiated
directional limits and cleared when a successful reconnect changes either
limit. Callers MUST use fresh bounded quorum evidence.

The transition to v5 wire-schema revision 6 and error-set revision 8 is a
coordinated stop/upgrade/start boundary, not a rolling deployment. Operators
MUST drain traffic and writers; run the #135 identity
audit; inventory every retained record, replication log, snapshot, restore
source, and replay source for the stable-ID and transaction-ID bounds; and
complete product-aware handover/nested-payload preflights. A retained-value
migration MUST be decoder-first: while writers remain quiesced, every migration
reader MUST be able to decode the legacy representation before any rewrite or
replacement occurs. Stable IDs MUST follow the product-aware #167
model/persistence/privacy/audit policy. Durable transaction IDs MUST follow
the #168 bounded-type and
[`migration policy`](../session-store-replication-tx-id-migration.md), including
current report version 4 and coordinated cutover with #127/#128/#143. The
migration MUST NOT silently truncate, hash, or rename a key or idempotency
identity. Operators MUST verify that the strict revision-3 decoder accepts the
result; then they MUST stop every session-net client, server, and protection
wrapper plus every handover reader/writer; upgrade them together; verify
exact-v5 authenticated restore/log traffic, rejection of modified/legacy
restore cursors, sparse empty-page progress, and fresh quorum evidence; and only
then restore traffic. Once an
`OPCH` value has been written, v3 rollback additionally requires a coherent
drained checkpoint restore or reviewed reverse migration of every live and
replayable record, log, snapshot, and restore source.
Revision 3 adds only an O(1) per-store cursor key to local restore metadata; it
does not rewrite session records or create another authority. A pre-revision-3
consensus snapshot lacks that metadata and MUST NOT be installed after upgrade;
operators MUST take and validate a coherent post-upgrade snapshot before
claiming repair or rollback coverage. In-profile
data needs no format conversion, but out-of-profile retained values MUST be
migrated or replaced before strict transport starts. Binary rollback MUST
restore one exact drained fleet profile and install a rollback-side decoder that
can read the retained target representation before old writers restart;
otherwise it MUST restore a coherent checkpoint or run a reviewed reverse
migration. Mixed revision-3 and older participants fail closed. Rollback
across the independent `OPCH`/#135 boundary retains its checkpoint/reverse-
migration requirement.

That compatibility cutover is distinct from credential rotation. Only after
every participant is admitted on the same revision-6 profile MAY operators use
material-epoch or explicit reauthentication to recycle connections without
draining application traffic. The lifecycle MUST NOT be used to mix protocol
profiles, negotiate a downgrade, or turn a binary rollback into a rolling
operation.

The cursor encoding is variable-length but strictly bounded by the consensus
RPC/key ceiling. HMAC-derived AEAD and synthetic-nonce keys are separated;
identical semantic positions encode identically. The seek key and snapshot
metadata remain confidential, while a clear cumulative examined-row position
is bound into cursor authentication. A receiver can reject a structurally
inconsistent claimed step and the issuer authenticates the position when the
cursor returns, but neither fact proves peer-page completeness or server
honesty. Production completeness comes from the local Openraft-applied state
after its linearizable barrier.
Cursors are backend-incarnation/node-bound: same-PVC restart can resume, but
another node or installed snapshot MUST return typed stale-cursor state and the
caller MUST discard partial pagination and restart at the first page.

#159 establishes only session-net response/write and wire-containment bounds.
It does not close #167 or #168 and does not provide #143's
payload-key/distributed production qualification. #163 real-mTLS transport
tests cover local/peer leaf-expiry retirement, overlapping trust, complete
replacement negotiation, old-trust rejection, and request/watch continuity.
TLS material tests separately prove effective configured/presented-chain expiry
through a real mutual-TLS handshake, while lifecycle unit tests prove the
corresponding local/peer retirement deadlines and fixed metric reasons.
Additional non-ignored single-host three- and five-process tests now exercise
one bounded multi-process slice: a test-only consensus-RPC admission loss on
one stable follower while a different member retains last-good material after
malformed trust; exact-address restart, catch-up, and repair; and a
same-issuer leaf with a 75-second remaining-validity/expiry budget through the
`expiry - 30 seconds` soft boundary, hard drain, source/controller
`LastGoodExpired`, survivor durable readiness and
encrypted-canary progress, and same-process valid replacement while bounded
mixed lease/CAS mutation, linearizable-read, watch, complete-restore,
readiness, and connection-recycling traffic remains active. The exact-address
restarted member is watcher-only before exit and joins the mutator set only
after bounded journal reconciliation; active-mutator crash/restart, a
real/deployed partition, a broader restart/fault matrix, resource/soak,
remote-HKMS, deployed-CNF, signed release, and evidence-schema/profile claims
remain unqualified. Generic
CRL/OCSP/certificate-or-identity-denylist revocation is not implemented. #177 removes
`opc-persist`'s separate config TCP
path and reuses the shared consensus peer/handler boundary instead of defining
another timeout or credential lifecycle. An in-process real-mTLS integration
forms a three-node config Openraft cluster and commits/linearizably reads
through the existing peer/server types. Any compatibility transport work
must preserve the single Openraft authority rather than reopen direct mutation
as a quorum path.
#161 atomic reload, #162 coherent material epochs, and #163 finite connection
reauthentication are implemented. Fleet SVID/trust-bundle qualification remains
#164 under umbrella #158.

### 12.4 Consensus-Only Session Transport

The production session HA transport MUST use `SessionConsensusServer` and
`RemoteSessionConsensusPeer` on the exact `opc-session-consensus/2` ALPN. The
server MUST own only a `SessionConsensusRpcHandler`; it MUST NOT accept a
`SessionBackend`, lease manager, direct mutation request, caller-authored
replication append, or rebuild request. The consensus ALPN and legacy
`opc-session-net/5` ALPN MUST NOT be multiplexed as equivalent authority on one
production listener.

The exact consensus contract profile MUST use transport/wire-schema revision 2
and error-set revision 4. The wire adds the bounded payload-free authority
preflight; the error set adds `RecordExpiryPreflightLimitExceeded`. Revision
1/error revision 3 or older MUST fail before engine dispatch.
Operators MUST drain traffic and writers, stop every consensus member, upgrade
the full membership together, verify exact-profile handshakes, and only then
restore traffic. Mixed-profile rolling operation is unsupported.

Each connection MUST perform mutual TLS and bind all of the following before
engine dispatch:

- the live certificate's one canonical SPIFFE URI;
- the logical `ReplicaId` and derived stable node ID of each side;
- the expected opposite peer and authenticated request sender;
- the cluster ID, exact configuration digest, and positive configuration epoch;
- the engine RPC family, peer role, exact transport revision/profile, and a
  fresh challenge.

The sender authenticated by the outer transport MUST equal the sender carried
inside the bounded engine request. DNS names, FQDNs, IP addresses, resolver
aliases, and Kubernetes pod hostnames MUST affect only connection routing and
MUST NOT be accepted as substitutes for any logical, stable, or certificate
identity.

One absolute family deadline MUST begin before lane acquisition and cover
bounded encode, write, and response read. AppendEntries/Openraft read-index
MUST use 2,000 ms, Vote 5,000 ms, and InstallSnapshot, forwarded mutation, and
consumer ReadBarrier 10,000 ms. If no valid cached connection exists,
resolution, TCP connect, mutual TLS, identity admission, and bootstrap MUST use
the lesser of the remaining family budget and a 1,500 ms cold sub-bound; cold
time MUST NOT be added to the family deadline. Each directed peer MAY cache a
fixed primary/overflow pool of at most two authenticated connections, with at
most one in-flight RPC per lane. Sequential calls MUST prefer primary; a
concurrent call MAY use overflow; when both lanes are busy, further calls MUST
wait for either lane under the same absolute family deadline. It MUST recache a
selected lane only after a complete, correctly correlated, authenticated,
validated successful response or typed semantic `Unavailable` response. The
`Unavailable` exception preserves a known stream position but grants no
success or authority. Cancellation, timeout, EOF, malformed/cross-correlated
response, protocol, authentication, scope mismatch, rejection, lifecycle
evidence mismatch, or any uncertain stream position MUST evict that lane. A
late connection or response after cancellation MUST NOT be reused. The
transport MUST carry only the shared bounded consensus envelope; the
session-store adapter compact-encodes Openraft RPCs, and the network layer MUST
NOT interpret commands or decide leadership, voting, log matching, commit, or
repair. An
identity, authentication, schema, payload-bound, or sender mismatch MUST fail
before Openraft dispatch with redaction-safe diagnostics.

Every authenticated client, peer, and listener MUST apply one finite
`ConnectionLifecyclePolicy`. Its hard deadline MUST be the earliest of the
configured maximum authentication age, the expiry of every certificate in the
local configured/presented SVID chain, and the expiry of every certificate
actually presented by the peer. A redundantly presented root contributes to
that bound. A certificate appearing only in a configured trust bundle is not
independently scanned for the deadline, and the time an anchor is removed is not
an expiry deadline. Production SVID chains SHOULD omit the trust anchor. Soft
retirement MUST begin early enough to leave at most one configured drain window
before the hard deadline. A coherent TLS material-epoch change or an explicit
process-local reauthentication generation MUST also schedule retirement, using
deterministic directed-peer jitter no greater than the configured bound.

After soft retirement the client MUST NOT assign a new operation to the
connection and the server MUST NOT read or dispatch another request. An
operation admitted before retirement MAY return once within its existing
operation deadline, but transport ownership MUST stop waiting by the lifecycle
hard deadline and MUST release every connection/task slot. Dropping the backend
future requests cancellation but MUST NOT be interpreted as rollback: bounded
supervised mutation work MAY finish later. Such an outcome MUST remain typed
ambiguous, MUST NOT be automatically replayed, and requires authoritative
readback or the operation's existing idempotency/fencing contract. A replacement
MUST repeat DNS/route resolution, mutual TLS, live certificate identity,
nonce/challenge, ALPN, version, and exact contract-profile checks. TLS
resumption, cached peer authority, plaintext fallback, and task-abort
reauthentication MUST NOT replace that handshake.

After authentication and bootstrap acknowledgement, if no byte of the next
request arrives before the listener idle deadline, the server MUST record the
fixed `idle_timeout` lifecycle-retirement reason, enter and complete the normal
drain/slot-release path, dispatch no request, and finish the connection handler
as a successful bounded lifecycle outcome rather than a timeout failure. This
rule applies to both the consensus listener and the legacy direct listener.
Silence during TLS/application bootstrap MUST remain a timeout failure. Once
any byte of an authenticated frame arrives, the remaining length prefix and
payload MUST complete within the original absolute idle deadline; an incomplete
active frame MUST remain a timeout failure and MUST NOT be relabeled as idle
retirement.

If a lifecycle retirement boundary (maximum authentication age, local or peer
certificate expiry, material epoch, or explicit reauthentication) is observed
after mutual TLS but before any bootstrap acknowledgement bytes are written,
the generic transport MUST return one complete authenticated
`BootstrapResponse::ConnectionRetiring` result. The consensus bootstrap context
MUST use
`SessionConsensusBootstrapResponse::Rejected(SessionConsensusPeerError::Rejected)`
as the corresponding no-dispatch control. That nested value is reserved in
this context only: ordinary authentication, identity or scope, contract, and
protocol failures MUST retain their existing classifications and MUST NOT be
emitted or interpreted as this control; a post-bootstrap engine `Rejected`
result MUST remain an ordinary call response. The sequential client MUST NOT
send application or Openraft request bytes before bootstrap succeeds. After it
decodes the complete retirement control, it MUST discard that connection and
retry the pending operation only through the existing bounded deadline and
backoff path.

EOF, an incomplete control, or an acknowledgement whose write has partially
completed MUST fail closed. Once an acknowledgement write may have emitted a
byte, the server MUST close rather than append a bootstrap retirement frame.
The client MUST NOT infer no-dispatch from that incomplete stream. The server
MUST count a connection-attempt `success` only after completely writing the
bootstrap retirement control; the client MUST count its own `success` only
after decoding the complete control. In both cases `success` means authenticated
transport/control completion, not application admission. That decode MUST
initiate the client's existing bounded deadline/backoff path and count a
reconnect `attempt`; the client MUST NOT count a reconnect `failure` or a
connection-failure outcome for that complete control.

The legacy direct profile MAY automatically retry a mutation after retirement
only when it has decoded the complete fixed `ConnectionRetiring` response,
which proves server dispatch did not occur. EOF, a partial retirement frame,
write failure without a complete buffered proof, or a generic transport error
MUST remain an ambiguous mutation outcome. A legacy watch MUST keep the caller
stream alive across planned retirement, pin any partially read item to its old
connection, advance the resume cursor only after caller delivery, and resume
from checked `last_delivered_sequence + 1`. Cursor overflow, compaction or
another permanent backend error, cancellation, and bounded slow-consumer
failure MUST terminate explicitly rather than reconnect forever.

This bootstrap behavior admits the already-frozen direct revision-6 variant and
existing consensus error value in their restricted bootstrap contexts. It
changes no public API, direct or consensus profile revision, persisted
SQLite/journal/snapshot format, Openraft commit authority, payload envelope,
encryption-at-rest boundary, or HKMS/provider placement. Older same-profile
decoders fail closed on the control rather than negotiating a downgrade, so
mixed-patch rolling rotation is not seamless. This closes only the narrow
authenticated post-TLS/pre-acknowledgement race; it does not satisfy the
remaining #164 fleet qualification.

This authenticated transport plus #127 commit authority is still not a
production qualification. #128 supplies current-format divergence recovery,
#129 supplies the audited offline legacy-fork campaign without reopening a
runtime consensus path, and #133 provides bounded applied-state restore without
reopening a direct backend/rebuild port. #143 remains the distributed
partition/restart/resource/soak and payload-key gate. #161 atomic reload, #162
material epochs, and #163 bounded reauthentication are implemented, including
scoped retained-connection, request, and watch continuity evidence. Production
rotation already has single-host multi-process trust transitions and the exact
synthetic fault/expiry slice described above. It MUST additionally qualify
deployed trust/root cutover, real network/storage faults and a broader restart
matrix, deployed mixed traffic/watch/restore under those real faults,
reconnect-storm bounds,
resources, soak, remote HKMS, deployed CNFs, and signed release evidence under
#164/#143. The lack of immediate generic CRL, OCSP, or
certificate/identity-denylist revocation MUST remain explicit. #158 remains the
umbrella until that fleet evidence passes.

## 13. Local Cache

The SDK SHOULD provide a two-level model:

1. Local in-process cache for hot reads.
2. Distributed backend for ownership, recovery, and replication.

Cache entries MUST include generation and fence. Stale cache entries MUST NOT be
used for authoritative writes. Data-plane lookup snapshots SHOULD be updated
through atomic swap or RCU-like mechanisms.

Cache invalidation options:

- backend watch stream
- polling by generation
- explicit publish from owner
- TTL expiry

NF owners must choose a cache mode per state class.

## 14. Security

### 14.1 Encryption

Session payloads MUST be encrypted before storage unless the profile explicitly
marks the backend as inside the same cryptographic boundary.

The production HA composition MUST place encryption or remote sealing above
consensus:

```text
application -> EncryptingSessionBackend / RemoteSealingSessionBackend
            -> ConsensusSessionStore -> Openraft -> SQLite/snapshots
```

Protection MUST finish before `client_write`. Openraft replication, follower
apply, replay, durable request-outcome storage, and snapshot build/install MUST
therefore receive only opaque RFC 003 envelopes. The consensus engine, network
adapter, and deterministic state machine MUST NOT receive plaintext payloads,
an HKMS/KMS provider, key material, or a provider key handle. Read-side
decryption/unsealing MUST happen only after the consensus read returns through
the wrapper, using the envelope key ID for historical-key selection. Provider
unavailability MAY block new protection or plaintext reads, but MUST NOT cause
provider I/O during deterministic apply or make already sealed Raft replay and
quorum formation depend on provider availability.

Remote unseal MUST pass the canonical envelope key ID through the provider
boundary after validating envelope shape and record AAD. The active remote key
is an atomic process-local material epoch used only by future seals; a seal
already in flight keeps its selected key ID, but may still fail because of
timeout, provider outage, or revocation. Mixed-epoch fleet writes remain
readable while KMS retains each envelope's exact key. Missing, revoked,
malformed, cross-tenant, and wrong-AAD inputs fail with coarse, redacted crypto
errors. Provider, endpoint, tenant, key ID, and payload text MUST NOT be
included in those errors.

KMS/HKMS owns remote historical-key retention and retirement. The SDK keeps no
local historical material or authorization cache and exposes no retirement API
or enforcement gate. It supplies exact key selection and bounded live-state
scan inputs, not a rewrap campaign or complete dependency proof. Operators MUST
combine a snapshot-bound, write-fenced live-state scan after rewrap with
separate compaction, expiry, or inspection of logs and snapshots, plus
inspection and rewrap/deletion/retention decisions for backups, restore sources,
and rollback checkpoints. A restore scan alone does not prove those retained
artifacts. Incomplete/stale evidence or an unbounded record blocks retirement.

`EnvelopeV1` MUST be validated rather than trusted as a marker. Construction,
wire decode, durable-row decode, log append, replay, and snapshot validation
MUST reject a malformed or non-canonical RFC 003 envelope, mismatched embedded
key ID, invalid algorithm nonce/tag shape, non-session AAD, or mismatch between
the AAD's visible tenant/NF/state/generation/fence fields and the record.
Consensus admission of a SQLite file MUST atomically fence all standalone
backend operations through retained or newly opened handles; only internal
state-machine apply and barrier-gated committed reads may bypass that fence.

AAD MUST include:

- tenant
- NF kind
- session key digest
- state type
- generation
- fence
- backend namespace

The bounded iterative transformation in §11.2.1 is mandatory for replication
wrappers. Protecting only the root or one `Batch` level is not conformant.
The envelope protects payload bytes, not the complete SQLite database. Raft and
SQLite metadata—including membership, terms/indexes, tenant and key routing,
owners, generations, fences, timestamps, request identities, and envelope key
IDs—remains visible to the host storage boundary. A deployment requiring
metadata or full-file encryption MUST add and qualify an approved database or
volume layer without moving provider access below the wrapper. Scoped
three-node in-process Openraft evidence uses actual file-backed nodes and
controllable RPC, explicitly forces snapshot installation, shuts down/restarts,
and restores both key epochs while counters prove replication, replay, quorum
formation, and snapshots perform no provider calls. Production KMS framing is
tested separately. This does not qualify multi-process or deployed-network
behavior; distributed protection/failure/soak evidence (#143) remains a
separate production-profile gate.

### 14.2 Integrity

AEAD integrity is required. Additional MAC fields MAY be used for backends that
need independent integrity checks, but they do not replace AEAD.

### 14.3 Privacy

Logs and metrics MUST NOT expose raw subscriber identifiers. The SDK SHOULD use
stable keyed digests for correlation when needed.

### 14.4 Transport Credential Rotation

Session TTL is application-state lifetime and MUST NOT be used as a certificate
lifetime, trust-bundle lifetime, or maximum-authentication-age policy. A
production networked session-store profile MUST rotate workload certificates
and trust bundles without interrupting service, use short-lived SVID expiry as
the bounded same-issuer credential-compromise/revocation response, and document
a maximum authentication age on long-lived connections. #161 atomic reload,
#162 coherent material epochs, and #163 finite connection
retirement/reauthentication are implemented. On epoch change or an explicit
orchestration request, both sides MUST stop new admission, end the transport
wait and release connection slots within the finite hard deadline, and repeat
the full mutual-TLS and application handshake on replacements.
Already-admitted supervised mutations retain the ambiguity/readback contract
above if their bounded backend work finishes later.

Rotation and reauthentication move cooperative participants but do not revoke
the old certificate/key. Its holder can establish a fresh connection until the
earliest expiry across every certificate in that presented chain while its
issuer remains trusted. Immediate generic CRL, OCSP,
certificate/identity-denylist, and other selective same-issuer revocation are
not implemented. Root removal is a trust-anchor cutover for all chains that
depend on it, not an expiry deadline or selective revocation.

The projected source's ongoing expiry monitor clears retained source material
at leaf expiry. It is not the authority for an earlier intermediate expiry.
`TlsMaterialController` MUST pre-scan every configured SVID-chain certificate,
mark material unavailable at the earliest effective chain expiry, and provide
the TLS readiness status. A production projected source MUST be paired through
`TlsMaterialController::new_from_projected_source` or
`new_pinned_from_projected_source`; direct subscription through a generic
controller constructor does not bind source failures and controller gauges to
one recorder. Source `Ready` alone MUST NOT satisfy this section.

An operator MUST publish overlapping old/new trust before new leaves, preserve
the exact stable SPIFFE and consensus scope, trigger reauthentication, and
verify that every directed peer path has authenticated on current material
before removing old trust. Removing that anchor cuts over later handshakes;
trigger reauthentication and prove that every chain depending on it is
rejected. The negative proof MUST remain visible to authentication/trust
alerting and MUST be accepted only when an immediate checkpoint proves the
exact qualified per-member delta with no concurrent increase, process reset, or
alert silence. Rollback before old-trust removal restores the prior leaf/material
publication and triggers another monotonic reauthentication generation;
rollback after removal MUST first restore overlapping trust and prove the
controller status is `Ready`, then restore the old leaf and trigger
reauthentication. A rollback MUST NOT reuse an old authenticated connection as
evidence. Its deadline MUST be derived from the exact fleet size and all bounded
two-pass operations, and the selected complete rollback material MUST be
revalidated against the deadline remaining immediately before every
publication. Evidence MUST bind one invocation, live-lease binding, monotonic
operation/nonce, exact member/checkpoint, phase/step, and fresh timestamp; it
MUST NOT contain the lease token. Serving withdrawal MUST remain executable
when evidence storage is unavailable. Reconnect-storm,
deployed root cutover, real partition/restart including active-mutator
crash/restart, broader fault behavior, deployed mixed traffic/watch/restore,
resource/soak, remote-HKMS, deployed-CNF, signed release, and wider distributed
production evidence remain #164/#143 under umbrella #158. The single-host
tests described in §12.3 cover bounded mixed traffic only through their exact
synthetic fault/expiry slice and make no evidence-schema/profile claim. They do
not change Openraft's sole commit authority, payload encryption, AAD,
key-provider/HKMS placement, durable formats, or encryption-at-rest
responsibilities.

## 15. Observability

Required metrics:

- `opc_session_store_ops_total{op,state_class,outcome}`
- `opc_session_store_latency_seconds{op,state_class}`
- `opc_session_store_cas_conflicts_total{state_class}`
- `opc_session_store_stale_fence_total{state_class}`
- `opc_session_lease_acquire_total{outcome}`
- `opc_session_lease_renew_total{outcome}`
- `opc_session_lease_lost_total{reason}`
- `opc_session_replication_lag_seconds{region}`
- `opc_session_cache_hit_ratio{state_class}`
- `opc_session_record_bytes{state_type}`
- `opc_session_restore_pages_total{outcome,cursor_profile,complete}`
- `opc_session_restore_page_records{cursor_profile}`
- `opc_session_restore_page_examined{cursor_profile}`
- `opc_session_restore_page_payload_bytes{cursor_profile}`
- `opc_session_net_connection_retirements_total{reason}`
- `opc_session_net_connection_lifecycle{state}`
- `opc_session_net_connection_drain_events_total{event}`
- `opc_session_net_connection_attempts_total{outcome}`
- `opc_session_net_reconnect_events_total{outcome}`
- `opc_session_net_watch_slow_consumers_total`

The lifecycle metric labels MUST come only from their closed SDK-owned reason,
state, event, and outcome enums. They MUST NOT contain endpoints, DNS names,
SPIFFE IDs, certificates, key material, transaction IDs, record keys, or
payload/backend text. The closed connection-retirement reason set includes
`idle_timeout`; it MUST NOT be counted as the `timeout` connection-attempt
failure. Bootstrap and partial active-frame timeouts remain `timeout` failures.
- `opc_session_restore_page_latency_seconds{cursor_profile}`
- `opc_session_restore_restarts_total{reason}` where `reason` is one of
  `stale_cursor`, `work_budget`, `response_too_large`, or `cancelled`

Restore metric labels MUST NOT include cursor bytes, key fields, tenant, owner,
payload, peer-controlled text, paths, or certificate identity. A product MAY
expose these metrics through its existing metrics facade; #133 does not add a
second registry or metrics authority.

Required logs for state transitions:

- `session_key_digest`
- `tenant`
- `state_class`
- `generation`
- `fence`
- `owner`
- `handover_tx_id`, when applicable
- `outcome`

Raw subscriber identifiers MUST be redacted.

## 16. Module Ownership

| Module | Responsibility |
| :--- | :--- |
| `opc-session-model` | Keys, record headers, generations, state classes |
| `opc-session-backend` | Backend trait and capability model |
| `opc-session-lease` | Lease manager and fencing rules |
| `opc-session-cache` | Local cache and snapshot publication |
| `opc-session-codec` | Session serialization and migrations |
| `opc-session-crypto` | Payload envelope integration with RFC 003 |
| `opc-session-replication` | Region log and apply rules |
| `opc-handover` | Generic handover storage state machine |
| `opc-session-testkit` | Fake backend, split-brain tests, stale fence tests |
| `opc-consensus` | The workspace's single Openraft import, identity, bounded codec, and consensus transport contracts |
| `opc-session-store::consensus` | Openraft adapter, deterministic session state machine, SQLite log/state/snapshot storage, and linearizable readiness |
| `opc-session-net` consensus profile | Mutual-TLS consensus-only peer transport; no direct backend mutation or rebuild authority |

Agents implementing backends must not modify NF-specific handover logic. Agents
implementing handover logic must use the public lease/CAS APIs and not bypass
fencing.

## 17. Testing Requirements

### 17.1 Unit Tests

- Session key tenant separation.
- CAS success and conflict.
- Stale fence rejection.
- Lease acquire/renew/release.
- TTL refresh with valid and stale fences.
- TTL zero, the exact 365-day maximum, maximum plus one, and `Duration::MAX`
  across direct, batch, replicated, persisted, and authenticated-wire paths;
  rejected values must have no partial effect.
- Serialization corrupt input rejection.
- Protocol-v5 golden frames with no target-width integer fields; checked
  fixed-width maximum/overflow conversion; exact collection limits; omitted
  restore fields recomputed; and size errors nested in batch results.
- Revision-2 negotiation with equal and unequal client/server limits, rejection
  below `MIN_NEGOTIATED_FRAME_SIZE` (8,192 bytes), the restore-minimum alias,
  executable conservative maximum-payload round trips, and
  fail-closed revision-1/revision-2 profile mismatch.
- Exact-limit and one-byte-over outbound encoding for every response/watch
  family; no oversized allocation or emitted prefix on rejection; non-truncated
  record/batch behavior; contiguous log and cursor-correct restore prefixes;
  fixed fallback redaction; and iterative consuming rejection of nested trees.
- One absolute write deadline for prefix/payload/flush; authenticated slow-reader
  reaping; handler/connection-slot return to baseline; repeated reconnect bounds
  on memory/tasks/file descriptors/CPU; and deterministic shutdown/abort while
  response serialization or socket writes are blocked.
- Exact-v5 handshake success plus older ALPN/version, profile, authentication,
  malformed acknowledgement, and replay rejection before backend dispatch;
  incompatible peers clear cached capabilities to all false/zero.
- Exact 1-byte and 128-byte owner/custom-key acceptance, empty and 129-byte
  rejection, canonical reserved-name handling, string ordering, and hostile
  Serde/session-net decode rejection without raw-value disclosure.
- Exact stable-ID 1/64-byte and replication-transaction-ID 1/128-UTF-8-byte
  acceptance/rejection, plus canonical lowercase hyphenated 36-byte CAS UUID
  admission across requests, responses, batches, nested replication carriers,
  log pages, and watch items.
- Valid legacy SQLite hydration; hostile owner/key types in records, active
  leases, key fences, and nested replication logs; no-effect rejection; and
  the bounded count-only audit's budgets, status/exit codes, and redaction.
- Versioned and bounded/current-valid original handover-envelope round trips;
  exact non-`OPCH` classifier cases (including ambiguous bare rejection); and
  malformed, zero-length, truncated, oversized, and typed-invalid rejection
  before mutation.
- AEAD AAD mismatch rejection.
- Nested replicated CAS protection at depths 1 through 16, rejection at depth
  17, exact 256-node acceptance and 257-node rejection, and fieldless errors.
- Replicate/rebuild/log/watch round trips through encryption and remote-sealing
  wrappers, including late-provider failure with no backend delegation or
  partial entry/page exposure.
- Cache generation checks.

### 17.2 Integration Tests

- Two owners racing for the same session.
- Owner pause beyond TTL, new owner writes, old owner resumes and is rejected.
- Handover prepare/activate/abort idempotency.
- Backend restart with leases recovered or invalidated according to profile.
- Geo-replication applies newer generation and rejects older generation.
- Cache invalidation after remote update.
- Coordinated v5 multi-replica admission and fresh-readiness behavior, including
  fail-closed mixed-profile peers and non-authoritative cached capabilities.
- Ambiguous mutation outcomes under response rejection/write timeout, proving
  callers recover through idempotency, fencing, and authoritative re-read rather
  than assuming rollback or blindly replaying the operation.
- A real Openraft proposal that commits before its forwarded result is delayed
  beyond the caller deadline returns typed ambiguity and produces exactly one
  durable application-journal event.
- Real SQLite external write-lock contention and async-future cancellation are
  bounded, retain at most one supervised worker, release it after interruption,
  and never classify a started mutation as safely retryable.
- Concurrent pristine three-node formation and mutation submission with one
  gap-free committed application journal on every replica.
- A one-node partition produces bounded readiness/write failure, then heals and
  rejoins without admitting a second authority path.
- Cross-node lease/CAS visibility and follower linearizable reads use the same
  Openraft barrier as `probe_durable_readiness`.
- Plaintext canaries written through the encryption wrapper are absent from
  SQLite database/WAL/SHM files, Raft logs and outcomes, captured consensus
  frames, and snapshots; restart and active-key rotation retain decryptability.
- Non-ignored three- and five-process single-host projected-mTLS cases combine
  one stable follower's test-only consensus-RPC admission loss with a different
  member's malformed-trust retained-last-good state, then prove survivor
  readiness/encrypted-canary progress, exact-address restart/catch-up, and
  repair. They separately drive a same-issuer leaf with a 75-second
  remaining-validity/expiry budget through its fixed 30-second soft-retirement
  window, hard drain, `LastGoodExpired`,
  survivor progress, and same-process valid replacement.

Run those two exact cases serially:

```bash
cargo test --locked -p opc-session-testkit --test qualification_mtls_multiprocess --no-default-features three_process_projected_mtls_unavailable_malformed_and_expiry_recovery -- --exact --test-threads=1
cargo test --locked -p opc-session-testkit --test qualification_mtls_multiprocess --no-default-features five_process_projected_mtls_unavailable_malformed_and_expiry_recovery -- --exact --test-threads=1
```

They are synthetic regression evidence, not a deployed network partition or a
production qualification. The bounded lease/CAS/read, watch, restore-scan,
readiness, and connection-recycling workload remains active throughout both
cases, and a restarted watcher reconciles the exact committed journal prefix
before resubscription.

### 17.3 Fault Injection

- Backend timeout.
- Partial batch failure.
- Redis/Aerospike failover.
- Clock skew.
- Network partition between owners and backend.
- Replication lag spike.
- Corrupt encrypted payload.
- Missing session key decryption key.

### 17.4 Performance Gates

Profiles must state which backend they apply to. Minimum SDK reference gates:

- Local cache read p99 under 50 microseconds.
- In-memory fenced CAS p99 under 100 microseconds.
- Backend adapter exposes measured p50/p99 for get, CAS, lease acquire, and
  renew.
- 100,000 updates/second per replica for in-memory or batched local profile.
- No packet fast-path benchmark depends on remote backend availability.

## 18. Acceptance Criteria

This RFC is implemented when:

1. Authoritative session writes require monotonic fencing and CAS.
2. Stale owners cannot overwrite newer session state after lease expiry.
3. Handover state transitions are idempotent and recoverable.
4. Geo-replication does not use wall-clock LWW for authoritative state.
5. Backend capabilities are declared and enforced by profile.
6. Session payloads are encrypted and tenant-bound.
7. Local cache supports fast reads without compromising write correctness.
8. Fault injection covers split-brain, failover, replication lag, and stale
   fences.
9. Every `Duration`-based TTL boundary accepts zero and the exact 365-day
   maximum, rejects
   larger values with the appropriate typed error before application/backend
   effects, and performs exact checked deadline arithmetic without unwinding.
10. Every replication operation tree is iteratively bounded to depth 16 and
    256 total nodes; every nested CAS is protected on write and unprotected on
    read; and transformation failure cannot delegate or expose a partial
    entry/prefix/page.
11. Owner IDs and custom session-key types have structural 1-through-128-byte
    invariants at every model, persistence, and transport decode boundary;
    legacy SQLite admission is bounded, count-only, read-only, and fail-closed;
    and invalid state is never silently rewritten.
12. `ConsensusSessionStore` is the only quorum-profile authority, all election,
    voting, log matching, commitment, membership, snapshots, and linearizable
    reads use the shared Openraft engine, and raw append/rebuild/lease sequencing
    cannot bypass it.
13. Durable readiness executes an Openraft linearizable barrier and waits for
    local committed apply; listener bind, TLS success, capabilities, local
    SQLite availability, and restore method availability cannot report ready.
14. The encryption/remote-sealing wrapper runs above consensus, plaintext and
    provider/key handles never enter Raft apply/log/snapshot transport, and the
    documented payload-envelope versus full-database boundary is qualified.
15. Divergence recovery (#128), operator-safe legacy-fork recovery (#129),
    bounded applied-state restore (#133), and finite connection
    reauthentication (#163) are implemented; distributed production
    qualification (#143) and fleet credential-rotation evidence (#164) under
    umbrella #158 have passed their own acceptance gates before a production
    claim (#161/#162 are implemented prerequisites).
