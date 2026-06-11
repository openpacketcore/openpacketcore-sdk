# OPC-SDK-RFC-004: High-Performance Session Store

**Status**: Draft for Implementation  
**Version**: 2.0.0  
**Date**: 2026-05-19  
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
    pub stable_id: bytes::Bytes,
}
```

Examples:

- SUPI-derived subscriber context key.
- PDU session ID plus SUPI hash.
- TEID mapping key.
- PFCP session SEID key.
- Handover transaction key.

Raw SUPI/GPSI MUST NOT be used directly as a backend key in production. The SDK
SHOULD derive stable keys with a tenant-specific keyed hash.

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

AAD MUST include:

- tenant
- NF kind
- session key digest
- state type
- generation
- fence
- backend namespace

### 14.2 Integrity

AEAD integrity is required. Additional MAC fields MAY be used for backends that
need independent integrity checks, but they do not replace AEAD.

### 14.3 Privacy

Logs and metrics MUST NOT expose raw subscriber identifiers. The SDK SHOULD use
stable keyed digests for correlation when needed.

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
- Serialization corrupt input rejection.
- AEAD AAD mismatch rejection.
- Cache generation checks.

### 17.2 Integration Tests

- Two owners racing for the same session.
- Owner pause beyond TTL, new owner writes, old owner resumes and is rejected.
- Handover prepare/activate/abort idempotency.
- Backend restart with leases recovered or invalidated according to profile.
- Geo-replication applies newer generation and rejects older generation.
- Cache invalidation after remote update.

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
