# OPC-SDK-RFC-001: Transactional Management Substrate

**Status**: Draft for Implementation  
**Version**: 2.0.0  
**Date**: 2026-05-19  
**Audience**: SDK implementers, NF owners, security reviewers, test authors

## 1. Abstract

This RFC defines the transactional management substrate for OpenPacketCore network
functions. It specifies the configuration commit state machine, the isolation
boundary between the management plane and data plane, the reference persistent
store, recovery behavior, authorization hooks, observability, and implementation
acceptance criteria.

The core invariant is:

> An NF's running configuration is a deterministic, validated, authorized, and
> durable projection of its YANG-defined configuration.

This RFC corrects the initial draft in four important ways:

1. The commit pipeline is a single-writer state machine, not a long-held async
   mutex.
2. The management plane is explicitly resource-isolated from the data plane.
3. SQLite WAL is allowed only as a reference management-plane store with
   container storage preflight checks.
4. Persistence, encryption, audit, rollback, and recovery are made explicit
   enough for independent implementation by multiple contributors.

## 2. Scope

### 2.1 In Scope

- gNMI, NETCONF, and local operator configuration commits.
- Candidate, running, startup, rollback, and shadow-security configuration
  stores.
- Authorization of configuration mutations.
- Durable commit history and audit trail.
- Deterministic change notification to NF subsystems.
- Reference SQLite persistence backend.
- Interfaces that allow other persistence backends later.

### 2.2 Out of Scope

- User-plane packet forwarding.
- High-rate session state. See RFC 004.
- Protocol parsing. See RFC 005.
- Full supply-chain evidence generation. See RFC 006.
- Cluster-wide consensus. This RFC covers per-replica local persistence and
  commit sequencing. Cluster-level orchestration must be layered above it.

## 3. Design Goals

### 3.1 Security

- Default-deny authorization for all write operations.
- Fail-closed behavior for corrupt storage, invalid identity, failed
  decryption, failed validation, and incomplete recovery.
- No unredacted secret material in audit logs, telemetry, traces, or error
  messages.
- Cryptographic binding between config payload, schema version, transaction
  metadata, and principal identity.
- Tamper-evident audit history.

### 3.2 Performance

- Configuration commits must not starve data-plane workers.
- Data-plane readers must see configuration through wait-free or bounded-time
  snapshot access.
- Commit admission must provide bounded memory growth and clear backpressure.
- Heavy validation, serialization, compression, encryption, and fsync must not
  run on the async I/O worker set.

### 3.3 Maintainability

- The state machine must be explicit and testable.
- Generated and hand-written validation must use the same error model.
- Storage backends must implement a narrow trait with deterministic semantics.
- Each phase must have owner modules, metrics, logs, and fault injection tests.

### 3.4 Functionality

- Support create, update, replace, delete, validate-only, commit-confirmed,
  rollback, and startup restore.
- Support path-level audit and change notifications.
- Support rollback points and schema migrations.
- Support shadow-security configuration that is not exposed through ordinary
  gNMI `Get`.

## 4. Core Concepts

### 4.1 Stores

The SDK defines the following logical stores:

| Store | Purpose | Durable | Exposed By gNMI Get |
| :--- | :--- | :--- | :--- |
| `candidate` | Transaction-local mutable config | No | No |
| `running` | Active immutable config | Yes | Yes, after NACM filtering |
| `startup` | Optional boot config alias or snapshot | Yes | Operator controlled |
| `rollback` | Explicit rollback points | Yes | Metadata only |
| `shadow-security` | gNSI/certificate/authz material | Yes | No |

The data plane MUST consume only immutable snapshots of `running` plus any
explicitly subscribed derived state. It MUST NOT read from `candidate`,
`startup`, or the raw persistence backend.

### 4.2 Config Snapshot

Generated root configs MUST implement:

```rust
pub trait OpcConfig: Clone + Send + Sync + 'static {
    type Delta: Send + Sync + core::fmt::Debug + 'static;

    fn schema_digest(&self) -> SchemaDigest;
    fn diff(&self, previous: &Self) -> Result<Vec<Self::Delta>, ConfigError>;
    fn apply_delta(&mut self, delta: Self::Delta) -> Result<(), ConfigError>;
    fn validate_syntax(&self) -> Result<(), ValidationError>;
    fn validate_semantics(&self, ctx: &ValidationContext) -> Result<(), ValidationError>;
}
```

`Clone` is required for the reference implementation, but large generated
configs SHOULD use structural sharing internally so candidate creation does not
copy every leaf for small patches.

### 4.3 Runtime Snapshot Access

The running config MUST be published through an atomic snapshot mechanism such
as `arc-swap` or an equivalent SDK type:

```rust
pub trait ConfigSnapshot<C>: Send + Sync {
    fn load(&self) -> std::sync::Arc<C>;
    fn version(&self) -> ConfigVersion;
}
```

Data-plane reads MUST NOT acquire the commit lock, await I/O, allocate large
buffers, or call validation hooks.

## 5. Commit State Machine

### 5.1 States

Each commit moves through the following states:

| State | Description | May Fail | Durable Side Effect |
| :--- | :--- | :--- | :--- |
| `Admitted` | Request accepted into bounded queue | Yes | No |
| `Authenticated` | Peer identity verified | Yes | No |
| `Authorized` | NACM/path policy passed | Yes | Audit denial |
| `Staged` | Candidate built from running snapshot | Yes | No |
| `SyntaxValidated` | YANG constraints passed | Yes | No |
| `SemanticallyValidated` | NF validation passed | Yes | No |
| `Prepared` | Serialized, encrypted, and ready to write | Yes | No |
| `Persisted` | Commit record and audit record fsynced | Yes | Yes |
| `Published` | Running pointer atomically swapped | No in normal operation | Yes |
| `Notified` | Subscribers informed | Best effort per subscriber | Metrics/audit only |

No state is allowed to panic as part of ordinary error handling. A panic in the
commit worker is a process bug and MUST be treated as `StateMachineFault`.

### 5.2 Corrected Phase Ordering

The commit worker MUST serialize commits, but it MUST NOT hold a
`tokio::sync::Mutex` across `.await`, blocking validation, encryption,
serialization, or database I/O. The recommended structure is:

1. Northbound handlers push `CommitRequest` into a bounded mpsc queue.
2. A single commit worker owns sequencing and transaction IDs.
3. CPU-heavy validation runs through a bounded blocking/CPU pool.
4. Crypto and serialization run through a bounded crypto pool.
5. Persistence runs through a single writer backend handle.
6. Publication is an atomic pointer swap.

This keeps ordering deterministic without turning the async runtime lock into a
global bottleneck.

### 5.3 Commit Request

```rust
pub struct CommitRequest<C: OpcConfig> {
    pub request_id: RequestId,
    pub principal: TrustedPrincipal,
    pub transport: TransportType,
    pub source: RequestSource,
    pub operation: ConfigOperation,
    pub mode: CommitMode,
    pub deadline: std::time::Instant,
    pub idempotency_key: Option<IdempotencyKey>,
    pub base_version: ConfigVersion,
    pub candidate: Option<C>,
    pub changed_paths: Vec<YangPath>,
}

pub enum CommitMode {
    Commit,
    ValidateOnly,
    CommitConfirmed { timeout: std::time::Duration },
    Rollback { target: RollbackTarget },
}
```

`idempotency_key` SHOULD be supported for northbound clients that retry after
`UNAVAILABLE`.

Candidate-bearing requests MUST carry the running config `base_version` used to
build the candidate. The ConfigBus worker MUST reject the request before
validation or publication when that value no longer matches the current running
version, so stale full-candidate writers cannot overwrite an intervening
commit.

### 5.4 Commit Result

```rust
pub struct CommitResult {
    pub tx_id: TxId,
    pub base_version: ConfigVersion,
    pub new_version: Option<ConfigVersion>,
    pub status: CommitStatus,
    pub changed_paths: Vec<YangPath>,
    pub apply_plan: Option<ApplyPlan>,
}
```

Failed commits MUST include stable machine-readable error codes. Error strings
MUST NOT contain secrets or raw config fragments.

Candidate-bearing commit, commit-confirmed, and validate-only requests SHOULD
return an `ApplyPlan` that classifies the operational impact of the
SDK-derived changed paths after validation and before durable append. The
default classifier returns `hot` plans so existing products remain compatible;
products MAY install a `ConfigImpactClassifier` for domain-specific `warm`,
`drain-required`, `restart-required`, or `forbidden-live` behavior.
`forbidden-live` and apply-plan hard errors MUST fail closed before durable
append/publication and attach the rejected plan to `CommitError.apply_plan`.

## 6. Management Thread Boundary

### 6.1 Required Execution Domains

The initial "Three-Pool" model is directionally correct but underspecified. The
SDK MUST implement the following boundaries:

| Domain | Work | Requirement |
| :--- | :--- | :--- |
| Async I/O | gNMI, NETCONF, gNSI, health, metrics | Never perform CPU-heavy work or fsync |
| Commit worker | Sequencing, state machine ownership | Single logical writer, bounded queue |
| Validation pool | Generated and NF semantic validation | Bounded threads and timeout |
| Crypto/serialization pool | RFC 7951 serialization, compression, AEAD | Bounded threads and memory |
| Persistence writer | SQLite or backend write transaction | Single writer per local store |
| Data-plane workers | Packet/session fast path | No dependency on management pools |

Implementations MAY combine validation and crypto pools for small deployments,
but the default carrier profile MUST expose independent limits for both.

### 6.2 Starvation Protection

The SDK MUST provide:

- Separate semaphores for validation, crypto, and persistence work.
- Configurable max queued commits, default `32`.
- Configurable max pending bytes across staged candidates, default `64 MiB`.
- Per-request deadline propagation.
- Admission rejection with gRPC `UNAVAILABLE` and retry metadata when queues are
  full.
- A hard rule that data-plane threads never run management-plane blocking work.

Carrier CNF deployments SHOULD pin data-plane workers and management workers to
different CPU sets using Kubernetes CPU Manager or an equivalent runtime
mechanism. The SDK MUST work without CPU pinning, but the documented production
profile MUST include it.

### 6.3 Time Budgets

Default phase budgets:

| Phase | Default Budget |
| :--- | :--- |
| Admission wait | 2 seconds |
| Syntax validation | 5 seconds |
| Semantic validation | 30 seconds |
| Serialization/encryption | 10 seconds |
| Persistence | 10 seconds |
| Notification fanout | 2 seconds per subscriber batch |

Budgets MUST be configurable per NF. Expired commits MUST fail before
publication. Persistence timeouts after partial backend work MUST be resolved by
backend recovery logic before the next commit is accepted.

## 7. Persistence Abstraction

### 7.1 Trait

```rust
#[async_trait::async_trait]
pub trait ConfigStore: Send + Sync {
    async fn load_latest(&self) -> Result<Option<StoredConfig>, PersistError>;
    async fn load_rollback(&self, target: RollbackTarget) -> Result<StoredConfig, PersistError>;
    async fn load_by_replay_lookup_digest(&self, digest: &str)
        -> Result<Option<StoredConfig>, PersistError>;
    async fn append_commit(&self, record: CommitRecord, audit: Vec<AuditRecord>)
        -> Result<(), PersistError>;
    async fn append_commit_resolving(
        &self,
        record: CommitRecord,
        audit: Vec<AuditRecord>,
        resolution: ConfirmedCommitResolution,
    ) -> Result<(), PersistError>;
    async fn clear_recovery_required(&self, tx_id: TxId) -> Result<(), PersistError>;
    async fn mark_confirmed(&self, tx_id: TxId) -> Result<(), PersistError>;
    async fn create_rollback_point(&self, tx_id: TxId, label: Option<String>)
        -> Result<(), PersistError>;
    async fn preflight(&self) -> Result<PersistCapabilities, PersistError>;
}
```

`append_commit` MUST be atomic: either the commit record and its audit records
are durable together, or neither is visible during recovery.
`append_commit_resolving` additionally MUST compare the current applied head,
resolve the exact pending commit-confirmed parent, and append its successor in
one state-machine operation. Splitting those actions permits two leaders to
make conflicting decisions and is prohibited. `load_by_replay_lookup_digest`
MUST be one authoritative lookup;
production stores must not walk a bounded ancestor prefix because history
length cannot become an availability limit for outcome reconciliation.

Once append admission may have reached durable authority, loss of the response
MUST be reported as `OutcomeUnknown`, not as a definite persistence or deadline
failure. The commit bus fences subsequent writes until an authoritative lookup
by request ID establishes an unkeyed result, or an exact same-key replay
establishes a keyed result. A request that changes mode, candidate, rollback
selector, confirmation timeout, caller-asserted base-version precondition, or
authenticated caller context is a collision, not a replay. The fenced bus may
answer the exact replay without performing a mutation, but it remains fenced
until its local snapshot is rebuilt from the authoritative store. If
authorities race after both miss the replay index, the compare-and-append loser
MUST reconcile the winner through that index; an unreadable winner is
`OutcomeUnknown`, never a definite persistence failure. Blind or semantically
changed retry is not a valid recovery strategy.

### 7.2 Commit Record

```rust
pub struct CommitRecord {
    pub tx_id: TxId,
    pub parent_tx_id: Option<TxId>,
    pub version: ConfigVersion,
    pub committed_at: Timestamp,
    pub principal: TrustedPrincipal,
    pub source: RequestSource,
    pub schema_digest: SchemaDigest,
    pub plaintext_digest: Sha256Digest,
    pub encrypted_blob: EncryptedBlob,
    pub rollback_point: bool,
    pub confirmed_deadline: Option<Timestamp>,
}
```

The plaintext digest is verified only after successful AEAD decryption. It is
not a substitute for AEAD integrity.

## 8. SQLite Reference Backend

### 8.1 Positioning

SQLite WAL is a sound reference backend for a single NF replica's management
configuration and audit history because commits are low-rate, read access is
local, recovery is simple, and the operational footprint is small.

SQLite MUST NOT be treated as a distributed consensus system. It MUST NOT be
used for high-rate session state or cross-replica active/active configuration
coordination.

### 8.2 Mandatory Container Storage Preflight

Before accepting writes, the SQLite backend MUST verify and report:

- Database path is on a persistent volume when persistence is required.
- Filesystem supports POSIX byte-range locking compatible with SQLite.
- WAL, SHM, and database files are on the same filesystem.
- The volume is not a known-unsafe network filesystem unless explicitly
  overridden by an operator with an evidence waiver.
- `fsync` is not disabled by mount options or runtime configuration.
- The database directory is writable only by the NF service account UID/GID.
- Free space is above configured threshold.
- Startup can create, checkpoint, close, and reopen a test WAL transaction.

If preflight fails, the NF MUST fail closed unless configured for an explicit
ephemeral development mode.

### 8.3 PRAGMA Profile

The reference backend MUST apply and verify:

```sql
PRAGMA journal_mode = WAL;
PRAGMA synchronous = EXTRA;
PRAGMA foreign_keys = ON;
PRAGMA locking_mode = NORMAL;
PRAGMA busy_timeout = 5000;
PRAGMA temp_store = MEMORY;
```

`locking_mode = EXCLUSIVE` SHOULD NOT be the default in containers because it
can break sidecar backup, online inspection, and some recovery workflows. The
backend MAY offer exclusive mode for sealed appliances, but the default is
`NORMAL` with a single SDK writer and no external writers.

`synchronous = EXTRA` is acceptable as a conservative default, but the backend
MUST document that durability still depends on the underlying filesystem and
storage class. Production deployments MUST use tested PVC/storage classes, not
overlay filesystem layers for durable config.

### 8.4 Schema

```sql
CREATE TABLE schema_version (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    schema_digest BLOB NOT NULL,
    sdk_version TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE config_history (
    tx_id BLOB PRIMARY KEY,
    parent_tx_id BLOB NULL REFERENCES config_history(tx_id),
    version INTEGER NOT NULL UNIQUE,
    committed_at TEXT NOT NULL,
    principal TEXT NOT NULL,
    source TEXT NOT NULL,
    schema_digest BLOB NOT NULL,
    plaintext_digest BLOB NOT NULL,
    encrypted_blob BLOB NOT NULL,
    rollback_point INTEGER NOT NULL DEFAULT 0,
    confirmed_deadline TEXT NULL,
    confirmed_at TEXT NULL
);

CREATE TABLE audit_trail (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tx_id BLOB NOT NULL REFERENCES config_history(tx_id) ON DELETE RESTRICT,
    sequence INTEGER NOT NULL,
    yang_path TEXT NOT NULL,
    op_type TEXT NOT NULL CHECK(op_type IN ('CREATE', 'UPDATE', 'REPLACE', 'DELETE')),
    previous_value TEXT NULL,
    new_value TEXT NULL,
    redaction_applied INTEGER NOT NULL DEFAULT 0,
    previous_hash BLOB NOT NULL,
    entry_hmac BLOB NOT NULL,
    UNIQUE(tx_id, sequence)
);

CREATE INDEX audit_trail_tx_id_idx ON audit_trail(tx_id);
CREATE INDEX config_history_rollback_idx ON config_history(version, rollback_point);
```

### 8.5 WAL Maintenance

The backend MUST:

- Set a bounded WAL autocheckpoint threshold.
- Run explicit checkpoints during graceful shutdown and after large commits.
- Export metrics for WAL size and checkpoint failures.
- Refuse startup when WAL recovery fails.
- Avoid deleting WAL or SHM files manually.

## 9. Encryption at Rest

Configuration encryption is specified here at the envelope level and governed
by RFC 003 for key management.

### 9.1 Algorithm

- Default AEAD: `AES-256-GCM-SIV`.
- Alternative for non-AES-accelerated targets: `XChaCha20-Poly1305`, if allowed
  by the deployment security profile.
- Random nonce generation is still REQUIRED even when using nonce-misuse
  resistant AEAD.

### 9.2 Envelope

```text
struct ConfigEnvelopeV1 {
    magic: [u8; 4] = "OPCE";
    version: u16 = 1;
    alg_id: u16;
    key_id_len: u16;
    nonce_len: u16;
    aad_len: u32;
    key_id: [u8; key_id_len];
    nonce: [u8; nonce_len];
    aad: [u8; aad_len];
    ciphertext_and_tag: [u8; remaining];
}
```

AAD MUST include:

- `tx_id`
- `parent_tx_id`
- `version`
- `committed_at`
- `principal`
- `schema_digest`
- `store_kind`

### 9.3 Key Derivation

When using a master secret, per-commit keys MUST be derived with HKDF-SHA256:

```text
salt = tx_id || schema_digest
info = "openpacketcore/config/v1" || store_kind || key_id
key = HKDF(master_secret, salt, info, 32)
```

The backend MUST support key rotation by retaining enough key metadata to read
old commits until the operator performs re-encryption or retention expiry.

## 10. Authorization Boundary

### 10.1 Auth Context

```rust
pub struct AuthContext {
    pub principal: TrustedPrincipal,
    pub spiffe_id: Option<SpiffeId>,
    pub transport: TransportType,
    pub source_ip: std::net::IpAddr,
    pub tenant: TenantId,
    pub authenticated_at: Timestamp,
}
```

### 10.2 NACM Requirements

The NACM engine MUST:

- Normalize YANG paths before policy evaluation.
- Reject ambiguous module prefixes.
- Treat missing policy as deny.
- Authorize every changed path, not just the top-level request path.
- Authorize `read`, `create`, `update`, `replace`, `delete`, `exec`, and
  `subscribe` actions separately.
- Enforce policy before candidate mutation and again before publication if the
  policy changed during a long-running commit.

Trie evaluation is acceptable for performance, but wildcard, subtree, module,
and default-deny semantics MUST be tested against RFC 8341 behavior.

## 11. Notifications

After publication, the ConfigBus MUST notify subscribers with:

```rust
pub struct ConfigChange<C: OpcConfig> {
    pub tx_id: TxId,
    pub version: ConfigVersion,
    pub previous: std::sync::Arc<C>,
    pub current: std::sync::Arc<C>,
    pub deltas: std::sync::Arc<[C::Delta]>,
    pub changed_paths: std::sync::Arc<[YangPath]>,
}
```

Subscriber channels MUST be bounded. Slow subscribers MUST be isolated so they
cannot block publication of future commits. Each subscriber must choose one of:

- `drop_oldest`
- `drop_newest`
- `disconnect_on_lag`
- `force_resync`

Byte-budgeted channels MUST charge an event before accepting it. The
conservative charge includes both retained snapshots, all deltas, and changed
paths. Config-model estimates include inline values and owned heap capacities
in bytes (for example `Vec<T>::capacity() * size_of::<T>()`, using checked or
saturating arithmetic) without cloning or serializing values. An unavailable
estimate, arithmetic overflow, or a single event larger than the full budget
engages the subscriber's lag policy; it MUST NOT fall back to shallow
`size_of` accounting. `disconnect_on_lag` preserves the order of events
already accepted and rejects the overflowing event before retention.

The byte limit is a conservative accounting bound rather than a strict
allocator-resident-memory bound. Shared allocations are charged in full for
each event occurrence. Allocator metadata, reference-count control blocks, and
queue spare capacity are excluded and MUST be documented by management
protocol adapters.

Critical NF subsystems that cannot tolerate missed notifications MUST expose a
resync method and compare local applied version against `ConfigBus::version()`.

## 12. Recovery

### 12.1 Startup

Startup MUST:

1. Run storage preflight.
2. Recover or checkpoint WAL if required.
3. Load highest confirmed config version.
4. Decrypt and authenticate envelope.
5. Verify plaintext digest.
6. Verify schema compatibility or run migration.
7. Run syntax validation.
8. Run semantic validation in startup mode.
9. Publish running snapshot.
10. Start northbound write admission only after running is published.

### 12.2 Rollback

If latest config fails startup semantic validation, the NF MAY try rollback
points in descending version order. It MUST audit the rollback decision on the
next successful write-capable startup. If no rollback point validates, the NF
MUST fail closed and expose a read-only recovery endpoint only if explicitly
enabled.

### 12.3 Commit-Confirmed

`commit-confirmed` MUST:

- Persist the tentative config with a deadline.
- Publish it as running.
- Require explicit confirmation before deadline.
- Automatically roll back to the parent config if not confirmed.
- Emit warning telemetry before rollback.

The rollback timer MUST survive process restart by reading persisted
`confirmed_deadline`.

## 13. Observability

Required metrics:

- `opc_config_commits_total{outcome,reason,transport}`
- `opc_config_commit_duration_seconds{phase}`
- `opc_config_commit_queue_depth`
- `opc_config_commit_queue_rejections_total{reason}`
- `opc_config_running_version`
- `opc_config_subscriber_lag{subscriber}`
- `opc_persist_wal_bytes`
- `opc_persist_checkpoint_total{outcome}`
- `opc_persist_fsync_duration_seconds`
- `opc_nacm_decisions_total{action,outcome}`

Required structured log fields:

- `request_id`
- `tx_id`
- `version`
- `principal`
- `tenant`
- `transport`
- `phase`
- `outcome`
- `error_code`

Logs MUST NOT contain secret values or raw config blobs.

## 14. Testing Requirements

### 14.1 Unit Tests

- State transition table.
- NACM path normalization and default deny.
- Candidate patch behavior.
- Encryption envelope parse/decrypt failures.
- Audit hash chain validation.
- Subscriber lag policies.

### 14.2 Integration Tests

- Concurrent commits serialize deterministically.
- Validation timeout does not block health/read endpoints.
- Persistence crash before commit is invisible after restart.
- Persistence crash after commit is visible after restart.
- WAL checkpoint and recovery on restart.
- Commit-confirmed rollback after process restart.
- Rollback point selection when latest config fails validation.

### 14.3 Fault Injection

- Disk full.
- `fsync` failure.
- Corrupt WAL.
- Corrupt encrypted blob.
- Missing key.
- Expired SPIFFE identity.
- NACM policy change during long commit.
- Slow or disconnected subscriber.

### 14.4 Performance Tests

Minimum carrier profile gates:

- Data-plane config snapshot load p99 under 1 microsecond in-process.
- Northbound read path remains available during 30 second semantic validation.
- Commit queue rejects rather than exceeding configured memory limit.
- 10,000 path-level audit records commit without unbounded memory growth.
- SQLite backend sustains 10 commits/second for 60 seconds on reference PVC.

## 15. Module Ownership

Contributors should implement these modules independently with the listed ownership:

| Module | Responsibility |
| :--- | :--- |
| `opc-config-bus` | Commit worker, snapshot publication, subscriber fanout |
| `opc-config-model` | Shared IDs, errors, request/result types |
| `opc-nacm` | Path normalization and authorization decisions |
| `opc-persist` | `ConfigStore` trait and SQLite backend |
| `opc-crypto` | Envelope encryption/decryption and key lookup adapter |
| `opc-audit` | Audit records, redaction markers, hash chain |
| `opc-config-testkit` | Fault injection, mock store, mock NACM |

Each module MUST expose a narrow public API, avoid cyclic dependencies, and
include doc examples for the primary workflow.

## 16. Acceptance Criteria

This RFC is implemented when:

1. A commit cannot publish unless authorization, validation, encryption, and
   durable append all succeed.
2. Data-plane snapshot access is independent of commit queue and persistence
   health.
3. SQLite preflight rejects unsafe durable deployments.
4. Recovery handles clean restart, crash restart, rollback, and
   commit-confirmed expiry.
5. Audit logs are tamper-evident and redacted.
6. Metrics expose queue, phase latency, persistence, and authorization health.
7. Fault injection tests cover all failures listed in Section 14.3.
