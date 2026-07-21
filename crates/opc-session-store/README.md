# opc-session-store

Session-state storage, leasing, fencing, replication, and restore primitives.

## Purpose

`opc-session-store` is the SDK substrate for per-session NF state. It models
stable session keys, generation counters, lease fences, compare-and-set writes,
backend capabilities, encryption wrappers, HA quorum coordination, and restore
evidence.

## API Shape

- `SessionBackend` defines storage operations: `capabilities`, `get`,
  `compare_and_set`, `delete_fenced`, `refresh_ttl`, `batch`, restore scans,
  replication-log methods, watch streams, and lease metadata.
- `SessionLeaseManager` owns acquire, renew, and release flows for fenced
  writes.
- `CompareAndSet`, `CompareAndSetResult`, `SessionOp`, and `SessionOpResult`
  model atomic mutation APIs.
- `ReplicationEntry::validate_sequence`, `validate_replication_prefix`,
  `validate_replication_page`, and `next_replication_sequence` define the
  checked 1-based log-position contract shared by adapters and consumers.
- `ReplicationLogRange`, `validate_replication_log_page`, and
  `MAX_REPLICATION_LOG_PAGE_ENTRIES` (65,536) define the exact checked cursor
  interval and returned-prefix contract shared by Fake/SQLite, wrappers,
  Openraft, cache, and network boundaries.
- `ReplicationTxId` makes the 1-through-128-byte durable idempotency/fork
  identity structural. New committed coordinator writes mint the fixed
  32-byte lowercase hexadecimal consensus request ID; valid legacy strings
  remain exact and are never normalized.
- `ReplicationEntry::into_validated`, `validate_replication_prefix_owned`, and
  `validate_replication_page_owned` consume caller-owned values and dismantle a
  rejected operation tree iteratively, avoiding recursive-drop exposure on the
  error path.
- `MAX_REPLICATION_OPERATION_DEPTH` (16) and
  `MAX_REPLICATION_OPERATIONS_PER_ENTRY` (256) bound every replication
  operation tree. The root is depth 1, and every operation node, including
  each `Batch`, counts toward the per-entry total.
- `MAX_SESSION_TTL` (365 days), `MAX_RECORD_EXPIRY_CLOCK_SKEW` (zero), and the
  TTL/absolute-expiry validators define the checked lifetime contract.
- `SessionKey`, bounded `StableId`, `SessionKeyType`, `StateClass`, `StateType`,
  `Generation`, `OwnerId`, and `FenceToken` describe session identity and
  ownership.
- `CustomSessionKeyType` makes deployment-specific key-type invariants
  structural, and `sqlite::audit::audit_sqlite_identity_invariants` plus the
  `opc-session-store-audit` binary provide a bounded, read-only legacy-store
  admission check.
- `StoredSessionRecord` carries key, generation, owner, fence, state class/type,
  expiry, and encrypted payload bytes.
- `FencedOwnershipStore` composes the existing backend lease, CAS, TTL, and
  committed-watch surfaces into key-agnostic logical ownership leases. Opaque
  keys contain 1 through 64 bytes, opaque metadata is capped at 64 KiB, every
  claim/renew/transfer commits a strictly higher fence-derived generation,
  and a key-scoped retained `FencedOwnershipMutationId` replays an exact
  committed result or rejects conflicting reuse while that result remains the
  current record. IDs are not a second global request registry.
  `FencedOwnershipToken` is the effect-point proof; a stale, equal, expired,
  wrong-owner, or wrong-namespace token fails closed. Logical expiry is derived
  from the backend-minted lease guard's authority timestamp, not a facade-local
  wall clock.
- `FencedOwnershipCache` is a bounded synchronous hot-path view whose hits
  clone only an `Arc`, not owner/metadata storage. An empty cache must replay
  from committed sequence 1 through a proven `FencedOwnershipCacheReplayHead`;
  resuming later requires an explicit `FencedOwnershipCacheSeed` asserting an
  externally coherent namespace, snapshot, head, and proof-completion
  timestamp. Entry count and total retained record bytes are independently
  bounded, and passive expiry is reclaimed through an ordered expiry index.
  A gap, malformed ownership record, capacity breach, stopped feed, clock
  regression, or lag beyond the explicit staleness bound returns
  `FencedOwnershipCacheLookup::Stale` without an owner. Its snapshot reports
  lag, retained bytes, and hit/miss/stale/feed-failure counters.
- `SqliteSessionBackend::open(path)` and `in_memory()` provide the reference
  backend.
- `EncryptingSessionBackend::new(inner, provider, backend_namespace)` wraps a
  backend with `opc-crypto`/`opc-key` envelope encryption.
- `ReplicaId`, `ReplicaEndpoint`, `ReplicaTlsIdentity`,
  `ReplicaFailureDomain`, and `ReplicaBackingIdentity` keep logical, network,
  authentication, placement, and physical-store identities distinct.
- `TopologyAttestationClaims` and `TopologyAttestationEvidence` bind an
  attestor-observed logical member, authenticated service identity, physical
  node, failure domain, durable backing, exact descriptor digest, collector,
  configuration epoch, and bounded validity window to one canonical digest.
  `QuorumTopologyAttestor` is the consumer-selected proof-verification port;
  constructing SDK values alone is not platform authentication.
- `BackendPeerBinding` is redaction-safe composition evidence retained for the
  legacy remote-backend compatibility transport. Production Openraft topology
  does not contain backend adapters; its consensus peer map performs live
  authenticated routing separately.
- `QuorumTopologyConfig::new_consensus` requires a cluster ID, exact
  configuration digest, and monotonic configuration epoch. Stable Openraft
  node IDs are derived from the cluster and logical `ReplicaId`; endpoint text
  is never identity. `ValidatedQuorumTopology::try_from` retains an explicitly
  labelled descriptor-only lab/compatibility admission. Production consumers
  use `ValidatedQuorumTopology::try_from_attested`, an explicit
  `TopologyAttestationPolicy`, one evidence token per exact member, and a
  selected `QuorumTopologyAttestor`. Both paths require an odd membership from
  3 through `QUORUM_TOPOLOGY_MAX_MEMBERS` (31), one exact local logical ID,
  unique declared identities, and an exact configuration digest before any
  backend I/O. Static profile methods report the fail-closed `Unknown` value
  for both descriptor-only and attested HA; only a time-aware production
  profile evaluation over fresh authenticated evidence may report `Quorum`.
- `ConsensusSessionStore::open` is the operational construction path.
  `QuorumSessionStore` is a compatibility type alias to that same Openraft
  implementation, not a second quorum algorithm. Callers install its
  consensus RPC handler, then call `initialize_cluster` for pristine storage.
  Every member may make that call concurrently. On clean first formation only
  the canonical lowest node initializes Openraft; the other pristine members
  wait for replicated membership. A member reopening durable Openraft state
  skips bootstrap and re-admits normally. Clean first formation fails closed
  when the canonical node is absent.
- `ConsensusSessionStore::probe_durable_readiness` uses the same bounded
  Openraft linearizable-read barrier as real authoritative operations. Its
  recovery-latch check and barrier share the configured complete-operation
  deadline; it does not treat a bound listener or cached capabilities as
  quorum evidence. Descriptor-only labs may use that engine-only probe;
  production traffic uses `probe_production_durable_readiness`, which first
  requires still-fresh `AuthenticatedPlatform` topology evidence.
- `recovery::LegacyForkRecovery` is the default-deny offline administrative
  boundary for a drained fleet. It creates a sealed, redaction-safe plan,
  quarantines every explicit target before mutation, installs one immutable
  checkpoint, journals crash-safe progress, and commits recovery fencing only
  through the current local Openraft leader. See the
  [operator runbook](../../docs/session-store-legacy-recovery.md).
- `DurableReadinessReport` returns `Ready`, `NoQuorum`, `TopologyInvalid`, or
  `RecoveryRequired`, together with `configured_voters`,
  `fresh_reachable_voters`, `agreeing_voters`, `required_quorum`, the optional
  committed/applied index, and typed observations without peer-controlled
  diagnostic text.
- `ValidatedQuorumTopology::try_new_consensus_lab_singleton` is the explicit
  one-replica Openraft lab path. Its platform profile is `single-replica`,
  never quorum HA; it still exercises the same log and state machine.
- Restore APIs include `RestoreScanRequest`, `RestoreScanPage`,
  `RestoreBlockReason`, summaries, page-size constants, and
  `summarize_restore_records`. Durable SQLite scans seek over the existing
  composite primary key, examine at most 4,096 live candidates plus one
  lookahead per page, cap combined payloads at 4 MiB, retained page bytes at
  8 MiB, and examined key/filter metadata at 8 MiB, and stop after 2,000,000
  SQLite VM steps or 1 second of SQLite work. One absolute restore deadline
  begins at the public entry point and covers the Openraft barrier/apply path,
  worker admission, asynchronous connection admission, SQLite progress, and
  task join. Each backend admits exactly one blocking restore worker, and the
  worker owns that permit until cancellation is observed and it exits.
  Timed-out callers cannot accumulate detached blocking tasks. Candidate SQL
  omits payload blobs; only selected records are fetched by exact primary key.
  Narrow scopes can therefore return an empty but advancing page. Their
  variable token is strictly bounded by the 2 MiB
  consensus RPC/key ceiling. HMAC-separated AES-256-GCM-SIV key and synthetic
  nonce domains make the encoding canonical for retries while keeping the seek
  key, backend epoch, record revision, logical time, and scope digest
  confidential and authenticated. The only clear metadata is a cumulative
  examined-row position bound into the cursor authentication. A receiver can
  check the server's claimed step structurally, and the issuer verifies it on
  the next request; this does not prove that a server returned a complete page.
  Cursors are backend-incarnation/node-bound: a same-PVC restart retains them,
  while mutation, scope reuse, token editing, another node, or an installed
  snapshot returns `RestoreScanCursorStale` and requires a first-page restart.
  The seek identifier is model-bounded to 64 bytes, so the complete hex cursor
  remains below 2 KiB and fits the legacy adapter's minimum frame.
  Exact response sizing returns typed `RestoreScanResponseTooLarge` without a
  partial frame unless peers negotiated a sufficient frame (up to 16 MiB).
- `opc-session-net` protocol v5 can transport only the durable opaque restore
  page profile. Compatibility offset cursors from `FakeSessionBackend` are
  local test evidence and are rejected by both remote client and server; this
  RPC does not create a second quorum or restore authority. Peer-page checks
  enforce structural bounds, order, scope, and claimed cursor progress only;
  production completeness comes from the barrier-confirmed local
  Openraft-applied state.
- The v5 adapter uses private fixed-width DTOs: `u32` request limits and
  restore-response budget; an exact confidential authenticated restore cursor;
  `u64` counts,
  `max_value_bytes`, and
  size-bearing store errors; checked conversion at both domain boundaries; and
  independent 256-batch, 1,024-restore, 65,536-log, and 65,536-rebuild limits.
  Its profile pins wire-schema revision 6, error-set revision 8,
  `max_restore_scan_examined_rows = 4096`,
  `max_restore_scan_page_retained_bytes = 8388608`,
  `max_restore_scan_examined_metadata_bytes = 8388608`, `min_frame_size = 8192`,
  `max_frame_size = 16777216`, the 128-byte
  owner/custom-key/state-type bounds,
  `stable_id_max_bytes = 64`, `replication_tx_id_max_bytes = 128`, and
  `cas_request_id_bytes = 36`. Stable IDs contain 1 through 64 bytes,
  replication transaction IDs contain 1 through 128 UTF-8 bytes, and CAS
  request IDs, when present, use the canonical lowercase hyphenated 36-byte UUID encoding.
  Revision 2 added exact directional frame negotiation. Revision 3 replaces
  revision 2's inspectable cursor fields with the confidential authenticated
  token, adds the page cursor profile, and pins the 4 MiB payload plus 4,096
  examined-candidate bounds. Error-set revision 3 carries typed restore
  stale-cursor, work-budget, and direct-CAS idempotency outcomes; revision 4
  adds the replication-log range, page-limit, and compacted-cursor outcomes;
  revision 5 adds the non-CAS backend and lease ambiguity outcomes; revision 6
  adds the typed bounded-watch catch-up outcome; and revision 7 adds
  absolute-record-expiry rejection.
  Hello requests the
  client's response limit, while HelloAck reports the accepted response limit
  and server request limit;
  all are fixed-width, at least `MIN_NEGOTIATED_FRAME_SIZE` (8 KiB, or
  8,192 bytes), and at most `MAX_NEGOTIATED_FRAME_SIZE` (16 MiB, or
  16,777,216 bytes). `MIN_RESTORE_SCAN_RESPONSE_FRAME_SIZE` aliases that minimum.
  Version/profile/authentication or malformed-handshake failure reports every
  capability boolean false with `max_value_bytes = 0`; cached capabilities are
  descriptive and never substitute for fresh quorum evidence.
- Direct CAS on the quarantined compatibility transport binds a canonical UUID
  to the authenticated logical peer, complete operation, cluster/configuration
  identity and epoch, and the server's process-scoped retry epoch. Exact
  success and conflict outcomes replay through a bounded single-flight cache.
  Reuse with another peer or operation is `CasIdempotencyConflict`; restart,
  retention rotation, pressure, or cancellation is
  `CasIdempotencyOutcomeUnavailable` before any retry mutation. The public
  remote backend never automatically resubmits an ambiguous CAS. Callers must
  re-read authoritative state and derive a new mutation. This compatibility
  cache is not a second durable authority and does not replace Openraft's
  atomically persisted production command outcomes.
- Every `SessionBackend`/`SessionLeaseManager` future is a cancellation
  boundary. Dropping a future signals cancellation; bounded admission and
  supervision remain owned until underlying work exits. Read resources are
  released after bounded cancellation completes, not necessarily immediately
  on `Drop`. A caller that drops a polled mutation future treats its result as
  unknown and re-reads authoritative state even if supervised work later
  finishes. Durable operation-bound replay is specific to Openraft and direct
  CAS contracts, not every adapter. An internal deadline or transport failure reports
  `BackendOperationOutcomeUnavailable` (lease:
  `OperationOutcomeUnavailable`) so callers do not retry an unknown effect.
  Spawned/blocking adapters must bound admission and retain a worker permit
  until the worker exits; dropping the async wrapper must not create detached
  unbounded work. The encrypted wrapper and HKMS/provider boundary are
  unchanged: cancellation does not bypass envelope encryption or expose
  protected bytes.
- `SqliteSessionBackend` admits one ordinary blocking worker per backend and
  acquires its async connection before spawning. The worker owns both permits
  until SQLite exits, uses a progress handler plus interrupt handle for future
  drop, caps external database-busy waits at 100 ms, and caps complete ordinary
  work at a two-second outward deadline. Failure before
  worker/connection/transaction admission remains retryable; once a CAS,
  non-CAS, or lease effect may have committed, or the async wrapper loses a
  started worker's outcome, the result is
  `CasIdempotencyOutcomeUnavailable`,
  `BackendOperationOutcomeUnavailable`, or
  `LeaseError::OperationOutcomeUnavailable`, respectively. Reads remain
  retryable. Consensus-gated SQLite reads use the same supervised worker path.
- The exact `opc-session-net/5` ALPN, version, and contract profile have no
  fallback or downgrade negotiation. Public session-net `Request`/`Response`
  remain, but `Hello`/`HelloAck` gain an optional `contract_profile`, so
  exhaustive construction and matching must account for the new field. The
  revision-2 public profile also adds `max_frame_size`, which is source-breaking
  for external struct literals/destructuring and requires the same coordinated
  fleet upgrade.
- Every protocol-v5 response and watch item is fully bounded-encoded before its
  length prefix is emitted. Common non-pageable and complete-page successes use
  one bounded encode with no sizing preflight. If a complete pageable response
  is too large, that direct attempt emits no prefix; bounded logarithmic sizing
  probes and the final encode reuse the same absolute deadline established
  before the first encode/probe. Lazy exact-length boxed chunks are not
  coalesced and retained
  encoded-JSON byte storage stays within the frame limit. Chunk metadata and
  allocator slab/RSS overhead are separate. Deadline and server-abort
  cancellation are checked cooperatively between synchronous serializer
  writes/chunks, and the same deadline continues through prefix, payload, and
  flush.
  Get/CAS records and positional batches are never truncated;
  restore/log pages may return only a complete cursor/sequence-preserving
  prefix; watch cannot skip an oversized sequence. A small SDK-owned,
  redaction-safe fallback is used when representable, otherwise the connection
  closes fail-closed. Slow-reader timeout releases the connection slot.
- Transport capabilities advertise
  the minimum of the backend maximum and `(frame - 8192) / 8` for both the
  accepted response and server request frames, rather than a raw frame size.
  The 8 KiB reserve and factor of eight cover the record/key/error envelope,
  worst-case JSON byte-array expansion, and equal escaping/metadata headroom. An
  advertised `max_value_bytes` remains executable across unequal client/server
  limits. At the exact 8 KiB minimum it is zero; the minimum fits the bounded
  maximum-profile metadata/envelopes, not a non-zero application payload. The
  1 MiB default advertises 130,048 bytes, while 16 MiB advertises 2,096,128;
  SQLite's complete 1 MiB limit requires at least 8,396,800 frame bytes. The
  ceiling is per frame: at the default 128 connection slots, concurrent
  ceiling-sized encodes can retain about 2 GiB before metadata/TLS/runtime
  overhead. The aggregate scales with `with_max_connections`, so aggregate
  limiting and resource/soak qualification remain #143.
- `SessionStore<B>` wraps a backend in a typed store handle.

```rust,no_run
use opc_session_store::{SessionBackend, SqliteSessionBackend};

async fn open() -> Result<(), opc_session_store::StoreError> {
    let backend = SqliteSessionBackend::in_memory()?;
    let caps = backend.capabilities().await;
    assert!(caps.atomic_compare_and_set);
    Ok(())
}
```

### Identity invariants and legacy SQLite admission

`StableId` contains exactly 1 through 64 opaque bytes. Its private storage and
fallible constructors make that invariant structural for direct Rust callers,
Serde, Fake/SQLite/cache/Openraft stores, restore pages and cursors,
replication/rebuild/watch values, and session-net facades. The JSON byte-array,
wire, and SQLite BLOB representation of every compliant legacy value is
unchanged. New SQLite tables also enforce BLOB type and width. Existing tables
are not rewritten on open; their complete drained state must pass the offline
audit described below.

Raw SUPI/GPSI bytes are forbidden. Use
`StableId::derive_hmac_sha256(tenant_privacy_key, tenant, canonical_subject)`
with a tenant-specific KMS/HSM privacy key and a product-defined canonical
subject representation. Privacy keys contain 16 through 64 bytes and canonical
subjects contain 1 through 256 bytes, bounding every derivation. The SDK
commits to one domain-separated, full-width 32-byte HMAC-SHA256 profile. It length-prefixes tenant and canonical subject
with unsigned 64-bit big-endian lengths and does not support digest truncation.
`SessionKey::digest_with_key` remains the separate digest of an already-built
composite key; it is not a substitute for deriving a privacy-safe `stable_id`.

`OwnerId` and a deployment-specific `SessionKeyType` name each contain exactly
1 through 128 UTF-8 encoded bytes. The limit is bytes, not Unicode scalar
values: for example, 64 two-byte `é` characters are accepted and 65 are not.
`SessionKeyType::Other` contains a `CustomSessionKeyType` with private storage,
so an empty, oversized, or reserved custom name cannot be constructed through
the public API. Runtime callers use the fallible `SessionKeyType::other`.

The canonical reserved names are `subscriber-context`, `pdu-session`,
`teid-mapping`, `pfcp-seid`, and `handover-transaction`. Parsing any of these
strings produces its well-known variant; `SessionKeyType::other` rejects it so
one persisted string cannot have two in-memory representations. Serialization,
display, SQLite identity, key-digest input, and `Ord` all use the canonical
string. Ordering therefore follows string order across known and custom values,
not enum declaration order.

Custom deserializers enforce the same bounds for Serde values and stop a stable
ID sequence after the first byte beyond the fixed maximum. SQLite point reads
validate persisted record owners; restore scans validate persisted stable IDs,
key types and owners before retaining row-owned identity bytes; lease acquire,
renew, release, and fenced mutations validate
the stored active owner before using it; and replication-log hydration validates
the complete nested entry. Session-net request and response decoding reuses
those deserializers before backend dispatch or caller exposure. Errors are
fixed or fieldless and do not include the rejected raw owner, key type, record,
or replication entry. Newly packed handover envelopes carry the `OPCH` magic
and an exact version byte, so their header and phase always decode strictly.
Original length-prefixed envelopes remain readable only when their phase is
complete, no larger than `HANDOVER_PHASE_HEADER_MAX_BYTES` (1,024 bytes), and
valid under the current `HandoverPhase` model. Non-`OPCH` input uses the exact
legacy classifier below; compatibility is not claimed for every arbitrary bare
payload or every envelope accepted by an older unbounded reader.

Before starting this SDK against an existing SQLite store, drain all writers
and run the audit against the resulting point-in-time database:

```text
opc-session-store-audit identity-invariants \
  --database /path/to/session-store.db \
  --max-rows N \
  --max-entry-json-bytes N \
  --max-total-json-bytes N \
  --expiry-reference 2026-07-13T18:00:00Z
```

All three budgets are required and non-zero;
`--max-entry-json-bytes` must not exceed `--max-total-json-bytes` or SQLite's
signed `i64` length range. The audit
opens an existing database read-only, enables SQLite `query_only`, scans one
consistent snapshot in fixed 256-row pages, and applies `--max-rows` across
`session_records`, `leases`, `key_fences`, and `session_replication_log` in
that order. The two JSON budgets bound individual and cumulative replication
entries before strict `ReplicationEntry` decoding and domain validation.

Report schema version 4 contains only the requested limits, the expiry
reference, per-table scanned counts, violation counts (`invalid_owner_fields`,
`invalid_session_key_type_fields`, `invalid_stable_id_fields`,
`invalid_replication_tx_id_fields`, `invalid_replication_entries`, and
`invalid_record_expiry_fields`), and an optional bounded `incomplete_reason`.
Relational expiry is checked against the reported reference; nested
compatibility CAS expiry is checked against its immutable replication-entry
timestamp. Relational stable-ID validation reads only SQLite type and length.
Transaction-ID validation retrieves at most 128 bytes and cross-checks the
exact relational and encoded representations. It
never emits the database path, row identity, tenant, owner, key type, stable
ID, payload, transaction, rejected row timestamp, or raw JSON. Omitting
`--expiry-reference` uses current UTC, but an explicit recorded RFC 3339 value
is required for a reproducible migration campaign.
The command contract is:

- `compliant` JSON on stdout and exit 0 only after the complete snapshot fits
  the budgets and has no violations;
- `violations_found` JSON on stdout and exit 1 after a complete scan finds one
  or more violations;
- `incomplete` JSON on stdout and exit 2 for row/JSON budget exhaustion,
  unsupported schema, database-read failure, or counter overflow; and
- redacted `error` JSON on stderr and exit 2 for invalid arguments or limits,
  database open/setup failure, or output failure.

`violations_found`, `incomplete`, and `error` all block upgrade. Increase the
budgets and re-run an incomplete audit, or perform a separately reviewed,
product-owned migration that preserves identity and authoritative-history
semantics, then audit the resulting snapshot again. The SDK and audit never
truncate, rename, normalize, delete, or rewrite invalid identities or log
entries automatically. Store replacement is the safer recovery when those
semantics cannot be established.

Run the same audit against every retained SQLite snapshot that could be
installed or used as a restore/rebuild source. A non-compliant snapshot must be
quarantined; after upgrade, take a fresh compliant snapshot before reopening
rollback/recovery coverage. The complete operator procedure, including
application-owned deterministic rekey requirements and rollback, is in
[`session-store-stable-id-migration.md`](../../docs/session-store-stable-id-migration.md).
The durable idempotency/fork-identity procedure is in
[`session-store-replication-tx-id-migration.md`](../../docs/session-store-replication-tx-id-migration.md).
The absolute-expiry audit, re-authoring, OpenRaft recovery, and rollback
procedure is in
[`session-store-record-expiry-migration.md`](../../docs/session-store-record-expiry-migration.md).

The identity audit deliberately does not read, decrypt, or classify payload
bytes in live records or nested `ReplicationOp::CompareAndSet` log entries;
`compliant` therefore does not certify handover payload compatibility. Every NF
or product using `HandoverEnvelope` must run a separate, provenance-aware
preflight over the complete drained/decrypted replay population: live records,
every recursively nested replication-log/snapshot record, restore/rebuild
sources, and any other retained copy that can become authoritative. Use
`unpack_raw_with_format` or typed `unpack_json_with_format`; decoder success
alone is not a pass. For non-`OPCH` bytes, the syntactic classifier is exactly:

- fewer than four bytes fall back to bare `Stable`;
- a zero first-word, or a big-endian length from 1 through 1,024 whose phase
  slice is truncated, is `InvalidHeader`;
- a complete 1-through-1,024-byte phase slice is an original envelope when it
  decodes as the current `HandoverPhase`; JSON-looking invalid phase bytes are
  `InvalidPhase`, while non-JSON-looking bytes fall back to bare `Stable`; and
- a length above 1,024 is `InvalidHeader` when the bytes after the first word
  begin, after ASCII whitespace, like a JSON value; otherwise it falls back to
  bare `Stable`.

This deliberately rejects some ambiguous bare values (for example
`[0, 0, 0, 1]` and some bare JSON) rather than downgrading possibly corrupted
typed state. Prefix collisions can also decode successfully: on a snapshot
known to predate `OPCH`, `HandoverEnvelopeFormat::VersionedV1` is necessarily a
historical bare collision, and every `OriginalLengthPrefixed` classification
must be confirmed against product provenance and payload semantics. When a
product can authoritatively identify a value as historical bare `Stable` state,
it must explicitly wrap the complete original bytes with `pack_raw`/`pack_json`
through a reviewed migration that preserves fencing, generation, encryption,
and payload semantics. Oversized/newly invalid phases or classifications that
cannot be proven need an equally reviewed semantic migration or store
replacement.

Accepted protocol-v4 identities keep the same JSON byte-array shape, but the
Rust API is source-breaking (`SessionKey::stable_id` becomes `StableId`,
`Other(String)` becomes `Other(CustomSessionKeyType)`, and both constructors
are fallible) and wire admission is semantically stricter. Handover decoding is
also source-breaking:
`unpack_raw` now returns `Result`, `unpack_json` returns
`HandoverEnvelopeDecodeError`, and `HandoverError` gains `InvalidEnvelope`.
`pack_raw`/`pack_json` now write the versioned `OPCH` envelope; a compatible
original or bare record rewrites to the versioned form on its next transition.
An older v3 participant can emit an empty or oversized value that v4 rejects
during exact contract negotiation. Do not use a mixed rolling deployment:
stop writers and traffic, run both preflights, upgrade every session-net
client/server/protection wrapper and every NF or product handover reader/writer,
then restart and restore traffic. Protocol v4's fixed-width DTO and handshake
now make the identity contract explicit.

The persisted handover migration is one-way once any `OPCH` record or replayable
copy is written: an older SDK reader treats the new envelope as opaque bare
`Stable` payload. Do not roll back binaries after that point. Rollback requires
keeping the fleet drained and either restoring one coherent fleet-wide
pre-upgrade checkpoint (explicitly accepting or reconciling all post-checkpoint
mutations) or running a reviewed reverse migration over every live and
replayable copy, including nested logs, snapshots, and restore sources. The v4
handshake does not make an opaque `OPCH` payload readable by an older binary.

### Validated HA construction

Build the complete descriptor set first, derive its order-independent
configuration digest with `opc_consensus::derive_configuration_id`, and pass
the resulting `ConsensusIdentity` to `QuorumTopologyConfig::new_consensus`.
Open each node with its own file-backed `SqliteSessionBackend`, snapshot
directory, and an exact map of every other stable node ID to a
`SessionConsensusPeer`. Install `rpc_handler()` on the dedicated authenticated
consensus listener before concurrently calling `initialize_cluster()` on the
fleet. During clean first formation the method admits only the canonical
lowest stable node ID as the Openraft initializer; other pristine members wait
for its exact membership to replicate. Persistent members skip initialization
on restart, so a noncanonical durable majority restarts normally. Do not form
membership from DNS order or start a local writer while peers are still
unidentified. Clean first formation requires the canonical node and fails
closed if it is absent; this restriction does not apply to a fleet reopening
persisted Openraft membership.

The topology member vector contains only `QuorumReplicaDescriptor` values.
The node's one local SQLite backend is supplied separately to
`ConsensusSessionStore::open`; remote members are represented only by their
descriptors and consensus-only peers. No dummy local database or legacy
`RemoteSessionBackend` is constructed for a remote vote.

Production replication uses `SessionConsensusServer` and
`RemoteSessionConsensusPeer` on the exact `opc-session-consensus/2` ALPN. The
live certificate's canonical SPIFFE URI, logical `ReplicaId`, stable node ID,
cluster, configuration digest, epoch, peer role, and fresh challenge must all
agree before an Openraft RPC is dispatched. Resolver or DNS aliases change
only the dial address; a bare self ID such as `epdg-app-0` can correctly name
the member whose route is an FQDN because the SDK never compares those strings.
The exact consensus contract uses transport/wire-schema revision 2 and
error-set revision 4. The wire adds the bounded payload-free expiry-authority
preflight, and the error set adds `RecordExpiryPreflightLimitExceeded`.
Revision 1/error revision 3 or older fails before dispatch. Drain traffic and
writers, then stop and upgrade every consensus member together; mixed-profile
rolling operation is unsupported.

Both durable domains use the shared 10-second operation default. Transport
families use 2 seconds for AppendEntries/Openraft read-index, 5 seconds for
Vote, and 10 seconds for InstallSnapshot/forwarded mutation/consumer
ReadBarrier. One absolute family deadline starts before per-peer lane
acquisition; a fresh DNS/TCP/mTLS/bootstrap path has a contained 1.5-second
sub-bound and does not receive additive time. A directed peer caches a fixed
primary/overflow pool of at most two authenticated connections after correlated
validated successes, with one in-flight RPC per lane.

Descriptor admission validates the complete descriptor set, its exact local
logical member, configuration digest, and stable derived node IDs without
holding a storage or network adapter. It is reported as
`descriptor-only-lab-ha`, not as observed platform proof. Production admission
additionally calls `ValidatedQuorumTopology::try_from_attested`. Each bounded
opaque proof is authenticated by the selected `QuorumTopologyAttestor`; the
SDK then independently rejects a wrong member/TLS/descriptor binding, a stale
cluster/configuration/epoch, an untrusted collector or provenance class, an
expired observation, or duplicate observed physical node, failure domain, or
durable backing identity. The dedicated consensus transport then
binds each descriptor's logical ID, node ID, endpoint, TLS identity, cluster,
configuration, and epoch to the live authenticated connection. Declared
failure-domain and backing strings remain configuration until an attestor
observes and authenticates matching platform facts.

The proof format is intentionally adapter-owned. A platform adapter creates
`TopologyAttestationClaims`, signs or otherwise authenticates
`canonical_digest()`, and carries that proof in
`TopologyAttestationEvidence::try_new`. Admission requires an explicit
`TopologyAttestationPolicy` containing the expected provenance, trusted
collector identities, and maximum observation age. Opaque proofs are limited
to 64 KiB each, collector lists and topology membership are bounded, and a
token validity window cannot exceed one hour. `DeterministicConformance`
evidence supports reproducible three-/five-member tests but cannot satisfy the
production readiness gate; production adapters select
`AuthenticatedPlatform` and must verify their real trust mechanism.

```rust,ignore
let policy = TopologyAttestationPolicy::try_new(
    TopologyAttestationProvenance::AuthenticatedPlatform,
    trusted_collector_ids,
    Duration::from_secs(300),
)?;
let topology = ValidatedQuorumTopology::try_from_attested(
    topology_config,
    one_token_per_exact_member,
    &policy,
    &platform_attestor,
    TopologyAttestationTime::now()?,
)?;
let attestation_context = topology.clone();
let store = ConsensusSessionStore::open(topology, local_sqlite, snapshots, peers).await?;
if !store
    .probe_production_durable_readiness()
    .await
    .is_production_traffic_ready()
{
    // Keep traffic readiness closed.
}

// Before the current observation expires, authenticate replacement evidence
// for the same immutable configuration and use it for subsequent probes.
let refreshed = attestation_context.verify_attestation_evidence(
    refreshed_tokens,
    &policy,
    &platform_attestor,
    TopologyAttestationTime::now()?,
)?;
if !store
    .probe_production_durable_readiness_with_attestation(&refreshed)
    .await
    .is_production_traffic_ready()
{
    // Keep traffic readiness closed.
}
```

The platform adapter, its trust roots, and token refresh/collection lifecycle
remain product-owned. Evidence is immutable and epoch-bound, but can be
refreshed for the same descriptor set without restarting the store. Membership
change requires freshly collected tokens for the new configuration epoch
rather than reuse of an old member or backing-store token. Verification anchors
each evidence set to an absolute monotonic expiry.
`VerifiedQuorumTopologyAttestation` deliberately implements neither
`Serialize` nor `Deserialize`, and its monotonic anchor is process-local.
Process restart therefore cannot carry that verified token or its monotonic
anchor: authenticate evidence again against current time before reopening
production traffic. An adapter may re-present a still-unexpired underlying
proof only when its proof-format replay policy permits that; otherwise it must
collect replacement evidence. Non-serializability is not a single-use or
anti-replay property for the opaque proof. The per-store wall-clock high-water
is likewise intentionally not persisted.

### Fresh durable readiness

`BackendCapabilities` and the static `platform_profile()` describe implemented
methods and engine shape, not observed platform provenance or current peer
reachability. Static HA profiles are therefore always `Unknown`. Before
opening production traffic, call `production_platform_profile_at(now)` and
require `Quorum`, then call `probe_production_durable_readiness()`. Require both
`DurableReadinessScope::ProductionTopologyAttested` and
`is_production_traffic_ready()` from that report; a bare
`DurableReadinessState::Ready` check is insufficient. The probe bounds all
asynchronous recovery and Openraft barrier work by both the configured
operation timeout and the evidence's remaining validity, then rechecks
wall-clock freshness before it can return `Ready`. The store also retains a
bounded nondecreasing wall-clock
high-water, so a forward or expired evaluation cannot be revived by a later
clock rollback; final checks repeat after the asynchronous barrier. Explicit
`*_at` calls must all use one trusted nondecreasing clock source. Descriptor-only
labs can call `probe_durable_readiness()` directly, but its `Ready` result is
engine evidence and must not authorize production traffic.
`topology_attestation_summary_at(now)` exposes only provenance, configuration
epoch, freshness durations, and result for diagnostics; the summary does not
apply monotonic expiry or the store clock high-water and is not authority.
Every report exposes a bounded `DurableReadinessScope`; production gates require
`ProductionTopologyAttested` and `is_production_traffic_ready()`, never merely
the generic `is_ready()` result of an `EngineOnly` report.
The probe does not scan replica application logs or run a second majority
algorithm. Openraft performs leader discovery and the quorum barrier, then the
adapter waits for local apply through the returned index. The report's `Debug`
output redacts replica identities and contains no raw transport, backend, or
peer-controlled error text.

`recovery_progress()` reports one stable local posture—`synchronized`,
`catching_up`, `awaiting_quorum`, or `recovery_required`—plus optional local
log, applied, snapshot, and purged indexes. These counters are bounded
operational evidence only. They contain no term, endpoint, certificate,
session key, transaction ID, or payload, and callers must not reconstruct a
repair decision from them.

`Ready` means Openraft completed a fresh linearizable barrier against the
admitted voting configuration and this node applied through that barrier. It
is point-in-time evidence, not an ownership lease. Every authoritative read or
write uses Openraft again rather than relying on an earlier probe result.
Consumers must keep ownership publication and traffic advertisement behind the
same continuously refreshed gate; a readiness report is not an ownership
lease.

Openraft owns election, voting, log matching, commitment, and linearizable
read authority. The SDK state machine owns deterministic session semantics,
the committed 1-based application journal, fencing, expiry logical time,
idempotent request outcomes, bounded snapshots, and watch cursors. Raw
`replicate_entry`, whole-state rebuild, and caller-selected lease sequencing
are rejected by the production consensus adapter; those are not alternate
ways to establish authority.

### Live topology-epoch transitions

`ConsensusSessionStore` supports one bounded, sequential topology transition
at a time. Construct a `SessionTopologyTransitionRequest` from the exact
expected epoch and desired descriptors, bind a
`SessionTopologyTransportAdmission`, and stage the desired peer map on every
current member and joining candidate. Staging grants only replication,
snapshot, and marker-barrier traffic; it grants neither application authority
nor voting authority.

`prepare_topology_transition` durably records the request, adds the exact new
learners, and proves every desired member applied the replicated learner-ready
marker. `commit_topology_transition` then fences application proposals, uses
Openraft's joint-consensus membership change, admits successor Vote traffic
only after exact joint membership is durably applied, commits the desired
uniform configuration, retires predecessor transport admission, and commits a
separate finalization record. A returned `Completed` status therefore cannot
be inferred from an in-memory route change or an uncommitted membership view.

Dropping or timing out either future never means rollback. The caller retries
the same request ID/digest and consults `topology_transition_status`; accepted
Openraft work retains the exclusive proposal-drain guard until its actual
terminal result. `abort_topology_transition` is explicit and succeeds only
before joint membership can have committed. It removes added learners and
verifies the exact old uniform membership before recording durable abort.
After joint commit, recovery always resumes forward.

The SQLite database keeps one immutable storage/genesis identity while the
active application authority advances by exact configuration epoch. Transition
evidence stores fixed-width digests, counts, phases, outcomes, and log indexes;
it never stores raw endpoints, TLS identities, backing identities, session
payloads, or key material. Payload sealing and HKMS remain outside Openraft as
described below. A process's original topology-attestation summary is not
silently reinterpreted as evidence for new descriptors: production readiness
remains closed until the desired epoch is reopened or explicitly supplied with
fresh exact topology evidence.

Each node uses the shared fixed eight-slot proposal admission pool. Normal
mutations and finite-expiry logical-time-floor proposals acquire from that same
pool within the operation's existing absolute deadline. After
`client_write_ff` accepts a command, a supervisor—not the caller future—owns
the permit until the accepted result resolves. Caller cancellation therefore
cannot create an unbounded detached Openraft queue. A finite-expiry preflight
returns success only after revalidating its payload-free descriptors against
the logical time returned by its committed floor command.

All fresh linearizable reads and mutation preflights also pass through exactly
one supervisor-owned Openraft check per node and at most 64 total callers
across the active and waiting cohorts. The operation's original deadline
covers admission and its wait for the result. Once a check is dispatched,
caller cancellation or timeout cannot
cancel it or start an overlapping check. Openraft still supplies every quorum
proof; the supervisor is only a local resource bound.

Each production mutation creates one hidden `SessionConsensusRequestId` and
keeps it across leader-forwarding retries. Failure before local proposal
submission remains `BackendUnavailable`. Once `client_write_ff` accepts the
command, deadline, receiver loss, fatal result loss, or an unvalidated forwarded
response is an unknown committed outcome: direct CAS returns
`CasIdempotencyOutcomeUnavailable`; non-CAS operations return
`BackendOperationOutcomeUnavailable`, which lease methods convert to
`LeaseError::OperationOutcomeUnavailable`. Openraft/state-machine durable
request outcomes prevent an internal retry of that same identity from applying
twice. A caller never receives a generic retryable availability error after
this boundary and must authoritatively re-read before deriving a new mutation.

### Openraft follower recovery

Openraft is the only online repair authority. Its term/log-matching protocol
may replace an uncommitted suffix above the persisted committed and applied
floor, or install a checksummed snapshot from the current leader. The SQLite
adapter independently rejects any truncate at or below either durable floor
and rejects a snapshot whose last log ID would move committed or applied state
backward. It never selects a branch by counting application rows visible now.

Snapshot receive/build/promote staging is file-backed and bounded. On restart,
the adapter validates the one metadata-referenced snapshot before Openraft
starts, removes only SDK-named interrupted staging files and unreferenced
promoted snapshots, and fails closed above 8,192 directory entries
or the current snapshot is missing, corrupt, or inconsistent. Snapshot table
replacement remains one SQLite transaction, so retry after interruption is
idempotent. Because Openraft schedules snapshot apply and covered-log purge on
separate workers, purge waits at most ten seconds for the persisted applied
floor and otherwise fails closed. Fences, lease credentials, application
sequence, request outcomes, and logical time move together with the
authoritative state-machine image.

Runbook: keep traffic and ownership publication closed unless readiness is
`Ready`. During `catching_up` or `awaiting_quorum`, restore authenticated peer
reachability and let Openraft reconcile; do not invoke raw rebuild or edit a
PVC. `recovery_required` blocks traffic and requires preserving the database,
snapshot directory, and redacted report for operator analysis. A database from
the removed pre-Openraft coordinator has no durable commit proof and uses the
explicit [#129 legacy-recovery workflow](../../docs/session-store-legacy-recovery.md);
current-format automatic recovery must never guess a legacy branch.

### Encryption and HKMS boundary

The required production composition is:

```text
application -> EncryptingSessionBackend / RemoteSealingSessionBackend
            -> ConsensusSessionStore -> Openraft -> SQLite/snapshots
```

Encryption or remote sealing completes before `client_write`. Openraft, peer
RPCs, follower apply, replay, and snapshot build/install receive only opaque
RFC 003 envelopes and never receive plaintext, key material, an HKMS provider,
or a key handle. Reads cross the wrapper in the opposite direction and use the
envelope key ID for historical-key lookup. A provider outage therefore blocks
a new plaintext write before consensus submission but does not prevent already
sealed Raft traffic, replay, or quorum formation.

`EnvelopeV1` is a validated boundary, not a caller assertion. Construction and
deserialization require the canonical RFC 003 envelope and session AAD; the
consensus adapter additionally matches the visible tenant, NF kind, state
type, generation, and fence fields to the record header. The protection
wrappers do not expose a raw-inner escape hatch. Once consensus claims a
SQLite file, retained clones and separately reopened raw handles fail closed;
they cannot bypass Openraft for reads, leases, mutation, rebuild, pruning, or
journal access, and their capability declaration collapses to the minimal
non-authoritative profile. The owning consensus adapter reports its own exact
capabilities separately.

This is payload-envelope encryption, not whole-database encryption. Session
payload bytes are sealed; SQLite/Raft metadata such as membership, log indexes,
tenant/key routing fields, owners, fences, timestamps, and key IDs remain
visible to the host storage boundary. Products requiring metadata or full-file
encryption must add an approved volume/database layer without moving HKMS into
the deterministic state machine. Qualification tests assert plaintext canaries
are absent from Raft logs, state/outcome tables, WAL/SHM files, captured
consensus frames, and snapshots. Local and remote-seal qualification covers
restart plus active-key rotation with historical decryptability. Remote unseal
receives the exact validated envelope key ID, while one current provider
configuration atomically selects the active key only for future seals. The
KMS/HKMS remains authoritative for historical retention/revocation; the SDK has
no local history cache, retirement API, or enforcement gate.

### Replication-log range cursor contract

`get_replication_log(start, limit)` describes one inclusive checked interval.
For both `start = 0` and `start = 1`, the first sequence is one. `limit = 0`
returns an empty page before a backend lock, provider call, Openraft barrier,
resolver lookup, or network operation. Otherwise the last admissible sequence
is `max(start, 1) + limit - 1`; arithmetic overflow returns
`InvalidReplicationLogRange`, and a limit above 65,536 returns
`ReplicationLogPageTooLarge`. `start = u64::MAX, limit = 1` is valid;
increasing that limit overflows. Empty logs, the terminal cursor immediately
after the head, and any future cursor return an empty page.

A non-empty result must start at the exact normalized cursor, remain
contiguous, and end inside that interval. It may be shorter only because the
current head or an outer encoded-frame budget was reached. The next request
starts at the first unsent sequence; no adapter may move past it. A contiguous
page before or after the requested range is a contract violation. Local
wrappers and the server reject it before caller exposure; the compatibility
client additionally drops the connection and cached capabilities before
another request can re-handshake.

When a requested sequence is no longer available, the adapter returns
`ReplicationLogCursorCompacted { resume_from }`, where `resume_from` is the
first sequence after the compacted floor. The resume point is not permission
to discard history: install a coherent snapshot/rebuild through the existing
Openraft or operator authority first, then resume incremental reads. A
zero-limit request does not consult the floor. `ConsensusSessionStore`
executes one linearizable Openraft barrier and reads only its local applied
SQLite state; it never unions pages or compaction floors from replicas.
Differing floors therefore produce typed local outcomes, not a synthetic page
that skips committed history.

These rules constrain range selection only. They do not create sequencing,
commit, snapshot, restore, or watch authority and do not change payload
envelopes, AAD, provider/HKMS placement, or encryption-at-rest composition.
The replication-log range outcomes were introduced in quarantined session-net
v4 error-set revision 4. Historical v4 revisions 5 through 7 added non-CAS
backend/lease ambiguity, bounded-watch catch-up, and absolute-record-expiry
rejection. Current v5 error revision 8 adds the bounded expiry-preflight limit
outcome and uses a distinct ALPN. Drain and upgrade all
compatibility participants together before restoring traffic.

### Replication-watch cursor and handoff contract

`watch(start_sequence)` uses an inclusive 1-based cursor. Zero is the
empty-head sentinel and normalizes to one. An existing cursor first emits that
entry; a future cursor waits and never receives a lower live entry.
`u64::MAX` is a valid future/terminal cursor. If that entry is ever delivered,
the stream closes after the item because a reconnect successor cannot be
represented. Otherwise reconnect from a processed item uses its checked
successor.

Backlog capture and live registration share the watcher-registry lock. Fake
captures under its state lock; SQLite holds the registry while it completes
the bounded journal query. An append that races this handoff is therefore
either in the backlog or delivered live exactly once. A notification already
captured in the backlog, or committed while a requested future cursor is still
waiting, is below that watcher's live cursor and is ignored; a true gap above
the next eligible sequence closes the watcher. Each watch owns at most 64
backlog entries plus a 64-entry live channel. More retained backlog returns the
fieldless,
non-retryable `ReplicationWatchCatchUpRequired`: invalidate dependent state,
perform the product's coherent snapshot/full-cache catch-up, and reconnect
from the position that procedure proves. It does not provide a cursor or
permission to skip history. `ReplicationLogCursorCompacted { resume_from }`
remains distinct and requires snapshot installation before its resume point.
Slow consumers are evicted when the live channel fills, and closed or
cancelled registrations are pruned without unbounded accumulation.

`ConsensusSessionStore` completes a linearizable read barrier before the
atomic local handoff using `opc-consensus::LinearizableReadBarrier` in its
default full-round mode. The shared gate waits for the serving node's local
Openraft apply after either a local or remote-leader fence; session-store adds
only membership, recovery, and route adapters. Only Openraft state-machine
apply publishes live entries. Merely appending a local Openraft log record
cannot make it visible.
Raw append/rebuild remains rejected beside that authority. The quarantined
session-net client performs the dedicated watch handshake before returning a
stream, so an initial typed rejection is returned exactly and is never
reclassified as disconnect ambiguity. It then requires the first and every
later entry to match the next inclusive cursor. Invalid, duplicated, skipped,
or otherwise malformed authenticated-peer metadata terminates the dedicated
connection with a redaction-safe protocol failure before an outer encryption
wrapper can invoke its provider. A typed backend stream error also ends that
stream; the next independent request uses a fresh authenticated connection.

`StoreError::ReplicationWatchCatchUpRequired` introduced the legacy
protocol-v4 error-set transition from revision 5 to 6. Exact-profile
negotiation requires a coordinated stop/upgrade/start. The wire schema,
Openraft consensus profile, persisted journal/snapshot format, encryption
envelopes, AAD, and local/remote HKMS boundary did not change for that
transition.

### TTL input contract

Every public `Duration` supplied as a session refresh or lease TTL is bounded
by `MAX_SESSION_TTL`, exactly 365 days. `Duration::ZERO` is valid and means
immediate expiry; the exact maximum is valid; any larger duration fails with
the redaction-safe
`StoreError::InvalidSessionTtl` or `LeaseError::InvalidSessionTtl` as
appropriate. The ceiling accommodates long-lived sessions and planned
maintenance/recovery windows while preventing a malformed value from creating
an effectively permanent lease; products may impose a smaller limit.
A zero-duration acquire may still consume a fence, credential, and replication
position before the lease is observed expired; callers must use `release` for
explicit revocation rather than treating zero as a rollback primitive.
`validate_session_ttl` enforces the duration bound, while
`checked_session_deadline` converts seconds and subsecond nanoseconds with
checked integer arithmetic and checks addition against the supplied clock. The
deadline path does not use floating-point duration conversion or panicking
timestamp addition.

Direct acquire, renew, and TTL-refresh calls, nested batch operations, nested
replication operations, forwarding/encryption/cache wrappers, quorum dispatch,
Fake/SQLite backends, and the session-net client/server boundary all reject an
invalid TTL before application/backend state, replication-log, watch,
cryptographic-provider, or database effects. A session-net client rejects
before resolver or network work; an authenticated server necessarily receives
and decodes the request, then rejects before backend dispatch and may return the
typed response on the same connection. The same checks remain in local backends
so direct callers and peers that did not validate at their first boundary still
fail closed.

This is a compatibility boundary. The public error enums gain variants, so
external exhaustive matches must add arms. Protocol v4 introduced the TTL
fixed-width DTOs in error revision 1; current v5 error revision 8 retains those
encodings and adds the bounded expiry-preflight outcome. An error-revision-7 or
older peer is not admitted. Before upgrading a store created by an older SDK, audit
its persisted replication log for TTL-bearing
operations above 365 days. Such legacy entries now fail closed during replay or
rebuild; the SDK does not silently clamp or rewrite them. Replicated
absolute-deadline validation permits at most one microsecond above the exact
`entry.timestamp + ttl` solely for compatibility with legacy `seconds_f64`
rounding. New deadlines remain exact, the tolerance does not enlarge
`MAX_SESSION_TTL`, and larger deadline mismatches still fail closed.

This TTL is application-state lifetime, not certificate expiry, trust-bundle
validity, or maximum authentication age. `opc-session-net` supplies finite
connection reauthentication under #163; fleet trust/revocation and deployed
continuity evidence remains #164/#143.

Caller-authored absolute `StoredSessionRecord::expires_at` has a separate but
equal finite horizon. Relative to the mutation authority's one captured
reference timestamp, a finite expiry may be past, immediate, or at most
`MAX_SESSION_TTL` in the future. The exact maximum is accepted; one nanosecond
more is rejected with fieldless `StoreError::InvalidRecordExpiry`.
`MAX_RECORD_EXPIRY_CLOCK_SKEW` is zero: coordinator clock synchronization is an
operator prerequisite, not a silent retention extension. Arithmetic saturates
at the timestamp range maximum and cannot unwind.

`None` intentionally means non-expiring and is accepted for
`AuthoritativeSession`, `DataplaneLookup`, `ReplicatedDr`, and
`TelemetryDerived`. It is rejected for `EphemeralProcedure`, whose existing
profile requires per-key expiry to collect abandoned procedure state. Direct
Fake/SQLite operations and whole batches use one injected backend-clock value.
Forwarding wrappers delegate that authority and never substitute a process
wall clock. Compatibility replication validates every nested CAS against the
immutable `ReplicationEntry::timestamp`.

Production OpenRaft leaders validate before proposal against the command's
leader-authored logical time. Apply, replay, and follower paths repeat the
verdict against the same committed metadata; follower clocks never decide it.
Remote and consensus clients never substitute their wall clock for authenticated
coordinator authority. Every forwarding wrapper MUST obtain the bounded,
payload-free authority preflight before cache invalidation, provider/HKMS work,
or sealing. The actual authenticated CAS/batch dispatcher repeats that
preflight before idempotency admission or backend dispatch. Invalid input and
preflight timeout/unavailability perform no provider call or requested state
mutation; the caller may retry because only a consensus logical-time floor may
have committed. Payload encryption, AAD, key selection, and HKMS placement are
unchanged.

Existing valid rows keep their representation. The version-4 count-only audit
accepts a pinned `--expiry-reference`, counts invalid relational deadlines,
and validates compatibility-log CAS deadlines against entry timestamps. It
never clamps or repairs data. Follow the drained backup, product-aware
re-authoring, OpenRaft rebootstrap, and rollback procedure in
[`session-store-record-expiry-migration.md`](../../docs/session-store-record-expiry-migration.md).

### Bounded protected replication trees

Every `ReplicationEntry` is validated iteratively against the public depth and
count limits above. A root operation is at depth 1; each child is one level
deeper. Every node counts once, whether it is a `Batch`, `CompareAndSet`, or any
other `ReplicationOp`. An empty root `Batch` therefore has depth 1 and count 1;
the deepest permitted node is at depth 16, and an entry may contain at most 256
nodes. A violation returns the fieldless, redaction-safe
`StoreError::ReplicationOperationLimitExceeded` without reporting the observed
shape or values.

Validation of an outbound entry or complete rebuild prefix finishes before
payload transformation, provider work, or backend delegation. Validation of a
complete returned page or watch item finishes before read-side transformation
or caller exposure; the backend has necessarily already produced that read.
Post-decode traversal and tree reassembly are iterative, and rejected owned
trees are dismantled iteratively, so accepted transformation and consuming
rejection do not recurse through the operation tree. Protocol v5 carries the
same depth-16/256-node rules in the exact contract profile and bounds its private
DTO collections before domain construction. Batch requests admit at most 256
operations; replication-log pages and rebuild prefixes admit at most 65,536
entries. The negotiated frame limit remains a separate encoded-byte bound.
Outbound sizing and emitted encoding use capped buffers and emit no prefix when
the result cannot fit. Batch results retain exact positional cardinality and are
never shortened. Replication-log results may expose only the largest complete
contiguous prefix; restore pages may expose only a complete cursor
prefix. An over-limit watch entry is not skipped because doing so would hide a
sequence gap; the stream terminates after a representable fixed error or by
closing the connection. Rejected owned operation trees continue to be
dismantled iteratively.
`EncryptingSessionBackend` and `RemoteSealingSessionBackend` then transform
every nested `CompareAndSet` record: replicate/rebuild paths encrypt or seal
before backend delegation, while replication-log and watch paths decrypt or
unseal before caller exposure. Non-payload fields and operation order are
preserved exactly.

Provider calls are sequential. A write-side transformation is staged in full,
so a failure at a late nested CAS causes no backend delegation or mutation;
earlier provider calls may already have occurred. A read-side page or watch
item is likewise exposed only after its complete operation tree has been
successfully transformed. Failure returns an error instead of a partially
decrypted/unsealed entry or page, although earlier provider calls—and earlier,
separate watch items already yielded by the stream—may have occurred.

This changed the confidentiality contract before the v4 boundary. `StoreError`
gains a public variant, so exhaustive matches must add an arm, and an older v3
peer cannot decode it. More importantly, an older wrapper does not protect
deeply nested CAS records. Protocol v4 rejects the older wire participant and
pins the two tree limits and error revision, but a session-net handshake cannot
prove that the product actually installed an encryption/sealing wrapper.
Upgrade every client, server, and protection-wrapper participant as one
coordinated fleet, verify the composition, and do not claim rolling
compatibility.

The SDK does not discover or scrub historical nested plaintext automatically.
Before upgrading, perform an offline audit of both operation-tree shape and
payload encoding without logging payloads. An entry already within the 16/256
limits whose nested CAS crossed a protection boundary as plaintext/unsealed may
be explicitly rewritten or rebuilt through the configured encryption/sealing
wrapper. A historical over-limit entry is rejected before wrapper
transformation and cannot use that path unchanged; it is never clamped or split
automatically. Replace the store under the product's audited recovery procedure,
or use a separately reviewed offline migrator that preserves the original
atomic semantics before the new SDK reads the log. Calling a raw inner-backend
rebuild does not add protection.

This closes #147's nested-wrapper traversal gap only. Durable sequencing now
uses Openraft under #127, but the networked profile remains experimental until
the remaining qualification gates pass. Seamless SVID/trust-bundle lifecycle
remains #158, while distributed payload-protection qualification remains #143.
These are separate mandatory gates, and the operation-tree limits do not
provide rotation evidence.

The outbound bound does not make backend effects transactional with response
delivery. A compare-and-set, batch slot, lease operation, replicated append, or
rebuild can complete before bounded encoding or the socket write fails. A
missing response is therefore an ambiguous mutation outcome, not evidence of
rollback; callers must follow the existing request-id/idempotency, fencing, and
authoritative re-read rules before retrying. Diagnostics use fixed
operation-family/reason categories and never record keys, owners, payloads,
transaction IDs, peer identities, or backend/peer-controlled error text.

## Fenced ownership

The ownership facade does not add a database, sequencer, election, encryption,
or product placement policy. In production, wrap the existing
`ConsensusSessionStore` in `EncryptingSessionBackend` with the deployment's
session `KeyProvider`/HKMS integration, then pass that wrapper to
`FencedOwnershipStore`. The facade itself does not call a key provider: passing
a plain backend stores a plaintext ownership payload. Correct composition seals
the opaque metadata in the existing authenticated session envelope while
retaining Openraft as the only commit authority. Standard session-record
headers (including lookup key and owner) keep their existing storage contract;
use a keyed digest rather than a sensitive raw identifier as the opaque key.
A short bounded backend lease only serializes one mutation; the expiring
authoritative record is the logical ownership lease. Passive expiry removes the
live record while the backend fence floor remains, so an ABA return to a former
owner still receives a higher generation.

```rust,no_run
use std::time::Duration;
use opc_session_store::{
    FencedOwnershipKey, FencedOwnershipMetadata, FencedOwnershipMutationId,
    FencedOwnershipNamespace, FencedOwnershipStore, OwnerId, SystemClock,
};
use opc_types::{NetworkFunctionKind, TenantId};

async fn claim<B>(backend: B) -> Result<(), opc_session_store::FencedOwnershipError>
where
    B: opc_session_store::SessionBackend
        + opc_session_store::SessionLeaseManager
        + 'static,
{
    let namespace = FencedOwnershipNamespace::new(
        TenantId::new("tenant-a")
            .map_err(|_| opc_session_store::FencedOwnershipError::InvalidKey)?,
        NetworkFunctionKind::new("epdg")
            .map_err(|_| opc_session_store::FencedOwnershipError::InvalidKey)?,
    );
    let ownership = FencedOwnershipStore::new(backend, namespace, SystemClock);
    ownership.validate_authority().await?;
    let record = ownership
        .claim(
            FencedOwnershipMutationId::new(),
            FencedOwnershipKey::new(b"caller-canonical-key")?,
            OwnerId::new("epdg-0")
                .map_err(|_| opc_session_store::FencedOwnershipError::InvalidKey)?,
            Duration::from_secs(30),
            FencedOwnershipMetadata::empty(),
        )
        .await?
        .into_inner();
    ownership.validate_fence(&record.fence_token()).await
}
```

Dropping an in-flight mutation makes its outcome unknown. The bounded mutation
lease and logical expiry preserve safety; retry only the exact retained
mutation ID and inputs, which recovers the committed result without applying a
second ownership change. Cache watch consumption owns no detached task and
marks and clears the view on explicit shutdown. Cache bootstrap has exactly two
safe forms: replay every committed entry from sequence 1, or install a
`FencedOwnershipCacheSeed::from_caller_proven_snapshot` whose records and head
were bound by an external coherent authority. Both proof types carry the time
that proof completed; installing them never resets an old view's freshness to
the local installation time. Manual full replay must call `begin_full_replay`
with a caller-proven head before applying sequence 1;
`run_watch_until` obtains a linearizable head from the backend and does this
automatically. A partial backlog remains stale. A healthy but quiet watch is
not a heartbeat and ages stale at the configured bound until another committed
entry or externally coherent proof arrives. The public restore-scan cursor
does not expose an atomic replication watermark, and bounded watch catch-up
does not manufacture one, so the SDK does not claim a turnkey arbitrary-cursor
snapshot/watch handoff. Selecting eligible owners, deciding when failover is
safe, interpreting metadata, and programming packet routing remain consumer
responsibilities. This primitive does not by itself graduate the networked
session-store profile; deployed failure/resource/soak evidence remains tracked
by issue #143.

## Relationships

- Uses `opc-types` for tenant/NF/time/version identifiers.
- Uses `opc-key` and `opc-crypto` in `EncryptingSessionBackend`.
- Used by `opc-session-cache`, `opc-session-net`, `opc-session-testkit`, and
  AMF-lite.

## Status Notes

- Raw subscriber identifiers should not be used as production `SessionKey`
  stable IDs; prefer keyed digests.
- Fenced CAS rejects stale-owner writes.
- `StateClass` drives monotonic-generation and profile requirements.
- SQLite file backends use WAL in tests and persist across restart.
- `FakeSessionBackend` is for tests.
- Descriptor-only topology validation proves only an odd, distinct voting set
  and one exact local member and is explicitly lab-labelled. Attested admission
  adds authenticated, epoch-bound platform facts; authenticated consensus peers
  add exact identity binding at admission. Openraft supplies durable commit and
  fresh linearizable readiness. #129 supplies operator-safe legacy-fork
  recovery, while #133 supplies bounded local applied-state restore without
  becoming a second consensus authority. Production qualification remains a
  separate gate.
- A bare logical self ID such as `epdg-app-0` may select a member whose endpoint
  is the full `epdg-app-0.<headless-service>.<namespace>.svc.cluster.local`
  FQDN. The SDK never shortens endpoints or treats endpoint text as identity.
- The local ID declares the node's own configured replica. Admission proves an
  exact descriptor match. The separately supplied local SQLite backend remains
  a product composition boundary; a peer manifest does not prove physical-store
  provenance.
- Endpoint DNS names are canonicalized for case and one trailing dot.
  Endpoint text is routing, never replica identity. TLS/failure-domain values
  are exact caller-provided identities; callers must use canonical deployment
  values. Backing identities are caller-provided stable physical IDs retained
  only as SHA-256 digests, not verified storage provenance.
- Restore-scan RPC parity does not create authority. The production adapter
  first completes an Openraft barrier and local apply, then runs the bounded
  snapshot-bound SQLite scan implemented under #133.
- Replication entries are strictly 1-based. Sequence zero is rejected with
  `StoreError::InvalidReplicationSequence` before state, cryptography,
  database, cache, or transport work; rebuild inputs must be a complete
  contiguous prefix. SQLite also checks its signed integer boundary and the
  agreement between each row position and serialized entry. These checks
  prevent malformed-input panics and partial replacement caused by malformed
  sequence metadata. Openraft, rather than this application sequence, assigns
  and proves distributed commit authority.
- Fake and SQLite apply each complete replication operation tree atomically:
  a late nested failure preserves records, leases, fence/credential counters,
  the replication log and its compaction cursor, and watch-visible state.
  Whole-state rebuild is staged and swapped only after every entry replays;
  existing watch subscriptions survive the swap, rebuild does not synthesize
  append events, and the next locally successful append is emitted exactly
  once. The Fake obtains this test-double behavior by cloning its bounded
  in-memory data into a watcher-free stage; SQLite uses a database transaction.
  This is backend-local atomicity only. The Openraft-backed production adapter
  publishes journal/watch entries only after committed state-machine apply.
- Session and lease TTLs use the checked 365-day contract above. This closes
  the oversized-duration panic and input-safety boundary only; it does not
  establish consensus, durable commit authority, fork recovery, or production
  networked HA.
- Nested replicated CAS payloads are protected under the bounded iterative
  contract above. This is confidentiality and input-boundary hardening, not
  consensus, durable authority, or production HA. Protocol v5 wire
  stabilization does not attest wrapper composition.
- The #135 identity/model boundary and offline SQLite audit are implemented,
  but do not establish durable sequencing, fork recovery, restore authority,
  fleet rotation qualification, or production HA. Fixed-width v5 wire admission is
  implemented under #134.
- #159 closes per-connection outbound frame allocation and slow-reader write
  bounds. Protocol-v4 wire-schema revision 3 carries #133's confidential
  authenticated restore cursor and explicit durable page profile. Error-set
  revision 2 carries typed stale-cursor and work-budget failures. Revision-3
  and revision-2 exact profiles require a
  coordinated stop/upgrade/start and fail closed when mixed. Existing SQLite
  stores receive only an O(1) `restore_scan_state.cursor_key` metadata
  migration; no session-record backfill or second authority is created. A
  pre-revision-3 consensus snapshot lacks that key and must not be installed
  into a revision-3 fleet; take a coherent post-upgrade snapshot before
  declaring rollback/repair coverage. This
  does not rewrite persisted store bytes, but the strict transport rejects
  empty/over-64-byte stable IDs and empty/over-128-byte UTF-8 transaction IDs in
  retained records/logs. Before startup, use a decoder-first, product-aware
  migration or coherent store replacement: quiesce writers, ensure the
  migration reader can decode the legacy representation, follow the #167
  stable-ID runbook and the
  [#168 transaction-ID runbook](../../docs/session-store-replication-tx-id-migration.md)
  without truncating or renaming durable identities, then verify with the
  strict decoder before enabling revision-3 writers. Rollback likewise installs
  a decoder for the retained target representation before old writers restart,
  or restores a coherent checkpoint/reverse migration. #167 now supplies the production
  stable-ID model/persistence/privacy/audit contract. #168 supplies the bounded
  durable transaction-ID type, canonical coordinator mint, exact legacy
  preservation, SQLite/recovery checks, and current version-4 audit coordinated with
  #127/#128/#143. This
  supplies no durable authority or distributed/payload-key qualification
  (#143). #163 shared real-mTLS tests now qualify bounded retained-connection
  retirement, complete reauthentication, and request/watch continuity. Broader
  multi-process rotation/soak and complete trust-bundle removal, revocation,
  reconnect-storm, and seamless continuity evidence remain #164/#143
  production gates. #177 removes
  `opc-persist`'s private config TCP path and reuses the shared consensus ports;
  #159 does not define a second config deadline or credential lifecycle.

## Roadmap

- Keep backend capabilities explicit so HA/profile suitability can fail closed.
- Continue hardening restore evidence and traffic-blocking gates.
- Retain #171's bounded log-range cursor contract and complete persisted peer
  logical-RPC deadlines (#169),
  then complete the production
  qualification profile. Finite connection retirement and reauthentication are
  implemented under #163; broader certificate/trust removal, revocation,
  reconnect-storm, multi-process, and soak evidence remains #164/#158;
  distributed payload-protection evidence remains #143. Remote-seal historical
  selection is implemented; old-key retirement remains KMS/operator-owned and
  requires external proof across live state and every retained artifact. The
  SDK supplies exact key selection and bounded live-state scans, but no rewrap
  campaign or retirement gate.
- Keep encryption AAD bound to namespace, NF kind, state type, generation,
  fence, and session-key digest.

## Verification

- Source checked: `Cargo.toml`, `src/lib.rs`, backend, lease, TTL, model, record,
  SQLite, topology, quorum, restore, and tests.
- `tests/quorum_topology.rs` covers descriptor fingerprinting, descriptor-only
  and attested construction, exact binding/uniqueness/time/policy bounds,
  expiry-driven re-admission, non-serializable process-local token semantics,
  unexpired replacement-backing rejection, and full attestation Debug/summary
  redaction.
- `tests/consensus_openraft.rs` covers the production probe's monotonic expiry,
  nondecreasing time authority, rollback/retry and concurrent-evaluation races,
  refreshed evidence, and foreign/non-production token rejection.
- `tests/replication_sequence_bounds.rs` covers direct Fake/SQLite sequence and
  rebuild-prefix admission, signed persistence boundaries, and corrupt-row
  rejection; quorum, encryption, cache, and session-net suites cover their own
  boundaries.
- `tests/replication_atomicity.rs` runs the shared Fake/SQLite contract for late
  compound-append and rebuild rollback, ordered child application, duplicate
  idempotency, exactly-one watch publication, and watcher survival across a
  successful rebuild. Fake-private tests compare every internal state dimension
  and prove error paths do not prune expired data or retain an early child.
- `tests/replication_structure_bounds.rs` covers exact depth/count admission,
  fieldless error serialization/redaction, owned entry/prefix/page validation,
  small-stack rejection, and Fake/SQLite no-effect failures.
- TTL, lease, refresh, batch, replicated-operation, clock, cache, testkit, and
  real-mTLS suites cover zero, the exact maximum, over-limit inputs, deadline
  overflow, redacted typed errors, and no-partial-effect rejection.
- Encryption and remote-sealing suites cover deep nested-CAS replicate,
  rebuild, log, and watch round trips; depth/count boundaries; no plaintext or
  protected-byte exposure; and late-provider failure without backend
  delegation or partial entry/page exposure. They also cover one-provider
  old/new remote-key reads, in-flight active publication, cross-tenant/AAD
  rejection before provider I/O, redacted KMS failure, and a scoped three-node
  in-process Openraft snapshot-install/shutdown/restart restore with actual
  file-backed nodes, controllable RPC, and explicit provider-call counts. This
  is not multi-process or deployed-network qualification.
- `tests/persisted_identity_bounds.rs`, `tests/sqlite_identity_audit.rs`, and
  `tests/sqlite_identity_audit_cli.rs` cover valid legacy hydration, hostile
  owner/key identities across SQLite and nested logs, no-effect rejection,
  exact byte boundaries, bounded count-only auditing, redaction, and stable
  command status/exit behavior. `tests/handover.rs` covers versioned and
  bounded/current-valid original-format round trips, the exact non-`OPCH`
  classifier including ambiguous bare rejection, and malformed/truncated/
  oversized/typed-invalid rejection without mutation.
- Recovery unit tests use distinct file-backed databases for two- and
  three-branch legacy campaigns and current-format minority repair. They cover
  whole-fleet backup-before-mutation, immutable checkpoint installation,
  duplicate backing/path/hard-link rejection, source/target drift, exact fresh
  schema import, corrupt artifacts, pending-workflow rejection, per-file
  backup/stage/install and epoch/rejoin failpoint resume, fleet-wide maxima and
  SQLite successor exhaustion, inspection budgets, cursor invalidation,
  audit/readiness latching, terminal idempotency, and exact legacy
  confirmation.
- Run with: `cargo test -p opc-session-store`.

## License

Licensed under the [Apache License, Version 2.0](../../LICENSE).
