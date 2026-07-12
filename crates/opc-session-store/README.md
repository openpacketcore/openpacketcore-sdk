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
- `ReplicationEntry::into_validated`, `validate_replication_prefix_owned`, and
  `validate_replication_page_owned` consume caller-owned values and dismantle a
  rejected operation tree iteratively, avoiding recursive-drop exposure on the
  error path.
- `MAX_REPLICATION_OPERATION_DEPTH` (16) and
  `MAX_REPLICATION_OPERATIONS_PER_ENTRY` (256) bound every replication
  operation tree. The root is depth 1, and every operation node, including
  each `Batch`, counts toward the per-entry total.
- `MAX_SESSION_TTL` (365 days), `validate_session_ttl`, and
  `checked_session_deadline` define the common checked TTL/deadline contract.
- `SessionKey`, `SessionKeyType`, `StateClass`, `StateType`, `Generation`,
  `OwnerId`, and `FenceToken` describe session identity and ownership.
- `CustomSessionKeyType` makes deployment-specific key-type invariants
  structural, and `sqlite::audit::audit_sqlite_identity_invariants` plus the
  `opc-session-store-audit` binary provide a bounded, read-only legacy-store
  admission check.
- `StoredSessionRecord` carries key, generation, owner, fence, state class/type,
  expiry, and encrypted payload bytes.
- `SqliteSessionBackend::open(path)` and `in_memory()` provide the reference
  backend.
- `EncryptingSessionBackend::new(inner, provider, backend_namespace)` wraps a
  backend with `opc-crypto`/`opc-key` envelope encryption.
- `ReplicaId`, `ReplicaEndpoint`, `ReplicaTlsIdentity`,
  `ReplicaFailureDomain`, and `ReplicaBackingIdentity` keep logical, network,
  authentication, placement, and physical-store identities distinct.
- `BackendPeerBinding` is redaction-safe composition evidence from an
  authenticated network adapter. It binds local/remote logical IDs, the exact
  expected remote TLS identity, both descriptor fingerprints, member count,
  and one opaque cluster/configuration scope.
- `QuorumTopologyConfig::new` records an unvalidated request.
  `ValidatedQuorumTopology::try_from` performs admission: an odd HA membership
  from 3 through `QUORUM_TOPOLOGY_MAX_MEMBERS` (31), exactly one exact local
  logical ID, and unique declared vote identities before any backend I/O.
- `QuorumSessionStore::from_validated_topology` is the operational construction
  path.
- `QuorumSessionStore::probe_durable_readiness` performs a fresh, bounded
  point-in-time assessment of distinct voter reachability, majority-prefix
  agreement, and safe strict-prefix catch-up. It does not consult cached
  capabilities.
- `DurableReadinessReport` returns `Ready`, `NoQuorum`, `TopologyInvalid`, or
  `RecoveryRequired`, together with `configured_voters`,
  `fresh_reachable_voters`, `agreeing_voters`, `required_quorum`, the optional
  `majority_visible_prefix_index`, and typed per-replica observations.
- `ValidatedQuorumTopology::try_new_lab_singleton` is the explicit one-replica
  lab path. Its topology mode is `lab-singleton`; its platform profile is
  `single-replica`, never quorum HA.
- The deprecated raw-vector `QuorumSessionStore::new` is intentionally
  non-operational: it reports `unknown`, masks capabilities, and fails store
  operations until the caller migrates to validated topology.
- Restore APIs include `RestoreScanRequest`, `RestoreScanPage`,
  `RestoreBlockReason`, summaries, page-size constants, and
  `summarize_restore_records`.
- `opc-session-net` protocol v3 lets an individual authenticated remote backend
  execute the same validated cursor-paged restore scan as a local backend.
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

Custom deserializers enforce the same bounds for Serde values. SQLite point
reads validate persisted record owners; restore scans validate persisted key
types and owners; lease acquire, renew, release, and fenced mutations validate
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
  --max-total-json-bytes N
```

All three budgets are required and non-zero;
`--max-entry-json-bytes` must not exceed `--max-total-json-bytes` or SQLite's
signed `i64` length range. The audit
opens an existing database read-only, enables SQLite `query_only`, scans one
consistent snapshot in fixed 256-row pages, and applies `--max-rows` across
`session_records`, `leases`, `key_fences`, and `session_replication_log` in
that order. The two JSON budgets bound individual and cumulative replication
entries before strict `ReplicationEntry` decoding and domain validation.

Report schema version 1 contains only the requested limits, per-table scanned
counts, violation counts (`invalid_owner_fields`,
`invalid_session_key_type_fields`, and `invalid_replication_entries`), and an
optional bounded `incomplete_reason`. It never emits the database path, row
identity, tenant, owner, key type, stable ID, payload, transaction, or raw JSON.
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

Accepted protocol-v3 identities keep the same JSON string shape, but the Rust
API is source-breaking (`Other(String)` becomes
`Other(CustomSessionKeyType)`, and `other` is fallible) and wire admission is
semantically stricter. Handover decoding is also source-breaking:
`unpack_raw` now returns `Result`, `unpack_json` returns
`HandoverEnvelopeDecodeError`, and `HandoverError` gains `InvalidEnvelope`.
`pack_raw`/`pack_json` now write the versioned `OPCH` envelope; a compatible
original or bare record rewrites to the versioned form on its next transition.
An older v3 participant can emit an empty or oversized value that a new
participant rejects. Do not use a mixed rolling deployment:
stop writers and traffic, run both preflights, upgrade every session-net
client/server/protection wrapper and every NF or product handover reader/writer,
then restart and restore traffic. Prefer one coordinated rollout with #134 so
the fixed-width DTO and handshake explicitly negotiate the identity contract.

The persisted handover migration is one-way once any `OPCH` record or replayable
copy is written: an older SDK reader treats the new envelope as opaque bare
`Stable` payload. Do not roll back binaries after that point. Rollback requires
keeping the fleet drained and either restoring one coherent fleet-wide
pre-upgrade checkpoint (explicitly accepting or reconciling all post-checkpoint
mutations) or running a reviewed reverse migration over every live and
replayable copy, including nested logs, snapshots, and restore sources. #134
negotiation does not make an opaque `OPCH` payload readable by an older binary.

### Validated HA construction

```rust
use std::sync::Arc;
use opc_session_store::{
    FencedSessionReplica, QuorumReplicaDescriptor, QuorumReplicaMember,
    QuorumSessionStore, QuorumTopologyConfig, QuorumTopologyError,
    ReplicaBackingIdentity, ReplicaEndpoint, ReplicaFailureDomain, ReplicaId,
    ReplicaTlsIdentity, SessionStoreBackend, ValidatedQuorumTopology,
};

fn member(
    slot: usize,
    logical_id: &str,
    host: &str,
    tls_identity: &str,
    failure_domain: &str,
    backing_identity: &str,
    backend: Arc<dyn SessionStoreBackend>,
) -> Result<QuorumReplicaMember, QuorumTopologyError> {
    Ok(QuorumReplicaMember::new(
        QuorumReplicaDescriptor::new(
            ReplicaId::new(logical_id)?,
            ReplicaEndpoint::new(host, 7443)?,
            ReplicaTlsIdentity::new(tls_identity)?,
            ReplicaFailureDomain::new(failure_domain)?,
            ReplicaBackingIdentity::new(backing_identity)?,
        ),
        FencedSessionReplica::new(slot, backend),
    ))
}

fn build_store(
    local_backend: Arc<dyn SessionStoreBackend>,
    peer_1_backend: Arc<dyn SessionStoreBackend>,
    peer_2_backend: Arc<dyn SessionStoreBackend>,
) -> Result<QuorumSessionStore, QuorumTopologyError> {
    let local_id = ReplicaId::new("epdg-app-0")?;
    let members = vec![
        member(0, "epdg-app-0", "epdg-app-0.quorum.ns.svc.cluster.local",
            "spiffe://cluster/tenant/epdg/ns/gateway/sa/epdg-app/nf/epdg/instance/0", "node/worker-a", "pvc-uid/1111",
            local_backend)?,
        member(1, "epdg-app-1", "epdg-app-1.quorum.ns.svc.cluster.local",
            "spiffe://cluster/tenant/epdg/ns/gateway/sa/epdg-app/nf/epdg/instance/1", "node/worker-b", "pvc-uid/2222",
            peer_1_backend)?,
        member(2, "epdg-app-2", "epdg-app-2.quorum.ns.svc.cluster.local",
            "spiffe://cluster/tenant/epdg/ns/gateway/sa/epdg-app/nf/epdg/instance/2", "node/worker-c", "pvc-uid/3333",
            peer_2_backend)?,
    ];
    let topology = ValidatedQuorumTopology::try_from(
        QuorumTopologyConfig::new(local_id, members),
    )?;
    Ok(QuorumSessionStore::from_validated_topology(topology))
}
```

Build one immutable `SessionReplicationManifest` from the cluster ID, an
operator-controlled configuration generation, and the complete descriptor
set. Bind its exact local `ReplicaId`, then derive each
`RemoteSessionBackend` from that local binding. Protocol v3 requires the live
certificate's canonical SPIFFE URI, claimed `ReplicaId`, opposite replica ID,
cluster, and configuration digest to agree before backend dispatch. Resolver
or DNS aliases change only the dial address; they do not change voting
identity.

The numeric `FencedSessionReplica::id` is a fault-injection/test-control slot
and is never the logical `ReplicaId` or a vote identity. A backend adapter used
as a vote must return
`Some(BackendInstanceIdentity)` from `SessionBackend::backend_instance_identity`;
forwarding wrappers must delegate that identity. The default `None` fails
admission with `MissingBackendInstanceIdentity`. The token describes a local
adapter instance only; it does not authenticate a remote physical store.
Remote network adapters additionally return `BackendPeerBinding`. Once any
member supplies peer-binding evidence, every remote member must supply a
binding whose IDs, TLS identity, descriptor fingerprints, member count, and
scope match the admitted topology; an in-process local member may remain
unbound.

### Fresh durable readiness

`BackendCapabilities` and `SessionStorePlatformProfile::Quorum` are admission
evidence. They describe implemented methods and configured shape, but do not
prove that peers are reachable now. Before opening traffic, call
`probe_durable_readiness()` and require `DurableReadinessState::Ready`. Set
custom limits once with `with_durable_readiness_options`; explicit probes and
authoritative operations always use that same store-level policy.

The report is bounded by an end-to-end timeout and a per-replica log-entry
budget. Log evidence is loaded in bounded adaptive pages rather than one
whole-log wire frame. Its stable replica failure classes are `Transport`, `Authentication`,
`Timeout`, `Protocol`, `Backend`, `LogUnavailable`, `Divergent`,
`RepairFailed`, and `ProbeBudgetExceeded`. The report's `Debug` output redacts
replica identities, and the report contains no raw transport or backend error.

`Ready` means a distinct configured majority freshly supplied usable evidence
and agrees on one majority-visible prefix. It is point-in-time evidence, not a
lease or durable commit proof. Every authoritative quorum operation repeats the
same fail-closed assessment rather than relying on an earlier probe result.
Consumers must keep ownership publication and traffic advertisement behind the
same continuously refreshed gate; a readiness report is not an ownership
lease.
Safe automatic repair only appends the missing suffix to a replica whose log is
a strict prefix of the majority-visible log. A conflicting entry or longer
minority tail yields `RecoveryRequired`; the readiness path does not truncate or
destructively rebuild the fork.

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

This is a compatibility boundary. The two public error enums gain new variants,
and those variants can appear in protocol-v3 error responses. External
exhaustive matches must add arms, and a session-net fleet must be upgraded as
one coordinated same-v3 compatibility unit before relying on the typed wire
error. For the TTL change alone, requests within the operation-tree contract
retain their v3 shape. Before upgrading a store created by an older SDK, audit
its persisted replication log for TTL-bearing
operations above 365 days. Such legacy entries now fail closed during replay or
rebuild; the SDK does not silently clamp or rewrite them. Replicated
absolute-deadline validation permits at most one microsecond above the exact
`entry.timestamp + ttl` solely for compatibility with legacy `seconds_f64`
rounding. New deadlines remain exact, the tolerance does not enlarge
`MAX_SESSION_TTL`, and larger deadline mismatches still fail closed.

This TTL is application-state lifetime, not certificate expiry, trust-bundle
validity, or maximum authentication age. Seamless certificate/trust rotation
for the networked production profile remains a qualification requirement in
#143.

The duration contract does not yet bound a caller-authored absolute
`StoredSessionRecord::expires_at`; that separate admission/migration invariant
is tracked by #148.

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
rejection do not recurse through the operation tree. Pre-allocation wire
decoding still depends on the current frame/serde recursion guards; #134 must
move the same limits into versioned DTO decoding before this becomes a complete
wire-decoder work bound.
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

This changes the confidentiality contract without changing the protocol-v3
number. `StoreError` gains a serialized public variant, so exhaustive matches
must add an arm and an older v3 peer cannot decode the new error. More
importantly, an older wrapper does not protect deeply nested CAS records; a
mixed old/new v3 fleet is therefore not confidentiality-safe. Upgrade every
session-net client, server, and protection-wrapper participant as one
coordinated fleet. Do not claim rolling compatibility. #134 must carry these
limits and the error encoding into the versioned fixed-width DTO and handshake
contract.

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

This closes #147's nested-wrapper traversal gap only. The networked profile
remains experimental and blocked on #143 and its other dependencies. Seamless
SVID rotation, payload-protection key rotation, and trust-bundle rotation
remain separate mandatory production qualifications; the operation-tree limits
do not provide rotation evidence.

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
- Configured topology validation proves only an odd, distinct voting set and
  one exact local member. Authenticated network adapters add manifest-derived
  peer-binding evidence at admission. Fresh readiness separately proves a
  point-in-time reachable and agreeing majority. None of these results proves
  durable commit authority, operator-safe fork recovery, restore authority, or
  production HA qualification.
- A bare logical self ID such as `epdg-app-0` may select a member whose endpoint
  is the full `epdg-app-0.<headless-service>.<namespace>.svc.cluster.local`
  FQDN. The SDK never shortens endpoints or treats endpoint text as identity.
- The local ID declares the coordinator's own configured replica. Admission
  proves an exact descriptor match. The local in-process adapter remains a
  product composition boundary; a peer manifest does not prove physical-store
  provenance.
- Endpoint DNS names are canonicalized for case and one trailing dot.
  Endpoint text is routing, never replica identity. TLS/failure-domain values
  are exact caller-provided identities; callers must use canonical deployment
  values. Backing identities are caller-provided stable physical IDs retained
  only as SHA-256 digests, not verified storage provenance.
- Remote transport parity does not make `QuorumSessionStore` restore a
  production authority: its current aggregation still materializes replica
  scans and resolves records without durable majority/commit proof (#127,
  #133).
- Replication entries are strictly 1-based. Sequence zero is rejected with
  `StoreError::InvalidReplicationSequence` before state, cryptography,
  database, cache, or transport work; rebuild inputs must be a complete
  contiguous prefix. SQLite also checks its signed integer boundary and the
  agreement between each row position and serialized entry. These checks
  prevent malformed-input panics and partial replacement caused by malformed
  sequence metadata, but do not assign or prove distributed commit authority.
- Fake and SQLite apply each complete replication operation tree atomically:
  a late nested failure preserves records, leases, fence/credential counters,
  the replication log and its compaction cursor, and watch-visible state.
  Whole-state rebuild is staged and swapped only after every entry replays;
  existing watch subscriptions survive the swap, rebuild does not synthesize
  append events, and the next locally successful append is emitted exactly
  once. The Fake obtains this test-double behavior by cloning its bounded
  in-memory data into a watcher-free stage; SQLite uses a database transaction.
  This is backend-local atomicity only; distributed commit-gated observation
  remains part of #127.
- Session and lease TTLs use the checked 365-day contract above. This closes
  the oversized-duration panic and input-safety boundary only; it does not
  establish consensus, durable commit authority, fork recovery, or production
  networked HA.
- Nested replicated CAS payloads are protected under the bounded iterative
  contract above. This is confidentiality and input-boundary hardening, not
  consensus, durable authority, wire stabilization, or production HA.
- The #135 identity/model boundary and offline SQLite audit are implemented,
  but do not establish durable sequencing, fork recovery, restore authority,
  wire stabilization, seamless rotation, or production HA.

## Roadmap

- Keep backend capabilities explicit so HA/profile suitability can fail closed.
- Continue hardening restore evidence and traffic-blocking gates.
- Complete durable sequencing and safe fork repair/recovery (#127–#129),
  bounded majority-authoritative restore (#133), fixed-width wire stabilization
  (#134), watch handoff correctness (#145), and absolute-expiry admission
  (#148), then complete the production qualification profile and distributed
  evidence—including seamless certificate, payload-protection-key, and
  trust-bundle rotation—in #143.
- Keep encryption AAD bound to namespace, NF kind, state type, generation,
  fence, and session-key digest.

## Verification

- Source checked: `Cargo.toml`, `src/lib.rs`, backend, lease, TTL, model, record,
  SQLite, topology, quorum, restore, and tests.
- `tests/quorum_topology.rs` covers descriptor fingerprinting, complete
  remote-binding admission, typed mismatch classes, and redacted diagnostics.
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
  delegation or partial entry/page exposure.
- `tests/persisted_identity_bounds.rs`, `tests/sqlite_identity_audit.rs`, and
  `tests/sqlite_identity_audit_cli.rs` cover valid legacy hydration, hostile
  owner/key identities across SQLite and nested logs, no-effect rejection,
  exact byte boundaries, bounded count-only auditing, redaction, and stable
  command status/exit behavior. `tests/handover.rs` covers versioned and
  bounded/current-valid original-format round trips, the exact non-`OPCH`
  classifier including ambiguous bare rejection, and malformed/truncated/
  oversized/typed-invalid rejection without mutation.
- Run with: `cargo test -p opc-session-store`.

## License

Licensed under the [Apache License, Version 2.0](../../LICENSE).
