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
- `MAX_SESSION_TTL` (365 days), `validate_session_ttl`, and
  `checked_session_deadline` define the common checked TTL/deadline contract.
- `SessionKey`, `SessionKeyType`, `StateClass`, `StateType`, `Generation`,
  `OwnerId`, and `FenceToken` describe session identity and ownership.
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
error; valid v3 requests and responses are unchanged. Before upgrading a store
created by an older SDK, audit its persisted replication log for TTL-bearing
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
is tracked by #148. Deeply nested replicated CAS payload transformation through
the encryption/sealing wrappers is tracked by #147.

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
- Session and lease TTLs use the checked 365-day contract above. This closes
  the oversized-duration panic and input-safety boundary only; it does not
  establish consensus, durable commit authority, fork recovery, or production
  networked HA.

## Roadmap

- Keep backend capabilities explicit so HA/profile suitability can fail closed.
- Continue hardening restore evidence and traffic-blocking gates.
- Complete durable sequencing and safe fork repair/recovery (#127–#129),
  bounded majority-authoritative restore (#133), fixed-width wire stabilization
  (#134), invariant-safe model decoding (#135), watch handoff correctness
  (#145), recursive protected-payload traversal (#147), and absolute-expiry
  admission (#148), then complete the production qualification profile and
  distributed evidence in #143.
- Keep encryption AAD bound to namespace, NF kind, state type, generation,
  fence, and session-key digest.

## Verification

- Source checked: `Cargo.toml`, `src/lib.rs`, backend, lease, TTL, model, record,
  SQLite, topology, quorum, restore, and tests.
- `tests/quorum_topology.rs` covers descriptor fingerprinting, complete
  remote-binding admission, typed mismatch classes, and redacted diagnostics.
- `tests/replication_sequence_bounds.rs` covers direct Fake/SQLite append,
  rebuild atomicity, signed persistence boundaries, and corrupt-row rejection;
  quorum, encryption, cache, and session-net suites cover their own boundaries.
- TTL, lease, refresh, batch, replicated-operation, clock, cache, testkit, and
  real-mTLS suites cover zero, the exact maximum, over-limit inputs, deadline
  overflow, redacted typed errors, and no-partial-effect rejection.
- Run with: `cargo test -p opc-session-store`.

## License

Licensed under the [Apache License, Version 2.0](../../LICENSE).
