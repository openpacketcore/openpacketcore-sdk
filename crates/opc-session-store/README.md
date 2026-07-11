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
- `QuorumTopologyConfig::new` records an unvalidated request.
  `ValidatedQuorumTopology::try_from` performs admission: an odd HA membership
  from 3 through `QUORUM_TOPOLOGY_MAX_MEMBERS` (31), exactly one exact local
  logical ID, and unique declared vote identities before any backend I/O.
- `QuorumSessionStore::from_validated_topology` is the operational construction
  path.
- `ValidatedQuorumTopology::try_new_lab_singleton` is the explicit one-replica
  lab path. Its topology mode is `lab-singleton`; its platform profile is
  `single-replica`, never quorum HA.
- The deprecated raw-vector `QuorumSessionStore::new` is intentionally
  non-operational: it reports `unknown`, masks capabilities, and fails store
  operations until the caller migrates to validated topology.
- Restore APIs include `RestoreScanRequest`, `RestoreScanPage`,
  `RestoreBlockReason`, summaries, page-size constants, and
  `summarize_restore_records`.
- `opc-session-net` protocol v2 lets an individual remote backend execute the
  same validated cursor-paged restore scan as a local backend.
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
            "spiffe://cluster/ns/epdg-app-0", "node/worker-a", "pvc-uid/1111",
            local_backend)?,
        member(1, "epdg-app-1", "epdg-app-1.quorum.ns.svc.cluster.local",
            "spiffe://cluster/ns/epdg-app-1", "node/worker-b", "pvc-uid/2222",
            peer_1_backend)?,
        member(2, "epdg-app-2", "epdg-app-2.quorum.ns.svc.cluster.local",
            "spiffe://cluster/ns/epdg-app-2", "node/worker-c", "pvc-uid/3333",
            peer_2_backend)?,
    ];
    let topology = ValidatedQuorumTopology::try_from(
        QuorumTopologyConfig::new(local_id, members),
    )?;
    Ok(QuorumSessionStore::from_validated_topology(topology))
}
```

Use the same source configuration to build each remote backend and its
descriptor; the current SDK cannot prove that independently declared metadata
matches the live peer until #125. The numeric `FencedSessionReplica::id` is a
fault-injection/test-control slot and is never the logical `ReplicaId` or a
vote identity. A backend adapter used as a vote must return
`Some(BackendInstanceIdentity)` from `SessionBackend::backend_instance_identity`;
forwarding wrappers must delegate that identity. The default `None` fails
admission with `MissingBackendInstanceIdentity`. The token describes a local
adapter instance only; it does not authenticate a remote physical store.

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
  one exact local member. It does not prove peer reachability, authenticated
  membership, durable commit authority, safe repair, restore authority, or
  production HA qualification.
- A bare logical self ID such as `epdg-app-0` may select a member whose endpoint
  is the full `epdg-app-0.<headless-service>.<namespace>.svc.cluster.local`
  FQDN. The SDK never shortens endpoints or treats endpoint text as identity.
- The local ID declares the coordinator's own configured replica. Admission
  proves an exact descriptor match, but cannot yet prove that the paired
  adapter reaches the local physical store. Products must bind composition to
  their own member configuration, and #125 must bind remote declarations to
  authenticated peers.
- Endpoint DNS names are canonicalized for case and one trailing dot.
  TLS/failure-domain values are exact caller-provided identities; callers must
  use canonical deployment values. Backing identities are caller-provided
  stable physical IDs retained only as SHA-256 digests, not verified storage
  provenance.
- Remote transport parity does not make `QuorumSessionStore` restore a
  production authority: its current aggregation still materializes replica
  scans and resolves records without durable majority/commit proof (#127,
  #133).

## Roadmap

- Keep backend capabilities explicit so HA/profile suitability can fail closed.
- Continue hardening restore evidence and traffic-blocking gates.
- Complete fresh-quorum readiness and authenticated peer identity (#124/#125),
  durable sequencing and safe fork repair/recovery (#127–#129), and bounded
  majority-authoritative restore (#133), fixed-width wire stabilization (#134),
  plus invariant-safe model decoding (#135).
- Keep encryption AAD bound to namespace, NF kind, state type, generation,
  fence, and session-key digest.

## Verification

- Source checked: `Cargo.toml`, `src/lib.rs`, backend, lease, model, record,
  sqlite, topology, quorum, restore, and tests.
- Run with: `cargo test -p opc-session-store`.

## License

Licensed under the [Apache License, Version 2.0](../../LICENSE).
