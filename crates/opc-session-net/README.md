# opc-session-net

Experimental network transport for remote session-store replicas.

## Purpose

`opc-session-net` exposes a length-prefixed JSON protocol between
`RemoteSessionBackend` clients and `SessionReplicationServer` instances. It
lets a `SessionBackend` or quorum coordinator call a remote replica using the
same session-store traits. Protocol v3 carries cursor-paged
`SessionBackend::scan_restore_records` calls and binds every production
connection to one authenticated member of one immutable replication manifest.

## API Shape

- `SessionReplicationManifest::try_new` validates one cluster ID, one
  operator-controlled configuration generation, and the complete replica
  descriptor set. It derives an order-independent configuration ID from the
  cluster, generation, and every descriptor field.
- `SessionReplicationManifest::bind_local` selects the exact local
  `ReplicaId`; `LocalReplicaBinding::bind_remote` derives the only supported
  production client binding for an admitted peer.
- `RemoteSessionBackend::new(binding, tls_config, deadline)` creates an mTLS
  client that implements `SessionBackend` and `SessionLeaseManager`. The
  endpoint comes from the binding; `new_with_resolver` may override address
  resolution, but not identity.
- `RemoteSessionBackend::new_insecure` exists only behind the `insecure-test`
  feature.
- `with_max_frame_size` overrides the default 1 MiB frame limit.
- `SessionReplicationServer::new(backend, tls_config, binding)` creates an mTLS
  server over an `Arc<dyn SessionStoreBackend>` and the exact local manifest
  member.
- `SessionReplicationServer::new_insecure` exists only behind the
  `insecure-test` feature.
- `with_idle_timeout`, `with_max_connections`, and `with_max_frame_size`
  configure the server; `with_restore_scan_timeout` bounds cancellable backend
  scan work.
- `RemoteSessionBackend::scan_restore_records` validates requests and peer
  pages. The server may return fewer records than requested so the encoded
  response fits the smaller client/server frame limit; callers continue from
  `next_cursor` until `complete`.
- `SessionBackend::probe_replication_head` performs a fresh, deadline-bounded
  wire request. It does not consult the client's capability cache and reports
  transport, authentication, timeout, protocol, and backend failures through
  redaction-safe `ReplicaReadinessFailure` variants.
- Replication append and rebuild calls validate sequence metadata before
  resolution or dispatch; malformed authenticated wire requests receive the
  typed store error without consuming the connection.
- If one record cannot fit, the call returns
  `StoreError::RestoreScanResponseTooLarge` instead of retrying indefinitely.
- `listen(bind_addr).await` starts the listener and returns a server handle and
  bound address.
- `Request`, `Response`, `ProtocolError`, and protocol constants live in the
  public protocol layer.

```rust,ignore
use opc_session_net::{RemoteSessionBackend, SessionReplicationManifest};
use opc_session_store::ReplicaId;
use std::time::Duration;

let manifest: std::sync::Arc<SessionReplicationManifest> = validated_manifest;
let local = manifest.bind_local(ReplicaId::new("epdg-app-0")?)?;
let peer = local.bind_remote(ReplicaId::new("epdg-app-1")?)?;
let tls_config = opc_tls::TlsConfigBuilder::new(identity_state_rx)
    .with_policy(replication_peer_policy)
    .build_authenticated_client_config()?;
let remote = RemoteSessionBackend::new(
    peer,
    tls_config,
    Some(Duration::from_secs(2)),
);
let _remote = remote.with_max_frame_size(1024 * 1024);
```

## Relationships

- Implements `opc-session-store` backend and lease traits over the wire.
- Uses the opaque authenticated client/server configs from `opc-tls` for
  production mTLS transport. The session transport sets and requires its exact
  v3 ALPN value.
- Intended to be composed under `QuorumSessionStore` or other store callers.
- HA-shaped composition must use `ValidatedQuorumTopology`; logical replica
  ID, dial endpoint, expected TLS identity, failure domain, backing identity,
  and exact local self remain independent descriptor fields.

## Status Notes

- `publish = false`.
- The transport is experimental.
- Production client and server construction requires opaque
  `AuthenticatedClientConfig`/`AuthenticatedServerConfig` values built by
  `opc-tls`; raw Rustls configs cannot enter these constructors.
- Plaintext client/server support is test-only and gated behind
  `insecure-test`.
- The wire contract version is `3`; the default max frame size is 1 MiB.
- The v3 handshake extracts the canonical SPIFFE URI from the live peer
  certificate and requires it to match the claimed stable `ReplicaId` in the
  manifest. Client and server also verify the expected opposite replica,
  cluster ID, and configuration ID; the client verifies its fresh challenge is
  echoed by the server. Wrong, missing,
  ambiguous, malformed, cross-cluster, or stale configuration identities fail
  before backend dispatch.
- Session-net disables TLS session caches, tickets, resumption, early data, and
  0-RTT. Every reconnect pays for a full mutual-TLS handshake so SVID rotation
  cannot reuse a cached peer certificate or authority decision.
- The configuration ID is a SHA-256 digest of the cluster ID, explicit
  generation, and the full sorted descriptor set. Changing a member ID,
  endpoint, TLS identity, failure domain, backing identity, cluster, or
  generation changes the authenticated scope.
- Protocol v3 has no production fallback to v2. The exact-version handshake
  and v3-only ALPN require a coordinated stop/upgrade/start of every
  session-net participant; mixed v2/v3 fleets are unsupported.
- DNS names and resolver overrides select only where to dial. FQDN, short-name,
  IP, and alias changes do not alter the expected `ReplicaId`, certificate
  SPIFFE identity, or manifest scope.
- `capabilities()` is descriptive admission evidence and may fall back to a
  previously successful negotiation after a disconnect. It is not a liveness
  or durable-readiness signal; replicated callers must use the fresh
  replication-head probe and require a distinct agreeing majority.
- Remote adapters expose redaction-safe peer-binding evidence to
  `ValidatedQuorumTopology`. Admission verifies the local and remote IDs,
  expected TLS identity, local and remote descriptor fingerprints, configured
  member count, and one shared configuration scope before counting the adapter
  as a vote. A local in-process backend need not present network-peer evidence.
- Peer binding is static admission evidence, not current health. Capability
  declarations and a successful handshake do not replace
  `QuorumSessionStore::probe_durable_readiness` or continuous traffic gating.
- Replication entry sequence zero and malformed rebuild prefixes are rejected
  before dialing on the client and before backend dispatch on the server. The
  unit `InvalidReplicationSequence` error contains no peer-controlled data;
  an authenticated server returns it as a typed v3 response and keeps the
  connection usable. This is input-boundary safety, not sequence authority.
- Remote scan and fresh-probe transport parity do not by themselves qualify
  networked session HA for production. Protocol v3 authenticates membership;
  it does not establish consensus, durable sequence/commit authority,
  fork reconciliation, or majority-authoritative restore. Those properties,
  fixed-width wire DTOs, and model-level decode invariants remain open in
  #127–#129 and #133–#135.

## Roadmap

- Close #127–#129 and #133–#135; add distributed failure and soak
  evidence before treating this as production transport.
- Keep plaintext transport limited to tests.
- Keep the server wrapping `SessionStoreBackend` rather than owning storage.

## Verification

- Source checked: `Cargo.toml`, `src/lib.rs`, client, server, protocol, and
  tests.
- `tests/authenticated_replica_identity.rs` covers exact identity, routing
  aliases, certificate/claim/scope mismatches, downgrade and malformed Hello,
  reconnect/rotation, relabeling, and replayed challenge responses over mTLS.
- Run with: `cargo test -p opc-session-net --all-features`.

## License

Licensed under the [Apache License, Version 2.0](../../LICENSE).
