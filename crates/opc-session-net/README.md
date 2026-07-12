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
- Replication entries, rebuild prefixes, returned log pages, and watch items
  enforce `MAX_REPLICATION_OPERATION_DEPTH` (16) and
  `MAX_REPLICATION_OPERATIONS_PER_ENTRY` (256). The root is depth 1 and every
  operation node, including `Batch`, counts toward the per-entry total.
- Acquire, renew, TTL refresh, batch, and nested replication requests enforce
  `opc_session_store::MAX_SESSION_TTL` (365 days) before resolution or backend
  dispatch. Zero remains valid and means immediate expiry.
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
- That reconnect behavior is a safety primitive, not seamless-rotation
  qualification. A production CNF must support certificate and trust-bundle
  rotation without a service interruption, including trust overlap,
  long-lived-connection retirement, revocation, reconnect storms, and a
  documented maximum authentication age. Distributed evidence for that
  profile remains open in #143. The 365-day session TTL bound is unrelated to
  certificate lifetime, trust-bundle lifetime, or authentication age.
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
- TTL-bearing requests above 365 days are rejected with
  `StoreError::InvalidSessionTtl` or `LeaseError::InvalidSessionTtl` before
  dialing on the client and before backend dispatch on the server. The exact
  maximum is accepted and zero means immediate expiry. The TTL request shape is
  unchanged for entries within the operation-tree contract. The new serialized
  error variants require external exhaustive matches and a coordinated same-v3
  fleet upgrade; an older v3 peer cannot decode a newly returned variant.
  Legacy persisted replication logs must be
  audited before upgrade because an entry carrying a larger TTL now fails
  closed during replay or rebuild rather than being clamped. Cross-field
  validation permits at most one microsecond of positive absolute-deadline
  drift solely for legacy `seconds_f64` rounding; new deadlines remain exact,
  the TTL maximum is unchanged, and larger mismatches fail closed.
- Replication operation trees are validated iteratively and fail with the
  fieldless `StoreError::ReplicationOperationLimitExceeded` when any entry
  exceeds depth 16 or 256 total nodes. Outbound clients reject before
  resolution/dialing; authenticated servers reject decoded requests before
  backend dispatch; clients validate complete returned pages/items before
  caller exposure. A typed rejection does not consume the connection.
- Protection wrappers above the transport encrypt or remotely seal every
  nested replicated CAS before replicate/rebuild delegation and decrypt or
  unseal every nested CAS from log/watch reads. Provider calls are sequential,
  and transformation is staged: a late provider failure may follow earlier
  provider calls, but causes no backend delegation on writes and exposes no
  partially transformed entry/page on reads.
- This is a breaking same-v3 confidentiality boundary, not rolling-compatible
  hardening. An older v3 peer cannot decode the new error, and an older wrapper
  can still forward a deeply nested CAS without protection. Mixed SDK versions
  are therefore not confidentiality-safe even though the protocol number is
  still 3. Drain and upgrade every client, server, and wrapper participant as
  one coordinated fleet before restoring traffic. #134 must pin the two limits
  and error representation in the versioned fixed-width DTO and handshake
  contract; this change does not claim wire stabilization.
- Existing logs are not scrubbed automatically. Audit tree shape and payload
  encoding offline before upgrade. A plaintext/unsealed nested CAS within the
  new limits may use an explicit wrapper-mediated rewrite/rebuild. A historical
  over-limit entry is rejected before transformation and cannot be ingested
  unchanged; use a separately audited semantic-preserving offline migration or
  replace the store before starting the new SDK. Never clamp or split the entry
  ad hoc; a raw inner-backend rebuild preserves the protection gap.
- Remote scan and fresh-probe transport parity do not by themselves qualify
  networked session HA for production. Protocol v3 authenticates membership;
  it does not establish consensus, durable sequence/commit authority,
  fork reconciliation, or majority-authoritative restore. Those properties,
  fixed-width wire DTOs, and model-level decode invariants remain open in
  #127–#129 and #133–#135.

## Roadmap

- Close #127–#129, #133–#135, #145, and #148; add distributed failure and soak
  evidence, including seamless SVID rotation, payload-protection key rotation,
  and trust-bundle rotation qualification in #143, before treating this as
  production transport.
- Keep plaintext transport limited to tests.
- Keep the server wrapping `SessionStoreBackend` rather than owning storage.

## Verification

- Source checked: `Cargo.toml`, `src/lib.rs`, client, server, protocol, and
  tests.
- `tests/authenticated_replica_identity.rs` covers exact identity, routing
  aliases, certificate/claim/scope mismatches, downgrade and malformed Hello,
  reconnect/rotation, relabeling, and replayed challenge responses over mTLS.
- `tests/three_node_quorum.rs` covers typed TTL and replication-tree-limit
  rejection before resolution and authenticated server dispatch, plus
  connection reuse after rejection. Client/server suites also cover malformed
  log/watch output rejection before caller exposure.
- Run with: `cargo test -p opc-session-net --all-features`.

## License

Licensed under the [Apache License, Version 2.0](../../LICENSE).
