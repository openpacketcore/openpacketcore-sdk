# opc-session-net

Experimental network transport for remote session-store replicas.

## Purpose

`opc-session-net` exposes a length-prefixed JSON protocol between
`RemoteSessionBackend` clients and `SessionReplicationServer` instances. It
lets a `SessionBackend` or quorum coordinator call a remote replica using the
same session-store traits. Protocol v2 carries cursor-paged
`SessionBackend::scan_restore_records` calls, so remote replicas no longer fall
through to the trait's unsupported-operation default.

## API Shape

- `RemoteSessionBackend::new(addr, tls_config, deadline)` creates an mTLS
  client that implements `SessionBackend` and `SessionLeaseManager`.
- `RemoteSessionBackend::new_insecure` exists only behind the `insecure-test`
  feature.
- `with_max_frame_size` overrides the default 1 MiB frame limit.
- `SessionReplicationServer::new(backend, tls_config)` creates an mTLS server
  over an `Arc<dyn SessionStoreBackend>`.
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
- If one record cannot fit, the call returns
  `StoreError::RestoreScanResponseTooLarge` instead of retrying indefinitely.
- `listen(bind_addr).await` starts the listener and returns a server handle and
  bound address.
- `Request`, `Response`, `ProtocolError`, and protocol constants live in the
  public protocol layer.

```rust,ignore
use opc_session_net::RemoteSessionBackend;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

let addr: SocketAddr = "127.0.0.1:9443".parse().unwrap();
let tls_config: Arc<opc_tls::ClientConfig> = product_tls_config;
let remote = RemoteSessionBackend::new(addr, tls_config, Some(Duration::from_secs(2)));
let _remote = remote.with_max_frame_size(1024 * 1024);
```

## Relationships

- Implements `opc-session-store` backend and lease traits over the wire.
- Uses `opc-tls` Rustls configs for production mTLS transport.
- Intended to be composed under `QuorumSessionStore` or other store callers.
- HA-shaped composition must use `ValidatedQuorumTopology`; logical replica
  ID, dial endpoint, expected TLS identity, failure domain, backing identity,
  and exact local self are independent inputs.

## Status Notes

- `publish = false`.
- The transport is experimental.
- Production client and server construction requires authenticated TLS.
- Plaintext client/server support is test-only and gated behind
  `insecure-test`.
- The wire contract version is `2`; the default max frame size is 1 MiB.
- The Hello handshake requires an exact version match. Protocol v1 and v2
  peers do not interoperate, so all session-net clients and servers require a
  coordinated upgrade; mixed-version rolling upgrades are unsupported.
- `capabilities()` is descriptive admission evidence and may fall back to a
  previously successful negotiation after a disconnect. It is not a liveness
  or durable-readiness signal; replicated callers must use the fresh
  replication-head probe and require a distinct agreeing majority.
- Restore scan is a bulk enumeration boundary. Production authorization still
  depends on binding authenticated peer identity to authorized replica
  membership (#125).
- Configured topology admission rejects duplicate declared vote identities,
  canonical endpoints, and duplicate process-local adapter instances, plus a
  missing or ambiguous local member. It cannot detect dishonest backing labels,
  independently constructed clients targeting one store through DNS aliases,
  or a mismatch between declarations and the live mTLS peer; that authenticated
  authorization remains #125.
- Remote scan and fresh-probe transport parity do not by themselves qualify
  networked session HA for production. Authenticated identity binding, durable
  authority, fork recovery, bounded majority-authoritative restore,
  fixed-width wire DTOs, and model-level decode invariants remain open in
  #125, #127–#129, and #133–#135.

## Roadmap

- Close #125, #127–#129, and #133–#135; add distributed failure and soak
  evidence before treating this as production transport.
- Keep plaintext transport limited to tests.
- Keep the server wrapping `SessionStoreBackend` rather than owning storage.

## Verification

- Source checked: `Cargo.toml`, `src/lib.rs`, client, server, protocol, and
  tests.
- Run with: `cargo test -p opc-session-net --all-features`.

## License

Licensed under the [Apache License, Version 2.0](../../LICENSE).
