# opc-session-net

Experimental network transport for remote session-store replicas.

## Purpose

`opc-session-net` exposes a length-prefixed JSON protocol between
`RemoteSessionBackend` clients and `SessionReplicationServer` instances. It
lets a `SessionBackend` or quorum coordinator call a remote replica using the
same session-store traits.

## API Shape

- `RemoteSessionBackend::new(addr, tls_config, deadline)` creates a client that
  implements `SessionBackend` and `SessionLeaseManager`.
- `with_max_frame_size` overrides the default 1 MiB frame limit.
- `SessionReplicationServer::new(backend, tls_config)` creates an mTLS server
  over an `Arc<dyn SessionStoreBackend>`.
- `SessionReplicationServer::new_insecure` exists only behind the
  `insecure-test` feature.
- `with_idle_timeout`, `with_max_connections`, and `with_max_frame_size`
  configure the server.
- `listen(bind_addr).await` starts the listener and returns a server handle and
  bound address.
- `Request`, `Response`, `ProtocolError`, and protocol constants live in the
  public protocol layer.

```rust,no_run
use opc_session_net::RemoteSessionBackend;
use std::net::SocketAddr;
use std::time::Duration;

let addr: SocketAddr = "127.0.0.1:9443".parse().unwrap();
let remote = RemoteSessionBackend::new(addr, None, Some(Duration::from_secs(2)));
let _remote = remote.with_max_frame_size(1024 * 1024);
```

## Relationships

- Implements `opc-session-store` backend and lease traits over the wire.
- Uses `opc-tls` Rustls configs for production mTLS transport.
- Intended to be composed under `QuorumSessionStore` or other store callers.

## Status Notes

- `publish = false`.
- The transport is experimental.
- Production server construction requires authenticated TLS.
- Plaintext server support is test-only and gated behind `insecure-test`.
- The wire contract version is `1`; the default max frame size is 1 MiB.

## Roadmap

- Harden protocol compatibility, cancellation behavior, watch streaming, and
  operational metrics before treating this as production transport.
- Keep plaintext transport limited to tests.
- Keep the server wrapping `SessionStoreBackend` rather than owning storage.

## Verification

- Source checked: `Cargo.toml`, `src/lib.rs`, client, server, protocol, and
  tests.
- Run with: `cargo test -p opc-session-net --all-features`.

## License

Licensed under the [Apache License, Version 2.0](../../LICENSE).
