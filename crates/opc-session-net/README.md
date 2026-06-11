# opc-session-net

Networked session replication transport for OpenPacketCore.

**Status: experimental.** The wire format is version-gated (see below) and may
change in breaking ways before 1.0.

## Purpose

`opc-session-store` provides production-grade quorum semantics (fencing,
leases, compare-and-set, read-repair) over in-process replica handles. This
crate supplies the missing network leg so those replicas can live in separate
processes or pods:

- **`SessionReplicationServer`** — a tokio TCP listener that exposes any
  `SessionStoreBackend` (e.g. the SQLite backend) over a length-prefixed JSON
  wire protocol, with optional mTLS via [`opc-tls`](../opc-tls/), bounded
  concurrent connections, and a maximum frame size (default 1 MiB).
- **`RemoteSessionBackend`** — a client implementing `SessionBackend` and
  `SessionLeaseManager` against a remote server, so it composes directly into
  `QuorumSessionStore`. Every method is bounded by a configurable end-to-end
  deadline (default 2 s) covering connection retries with backoff; on expiry
  the method reports the backend as unavailable so the quorum layer treats the
  replica as offline instead of stalling.

Connections begin with a `Hello { contract_version, node_id }` handshake; a
major-version mismatch closes the connection with a typed error.

## Example

```rust,no_run
use std::sync::Arc;
use opc_session_net::{RemoteSessionBackend, SessionReplicationServer};
use opc_session_store::fake::FakeSessionBackend;
use opc_session_store::quorum::{FencedSessionReplica, QuorumSessionStore};

# async fn demo() -> Result<(), Box<dyn std::error::Error>> {
// Serve a backend (one per replica process). `None` = plaintext, test only;
// pass an `opc_tls::ServerConfig` in real deployments.
let backend = Arc::new(FakeSessionBackend::new());
let server = SessionReplicationServer::new(backend, None);
let (_handle, addr) = server.listen("127.0.0.1:0".parse()?).await?;

// Compose remote replicas into a quorum store.
let remote = Arc::new(RemoteSessionBackend::new(addr, None, None));
let quorum = QuorumSessionStore::new(vec![FencedSessionReplica::new(1, remote)]);
# Ok(()) }
```

See `tests/three_node_quorum.rs` for a full three-node kill/restart and
read-repair scenario.

## Non-goals

- **No consensus or leader election.** Quorum decisions, fencing, and
  read-repair stay in `opc-session-store`'s `QuorumSessionStore`; this crate
  is transport only.
- **No persistence of its own.** Durability belongs to the backend each
  server wraps (e.g. `SqliteSessionBackend`).
- **No stable wire format yet.** Frames are versioned via the `Hello`
  handshake (`CONTRACT_VERSION`); cross-version compatibility is not
  guaranteed while experimental.
- **No connection pooling or multiplexing.** Each request opens a fresh
  connection; the watch stream holds a dedicated long-lived connection.

## Roadmap to non-experimental

The crate keeps its experimental label until:

1. **Connection pooling / multiplexing** — today every request opens a
   fresh connection and the watch stream holds its own; a pooled transport
   with in-flight pipelining is required before production traffic levels.
2. **Wire-format freeze** — the length-prefixed JSON framing is
   version-gated via the `Hello` handshake but not yet stable; a freeze
   requires a documented compatibility policy (and likely a binary
   encoding) before `CONTRACT_VERSION` is declared 1.0-stable.
3. **Soak evidence** — multi-hour three-node soak under fault injection
   (partition, slow-link, restart loops) recorded through `opc-evidence`,
   plus latency/throughput baselines.

## License

Apache-2.0. See [LICENSE](../../LICENSE).
