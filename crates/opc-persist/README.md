# opc-persist

Persistence primitives for config commits, audit chains, security policy, and
prototype consensus storage.

## Purpose

`opc-persist` provides the durable storage contracts used by configuration and
security-policy code. The SQLite backend is the reference single-replica
implementation; consensus and quorum types are hardening surfaces for HA tests
and SDK integration, not a declared carrier-production consensus backend.

## API Shape

- `ConfigStore` is the async commit-store trait:
  `load_latest`, `load_rollback`, `append_commit`, `mark_confirmed`,
  `create_rollback_point`, and `preflight`.
- `SqliteBackend::open(path, ephemeral, min_free_bytes)` opens ephemeral stores.
  Durable stores require `open_with_audit_key`.
- `AuditKey::new([u8; 32])` rejects all-zero keys. `verify_audit_chain`
  validates the tamper-evident audit chain.
- `PersistCapabilities` reports fsync, locking, filesystem, permission, and
  free-space checks. `is_safe_for_writes` is conservative.
- `FencedReplica` and `QuorumConfigStore` provide majority write/read behavior
  with leader-epoch fencing over `ConfigStore` replicas.
- `ConsensusConfigStore`, `ConsensusPeer`, `TcpPeer`, and `TcpRpcServer` expose
  the current durable consensus prototype.
- `SecurityPolicyService` and `SqliteSecurityPolicyService` stage, validate,
  apply, dry-run, roll back, inspect, and list security policies.
- Break-glass APIs model request, approval, activation, denial, revocation, and
  expiry flows with alarm/approval hooks.

```rust,no_run
use opc_persist::{AuditKey, ConfigStore, SqliteBackend};

async fn open_store() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let key = AuditKey::new([3u8; 32])?;
    let store = SqliteBackend::open_with_audit_key("config.db", false, 10 * 1024 * 1024, key).await?;
    store.preflight().await?;
    Ok(())
}
```

## Relationships

- Uses `opc-key` and `opc-crypto` for encrypted security-policy/config payloads.
- Consumed by `opc-config-bus`, AMF-lite integration, and security-policy
  services.
- Uses `opc-nacm` concepts at the caller/service boundary; this crate is not a
  northbound gNMI, NETCONF, or gNSI server.

## Consensus RPC deadlines and retries

`TcpPeer::new(..., timeout)` treats `timeout` as one end-to-end logical RPC
deadline. Authentication and TLS-connector lock acquisition, request framing,
TCP connect, the mTLS handshake, request writes, response length/body reads,
response decoding, all attempts, and the 50/100 ms retry delays consume the
same absolute deadline. A stage or retry is never started after expiry. Zero
expires before setup or network I/O; durations outside the monotonic clock's
representable range fail closed rather than panicking.

The transport can make at most three attempts when the deadline leaves enough
time. RequestVote, AppendEntries, and InstallSnapshot replay the same Raft
term/log coordinates and are safe to duplicate; LoadLatest and LoadRollback
are read-only. TimeoutNow is not retried after any request bytes may have been
delivered because a lost response does not prove that the server failed to
launch the campaign. Local identity/connector errors and certificate
verification failures are treated as permanent for that call instead of being
retried until they look like timeouts.

Election vote requests and replication peer fan-out run concurrently. Within
one peer, a synchronous or background catch-up trigger is capped at 64
sequential snapshot/append rounds. A rejected snapshot can fall through to one
append in the same round, so a pass issues at most 128 logical RPCs and its
transport wait is at most `128 * timeout`; a later trigger resumes from the
stored `next_index`. The cap prevents a single task from living forever while
retaining enough rounds to repair ordinary log divergence without scheduling
a new trigger for every entry. Large gaps should use snapshot installation;
repeated triggers continue safe incremental catch-up.

This changes the meaning of an existing public setting. Before upgrading,
retune `TcpPeer::timeout`/`--rpc-timeout` as an end-to-end value rather than a
per-stage allowance, and roll out the selected value coherently across cluster
members. Downstream exhaustive matches on the public `PersistErrorKind` must
also handle `ConsensusRpcTimeout`.

`ConsensusMetricsDump::rpc_timeouts` counts only typed logical-deadline
expirations. `rpc_timeouts_by_family` and `rpc_timeouts_by_stage` expose the
same events with fixed low-cardinality labels; endpoint, certificate, SPIFFE,
tenant, and request data are never labels.

`set_identity` publishes the local identity/server-acceptor pair atomically,
and each peer adapter atomically invalidates its cached client connector for
new RPC attempts. An in-flight attempt may finish on the previous connector,
while a retry re-reads the current connector. Store-wide peer propagation is
serialized but is not one transaction: an error or caller cancellation can
leave peers on mixed generations, so the caller must retain trust overlap and
retry until fresh-handshake readiness proves convergence. A seamless CNF
rollout must distribute overlapping trust
bundles before switching leaf certificates, retain the overlap until old
connections drain, and then remove the old trust root. This API does not invent
trust overlap when callers replace both leaf and trust material at once. The
`opc-consensus-node` test binary reads certificate files only at startup; a CNF
must call the live `set_identity` API from its identity watcher (or use a
drained restart) rather than treating that binary as a production certificate
rotation controller.

Production composition should register adapters with `try_add_peer`, which
returns a fixed error and leaves the peer unpublished when authentication or
identity setup fails. The older `add_peer` API remains source-compatible but
can only warn on that failure; it also refuses to publish the unusable peer.

## Status Notes

- Durable SQLite opens without an explicit audit key fail closed.
- `:memory:` is always ephemeral and rejected when requested as durable.
- Security-policy changes require tenant match, a `security-admin` principal,
  and active NACM allow on `/security:policy`.
- Break-glass approval requires a separate approver, `security-admin`, optional
  active NACM approve on `/security:break-glass`, and a maximum requested
  duration of 900 seconds.
- `dangerous-test-hooks` exposes fault-injection controls and test-only audit
  helpers for explicitly gated tests. Ordinary integration tests compile and
  run without the feature. Integration tests compile `opc-persist` as a
  dependency, so `cfg(test)` alone does not expose these APIs. `--all-features`
  enables the hooks and is a CI/test profile, not a production build profile.

## Roadmap

- Keep SQLite as the reference backend for correctness and audit-chain tests.
- Harden consensus transport, membership, and failure behavior before calling it
  production-ready.
- Keep northbound authorization and request translation outside this crate.

## Verification

- Source checked: `Cargo.toml`, `src/lib.rs`, backend, consensus, security
  policy, break-glass, and tests.
- Compile and run the default contract with
  `cargo test --locked -p opc-persist`.
- Run fault-injection and consensus coverage serially with
  `cargo test --locked -p opc-persist --all-features -- --test-threads=1`.

## License

Licensed under the [Apache License, Version 2.0](../../LICENSE).
