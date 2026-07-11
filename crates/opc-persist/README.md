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
