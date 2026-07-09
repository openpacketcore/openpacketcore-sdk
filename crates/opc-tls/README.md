# opc-tls

SPIFFE-aware Rustls configuration helpers for OpenPacketCore services.

## Purpose

`opc-tls` converts `opc-identity` SVID state into reloadable client and server
TLS configs. It enforces peer policy over SPIFFE trust domain, tenant, NF kind,
and instance metadata.

## API Shape

- `TlsConfigBuilder::new(state_rx)` builds client or server configs from an
  identity watch channel.
- `with_policy` installs a `PeerPolicy`.
- `allow_any_trusted_peer` is required before building with an unconstrained
  default policy.
- `with_compat_mode(true)` enables TLS 1.2 compatibility; otherwise TLS 1.3 is
  used.
- `ReloadingClientCertResolver` and `ReloadingServerCertResolver` serve the
  current SVID certificate/key.
- `SpiffeServerCertVerifier` and `SpiffeClientCertVerifier` validate peer SVIDs
  against trust bundles and policy.
- `ServerConfig` and `ClientConfig` are re-exported Rustls config aliases.

```rust,no_run
use opc_tls::{PeerPolicy, TlsConfigBuilder};

fn describe(policy: PeerPolicy) -> bool {
    policy.is_unconstrained()
}

async fn build_configs(
    rx: tokio::sync::watch::Receiver<opc_identity::IdentityState>,
) -> Result<rustls::ServerConfig, Box<dyn std::error::Error + Send + Sync>> {
    let server = TlsConfigBuilder::new(rx)
        .with_policy(PeerPolicy::default())
        .allow_any_trusted_peer()
        .build_server_config()?;
    Ok(server)
}
```

## Relationships

- Consumes `opc-identity::IdentityState` from `SvidWatcher` or
  `FileSvidSource`.
- Uses `opc-types` identity values embedded in SPIFFE IDs.
- Intended for KMS, session transport, consensus transport, and other mTLS
  service boundaries.

## Status Notes

- Safe Rust only.
- Builds fail closed when the peer policy is unconstrained and
  `allow_any_trusted_peer` was not called.
- Default client ALPN includes `h2` and `http/1.1`.
- Certificate/key rotation is driven by identity state updates; this crate does
  not fetch SVIDs itself.

## Roadmap

- Keep certificate reload behavior tied to `opc-identity`.
- Add policy dimensions only when encoded in workload identity metadata.
- Keep compatibility mode explicit so TLS 1.2 is never enabled accidentally.

## Verification

- Source checked: `Cargo.toml`, `src/lib.rs`, and TLS/identity tests.
- Run with: `cargo test -p opc-tls`.

## License

Licensed under the [Apache License, Version 2.0](../../LICENSE).
