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
- `build_authenticated_client_config` and
  `build_authenticated_server_config` return opaque, redaction-safe wrappers
  proving that the config was built with this crate's SPIFFE verifier and
  reloadable SVID resolver. Security-sensitive consumers such as
  `opc-session-net` require these wrappers instead of raw Rustls configs.
- `TlsMaterialController::new(source)` pins the first accepted local SPIFFE ID;
  `new_pinned(source, id)` enforces an explicit pin. Clones share one bounded,
  process-local monotonic epoch and last-good state.
- `TlsConfigBuilder::from_material_controller(controller)` lets client and
  server wrappers share that exact authority. `begin_handshake()` freezes one
  leaf/key/chain/trust snapshot; its config must be used for the complete TLS
  exchange, and `admit()` must run only after application negotiation.
- `run_handshake()` enforces 128 concurrent operations and retries at most two
  epoch changes after the initial attempt. Its successful
  `TlsAdmittedConnection` records the exact epoch and local leaf expiry.
- `peer_spiffe_id_from_client_connection` and
  `peer_spiffe_id_from_server_connection` extract the one canonical SPIFFE URI
  from an established TLS connection. Missing, malformed, or ambiguous URI
  SANs fail closed.
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

For coherent production handshake admission:

```rust,no_run
use opc_tls::{PeerPolicy, TlsConfigBuilder, TlsMaterialController};

async fn coherent_handshake(
    source: tokio::sync::watch::Receiver<Option<opc_identity::IdentityState>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let controller = TlsMaterialController::new(source);
    let client = TlsConfigBuilder::from_material_controller(controller)
        .with_policy(PeerPolicy::default())
        .allow_any_trusted_peer()
        .build_authenticated_client_config()?;

    let outcome = client
        .run_handshake(|attempt| async move {
            let fixed_config = attempt.rustls_config();
            // Perform TLS and application negotiation with fixed_config.
            drop(fixed_config);
            Ok::<_, std::io::Error>(())
        })
        .await?;
    let (_value, admission) = outcome.into_parts();
    let _epoch = admission.epoch();
    Ok(())
}
```

## Relationships

- Consumes `opc-identity::IdentityState` from `ProjectedSvidSource`,
  `SvidWatcher`, or `FileSvidSource`.
- Uses `opc-types` identity values embedded in SPIFFE IDs.
- Intended for KMS, session transport, consensus transport, and other mTLS
  service boundaries.

## Status Notes

- Safe Rust only.
- Builds fail closed when the peer policy is unconstrained and
  `allow_any_trusted_peer` was not called.
- Default client ALPN includes `h2` and `http/1.1`.
- Protocol adapters may clone an authenticated wrapper and replace ALPN with
  their exact application protocol; the wrapper does not authorize application
  membership by itself.
- Certificate/key rotation is driven by identity state updates; this crate does
  not fetch SVIDs itself.
- Controller status contains only an epoch, closed availability/reason enums,
  and local leaf expiry. It never contains paths, PEM, key bytes, SPIFFE IDs,
  parser text, or user operation errors. Status/snapshot access reconciles the
  latest watch value and enforces expiry.
- A candidate is revalidated under limits of 16 chain certificates, 16 trust
  bundles, 128 trust anchors, 64 KiB private-key bytes, and 4 MiB total material.
  Same-SPIFFE leaf/key and overlapping-trust updates publish a new epoch;
  changed identity, wrong key/chain/trust, malformed/oversized, future, or
  expired candidates preserve the prior snapshot only until its leaf expires.

## Compatibility

`TlsConfigBuilder::new`, raw config builders, `rustls_config()`, peer-identity
helpers, and identity-source events remain source compatible. The legacy
`rustls_config()` view remains reloadable for existing consumers; it does not
provide the new post-application epoch-current admission proof. New production
transport integrations should use `run_handshake()` by default. Direct
`begin_handshake()` is a low-level adapter primitive: an adapter using it must
independently enforce equivalent concurrency, deadline, epoch-retry, and
post-application `admit()` bounds.

This contract makes each new handshake coherent and records its exact material
epoch. It does not drain already authenticated connections or enforce maximum
authentication age; that lifecycle remains #163, followed by #164 fleet
qualification under umbrella #158.

## Roadmap

- Wire bounded epoch admission into long-lived transport connection lifecycle
  under #163 without reintroducing per-callback dynamic material reads.
- Add policy dimensions only when encoded in workload identity metadata.
- Keep compatibility mode explicit so TLS 1.2 is never enabled accidentally.

## Verification

- Source checked: `Cargo.toml`, `src/lib.rs`, and TLS/identity tests.
- Run with: `cargo test -p opc-tls`.

## License

Licensed under the [Apache License, Version 2.0](../../LICENSE).
