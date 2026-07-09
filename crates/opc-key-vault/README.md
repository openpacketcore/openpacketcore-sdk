# opc-key-vault

HashiCorp Vault Transit implementation of the `opc-key` provider boundary.

## Purpose

`opc-key-vault` retrieves and unwraps data-encryption keys through Vault
Transit while presenting the same `KeyProvider` trait as local and KMS-backed
providers. It is the Vault adapter for callers that already use `opc-crypto`
or `opc-key` AAD domains.

## API Shape

- `VaultKeyProvider::new(base_url, token, mount_path)` constructs a provider.
- `get_active_key` creates a Transit data key for the tenant/purpose key name.
- `get_key_by_id` unwraps the Vault-wrapped key encoded in the key ID.
- `rotate_key` calls the Transit rotate endpoint and then returns a fresh
  active data key.
- `dangerous_allow_insecure_http` permits plain HTTP for local tests only.
- Feature `k8s-auth` adds `with_kubernetes_auth(role, jwt)` for Vault Kubernetes
  auth and token renewal.
- `VaultError` covers adapter construction/auth errors; `KeyProvider` methods
  map Vault failures into `KeyError`.

```rust,no_run
use opc_key::{KeyProvider, KeyPurpose};
use opc_key_vault::VaultKeyProvider;
use opc_types::TenantId;
use url::Url;

async fn active_key() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let provider = VaultKeyProvider::new(
        Url::parse("https://vault.service:8200")?,
        "vault-token".to_string(),
        "transit".to_string(),
    );
    let tenant = TenantId::new("tenant-a")?;
    let _key = provider.get_active_key(KeyPurpose::Config, &tenant).await?;
    Ok(())
}
```

## Relationships

- Implements `opc-key::KeyProvider`.
- Produces `KeyHandle` values consumed by `opc-crypto`, `opc-persist`, and
  `opc-session-store`.

## Status Notes

- `publish = false`.
- HTTPS is required by default. HTTP requires an explicit dangerous opt-in.
- Transient 5xx responses are retried; 403 can trigger Kubernetes reauth when
  the `k8s-auth` feature is enabled.
- Key IDs encode the Vault key name, version, and wrapped data key. Treat them
  as sensitive metadata even though plaintext key material is not exposed.
- This crate does not run or configure Vault; tests use mocked HTTP behavior.

## Roadmap

- Keep the Transit data-key contract aligned with `opc-key::KeyProvider`.
- Harden auth renewal and error mapping as production deployment requirements
  become explicit.
- Keep local insecure transport limited to tests and development fixtures.

## Verification

- Source checked: `Cargo.toml`, `src/lib.rs`, and integration tests.
- Run with: `cargo test -p opc-key-vault --all-features`.

## License

Licensed under the [Apache License, Version 2.0](../../LICENSE).
